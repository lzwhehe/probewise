"""HTTP API + Web 控制台。

checkpoint 用 SQLite 持久化（PROBEWISE_DB），服务重启后调查仍可继续审批、回放和分叉。
只对内置的合成场景开放调查，不接受任意目标，适合公开演示。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from langgraph.checkpoint.sqlite import SqliteSaver
from pydantic import BaseModel, Field

from . import __version__
from .bench import run_bench
from .graph import STRATEGIES, STRATEGY_NAMES, Engine
from .kb import load_scenarios
from .proof import verify, whatif
from .workbench import FeedbackStore, closing_note, run_queue

WEB_DIR = Path(os.environ.get("PROBEWISE_WEB", Path(__file__).resolve().parent.parent / "web"))
DB_PATH = os.environ.get("PROBEWISE_DB", "probewise.db")

_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
engine = Engine(checkpointer=SqliteSaver(_conn))
_bench_cache: dict = {}
_bench_lock = threading.Lock()
_queue_lock = threading.Lock()
feedback = FeedbackStore(_conn)

# 部署在网关子路径下时（网关会去掉前缀再转发），PUBLIC_PATH 只用来告诉 API 文档对外地址，
# 不设置 FastAPI 的 root_path，以免静态文件路由匹配出错
PUBLIC_PATH = os.environ.get("PUBLIC_PATH", "")
app = FastAPI(
    title="Probewise API",
    version=__version__,
    description="证据驱动的安全告警研判：每个判定都附带可独立验证的证明。",
    docs_url=None,
    redoc_url=None,
    servers=[{"url": PUBLIC_PATH}] if PUBLIC_PATH else None,
)


@app.get("/docs", include_in_schema=False)
def docs():
    # 用相对路径加载 openapi.json，挂在任何子路径下都能工作
    return get_swagger_ui_html(openapi_url="openapi.json", title="Probewise API")


class RunRequest(BaseModel):
    alert_id: str
    strategy: str = "probewise"
    budget: float = Field(10, ge=1, le=30)


class ApproveRequest(BaseModel):
    decisions: dict[str, str]
    by: str = Field("analyst", max_length=40)


class ForkRequest(BaseModel):
    evidence_id: str
    outcome: str


class WhatIfRequest(BaseModel):
    overrides: dict[str, str]


class FeedbackRequest(BaseModel):
    correct_label: str = Field(pattern="^(malicious|benign|escalate)$")
    comment: str = Field("", max_length=300)
    by: str = Field("analyst", max_length=40)


def _private_copy(run_id: str) -> str:
    """队列里的调查（q-*）是所有访客共享的：审批、分叉前先复制一份，只改访客自己的副本。"""
    if not run_id.startswith("q-"):
        return run_id
    t = _get(run_id)
    new_id = f"{run_id}-{uuid.uuid4().hex[:6]}"
    engine.start(t["alert"]["id"], run_id=new_id, strategy=t["strategy"], approval_mode="interrupt")
    return new_id


def _get(run_id: str) -> dict:
    try:
        return engine.trace(run_id)
    except KeyError:
        raise HTTPException(404, f"没有找到调查 {run_id}")


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/alerts")
def alerts():
    return [
        {k: s[k] for k in ("id", "type", "severity", "time", "title", "summary", "entities")}
        | {"type_name": engine.kb.alert_types[s["type"]]["name"], "answer": s["ground_truth"]}
        for s in load_scenarios()
    ]


@app.get("/api/kb")
def kb():
    return {
        "thresholds": engine.kb.thresholds,
        "probes": {
            k: {
                "name": p["name"],
                "cost": p["cost"],
                "outcomes": {o: {**{kk: v[kk] for kk in ("label", "p_mal", "p_ben")}, "log_lr": round(engine.kb.llr(k, o), 6)} for o, v in p["outcomes"].items()},
            }
            for k, p in engine.kb.probes.items()
        },
        "alert_types": {k: {"name": t["name"], "prior": t["prior"], "probes": t["probes"], "platt": engine.kb.platt(k)} for k, t in engine.kb.alert_types.items()},
        "strategies": [{"id": s, "name": STRATEGY_NAMES[s]} for s in STRATEGIES],
    }


@app.post("/api/runs")
def start_run(req: RunRequest):
    try:
        return engine.start(req.alert_id, strategy=req.strategy, budget=req.budget, approval_mode="interrupt")
    except (KeyError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    return _get(run_id)


@app.post("/api/runs/{run_id}/approve")
def approve(run_id: str, req: ApproveRequest):
    _get(run_id)
    run_id = _private_copy(run_id)
    try:
        return engine.approve(run_id, req.decisions, by=req.by)
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.post("/api/runs/{run_id}/fork")
def fork(run_id: str, req: ForkRequest):
    _get(run_id)
    run_id = _private_copy(run_id)
    try:
        return engine.fork(run_id, req.evidence_id, req.outcome)
    except (KeyError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/runs/{run_id}/checkpoints")
def checkpoints(run_id: str):
    _get(run_id)
    return engine.checkpoints(run_id)


@app.post("/api/runs/{run_id}/verify")
def verify_run(run_id: str):
    return verify(_get(run_id), engine.kb)


@app.post("/api/verify")
def verify_trace(trace: dict):
    """验证任意一份调查记录（例如从别处导出的 JSON）。"""
    try:
        return verify(trace, engine.kb)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, f"调查记录格式不正确：{exc}")


@app.post("/api/runs/{run_id}/whatif")
def what_if(run_id: str, req: WhatIfRequest):
    try:
        return whatif(_get(run_id), engine.kb, req.overrides)
    except (KeyError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/queue")
def queue():
    """一次研判队列里的全部网络攻击告警，返回排序后的队列、汇总和规则调优建议。"""
    with _queue_lock:
        return run_queue(engine)


@app.get("/api/runs/{run_id}/note")
def note(run_id: str):
    return {"text": closing_note(_get(run_id), engine.scenarios)}


@app.post("/api/runs/{run_id}/feedback")
def add_feedback(run_id: str, req: FeedbackRequest, request: Request):
    t = _get(run_id)
    if not t.get("verdict"):
        raise HTTPException(409, "调查还没有给出判定，暂不能反馈")
    client = request.headers.get("x-real-ip") or (request.client.host if request.client else "-")
    try:
        return feedback.add(run_id, t["alert"]["id"], t["verdict"]["label"], req.correct_label, req.comment, req.by, client)
    except ValueError as exc:
        raise HTTPException(429, str(exc))


@app.get("/api/feedback")
def list_feedback():
    return feedback.list()


@app.get("/api/web-eval")
def web_eval():
    """在真实标注数据（SecAlertBench）上的评测结果，由 `probewise evaluate` 生成。"""
    f = Path(__file__).parent / "data" / "web_eval.json"
    if not f.exists():
        raise HTTPException(404, "还没有评测结果，请先运行 probewise evaluate")
    return json.loads(f.read_text(encoding="utf-8"))


@app.get("/api/bench")
def bench():
    with _bench_lock:
        if "result" not in _bench_cache:
            # 镜像构建时会预先算好基准结果（PROBEWISE_BENCH_FILE），没有时才现场计算
            cached = Path(os.environ.get("PROBEWISE_BENCH_FILE", "bench.json"))
            if cached.exists():
                _bench_cache["result"] = json.loads(cached.read_text(encoding="utf-8"))
            else:
                _bench_cache["result"] = run_bench(seeds=int(os.environ.get("PROBEWISE_BENCH_SEEDS", "10")))
    return _bench_cache["result"]


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")
