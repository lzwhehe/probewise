"""Probewise 的 MCP Server：让 Claude Code、Cursor 等 Agent 直接调用证据驱动的告警研判。

两种用法：
1. triage_alert：一次调用完成整个调查（内置规则读取器）。
2. open_case → submit_reading（循环）→ get_report：调用方 Agent 充当「读取器」，
   每次只把一段工具输出读成一个结论选项；查什么、何时停、下什么判定由 Probewise 的账本决定，
   调用方无法跳过证据直接下结论。
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from .graph import Engine
from .kb import load_scenarios
from .proof import verify

server = MCPServer(
    name="probewise",
    instructions=(
        "Probewise 是证据驱动的安全告警研判引擎。用 open_case 开始调查后，你的角色只是读取器："
        "把每段工具输出读成给定选项中的一个，用 submit_reading 提交；不要自行下判定。"
        "出现需要审批的处置动作时，必须交给人类决定。"
    ),
)
_engine = Engine()
MODES = {"fast": "probewise", "robust": "probewise-robust"}


def _step(trace: dict) -> dict:
    """把调查记录压缩成 Agent 下一步需要的信息。"""
    out = {"case_id": trace["run_id"], "status": trace["status"], "evidence_collected": len(trace["rounds"])}
    waiting = trace.get("awaiting")
    if waiting and waiting.get("type") == "reading":
        out["next"] = {
            "action": "请把下面的工具输出读成 options 中的一个选项，然后调用 submit_reading",
            "probe": waiting["probe_name"],
            "tool_output": waiting["raw_text"],
            "options": waiting["options"],
        }
    elif trace.get("verdict"):
        v = trace["verdict"]
        out["verdict"] = {"label": v["label"], "posterior": v["posterior"], "summary": v["summary"]}
        if trace.get("pending"):
            out["needs_human_approval"] = [{"id": a["id"], "name": a["name"]} for a in trace["pending"]]
    return out


@server.tool()
def list_alerts() -> list[dict]:
    """列出可调查的告警（合成演示数据）。"""
    return [
        {"id": s["id"], "type": s["type"], "severity": s["severity"], "title": s["title"], "summary": s["summary"]}
        for s in load_scenarios()
    ]


@server.tool()
def triage_alert(alert_id: str, mode: str = "fast", budget: float = 10) -> dict:
    """自动完成一次调查并返回判定、证据与报告。mode: fast | robust。"""
    trace = _engine.start(alert_id, strategy=MODES.get(mode, "probewise"), budget=budget, approval_mode="defer")
    return {
        "case_id": trace["run_id"],
        "verdict": trace["verdict"],
        "evidence": [
            {"id": r["evidence_id"], "probe": r["probe_name"], "reading": r["outcome_label"], "likelihood_ratio": r["lr"]}
            for r in trace["rounds"]
        ],
        "actions": trace["actions"],
        "report_markdown": trace["report"]["markdown"],
    }


@server.tool()
def open_case(alert_id: str, mode: str = "robust", budget: float = 10) -> dict:
    """以「外部读取器」模式开始调查：Probewise 选择检查项并执行，你负责读取工具输出。"""
    trace = _engine.start(
        alert_id, strategy=MODES.get(mode, "probewise-robust"), budget=budget, approval_mode="defer", reader_mode="external"
    )
    return _step(trace)


@server.tool()
def submit_reading(case_id: str, outcome: str) -> dict:
    """提交你对当前工具输出的读取结果（必须是 options 中的一个键）。返回下一段待读输出或最终判定。"""
    trace = _engine.submit_reading(case_id, outcome, reader="mcp-client")
    return _step(trace)


@server.tool()
def get_report(case_id: str) -> dict:
    """获取调查报告（Markdown）、判定证明和 RAG 引用。"""
    trace = _engine.trace(case_id)
    return {
        "report_markdown": (trace.get("report") or {}).get("markdown", "调查尚未完成"),
        "proof": (trace.get("verdict") or {}).get("proof"),
        "references": [{"id": c["id"], "title": c["title"]} for c in trace.get("context", [])],
    }


@server.tool()
def verify_case(case_id: str) -> dict:
    """独立验证调查记录：哈希链完整性、后验可重算、判定符合阈值与交叉印证规则。"""
    return verify(_engine.trace(case_id), _engine.kb)


@server.resource("probewise://knowledge-base", name="knowledge-base", mime_type="application/json")
def knowledge_base() -> str:
    """检查项、结论选项、似然与告警类型的定义。"""
    return json.dumps(_engine.kb.raw, ensure_ascii=False)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
