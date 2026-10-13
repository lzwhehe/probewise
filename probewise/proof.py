"""证据承载式判定：哈希链审计、独立验证、反事实推演。

哈希链里的数字一律格式化成固定 4 位小数的字符串，JSON 用排序后的紧凑格式序列化，
这样浏览器里的 JavaScript 可以逐字节重算出同样的 SHA-256，独立验证调查记录没有被改过。
"""

from __future__ import annotations

import hashlib
import json
import math

from .kb import KnowledgeBase
from .ledger import logit, sigmoid

GENESIS = "0" * 64
STRONG_LR = 2.0  # 交叉印证只计入「强证据」：似然比 ≥ 2（支持恶意）或 ≤ 0.5（支持良性）


def supports(lr: float, label: str) -> bool:
    if label == "malicious":
        return lr >= STRONG_LR
    if label == "benign":
        return lr <= 1 / STRONG_LR
    return False


def supporting_count(lrs, label: str) -> int:
    return sum(1 for lr in lrs if supports(float(lr), label))


def fmt(x: float) -> str:
    return f"{x:.4f}"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(obj: dict) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def chain_record(seq: int, kind: str, body: dict, prev: str) -> dict:
    """生成一条链上记录：body 里只能放字符串或整数。"""
    record = {"seq": seq, "kind": kind, "prev": prev, **body}
    return {**record, "hash": digest(record)}


def verdict_label(posterior: float, thresholds: dict) -> str:
    if posterior >= thresholds["malicious"]:
        return "malicious"
    if posterior <= thresholds["benign"]:
        return "benign"
    return "escalate"


def recompute(prior: float, readings: list[tuple[str, str]], kb: KnowledgeBase) -> float:
    """只用先验、知识库和 (检查, 结论) 列表重算后验，不依赖调查过程中的任何中间值。"""
    x = logit(prior)
    for probe, outcome in readings:
        o = kb.outcome(probe, outcome)
        x += math.log(o["p_mal"] / o["p_ben"])
    return sigmoid(x)


def verify(trace: dict, kb: KnowledgeBase) -> dict:
    """独立验证一份调查记录，返回每项检查的结果。"""
    checks = []
    chain = trace.get("chain", [])

    prev = GENESIS
    broken = None
    for rec in chain:
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("prev") != prev or digest(body) != rec.get("hash"):
            broken = rec.get("seq")
            break
        prev = rec["hash"]
    checks.append(
        {
            "name": "哈希链完整",
            "ok": broken is None and bool(chain),
            "detail": f"共 {len(chain)} 条记录" if broken is None else f"第 {broken} 条记录被改动或顺序被打乱",
        }
    )

    rounds = [r for r in chain if r["kind"] == "evidence"]
    readings = [(r["probe"], r["outcome"]) for r in rounds]
    try:
        recomputed = recompute(trace["prior"], readings, kb)
        recorded = float(rounds[-1]["posterior"]) if rounds else trace["prior"]
        same = abs(recomputed - recorded) < 1e-3
        checks.append(
            {
                "name": "后验可重算",
                "ok": same,
                "detail": f"按知识库重算为 {recomputed:.4f}，记录值为 {recorded:.4f}",
            }
        )
    except KeyError as exc:
        recomputed = None
        checks.append({"name": "后验可重算", "ok": False, "detail": str(exc)})

    verdict_rec = next((r for r in chain if r["kind"] == "verdict"), None)
    if verdict_rec and recomputed is not None:
        expected = verdict_label(recomputed, trace["thresholds"])
        # 交叉印证：结案需要足够多条同方向的证据，否则只能升级
        need = trace.get("corroboration", 1)
        if expected != "escalate" and supporting_count([r["lr"] for r in rounds], expected) < need:
            expected = "escalate"
        checks.append(
            {
                "name": "判定符合阈值",
                "ok": expected == verdict_rec["label"],
                "detail": f"按阈值应判定为 {expected}，记录为 {verdict_rec['label']}",
            }
        )
    else:
        checks.append({"name": "判定符合阈值", "ok": False, "detail": "没有找到判定记录"})

    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def whatif(trace: dict, kb: KnowledgeBase, overrides: dict[str, str]) -> dict:
    """反事实推演：把某些证据的结论换掉，看后验和判定会怎么变。

    overrides: {证据编号: 新的结论选项}
    """
    rounds = [r for r in trace.get("rounds", [])]
    readings = []
    changed = []
    for r in rounds:
        outcome = overrides.get(r["evidence_id"], r["outcome"])
        if outcome not in kb.probes[r["probe"]]["outcomes"]:
            raise ValueError(f"{r['evidence_id']}（{r['probe']}）没有结论选项 {outcome}")
        if outcome != r["outcome"]:
            changed.append({"evidence_id": r["evidence_id"], "probe": r["probe"], "from": r["outcome"], "to": outcome})
        readings.append((r["probe"], outcome))
    before = trace["verdict"]["posterior"]
    after = recompute(trace["prior"], readings, kb)
    label = verdict_label(after, trace["thresholds"])
    need = trace.get("corroboration", 1)
    lrs = [kb.outcome(p, o)["p_mal"] / kb.outcome(p, o)["p_ben"] for p, o in readings]
    if label != "escalate" and supporting_count(lrs, label) < need:
        label = "escalate"
    return {
        "changed": changed,
        "before": {"posterior": before, "label": trace["verdict"]["label"]},
        "after": {"posterior": round(after, 4), "label": label},
        "note": "只重算已收集的证据；如果换掉证据后控制器本会改查其它项目，需要重新调查才能得到完整结果。",
    }
