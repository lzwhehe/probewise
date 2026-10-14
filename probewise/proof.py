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


def apply_guards(label: str, rounds: list, alert_type: str) -> str:
    """与引擎一致的结案护栏：网络攻击告警判误报，必须看过载荷且没有明确利用载荷、至少两项检查。"""
    if alert_type == "web_attack" and label == "benign":
        payload = [r for r in rounds if r.get("probe") == "payload_check"]
        if not payload or payload[0].get("outcome") == "explicit_exploit" or len(rounds) < 2:
            return "escalate"
    return label


def recompute(prior: float, readings: list[tuple[str, str]], kb: KnowledgeBase, platt: dict | None = None, skip: set | None = None) -> float:
    """只用先验、知识库和 (检查, 结论) 列表重算后验，不依赖调查过程中的任何中间值。

    platt：概率校准参数（从历史工单学到的表才有）；skip：核验未通过、不计分的证据序号。
    """
    x = logit(prior)
    for i, (probe, outcome) in enumerate(readings):
        if skip and i in skip:
            continue
        x += kb.llr(probe, outcome)
    c = platt or {"a": 1.0, "b": 0.0}
    return sigmoid(c["a"] * x + c["b"])


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
    # 校准参数和阈值一律取服务端知识库，不信任调查记录里自带的值（防止伪造记录「自证」）
    alert_type = chain[0].get("type") if chain else (trace.get("alert") or {}).get("type")
    platt = kb.platt(alert_type) if alert_type in kb.alert_types else None
    thresholds = kb.thresholds
    try:
        skip = {i for i, r in enumerate(rounds) if r.get("unverified")}
        recomputed = recompute(trace["prior"], readings, kb, platt, skip)
        recorded = float(rounds[-1]["posterior"]) if rounds else recompute(trace["prior"], [], kb, platt)
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
        expected = verdict_label(recomputed, thresholds)
        # 交叉印证：结案需要足够多条同方向的证据，否则只能升级
        need = trace.get("corroboration", 1)
        lrs = [1.0 if r.get("unverified") else r["lr"] for r in rounds]
        if expected != "escalate" and supporting_count(lrs, expected) < need:
            expected = "escalate"
        expected = apply_guards(expected, rounds, alert_type)
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
    alert_type = (trace.get("alert") or {}).get("type")
    platt = kb.platt(alert_type) if alert_type in kb.alert_types else None
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
    skip = {i for i, r in enumerate(rounds) if r.get("unverified") and r["evidence_id"] not in overrides}
    after = recompute(trace["prior"], readings, kb, platt, skip)
    label = verdict_label(after, kb.thresholds)
    need = trace.get("corroboration", 1)
    lrs = [1.0 if i in skip else math.exp(kb.llr(p, o)) for i, (p, o) in enumerate(readings)]
    if label != "escalate" and supporting_count(lrs, label) < need:
        label = "escalate"
    label = apply_guards(label, [{"probe": p, "outcome": o} for p, o in readings], alert_type)
    return {
        "changed": changed,
        "before": {"posterior": before, "label": trace["verdict"]["label"]},
        "after": {"posterior": round(after, 4), "label": label},
        "note": "只重算已收集的证据；如果换掉证据后控制器本会改查其它项目，需要重新调查才能得到完整结果。",
    }
