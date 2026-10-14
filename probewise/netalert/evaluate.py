"""在带标注的真实告警（SecAlertBench）上评测研判策略。

标签含义（写在前面，避免误读）：Attack =「真实的攻击尝试」（扫描、漏洞利用，不论是否成功），
Non-Attack =「业务流量被规则误报」。所以「攻击是否成功」是另一个问题，单独作为提示展示。

评测前先去重（同规则、方法、URI、请求体视为同一条），再做三种切分：
- random：分层随机 70/30。同一个 SOC、规则和业务系统都见过 —— 偏乐观。
- time：2025 年及更早训练，2026 年测试（按响应头 Date 判断年份，无日期的放训练集）。最接近真实上线。
- rule_grouped：按规则分组，测试集的规则在训练集里从未出现 —— 新规则 / 冷启动压力测试。

头号指标是漏报：被自动判为误报关掉的真攻击 / 全部真攻击。
对照组：
- artifact：只用采集伪特征的三行规则（有 XFF→误报，CONNECT→误报，状态码非 200→攻击）。
  它能「打败」论文里的大模型，说明那种比较没有意义；Probewise 不使用这些字段。
- sop：每项检查都做一遍再判定。
"""

from __future__ import annotations

import math
import random
import re
from collections import defaultdict

from ..ledger import expected_info_gain, logit, sigmoid
from .calibrate import calibrated, learn, log_lr, run_checks
from .history import TicketHistory, is_attack

THRESHOLDS = {"malicious": 0.95, "benign": 0.05}
MIN_INFO_GAIN = 0.02
STRATEGIES = {
    "probewise": "Probewise（信息增益 / 成本，够确定就停）",
    "probewise-robust": "Probewise 稳健（默认；结案需 2 条同向强证据）",
    "sop": "固定流程（每项检查都做）",
    "artifact": "伪特征三行规则（对照，不可用于生产）",
}
STRONG = math.log(2)  # |log LR| ≥ ln2 视为强证据（与引擎的 STRONG_LR = 2 一致）


def _label(p, th):
    return "malicious" if p >= th["malicious"] else "benign" if p <= th["benign"] else "escalate"


def triage(findings: dict, kb: dict, strategy: str = "probewise", budget: float = 10, thresholds=THRESHOLDS) -> dict:
    """离线复现控制器的决策（与 LangGraph 引擎同一套规则）。

    自动判误报的额外护栏：必须做过载荷核验且没有明确利用载荷、并且至少有 2 项检查 ——
    防止攻击者先用大量无害请求把某条规则「刷」成历史误报，再发真正的利用（反馈投毒）。
    """
    probes, platt = kb["probes"], kb["platt"]
    z = logit(kb["prior"])
    used, llrs, spent = [], [], 0.0
    need = 2 if strategy == "probewise-robust" else 1

    def benign_guard_ok():
        return "payload_check" in used and findings["payload_check"]["outcome"] != "explicit_exploit" and len(used) >= 2

    def strong_count(lab):
        return sum(1 for v in llrs if (v >= STRONG if lab == "malicious" else v <= -STRONG))

    while True:
        p = calibrated(z, platt)
        lab = _label(p, thresholds)
        if strategy != "sop" and lab != "escalate" and strong_count(lab) >= need and (lab != "benign" or benign_guard_ok()) and (lab != "malicious" or "response_check" in used):
            break
        remaining = [c for c in probes if c not in used and probes[c]["cost"] <= budget - spent]
        if not remaining:
            break
        if strategy == "sop":
            cid = remaining[0]
        elif lab == "benign" and "payload_check" in remaining:
            cid = "payload_check"  # 想结案为误报，先过载荷这一关
        elif lab == "malicious" and "response_check" in remaining:
            cid = "response_check"  # 判为攻击前确认是否成功
        else:
            def gain(c):
                outs = {o: {"p_mal": v["p_mal"], "p_ben": v["p_ben"]} for o, v in probes[c]["outcomes"].items()}
                return expected_info_gain(p, outs) / probes[c]["cost"]
            cid = max(remaining, key=gain)
            if gain(cid) * probes[cid]["cost"] < MIN_INFO_GAIN:
                break
        v = log_lr(probes[cid], findings[cid]["outcome"])
        z += v
        llrs.append(v)
        used.append(cid)
        spent += probes[cid]["cost"]
    p = calibrated(z, platt)
    lab = _label(p, thresholds)
    if lab != "escalate" and strong_count(lab) < need:
        lab = "escalate"
    if lab == "benign" and not benign_guard_ok():
        lab = "escalate"
    success = "response_check" in used and findings["response_check"]["outcome"] == "exploit_echo"
    return {"label": lab, "posterior": p, "used": used, "cost": spent, "success_sign": success}


def artifact_baseline(record: dict) -> dict:
    if record.get("xff") or str(record.get("method", "")).upper() == "CONNECT":
        lab = "benign"
    else:
        lab = "benign" if record.get("rsp_status") == 200 else "malicious"
    return {"label": lab, "posterior": 0.0 if lab == "benign" else 1.0, "used": [], "cost": 0.0}


def _metrics(results: list[tuple[bool, dict]]) -> dict:
    n = len(results)
    att = sum(1 for a, _ in results if a)
    ben = n - att
    closed = [(a, r) for a, r in results if r["label"] == "benign"]
    missed = sum(1 for a, _ in closed if a)
    decided = [(a, r) for a, r in results if r["label"] != "escalate"]
    correct = sum(1 for a, r in decided if (r["label"] == "malicious") == a)
    return {
        "n": n,
        "attacks": att,
        "missed_attacks": missed,
        "missed_attack_rate": missed / att if att else 0.0,
        "auto_close_rate": len(closed) / n,
        "auto_close_precision": (len(closed) - missed) / len(closed) if closed else None,
        "auto_malicious_rate": sum(1 for _, r in results if r["label"] == "malicious") / n,
        "escalation_rate": sum(1 for _, r in results if r["label"] == "escalate") / n,
        "accuracy_decided": correct / len(decided) if decided else None,
        "tpr": sum(1 for a, r in results if a and r["label"] != "benign") / att if att else None,
        "fpr": sum(1 for a, r in results if not a and r["label"] != "benign") / ben if ben else None,
        "avg_checks": sum(len(r["used"]) for _, r in results) / n,
        "brier": sum((r["posterior"] - a) ** 2 for a, r in results) / n,
    }


def dedupe(records: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in records:
        k = (r.get("rule_name"), r.get("method"), r.get("uri"), r.get("req_body"))
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def year_of(record: dict):
    m = re.search(r"Date:\s*\w+,\s*\d+\s+\w+\s+(\d{4})", str(record.get("rsp_header") or ""))
    return int(m.group(1)) if m else None


def split(records: list[dict], mode: str, seed: int, test_frac: float = 0.3):
    rng = random.Random(seed)
    if mode == "time":
        test = [r for r in records if (year_of(r) or 0) >= 2026]
        train = [r for r in records if (year_of(r) or 0) < 2026]
        return train, test
    if mode == "rule_grouped":
        rules = sorted({r["rule_name"] for r in records})
        rng.shuffle(rules)
        test_rules, size = set(), 0
        for rule in rules:
            if size >= test_frac * len(records):
                break
            test_rules.add(rule)
            size += sum(1 for r in records if r["rule_name"] == rule)
        return [r for r in records if r["rule_name"] not in test_rules], [r for r in records if r["rule_name"] in test_rules]
    by = defaultdict(list)
    for r in records:
        by[is_attack(r)].append(r)
    train, test = [], []
    for group in by.values():
        g = group[:]
        rng.shuffle(g)
        k = int(len(g) * test_frac)
        test += g[:k]
        train += g[k:]
    return train, test


def evaluate(records: list[dict], mode: str = "random", seeds: int = 3, strategies=tuple(STRATEGIES)) -> dict:
    records = dedupe(records)
    seeds = 1 if mode == "time" else seeds
    per = defaultdict(list)
    kb0 = None
    for seed in range(seeds):
        train, test = split(records, mode, seed)
        hist = TicketHistory(train)
        kb = learn(train, hist, seed=seed)
        kb0 = kb0 or kb
        cache = [(is_attack(r), r, run_checks(r, hist, exclude_self=False)) for r in test]
        for s in strategies:
            if s == "artifact":
                per[s].append(_metrics([(a, artifact_baseline(r)) for a, r, _ in cache]))
            else:
                per[s].append(_metrics([(a, triage(f, kb, s)) for a, _, f in cache]))
    rows = []
    for s in strategies:
        ms = per[s]
        avg = {}
        for k in ms[0]:
            vals = [m[k] for m in ms if m[k] is not None]
            avg[k] = sum(vals) / len(vals) if vals else None
        rows.append({"strategy": s, "strategy_name": STRATEGIES[s], **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in avg.items()}})
    return {"mode": mode, "seeds": seeds, "records": len(records), "train_size": kb0["trained_on"] + kb0["validated_on"], "rows": rows, "kb": kb0}


PAPER_LLM = {
    "note": "SecAlertBench 论文：16 个 LLM 直接研判的平均值（不同切分、不同协议，仅作背景参考，不可直接比较）",
    "url": "https://github.com/Dxsssu/SecAlertBench",
    "tpr": 0.7971,
    "fpr": 0.4413,
}
