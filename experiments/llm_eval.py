"""大模型实验：在 SecAlertBench 同一切分上回答三个问题。

1. LLM 直接研判（同切分、同样去掉伪特征的字段、零样本）表现如何？——红队要求的同口径基线。
2. 把 LLM 作为 Probewise 的一个「大模型复核」子 Agent（成本 4，只在便宜检查定不下来时用），
   能不能减少升级人工、又不增加漏报？它的似然从训练集上学出来，不手填。
3. 往攻击请求里植入提示注入文本：LLM 直接研判会被骗多少？进了 Probewise 之后呢？

    python experiments/llm_eval.py --base-url http://127.0.0.1:8011/v1 --model qwen2.5-7b
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from probewise.netalert.build import INJECTION, load_records  # noqa: E402
from probewise.netalert.calibrate import learn, log_lr, run_checks  # noqa: E402
from probewise.netalert.evaluate import _metrics, dedupe, split, triage  # noqa: E402
from probewise.netalert.history import TicketHistory, is_attack  # noqa: E402
from probewise.netalert.llm_agent import LLMReviewAgent  # noqa: E402

LLM_COST = 4
LABELS = {"malicious": "复核认为是攻击", "benign": "复核认为是业务流量", "unsure": "复核也无法判断"}


def run_llm(agent: LLMReviewAgent, records: list[dict], workers: int) -> list[dict]:
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(lambda r: agent.run(r, {}), records))


def learn_llm_table(findings: list[dict], labels: list[bool], alpha: float = 1.0, cap: float = math.log(20)) -> dict:
    counts = {"mal": {k: 0 for k in LABELS}, "ben": {k: 0 for k in LABELS}}
    for f, att in zip(findings, labels):
        counts["mal" if att else "ben"][f["outcome"]] += 1
    tm, tb = sum(counts["mal"].values()), sum(counts["ben"].values())
    out = {}
    for o, lab in LABELS.items():
        pm = (counts["mal"][o] + alpha) / (tm + alpha * 3)
        pb = (counts["ben"][o] + alpha) / (tb + alpha * 3)
        out[o] = {"label": lab, "p_mal": pm, "p_ben": pb, "log_lr": max(-cap, min(cap, math.log(pm / pb))), "n_mal": counts["mal"][o], "n_ben": counts["ben"][o]}
    return {"name": "大模型复核", "cost": LLM_COST, "outcomes": out}


def direct_metrics(findings: list[dict], labels: list[bool]) -> dict:
    """把 LLM 的结论直接当判定：malicious→攻击，benign→误报（自动关闭），unsure→升级。"""
    res = []
    for f, att in zip(findings, labels):
        lab = {"malicious": "malicious", "benign": "benign"}.get(f["outcome"], "escalate")
        res.append((att, {"label": lab, "posterior": 1.0 if lab == "malicious" else 0.0 if lab == "benign" else 0.5, "used": [], "cost": 0}))
    return _metrics(res)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=".datasets/secalertbench/secalertbench.json")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--train-sample", type=int, default=1200)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--out", default="experiments/results")
    args = ap.parse_args()

    started = time.time()
    records = dedupe(load_records(args.data))
    train, test = split(records, "time", 0)
    hist = TicketHistory(train)
    kb = learn(train, hist)
    agent = LLMReviewAgent(args.base_url, args.model, timeout=120)
    rng = random.Random(0)
    cal = rng.sample(train, min(args.train_sample, len(train)))

    print(f"[{time.time() - started:.0f}s] 训练集抽样 {len(cal)} 条，用来学习大模型复核的似然 …", flush=True)
    cal_f = run_llm(agent, cal, args.workers)
    table = learn_llm_table(cal_f, [is_attack(r) for r in cal])
    print(f"[{time.time() - started:.0f}s] 测试集 {len(test)} 条 …", flush=True)
    test_f = run_llm(agent, test, args.workers)
    test_labels = [is_attack(r) for r in test]

    # 1. LLM 直接研判
    direct = direct_metrics(test_f, test_labels)

    # 2. Probewise + 大模型复核
    kb_llm = {**kb, "probes": {**kb["probes"], "llm_review": table}}
    base_checks = [run_checks(r, hist, exclude_self=False) for r in test]
    rows = {}
    for name, k, extra in (("probewise-robust", kb, False), ("probewise-robust+llm", kb_llm, True)):
        res = []
        for att, f, lf in zip(test_labels, base_checks, test_f):
            findings = {**f, "llm_review": lf} if extra else f
            res.append((att, triage(findings, k, "probewise-robust")))
        m = _metrics(res)
        m["llm_calls"] = sum(1 for _, r in res if "llm_review" in r["used"])
        rows[name] = m

    # 3. 注入测试：只看测试集里的攻击
    attacks = [r for r in test if is_attack(r)]
    poisoned = [{**r, "parameter": f"{r.get('parameter') or ''} {INJECTION}", "req_body": f"{r.get('req_body') or ''}\n{INJECTION}"} for r in attacks]
    print(f"[{time.time() - started:.0f}s] 注入测试 {len(poisoned)} 条 …", flush=True)
    clean_f = [f for f, r in zip(test_f, test) if is_attack(r)]
    pois_f = run_llm(agent, poisoned, args.workers)
    direct_flip = sum(1 for a, b in zip(clean_f, pois_f) if a["outcome"] != "benign" and b["outcome"] == "benign")
    pw_flip = 0
    for r, p, lf in zip(attacks, poisoned, pois_f):
        before = triage({**run_checks(r, hist, exclude_self=False), "llm_review": next(f for f, rr in zip(test_f, test) if rr is r)}, kb_llm, "probewise-robust")["label"]
        after = triage({**run_checks(p, hist, exclude_self=False), "llm_review": lf}, kb_llm, "probewise-robust")["label"]
        pw_flip += before != "benign" and after == "benign"

    out = {
        "model": args.model,
        "split": "time（2025→2026）",
        "test_size": len(test),
        "test_attacks": sum(test_labels),
        "calibration_sample": len(cal),
        "llm_table": {o: {k: (round(v, 4) if isinstance(v, float) else v) for k, v in d.items()} for o, d in table["outcomes"].items()},
        "llm_outcomes_on_test": {o: sum(1 for f in test_f if f["outcome"] == o) for o in LABELS},
        "llm_quotes_dropped": sum(1 for f in test_f for s in f["steps"] if "被丢弃" in s.get("result", "") and "0 处找不到" not in s.get("result", "")),
        "direct": direct,
        "probewise": rows,
        "injection": {"attacks": len(attacks), "llm_direct_flipped_to_benign": direct_flip, "probewise_with_llm_flipped_to_benign": pw_flip},
        "elapsed_s": round(time.time() - started, 1),
    }
    Path(args.out).mkdir(parents=True, exist_ok=True)
    f = Path(args.out) / f"llm_eval_{args.model.replace('/', '_')}.json"
    f.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    # 汇总进 Web 控制台的评测数据
    ev = Path(__file__).resolve().parent.parent / "probewise" / "data" / "web_eval.json"
    if ev.exists():
        data = json.loads(ev.read_text(encoding="utf-8"))
        keep = ("model", "test_size", "test_attacks", "calibration_sample", "llm_table", "llm_outcomes_on_test", "direct", "injection")
        data.setdefault("llm_experiments", {})[args.model] = {**{k: out[k] for k in keep}, "probewise_with_llm": out["probewise"]["probewise-robust+llm"], "probewise": out["probewise"]["probewise-robust"]}
        ev.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("llm_outcomes_on_test", "direct", "probewise", "injection", "elapsed_s")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
