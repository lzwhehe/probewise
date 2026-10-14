"""基准测试：比较不同调查策略在不同「读取噪声」下的准确性与成本。

读取噪声模拟能力有限的小模型：以一定概率把工具输出读错。
关键安全指标是「漏报」：真实威胁被当成误报关闭。升级给人工不算错，但会占用分析师时间。
"""

from __future__ import annotations

from .graph import STRATEGIES, STRATEGY_NAMES, Engine
from .kb import KnowledgeBase, load_scenarios
from .reader import NoisyReader, RuleReader


def run_bench(noise_levels=(0.0, 0.1, 0.2), seeds: int = 10, budget: float = 10, strategies=STRATEGIES) -> dict:
    kb = KnowledgeBase.load()
    # 基准测试只覆盖合成场景；网络攻击告警在真实标注数据上单独评测（probewise evaluate）
    scenarios = [s for s in load_scenarios() if s["type"] != "web_attack"]
    truth = {s["id"]: s["ground_truth"] for s in scenarios}
    rows = []
    for noise in noise_levels:
        for strategy in strategies:
            agg = {"runs": 0, "correct": 0, "wrong": 0, "missed_threats": 0, "false_alarms": 0, "escalated": 0, "cost": 0.0, "probes": 0}
            n_seeds = 1 if (noise == 0 and strategy != "random") else seeds
            for seed in range(n_seeds):
                reader = RuleReader() if noise == 0 else NoisyReader(noise, seed=seed)
                engine = Engine(kb=kb, scenarios=scenarios, reader=reader)
                for s in scenarios:
                    t = engine.start(s["id"], strategy=strategy, budget=budget, approval_mode="defer", seed=seed, run_id=f"b-{s['id']}-{seed}")
                    v = t["verdict"]
                    agg["runs"] += 1
                    agg["cost"] += v["cost_spent"]
                    agg["probes"] += v["probes_used"]
                    if v["label"] == "escalate":
                        agg["escalated"] += 1
                    elif v["label"] == truth[s["id"]]:
                        agg["correct"] += 1
                    else:
                        agg["wrong"] += 1
                        if truth[s["id"]] == "malicious":
                            agg["missed_threats"] += 1
                        else:
                            agg["false_alarms"] += 1
            n = agg["runs"]
            decided = agg["correct"] + agg["wrong"]
            rows.append(
                {
                    "strategy": strategy,
                    "strategy_name": STRATEGY_NAMES[strategy],
                    "noise": noise,
                    "runs": n,
                    "accuracy_decided": round(agg["correct"] / decided, 4) if decided else None,
                    "correct_rate": round(agg["correct"] / n, 4),
                    "missed_threat_rate": round(agg["missed_threats"] / n, 4),
                    "false_alarm_rate": round(agg["false_alarms"] / n, 4),
                    "escalation_rate": round(agg["escalated"] / n, 4),
                    "avg_cost": round(agg["cost"] / n, 3),
                    "avg_probes": round(agg["probes"] / n, 3),
                }
            )
    return {"budget": budget, "seeds": seeds, "scenarios": len(scenarios), "rows": rows}


def format_table(result: dict) -> str:
    head = f"{'读取噪声':<8}{'策略':<26}{'正确率':>8}{'漏报率':>8}{'误报率':>8}{'升级率':>8}{'平均成本':>10}{'平均检查数':>10}"
    lines = [head, "-" * len(head)]
    for r in result["rows"]:
        lines.append(
            f"{r['noise']:<12.0%}{r['strategy_name']:<20}{r['correct_rate']:>10.1%}{r['missed_threat_rate']:>9.1%}"
            f"{r['false_alarm_rate']:>9.1%}{r['escalation_rate']:>9.1%}{r['avg_cost']:>11.2f}{r['avg_probes']:>11.2f}"
        )
    return "\n".join(lines)
