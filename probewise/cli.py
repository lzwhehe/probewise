"""命令行：probewise list | triage | bench | verify | whatif | serve | mcp | export-demo"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .graph import STRATEGIES, Engine
from .kb import KnowledgeBase, load_scenarios
from .proof import verify, whatif
from .reader import make_reader

C = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m", "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}
LABEL = {"malicious": ("真实威胁", "red"), "benign": ("误报", "green"), "escalate": ("升级人工", "yellow")}


def c(text: str, color: str) -> str:
    return f"{C[color]}{text}{C['end']}" if sys.stdout.isatty() else text


def cmd_list(args) -> None:
    for s in load_scenarios():
        print(f"{s['id']}  [{s['severity']:<6}] {s['type']:<26} {s['title']}")


def print_trace(t: dict) -> None:
    a = t["alert"]
    print(c(f"\n▌{a['id']} {a['title']}", "bold"))
    print(c(f"  {a['summary']}", "dim"))
    print(f"  先验 P(恶意) = {t['prior']:.2f}　策略 = {t['strategy']}　预算 = {t['budget']:g}\n")
    for r in t["rounds"]:
        arrow = c("▲", "red") if r["lr"] > 1 else c("▼", "green")
        print(f"  {c(r['evidence_id'], 'cyan')} {r['probe_name']}（成本 {r['cost']}）")
        if r["why"]:
            print(c(f"     为什么查它：{r['why']}", "dim"))
        print(f"     工具输出：{r['raw_text']}")
        print(f"     读取结论：{r['outcome_label']}　{arrow} 似然比 ×{r['lr']:.2f}　后验 {r['posterior_before']:.3f} → {r['posterior_after']:.3f}")
    v = t["verdict"]
    name, color = LABEL[v["label"]]
    print(c(f"\n  判定：{name}（后验 {v['posterior']:.3f}，花费 {v['cost_spent']:g}）", color))
    print(f"  {v['summary']}")
    for act in t["actions"]:
        print(f"  · {act['name']} —— {act['status']}")


def cmd_triage(args) -> None:
    reader = make_reader(args.reader, seed=args.seed, base_url=args.base_url, model=args.model, api_key=args.api_key)
    engine = Engine(reader=reader)
    t = engine.start(args.alert_id, strategy=args.strategy, budget=args.budget, approval_mode="interrupt", seed=args.seed)
    print_trace(t)
    if t["status"] == "awaiting_approval":
        decisions = {}
        for a in t["pending"]:
            if args.approve == "ask" and sys.stdin.isatty():
                ans = input(f"\n  是否批准「{a['name']}」？[y/N] ").strip().lower()
                decisions[a["id"]] = "approve" if ans == "y" else "reject"
            else:
                decisions[a["id"]] = "approve" if args.approve == "all" else "reject"
        t = engine.approve(t["run_id"], decisions, by=args.by)
        print()
        for act in t["actions"]:
            print(f"  · {act['name']} —— {act['status']}")
    print("\n" + t["report"]["markdown"])
    if args.json:
        Path(args.json).write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")
        print(c(f"\n调查记录已保存到 {args.json}，可用 probewise verify 独立验证。", "dim"))


def cmd_bench(args) -> None:
    from .bench import format_table, run_bench

    noise = tuple(float(x) for x in args.noise.split(","))
    result = run_bench(noise_levels=noise, seeds=args.seeds, budget=args.budget)
    print(format_table(result))
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


def cmd_verify(args) -> None:
    trace = json.loads(Path(args.trace).read_text(encoding="utf-8"))
    report = verify(trace, KnowledgeBase.load())
    for ch in report["checks"]:
        print(f"  {'✓' if ch['ok'] else '✗'} {ch['name']}：{ch['detail']}")
    print(c("证明有效" if report["ok"] else "证明无效", "green" if report["ok"] else "red"))
    sys.exit(0 if report["ok"] else 1)


def cmd_whatif(args) -> None:
    trace = json.loads(Path(args.trace).read_text(encoding="utf-8"))
    overrides = dict(item.split("=", 1) for item in args.overrides)
    r = whatif(trace, KnowledgeBase.load(), overrides)
    for ch in r["changed"]:
        print(f"  {ch['evidence_id']} {ch['probe']}：{ch['from']} → {ch['to']}")
    print(f"  后验 {r['before']['posterior']:.3f}（{r['before']['label']}）→ {r['after']['posterior']:.3f}（{r['after']['label']}）")
    print(c(f"  {r['note']}", "dim"))


def cmd_serve(args) -> None:
    import uvicorn

    uvicorn.run("probewise.api:app", host=args.host, port=args.port)


def cmd_mcp(args) -> None:
    from .mcp_server import main

    main()


def cmd_export(args) -> None:
    """导出静态演示数据（不依赖后端也能展示）。"""
    from .bench import run_bench

    engine = Engine()
    traces = [engine.start(s["id"], approval_mode="defer") for s in load_scenarios()]
    data = {"traces": traces, "bench": run_bench(seeds=args.seeds)}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    print(f"已导出 {len(traces)} 份调查记录到 {args.out}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="probewise", description="证据驱动的安全告警研判")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="列出演示告警").set_defaults(func=cmd_list)

    t = sub.add_parser("triage", help="调查一条告警")
    t.add_argument("alert_id")
    t.add_argument("--strategy", default="probewise", choices=STRATEGIES)
    t.add_argument("--budget", type=float, default=10)
    t.add_argument("--reader", default="rule", help="rule | noisy:0.2 | llm")
    t.add_argument("--base-url", default="", help="OpenAI 兼容接口，如 http://localhost:11434/v1")
    t.add_argument("--model", default="")
    t.add_argument("--api-key", default="")
    t.add_argument("--approve", default="ask", choices=["ask", "all", "none"])
    t.add_argument("--by", default="analyst")
    t.add_argument("--seed", type=int, default=0)
    t.add_argument("--json", help="保存调查记录")
    t.set_defaults(func=cmd_triage)

    b = sub.add_parser("bench", help="策略对比基准测试")
    b.add_argument("--noise", default="0,0.1,0.2")
    b.add_argument("--seeds", type=int, default=10)
    b.add_argument("--budget", type=float, default=10)
    b.add_argument("--json")
    b.set_defaults(func=cmd_bench)

    v = sub.add_parser("verify", help="独立验证调查记录")
    v.add_argument("trace")
    v.set_defaults(func=cmd_verify)

    w = sub.add_parser("whatif", help="反事实推演，例如 probewise whatif t.json E2=clean")
    w.add_argument("trace")
    w.add_argument("overrides", nargs="+")
    w.set_defaults(func=cmd_whatif)

    s = sub.add_parser("serve", help="启动 API 与 Web 控制台")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)

    sub.add_parser("mcp", help="以 stdio 方式运行 MCP Server").set_defaults(func=cmd_mcp)

    e = sub.add_parser("export-demo", help="导出静态演示数据")
    e.add_argument("out", nargs="?", default="web/data/demo.json")
    e.add_argument("--seeds", type=int, default=10)
    e.set_defaults(func=cmd_export)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
