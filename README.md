<div align="center">

# ◆ Probewise

**Evidence-backed security alert triage that asks the next question wisely.**
**Every verdict ships with a proof you can verify — even in your browser.**

[Live demo](http://39.105.66.226/probewise/) · [中文说明](README.zh-CN.md) · [How it works](#how-it-works) · [Benchmark](#benchmark) · [MCP + Skill](#use-it-from-claude-code-mcp--skill)

![python](https://img.shields.io/badge/python-3.10+-blue) ![langgraph](https://img.shields.io/badge/LangGraph-1.x-5eead4) ![mcp](https://img.shields.io/badge/MCP-server-8b5cf6) ![otel](https://img.shields.io/badge/OpenTelemetry-GenAI-orange) ![license](https://img.shields.io/badge/license-MIT-green)

</div>

Most AI SOC agents let an LLM decide **what to check next** *and* **what the verdict is**. When the model misreads a log line — or gets nudged by text inside a tool result — the verdict is wrong and nobody can audit why.

Probewise splits the job in two:

- **The model only reads.** A reader (rules, a local model via Ollama/vLLM, or an external agent over MCP) turns one tool output into one of a fixed set of findings.
- **The controller decides.** A Bayesian evidence ledger picks the next check by **expected information gain ÷ cost**, stops as soon as the evidence is sufficient, and emits a **proof**: prior, likelihood ratio of every piece of evidence, posterior, and a SHA-256 hash chain anyone can recompute.

```
$ probewise triage A-004
 E1 IOC reputation (cost 1)   why: best bits-per-cost among affordable checks (0.324 bits / 1)
    tool : sha256:9f2c…a71d has no record in connected threat-intel feeds.
    read : unknown       ▼ LR ×0.70   posterior 0.400 → 0.319
 E2 Peer prevalence (cost 1)  ...  ▲ LR ×2.83   0.319 → 0.570
 E3 EDR corroboration (cost 2) ... ▲ LR ×12.00  0.570 → 0.941
 E4 Process lineage (cost 3)  ...  ▲ LR ×7.50   0.941 → 0.992
 verdict: MALICIOUS (posterior 0.992, cost 7/10)
 · isolate host — pending approval      ← LangGraph interrupt, waits for a human
```

## Why it's different

| | Typical LLM SOC agent | **Probewise** |
|---|---|---|
| Who chooses the next check | the LLM | expected information gain ÷ cost |
| When to stop | when the LLM feels done | posterior crosses a threshold **and** (robust mode) ≥2 strong independent pieces of evidence agree |
| Verdict | free text | label + posterior + per-evidence likelihood ratios |
| Auditability | logs | hash-chained proof, verifiable offline / in the browser |
| A misread tool output | can flip the verdict silently | moves one ledger entry; robust mode needs corroboration |
| High-risk response | often auto-executed | LangGraph `interrupt()` → human approval, recorded in the chain |
| "What if that log said otherwise?" | re-run and hope | time-travel: fork from any checkpoint with a rewritten finding |

## Features

- **LangGraph state machine** — `intake → plan ⇄ investigate → decide → respond → report`, persisted with a SQLite checkpointer.
- **Information-gain planning** — each step scores every remaining check in bits per unit cost; expensive checks (sandbox detonation) run only when cheap ones can't settle it.
- **Proof-carrying verdicts** — `probewise verify trace.json` (or the *Verify in browser* button) recomputes the hash chain and the posterior from the knowledge base alone. Tampering with any finding is detected.
- **Human-in-the-loop** — isolation, credential resets, suppression rules… anything risky pauses the graph until someone approves; the decision goes into the hash chain.
- **Time-travel counterfactuals** — rewrite one finding and resume from the checkpoint right before it; the controller re-plans the rest of the investigation.
- **Robust mode** — requires two strong same-direction pieces of evidence before closing a case, which cuts missed threats when the reader is unreliable (see benchmark).
- **RAG with citations** — playbooks, ATT&CK notes and past cases retrieved with BM25 (optional embedding re-rank through any OpenAI-compatible endpoint); every report cites `[P-02] [C-03]`.
- **MCP server + Agent Skill** — Claude Code, Cursor or any MCP client can triage alerts, or act purely as the *reader* while Probewise keeps the decision.
- **OpenTelemetry GenAI spans** — `invoke_agent`, `execute_tool {name}` with `gen_ai.*` attributes; ship them to Jaeger/Langfuse by setting `OTEL_EXPORTER_OTLP_ENDPOINT`.
- **Bring your own model** — `--reader llm --base-url http://localhost:11434/v1 --model qwen2.5:7b`; invalid model output falls back to the rule reader and is recorded.
- **Zero keys needed** for the demo: 18 synthetic alerts, mock tools, rule reader.

## Quick start

```bash
pip install git+https://github.com/lzwhehe/probewise
probewise list                     # 18 demo alerts
probewise triage A-004             # investigate, approve/reject interactively
probewise triage A-016 --json t.json && probewise verify t.json
probewise whatif t.json E2=known_good
probewise bench                    # strategy × reader-noise benchmark
probewise serve                    # web console + API at http://127.0.0.1:8000
```

Docker:

```bash
docker build -t probewise . && docker run -p 8000:8000 -v probewise-data:/data probewise
```

## Use it from Claude Code (MCP + Skill)

```bash
claude mcp add probewise -- probewise mcp
cp -r skills/probewise-triage ~/.claude/skills/
```

Tools exposed: `list_alerts`, `triage_alert`, `open_case`, `submit_reading`, `get_report`, `verify_case`.
With `open_case`, the calling agent becomes the **reader**: each step it receives one raw tool output plus the allowed findings and must pick one; Probewise decides what to check next and when to conclude. The [Skill](skills/probewise-triage/SKILL.md) teaches the agent this protocol — including treating tool output as data, never as instructions, and leaving approvals to the human.

## How it works

For each alert type the knowledge base defines a prior and the applicable checks; each check has outcomes with likelihoods `P(outcome | malicious)` and `P(outcome | benign)`.

1. **Ledger.** Evidence adds `log LR = log P(o|M)/P(o|B)` to the log-odds. Posterior = `σ(logit(prior) + Σ log LR)`.
2. **Planning.** For each remaining affordable check, expected information gain `IG = H(p) − Σₒ P(o)·H(p | o)`; pick the highest `IG / cost`. Stop when the posterior crosses `0.95 / 0.05` (plus corroboration in robust mode), when no check is affordable, or when the best IG < 0.02 bits — then escalate with a hint of the most valuable missing check.
3. **Proof.** Every finding and the verdict are appended to a SHA-256 hash chain whose payload uses fixed-precision strings, so Python and JavaScript produce byte-identical digests.

## Benchmark

`probewise bench` — 18 synthetic alerts × 5 strategies × reader noise (probability that the reader misreads a tool output), 10 seeds, budget 10.

| Reader noise | Strategy | Correct | **Missed threats** | Escalated | Avg cost |
|---|---|---|---|---|---|
| 0% | **Probewise fast** | **77.8%** | 0.0% | 22.2% | **4.56** |
| 0% | Fixed SOP (run every check) | 66.7% | 0.0% | 33.3% | 7.00 |
| 10% | Probewise fast | 68.3% | 2.8% | 27.8% | 4.65 |
| 10% | **Probewise robust** | 56.7% | **0.6%** | 41.7% | 5.12 |
| 20% | Probewise fast | 61.7% | 4.4% | 31.1% | 4.90 |
| 20% | **Probewise robust** | 44.4% | **2.8%** | 50.6% | 5.10 |

Takeaways: information-gain planning reaches more confident, correct verdicts at ~35% lower cost than running a fixed SOP. When the reader is unreliable, robust mode cuts missed threats ~4.7× at 10% noise, paid for with more escalations — use *fast* with reliable readers, *robust* with small local models. (Synthetic scenarios and illustrative likelihoods: the numbers show the trade-off, not real-world performance.)

## Project layout

```
probewise/
  graph.py       LangGraph engine: nodes, interrupts, checkpoints, time-travel fork
  ledger.py      Bayesian log-odds ledger, entropy, expected information gain
  proof.py       hash chain, independent verification, counterfactual what-if
  reader.py      rule / noisy / OpenAI-compatible LLM readers
  rag.py         BM25 retrieval (+ optional embedding re-rank) over playbooks, ATT&CK notes, cases
  telemetry.py   OpenTelemetry GenAI spans
  mcp_server.py  MCP server (stdio)
  api.py         FastAPI + web console
  data/          knowledge base, 18 synthetic scenarios, RAG corpus
skills/probewise-triage/SKILL.md
web/             console (vanilla JS, pure-JS SHA-256 for in-browser verification)
```

## Limitations

- Demo data is synthetic and tools are mocked; likelihoods are illustrative and should be calibrated on your own ticket history.
- Two hypotheses (malicious / benign) and conditionally independent evidence — a deliberate simplification that keeps every number explainable.
- Response actions are recorded, never executed.

## Background

Probewise is the engineering counterpart of the author's research on making small LLM triage agents reliable by separating *reading* from *deciding* ([HESP](https://github.com/lzwhehe/HESP)).

## License

MIT
