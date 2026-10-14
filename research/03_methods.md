# 03 — Methods survey: reliable, auditable LLM-agent SOC triage

Compiled 2026-10-14. About 22 searches and fetches. "[unverified]" marks figures I saw only in secondary sources or could not check against the primary text.

Design under review: a deterministic EIG/cost controller works over a Bayesian evidence ledger. The LLM only classifies tool output into fixed outcomes. LangGraph handles checkpoints and human approval. Planned additions: (a) read-only specialist sub-agents, (b) likelihoods learned from tickets, (c) dedup, clustering and prioritization, (d) ticketing and analyst feedback.

---

## 1. Supervisor-worker patterns and constraining workers

**Sources**
- **Anthropic, "How we built our multi-agent research system"** (2025-06-13). https://www.anthropic.com/engineering/multi-agent-research-system
  - Uses an orchestrator-worker design. A lead agent with Opus 4 and Sonnet 4 subagents beat a single Opus 4 agent by 90.2% on Anthropic's internal eval.
  - The cost is high: about 15x the tokens of chat. Token use alone explained about 80% of the variance on BrowseComp.
  - Each delegation must state an **objective, output format, tools/sources and task boundaries**. Vague briefs caused duplicated work.
  - Effort-scaling rules: 1 agent with 3–10 calls for simple tasks, 2–4 subagents for comparisons.
  - A separate **CitationAgent** attributes claims after the research is done.
  - Subagents write outputs to external storage and pass references back.
  - Uses checkpoints and resume.
  - Failure modes seen: 50 subagents spawned for simple queries, and endless searches for sources that do not exist.
- **Anthropic, "Building effective agents"** (2024-12-19). https://www.anthropic.com/engineering/building-effective-agents
  - Distinguishes *workflows*, which follow predefined code paths, from *agents*. Patterns include orchestrator-workers and evaluator-optimizer.
  - Advice: use the simplest thing that works. I relied on prior knowledge for this source and did not re-fetch it this session.
- **LangChain/LangGraph.**
  - `langgraph-supervisor` is no longer actively maintained. The docs now recommend the **subagents pattern**: a main agent calls workers as tools (https://docs.langchain.com/oss/python/migrate/langgraph-supervisor.md, undated).
  - Subagents are stateless by default (isolated context) and can run in parallel. They can `interrupt` for human approval, but **`get_state(subgraphs=True)` cannot see subagent state when the subagent is called inside a tool** (https://docs.langchain.com/oss/python/langchain/multi-agent/subagents, undated).
  - The `Send` API does runtime fan-out and map-reduce with a per-branch state that differs from the parent state. I took this from community and mirror docs, so verify it against the official Graph API reference.
- **OpenAI Agents SDK** (https://openai.github.io/openai-agents-python/agents/).
  - *Handoffs* transfer control; *agents-as-tools* keep the manager in charge.
  - `output_type` forces structured final output.
  - Input, output and tool guardrails can trip and halt a run.
  - Exact semantics came partly from secondary sources [partly unverified].
- **Google A2A** (announced 2025-04; now under the Linux Foundation).
  - Provides Agent Cards (`/.well-known/agent-card.json`), a Task lifecycle (submitted, working, input-required, completed, failed, …) and JSON-RPC, gRPC and REST bindings.
  - The current version (v0.3 vs v1.0) is inconsistent across sources [unverified]. https://github.com/a2aproject/A2A, https://tyk.io/learning-center/a2a-protocol-architecture-and-technical-specification/

**Recommendations**
1. Implement each sub-agent as a **LangGraph subgraph node**, not as a tool inside an LLM agent. That keeps checkpoint and state visibility (`get_state(subgraphs=True)`) and lets the deterministic controller stay the "supervisor". Use `Send` only when the controller explicitly picks several checks to run in parallel.
2. Give every worker a fixed contract:
   - `{check_id, outcome ∈ enum, confidence, evidence:[{source, query_or_url, retrieved_at, raw_ref, excerpt_span}], cost}`, validated by Pydantic.
   - Hard budgets: max tool calls, wall-clock time and tokens. These address the "50 subagents" failure.
   - Allowlisted read-only tools under per-worker credentials, i.e. least privilege: TI API keys and a SIEM role with no write or delete.
3. Store raw tool output content-addressed (hash) outside the LLM context and pass references, as Anthropic does. The ledger cites hashes, which gives auditability.
4. A2A and handoffs are **not needed** inside one process. Consider A2A only if a worker becomes a separately deployed service.

## 2. Making sub-agent findings verifiable, and injection defense

**Sources**
- **CaMeL** (Debenedetti et al., arXiv 2503.18813, 2025-03).
  - Extends Willison's **Dual-LLM** pattern (2023-04). A privileged LLM plans code from the trusted query only. A quarantined LLM parses untrusted data into a schema and has no tools.
  - An interpreter tracks provenance and capabilities and blocks disallowed data flows.
  - Reported 67% (later version 77%) of AgentDojo tasks solved with provable security [version discrepancy].
  - Limitation: tasks whose plan depends on untrusted data.
  - https://simonw.substack.com/p/camel-offers-a-promising-new-direction
- **Spotlighting** (Hines et al., Microsoft, arXiv 2403.14720, 2024-03).
  - Variants: delimiting, **datamarking** and **encoding**. Datamarking costs little task accuracy; encoding works best but needs strong models.
  - A ">50% → <2% ASR" figure circulates in blogs [unverified].
  - https://arxiv.org/html/2403.14720v1
- **OWASP Top 10 for Agentic Applications 2026** (published 2025-12-09; categories ASI01–ASI10). Covers goal hijack, tool misuse, identity/privilege, supply chain, code execution, memory poisoning, inter-agent communication, cascading failures, human-agent trust and rogue agents.
  - Category names come from secondary summaries; the official PDF is behind the download link.
  - https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026
  - Apply it together with the OWASP LLM Top 10 (LLM01 Prompt Injection etc.).
- **LLM-as-judge pitfalls**: position, verbosity and self-preference biases; 12 bias types are catalogued (CALM). Surveys: https://arxiv.org/pdf/2411.15594, https://arxiv.org/pdf/2410.21819
- **Self-consistency**: majority vote lowers variance but cannot fix a model whose modal answer is wrong. Reliability depends on the margin between the top two answers (https://arxiv.org/html/2510.17472v1).

**Recommendations**
1. Your current split is already a Dual-LLM / CaMeL-lite design. The controller is deterministic and never reads raw text; the LLM only maps text to an enum.
   - Keep the **sub-agent's planning** (pivoting, writing SIEM queries) from seeing raw tool output where possible.
   - Where pivoting must depend on data, as in TI pivots, restrict it to **typed values extracted by schema**: IP, domain, hash, regex-validated. Never pass free text.
   - Tag every value with provenance, in CaMeL style.
2. Apply **datamarking** to all tool output shown to the classifier LLM. Strip or neutralise markdown links and HTML from it.
3. **Verifiability**:
   - (a) Each outcome must cite an `excerpt_span` that a deterministic check confirms exists verbatim in the stored raw output; reject the outcome if not.
   - (b) For high-impact outcomes (those that flip the posterior across a decision threshold), run an **independent re-read**: a different model, or a fresh context, given only the raw evidence and the fixed outcome enum, with no sight of the first verdict. Disagreement → `inconclusive` → human.
   - (c) Use self-consistency (k=3–5) only on the classifier, and record the vote margin as a confidence input to the ledger.
4. Do not use an LLM judge from the same model family to grade production verdicts. Use judges only for offline eval, calibrated against analyst labels, with order randomization.
5. Threat-model doc: map controls to ASI01–ASI10 explicitly. This is cheap and shows reviewers you understand agent threats.

## 3. NL-to-query for security data

**Sources**
- **NL2KQL** (Microsoft, arXiv 2404.02933, v4 2025-01-17).
  - Pipeline: Schema Refiner (prunes the schema to relevant tables and columns), dynamic few-shot selector, and a Query Refiner that repairs errors using the KQL parser.
  - Offline: syntax 0.988, semantic 0.960, table match 0.822, filter-column 0.699.
  - Online execution (Avg Exec): **0.635 vs 0.232** for GPT-4 with a KQL guide and 0.115 without.
  - Execution correctness is far below syntax correctness.
  - https://arxiv.org/html/2404.02933v4
- **Elastic text-to-ES|QL benchmark** (Search Labs, date not verified). On 500 BIRD questions the best model returned the right rows 59% of the time single-shot, given index mappings. Errors were join keys, guessed literal values and SQL-isms. https://www.elastic.co/search-labs/blog/text-to-esql-benchmark
- **SynRAG** (arXiv 2512.24571, 2025-12): cross-SIEM (QRadar AQL, SecOps). Reports only BLEU 0.129 and ROUGE-L 0.604, lexical metrics that are weak evidence. https://arxiv.org/pdf/2512.24571
- **arXiv 2604.27321** (2026): AQL/YARA-L generation; best BLEU 0.149, many syntax and field errors.
- **Splunk AI Assistant for SPL**: retrieval of SPL examples improves parseability (vendor blog). https://www.splunk.com/en_us/blog/artificial-intelligence/technical-review-of-splunk-ai-assistant-for-spl.html
- **OCSF** (Linux Foundation project). v1.5.0 has about 74 event classes and 157 objects (https://docs.tenzir.com/reference/ocsf). Browser: https://schema.ocsf.io

**Recommendations**
1. Do **not** let the log-search worker write free-form queries by default. Use a tiered approach:
   - (i) a **parameterised query template library** per check (the EIG controller already knows which check it wants), filled with typed IOCs;
   - (ii) NL-to-query only as a fallback, NL2KQL-style: schema pruning, retrieved few-shot examples, parser validation and repair loop, plus a `| take N` / time-bound guard and a dry-run cost estimate.
2. Normalise the evidence layer to **OCSF** (or ECS) field names. Templates and likelihood features then become backend-agnostic. Generate per-backend SQL/KQL/SPL from the OCSF field map.
3. Evaluate query workers on **execution match** (row/column sets vs a gold query), not BLEU.

## 4. Learning from historical tickets; dedup, clustering and RBA

**Sources**
- **GUIDE dataset** (Microsoft, arXiv 2407.09017, CGR paper, 2024).
  - 13M evidence items, 1.6M alerts, 1M incidents, with **TruePositive / BenignPositive / FalsePositive** triage labels from customer analysts.
  - License stated as **CDLA-Permissive-2.0** (paper says "CDLA-2.0"; check the Kaggle data card).
  - https://arxiv.org/abs/2407.09017
- **DeepCASE** (van Ede et al., IEEE S&P 2022).
  - Clusters correlated event *sequences*; analysts set one policy per cluster.
  - Reports 86.72% of events auto-filtered and a 90.53% workload reduction, with <0.001% risk underestimation (author-reported).
  - https://gangw.cs.illinois.edu/class/cs562/papers/DeepCASE-sp22.pdf
- **TESSERACT** (Pendlebury et al., USENIX Security 2019). Random train/test splits inflate security ML results. Requires **temporal splits** and measures time decay; active learning helps. https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury
- **Label quality.** Analyst TP/FP comments are often vague or conditional, and noisy labels hurt accuracy (arXiv 2208.12729). https://arxiv.org/pdf/2208.12729
- **Splunk RBA** (ES 7.x docs).
  - Detections emit *risk events* with scores on an entity. A notable fires when the summed score crosses a threshold.
  - Thresholds can be tuned by distinct detection count and tactic count; entity zones avoid spurious aggregation.
  - Vendor claim: 50–90% fewer alerts [vendor, unverified].
  - https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/best-practices/adjust-the-risk-threshold-to-avoid-high-alert-volume

**Recommendations**
1. **Likelihood table** P(outcome | hypothesis, check). Estimate each cell as a **Dirichlet/Beta posterior mean**: counts plus an expert prior of pseudo-count n₀ ≈ 5–20, set from the current hand-written table. This is naive Bayes with smoothing.
   - It stays interpretable and degrades gracefully with few tickets.
   - Keep the expert table as the prior so that zero-count cells never yield 0 or 1.
2. Naive Bayes assumes checks are conditionally independent, but many are correlated (e.g. two TI feeds sharing upstream data). Mitigations: merge correlated checks into one node, or fit a **logistic regression** on outcome indicators as a calibration layer. Report the calibration of the posterior (reliability diagram, Brier score).
3. **Drift**: retrain on a rolling window and always evaluate on a *later* time slice (TESSERACT). Alarm when per-cell posterior shift or calibration error exceeds a bound. Weight recent tickets with exponential decay.
4. **Labels**: map ticket closures to {TP, BP, FP} like GUIDE. Exclude tickets closed without a reason, or down-weight them.
5. **Dedup and clustering**:
   - Fingerprint by (rule_id, normalised entity set, time bucket) for exact dedup.
   - Then cluster at entity level in RBA style: accumulate risk per user/host over a window, investigate the *entity* rather than each alert, and reuse ledger evidence across alerts in the cluster.
   - DeepCASE-style sequence clusters with analyst policies are a good later step.
6. **Queue priority** = posterior P(malicious) × asset criticality × (1 − already-investigated), with an RBA-like threshold for auto-escalation.

## 5. Evaluation metrics and datasets

**Metrics to report**, each with a CI and a temporal holdout:
- Missed-threat rate: FN among TP-labelled alerts. This is the primary safety metric; report it at a fixed escalation budget.
- Escalation rate and auto-close rate.
- Precision of auto-close.
- Calibration: Brier score, ECE.
- Checks per alert and cost per alert: tokens plus API calls in $.
- Time-to-verdict, and analyst time saved (needs a user study or logged handle time; otherwise label it "estimated").
- Injection robustness: attack success rate on injected tool output.
- Evidence-citation validity rate.

**Datasets**

| Dataset | Use | License |
|---|---|---|
| **GUIDE** (Microsoft, 2024) | Learn and evaluate likelihoods and triage grades (TP/BP/FP) | CDLA-Permissive-2.0 (verify on data card) |
| **Splunk BOTS v1–v3** | End-to-end investigation with Q&A ground truth; SPL query workers | CC0-based per Splunk; v3 by email request, v2 GitHub lists CC0-1.0 (https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html) |
| **OTRF Security-Datasets (Mordor)** | ATT&CK-mapped attack telemetry for log-search workers | **Inconsistent**: GitHub sidebar MIT, README says GPL-3.0. Check LICENSE before redistributing (https://github.com/OTRF/Security-Datasets) |
| **ExCyTIn-Bench** (Microsoft, arXiv 2507.14201, ICML 2026) | Agentic investigation over 57 Sentinel-style tables, 7,542 questions; best model reward 0.606 | Open source on GitHub; license not verified |
| **CyberSOCEval** (Meta + CrowdStrike, 2025-09) | Malware-analysis and TI-reasoning sub-skills (609 + 588 Qs) | Open source; license not verified. Reported 15–28% / 43–53% accuracy [unverified] |
| **AgentDojo** | Prompt-injection robustness of the tool loop | (used by CaMeL; license not checked) |

**Recommended eval plan**
1. GUIDE with a temporal split: likelihood learning, calibration, and missed-threat rate vs escalation-rate curves.
2. BOTS / ExCyTIn: end-to-end investigations, checks per alert, cost, and query execution accuracy.
3. Mordor: log-search worker template coverage.
4. An injection suite built from AgentDojo-style payloads planted in TI and log fields. Measure ASR with and without datamarking and evidence-span checks.
5. Run an ablation of *deterministic EIG controller vs LLM-chosen next step* at equal budget. This is the experiment that justifies the architecture.

## Summary of design decisions

- Sub-agents become **typed subgraphs** with budgets, read-only scoped credentials and a strict output schema. Raw output is stored by hash.
- Pivots use only **schema-extracted typed values**. Classifier input is datamarked. Verbatim **evidence-span** checks are mandatory, and an **independent re-read** runs on decision-flipping outcomes.
- SIEM access goes through **templates first**, with an NL2KQL-style validated fallback, over OCSF-normalised fields.
- Likelihoods use **Dirichlet-smoothed counts with expert priors**, temporal retraining and calibration monitoring.
- Alerts are grouped into **entity-level RBA-style clusters** before investigation.
- Evaluation runs on GUIDE + BOTS + ExCyTIn, plus an injection suite, with missed-threat rate at a fixed escalation budget as the headline metric.

**Unverified or flagged**: the LangGraph `Send` details (community sources); the current A2A version; OWASP ASI category names; the spotlighting ">50%→<2%" figure; the CaMeL 67%/77% version discrepancy; CyberSOCEval accuracy ranges; Splunk's 50–90% reduction claim; the GUIDE license wording; the OTRF license conflict; the date of the Elastic benchmark post. "Building effective agents" content was from memory and was not re-fetched this session.
