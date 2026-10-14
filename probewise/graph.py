"""Probewise 的 LangGraph 状态图。

    接收（RAG 检索）→ 规划（信息增益 / 成本）⇄ 调查（调用工具 → 读取 → 记账）
                        ↓ 满足停止条件
                      判定（附证明）→ 响应（高危动作 interrupt 等人工审批）→ 报告（带引用）

设计要点：
- 读判分离：读取器（规则或大模型）只把工具输出读成一个结论选项；查什么、查到什么时候、
  下什么判定，全部由控制器按账本决定。
- 每一步都是一个 checkpoint，可以持久化、回放，也可以从任意一步分叉改写证据（反事实重查）。
- 每个判定都附带哈希链证明，可以离线独立验证。
"""

from __future__ import annotations

import math
import random
import uuid
from typing import Optional, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

import json

from .kb import DATA_DIR, KnowledgeBase, find_scenario, load_scenarios
from .netalert.checks import run_check
from .netalert.fields import sanitize
from .netalert.history import TicketHistory
from .netalert.verify import verify_finding
from .ledger import entropy, expected_info_gain, logit, sigmoid
from .proof import GENESIS, chain_record, fmt, supporting_count, verdict_label
from .rag import Retriever
from .reader import RuleReader
from .telemetry import RunTracer
from .tools import MockToolkit

MIN_INFO_GAIN = 0.02  # 比特：剩余检查都低于这个值时，再查也改变不了结论
PLAYBOOK_OF = {
    "suspicious_login": "P-01",
    "malware_execution": "P-02",
    "beaconing": "P-03",
    "privileged_account_change": "P-04",
    "bulk_upload": "P-05",
    "office_child_process": "P-06",
    "web_attack": "P-07",
}
WEB = "web_attack"
STRATEGIES = ("probewise", "probewise-robust", "playbook", "cheapest", "random")
STRATEGY_NAMES = {
    "probewise": "Probewise 快速（信息增益 / 成本）",
    "probewise-robust": "Probewise 稳健（+ 强证据交叉印证）",
    "playbook": "固定 SOP（全部检查跑一遍）",
    "cheapest": "便宜优先",
    "random": "随机顺序",
}


class TriageState(TypedDict, total=False):
    run_id: str
    alert: dict
    strategy: str
    budget: float
    budget_left: float
    seed: int
    approval_mode: str  # interrupt | defer
    corroboration: int  # 结案前至少需要几条同方向的证据
    reader_mode: str  # auto：内置读取器；external：由外部 Agent（如 Claude Code 经 MCP）读取
    world_overrides: dict
    prior: float
    z: float  # 未校准的对数几率：logit(先验) + Σ 各证据的对数似然比
    posterior: float
    used: list
    rounds: list
    chain: list
    context: list
    plan: dict
    next_probe: Optional[str]
    stop_reason: str
    verdict: dict
    actions: list
    approvals: list
    report: dict


def supporting(rounds: list, label: str) -> int:
    """与判定方向一致的强证据条数（规则见 proof.supports）。"""
    return supporting_count([r["lr"] for r in rounds], label)


def public_alert(scenario: dict, kb: KnowledgeBase) -> dict:
    """去掉 world 和 ground_truth：调查引擎只能看到告警本身。"""
    t = kb.alert_types[scenario["type"]]
    keep = ("id", "type", "severity", "time", "title", "summary", "entities")
    out = {**{k: scenario[k] for k in keep}, "type_name": t["name"], "mitre": t["mitre"]}
    if scenario.get("record"):
        # 原始告警记录供分析员查看；检查子 Agent 只用去掉采集伪特征后的视图，标签不进入引擎
        out["record"] = sanitize(scenario["record"])  # 证据偏移量正是在这个视图上计算的
    return out


class Engine:
    def __init__(self, kb: KnowledgeBase | None = None, scenarios: list[dict] | None = None, reader=None, checkpointer=None, retriever=None):
        self.kb = kb or KnowledgeBase.load()
        self.scenarios = scenarios or load_scenarios()
        self.reader = reader or RuleReader()
        self.retriever = retriever or Retriever()
        self.checkpointer = checkpointer if checkpointer is not None else InMemorySaver()
        self._maybe_enable_llm_review()
        hist_file = DATA_DIR / "web_history.json"
        self.web_history = TicketHistory.from_json(json.loads(hist_file.read_text(encoding="utf-8"))) if hist_file.exists() else TicketHistory()
        org_file = DATA_DIR / "demo_org_history.json"
        if org_file.exists():  # 本单位自己的工单历史（演示用模拟数据），叠加在通用的规则历史之上
            for kind, value, att, tot in json.loads(org_file.read_text(encoding="utf-8"))["counts"]:
                c = self.web_history.counts[(kind, value)]
                c[0] += att
                c[1] += tot
        self.spans: dict[str, list] = {}
        self._tracers: dict[str, RunTracer] = {}
        self.graph = self._build()

    def _maybe_enable_llm_review(self) -> None:
        """配置了 OpenAI 兼容接口（如本地 Ollama）时，为网络攻击告警加上「大模型复核」子 Agent。
        它成本高（4），只有便宜的检查都定不下来时，按信息增益 / 成本才会被选中。"""
        import os

        from .netalert.checks import CHECKS
        from .netalert.llm_agent import OUTCOMES, LLMReviewAgent

        self.checks = dict(CHECKS)  # 每个引擎自己的检查集合，不改模块级注册表
        base, model = os.environ.get("PROBEWISE_LLM_BASE_URL"), os.environ.get("PROBEWISE_LLM_MODEL")
        if not (base and model) or WEB not in self.kb.alert_types:
            return
        self.kb.alert_types[WEB] = {**self.kb.alert_types[WEB], "probes": list(self.kb.alert_types[WEB]["probes"])}
        self.checks["llm_review"] = LLMReviewAgent(base, model, os.environ.get("PROBEWISE_LLM_API_KEY", ""))
        self.kb.probes["llm_review"] = {"name": f"大模型复核（{model}，似然未经校准）", "cost": 4, "outcomes": {k: dict(v) for k, v in OUTCOMES.items()}}
        if "llm_review" not in self.kb.alert_types[WEB]["probes"]:
            self.kb.alert_types[WEB]["probes"].append("llm_review")

    # ---------- 节点 ----------

    def _calibrated(self, alert_type: str, z: float) -> float:
        c = self.kb.platt(alert_type)
        return sigmoid(c["a"] * z + c["b"])

    def _benign_guard(self, state) -> bool:
        """网络攻击告警自动判误报的护栏：必须看过载荷且没有明确利用载荷，并至少做过 2 项检查。
        防止攻击者先把某条规则「刷」成历史误报，再发真正的利用（反馈投毒）。"""
        if state["alert"]["type"] != WEB:
            return True
        payload = next((r for r in state["rounds"] if r["probe"] == "payload_check"), None)
        return payload is not None and payload["outcome"] != "explicit_exploit" and len(state["rounds"]) >= 2

    def _tracer(self, state: TriageState) -> RunTracer:
        return self._tracers[state["run_id"]]

    def intake(self, state: TriageState) -> dict:
        with self._tracer(state).span("chain intake", **{"probewise.node": "intake"}):
            alert = state["alert"]
            t = self.kb.alert_types[alert["type"]]
            query = " ".join([alert["title"], alert["summary"], t["name"], *[m["name"] for m in t["mitre"]]])
            must = [PLAYBOOK_OF[alert["type"]], *[m["id"] for m in t["mitre"]]]
            context = self.retriever.search(query, k=6, must_include=must)
            prior = t["prior"]
            rec = chain_record(0, "alert", {"alert_id": alert["id"], "type": alert["type"], "prior": fmt(prior)}, GENESIS)
            return {
                "prior": prior,
                "z": logit(prior),
                "posterior": self._calibrated(alert["type"], logit(prior)),
                "budget_left": state["budget"],
                "used": [],
                "rounds": [],
                "chain": [rec],
                "context": context,
                "approvals": [],
                "world_overrides": state.get("world_overrides", {}),
            }

    def plan(self, state: TriageState) -> dict:
        with self._tracer(state).span("chain plan", **{"probewise.node": "plan", "probewise.posterior": state["posterior"]}):
            p = state["posterior"]
            strategy = state["strategy"]
            label = verdict_label(p, self.kb.thresholds)
            if strategy != "playbook" and label != "escalate":
                need = state.get("corroboration", 1)
                response_done = state["alert"]["type"] != WEB or "response_check" in state["used"] or "response_check" not in self.kb.probes_for(WEB)
                if supporting(state["rounds"], label) >= need and (label != "benign" or self._benign_guard(state)) and (label != "malicious" or response_done):
                    return {"next_probe": None, "stop_reason": "后验已越过判定阈值，且有足够的同方向证据", "plan": {}}

            candidates = []
            for probe in self.kb.probes_for(state["alert"]["type"]):
                if probe in state["used"]:
                    continue
                info = self.kb.probes[probe]
                ig = expected_info_gain(p, info["outcomes"])
                candidates.append(
                    {
                        "probe": probe,
                        "name": info["name"],
                        "cost": info["cost"],
                        "info_gain": round(ig, 4),
                        "score": round(ig / info["cost"], 4),
                        "affordable": info["cost"] <= state["budget_left"],
                    }
                )
            affordable = [c for c in candidates if c["affordable"]]
            if not affordable:
                reason = "预算已用完" if candidates else "可用的检查都已执行"
                return {"next_probe": None, "stop_reason": reason, "plan": {"candidates": candidates}}

            guard_payload = next((c for c in affordable if c["probe"] == "payload_check"), None)
            guard_response = next((c for c in affordable if c["probe"] == "response_check"), None)
            if strategy.startswith("probewise") and label == "malicious" and guard_response and state["alert"]["type"] == WEB:
                chosen = guard_response
                why = "已经足以判定为攻击；结案前再看一眼响应，确认攻击是否成功（决定要不要启动应急响应）"
            elif strategy.startswith("probewise") and label == "benign" and guard_payload and not self._benign_guard(state):
                chosen = guard_payload
                why = "可疑度已经低于误报阈值，但结案为误报之前必须先核验载荷（防反馈投毒的护栏）"
            elif strategy.startswith("probewise"):
                chosen = max(affordable, key=lambda c: c["score"])
                if chosen["info_gain"] < MIN_INFO_GAIN:
                    return {
                        "next_probe": None,
                        "stop_reason": f"剩余检查的信息增益都低于 {MIN_INFO_GAIN} 比特，再查也难以改变结论",
                        "plan": {"candidates": candidates},
                    }
                why = f"在可负担的检查中，「{chosen['name']}」每单位成本能消除的不确定性最多（{chosen['info_gain']:.3f} 比特 / 成本 {chosen['cost']}）"
            elif strategy == "playbook":
                chosen = affordable[0]
                why = "按固定 SOP 的顺序执行下一项检查"
            elif strategy == "cheapest":
                chosen = min(affordable, key=lambda c: c["cost"])
                why = "选择成本最低的检查"
            else:
                rng = random.Random(state.get("seed", 0) * 1000 + len(state["used"]))
                chosen = rng.choice(affordable)
                why = "随机选择一项检查"

            for c in candidates:
                c["chosen"] = c["probe"] == chosen["probe"]
            candidates.sort(key=lambda c: -c["score"])
            return {"next_probe": chosen["probe"], "plan": {"candidates": candidates, "why": why, "uncertainty_bits": round(entropy(p), 4)}}

    def investigate(self, state: TriageState) -> dict:
        probe = state["next_probe"]
        info = self.kb.probes[probe]
        tracer = self._tracer(state)
        scenario = find_scenario(self.scenarios, state["alert"]["id"])
        overrides = state.get("world_overrides") or {}
        if overrides:
            scenario = {**scenario, "world": {**scenario["world"], **overrides}}

        finding, verification = None, None
        if state["alert"]["type"] == WEB:
            reading, raw, finding, verification = self._investigate_web(state, probe, info, scenario, overrides, tracer)
        else:
            with tracer.span(
                f"execute_tool {probe}",
                **{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": probe, "gen_ai.tool.type": "function", "probewise.cost": info["cost"]},
            ) as span:
                raw = MockToolkit(scenario, self.kb).run(probe)
                if state.get("reader_mode") == "external":
                    # 外部 Agent 只负责「读」：把工具输出读成一个结论选项，判定权留在账本里
                    options = {k: o["label"] for k, o in info["outcomes"].items()}
                    answer = interrupt({"type": "reading", "probe": probe, "probe_name": info["name"], "raw_text": raw["text"], "options": options})
                    if answer.get("outcome") not in options:
                        raise ValueError(f"外部读取结果 {answer.get('outcome')!r} 不在选项中")
                    reading = {"outcome": answer["outcome"], "reader": answer.get("reader", "external")}
                else:
                    reading = self.reader.read(probe, raw, self.kb)
                span.set_attribute("probewise.reader", reading["reader"])
                span.set_attribute("probewise.outcome", reading["outcome"])

        o = self.kb.outcome(probe, reading["outcome"])
        delta = 0.0 if reading.get("unverified") else self.kb.llr(probe, reading["outcome"])
        lr = math.exp(delta)
        before = state["posterior"]
        z = state.get("z", logit(state["prior"])) + delta
        after = self._calibrated(state["alert"]["type"], z)
        rounds = list(state["rounds"])
        eid = f"E{len(rounds) + 1}"
        chain = list(state["chain"])
        chain.append(
            chain_record(
                len(chain),
                "evidence",
                {"evidence_id": eid, "probe": probe, "outcome": reading["outcome"], "lr": fmt(lr), "posterior": fmt(after), **({"unverified": 1} if reading.get("unverified") else {})},
                chain[-1]["hash"],
            )
        )
        rounds.append(
            {
                "round": len(rounds) + 1,
                "evidence_id": eid,
                "probe": probe,
                "probe_name": info["name"],
                "cost": info["cost"],
                "outcome": reading["outcome"],
                "outcome_label": o["label"],
                "raw_text": raw["text"],
                "reader": reading["reader"],
                "misread": reading.get("misread", False),
                "fallback_reason": reading.get("fallback_reason"),
                "finding": finding,
                "verification": verification,
                "unverified": bool(reading.get("unverified")),
                "counterfactual": probe in (state.get("world_overrides") or {}),
                "lr": round(lr, 4),
                "delta": round(delta, 4),
                "posterior_before": round(before, 4),
                "posterior_after": round(after, 4),
                "candidates": state["plan"].get("candidates", []),
                "why": state["plan"].get("why", ""),
                "uncertainty_bits": state["plan"].get("uncertainty_bits"),
            }
        )
        return {
            "rounds": rounds,
            "chain": chain,
            "z": z,
            "posterior": after,
            "used": [*state["used"], probe],
            "budget_left": state["budget_left"] - info["cost"],
        }

    def _investigate_web(self, state, probe, info, scenario, overrides, tracer):
        """派出取证子 Agent：在告警原文和团队历史工单上执行只读检查，交回结论 + 证据 + 步骤；
        控制器逐字核验证据后才记账，核验不通过的结论记为「无法确认」（不计分）。"""
        record = scenario["record"]
        with tracer.span(
            f"invoke_agent {probe}",
            **{"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": f"{probe}_investigator", "probewise.cost": info["cost"]},
        ) as span:
            finding = run_check(probe, record, {"history": self.web_history}, self.checks)
            if probe in overrides:  # time-travel 反事实：把这项检查的结论改写为指定值
                finding = {**finding, "outcome": overrides[probe], "counterfactual": True}
            verification = verify_finding(finding, record, self.web_history, info["outcomes"], registry=self.checks)
            if finding.get("counterfactual"):
                verification = {"ok": True, "problems": [], "note": "反事实改写，不核验原文"}
            span.set_attribute("probewise.outcome", finding["outcome"])
            span.set_attribute("probewise.verified", verification["ok"])
            for st in finding.get("steps", []):
                with tracer.span(f"execute_tool {st['tool']}", **{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": st["tool"]}):
                    pass
        reading = {"outcome": finding["outcome"], "reader": f"{finding.get('mode', 'runbook')} 子 Agent"}
        if not verification["ok"]:
            reading["unverified"] = True
        raw = {"text": finding.get("summary", "")}
        return reading, raw, finding, verification

    def decide(self, state: TriageState) -> dict:
        with self._tracer(state).span("chain decide", **{"probewise.node": "decide"}):
            p = state["posterior"]
            label = verdict_label(p, self.kb.thresholds)
            need = state.get("corroboration", 1)
            uncorroborated = label != "escalate" and supporting(state["rounds"], label) < need
            if uncorroborated:
                label = "escalate"
            guard_failed = label == "benign" and not self._benign_guard(state)
            if guard_failed:
                label = "escalate"
            success_sign = any(r["probe"] == "response_check" and r["outcome"] == "exploit_echo" for r in state["rounds"])
            contributions = sorted(
                (
                    {
                        "evidence_id": r["evidence_id"],
                        "probe_name": r["probe_name"],
                        "outcome_label": r["outcome_label"],
                        "lr": r["lr"],
                        "delta": r["delta"],
                    }
                    for r in state["rounds"]
                ),
                key=lambda c: -abs(c["delta"]),
            )
            pro = [c for c in contributions if (c["delta"] > 0) == (label == "malicious")][:3]
            basis = "；".join(f"{c['evidence_id']} {c['probe_name']}：{c['outcome_label']}（似然比 ×{c['lr']:.2f}）" for c in pro)
            if label == "malicious" and success_sign:
                summary = f"判定为真实攻击，且响应中出现利用成功的迹象，需立即启动应急响应。后验 {p:.3f}。主要依据：{basis}。"
            elif label == "malicious":
                summary = f"判定为真实威胁，后验 {p:.3f}。主要依据：{basis}。"
            elif label == "benign":
                summary = f"判定为误报，后验 {p:.3f}。主要依据：{basis}。"
            else:
                remaining = sorted(state.get("plan", {}).get("candidates", []), key=lambda c: -c["score"])
                hint = f"如果条件允许，最值得补做的是「{remaining[0]['name']}」。" if remaining else ""
                why = (
                    f"后验已越过阈值，但只有 {supporting(state['rounds'], verdict_label(p, self.kb.thresholds))} 条同方向证据，未达到交叉印证要求（≥{need} 条）"
                    if uncorroborated
                    else "可疑度低于误报阈值，但没有满足「看过载荷且无明确利用载荷、至少两项检查」的结案护栏"
                    if guard_failed
                    else state.get("stop_reason", "")
                )
                summary = f"证据不足以下结论（后验 {p:.3f}），升级人工研判。原因：{why}。{hint}"
            chain = list(state["chain"])
            chain.append(chain_record(len(chain), "verdict", {"label": label, "posterior": fmt(p)}, chain[-1]["hash"]))
            verdict = {
                "label": label,
                "posterior": round(p, 4),
                "summary": summary,
                "stop_reason": state.get("stop_reason", ""),
                "cost_spent": state["budget"] - state["budget_left"],
                "probes_used": len(state["rounds"]),
                "success_sign": success_sign,
                "proof": {"prior": state["prior"], "prior_logodds": round(logit(state["prior"]), 4), "contributions": contributions},
            }
            return {"verdict": verdict, "chain": chain}

    def respond(self, state: TriageState) -> dict:
        alert = state["alert"]
        label = state["verdict"]["label"]
        ents = alert.get("entities", {})
        if label == "malicious":
            actions = [
                {**a, "status": "pending_approval" if a["approval"] else "auto"} for a in self.kb.alert_types[alert["type"]]["response"]
            ]
            if state["verdict"].get("success_sign"):
                actions.insert(0, {"id": "incident_response", "name": "启动应急响应：响应中出现利用成功迹象，核查目标是否已失陷", "approval": True, "status": "pending_approval"})
        elif label == "benign" and alert["type"] == WEB:
            rule = (find_scenario(self.scenarios, alert["id"]).get("record") or {}).get("rule_name", "-")
            path = str((find_scenario(self.scenarios, alert["id"]).get("record") or {}).get("uri") or "-").split("?", 1)[0][:60]
            actions = [
                {"id": "close_fp", "name": "以误报关闭工单（附结案记录）", "approval": False, "status": "auto"},
                {"id": "whitelist_candidate", "name": f"白名单建议：规则「{rule[:40]}」+ 路径 {path}（复核后才生效）", "approval": True, "status": "pending_approval"},
            ]
        elif label == "benign":
            actions = [
                {"id": "close_fp", "name": "以误报关闭工单", "approval": False, "status": "auto"},
                {
                    "id": "suppression_candidate",
                    "name": f"生成抑制规则候选：{ents.get('indicator', '-')} + {ents.get('user', '-')}（复核后才生效）",
                    "approval": True,
                    "status": "pending_approval",
                },
            ]
        else:
            actions = [{"id": "escalate_tier2", "name": "升级给二线分析师，并附上已收集的证据与剩余不确定性", "approval": False, "status": "auto"}]

        pending = [a for a in actions if a["status"] == "pending_approval"]
        approvals = list(state.get("approvals", []))
        chain = list(state["chain"])
        if pending and state.get("approval_mode") == "interrupt":
            # 高危或会改变检测策略的动作，必须等人工决定后才继续
            decision = interrupt({"type": "approval", "run_id": state["run_id"], "verdict": label, "pending": pending})
            by = decision.get("by", "analyst")
            for a in actions:
                if a["status"] != "pending_approval":
                    continue
                d = decision.get("decisions", {}).get(a["id"], "reject")
                a["status"] = "approved" if d == "approve" else "rejected"
                approvals.append({"action": a["id"], "decision": d, "by": by})
                chain.append(chain_record(len(chain), "approval", {"action": a["id"], "decision": d, "by": by}, chain[-1]["hash"]))
        return {"actions": actions, "approvals": approvals, "chain": chain}

    def report(self, state: TriageState) -> dict:
        with self._tracer(state).span("chain report", **{"probewise.node": "report"}):
            alert = state["alert"]
            v = state["verdict"]
            refs = [c for c in state.get("context", [])]
            playbook = next((c for c in refs if c["id"] == PLAYBOOK_OF[alert["type"]]), None)
            cases = [c for c in refs if c["id"].startswith("C-")][:2]
            lines = [f"### {alert['id']} {alert['title']}", "", f"**结论**：{v['summary']}", ""]
            lines.append("**证据**：")
            for r in state["rounds"]:
                lines.append(f"- [{r['evidence_id']}] {r['probe_name']} → {r['outcome_label']}（似然比 ×{r['lr']:.2f}）")
            lines.append("")
            lines.append("**处置**：")
            for a in state.get("actions", []):
                status = {"auto": "已自动执行（模拟）", "pending_approval": "待审批", "approved": "已批准并执行（模拟）", "rejected": "已驳回"}[a["status"]]
                lines.append(f"- {a['name']}：{status}")
            lines.append("")
            if playbook:
                lines.append(f"**处置依据**：[{playbook['id']}] {playbook['title']}")
            for c in cases:
                lines.append(f"**相似案例**：[{c['id']}] {c['title']}")
            lines.append(f"**ATT&CK**：" + "、".join(f"{m['id']} {m['name']}" for m in alert["mitre"]))
            return {"report": {"markdown": "\n".join(lines), "references": [c["id"] for c in refs]}}

    # ---------- 图 ----------

    def _route_after_plan(self, state: TriageState) -> str:
        return "investigate" if state.get("next_probe") else "decide"

    def _build(self):
        g = StateGraph(TriageState)
        g.add_node("intake", self.intake)
        g.add_node("plan", self.plan)
        g.add_node("investigate", self.investigate)
        g.add_node("decide", self.decide)
        g.add_node("respond", self.respond)
        g.add_node("report", self.report)
        g.add_edge(START, "intake")
        g.add_edge("intake", "plan")
        g.add_conditional_edges("plan", self._route_after_plan, {"investigate": "investigate", "decide": "decide"})
        g.add_edge("investigate", "plan")
        g.add_edge("decide", "respond")
        g.add_edge("respond", "report")
        g.add_edge("report", END)
        return g.compile(checkpointer=self.checkpointer)

    # ---------- 对外接口 ----------

    def _invoke(self, run_id: str, payload, config: dict, operation: str = "invoke_agent") -> None:
        self._tracers[run_id] = RunTracer(run_id, operation)
        try:
            self.graph.invoke(payload, config)
        finally:
            spans = self._tracers.pop(run_id).finish()
            self.spans.setdefault(run_id, []).extend(spans)

    def start(
        self,
        alert_id: str,
        strategy: str = "probewise",
        budget: float = 10,
        approval_mode: str = "interrupt",
        seed: int = 0,
        run_id: str | None = None,
        world_overrides: dict | None = None,
        corroboration: int | None = None,
        reader_mode: str = "auto",
    ) -> dict:
        if strategy not in STRATEGIES:
            raise ValueError(f"未知策略 {strategy}，可选：{', '.join(STRATEGIES)}")
        scenario = find_scenario(self.scenarios, alert_id)
        run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
        state = {
            "run_id": run_id,
            "alert": public_alert(scenario, self.kb),
            "strategy": strategy,
            "budget": float(budget),
            "seed": seed,
            "approval_mode": approval_mode,
            "world_overrides": world_overrides or {},
            # 稳健模式：结案至少需要 2 条同方向的强证据，适合读取器不够可靠（如本地小模型）的部署
            "corroboration": corroboration if corroboration is not None else (2 if strategy == "probewise-robust" else 1),
            "reader_mode": reader_mode,
        }
        self._invoke(run_id, state, self.config(run_id))
        return self.trace(run_id)

    def submit_reading(self, run_id: str, outcome: str, reader: str = "external") -> dict:
        waiting = self.awaiting(run_id)
        if not waiting or waiting["type"] != "reading":
            raise ValueError("该调查当前没有等待读取的工具输出")
        if outcome not in waiting["options"]:
            raise ValueError(f"结论必须是以下选项之一：{', '.join(waiting['options'])}")
        self._invoke(run_id, Command(resume={"outcome": outcome, "reader": reader}), self.config(run_id), "resume_agent")
        return self.trace(run_id)

    def approve(self, run_id: str, decisions: dict[str, str], by: str = "analyst") -> dict:
        waiting = self.awaiting(run_id)
        if not waiting or waiting["type"] != "approval":
            raise ValueError("该调查当前没有等待审批的动作")
        self._invoke(run_id, Command(resume={"decisions": decisions, "by": by}), self.config(run_id), "resume_agent")
        return self.trace(run_id)

    def fork(self, run_id: str, evidence_id: str, outcome: str) -> dict:
        """time-travel：回到某条证据被收集之前的 checkpoint，改写那次检查的结果，从那里继续调查。"""
        target = None
        for snap in self.graph.get_state_history(self.config(run_id)):
            rounds = snap.values.get("rounds", [])
            if snap.next == ("investigate",) and f"E{len(rounds) + 1}" == evidence_id:
                target = snap
                break
        if target is None:
            raise ValueError(f"没有找到 {evidence_id} 之前的 checkpoint")
        probe = target.values["next_probe"]
        if outcome not in self.kb.probes[probe]["outcomes"]:
            raise ValueError(f"检查 {probe} 没有结论选项 {outcome}")
        overrides = {**(target.values.get("world_overrides") or {}), probe: outcome}
        new_config = self.graph.update_state(
            target.config, {"world_overrides": overrides, "approval_mode": "defer"}, as_node="plan"
        )
        self._invoke(run_id, None, new_config, "fork_agent")
        result = self.trace(run_id)
        result["fork"] = {"from_checkpoint": target.config["configurable"]["checkpoint_id"], "evidence_id": evidence_id, "probe": probe, "outcome": outcome}
        return result

    def checkpoints(self, run_id: str) -> list[dict]:
        out = []
        for snap in self.graph.get_state_history(self.config(run_id)):
            v = snap.values
            out.append(
                {
                    "checkpoint_id": snap.config["configurable"]["checkpoint_id"],
                    "step": snap.metadata.get("step"),
                    "next": list(snap.next),
                    "rounds": len(v.get("rounds", [])),
                    "posterior": round(v["posterior"], 4) if "posterior" in v else None,
                    "created_at": snap.created_at,
                }
            )
        return out

    def awaiting(self, run_id: str) -> dict | None:
        """当前停在哪个 interrupt：等待外部读取（reading）或等待人工审批（approval）。"""
        snap = self.graph.get_state(self.config(run_id))
        for task in snap.tasks:
            for itr in task.interrupts:
                return itr.value
        return None

    def pending(self, run_id: str) -> list:
        waiting = self.awaiting(run_id)
        return waiting.get("pending", []) if waiting and waiting.get("type") == "approval" else []

    @staticmethod
    def config(run_id: str) -> dict:
        return {"configurable": {"thread_id": run_id}}

    def trace(self, run_id: str) -> dict:
        snap = self.graph.get_state(self.config(run_id))
        v = snap.values
        if not v:
            raise KeyError(f"没有找到调查 {run_id}")
        waiting = self.awaiting(run_id)
        pending = waiting.get("pending", []) if waiting and waiting.get("type") == "approval" else []
        status = f"awaiting_{waiting['type']}" if waiting else ("completed" if not snap.next else "running")
        return {
            "schema": "probewise.trace/v1",
            "run_id": run_id,
            "status": status,
            "awaiting": waiting,
            "alert": v["alert"],
            "strategy": v["strategy"],
            "budget": v["budget"],
            "prior": v["prior"],
            "platt": self.kb.platt(v["alert"]["type"]),
            "thresholds": self.kb.thresholds,
            "corroboration": v.get("corroboration", 1),
            "rounds": v.get("rounds", []),
            "verdict": v.get("verdict"),
            "actions": v.get("actions", []),
            "pending": pending,
            "approvals": v.get("approvals", []),
            "report": v.get("report"),
            "context": v.get("context", []),
            "world_overrides": v.get("world_overrides", {}),
            "chain": v.get("chain", []),
            "telemetry": self.spans.get(run_id, []),
        }
