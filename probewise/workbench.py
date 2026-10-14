"""分析员工作台：告警队列、规则调优建议、结案记录、分析员反馈。

调研结论（research/01）：分析员最怕漏报；告警量大、误报多；结案记录要写；
「这条规则平时准不准」全凭记忆。工作台把这些落到日常流程里：
- 队列：一次研判整批告警，去重后按「是否需要人处理」排序，人只看升级和待批准的；
- 规则调优：同一条规则长期以误报为主时，给出「规则 + 路径」白名单建议（需人工批准）；
- 结案记录：每个案件生成可直接贴进工单的文本，证据引用原文，附哈希便于事后核对；
- 反馈：分析员可以纠正判定，纠正记录用于下一次 `probewise calibrate`（需要认证用户，见 docs）。
"""

from __future__ import annotations

import sqlite3
import time
from collections import defaultdict

from .kb import find_scenario

LABEL_CN = {"malicious": "攻击", "benign": "误报", "escalate": "升级人工"}
STATUS_CN = {"auto": "已自动执行（模拟）", "pending_approval": "待审批", "approved": "已批准（模拟执行）", "rejected": "已驳回"}


def fingerprint(record: dict) -> tuple:
    return (record.get("rule_name"), record.get("method"), record.get("uri"), record.get("req_body"))


def run_queue(engine, alert_ids: list[str] | None = None) -> dict:
    """研判队列里的全部网络攻击告警（已研判过的直接复用 checkpoint）。"""
    web = [s for s in engine.scenarios if s["type"] == "web_attack" and (alert_ids is None or s["id"] in alert_ids)]
    seen: dict[tuple, str] = {}
    items = []
    for s in sorted(web, key=lambda x: x["time"]):
        rec = s["record"]
        fp = fingerprint(rec)
        dup_of = seen.get(fp)
        seen.setdefault(fp, s["id"])
        run_id = f"q-{s['id']}"
        try:
            t = engine.trace(run_id)
        except KeyError:
            t = engine.start(s["id"], run_id=run_id, strategy="probewise-robust", approval_mode="interrupt")
        v = t["verdict"] or {}
        items.append(
            {
                "alert_id": s["id"],
                "run_id": run_id,
                "time": s["time"],
                "rule_name": rec.get("rule_name"),
                "method": rec.get("method"),
                "path": str(rec.get("uri") or "/").split("?", 1)[0][:80],
                "asset": (rec.get("asset") or {}).get("name"),
                "criticality": (rec.get("asset") or {}).get("criticality"),
                "rsp_status": rec.get("rsp_status"),
                "label": v.get("label"),
                "posterior": v.get("posterior"),
                "success_sign": v.get("success_sign", False),
                "checks": v.get("probes_used"),
                "status": t["status"],
                "pending": len(t.get("pending", [])),
                "duplicate_of": dup_of,
            }
        )
    order = {"malicious": 0, "escalate": 1, "benign": 2}
    items.sort(key=lambda i: (not i["success_sign"], order.get(i["label"], 3), -(i["posterior"] or 0)))
    n = len(items)
    counts = defaultdict(int)
    for i in items:
        counts[i["label"]] += 1
    need_human = sum(1 for i in items if i["label"] != "benign")
    return {
        "items": items,
        "summary": {
            "total": n,
            "malicious": counts["malicious"],
            "benign": counts["benign"],
            "escalate": counts["escalate"],
            "success_sign": sum(1 for i in items if i["success_sign"]),
            "duplicates": sum(1 for i in items if i["duplicate_of"]),
            "need_human": need_human,
            "pending_approvals": sum(i["pending"] for i in items),
            "auto_closed": counts["benign"],
        },
        "rules": rule_suggestions(engine, items),
    }


def rule_suggestions(engine, items: list[dict]) -> list[dict]:
    """按规则汇总：今天的告警量、自动判误报的比例、团队历史上的误报率 → 是否建议加白名单。"""
    by = defaultdict(list)
    for i in items:
        by[i["rule_name"]].append(i)
    out = []
    for rule, rows in by.items():
        att, tot = engine.web_history.lookup("rule", rule)
        fp_hist = (tot - att) / tot if tot else None
        closed = sum(1 for r in rows if r["label"] == "benign")
        paths = sorted({r["path"] for r in rows if r["label"] == "benign"})
        suggest = bool(fp_hist is not None and fp_hist >= 0.9 and tot >= 20 and closed == len(rows))
        out.append(
            {
                "rule_name": rule,
                "today": len(rows),
                "auto_closed": closed,
                "history_total": tot,
                "history_fp_rate": round(fp_hist, 3) if fp_hist is not None else None,
                "suggest_whitelist": suggest,
                "whitelist_paths": paths[:5] if suggest else [],
                "note": (
                    f"历史 {tot} 条中 {tot - att} 条为误报。建议对路径 {', '.join(paths[:3])} 加「规则 + 路径」白名单，复核后生效；白名单不覆盖带明确利用载荷的请求。"
                    if suggest
                    else "暂不建议调整" if tot >= 20 else "历史样本不足，先积累处置记录"
                ),
            }
        )
    return sorted(out, key=lambda r: (-r["suggest_whitelist"], -r["today"]))


def closing_note(trace: dict, scenarios: list[dict]) -> str:
    """生成可直接贴进工单的结案记录。"""
    a, v = trace["alert"], trace.get("verdict") or {}
    rec = find_scenario(scenarios, a["id"]).get("record") or {}
    lines = [
        f"【告警】{a['id']} {a['title']}（{a.get('time', '')}）",
        f"【对象】{a.get('summary', '')}",
        f"【结论】{LABEL_CN.get(v.get('label'), v.get('label'))}，可疑度 {v.get('posterior', 0):.1%}" + ("，响应中有利用成功迹象" if v.get("success_sign") else ""),
        "【依据】",
    ]
    for r in trace.get("rounds", []):
        f = r.get("finding") or {}
        cite = ""
        for e in f.get("evidence", [])[:1]:
            if e.get("source") == "alert":
                cite = f"；原文 {e['ref']}：「{e['excerpt'][:60]}」"
            elif e.get("source") == "history":
                cite = f"；历史工单 {e['result']['attack']}/{e['result']['total']} 为真攻击"
        flag = "（证据核验未通过，未计分）" if r.get("verification") and not r["verification"].get("ok") else ""
        lines.append(f"  {r['evidence_id']} {r['probe_name']}：{r['outcome_label']}{cite}{flag}")
    acts = trace.get("actions", [])
    if acts:
        lines.append("【处置】" + "；".join(f"{x['name']}（{STATUS_CN.get(x['status'], x['status'])}）" for x in acts))
    if trace.get("approvals"):
        lines.append("【审批】" + "；".join(f"{x['action']} → {x['decision']}（{x['by']}）" for x in trace["approvals"]))
    if rec.get("asset"):
        lines.append(f"【资产】{rec['asset'].get('name')}，负责人 {rec['asset'].get('owner', '-')}，重要性 {rec['asset'].get('criticality', '-')}")
    chain = trace.get("chain", [])
    if chain:
        lines.append(f"【审计】调查记录哈希 {chain[-1]['hash'][:16]}…（可用 probewise verify 独立核对）")
    lines.append("—— 由 Probewise 生成，结论仅供参考，处置以人工审批为准")
    return "\n".join(lines)


class FeedbackStore:
    """分析员对判定的纠正。只记录，不会自动改表：下一次 calibrate 时作为新的历史工单参与学习，
    并且有速率上限，防止有人刷反馈把某条规则「洗」成误报（反馈投毒）。"""

    MAX_PER_HOUR = 30

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        conn.execute("CREATE TABLE IF NOT EXISTS feedback (ts REAL, run_id TEXT, alert_id TEXT, verdict TEXT, correct_label TEXT, comment TEXT, by TEXT)")
        cols = [r[1] for r in conn.execute("PRAGMA table_info(feedback)")]
        if "client" not in cols:
            conn.execute("ALTER TABLE feedback ADD COLUMN client TEXT")
        conn.commit()

    def add(self, run_id: str, alert_id: str, verdict: str, correct_label: str, comment: str, by: str, client: str = "-") -> dict:
        # 按来源限速：一个来源刷屏不会挡住其他分析员。真实部署时 by / client 应来自登录身份，而不是请求体
        recent = self.conn.execute("SELECT COUNT(*) FROM feedback WHERE ts > ? AND client = ?", (time.time() - 3600, client)).fetchone()[0]
        if recent >= self.MAX_PER_HOUR:
            raise ValueError("该来源最近一小时的反馈过多，已暂停接收（防止反馈投毒）")
        self.conn.execute(
            "INSERT INTO feedback (ts, run_id, alert_id, verdict, correct_label, comment, by, client) VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), run_id, alert_id, verdict, correct_label, comment[:300], by[:40], client[:64]),
        )
        self.conn.commit()
        return {"ok": True}

    def list(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute("SELECT ts, run_id, alert_id, verdict, correct_label, comment, by FROM feedback ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(zip(("ts", "run_id", "alert_id", "verdict", "correct_label", "comment", "by"), r)) for r in rows]
