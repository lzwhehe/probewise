"""核验子 Agent 交回的 Finding：不信任何「说法」，只信能复算的东西。

- 结论必须是该检查的枚举值；
- 引用告警原文的证据：字段必须在该检查允许的范围内（例如响应研判只能引用响应字段），
  并且 view[offset:offset+len] 与引用逐字相同 —— 防止编造证据，也防止攻击者在请求里
  伪造一段「SQL 报错」再被当成响应证据引用；
- 引用历史工单的证据：重新查询，数字必须一致。
不通过的 Finding 不进账本，记为「无法确认」。
"""

from __future__ import annotations

from .checks import CHECKS
from .fields import sanitize, view


def verify_finding(finding: dict, alert: dict, history, outcomes: dict, exclude=None, registry: dict | None = None) -> dict:
    problems = []
    check = (registry or CHECKS).get(finding.get("check"))
    if check is None:
        return {"ok": False, "problems": [f"未知检查 {finding.get('check')!r}"]}
    if finding.get("outcome") not in outcomes:
        problems.append(f"结论 {finding.get('outcome')!r} 不在允许的选项中")
    clean = sanitize(alert)
    for i, ev in enumerate(finding.get("evidence", [])):
        if ev.get("source") == "alert":
            ref = str(ev.get("ref", ""))
            field = ref.partition("@")[0]
            if field not in check.fields:
                problems.append(f"证据 {i + 1} 引用了 {field}，不在「{check.name}」允许的字段内")
                continue
            s, off, ex = view(clean, ref), ev.get("offset"), ev.get("excerpt", "")
            if not isinstance(off, int) or off < 0 or s[off : off + len(ex)] != ex or not ex:
                problems.append(f"证据 {i + 1} 在 {ref} 的指定位置找不到原文")
        elif ev.get("source") == "history":
            q, res = ev.get("query", {}), ev.get("result", {})
            att, tot = history.lookup(q.get("key"), q.get("value"), exclude=exclude)
            if (att, tot) != (res.get("attack"), res.get("total")):
                problems.append(f"证据 {i + 1} 的历史统计与重新查询结果不一致")
        else:
            problems.append(f"证据 {i + 1} 来源未知")
    return {"ok": not problems, "problems": problems}
