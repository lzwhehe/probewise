"""团队历史工单：把分析员脑子里的「这条规则平时准不准」「这个路径是不是自己的业务」变成可查询的数据。

真实部署时来自工单系统（Jira / ServiceNow / 自研）里已结案、带处置结论的告警；
演示和评测时来自 SecAlertBench 的训练集或内置示例。
"""

from __future__ import annotations

from collections import defaultdict

from .fields import path_prefix, text


def is_attack(record: dict) -> bool:
    return str(record.get("Label", record.get("label", ""))).lower() in ("attack", "malicious", "tp", "true_positive")


class TicketHistory:
    def __init__(self, records: list[dict] | None = None):
        self.counts: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])  # (kind, value) -> [attack, total]
        self.size = 0
        for r in records or []:
            self.add(r)

    @staticmethod
    def keys(record: dict) -> list[tuple]:
        return [("rule", text(record, "rule_name")), ("path", path_prefix(record))]

    def add(self, record: dict, label_attack: bool | None = None) -> None:
        attack = is_attack(record) if label_attack is None else label_attack
        for k in self.keys(record):
            c = self.counts[k]
            c[0] += int(attack)
            c[1] += 1
        self.size += 1

    def lookup(self, kind: str, value: str, exclude: dict | None = None) -> tuple[int, int]:
        """返回 (真攻击数, 总数)。exclude 为当前告警自身时做留一法，避免拿自己当自己的历史。"""
        att, tot = self.counts.get((kind, value), (0, 0))
        if exclude is not None and (kind, value) in self.keys(exclude):
            att -= int(is_attack(exclude))
            tot -= 1
        return max(att, 0), max(tot, 0)

    def top(self, kind: str, n: int = 20) -> list[dict]:
        rows = [{"value": v, "attack": c[0], "total": c[1]} for (k, v), c in self.counts.items() if k == kind]
        return sorted(rows, key=lambda r: -r["total"])[:n]

    def to_json(self) -> dict:
        return {"size": self.size, "counts": [[k, v, c[0], c[1]] for (k, v), c in self.counts.items()]}

    @classmethod
    def from_json(cls, data: dict) -> "TicketHistory":
        h = cls()
        h.size = data.get("size", 0)
        for k, v, att, tot in data.get("counts", []):
            h.counts[(k, v)] = [att, tot]
        return h
