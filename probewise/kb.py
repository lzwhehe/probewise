"""知识库与场景加载。默认读取包内 data/ 目录，也可以传入自定义 JSON。"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


class KnowledgeBase:
    def __init__(self, data: dict):
        self.raw = data
        self.thresholds = data["thresholds"]
        self.probes = data["probes"]
        self.alert_types = data["alert_types"]

    @classmethod
    def load(cls, path: str | Path | None = None) -> "KnowledgeBase":
        path = Path(path) if path else DATA_DIR / "kb.json"
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def outcome(self, probe: str, outcome: str) -> dict:
        try:
            return self.probes[probe]["outcomes"][outcome]
        except KeyError as exc:
            raise KeyError(f"知识库里没有检查 {probe} 的结果 {outcome}") from exc

    def probes_for(self, alert_type: str) -> list[str]:
        return list(self.alert_types[alert_type]["probes"])

    def validate(self) -> list[str]:
        """检查似然是否构成合法的概率分布，返回问题列表。"""
        problems = []
        for pid, probe in self.probes.items():
            for side in ("p_mal", "p_ben"):
                total = sum(o[side] for o in probe["outcomes"].values())
                if abs(total - 1) > 1e-6:
                    problems.append(f"{pid}.{side} 之和为 {total:.4f}，应为 1")
                if any(o[side] <= 0 for o in probe["outcomes"].values()):
                    problems.append(f"{pid}.{side} 存在非正的似然")
        for tid, t in self.alert_types.items():
            if not 0 < t["prior"] < 1:
                problems.append(f"{tid}.prior 必须在 (0, 1) 之间")
            for p in t["probes"]:
                if p not in self.probes:
                    problems.append(f"{tid} 引用了不存在的检查 {p}")
        return problems


def load_scenarios(path: str | Path | None = None) -> list[dict]:
    path = Path(path) if path else DATA_DIR / "scenarios.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["scenarios"] if isinstance(data, dict) else data


def find_scenario(scenarios: list[dict], scenario_id: str) -> dict:
    for s in scenarios:
        if s["id"].lower() == scenario_id.lower():
            return s
    raise KeyError(f"没有找到场景 {scenario_id}")
