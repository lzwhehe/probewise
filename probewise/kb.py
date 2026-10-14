"""知识库与场景加载。默认读取包内 data/ 目录，也可以传入自定义 JSON。"""

from __future__ import annotations

import json
import math
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
        data = json.loads(path.read_text(encoding="utf-8"))
        # 网络攻击告警的知识库由 `probewise calibrate` 从历史工单学出来，单独存放后合并
        learned = path.parent / "web_kb.json"
        if learned.exists():
            web = json.loads(learned.read_text(encoding="utf-8"))
            data = {**data, "probes": {**data["probes"], **web["probes"]}, "alert_types": {**data["alert_types"], **web["alert_types"]}}
        return cls(data)

    def llr(self, probe: str, outcome: str) -> float:
        """对数似然比。学习得到的表里已经做过封顶 / 中性化处理（log_lr），手填的表按 p_mal/p_ben 计算。"""
        o = self.outcome(probe, outcome)
        return o["log_lr"] if "log_lr" in o else math.log(o["p_mal"] / o["p_ben"])

    def platt(self, alert_type: str) -> dict:
        """概率校准参数 p = σ(a·z + b)；手填的表不校准（a=1, b=0）。"""
        return self.alert_types[alert_type].get("platt", {"a": 1.0, "b": 0.0})

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
                if abs(total - 1) > 1e-4:
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
    scenarios = data["scenarios"] if isinstance(data, dict) else data
    web = (path.parent / "web_alerts.json") if path else DATA_DIR / "web_alerts.json"
    if web.exists():
        scenarios = [*scenarios, *(web_scenario(a) for a in json.loads(web.read_text(encoding="utf-8")))]
    return scenarios


def web_scenario(a: dict) -> dict:
    """把一条 WAF / IDS 告警包装成场景：record 保留原始字段，检查时会先去掉采集伪特征。"""
    path = str(a.get("uri") or "/").split("?", 1)[0][:60]
    asset = a.get("asset") or {}
    gt = str(a.get("ground_truth", "")).lower()
    return {
        "id": a["id"],
        "type": "web_attack",
        "severity": {"高": "high", "中": "medium", "低": "low"}.get(asset.get("criticality", ""), "medium"),
        "time": a.get("time", ""),
        "title": f"{a.get('rule_name', '')}",
        "summary": f"{a.get('method') or '-'} {path} → {asset.get('name') or a.get('dip') or '-'}（响应 {a.get('rsp_status')}）",
        "entities": {"indicator": a.get("sip", "-"), "host": asset.get("name") or a.get("dip", "-"), "user": "-", "ticket": "-"},
        "ground_truth": "malicious" if gt == "attack" else "benign",
        "record": a,
        "world": {},
    }


def find_scenario(scenarios: list[dict], scenario_id: str) -> dict:
    for s in scenarios:
        if s["id"].lower() == scenario_id.lower():
            return s
    raise KeyError(f"没有找到场景 {scenario_id}")
