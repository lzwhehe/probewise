"""模拟的调查工具层。

真实部署时，这一层会对接 SIEM 查询、威胁情报、CMDB、EDR、沙箱等接口；
这里用场景里的 world 字段作为「查了就会得到的结果」，并按知识库模板生成工具原始输出文本。
"""

from __future__ import annotations

from .kb import KnowledgeBase


class ToolError(Exception):
    pass


class MockToolkit:
    def __init__(self, scenario: dict, kb: KnowledgeBase):
        self.scenario = scenario
        self.kb = kb

    def run(self, probe: str) -> dict:
        world = self.scenario.get("world", {})
        if probe not in world:
            raise ToolError(f"场景 {self.scenario['id']} 不支持检查 {probe}")
        outcome = world[probe]
        template = self.kb.outcome(probe, outcome)["text"]
        entities = {"indicator": "-", "host": "-", "user": "-", "ticket": "-", **self.scenario.get("entities", {})}
        return {"probe": probe, "outcome": outcome, "text": template.format(**entities)}
