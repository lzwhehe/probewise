"""读取器：把工具的原始输出「读」成知识库里的某个结论选项。

设计原则（读判分离）：读取器只负责理解工具输出、选出一个结论选项；
是否继续调查、下什么判定，全部由控制器根据账本决定。所以即使接入的是能力有限的小模型，
它最多读错某一条证据，不能直接替系统下结论。
"""

from __future__ import annotations

import json
import random
import urllib.request

from .kb import KnowledgeBase


class RuleReader:
    """确定性读取：直接使用工具返回的结构化字段（相当于为每个工具写好的解析器）。"""

    name = "rule"

    def read(self, probe: str, raw: dict, kb: KnowledgeBase) -> dict:
        return {"outcome": raw["outcome"], "reader": self.name}


class NoisyReader:
    """模拟「会读错的小模型」：以给定概率随机选错结论选项，用来做抗噪压力测试。"""

    def __init__(self, rate: float, seed: int = 0):
        self.rate = rate
        self.rng = random.Random(seed)
        self.name = f"noisy({rate:g})"

    def read(self, probe: str, raw: dict, kb: KnowledgeBase) -> dict:
        options = list(kb.probes[probe]["outcomes"])
        if self.rng.random() < self.rate and len(options) > 1:
            wrong = self.rng.choice([o for o in options if o != raw["outcome"]])
            return {"outcome": wrong, "reader": self.name, "misread": True}
        return {"outcome": raw["outcome"], "reader": self.name}


class LLMReader:
    """调用任意 OpenAI 兼容接口（如本地 Ollama、vLLM）读取工具输出。

    模型只能从给定选项里选一个；输出不合法或调用失败时，回退到规则读取，并在轨迹里记下原因。
    """

    def __init__(self, base_url: str, model: str, api_key: str = "", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.name = f"llm({model})"
        self.fallback = RuleReader()

    def _prompt(self, probe: str, raw: dict, kb: KnowledgeBase) -> str:
        p = kb.probes[probe]
        options = "\n".join(f"- {k}：{v['label']}" for k, v in p["outcomes"].items())
        return (
            f"你在协助安全分析师阅读工具输出。工具：{p['name']}。\n"
            f"工具原始输出：{raw['text']}\n"
            f"请从下列选项中选出最符合输出内容的一项，只输出 JSON，例如 {{\"outcome\": \"选项名\"}}：\n{options}"
        )

    def read(self, probe: str, raw: dict, kb: KnowledgeBase) -> dict:
        allowed = set(kb.probes[probe]["outcomes"])
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "messages": [{"role": "user", "content": self._prompt(probe, raw, kb)}],
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                content = json.loads(resp.read())["choices"][0]["message"]["content"]
            start, end = content.find("{"), content.rfind("}")
            outcome = json.loads(content[start : end + 1]).get("outcome")
            if outcome in allowed:
                return {"outcome": outcome, "reader": self.name}
            reason = f"模型输出了不在选项中的结果：{outcome!r}"
        except Exception as exc:  # 网络错误、超时、JSON 格式错误等
            reason = f"模型调用失败：{type(exc).__name__}"
        result = self.fallback.read(probe, raw, kb)
        result.update({"reader": f"{self.name}→rule", "fallback_reason": reason})
        return result


def make_reader(spec: str, seed: int = 0, base_url: str = "", model: str = "", api_key: str = ""):
    """spec 取值：rule | noisy:0.2 | llm"""
    if spec == "rule":
        return RuleReader()
    if spec.startswith("noisy"):
        rate = float(spec.split(":", 1)[1]) if ":" in spec else 0.1
        return NoisyReader(rate, seed)
    if spec == "llm":
        if not (base_url and model):
            raise ValueError("使用 llm 读取器需要 --base-url 和 --model")
        return LLMReader(base_url, model, api_key)
    raise ValueError(f"未知的读取器：{spec}")
