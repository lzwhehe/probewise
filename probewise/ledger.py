"""假设账本：用对数几率（log-odds）累加证据，并计算每个候选检查的期望信息增益。

只有两个假设：malicious（真实威胁）与 benign（误报）。
每条证据的作用 = 似然比 LR = P(结果 | 恶意) / P(结果 | 良性)，在对数几率上做加法。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

EPS = 1e-9


def logit(p: float) -> float:
    p = min(max(p, EPS), 1 - EPS)
    return math.log(p / (1 - p))


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1 / (1 + math.exp(-x))
    e = math.exp(x)
    return e / (1 + e)


def entropy(p: float) -> float:
    """二元熵（比特）。"""
    if p <= 0 or p >= 1:
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def posterior_after(p_mal: float, p_obs_mal: float, p_obs_ben: float) -> float:
    num = p_mal * p_obs_mal
    den = num + (1 - p_mal) * p_obs_ben
    return num / den if den > 0 else p_mal


def expected_info_gain(p_mal: float, outcomes: dict) -> float:
    """执行一次检查后，对「是否恶意」这一问题的不确定性平均能减少多少比特。

    outcomes: {结果名: {"p_mal": ..., "p_ben": ...}}
    """
    before = entropy(p_mal)
    after = 0.0
    for o in outcomes.values():
        p_o = p_mal * o["p_mal"] + (1 - p_mal) * o["p_ben"]
        if p_o <= 0:
            continue
        after += p_o * entropy(posterior_after(p_mal, o["p_mal"], o["p_ben"]))
    return max(0.0, before - after)


@dataclass
class Entry:
    evidence_id: str
    probe: str
    outcome: str
    lr: float
    delta: float


@dataclass
class Ledger:
    prior: float
    logodds: float = field(init=False)
    entries: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.logodds = logit(self.prior)

    @property
    def posterior(self) -> float:
        return sigmoid(self.logodds)

    def add(self, evidence_id: str, probe: str, outcome: str, p_mal: float, p_ben: float) -> Entry:
        lr = p_mal / p_ben
        delta = math.log(lr)
        self.logodds += delta
        entry = Entry(evidence_id, probe, outcome, lr, delta)
        self.entries.append(entry)
        return entry
