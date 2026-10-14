"""从历史工单学习似然表（替代手填的「专家估计」），并做概率校准。

1. 对每条带人工结论的历史告警运行全部检查（只看去掉伪特征的视图）；
   「规则历史」「业务路径」用留一法，避免拿自己当自己的历史。
2. 按「真攻击 / 误报」计数，Dirichlet(α) 平滑：P(o|类) = (n_o + α) / (N + α·K)。
3. 每项检查的 |log 似然比| 封顶（MAX_LOG_LR），任何单项检查都不能一锤定音。
4. 「规则历史太少」一律视为中性（LR=1）：新规则没有历史不是攻击的证据，
   否则换一批新规则就会系统性误判（红队评审 P0）。
5. 各检查并不条件独立（攻击工具常带明确载荷，规则历史和载荷都在间接反映规则），
   直接相加会过度自信。留出一部分训练数据做验证集，拟合 Platt 校准：
   p = σ(a · z + b)，z 为先验对数几率与各证据对数似然比之和。
"""

from __future__ import annotations

import math
import random
from collections import defaultdict

from ..ledger import logit, sigmoid
from .checks import CHECKS, run_check
from .history import TicketHistory, is_attack

ALPHA = 1.0
MAX_LOG_LR = math.log(20)
NEUTRAL = {("rule_history", "sparse")}
# 训练数据里没有样本、但含义明确的结论：按专家规则给定（并在知识库里标注来源）
EXPERT = {("response_check", "exploit_echo"): MAX_LOG_LR}
COSTS = {"rule_history": 1, "payload_check": 1, "response_check": 1, "client_profile": 1, "path_profile": 1}
OUTCOME_LABELS = {
    "rule_history": {"mostly_fp": "历史上多为误报", "mixed": "历史上好坏参半", "mostly_attack": "历史上多为真攻击", "sparse": "历史样本太少（不计分）"},
    "payload_check": {"explicit_exploit": "明确利用载荷", "weak_fragment": "只有弱特征", "no_payload": "未见载荷"},
    "response_check": {
        "exploit_echo": "有利用成功迹象",
        "not_found_or_rejected": "资源不存在 / 被拒绝",
        "server_error": "服务端报错",
        "auth_or_redirect": "需认证 / 被重定向",
        "no_response": "无响应记录",
        "normal_success": "正常返回",
    },
    "client_profile": {"attack_tool": "已知扫描器", "script_client": "脚本 / 程序库", "browser": "浏览器", "missing": "无 User-Agent"},
    "path_profile": {"business_path": "像本单位业务系统", "attack_path": "历史多为攻击探测", "mixed_path": "历史好坏参半", "unseen_path": "历史罕见路径", "generic_path": "通用路径"},
}


def run_checks(record: dict, history: TicketHistory, exclude_self: bool) -> dict:
    ctx = {"history": history, "exclude": record if exclude_self else None}
    return {cid: run_check(cid, record, ctx) for cid in CHECKS}


def log_lr(probe: dict, outcome: str) -> float:
    o = probe["outcomes"][outcome]
    return o.get("log_lr", math.log(o["p_mal"] / o["p_ben"]))


def score(prior: float, outcomes: dict, probes: dict) -> float:
    """未校准的对数几率 z。"""
    return logit(prior) + sum(log_lr(probes[c], o) for c, o in outcomes.items())


def calibrated(z: float, platt: dict) -> float:
    return sigmoid(platt["a"] * z + platt["b"])


def learn(records: list[dict], history: TicketHistory | None = None, alpha: float = ALPHA, val_frac: float = 0.2, seed: int = 0) -> dict:
    history = history or TicketHistory(records)
    rows = [(is_attack(r), {cid: f["outcome"] for cid, f in run_checks(r, history, exclude_self=True).items()}) for r in records]
    rng = random.Random(seed)
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    k = int(len(idx) * val_frac)
    val = [rows[i] for i in idx[:k]]
    fit = [rows[i] for i in idx[k:]]

    counts = {cid: {"mal": defaultdict(int), "ben": defaultdict(int)} for cid in CHECKS}
    n_mal = 0
    for att, outs in fit:
        n_mal += att
        for cid, o in outs.items():
            counts[cid]["mal" if att else "ben"][o] += 1
    prior = (n_mal + 1) / (len(fit) + 2)
    probes = {}
    for cid, c in counts.items():
        outs = OUTCOME_LABELS[cid]
        kk = len(outs)
        tm, tb = sum(c["mal"].values()), sum(c["ben"].values())
        table = {}
        for o, lab in outs.items():
            pm = (c["mal"][o] + alpha) / (tm + alpha * kk)
            pb = (c["ben"][o] + alpha) / (tb + alpha * kk)
            llr = 0.0 if (cid, o) in NEUTRAL else max(-MAX_LOG_LR, min(MAX_LOG_LR, math.log(pm / pb)))
            source = "neutral" if (cid, o) in NEUTRAL else "data"
            if (cid, o) in EXPERT and c["mal"][o] + c["ben"][o] < 10:
                llr, source = EXPERT[(cid, o)], "expert"
            table[o] = {"label": lab, "p_mal": round(pm, 6), "p_ben": round(pb, 6), "log_lr": round(llr, 6), "n_mal": c["mal"][o], "n_ben": c["ben"][o], "source": source}
        probes[cid] = {"name": CHECKS[cid].name, "cost": COSTS[cid], "outcomes": table}

    platt = fit_platt_anchored(val, prior, probes, seed=seed)
    return {
        "prior": round(prior, 6),
        "platt": platt,
        "max_log_lr": round(MAX_LOG_LR, 4),
        "probes": probes,
        "trained_on": len(fit),
        "validated_on": len(val),
        "positives": n_mal,
        "calibration": calibration_report(val, prior, probes, platt),
    }


def fit_platt_anchored(rows, prior, probes, seed: int = 0) -> dict:
    """控制器会在「只做了部分检查」时就判定，所以校准要覆盖部分证据的状态：
    对验证集每条告警随机排列检查顺序，取全部前缀的得分来拟合；
    并把截距锚定在先验上（b = z0·(1−a)），保证没有任何证据时可疑度就等于先验。"""
    rng = random.Random(seed)
    z0 = logit(prior)
    pairs = []
    for att, outs in rows:
        order = list(outs)
        rng.shuffle(order)
        z = z0
        for c in order:
            z += log_lr(probes[c], outs[c])
            pairs.append((att, z))
    best = min((round(0.3 + 0.01 * i, 2) for i in range(91)), key=lambda a: _nll(pairs, a, z0 * (1 - a)))
    return {"a": best, "b": round(z0 * (1 - best), 4)}


def _nll(pairs, a, b) -> float:
    s = 0.0
    for y, z in pairs:
        p = min(max(sigmoid(a * z + b), 1e-9), 1 - 1e-9)
        s -= math.log(p if y else 1 - p)
    return s / max(len(pairs), 1)


def fit_platt(pairs: list[tuple[bool, float]], iters: int = 300, lr: float = 0.05) -> dict:
    """在验证集上用梯度下降拟合 p = σ(a·z + b)。"""
    a, b = 1.0, 0.0
    n = max(len(pairs), 1)
    for _ in range(iters):
        ga = gb = 0.0
        for y, z in pairs:
            p = sigmoid(a * z + b)
            ga += (p - y) * z
            gb += p - y
        a -= lr * ga / n
        b -= lr * gb / n
    return {"a": round(a, 4), "b": round(b, 4)}


def calibration_report(rows, prior, probes, platt) -> dict:
    bins = [[0, 0, 0.0] for _ in range(10)]
    brier = ll = ll_raw = 0.0
    for att, outs in rows:
        z = score(prior, outs, probes)
        p = calibrated(z, platt)
        q = min(max(sigmoid(z), 1e-6), 1 - 1e-6)
        pc = min(max(p, 1e-6), 1 - 1e-6)
        brier += (p - att) ** 2
        ll -= math.log(pc if att else 1 - pc)
        ll_raw -= math.log(q if att else 1 - q)
        b = bins[min(int(p * 10), 9)]
        b[0] += 1
        b[1] += att
        b[2] += p
    n = max(len(rows), 1)
    ece = sum(abs(b[1] - b[2]) for b in bins) / n
    return {
        "brier": round(brier / n, 4),
        "ece": round(ece, 4),
        "logloss": round(ll / n, 4),
        "logloss_uncalibrated": round(ll_raw / n, 4),
        "reliability": [
            {"bin": f"{i/10:.1f}-{(i+1)/10:.1f}", "n": b[0], "predicted": round(b[2] / b[0], 3) if b[0] else None, "observed": round(b[1] / b[0], 3) if b[0] else None}
            for i, b in enumerate(bins)
        ],
    }
