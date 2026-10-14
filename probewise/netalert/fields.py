"""网络攻击告警（WAF / IDS）的字段处理。

告警记录沿用 SecAlertBench 的字段（国内 WAF/IDS 常见格式）：
attack_type, rule_name, method, uri, parameter, req_header, req_body,
rsp_status, rsp_header, rsp_body, sip, dip, dport, proto ...

这些字段大多由请求方（可能是攻击者）控制，一律视为不可信数据：
只能被解析和引用，永远不能被当作指令。
"""

from __future__ import annotations

import html
import re
from urllib.parse import unquote_plus

REQUEST_FIELDS = ("uri", "parameter", "req_body", "req_header")
RESPONSE_FIELDS = ("rsp_body", "rsp_header")
ALL_FIELDS = (*REQUEST_FIELDS, *RESPONSE_FIELDS, "rule_name", "attack_type", "method", "rsp_status")


# 评测中发现会「泄漏答案」的采集伪特征（红队评审 research/04）：不同企业的设备配置不同，
# 这些字段区分的是「数据来自哪家」，不是「是不是攻击」。任何检查和大模型都看不到它们。
LEAKY_FIELDS = ("xff", "dport", "sport", "kill_chain_all", "attack_type", "sip", "dip", "host", "Label", "label", "ground_truth", "note_for_dev")
LEAKY_HEADERS = re.compile(r"^(?:Date|Server|X-Forwarded-For|X-Real-IP|Via|Set-Cookie|Last-Modified|Expires|ETag):.*$", re.I | re.M)


def sanitize(alert: dict) -> dict:
    """去掉采集伪特征后的告警视图。所有检查、证据核验、大模型输入都只用这个视图。"""
    out = {k: v for k, v in alert.items() if k not in LEAKY_FIELDS}
    for h in ("req_header", "rsp_header"):
        if out.get(h):
            out[h] = LEAKY_HEADERS.sub("", str(out[h]))
    return out


def text(alert: dict, field: str) -> str:
    v = alert.get(field)
    return "" if v is None else str(v)


def decode(s: str, rounds: int = 3) -> str:
    """逐层解码 URL 编码与 HTML 实体，直到不再变化（最多 rounds 层）。确定性，可复算。"""
    for _ in range(rounds):
        nxt = html.unescape(unquote_plus(s))
        if nxt == s:
            break
        s = nxt
    return s


def view(alert: dict, ref: str) -> str:
    """证据引用的原文视图：`uri` 表示原始字段，`uri@decoded` 表示解码后的字段。"""
    field, _, mode = ref.partition("@")
    raw = text(alert, field)
    return decode(raw) if mode == "decoded" else raw


def user_agent(alert: dict) -> str:
    m = re.search(r"User-Agent:[ \t]*([^\r\n]*)", text(alert, "req_header"), re.I)
    return m.group(1).strip() if m else ""


def path_of(alert: dict) -> str:
    uri = text(alert, "uri")
    path = uri.split("?", 1)[0]
    return path or "/"


def path_prefix(alert: dict) -> str:
    """第一段路径，用来识别「这是哪个业务系统」，例如 /FHB2B/QoHeader.do → /fhb2b。"""
    segs = [s for s in re.split(r"[/\\]+", path_of(alert)) if s]
    if not segs:
        return "/"
    first = segs[0].lower()
    # 带扩展名的单个文件（/index.php）和明显的探测串不当作业务系统名
    if len(segs) == 1 and "." in first:
        return "/"
    return "/" + first[:40]


def datamark(s: str, limit: int = 1500) -> str:
    """给不可信文本加数据标记（spotlighting）：交给大模型时，明确这是数据，不是指令。"""
    s = s[:limit].replace("<<", "‹‹").replace(">>", "››")
    return f"<<UNTRUSTED_DATA>>{s}<<END_UNTRUSTED_DATA>>"
