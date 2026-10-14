"""网络攻击告警的调查子 Agent（运行手册模式）。

每个子 Agent 只回答一个小问题，只用只读工具，交回一份 Finding：
    {check, outcome, evidence:[...], steps:[...], summary, mode}

- outcome 必须是知识库里该检查的枚举值之一；
- evidence 里引用告警原文的片段（excerpt）必须能在对应字段视图中逐字找到，
  引用历史工单的条目必须能被重新查询复算 —— 见 verify.py；
- steps 记录子 Agent 每一步做了什么，供分析员复查。

运行手册模式是确定性的、无需任何模型或 key；LLM 模式见 llm_agent.py。
"""

from __future__ import annotations

import re

from .fields import REQUEST_FIELDS, decode, path_prefix, sanitize, text, user_agent

# ---------- 载荷特征 ----------
# 强特征：出现即可视为明确的利用载荷
EXPLOIT_SIGNATURES = [
    ("目录穿越", r"(?:\.\.[/\\]){2,}|(?:\.\.%2f|\.\.%5c){2,}"),
    ("敏感文件路径", r"/etc/(?:passwd|shadow|hosts|group)\b|win\.ini|boot\.ini|windows[/\\]+system32|/proc/self/environ"),
    ("JNDI 注入（Log4Shell）", r"\$\{\s*(?:jndi|::-j|lower:j|upper:j|env:)"),
    ("OGNL / 表达式注入", r"\$\{\s*\(?\s*\d+\s*\*\s*\d+|%\{\s*\(?\s*\d+\s*\*|#_memberAccess|@java\.lang|java\.lang\.Runtime|class\.module\.classLoader|T\(java\."),
    ("SQL 注入载荷", r"union(?:\s|/\*.*?\*/|\+)+(?:all(?:\s|\+)+)?select|sleep\s*\(\s*\d|benchmark\s*\(|extractvalue\s*\(|updatexml\s*\(|waitfor\s+delay|information_schema|xp_cmdshell|'\s*(?:or|and)\s*'?\d+'?\s*=\s*'?\d"),
    ("XSS 载荷", r"<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*svg[^>]*on\w+\s*="),
    ("命令注入", r"[;|`&]\s*(?:echo|cat|id|whoami|wget|curl|ping|nslookup|bash|sh|uname)\b|\$\(\s*(?:id|whoami|uname)|/bin/(?:ba)?sh\b|cmd\.exe|powershell"),
    ("Java 反序列化载荷", r"rememberMe=[A-Za-z0-9+/=%]{40,}|rO0AB[A-Za-z0-9+/=]{20,}|aced0005[0-9a-f]{16,}"),
    ("WebShell / 代码执行", r"\beval\s*\(|\bassert\s*\(|base64_decode\s*\(|phpinfo\s*\(|<\?php|\bsystem\s*\(|passthru\s*\(|shell_exec"),
]
# 弱特征：常见于业务系统自己拼的 SQL、搜索框、调试参数，单独出现不足以说明是攻击
WEAK_SIGNATURES = [
    ("SQL 关键字", r"\bselect\b.{0,200}?\bfrom\b|\b(?:and|or)\s+1\s*=\s*[01]\b|\border\s+by\b|\bwhere\b|\bdelete\s+from\b|\binsert\s+into\b"),
    ("脚本 / 标签片段", r"<\s*(?:iframe|img|a)\b|document\.cookie"),
    ("路径跳转片段", r"\.\.[/\\]|redirect:|url=https?://"),
]

TOOL_UA = r"sqlmap|nuclei|zgrab|masscan|nmap|nikto|dirbuster|gobuster|dirsearch|xray|awvs|acunetix|nessus|openvas|wpscan|hydra|fuzz|burp|goby|fscan|afrog"
SCRIPT_UA = r"python-requests|python-urllib|aiohttp|httpx|curl/|wget/|go-http-client|java/|okhttp|apache-httpclient|libwww|scrapy|axios|node-fetch|postman"

SUCCESS_MARKERS = [
    ("/etc/passwd 内容", r"root:[^:\r\n]*:0:0:"),
    ("win.ini 内容", r"\[(?:extensions|fonts|mci extensions)\]"),
    ("命令执行回显", r"uid=\d+\([a-z_][\w-]*\)"),
    ("phpinfo 页面", r"<title>phpinfo\(\)|PHP Version \d"),
    ("数据库报错", r"You have an error in your SQL syntax|ORA-\d{5}|mysql_fetch|Microsoft OLE DB|SQLSTATE\[|Unclosed quotation mark"),
]


def _cite(ref: str, s: str, m: re.Match, note: str, pad: int = 24) -> dict:
    """证据绑定到（字段视图, 偏移量）：核验时要求 view[offset:offset+len] 与引用逐字相同。"""
    a, b = max(0, m.start() - pad), min(len(s), m.end() + pad)
    return {"source": "alert", "ref": ref, "offset": a, "excerpt": s[a:b], "note": note}


def _cite_span(ref: str, s: str, start: int, length: int, note: str) -> dict:
    return {"source": "alert", "ref": ref, "offset": start, "excerpt": s[start : start + length], "note": note}


class Check:
    id = ""
    name = ""
    fields: tuple = ()  # 该检查允许引用的字段：防止攻击者在请求里伪造「响应报错」再被当作响应证据引用

    def run(self, alert: dict, ctx: dict) -> dict:
        raise NotImplementedError

    def _finding(self, outcome: str, evidence: list, steps: list, summary: str) -> dict:
        return {"check": self.id, "outcome": outcome, "evidence": evidence, "steps": steps, "summary": summary, "mode": "runbook"}


class PayloadCheck(Check):
    id = "payload_check"
    name = "载荷核验"
    fields = REQUEST_FIELDS

    def run(self, alert, ctx):
        steps, strong, weak = [], [], []
        for field in REQUEST_FIELDS:
            raw = text(alert, field)
            if not raw:
                continue
            dec = decode(raw)
            ref = f"{field}@decoded" if dec != raw else field
            steps.append({"tool": "decode_field", "args": {"field": field}, "result": f"{len(raw)} 字符" + ("，已逐层解码" if dec != raw else "，无需解码")})
            for label, pat in EXPLOIT_SIGNATURES:
                m = re.search(pat, dec, re.I | re.S)
                if m:
                    strong.append(_cite(ref, dec, m, label))
            for label, pat in WEAK_SIGNATURES:
                m = re.search(pat, dec, re.I | re.S)
                if m:
                    weak.append(_cite(ref, dec, m, label))
        steps.append({"tool": "match_signatures", "args": {"sets": ["exploit", "weak"]}, "result": f"强特征 {len(strong)} 处，弱特征 {len(weak)} 处"})
        if strong:
            kinds = "、".join(dict.fromkeys(e["note"] for e in strong))
            return self._finding("explicit_exploit", strong[:3], steps, f"请求中有明确的利用载荷：{kinds}")
        if weak:
            kinds = "、".join(dict.fromkeys(e["note"] for e in weak))
            return self._finding("weak_fragment", weak[:2], steps, f"只有弱特征（{kinds}），常见于业务系统自己拼接的参数")
        return self._finding("no_payload", [], steps, "请求中没有发现攻击载荷，告警可能由路径或规则本身触发")


class ResponseCheck(Check):
    id = "response_check"
    name = "响应研判"
    fields = ("rsp_body", "rsp_header", "rsp_status")

    def run(self, alert, ctx):
        status = alert.get("rsp_status")
        body = text(alert, "rsp_body")
        steps = [{"tool": "read_response", "args": {"fields": ["rsp_status", "rsp_body"]}, "result": f"状态码 {status}，响应体 {len(body)} 字符"}]
        markers = list(SUCCESS_MARKERS)
        # 表达式注入常用 ${a*b} 探测：响应里出现乘积就是执行成功的回显
        req = decode(" ".join(text(alert, f) for f in REQUEST_FIELDS))
        for a, b in re.findall(r"\$\{\s*\(?\s*(\d{2,6})\s*\*\s*(\d{2,6})", req)[:2]:
            markers.append((f"表达式 {a}*{b} 的计算结果", re.escape(str(int(a) * int(b)))))
        # 命令注入常用 echo 一个随机标记：响应里原样出现这个标记，说明命令被执行了
        for tok in re.findall(r"\becho\s+['\"]?([A-Za-z0-9_]{6,40})", req)[:2]:
            markers.append((f"echo 标记 {tok} 的回显", re.escape(tok)))
        header = text(alert, "rsp_header")
        for label, pat in markers:
            for field, s in (("rsp_body", body), ("rsp_header", header)):
                m = re.search(pat, s, re.I)
                if m:
                    steps.append({"tool": "match_success_markers", "args": {"field": field}, "result": f"命中：{label}"})
                    return self._finding("exploit_echo", [_cite(field, s, m, label)], steps, f"响应中出现利用成功的迹象：{label}，需要立即升级")
        steps.append({"tool": "match_success_markers", "args": {}, "result": "未命中"})
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = 0
        ev = [_cite_span("rsp_status", str(status), 0, len(str(status)), "响应状态码")] if status is not None else []
        if code == 0:
            return self._finding("no_response", ev, steps, "没有捕获到响应（连接被拦截、中断或设备未记录）")
        if code in (400, 404, 405, 406, 410, 501):
            return self._finding("not_found_or_rejected", ev, steps, f"状态码 {code}：目标资源不存在或请求被拒绝，常见于对不存在路径的批量探测")
        if code >= 500:
            return self._finding("server_error", ev, steps, f"状态码 {code}：服务端报错，载荷可能触发了异常处理")
        if code in (401, 403, 407) or 300 <= code < 400:
            return self._finding("auth_or_redirect", ev, steps, f"状态码 {code}：需要认证或被重定向")
        return self._finding("normal_success", ev, steps, f"状态码 {code}：正常返回，且没有利用成功的迹象")


class ClientCheck(Check):
    id = "client_profile"
    name = "客户端画像"
    fields = ("req_header",)

    def run(self, alert, ctx):
        ua = user_agent(alert)
        steps = [{"tool": "parse_headers", "args": {"header": "User-Agent"}, "result": ua[:80] or "（无）"}]
        if not ua:
            return self._finding("missing", [], steps, "请求没有 User-Agent")
        hdr = text(alert, "req_header")
        ev = [_cite_span("req_header", hdr, hdr.find(ua), min(len(ua), 120), "User-Agent")]
        if re.search(TOOL_UA, ua, re.I):
            return self._finding("attack_tool", ev, steps, "User-Agent 是已知的扫描 / 攻击工具")
        if re.search(SCRIPT_UA, ua, re.I):
            return self._finding("script_client", ev, steps, "User-Agent 是脚本或程序库，不是浏览器")
        if re.search(r"mozilla|chrome|safari|edg/|firefox", ua, re.I):
            return self._finding("browser", ev, steps, "User-Agent 是常见浏览器（注意：攻击者可以伪造）")
        return self._finding("script_client", ev, steps, "User-Agent 不是浏览器")


class RuleHistoryCheck(Check):
    """把「这条规则平时报得准不准」从分析员的记忆变成可查询的数据。"""

    id = "rule_history"
    name = "规则历史处置"
    fields = ("rule_name",)
    MIN = 5

    def run(self, alert, ctx):
        hist = ctx["history"]
        rule = text(alert, "rule_name")
        att, tot = hist.lookup("rule", rule, exclude=ctx.get("exclude"))
        steps = [{"tool": "query_ticket_history", "args": {"key": "rule_name", "value": rule[:60]}, "result": f"历史 {tot} 条，其中真攻击 {att} 条"}]
        ev = [
            _cite_span("rule_name", rule, 0, min(len(rule), 120), "告警规则"),
            {"source": "history", "query": {"key": "rule", "value": rule}, "result": {"attack": att, "total": tot}, "note": "团队历史工单"},
        ]
        if tot < self.MIN:
            return self._finding("sparse", ev, steps, f"这条规则历史只有 {tot} 条，经验不足")
        rate = att / tot
        if rate <= 0.1:
            return self._finding("mostly_fp", ev, steps, f"这条规则历史上 {tot} 条里只有 {att} 条是真攻击（{rate:.0%}），以误报为主")
        if rate >= 0.7:
            return self._finding("mostly_attack", ev, steps, f"这条规则历史上 {tot} 条里有 {att} 条是真攻击（{rate:.0%}），报得很准")
        return self._finding("mixed", ev, steps, f"这条规则历史上真攻击占 {rate:.0%}（{att}/{tot}），好坏参半")


class PathProfileCheck(Check):
    """这个路径是不是本单位自己的业务系统：分析员靠记忆，这里靠历史工单。"""

    id = "path_profile"
    name = "业务路径画像"
    fields = ("uri",)
    MIN = 5

    def run(self, alert, ctx):
        hist = ctx["history"]
        prefix = path_prefix(alert)
        steps = [{"tool": "extract_path_prefix", "args": {}, "result": prefix}]
        if prefix == "/":
            return self._finding("generic_path", [_cite_span("uri", text(alert, "uri"), 0, min(len(text(alert, "uri")), 80), "请求路径")], steps, "请求的是根路径或单个文件，看不出属于哪个业务系统")
        att, tot = hist.lookup("path", prefix, exclude=ctx.get("exclude"))
        steps.append({"tool": "query_ticket_history", "args": {"key": "path_prefix", "value": prefix}, "result": f"历史 {tot} 条，其中真攻击 {att} 条"})
        ev = [{"source": "history", "query": {"key": "path", "value": prefix}, "result": {"attack": att, "total": tot}, "note": "该路径的历史告警"}]
        if tot < self.MIN:
            return self._finding("unseen_path", ev, steps, f"路径 {prefix} 历史上很少出现（{tot} 次）")
        rate = att / tot
        if rate <= 0.1:
            return self._finding("business_path", ev, steps, f"路径 {prefix} 历史上 {tot} 条告警几乎都是误报，像是本单位的业务系统")
        if rate >= 0.7:
            return self._finding("attack_path", ev, steps, f"路径 {prefix} 历史上大多是攻击探测（{att}/{tot}）")
        return self._finding("mixed_path", ev, steps, f"路径 {prefix} 历史上好坏参半（{att}/{tot}）")


def run_check(check_id: str, alert: dict, ctx: dict, registry: dict | None = None) -> dict:
    """统一入口：检查只看去掉伪特征后的告警视图。registry 让每个引擎有自己的检查集合（例如加上大模型复核）。"""
    return (registry or CHECKS)[check_id].run(sanitize(alert), ctx)


CHECKS = {c.id: c for c in (RuleHistoryCheck(), PayloadCheck(), ResponseCheck(), ClientCheck(), PathProfileCheck())}
