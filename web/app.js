"use strict";

// ---------- 基础 ----------
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const LABEL = { malicious: "真实威胁", benign: "误报", escalate: "升级人工" };
const STATUS = { auto: "已自动执行（模拟）", pending_approval: "待审批", approved: "已批准并执行（模拟）", rejected: "已驳回" };

async function api(path, opts = {}) {
  const res = await fetch("api/" + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `请求失败：HTTP ${res.status}`);
  return data;
}

const S = { alerts: [], kb: null, current: null, traces: {}, original: {}, decisions: {}, verifying: false };

// ---------- SHA-256（纯 JS；HTTP 页面无法使用 WebCrypto） ----------
function sha256(str) {
  const bytes = new TextEncoder().encode(str);
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const len = bytes.length;
  const total = Math.ceil((len + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(total - 8, Math.floor((len * 8) / 2 ** 32));
  view.setUint32(total - 4, (len * 8) >>> 0);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return Array.from(H, (x) => (x >>> 0).toString(16).padStart(8, "0")).join("");
}

// 与 Python json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":")) 逐字节一致
function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  return JSON.stringify(v);
}

// ---------- 在浏览器里独立验证证明 ----------
function verifyInBrowser(trace) {
  const checks = [];
  let prev = "0".repeat(64);
  let broken = null;
  for (const rec of trace.chain) {
    const { hash, ...body } = rec;
    if (rec.prev !== prev || sha256(canonical(body)) !== hash) { broken = rec.seq; break; }
    prev = hash;
  }
  checks.push({ name: "哈希链完整", ok: broken === null, detail: broken === null ? `${trace.chain.length} 条记录逐条重算 SHA-256 一致` : `第 ${broken} 条记录被改动` });

  let x = Math.log(trace.prior / (1 - trace.prior));
  const ev = trace.chain.filter((r) => r.kind === "evidence");
  for (const r of ev) {
    const o = S.kb.probes[r.probe].outcomes[r.outcome];
    x += Math.log(o.p_mal / o.p_ben);
  }
  const post = 1 / (1 + Math.exp(-x));
  const recorded = ev.length ? parseFloat(ev[ev.length - 1].posterior) : trace.prior;
  checks.push({ name: "后验可重算", ok: Math.abs(post - recorded) < 1e-3, detail: `只用先验和知识库似然重算为 ${post.toFixed(4)}，记录值 ${recorded.toFixed(4)}` });

  const th = trace.thresholds;
  let expected = post >= th.malicious ? "malicious" : post <= th.benign ? "benign" : "escalate";
  if (expected !== "escalate") {
    const strong = ev.filter((r) => (expected === "malicious" ? parseFloat(r.lr) >= 2 : parseFloat(r.lr) <= 0.5)).length;
    if (strong < (trace.corroboration || 1)) expected = "escalate";
  }
  const v = trace.chain.find((r) => r.kind === "verdict");
  checks.push({ name: "判定符合规则", ok: v && v.label === expected, detail: `按阈值与交叉印证规则应为「${LABEL[expected]}」，记录为「${v ? LABEL[v.label] : "无"}」` });
  return checks;
}

// ---------- 队列与告警头 ----------
function renderQueue() {
  $("qcount").textContent = `${S.alerts.length} 条`;
  $("queue").innerHTML = S.alerts
    .map((a) => {
      const t = S.traces[a.id];
      const v = t && t.verdict ? `<span class="chip ${t.verdict.label}">${LABEL[t.verdict.label]}</span>` : "";
      return `<button class="qitem ${S.current === a.id ? "on" : ""}" data-id="${a.id}">
        <div class="row"><span>${a.id}</span><span class="sev ${a.severity}">${a.severity}</span><span>${esc(a.type_name)}</span>${v}</div>
        <div class="t">${esc(a.title)}</div></button>`;
    })
    .join("");
  document.querySelectorAll(".qitem").forEach((b) => (b.onclick = () => selectAlert(b.dataset.id)));
}

function renderHeader(a) {
  const ents = Object.entries(a.entities || {}).filter(([, v]) => v && v !== "-");
  const strategies = S.kb.strategies.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("");
  $("ahead").innerHTML = `
    <div class="muted">${a.id} · ${esc(a.type_name)} · ${esc(a.time)} · <span class="sev ${a.severity}">${a.severity}</span></div>
    <h2>${esc(a.title)}</h2>
    <div>${esc(a.summary)}</div>
    <div class="ents">${ents.map(([k, v]) => `<span class="ent">${k}: ${esc(v)}</span>`).join("")}</div>
    <div class="controls">
      <label class="muted">策略 <select id="strategy">${strategies}</select></label>
      <label class="muted">预算 <input id="budget" type="number" min="1" max="30" value="10" style="width:64px" /></label>
      <button class="btn" id="run">开始调查</button>
      <span class="muted" id="runmsg"></span>
    </div>`;
  const t = S.traces[a.id];
  if (t) { $("strategy").value = t.strategy; $("budget").value = t.budget; }
  $("run").onclick = () => run(a.id);
}

async function selectAlert(id) {
  S.current = id;
  const a = S.alerts.find((x) => x.id === id);
  renderQueue();
  renderHeader(a);
  if (S.traces[id]) renderTrace(S.traces[id]);
  else await run(id);
}

async function run(id) {
  const btn = $("run");
  btn.disabled = true;
  $("runmsg").textContent = "LangGraph 正在运行…";
  try {
    const t = await api("runs", { method: "POST", body: { alert_id: id, strategy: $("strategy").value, budget: Number($("budget").value) } });
    S.traces[id] = t;
    delete S.original[id];
    S.decisions = {};
    renderQueue();
    renderTrace(t);
    $("runmsg").textContent = `完成，run_id = ${t.run_id}`;
  } catch (e) {
    $("runmsg").textContent = e.message;
  } finally {
    btn.disabled = false;
  }
}

// ---------- 调查过程 ----------
function renderChart(t) {
  const W = 640, H = 190, pad = { l: 34, r: 14, t: 12, b: 24 };
  const pts = [t.prior, ...t.rounds.map((r) => r.posterior_after)];
  const n = Math.max(pts.length - 1, 1);
  const X = (i) => pad.l + ((W - pad.l - pad.r) * i) / n;
  const Y = (p) => pad.t + (H - pad.t - pad.b) * (1 - p);
  const th = t.thresholds;
  const band = (y1, y2, color) => `<rect x="${pad.l}" y="${Y(y2)}" width="${W - pad.l - pad.r}" height="${Y(y1) - Y(y2)}" fill="${color}" opacity=".10"/>`;
  const line = pts.map((p, i) => `${i ? "L" : "M"}${X(i)},${Y(p)}`).join(" ");
  const dots = pts
    .map((p, i) => `<circle cx="${X(i)}" cy="${Y(p)}" r="4" fill="${p >= 0.5 ? "#f87171" : "#4ade80"}"/>
      <text x="${X(i)}" y="${H - 6}" text-anchor="middle">${i ? t.rounds[i - 1].evidence_id : "先验"}</text>
      <text x="${X(i)}" y="${Y(p) - 8}" text-anchor="middle">${p.toFixed(2)}</text>`)
    .join("");
  $("chart").innerHTML = `
    ${band(th.malicious, 1, "#f87171")}${band(0, th.benign, "#4ade80")}
    <line x1="${pad.l}" x2="${W - pad.r}" y1="${Y(th.malicious)}" y2="${Y(th.malicious)}" stroke="#f87171" stroke-dasharray="4 4" opacity=".6"/>
    <line x1="${pad.l}" x2="${W - pad.r}" y1="${Y(th.benign)}" y2="${Y(th.benign)}" stroke="#4ade80" stroke-dasharray="4 4" opacity=".6"/>
    <text x="4" y="${Y(th.malicious) + 4}">${th.malicious}</text><text x="4" y="${Y(th.benign) + 4}">${th.benign}</text>
    <path d="${line}" fill="none" stroke="#5eead4" stroke-width="2.5"/>${dots}`;
}

function renderRounds(t) {
  if (!t.rounds.length) { $("rounds").innerHTML = `<div class="empty">没有执行任何检查</div>`; return; }
  $("rounds").innerHTML = t.rounds
    .map((r) => {
      const maxScore = Math.max(...r.candidates.map((c) => c.score), 1e-9);
      const cands = r.candidates.length
        ? `<table class="cands">${r.candidates
            .map((c) => `<tr class="${c.chosen ? "chosen" : ""}"><td>${c.chosen ? "▶ " : ""}${esc(c.name)}</td><td>${c.info_gain.toFixed(3)} 比特</td><td>成本 ${c.cost}${c.affordable ? "" : "（超预算）"}</td><td style="width:30%"><div class="bar" style="width:${(100 * c.score) / maxScore}%"></div></td></tr>`)
            .join("")}</table>`
        : "";
      const opts = Object.entries(S.kb.probes[r.probe].outcomes)
        .map(([k, o]) => `<option value="${k}" ${k === r.outcome ? "selected" : ""}>${esc(o.label)}</option>`)
        .join("");
      return `<div class="round ${r.counterfactual ? "cf" : ""}">
        <div class="rhead"><span class="eid">${r.evidence_id}</span><b>${esc(r.probe_name)}</b><span class="muted">成本 ${r.cost} · 读取器 ${esc(r.reader)}</span>
          ${r.counterfactual ? `<span class="chip" style="color:#93c5fd">反事实改写</span>` : ""}
          <label class="cfsel muted">反事实：如果读到的是 <select data-eid="${r.evidence_id}" class="cf">${opts}</select></label></div>
        ${r.why ? `<div class="why">为什么查它：${esc(r.why)}${r.uncertainty_bits != null ? `（当前不确定性 ${r.uncertainty_bits} 比特）` : ""}</div>` : ""}
        ${cands}
        <div class="out">${esc(r.raw_text)}</div>
        <div class="reading">读取结论 <span class="pill ${r.lr > 1 ? "up" : "down"}">${esc(r.outcome_label)}</span>
          <span class="muted">似然比 ×${r.lr.toFixed(2)} · 对数几率 ${r.delta >= 0 ? "+" : ""}${r.delta.toFixed(2)} · 后验 ${r.posterior_before.toFixed(3)} → <b>${r.posterior_after.toFixed(3)}</b></span></div>
      </div>`;
    })
    .join("");
  document.querySelectorAll("select.cf").forEach((sel) => (sel.onchange = () => fork(sel.dataset.eid, sel.value)));
}

async function fork(eid, outcome) {
  const t = S.traces[S.current];
  if (!S.original[S.current]) S.original[S.current] = t;
  $("banner").innerHTML = `<div class="banner">正在回到 ${eid} 之前的 checkpoint 分叉重查…</div>`;
  try {
    const f = await api(`runs/${t.run_id}/fork`, { method: "POST", body: { evidence_id: eid, outcome } });
    S.traces[S.current] = f;
    renderQueue();
    renderTrace(f);
  } catch (e) {
    $("banner").innerHTML = `<div class="banner">${esc(e.message)}</div>`;
  }
}

function renderBanner(t) {
  if (!t.fork) { $("banner").innerHTML = ""; return; }
  const o = S.original[S.current];
  $("banner").innerHTML = `<div class="banner">🕰 time-travel：从 <b>${t.fork.evidence_id}</b> 之前的 checkpoint 分叉，把「${esc(S.kb.probes[t.fork.probe].name)}」改写为「${esc(S.kb.probes[t.fork.probe].outcomes[t.fork.outcome].label)}」后，控制器重新规划了之后的检查。
    原判定：${o ? `<span class="chip ${o.verdict.label}">${LABEL[o.verdict.label]} ${o.verdict.posterior.toFixed(3)}</span>` : "-"} → 反事实判定：<span class="chip ${t.verdict.label}">${LABEL[t.verdict.label]} ${t.verdict.posterior.toFixed(3)}</span>
    <button class="btn ghost small" id="back">回到原调查</button></div>`;
  $("back").onclick = () => { S.traces[S.current] = S.original[S.current]; delete S.original[S.current]; renderQueue(); renderTrace(S.traces[S.current]); };
}

// ---------- 判定、证明、处置、报告 ----------
function renderVerdict(t) {
  const v = t.verdict;
  const ans = S.alerts.find((a) => a.id === t.alert.id)?.answer;
  $("verdict").className = `panel verdict ${v.label}`;
  $("verdict").innerHTML = `
    <div class="muted">判定（${esc(S.kb.strategies.find((s) => s.id === t.strategy)?.name || t.strategy)}）</div>
    <div class="vlabel ${v.label}">${LABEL[v.label]}</div>
    <div class="post">P = ${v.posterior.toFixed(3)}</div>
    <p style="font-size:13px">${esc(v.summary)}</p>
    <div class="muted">检查 ${v.probes_used} 项 · 花费 ${v.cost_spent} / ${t.budget}${t.corroboration > 1 ? " · 交叉印证 ≥ " + t.corroboration + " 条强证据" : ""}</div>
    ${ans ? `<div class="muted" style="margin-top:6px">演示参考答案：<span class="chip ${ans}">${LABEL[ans]}</span>${v.label === "escalate" ? "（升级不算错：系统在证据不足时选择交给人工）" : ""}</div>` : ""}`;
}

function renderProof(t) {
  const p = t.verdict.proof;
  const total = p.prior_logodds + p.contributions.reduce((s, c) => s + c.delta, 0);
  $("proof").innerHTML = `
    <h3>证明 <span class="sub">对数几率逐项相加 = 后验</span></h3>
    <table class="ledger">
      <tr><td>先验（${esc(t.alert.type_name)}，P=${p.prior}）</td><td class="n">${p.prior_logodds.toFixed(2)}</td></tr>
      ${t.rounds.map((r) => `<tr><td>${r.evidence_id} ${esc(r.probe_name)}：${esc(r.outcome_label)}</td><td class="n" style="color:${r.delta > 0 ? "#f87171" : "#4ade80"}">${r.delta >= 0 ? "+" : ""}${r.delta.toFixed(2)}</td></tr>`).join("")}
      <tr class="total"><td>合计 → P = 1/(1+e<sup>−x</sup>)</td><td class="n">${total.toFixed(2)} → ${(1 / (1 + Math.exp(-total))).toFixed(3)}</td></tr>
    </table>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn ghost small" id="vb">在浏览器中独立验证</button>
      <button class="btn ghost small" id="tamper">模拟篡改后再验证</button>
    </div>
    <ul class="checks" id="vresult"></ul>`;
  const show = (checks, note) =>
    ($("vresult").innerHTML = (note ? `<li class="muted">${note}</li>` : "") + checks.map((c) => `<li class="${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"} ${c.name}：<span class="muted">${esc(c.detail)}</span></li>`).join(""));
  $("vb").onclick = () => show(verifyInBrowser(t), "不依赖后端：用 JS 重算哈希链与贝叶斯后验");
  $("tamper").onclick = () => {
    const forged = JSON.parse(JSON.stringify(t));
    const ev = forged.chain.find((r) => r.kind === "evidence");
    if (ev) { const alt = Object.keys(S.kb.probes[ev.probe].outcomes).find((o) => o !== ev.outcome); ev.outcome = alt; }
    show(verifyInBrowser(forged), `把 ${ev ? ev.evidence_id : "证据"} 的结论偷偷改掉后：`);
  };
}

function renderActions(t) {
  const pending = t.status === "awaiting_approval";
  // 暂停期间 respond 节点还没返回，待审批的动作来自 interrupt 载荷
  const list = pending ? t.pending : t.actions;
  $("actions").innerHTML = `
    <h3>处置 <span class="sub">${pending ? "高危动作已被 LangGraph interrupt 暂停，等待人工审批" : "人在回路：需要审批的动作不会自动执行"}</span></h3>
    ${pending ? `<div class="muted" style="margin-bottom:4px">以下动作需要人工决定；无需审批的动作会在提交后一并执行（模拟）。</div>` : ""}
    ${list
      .map((a) => {
        const ctl =
          pending && a.status === "pending_approval"
            ? `<span class="seg"><button class="approve ${S.decisions[a.id] === "approve" ? "on" : ""}" data-a="${a.id}" data-d="approve">批准</button><button class="reject ${S.decisions[a.id] === "reject" ? "on" : ""}" data-a="${a.id}" data-d="reject">驳回</button></span>`
            : "";
        return `<div class="act"><span class="name">${esc(a.name)}</span><span class="st ${a.status}">${STATUS[a.status]}</span>${ctl}</div>`;
      })
      .join("")}
    ${pending ? `<div class="controls"><input type="text" id="by" value="值班分析师" style="width:120px" /><button class="btn small" id="submit">提交审批</button><span class="muted" id="amsg"></span></div>` : ""}
    ${t.approvals.length ? `<div class="muted" style="margin-top:6px">审批记录已写入哈希链：${t.approvals.map((x) => `${esc(x.by)} ${x.decision === "approve" ? "批准" : "驳回"} ${x.action}`).join("；")}</div>` : ""}`;
  document.querySelectorAll(".seg button").forEach((b) => (b.onclick = () => { S.decisions[b.dataset.a] = b.dataset.d; renderActions(t); }));
  if (pending) $("submit").onclick = async () => {
    const decisions = {};
    t.pending.forEach((a) => (decisions[a.id] = S.decisions[a.id] || "reject"));
    try {
      const d = await api(`runs/${t.run_id}/approve`, { method: "POST", body: { decisions, by: $("by").value || "analyst" } });
      S.traces[S.current] = d;
      S.decisions = {};
      renderTrace(d);
    } catch (e) { $("amsg").textContent = e.message; }
  };
}

function md(text) {
  const lines = esc(text).split("\n");
  let html = "", inList = false;
  for (const l of lines) {
    const b = l.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\[(E\d+|[PC]-\d+|T\d+)\]/g, '<span class="eid">[$1]</span>');
    if (l.startsWith("- ")) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${b.slice(2)}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (l.startsWith("### ")) html += `<h4>${b.slice(4)}</h4>`;
    else if (l.trim()) html += `<p>${b}</p>`;
  }
  return html + (inList ? "</ul>" : "");
}

function renderReport(t) {
  if (!t.report) { $("report").innerHTML = `<h3>报告</h3><div class="muted">等待审批后生成</div>`; return; }
  $("report").innerHTML = `<h3>报告 <span class="sub">RAG 检索的处置手册与相似案例</span></h3>
    <div class="md">${md(t.report.markdown)}</div>
    ${t.context.map((c) => `<details class="ref"><summary>[${c.id}] ${esc(c.title)} <span class="muted">· ${esc(c.source)} · BM25 ${c.score}</span></summary><div>${esc(c.text)}</div></details>`).join("")}`;
}

function renderWaterfall(t) {
  const spans = t.telemetry || [];
  $("spancount").textContent = `${spans.length} 个 span`;
  const end = Math.max(...spans.map((s) => s.start_ms + s.duration_ms), 1);
  $("waterfall").innerHTML = spans
    .map((s) => `<div class="wfrow"><span class="nm" title="${esc(JSON.stringify(s.attributes))}">${s.parent_id ? "　" : ""}${esc(s.name)}</span>
      <span class="track"><span class="span ${s.name.startsWith("execute_tool") ? "tool" : ""}" style="left:${(100 * s.start_ms) / end}%;width:${Math.max((100 * s.duration_ms) / end, 0.6)}%"></span></span>
      <span class="d">${s.duration_ms.toFixed(1)}ms</span></div>`)
    .join("");
}

async function loadCheckpoints(t) {
  try {
    const cps = await api(`runs/${t.run_id}/checkpoints`);
    $("cpcount").textContent = `${cps.length} 个 checkpoint（SQLite 持久化）`;
    $("checkpoints").innerHTML = cps
      .map((c) => `<div>step ${String(c.step).padStart(2)} · 下一节点 ${c.next.join(",") || "（结束）"} · 证据 ${c.rounds} 条 · P=${c.posterior ?? "-"} · ${c.checkpoint_id.slice(0, 13)}…</div>`)
      .join("");
  } catch { $("checkpoints").textContent = "加载失败"; }
}

function renderTrace(t) {
  renderBanner(t);
  renderChart(t);
  renderRounds(t);
  if (t.verdict) { renderVerdict(t); renderProof(t); }
  renderActions(t);
  renderReport(t);
  renderWaterfall(t);
  loadCheckpoints(t);
}

// ---------- 基准测试 ----------
let benchLoaded = false;
async function loadBench() {
  if (benchLoaded) return;
  benchLoaded = true;
  const b = await api("bench");
  $("benchmeta").textContent = `${b.scenarios} 个场景 × 5 种策略 × 3 档读取噪声，每档 ${b.seeds} 个随机种子，预算 ${b.budget}`;
  const pct = (x) => (x * 100).toFixed(1) + "%";
  $("benchtable").innerHTML = `<table class="btable"><tr><th>读取噪声</th><th>策略</th><th>正确率</th><th>漏报率</th><th>误报率</th><th>升级率</th><th>平均成本</th><th>平均检查数</th></tr>
    ${b.rows.map((r) => `<tr class="${r.strategy.startsWith("probewise") ? "pw" : ""}"><td>${pct(r.noise)}</td><td>${esc(r.strategy_name)}</td><td>${pct(r.correct_rate)}</td><td>${pct(r.missed_threat_rate)}</td><td>${pct(r.false_alarm_rate)}</td><td>${pct(r.escalation_rate)}</td><td>${r.avg_cost.toFixed(2)}</td><td>${r.avg_probes.toFixed(2)}</td></tr>`).join("")}</table>`;
  const metric = (key, title, cls, fmt, max) =>
    `<div class="panel"><h3>${title}</h3>${[0, 0.1, 0.2]
      .map((n) => `<div class="muted" style="margin-top:6px">读取噪声 ${pct(n)}</div>${b.rows
        .filter((r) => r.noise === n)
        .map((r) => `<div class="hbar"><span>${esc(r.strategy_name.split("（")[0])}</span><span class="track"><span class="fill ${cls}" style="display:block;width:${(100 * r[key]) / max}%"></span></span><span class="v">${fmt(r[key])}</span></div>`)
        .join("")}`)
      .join("")}</div>`;
  const maxCost = Math.max(...b.rows.map((r) => r.avg_cost));
  $("benchcharts").innerHTML =
    metric("correct_rate", "正确率（越高越好）", "", pct, 1) +
    metric("missed_threat_rate", "漏报率（越低越好）", "warn", pct, Math.max(...b.rows.map((r) => r.missed_threat_rate), 0.01)) +
    metric("escalation_rate", "升级率", "esc", pct, 1) +
    metric("avg_cost", "平均调查成本（越低越好）", "", (x) => x.toFixed(2), maxCost);
  const get = (s, n) => b.rows.find((r) => r.strategy === s && r.noise === n);
  const f0 = get("probewise", 0), sop0 = get("playbook", 0), f1 = get("probewise", 0.1), r1 = get("probewise-robust", 0.1);
  $("benchtake").innerHTML = `<h3>结论</h3><ul class="md" style="font-size:13px">
    <li>读取准确时，Probewise 快速模式正确率 ${pct(f0.correct_rate)}，平均成本 ${f0.avg_cost.toFixed(2)}；固定 SOP 正确率 ${pct(sop0.correct_rate)}，成本 ${sop0.avg_cost.toFixed(2)}。按信息增益选检查，用更少的成本得到更多确定结论。</li>
    <li>读取器有 10% 出错率时，快速模式漏报率 ${pct(f1.missed_threat_rate)}；开启交叉印证的稳健模式降到 ${pct(r1.missed_threat_rate)}，代价是升级率从 ${pct(f1.escalation_rate)} 升到 ${pct(r1.escalation_rate)}。</li>
    <li>因此：读取器可靠（规则、强模型）时用快速模式；用本地小模型读取时用稳健模式，宁可多升级，也不要漏掉真实威胁。</li>
    <li>说明：场景为合成数据，似然参数是示意值，结论用于说明方法的取舍，不代表真实环境的绝对数值。</li></ul>`;
}

// ---------- 启动 ----------
document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + b.dataset.view));
  if (b.dataset.view === "bench") loadBench().catch((e) => ($("benchtable").innerHTML = `<div class="empty">${esc(e.message)}</div>`));
}));

(async function init() {
  try {
    [S.alerts, S.kb] = await Promise.all([api("alerts"), api("kb")]);
    renderQueue();
    await selectAlert("A-004");
  } catch (e) {
    $("ahead").innerHTML = `<div class="empty">无法连接后端：${esc(e.message)}</div>`;
  }
})();
