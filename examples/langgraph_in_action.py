"""LangGraph 在 Probewise 里具体干了什么：四个场景，直接看运行结果。

    python examples/langgraph_in_action.py
"""

import os
import sqlite3
import sys
import tempfile

from langgraph.checkpoint.sqlite import SqliteSaver

from probewise.graph import Engine

DB = os.path.join(tempfile.gettempdir(), "probewise_langgraph_demo.db")
if os.path.exists(DB):
    os.remove(DB)


def new_engine():
    # 每次新建一个 Engine，相当于“重启一次服务”，只有 SQLite 文件是共享的
    return Engine(checkpointer=SqliteSaver(sqlite3.connect(DB, check_same_thread=False)))


def show_rounds(t):
    for r in t["rounds"]:
        print(f"   {r['evidence_id']} {r['probe_name']:<8} → {r['outcome_label']:<8} 可疑度 {r['posterior_before']:.3f} → {r['posterior_after']:.3f}")


print("=" * 70)
print("场景 1：流程图 —— LangGraph 按这张图调度，plan ⇄ investigate 会自己绕圈")
print("=" * 70)
eng = new_engine()
print(eng.graph.get_graph().draw_mermaid())

print("=" * 70)
print("场景 2：自动绕圈 + 停下来等人批准（interrupt）")
print("=" * 70)
t = eng.start("A-004", run_id="demo-1")
show_rounds(t)
snap = eng.graph.get_state(eng.config("demo-1"))
print(f"\n   结论：{t['verdict']['label']}（{t['verdict']['posterior']:.3f}）")
print(f"   LangGraph 当前状态：流程停在节点 {snap.next}，等待人工审批")
for a in eng.pending("demo-1"):
    print(f"   待审批动作：{a['name']}")

print("\n   每走一步存一次档（共 %d 个存档点，从新到旧）：" % len(eng.checkpoints("demo-1")))
for c in eng.checkpoints("demo-1"):
    print(f"     step {c['step']:>2}  下一步={str(c['next']):<18} 已有证据 {c['rounds']} 条  可疑度 {c['posterior']}")

print("\n" + "=" * 70)
print("场景 3：模拟服务器重启 —— 新进程从 SQLite 读回存档，接着审批")
print("=" * 70)
del eng
eng2 = new_engine()  # 全新的对象，内存里什么都没有
print(f"   重启后读回状态：流程仍停在 {eng2.graph.get_state(eng2.config('demo-1')).next}")
t = eng2.approve("demo-1", {a["id"]: "approve" for a in eng2.pending("demo-1")}, by="张分析师")
for a in t["actions"]:
    print(f"   {a['name']}：{a['status']}")
print(f"   流程已走完：下一步 = {eng2.graph.get_state(eng2.config('demo-1')).next or '无（结束）'}")

print("\n" + "=" * 70)
print("场景 4：读档重来（time-travel）—— 假设 E3 当时查出来是另一个结果")
print("=" * 70)
probe = t["rounds"][2]["probe"]
outcomes = list(eng2.kb.probes[probe]["outcomes"])
alt = [o for o in outcomes if o != t["rounds"][2]["outcome"]][-1]
print(f"   原来 E3「{t['rounds'][2]['probe_name']}」= {t['rounds'][2]['outcome_label']}，改成 {eng2.kb.probes[probe]['outcomes'][alt]['label']}")
f = eng2.fork("demo-1", "E3", alt)
print(f"   回到存档点 {f['fork']['from_checkpoint'][:18]}…，从那里重新往下查：")
show_rounds(f)
print(f"   新结论：{f['verdict']['label']}（{f['verdict']['posterior']:.3f}）—— E3 之后的步骤是从存档点重新跑出来的，控制器会按新的可疑度重新规划")

print("\n" + "=" * 70)
print("场景 5：外部 AI 当“读卡员” —— 每查一项就 interrupt，把材料交给外部 AI 选答案")
print("=" * 70)
t = eng2.start("A-004", run_id="demo-2", reader_mode="external")
w = eng2.awaiting("demo-2")
print(f"   流程停住，交给外部 AI 的材料：\n     检查：{w['probe_name']}\n     工具原文：{w['raw_text']}\n     只能选：{list(w['options'].values())}")
pick = list(w["options"])[0]
t = eng2.submit_reading("demo-2", pick, reader="claude-code")
w = eng2.awaiting("demo-2")
print(f"   外部 AI 选了「{t['rounds'][0]['outcome_label']}」→ LangGraph 恢复执行，控制器算分后又停在下一项：{w['probe_name'] if w else '无'}")
