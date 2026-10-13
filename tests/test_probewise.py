import copy
import os
import tempfile

import pytest

from probewise.graph import Engine
from probewise.kb import KnowledgeBase, load_scenarios
from probewise.ledger import entropy, expected_info_gain
from probewise.proof import verify, whatif
from probewise.rag import Retriever

KB = KnowledgeBase.load()
TRUTH = {s["id"]: s["ground_truth"] for s in load_scenarios()}


@pytest.fixture(scope="module")
def engine():
    return Engine()


def test_knowledge_base_is_consistent():
    assert KB.validate() == []


def test_information_gain_is_bounded():
    for probe in KB.probes.values():
        for p in (0.05, 0.3, 0.5, 0.9):
            ig = expected_info_gain(p, probe["outcomes"])
            assert 0 <= ig <= entropy(p) + 1e-9


def test_no_confident_wrong_verdicts_with_rule_reader(engine):
    for sid, truth in TRUTH.items():
        v = engine.start(sid, approval_mode="defer")["verdict"]
        assert v["label"] in (truth, "escalate"), sid


def test_probewise_is_cheaper_than_full_playbook(engine):
    pw = sum(engine.start(s, approval_mode="defer")["verdict"]["cost_spent"] for s in TRUTH)
    sop = sum(engine.start(s, strategy="playbook", approval_mode="defer")["verdict"]["cost_spent"] for s in TRUTH)
    assert pw < sop


def test_proof_verifies_and_detects_tampering(engine):
    trace = engine.start("A-004", approval_mode="defer")
    assert verify(trace, KB)["ok"]

    forged = copy.deepcopy(trace)
    ev = next(r for r in forged["chain"] if r["kind"] == "evidence")
    ev["outcome"] = "expected_lineage" if ev["probe"] == "process_tree" else ev["outcome"]
    ev["lr"] = "0.1000"
    assert not verify(forged, KB)["ok"]


def test_whatif_flips_verdict(engine):
    trace = engine.start("A-007", approval_mode="defer")
    flips = {r["evidence_id"]: next(o for o in KB.probes[r["probe"]]["outcomes"] if KB.outcome(r["probe"], o)["p_mal"] < KB.outcome(r["probe"], o)["p_ben"]) for r in trace["rounds"]}
    result = whatif(trace, KB, flips)
    assert result["after"]["posterior"] < result["before"]["posterior"]


def test_human_approval_interrupt_and_resume(engine):
    trace = engine.start("A-004", approval_mode="interrupt")
    assert trace["status"] == "awaiting_approval"
    pending = {a["id"] for a in trace["pending"]}
    assert "isolate_host" in pending
    done = engine.approve(trace["run_id"], {"isolate_host": "approve"}, by="tester")
    assert done["status"] == "completed"
    statuses = {a["id"]: a["status"] for a in done["actions"]}
    assert statuses["isolate_host"] == "approved"
    assert any(r["kind"] == "approval" for r in done["chain"])
    assert verify(done, KB)["ok"]


def test_time_travel_fork_changes_investigation(engine):
    trace = engine.start("A-004", approval_mode="interrupt")
    first = trace["rounds"][0]
    benign_outcome = min(KB.probes[first["probe"]]["outcomes"], key=lambda o: KB.outcome(first["probe"], o)["p_mal"] / KB.outcome(first["probe"], o)["p_ben"])
    forked = engine.fork(trace["run_id"], first["evidence_id"], benign_outcome)
    assert forked["rounds"][0]["counterfactual"] is True
    assert forked["rounds"][0]["outcome"] == benign_outcome
    assert len(engine.checkpoints(trace["run_id"])) > len(trace["rounds"])


def test_external_reader_flow(engine):
    trace = engine.start("A-013", reader_mode="external", approval_mode="defer")
    steps = 0
    while trace["status"] == "awaiting_reading":
        waiting = trace["awaiting"]
        truth = next(s for s in load_scenarios() if s["id"] == "A-013")["world"][waiting["probe"]]
        trace = engine.submit_reading(trace["run_id"], truth)
        steps += 1
    assert steps >= 1
    assert trace["verdict"]["label"] == "benign"
    assert all(r["reader"] == "external" for r in trace["rounds"])


def test_external_reader_rejects_invalid_option(engine):
    trace = engine.start("A-001", reader_mode="external", approval_mode="defer")
    with pytest.raises(ValueError):
        engine.submit_reading(trace["run_id"], "definitely_not_an_option")


def test_robust_mode_requires_corroboration(engine):
    trace = engine.start("A-008", strategy="probewise-robust", approval_mode="defer")
    assert trace["corroboration"] == 2
    if trace["verdict"]["label"] != "escalate":
        strong = [r for r in trace["rounds"] if r["lr"] <= 0.5 or r["lr"] >= 2]
        assert len(strong) >= 2
    assert verify(trace, KB)["ok"]


def test_rag_returns_playbook_and_cases():
    hits = Retriever().search("财务人员账号 MFA 推送 异常登录", k=4, must_include=["P-01"])
    ids = [h["id"] for h in hits]
    assert ids[0] == "P-01"
    assert any(i.startswith("C-") for i in ids)


def test_telemetry_spans_follow_genai_conventions(engine):
    trace = engine.start("A-002", approval_mode="defer")
    names = [s["name"] for s in trace["telemetry"]]
    assert names[0].startswith("invoke_agent")
    tools = [s for s in trace["telemetry"] if s["name"].startswith("execute_tool")]
    assert tools and all(s["attributes"]["gen_ai.tool.name"] for s in tools)


def test_api_end_to_end():
    from fastapi.testclient import TestClient

    os.environ["PROBEWISE_DB"] = os.path.join(tempfile.mkdtemp(), "api.db")
    from probewise.api import app

    client = TestClient(app)
    assert len(client.get("/api/alerts").json()) == 18
    run = client.post("/api/runs", json={"alert_id": "A-014"}).json()
    assert run["status"] == "awaiting_approval"
    done = client.post(f"/api/runs/{run['run_id']}/approve", json={"decisions": {a["id"]: "approve" for a in run["pending"]}}).json()
    assert done["status"] == "completed"
    assert client.post(f"/api/runs/{run['run_id']}/verify").json()["ok"]
    assert client.get(f"/api/runs/{run['run_id']}/checkpoints").json()
    assert client.post("/api/runs", json={"alert_id": "nope"}).status_code == 400


def test_mcp_tools_drive_external_reading():
    from probewise import mcp_server

    step = mcp_server.open_case("A-011", mode="robust")
    world = next(s for s in load_scenarios() if s["id"] == "A-011")["world"]
    names = {p["name"]: k for k, p in KB.probes.items()}
    while "next" in step:
        probe = names[step["next"]["probe"]]
        step = mcp_server.submit_reading(step["case_id"], world[probe])
    assert step["verdict"]["label"] in ("benign", "escalate")
    assert mcp_server.verify_case(step["case_id"])["ok"]
    assert "处置依据" in mcp_server.get_report(step["case_id"])["report_markdown"]
