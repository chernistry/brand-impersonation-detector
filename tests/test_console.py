"""Operator console: runs, a person's decisions, releases, queue stop and exports."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bid import api, records
from bid.decisions import latest_by_candidate
from bid.evidence import manifest_hash, verify_chain_public
from bid.governance import load_config
from bid.storage import ContentStore

NOW = datetime(2026, 11, 6, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def config():
    return load_config()[0]  # the bundled example settings


@pytest.fixture
def run(tmp_path):
    view = api.run_pipeline_api(tmp_path, k=10, now=NOW)
    return tmp_path, view


def _escalated_positive(view) -> str:
    for b in view["brands"]:
        for c in b["queue"]:
            if c["label"] in ("impersonation", "fraud") and c["receipt"]["outcome"] == "escalate":
                return c["candidate_id"]
    raise AssertionError("fixture run has no escalated positive finding")


def test_run_triages_every_candidate_and_waits_for_a_person(run):
    root, view = run
    assert view["evidence"]["pub_ok"] and view["evidence"]["chain_ok"]
    total, signed = view["evidence"]["coverage"].split("/")
    assert total == signed
    queue = [c for b in view["brands"] for c in b["queue"]]
    assert queue and all(c["receipt"]["automated"] for c in queue)
    # positive findings are never confirmed by the default policy
    assert not any(c["receipt"]["outcome"] == "confirm" for c in queue)
    assert view["metrics"]["open_holds"] >= 1
    first = queue[0]
    assert first["model"]["id"] and first["model"]["family"]
    assert first["triage_reason"]
    assert first["calibrated_band"] in ("above_threshold", "below_threshold")


def test_each_run_keeps_its_own_directory(tmp_path):
    first = api.run_pipeline_api(tmp_path, k=10, now=NOW)
    second = api.run_pipeline_api(tmp_path, k=10, now=NOW)
    assert first["run_id"] != second["run_id"]
    assert len(list((tmp_path / "runs").iterdir())) == 2
    assert api.current_run(tmp_path).name == second["run_id"]


def test_person_decisions_are_signed_into_the_chain(run):
    root, view = run
    cid = _escalated_positive(view)
    r = api.decide(root, cid, "confirm", "analyst_01", note="matches the brand's logo", now=NOW)
    assert r["receipt"]["outcome"] == "confirm" and not r["receipt"]["automated"]
    assert r["receipt"]["decided_by"] == "analyst_01"
    assert r["chain"]["pub_ok"] and r["chain"]["index"] == r["chain"]["length"] - 1
    assert r["feedback"]["ledger_verified"]

    again = api.decide(root, cid, "confirm", "analyst_01", now=NOW)
    assert again["already_signed"] and again["receipt"] == r["receipt"]
    with pytest.raises(ValueError, match="release"):
        api.decide(root, cid, "reject", "analyst_01", now=NOW)

    run_dir = api.current_run(root)
    chain = records.read_receipts(run_dir)
    assert verify_chain_public(chain, ContentStore(run_dir))[0]
    assert api.run_view(root)["evidence"]["by_outcome"]["confirm"] == 1


def test_decision_needs_a_named_person_and_a_known_candidate(run):
    root, view = run
    cid = _escalated_positive(view)
    with pytest.raises(ValueError, match="who is acting"):
        api.decide(root, cid, "confirm", "  ", now=NOW)
    with pytest.raises(LookupError):
        api.decide(root, "no-such-candidate", "confirm", "analyst_01", now=NOW)
    with pytest.raises(ValueError):
        api.decide(root, cid, "release", "analyst_01", now=NOW)


def test_release_needs_a_declared_releaser_and_blocks_export(run, config):
    root, view = run
    cid = _escalated_positive(view)
    confirm = api.decide(root, cid, "confirm", "analyst_01", now=NOW)
    assert api.project_api(root, cid, "finding")["receipt"]["outcome"] == "confirm"

    with pytest.raises(PermissionError):
        api.release_api(root, cid, "analyst_01", "wrong account", config, now=NOW)
    with pytest.raises(ValueError, match="reason"):
        api.release_api(root, cid, "counsel-01", " ", config, now=NOW)
    r = api.release_api(root, cid, "counsel-01", "the account belongs to a licensed reseller", config, now=NOW)
    assert r["receipt"]["outcome"] == "release"
    assert r["receipt"]["supersedes"] == confirm["receipt"]["manifest_hash"]
    assert r["receipt"]["authority"] == "legal counsel"
    with pytest.raises(ValueError, match="only a confirmed finding"):
        api.project_api(root, cid, "finding")


def test_stop_halts_runs_and_exports_but_not_people(run, config):
    root, view = run
    cid = _escalated_positive(view)
    api.decide(root, cid, "confirm", "analyst_01", now=NOW)
    with pytest.raises(PermissionError):
        api.set_queue(True, "someone-else", "", config, now=NOW)

    api.set_queue(True, "analyst_01", "classifier looks off", config, now=NOW)
    state = api.governance_state(root, config, "test", now=NOW)
    assert state["halted"] and state["halted_by"] == "analyst_01"
    assert state["halt_reason"] == "classifier looks off" and state["journal_ok"]
    with pytest.raises(api.QueueStopped):
        api.run_pipeline_api(root, k=10, now=NOW)
    with pytest.raises(api.QueueStopped):
        api.project_api(root, cid, "finding")
    other = next(c["candidate_id"] for b in view["brands"] for c in b["queue"] if c["candidate_id"] != cid)
    assert api.decide(root, other, "escalate", "analyst_01", now=NOW)["receipt"]["outcome"] == "escalate"

    api.set_queue(False, "duty-manager-01", "checked", config, now=NOW)
    assert not api.governance_state(root, config, "test", now=NOW)["halted"]
    assert api.project_api(root, cid, "all")["projection"]["projections"]


def test_overdue_holds_are_reported(run, config):
    root, _ = run
    later = NOW + timedelta(hours=config.hold_sla_hours + 1)
    state = api.governance_state(root, config, "test", now=later)
    assert state["overdue_holds"] and set(state["overdue_holds"]) <= set(state["open_holds"])
    assert not api.governance_state(root, config, "test", now=NOW)["overdue_holds"]


def test_tamper_check_leaves_the_run_untouched(run):
    root, _ = run
    run_dir = api.current_run(root)
    before = {p.name: p.read_bytes() for p in run_dir.iterdir() if len(p.name) == 64}
    assert api.verify_sample(root)["ok"]
    assert api.tamper_sample(root)["detected"]
    after = {p.name: p.read_bytes() for p in run_dir.iterdir() if len(p.name) == 64}
    assert before == after
    assert api.verify_sample(root)["ok"]


def test_receipt_view_names_the_receipt(run):
    root, _ = run
    run_dir = api.current_run(root)
    pkg = next(iter(latest_by_candidate(records.read_receipts(run_dir)).values()))
    assert api.receipt_view(pkg)["manifest_hash"] == manifest_hash(pkg)


def test_asset_path_stays_inside_the_run(run):
    root, _ = run
    with pytest.raises(ValueError):
        api.asset_path(root, "../../etc/passwd")
    assert api.asset_path(root, "0" * 64) is None


# --- HTTP layer -------------------------------------------------------------

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from bid import server  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("BID_CONSOLE_TOKEN", raising=False)
    monkeypatch.delenv("BID_CONSOLE_ACTOR_HEADER", raising=False)
    return TestClient(server.app)


def test_http_flow_maps_refusals_to_status_codes(client):
    assert client.get("/api/run").status_code == 404  # no run yet
    view = client.post("/api/run", json={}).json()
    cid = _escalated_positive(view)
    assert client.get("/api/run").json()["run_id"] == view["run_id"]

    r = client.post("/api/decide", json={"candidate_id": cid, "decision": "confirm", "analyst_id": "analyst_01"})
    assert r.status_code == 200 and r.json()["receipt"]["outcome"] == "confirm"
    r = client.post("/api/release", json={"candidate_id": cid, "actor": "analyst_01", "reason": "x"})
    assert r.status_code == 403
    assert client.post("/api/decide", json={"candidate_id": cid, "decision": "nope"}).status_code == 422

    assert client.post("/api/halt", json={"actor": "analyst_01", "reason": "pause"}).status_code == 200
    assert client.get("/api/governance").json()["halted"] is True
    assert client.post("/api/run", json={}).status_code == 409
    assert client.get(f"/api/project/{cid}?kind=finding").status_code == 409
    assert client.post("/api/resume", json={"actor": "analyst_01"}).status_code == 200
    assert client.get(f"/api/project/{cid}?kind=finding").status_code == 200


def test_actor_comes_from_the_proxy_header_when_configured(client, monkeypatch):
    view = client.post("/api/run", json={}).json()
    cid = _escalated_positive(view)
    monkeypatch.setenv("BID_CONSOLE_ACTOR_HEADER", "X-Forwarded-User")
    body = {"candidate_id": cid, "decision": "escalate", "analyst_id": "typed-name"}
    assert client.post("/api/decide", json=body).status_code == 403
    r = client.post("/api/decide", json=body, headers={"X-Forwarded-User": "jdoe@example.test"})
    assert r.status_code == 200 and r.json()["receipt"]["decided_by"] == "jdoe@example.test"
    gov = client.get("/api/governance", headers={"X-Forwarded-User": "jdoe@example.test"}).json()
    assert gov["actor_header"] == "X-Forwarded-User" and gov["actor"] == "jdoe@example.test"


def test_console_journal_is_the_command_line_journal(client):
    from bid import paths
    from bid.governance import GovernanceJournal

    client.post("/api/halt", json={"actor": "analyst_01", "reason": "shared"})
    assert GovernanceJournal(paths.data_dir() / "governance.jsonl").is_halted()
    assert Path(paths.data_dir() / "governance.jsonl").exists()
