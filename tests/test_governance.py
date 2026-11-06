"""
Governance: release, queue stop, hold SLA escalation and the signed journal.

Pins: a release is done by a declared releaser, reverses a confirm and names
the receipt it reverses; only declared stop authority halts or resumes the
queue and each call is recorded; an overdue hold is escalated once; editing
the journal on disk breaks both the HMAC and the public-key verification.
"""
from __future__ import annotations

import json
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bid import evidence
from bid.decisions import TriagePolicy, auto_decision, coverage, latest_by_candidate, open_holds
from bid.evidence import Ed25519Dsse, HmacEvidenceSigner, chain_link
from bid.governance import (
    record_hash,
    GOVERNANCE_PAYLOAD_TYPE,
    GovernanceConfig,
    GovernanceJournal,
    Releaser,
    escalate_overdue,
    halt_queue,
    release,
    resume_queue,
    verify_release,
)
from bid.models import AnalystDecision, Asset, Candidate, DetSignals, EvidencePackage, Verdict
from bid.storage import ContentStore

T0 = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
KEY = "k"
GENESIS = "0" * 64
EXAMPLE = Path(__file__).resolve().parents[1] / "bid" / "fixtures" / "governance.json"


def _signer() -> HmacEvidenceSigner:
    return HmacEvidenceSigner(key=KEY, dsse=Ed25519Dsse("seed"))


def _config(**overrides) -> GovernanceConfig:
    settings = {
        "releasers": (Releaser("lead-1", "brand-protection lead"), Releaser("counsel-1", "legal counsel")),
        "stop_authority": ("duty-1",),
        "ask_contact": "brand-protection on-call (#brand-protection)",
    }
    settings.update(overrides)
    return GovernanceConfig(**settings)


def _journal(tmp_path: Path, *, dsse: bool = True) -> GovernanceJournal:
    return GovernanceJournal(tmp_path / "governance.jsonl", hmac_key=KEY,
                             dsse=Ed25519Dsse("seed") if dsse else None)


def _candidate(cid: str, store: ContentStore | None = None) -> Candidate:
    assets = []
    if store is not None:
        digest = store.put_bytes(f"icon bytes for {cid}".encode())
        assets.append(Asset(sha256=digest, media_type="image/png"))
    return Candidate(
        id=cid, brand_id="brand-1", sensor_name="fixture-sensor", platform="app_store",
        platform_uid=f"uid-{cid}", handle=f"brand-support-{cid}", display_name="Brand Support",
        bio="Support desk", assets=assets, dedup_key=f"dedup-{cid}",
        raw_observation_ref="r" * 64, first_seen=T0,
    )


def _verdict(cid: str, label: str = "impersonation", confidence: float = 0.95) -> Verdict:
    return Verdict(
        candidate_id=cid, label=label, confidence=confidence, signals=DetSignals(),
        reasoning="fixture verdict", model_id="mock-deterministic-v1",
        prompt_hash="primary-prompt", input_hashes=[],
    )


def _person(cid: str, outcome: str, at: datetime) -> AnalystDecision:
    return AnalystDecision(candidate_id=cid, analyst_id="analyst-1", decision=outcome,
                           decided_at=at, authority="brand-protection analyst")


def _sign(signer, candidate, verdict, decision, at, chain: list[EvidencePackage]) -> EvidencePackage:
    prev = chain_link(chain[-1]) if chain else None
    pkg = signer.package(candidate, verdict, decision, prev, at)
    chain.append(pkg)
    return pkg


# --- configuration ---------------------------------------------------------------


def test_config_defaults():
    cfg = GovernanceConfig()
    assert cfg.usable_default.startswith("Not sure? Escalate.")
    assert "never held against" in cfg.stop_statement
    assert cfg.hold_sla_hours == 24.0
    assert cfg.releasers == () and cfg.stop_authority == ()
    assert cfg.releaser("anyone") is None
    assert cfg.may_stop("anyone") is False


def test_config_direct_construction_is_validated():
    with pytest.raises(ValueError, match="duplicate releaser"):
        GovernanceConfig(releasers=(Releaser("a", "x"), Releaser("a", "y")))
    with pytest.raises(ValueError):
        Releaser("", "brand-protection lead")
    with pytest.raises(ValueError):
        Releaser("lead-1", " ")
    with pytest.raises(ValueError):
        GovernanceConfig(hold_sla_hours=0)
    with pytest.raises(ValueError):
        GovernanceConfig(stop_authority=("",))
    cfg = _config(stop_authority=["duty-1"], hold_sla_hours=12)
    assert cfg.stop_authority == ("duty-1",)  # lists are normalised to tuples
    assert cfg.hold_sla_hours == 12.0
    assert cfg.releaser("lead-1") == Releaser("lead-1", "brand-protection lead")
    assert cfg.may_stop("duty-1") and not cfg.may_stop("lead-1")


@pytest.mark.parametrize("content, message", [
    ("not json", "not valid JSON"),
    ("[]", "JSON object"),
    ('{"hold_sla_hours": 0}', "hold_sla_hours"),
    ('{"hold_sla_hours": -1}', "hold_sla_hours"),
    ('{"hold_sla_hours": "24"}', "hold_sla_hours"),
    ('{"hold_sla_hours": true}', "hold_sla_hours"),
    ('{"hold_sla_hours": NaN}', "hold_sla_hours"),
    ('{"hold_sla_hour": 24}', "unknown governance config key"),
    ('{"releasers": [{"id": "a", "authority": "x"}, {"id": "a", "authority": "y"}]}', "duplicate releaser"),
    ('{"releasers": [{"id": "", "authority": "x"}]}', "non-empty"),
    ('{"releasers": [{"id": "a", "authority": " "}]}', "authority"),
    ('{"releasers": [{"id": "a"}]}', "both id and authority"),
    ('{"releasers": [{"id": "a", "authority": "x", "role": "y"}]}', "unknown key"),
    ('{"releasers": {"id": "a", "authority": "x"}}', "must be a list"),
    ('{"releasers": ["a"]}', "must be an object"),
    ('{"stop_authority": "duty-1"}', "must be a list"),
    ('{"stop_authority": [""]}', "non-empty"),
    ('{"ask_contact": 7}', "ask_contact"),
])
def test_config_load_errors(tmp_path, content, message):
    path = tmp_path / "governance.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message) as err:
        GovernanceConfig.load(path)
    assert str(path) in str(err.value)  # the error names the file


def test_config_load_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        GovernanceConfig.load(tmp_path / "absent.json")


def test_example_config_loads():
    cfg = GovernanceConfig.load(EXAMPLE)
    assert len(cfg.releasers) == 2
    assert cfg.stop_authority == ("duty-manager-01", "analyst_01")
    assert cfg.hold_sla_hours == 24.0
    assert cfg.ask_contact
    for r in cfg.releasers:
        assert cfg.releaser(r.id) == r
    assert cfg.may_stop(cfg.stop_authority[0])
    # the example spells out every setting
    assert set(json.loads(EXAMPLE.read_text(encoding="utf-8"))) == {f.name for f in fields(GovernanceConfig)}


# --- queue stop -------------------------------------------------------------------


def test_halt_and_resume_need_stop_authority(tmp_path):
    journal, cfg = _journal(tmp_path), _config()
    assert journal.is_halted() is False

    with pytest.raises(PermissionError):
        halt_queue(journal, cfg, "lead-1", "a releaser is not stop authority", T0)
    assert journal.packages() == []

    halt = halt_queue(journal, cfg, "duty-1", "sensor returns malformed data", T0)
    assert halt.record.kind == "queue_halt"
    assert halt.record.actor == "duty-1"
    assert halt.record.authority == "stop-authority"
    assert halt.record.payload == {"reason": "sensor returns malformed data"}
    assert halt.record.prev_record_hash == GENESIS
    assert halt.record.created_at == T0
    assert halt.dsse_envelope["payloadType"] == GOVERNANCE_PAYLOAD_TYPE
    assert journal.is_halted() is True

    # other record kinds do not change the queue state
    journal.append("conduct_scorecard", "reviewer-1", T0, payload={"precision": 0.9})
    assert journal.is_halted() is True

    with pytest.raises(PermissionError):
        resume_queue(journal, cfg, "intern-1", "not stop authority", T0 + timedelta(hours=1))
    assert journal.is_halted() is True

    resume = resume_queue(journal, cfg, "duty-1", "sensor fixed", T0 + timedelta(hours=1))
    assert resume.record.authority == "stop-authority"
    assert journal.is_halted() is False

    # a fresh reader of the same file sees the same state and a valid chain
    reread = GovernanceJournal(journal.path, hmac_key=KEY)
    assert [p.record.kind for p in reread.packages()] == ["queue_halt", "conduct_scorecard", "queue_resume"]
    assert reread.is_halted() is False
    assert reread.verify()[0] is True
    assert reread.verify_public()[0] is True
    ok, reason = reread.verify_public(Ed25519Dsse("seed").public_key_hex())
    assert ok, reason


def test_journal_links_each_record_to_the_previous_one(tmp_path):
    journal, cfg = _journal(tmp_path), _config()
    a = halt_queue(journal, cfg, "duty-1", "first", T0)
    b = resume_queue(journal, cfg, "duty-1", "second", T0 + timedelta(minutes=5))
    assert a.record.prev_record_hash == GENESIS
    assert b.record.prev_record_hash == record_hash(a)
    assert journal.verify() == (True, "governance journal of 2 record(s) verified")


# --- release ----------------------------------------------------------------------


def test_release_by_non_releaser_raises(tmp_path):
    store, chain, signer = ContentStore(tmp_path / "assets"), [], _signer()
    cand, verdict = _candidate("c1", store), _verdict("c1")
    confirmed = _sign(signer, cand, verdict, _person("c1", "confirm", T0), T0, chain)
    for actor in ("duty-1", "analyst-1", ""):
        with pytest.raises(PermissionError):
            release(cand, verdict, confirmed, signer, _config(), actor, "reason",
                    T0 + timedelta(hours=1), chain_link(confirmed))


def test_releasing_anything_but_a_matching_confirm_raises(tmp_path):
    store, chain, signer, cfg = ContentStore(tmp_path / "assets"), [], _signer(), _config()
    cand, verdict = _candidate("c1", store), _verdict("c1", "legit")
    rejected = _sign(signer, cand, verdict, _person("c1", "reject", T0), T0, chain)
    with pytest.raises(ValueError, match="only a confirm"):
        release(cand, verdict, rejected, signer, cfg, "lead-1", "reason",
                T0 + timedelta(hours=1), chain_link(rejected))

    other, other_verdict = _candidate("c2", store), _verdict("c2")
    confirmed_other = _sign(signer, other, other_verdict, _person("c2", "confirm", T0), T0, chain)
    with pytest.raises(ValueError, match="candidate"):
        release(cand, verdict, confirmed_other, signer, cfg, "lead-1", "reason",
                T0 + timedelta(hours=1), chain_link(confirmed_other))


def test_release_receipt_verifies(tmp_path):
    store, chain, signer, cfg = ContentStore(tmp_path / "assets"), [], _signer(), _config()
    cand, verdict = _candidate("c1", store), _verdict("c1")
    escalated = _sign(signer, cand, verdict, auto_decision(verdict, TriagePolicy(), T0), T0, chain)
    confirmed = _sign(signer, cand, verdict, _person("c1", "confirm", T0 + timedelta(hours=1)),
                      T0 + timedelta(hours=1), chain)

    rel = release(cand, verdict, confirmed, signer, cfg, "lead-1",
                  "account belongs to a licensed reseller", T0 + timedelta(hours=2),
                  chain_link(chain[-1]))
    chain.append(rel)

    m = rel.manifest
    assert m.outcome == "release"
    assert m.decided_by == "lead-1"
    assert m.authority == "brand-protection lead"
    assert m.automated is False
    assert m.supersedes == evidence.manifest_hash(confirmed)

    ok, reason = evidence.verify_chain(chain, KEY, store)
    assert ok, reason
    ok, reason = evidence.verify_package_public(rel, store)
    assert ok, reason
    ok, reason = verify_release(rel, confirmed)
    assert ok, reason

    # the release is now the candidate's latest receipt, and no hold is open
    assert latest_by_candidate(chain)["c1"] is rel
    assert open_holds(chain) == []
    assert coverage(["c1"], chain)["by_outcome"] == {"confirm": 0, "reject": 0, "escalate": 0, "release": 1}

    # verify_release refuses the wrong pairing
    assert verify_release(rel, escalated)[0] is False
    assert verify_release(confirmed, confirmed)[0] is False
    another_confirm = _sign(signer, cand, verdict, _person("c1", "confirm", T0 + timedelta(minutes=30)),
                            T0 + timedelta(minutes=30), [])
    ok, reason = verify_release(rel, another_confirm)  # same candidate, not the reversed receipt
    assert ok is False and "supersedes" in reason
    other, other_verdict = _candidate("c2", store), _verdict("c2")
    confirmed_other = _sign(signer, other, other_verdict, _person("c2", "confirm", T0), T0, [])
    assert verify_release(rel, confirmed_other)[0] is False


# --- hold SLA ---------------------------------------------------------------------


def test_escalate_overdue_is_idempotent(tmp_path):
    chain, signer, journal = [], _signer(), _journal(tmp_path)
    cfg = _config(hold_sla_hours=24)
    auto_confirm = TriagePolicy(auto_confirm_min_confidence=0.9)

    v1, v2, v3 = _verdict("c1", "suspicious", 0.6), _verdict("c2", "fraud", 0.95), _verdict("c3", "legit", 0.95)
    hold1 = _sign(signer, _candidate("c1"), v1, auto_decision(v1, TriagePolicy(), T0), T0, chain)
    at2 = T0 + timedelta(hours=1)
    hold2 = _sign(signer, _candidate("c2"), v2, auto_decision(v2, auto_confirm, at2), at2, chain)
    _sign(signer, _candidate("c3"), v3, auto_decision(v3, TriagePolicy(), T0), T0, chain)
    assert hold2.manifest.outcome == "confirm" and hold2.manifest.automated is True

    assert escalate_overdue(chain, journal, cfg, T0 + timedelta(hours=23)) == []

    now = T0 + timedelta(hours=24)
    first = escalate_overdue(chain, journal, cfg, now)
    assert len(first) == 1
    rec = first[0].record
    assert rec.kind == "hold_sla_escalation"
    assert rec.actor == "bid-sla-monitor"
    assert rec.subject == evidence.manifest_hash(hold1)
    assert rec.created_at == now
    assert rec.payload == {"candidate_id": "c1", "outcome": "escalate",
                           "held_since": "2026-07-03T12:00:00Z", "sla_hours": 24.0}
    assert escalate_overdue(chain, journal, cfg, now) == []

    later = T0 + timedelta(hours=25)
    second = escalate_overdue(chain, journal, cfg, later)
    assert [p.record.payload["candidate_id"] for p in second] == ["c2"]
    assert second[0].record.payload["outcome"] == "confirm"
    assert second[0].record.payload["held_since"] == "2026-07-03T13:00:00Z"
    assert escalate_overdue(chain, journal, cfg, later) == []
    # idempotent across a reload of the journal file as well
    assert escalate_overdue(chain, GovernanceJournal(journal.path, hmac_key=KEY), cfg, later) == []

    # a person resolves c1; nothing new is recorded much later
    _sign(signer, _candidate("c1"), v1, _person("c1", "reject", later), later, chain)
    assert escalate_overdue(chain, journal, cfg, T0 + timedelta(hours=72)) == []
    assert len(journal.packages()) == 2
    assert journal.verify()[0] is True
    assert journal.verify_public()[0] is True


# --- tamper evidence --------------------------------------------------------------


@pytest.mark.parametrize("line_index", [0, 1])
def test_editing_one_journal_line_fails_both_verifications(tmp_path, line_index):
    journal, cfg = _journal(tmp_path), _config()
    halt_queue(journal, cfg, "duty-1", "reason zero", T0)
    resume_queue(journal, cfg, "duty-1", "reason one", T0 + timedelta(hours=1))
    assert journal.verify()[0] is True and journal.verify_public()[0] is True

    lines = journal.path.read_text(encoding="utf-8").splitlines()
    original = '"reason one"' if line_index else '"reason zero"'
    assert original in lines[line_index]
    lines[line_index] = lines[line_index].replace(original, '"edited reason"')
    journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for reader in (journal, GovernanceJournal(journal.path, hmac_key=KEY)):
        ok, reason = reader.verify()
        assert ok is False and f"record {line_index}" in reason
        ok, reason = reader.verify_public(Ed25519Dsse("seed").public_key_hex())
        assert ok is False and f"record {line_index}" in reason


def test_removing_a_journal_line_breaks_the_chain(tmp_path):
    journal, cfg = _journal(tmp_path), _config()
    halt_queue(journal, cfg, "duty-1", "first", T0)
    resume_queue(journal, cfg, "duty-1", "second", T0 + timedelta(hours=1))
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    journal.path.write_text(lines[1] + "\n", encoding="utf-8")
    assert "chain break at record 0" in journal.verify()[1]
    assert "chain break at record 0" in journal.verify_public()[1]


def test_journal_needs_the_right_keys(tmp_path):
    journal, cfg = _journal(tmp_path), _config()
    halt_queue(journal, cfg, "duty-1", "maintenance", T0)
    assert GovernanceJournal(journal.path, hmac_key="other").verify()[0] is False
    ok, reason = journal.verify_public(Ed25519Dsse("other-seed").public_key_hex())
    assert ok is False and "different public key" in reason

    unsigned = _journal(tmp_path / "unsigned", dsse=False)
    halt_queue(unsigned, cfg, "duty-1", "maintenance", T0)
    assert unsigned.verify()[0] is True
    ok, reason = unsigned.verify_public()
    assert ok is False and "no DSSE envelope" in reason


def test_unreadable_journal_line_fails_verification(tmp_path):
    journal, cfg = _journal(tmp_path), _config()
    halt_queue(journal, cfg, "duty-1", "maintenance", T0)
    with journal.path.open("a", encoding="utf-8") as f:
        f.write("{not json\n")
    ok, reason = journal.verify()
    assert ok is False and "line 2" in reason
    assert journal.verify_public()[0] is False


def test_cli_takes_shared_options_on_either_side_of_the_subcommand(tmp_path, capsys):
    from bid import governance

    cfg = tmp_path / "governance.json"
    cfg.write_text(json.dumps({"stop_authority": ["duty-1"]}), encoding="utf-8")
    journal = tmp_path / "journal.jsonl"
    now = "2026-07-04T12:00:00Z"

    assert governance.main(["halt", "--actor", "duty-1", "--reason", "drift",
                            "--config", str(cfg), "--journal", str(journal), "--now", now]) == 0
    assert governance.main(["escalate", "--run-dir", str(tmp_path / "run"),
                            "--config", str(cfg), "--journal", str(journal), "--now", now]) == 0
    capsys.readouterr()
    assert governance.main(["--config", str(cfg), "--journal", str(journal), "--now", now, "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["halted"] is True
