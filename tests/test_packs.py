from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from bid import packs
from bid.decisions import TriagePolicy, decide_and_sign
from bid.evidence import Ed25519Dsse, HmacEvidenceSigner, _hash, chain_link
from bid.governance import GovernanceConfig, GovernanceJournal, escalate_overdue, release
from bid.models import AnalystDecision, Asset, Candidate, DetSignals, Verdict
from bid.projections import project
from bid.storage import ContentStore

T0 = datetime(2026, 7, 3, 12, 0, tzinfo=timezone.utc)
KEY = "k"


def _signer() -> HmacEvidenceSigner:
    return HmacEvidenceSigner(key=KEY, dsse=Ed25519Dsse("seed"))


def _candidate(cid: str, store: ContentStore) -> Candidate:
    digest = store.put_bytes(f"logo-{cid}".encode())
    return Candidate(id=cid, brand_id="lorvanne", sensor_name="fixture", platform="social",
                     platform_uid=f"uid-{cid}", handle=f"l0rvanne_{cid}", display_name="Lorvanne Bank",
                     bio="support", link_in_bio_url=f"https://{cid}.lorvanne-secure.test/login",
                     assets=[Asset(sha256=digest, media_type="image/png")], dedup_key=cid,
                     raw_observation_ref="r" * 64, first_seen=T0 - timedelta(hours=6))


def _verdict(cid: str, label: str, confidence: float = 0.9) -> Verdict:
    return Verdict(candidate_id=cid, label=label, confidence=confidence, signals=DetSignals(),
                   reasoning="r", model_id="mock-deterministic-v1", prompt_hash="p" * 16,
                   input_hashes=[], model_family="rules", prompt_template="bid-prompt-v1+abcd1234")


def _config() -> GovernanceConfig:
    return GovernanceConfig.from_dict({
        "releasers": [{"id": "lead-1", "authority": "brand-protection lead"}],
        "stop_authority": ["duty-1"],
        "hold_sla_hours": 24,
    })


def _chain(store):
    cands = {c: _candidate(c, store) for c in ("c1", "c2", "c3")}
    verdicts = [_verdict("c1", "impersonation"), _verdict("c2", "legit", 0.95), _verdict("c3", "suspicious", 0.5)]
    chain = decide_and_sign(cands, verdicts, _signer(), TriagePolicy(), T0)
    person = AnalystDecision(candidate_id="c1", analyst_id="analyst-1", decision="confirm",
                             decided_at=T0 + timedelta(hours=1), authority="brand-protection analyst")
    chain.append(_signer().package(cands["c1"], verdicts[0], person, chain_link(chain[-1]),
                                   T0 + timedelta(hours=1)))
    return cands, verdicts, chain


def test_bundled_packs_load_and_have_stable_identity():
    assert {"eu-dsa-art16", "generic-best-effort", "template"} <= set(packs.list_packs())
    for name in packs.list_packs():
        pack = packs.load_pack(name)
        assert packs.pack_ref(pack) == packs.pack_ref(packs.load_pack(name))
    dsa = packs.load_pack("eu-dsa-art16")
    edited = dsa.model_copy(update={"version": "2"})
    assert packs.pack_ref(edited).sha256 != packs.pack_ref(dsa).sha256


def test_pack_with_unknown_metric_is_refused(tmp_path):
    bad = json.loads((packs.PACK_DIR / "template.json").read_text())
    bad["requirements"][0]["fields"] = ["no.such.metric"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="unknown metrics"):
        packs.load_pack(path)


def test_notice_check_separates_tool_and_operator_items(tmp_path):
    store = ContentStore(tmp_path)
    cands, verdicts, chain = _chain(store)
    report = project("platform_ip_report", cands["c1"], verdicts[0], chain[-1], brand_name="Lorvanne Bank")
    out = packs.check_notice(report, packs.load_pack("eu-dsa-art16"))
    status = {r["id"]: r["status"] for r in out["requirements"]}
    assert status == {"reasons": "met", "location": "met", "notifier": "operator",
                      "good-faith-statement": "operator"}
    assert out["operator_must_add"] == ["notifier", "good-faith-statement"]
    assert out["gaps"] == []
    assert out["pack"]["review_status"] == "unreviewed"
    assert "not legal advice" in out["notice"]

    report["reported_content"]["platform_uid"] = ""
    report["reported_content"]["url"] = None
    gap = packs.check_notice(report, packs.load_pack("eu-dsa-art16"))
    assert gap["gaps"] == ["location"]

    finding = project("finding", cands["c1"], verdicts[0], chain[-1])
    with pytest.raises(ValueError, match="applies to"):
        packs.check_notice(finding, packs.load_pack("eu-dsa-art16"))


def test_best_effort_report_without_optional_inputs_marks_them_unchecked(tmp_path):
    _, _, chain = _chain(ContentStore(tmp_path))
    out = packs.best_effort_report(chain, packs.load_pack("generic-best-effort"))
    status = {r["id"]: r["status"] for r in out["requirements"]}
    assert status["detection"] == "met"
    assert status["decision"] == "met"
    assert status["explanation"] == "met"
    assert status["independent-check"] == "not_checked"  # no recheck ran
    assert status["integrity"] == "not_checked"
    assert status["customer-actions"] == "operator"
    assert out["receipts"] == len(chain)
    assert out["period"] == {"from": "2026-07-03T12:00:00Z", "to": "2026-07-03T13:00:00Z"}


def test_best_effort_report_with_journal_store_and_config(tmp_path):
    store = ContentStore(tmp_path / "assets")
    cands, verdicts, chain = _chain(store)
    journal = GovernanceJournal(tmp_path / "gov.jsonl", hmac_key=KEY, dsse=Ed25519Dsse("seed"))
    cfg = _config()
    now = T0 + timedelta(hours=30)
    pack = packs.load_pack("generic-best-effort")

    first = packs.best_effort_report(chain, pack, store=store, journal=journal.packages(),
                                     config=cfg, now=now, candidates=list(cands.values()))
    rows = {r["id"]: r for r in first["requirements"]}
    assert rows["integrity"]["status"] == "met"
    assert rows["timeliness"]["status"] == "gap"  # c3 has been held for 30 h, nobody escalated it
    assert "c3" in rows["timeliness"]["evidence"]["holds.escalated"]["detail"]
    assert rows["stop-authority"]["status"] == "met"
    assert rows["deployment-controls"]["status"] == "gap"  # receipts name no attestation
    ttd = rows["timeliness"]["evidence"]["detection.time_to_decision"]["value"]
    assert ttd["median_hours"] == 6.0

    escalate_overdue(chain, journal, cfg, now)
    second = packs.best_effort_report(chain, pack, store=store, journal=journal.packages(),
                                      config=cfg, now=now, candidates=list(cands.values()))
    assert {r["id"]: r["status"] for r in second["requirements"]}["timeliness"] == "met"


def test_attested_receipts_and_accountable_release(tmp_path):
    store = ContentStore(tmp_path / "assets")
    journal = GovernanceJournal(tmp_path / "gov.jsonl", hmac_key=KEY, dsse=Ed25519Dsse("seed"))
    payload = {"profile": "sovereign", "settings": {"redact_pii": True}}
    journal.append("deployment_attestation", "deployer", T0, subject="dep-1", payload=payload)
    cand = _candidate("c1", store)
    verdict = _verdict("c1", "impersonation")
    person = AnalystDecision(candidate_id="c1", analyst_id="analyst-1", decision="confirm",
                             decided_at=T0, authority="brand-protection analyst")
    confirm = _signer().package(cand, verdict, person, None, T0, attestation_hash=_hash(payload))
    rel = release(cand, verdict, confirm, _signer(), _config(), "lead-1", "licensed reseller",
                  T0 + timedelta(hours=1), chain_link(confirm))
    out = packs.best_effort_report([confirm], packs.load_pack("generic-best-effort"),
                                   journal=journal.packages())
    assert {r["id"]: r["status"] for r in out["requirements"]}["deployment-controls"] == "met"
    summary = packs.evidence_summary([confirm, rel])
    assert summary["releases.accountable"]["met"] is True


def test_report_is_deterministic(tmp_path):
    _, _, chain = _chain(ContentStore(tmp_path))
    pack = packs.load_pack("generic-best-effort")
    a = packs.best_effort_report(chain, pack, now=T0 + timedelta(days=1))
    b = packs.best_effort_report(chain, pack, now=T0 + timedelta(days=1))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["as_of"] == "2026-07-04T12:00:00Z"


def test_report_integrity_pins_the_published_key(tmp_path):
    store = ContentStore(tmp_path / "assets")
    _, _, chain = _chain(store)
    published = Ed25519Dsse("seed").public_key_hex()

    pinned = packs.evidence_summary(chain, store=store, pubkey=published)["integrity.public_signature"]
    assert pinned["met"] is True and "not pinned" not in pinned["detail"]

    other = packs.evidence_summary(chain, store=store, pubkey=Ed25519Dsse("other").public_key_hex())
    assert other["integrity.public_signature"]["met"] is False

    unpinned = packs.evidence_summary(chain, store=store)["integrity.public_signature"]
    assert unpinned["met"] is True and "not pinned" in unpinned["detail"]
