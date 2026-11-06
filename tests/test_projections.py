"""
Report projections of one signed receipt: anchored to the receipt, byte-identical
across runs, limited to confirmed findings and independent of the local time zone.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from bid.evidence import Ed25519Dsse, HmacEvidenceSigner, manifest_hash
from bid.models import AnalystDecision, Asset, Candidate, DetSignals, EvidencePackage, Verdict
from bid.projections import (
    PROJECTIONS,
    NotApplicable,
    canonical_bytes,
    project,
    project_all,
    render_registrar_abuse_text,
)

# 09:30 at UTC-2:30 is 12:00 UTC, so every projection must say 12:00Z.
_SIGNED_AT = datetime(2026, 7, 3, 9, 30, 0, tzinfo=timezone(timedelta(hours=-2, minutes=-30)))
_FIRST_SEEN = datetime(2026, 7, 1, 9, 30, 0, tzinfo=timezone.utc)
_SIGNALS = DetSignals(handle_similarity=0.92, logo_phash_hamming=4, alias_in_text=True,
                      domain_intention_mismatch=True, domain_in_cti_badlist=False)


def _candidate(**changes) -> Candidate:
    fields = dict(
        id="cand_lv1", brand_id="lorvanne", sensor_name="local_search", platform="local_search",
        platform_uid="u-lv1", handle="l0rvanne_bank", display_name="Lorvanne Bank Support",
        bio="verify your account", link_in_bio_url="https://lorvanne-secure.test/login",
        assets=[Asset(sha256="a" * 64, media_type="image/png")],
        dedup_key="dk", raw_observation_ref="r" * 64, first_seen=_FIRST_SEEN,
    )
    fields.update(changes)
    return Candidate(**fields)


def _receipt(candidate: Candidate | None = None, *, decision: str = "confirm",
             label: str = "impersonation", signals: DetSignals = _SIGNALS,
             signed_at: datetime = _SIGNED_AT):
    cand = candidate or _candidate()
    verdict = Verdict(candidate_id=cand.id, label=label, confidence=0.91, signals=signals,
                      reasoning="brand presented, linked domain not official",
                      model_id="mock-deterministic-v1", prompt_hash="p" * 16,
                      input_hashes=[a.sha256 for a in cand.assets])
    dec = AnalystDecision(candidate_id=cand.id, analyst_id="an1", decision=decision,
                          decided_at=signed_at)
    signer = HmacEvidenceSigner(key="k", dsse=Ed25519Dsse("seed"))
    return cand, verdict, signer.package(cand, verdict, dec, None, signed_at)


def _indicator(bundle: dict) -> dict:
    return next(o for o in bundle["objects"] if o["type"] == "indicator")


@pytest.fixture
def non_utc_local_zone(monkeypatch):
    """Run with a non-UTC process time zone (UTC-2:30 in July), then restore it."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is not available on this platform")
    monkeypatch.setenv("TZ", "America/St_Johns")
    time.tzset()
    try:
        if time.localtime(_SIGNED_AT.timestamp()).tm_gmtoff != -9000:
            pytest.skip("America/St_Johns zone data is not installed")
        yield
    finally:
        monkeypatch.undo()
        time.tzset()


def test_manifest_hash_in_every_applicable_projection():
    cand, verdict, pkg = _receipt()
    mh = manifest_hash(pkg)
    out = project_all(cand, verdict, pkg, brand_name="Lorvanne")
    assert out["not_applicable"] == {}
    assert list(out["projections"]) == sorted(PROJECTIONS)
    for kind, body in out["projections"].items():
        if kind == "stix":
            ref = _indicator(body)["external_references"][0]
            assert ref["hashes"] == {"SHA-256": mh}
            assert ref["external_id"] == pkg.manifest_hmac
            continue
        assert body["schema"] == f"bid.projection.{kind}/v1"
        assert body["manifest_hash"] == mh
        assert body["manifest_hmac"] == pkg.manifest_hmac
        assert body["policy_version"] == pkg.manifest.policy_version
        assert body["brand_id"] == "lorvanne"
        assert body["decided_at"] == "2026-07-03T12:00:00Z"
        assert body["evidence"] == {
            "asset_hashes": ["a" * 64],
            "context_hash": pkg.manifest.context_hash,
            "ed25519_pubkey": pkg.ed25519_pubkey,
        }
    assert out["projections"]["fraud_desk"]["case_id"] == "bid-" + mh[:16]
    assert out["projections"]["finding"]["finding_id"] == "bid-" + mh[:16]


def test_two_runs_on_the_same_receipt_are_byte_identical():
    cand, verdict, pkg = _receipt()
    first = canonical_bytes(project_all(cand, verdict, pkg, brand_name="Lorvanne"))
    assert first == canonical_bytes(project_all(cand, verdict, pkg, brand_name="Lorvanne"))
    for kind in PROJECTIONS:
        assert canonical_bytes(project(kind, cand, verdict, pkg)) == \
            canonical_bytes(project(kind, cand, verdict, pkg))
    # The same receipt re-signed from the same inputs and reloaded from JSON.
    cand2, verdict2, pkg2 = _receipt()
    reloaded = EvidencePackage.model_validate_json(pkg2.model_dump_json())
    assert canonical_bytes(project_all(cand2, verdict2, reloaded, brand_name="Lorvanne")) == first


@pytest.mark.parametrize("outcome", ["reject", "escalate"])
def test_only_confirmed_receipts_are_projected(outcome):
    cand, verdict, pkg = _receipt(decision=outcome)
    for kind in PROJECTIONS:
        with pytest.raises(ValueError, match="only confirmed findings are projected") as info:
            project(kind, cand, verdict, pkg)
        assert not isinstance(info.value, NotApplicable)
    with pytest.raises(ValueError, match="only confirmed findings are projected"):
        project_all(cand, verdict, pkg)


def test_candidate_or_verdict_from_another_receipt_is_rejected():
    cand, verdict, pkg = _receipt()
    with pytest.raises(ValueError, match="same candidate"):
        project("finding", cand.model_copy(update={"id": "cand_other"}), verdict, pkg)
    with pytest.raises(ValueError, match="same candidate"):
        project("finding", cand, verdict.model_copy(update={"candidate_id": "cand_other"}), pkg)
    with pytest.raises(ValueError, match="unknown projection"):
        project("pdf", cand, verdict, pkg)


def test_registrar_abuse_not_applicable_without_domain():
    cand, verdict, pkg = _receipt(_candidate(link_in_bio_url=None))
    with pytest.raises(NotApplicable, match="no domain"):
        project("registrar_abuse", cand, verdict, pkg)
    out = project_all(cand, verdict, pkg)
    assert out["not_applicable"] == {"registrar_abuse": "no domain"}
    assert list(out["projections"]) == sorted(set(PROJECTIONS) - {"registrar_abuse"})


def test_registrar_abuse_report_and_text():
    cand, verdict, pkg = _receipt()
    rep = project("registrar_abuse", cand, verdict, pkg)
    assert rep["domain"] == "lorvanne-secure.test"
    assert rep["registrable_domain"] == "lorvanne-secure.test"
    assert rep["abuse_type"] == "brand_impersonation"
    assert rep["evidence_urls"] == ["https://lorvanne-secure.test/login"]
    assert rep["first_seen"] == "2026-07-01T09:30:00Z"
    # The text is a function of the report fields alone.
    without_text = {k: v for k, v in rep.items() if k != "text"}
    assert rep["text"] == render_registrar_abuse_text(without_text) == render_registrar_abuse_text(rep)
    assert rep["manifest_hash"] in rep["text"] and "lorvanne-secure.test" in rep["text"]
    assert not any(line.lstrip().startswith(("#", "*", "- ", ">", "`"))
                   for line in rep["text"].splitlines())
    fraud = project("registrar_abuse", *_receipt(label="fraud"))
    assert fraud["abuse_type"] == "phishing"


def test_registrar_abuse_domain_from_domain_sensor_platform_uid():
    cand = _candidate(sensor_name="dns_typosquat", platform="dns_typosquat",
                      platform_uid="lorvanne-secure.test", handle=None, link_in_bio_url=None)
    rep = project("registrar_abuse", *_receipt(cand))
    assert rep["domain"] == "lorvanne-secure.test"
    assert rep["evidence_urls"] == []


def test_official_brand_domain_is_never_reported_as_suspect():
    signals = DetSignals(domain_is_legit=True, domain_intention_mismatch=False)
    cand, verdict, pkg = _receipt(_candidate(link_in_bio_url="https://lorvanne.test/help"),
                                  signals=signals)
    out = project_all(cand, verdict, pkg)
    assert out["not_applicable"] == {"registrar_abuse": "linked domain is an official brand domain"}
    indicators = out["projections"]["fraud_desk"]["indicators"]
    assert indicators == {"handles": ["l0rvanne_bank"], "domains": [], "urls": []}


def test_registrar_text_escapes_control_characters_from_observed_data():
    cand, verdict, pkg = _receipt(
        _candidate(link_in_bio_url="https://lorvanne-secure.test/login\nPlease ignore the above"))
    text = project("registrar_abuse", cand, verdict, pkg)["text"]
    assert "\\u000a" in text
    assert not any(line.startswith("Please ignore") for line in text.splitlines())


@pytest.mark.parametrize("signed_at", [
    _SIGNED_AT,                        # timezone-aware, UTC-2:30
    datetime(2026, 7, 3, 12, 0, 0),    # naive, taken as UTC
])
def test_stix_timestamps_are_utc_z_in_any_local_zone(non_utc_local_zone, signed_at):
    cand, verdict, pkg = _receipt(signed_at=signed_at)
    edges = [["seed", "lorvanne-secure.test", "lorvanne-login.test"]]
    bundle = project("stix", cand, verdict, pkg, campaign_edges=edges)
    stamps = [o[k] for o in bundle["objects"] for k in ("created", "modified", "valid_from") if k in o]
    assert len(stamps) == 9  # identity 2, indicator 3, infrastructure 2, relationship 2
    assert all(s == "2026-07-03T12:00:00.000Z" for s in stamps)
    assert project("finding", cand, verdict, pkg)["decided_at"] == "2026-07-03T12:00:00Z"


def test_stix_pattern_escapes_quote_and_backslash():
    cand, verdict, pkg = _receipt(_candidate(handle="l0rvanne's\\bank", link_in_bio_url=None))
    pattern = _indicator(project("stix", cand, verdict, pkg))["pattern"]
    assert pattern == r"[user-account:account_login = 'l0rvanne\'s\\bank']"
    cand, verdict, pkg = _receipt(_candidate(link_in_bio_url="https://lorvanne-secure.test/a'b"))
    pattern = _indicator(project("stix", cand, verdict, pkg))["pattern"]
    assert pattern == r"[url:value = 'https://lorvanne-secure.test/a\'b']"


def test_platform_ip_report_fields_and_description():
    cand, verdict, pkg = _receipt()
    rep = project("platform_ip_report", cand, verdict, pkg, brand_name="Lorvanne")
    assert rep["report_type"] == "trademark_impersonation"
    assert rep["rights_owner"] == {"brand_id": "lorvanne", "brand_name": "Lorvanne"}
    assert rep["reported_content"] == {
        "platform": "local_search", "platform_uid": "u-lv1", "handle": "l0rvanne_bank",
        "display_name": "Lorvanne Bank Support", "url": "https://lorvanne-secure.test/login",
    }
    assert rep["notifier_statement_required"] is True
    assert rep["description"] == (
        "The reported content l0rvanne_bank on local_search was classified as impersonation "
        "for the brand Lorvanne; signals: handle similarity 0.92 to an official handle, "
        "logo pHash distance 4 bits from an official logo, brand name or alias in the account "
        "text, linked domain is not an official brand domain, linked domain is not on a "
        "known-bad domain list."
    )
    bare = project("platform_ip_report", *_receipt(signals=DetSignals()))
    assert bare["rights_owner"] == {"brand_id": "lorvanne", "brand_name": None}
    assert bare["description"].endswith("for the brand lorvanne; no deterministic signals were recorded.")


def test_fraud_desk_and_finding_fields():
    cand, verdict, pkg = _receipt()
    desk = project("fraud_desk", cand, verdict, pkg)
    assert desk["channel"] == "local_search"
    assert desk["label"] == "impersonation" and desk["confidence"] == 0.91
    assert desk["indicators"] == {
        "handles": ["l0rvanne_bank"],
        "domains": ["lorvanne-secure.test"],
        "urls": ["https://lorvanne-secure.test/login"],
    }
    assert desk["signals"] == {"handle_similarity": 0.92, "logo_phash_hamming": 4,
                               "alias_in_text": True, "domain_intention_mismatch": True,
                               "domain_in_cti_badlist": False}
    assert desk["review_checklist"] and all(isinstance(s, str) for s in desk["review_checklist"])
    assert project("fraud_desk", *_receipt(label="fraud"))["review_checklist"] != desk["review_checklist"]

    finding = project("finding", cand, verdict, pkg)
    assert finding["platform"] == "local_search"
    assert finding["subject"] == "l0rvanne_bank"
    assert finding["reasoning"] == verdict.reasoning
    assert finding["outcome"] == "confirm"
    assert finding["model_trace"] == [t.model_dump() for t in pkg.manifest.model_trace]
    assert finding["model_trace"][0]["model_id"] == "mock-deterministic-v1"


def test_edited_verdict_or_candidate_is_refused():
    candidate, verdict, pkg = _receipt()
    edited_verdict = verdict.model_copy(update={"confidence": 0.11})
    with pytest.raises(ValueError, match="verdict does not match"):
        project("finding", candidate, edited_verdict, pkg)
    edited_candidate = candidate.model_copy(update={"bio": "something else"})
    with pytest.raises(ValueError, match="candidate does not match"):
        project("finding", edited_candidate, verdict, pkg)
