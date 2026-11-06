"""
STIX 2.1 export invariants: valid shape, deterministic projection, receipt-anchored.

Pins: the CTI bundle is a byte-deterministic
projection of the SIGNED evidence package (two exports identical), it carries the
manifest_hmac + policy_version as an external reference (strip the receipt and the
CTI record loses its anchor), and an optional campaign graph projects as an
Infrastructure SDO linked by an `indicates` relationship.
"""
from datetime import datetime, timezone

from bid.evidence import DEFAULT_HMAC_KEY, Ed25519Dsse, HmacEvidenceSigner
from bid.models import AnalystDecision, Asset, Candidate, DetSignals, Verdict
from bid.stix_export import to_stix_bundle

_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _fixture():
    cand = Candidate(
        id="cand_x", brand_id="wrenvalepay", sensor_name="local_search", platform="local_search",
        platform_uid="u1", handle="wrenva1epay-secure", display_name="WrenvalePay Secure",
        bio="verify here", link_in_bio_url="https://wrenva1epay-secure.com/login",
        assets=[Asset(sha256="a" * 64, media_type="image/png")],
        dedup_key="dk", raw_observation_ref="r" * 64, first_seen=_NOW)
    verdict = Verdict(candidate_id="cand_x", label="fraud", confidence=0.93,
                      signals=DetSignals(), reasoning="brand presented, domain not official",
                      model_id="mock-deterministic-v1", prompt_hash="p" * 16, input_hashes=["a" * 64])
    dec = AnalystDecision(candidate_id="cand_x", analyst_id="an1", decision="confirm", decided_at=_NOW)
    signer = HmacEvidenceSigner(DEFAULT_HMAC_KEY, dsse=Ed25519Dsse())
    pkg = signer.package(cand, verdict, dec, None, _NOW)
    return cand, verdict, pkg


def test_bundle_is_valid_stix_shape():
    cand, verdict, pkg = _fixture()
    b = to_stix_bundle(cand, verdict, pkg)
    assert b["type"] == "bundle"
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "indicator"} <= types
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert ind["pattern_type"] == "stix"
    assert ind["confidence"] == 93
    # anchored back to the signed receipt
    ext = ind["external_references"][0]
    assert ext["external_id"] == pkg.manifest_hmac
    assert pkg.manifest.policy_version in ext["description"]


def test_export_is_deterministic():
    cand, verdict, pkg = _fixture()
    assert to_stix_bundle(cand, verdict, pkg) == to_stix_bundle(cand, verdict, pkg)


def test_campaign_edges_project_infrastructure():
    cand, verdict, pkg = _fixture()
    edges = [["seed", "wrenva1epay-secure.com", "wrenva1epay-login.com"],
             ["seed", "wrenva1epay-secure.com", "1.2.3.4"]]
    b = to_stix_bundle(cand, verdict, pkg, campaign_edges=edges)
    types = [o["type"] for o in b["objects"]]
    assert "infrastructure" in types
    assert "relationship" in types
    rel = next(o for o in b["objects"] if o["type"] == "relationship")
    assert rel["relationship_type"] == "indicates"
