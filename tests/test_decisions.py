"""
Triage decisions, open holds and receipt coverage.

Pins: the triage policy rejects only clear negatives and escalates the rest; an
automatic confirm stays an open hold until a person looks at it; every
automated decision gets a chained receipt that verifies offline.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bid import evidence
from bid.decisions import (
    TriagePolicy,
    auto_decision,
    coverage,
    decide_and_sign,
    latest_by_candidate,
    open_holds,
    overdue_holds,
)
from bid.evidence import Ed25519Dsse, HmacEvidenceSigner, chain_link
from bid.models import (
    POSITIVE_LABELS,
    AnalystDecision,
    Asset,
    Candidate,
    DetSignals,
    EvidencePackage,
    Recheck,
    Verdict,
)
from bid.storage import ContentStore

T0 = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
KEY = "k"
GENESIS = "0" * 64


def _signer() -> HmacEvidenceSigner:
    return HmacEvidenceSigner(key=KEY, dsse=Ed25519Dsse("seed"))


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


def _verdict(cid: str, label: str = "impersonation", confidence: float = 0.9, *,
             injection: bool = False, recheck_agrees: bool | None = None) -> Verdict:
    recheck = None
    if recheck_agrees is not None:
        other = "legit" if label in POSITIVE_LABELS else "impersonation"
        recheck = Recheck(model_id="google/gemini-2.5-flash-lite", family="google",
                          label=label if recheck_agrees else other, confidence=0.7,
                          prompt_hash="recheck-prompt", agrees=recheck_agrees)
    return Verdict(
        candidate_id=cid, label=label, confidence=confidence, signals=DetSignals(),
        reasoning="fixture verdict", model_id="mock-deterministic-v1",
        prompt_hash="primary-prompt", input_hashes=[], injection_flagged=injection,
        recheck=recheck,
    )


def _person(cid: str, outcome: str, at: datetime, analyst: str = "analyst-1") -> AnalystDecision:
    return AnalystDecision(candidate_id=cid, analyst_id=analyst, decision=outcome,
                           decided_at=at, authority="brand-protection analyst")


class _Chain:
    """Signs receipts one after another, each linked to the previous one."""

    def __init__(self) -> None:
        self.signer = _signer()
        self.packages: list[EvidencePackage] = []

    def add(self, verdict: Verdict, decision: AnalystDecision, at: datetime) -> EvidencePackage:
        prev = chain_link(self.packages[-1]) if self.packages else None
        pkg = self.signer.package(_candidate(verdict.candidate_id), verdict, decision, prev, at)
        self.packages.append(pkg)
        return pkg

    def auto(self, verdict: Verdict, at: datetime, policy: TriagePolicy | None = None) -> EvidencePackage:
        return self.add(verdict, auto_decision(verdict, policy or TriagePolicy(), at), at)

    def person(self, cid: str, outcome: str, at: datetime) -> EvidencePackage:
        return self.add(_verdict(cid), _person(cid, outcome, at), at)


AUTO_CONFIRM = TriagePolicy(auto_confirm_min_confidence=0.9)


# --- auto_decision -----------------------------------------------------------


@pytest.mark.parametrize("verdict, policy, outcome, reason_part", [
    pytest.param(_verdict("c", "legit", 0.99, injection=True), TriagePolicy(), "escalate", "steer",
                 id="injection-beats-confident-negative"),
    pytest.param(_verdict("c", "impersonation", 0.99, injection=True), AUTO_CONFIRM, "escalate", "steer",
                 id="injection-beats-auto-confirm"),
    pytest.param(_verdict("c", "legit", 0.95, recheck_agrees=False), TriagePolicy(), "escalate", "recheck",
                 id="recheck-disagrees"),
    pytest.param(_verdict("c", "fraud", 0.99, recheck_agrees=False), AUTO_CONFIRM, "escalate", "recheck",
                 id="recheck-disagrees-beats-auto-confirm"),
    pytest.param(_verdict("c", "legit", 0.95, recheck_agrees=True), TriagePolicy(), "reject", "clear negative",
                 id="recheck-agrees-falls-through"),
    pytest.param(_verdict("c", "fraud", 0.99), TriagePolicy(), "escalate", "a person confirms",
                 id="positive-without-auto-confirm"),
    pytest.param(_verdict("c", "impersonation", 0.9), AUTO_CONFIRM, "confirm", "open hold",
                 id="positive-at-auto-confirm-threshold"),
    pytest.param(_verdict("c", "impersonation", 0.89), AUTO_CONFIRM, "escalate", "below the auto-confirm",
                 id="positive-below-auto-confirm-threshold"),
    pytest.param(_verdict("c", "suspicious", 0.99), TriagePolicy(auto_confirm_min_confidence=0.5),
                 "escalate", "suspicious", id="suspicious"),
    pytest.param(_verdict("c", "legit", 0.8), TriagePolicy(), "reject", "clear negative",
                 id="legit-at-reject-threshold"),
    pytest.param(_verdict("c", "fan", 0.95), TriagePolicy(), "reject", "clear negative",
                 id="fan-above-reject-threshold"),
    pytest.param(_verdict("c", "legit", 0.79), TriagePolicy(), "escalate", "below the auto-reject",
                 id="legit-below-reject-threshold"),
    pytest.param(_verdict("c", "fan", 0.95), TriagePolicy(auto_reject_labels=frozenset({"legit"})),
                 "escalate", "not auto-rejected", id="label-not-in-auto-reject-labels"),
])
def test_auto_decision_rules(verdict, policy, outcome, reason_part):
    d = auto_decision(verdict, policy, T0)
    assert d.decision == outcome
    assert reason_part in d.note


def test_auto_decision_is_marked_as_the_policy():
    policy = TriagePolicy(policy_id="bid-triage-test")
    d = auto_decision(_verdict("c7", "legit", 0.95), policy, T0)
    assert d.automated is True
    assert d.analyst_id == policy.version
    assert d.analyst_id.startswith("bid-triage-test+")
    assert d.authority == "triage-policy"
    assert d.candidate_id == "c7"
    assert d.decided_at == T0


# --- TriagePolicy ------------------------------------------------------------


@pytest.mark.parametrize("kwargs", [
    {"auto_reject_min_confidence": 1.5},
    {"auto_reject_min_confidence": -0.1},
    {"auto_reject_min_confidence": float("nan")},
    {"auto_reject_min_confidence": "0.8"},
    {"auto_confirm_min_confidence": 0.49},
    {"auto_confirm_min_confidence": 1.01},
    {"auto_reject_labels": frozenset({"fraud"})},
    {"auto_reject_labels": frozenset({"suspicious"})},
    {"auto_reject_labels": "legit"},
    {"policy_id": ""},
])
def test_policy_validation(kwargs):
    with pytest.raises(ValueError):
        TriagePolicy(**kwargs)


def test_policy_defaults_and_valid_edges():
    default = TriagePolicy()
    assert default.policy_id == "bid-triage-v1"
    assert default.auto_confirm_min_confidence is None  # a person confirms by default
    assert default.auto_reject_labels == frozenset({"legit", "fan"})
    assert TriagePolicy(auto_confirm_min_confidence=0.5).auto_confirm_min_confidence == 0.5
    assert TriagePolicy(auto_reject_min_confidence=0).auto_reject_min_confidence == 0.0
    assert TriagePolicy(auto_reject_labels={"legit"}).auto_reject_labels == frozenset({"legit"})


# --- latest_by_candidate / open_holds / overdue_holds -------------------------


def test_latest_by_candidate_after_escalate_then_person_confirm():
    chain = _Chain()
    escalated = chain.auto(_verdict("c1", "impersonation", 0.95), T0)
    chain.auto(_verdict("c2", "legit", 0.95), T0)
    confirmed = chain.person("c1", "confirm", T0 + timedelta(hours=1))
    assert escalated.manifest.outcome == "escalate"

    latest = latest_by_candidate(chain.packages)
    assert latest["c1"] is confirmed
    assert latest["c1"].manifest.automated is False
    assert latest["c1"].manifest.decided_by == "analyst-1"
    assert latest["c2"].manifest.outcome == "reject"
    # the escalation is resolved by a person and a reject is not a hold
    assert open_holds(chain.packages) == []


def test_open_holds_include_automated_confirm_sorted():
    chain = _Chain()
    chain.auto(_verdict("c2", "suspicious", 0.7), T0 + timedelta(hours=1))
    chain.auto(_verdict("c1", "fraud", 0.99, injection=True), T0 + timedelta(hours=1), AUTO_CONFIRM)
    auto_confirmed = chain.auto(_verdict("c3", "impersonation", 0.95), T0, AUTO_CONFIRM)
    chain.auto(_verdict("c4", "legit", 0.95), T0)
    chain.person("c5", "confirm", T0)
    assert auto_confirmed.manifest.outcome == "confirm"
    assert auto_confirmed.manifest.automated is True

    # oldest first, whatever the chain or id order; equal created_at falls back to id
    assert [p.manifest.candidate_id for p in open_holds(chain.packages)] == ["c3", "c1", "c2"]

    # a person confirming the automatic confirm closes that hold
    chain.person("c3", "confirm", T0 + timedelta(hours=3))
    assert [p.manifest.candidate_id for p in open_holds(chain.packages)] == ["c1", "c2"]


def test_overdue_at_and_before_deadline():
    chain = _Chain()
    hold = chain.auto(_verdict("c1", "suspicious", 0.6), T0)
    deadline = T0 + timedelta(hours=24)

    assert overdue_holds(chain.packages, deadline - timedelta(seconds=1), 24) == []
    assert overdue_holds(chain.packages, deadline, 24) == [hold]
    assert overdue_holds(chain.packages, T0 + timedelta(minutes=30), 0.5) == [hold]
    # the same instant in another offset, and a naive time read as UTC
    assert overdue_holds(chain.packages, deadline.astimezone(timezone(timedelta(hours=-2, minutes=-30))), 24) == [hold]
    assert overdue_holds(chain.packages, deadline.replace(tzinfo=None), 24) == [hold]


@pytest.mark.parametrize("sla_hours", [0, -1, float("nan"), float("inf"), True])
def test_overdue_rejects_invalid_sla(sla_hours):
    with pytest.raises(ValueError):
        overdue_holds([], T0, sla_hours)


# --- coverage ------------------------------------------------------------------


def test_coverage_lists_missing_candidates():
    chain = _Chain()
    chain.auto(_verdict("c1", "impersonation", 0.95), T0)
    chain.auto(_verdict("c2", "suspicious", 0.6), T0)
    chain.auto(_verdict("c9", "legit", 0.95), T0)  # outside the requested set
    chain.person("c1", "confirm", T0 + timedelta(hours=1))

    assert coverage(["c1", "c2", "c3"], chain.packages) == {
        "total": 3,
        "with_receipt": 2,
        "missing": ["c3"],
        "by_outcome": {"confirm": 1, "reject": 0, "escalate": 1, "release": 0},
        "open_holds": ["c2"],
    }
    empty = coverage([], chain.packages)
    assert empty["total"] == 0 and empty["missing"] == [] and sum(empty["by_outcome"].values()) == 0


# --- decide_and_sign -----------------------------------------------------------


def _batch(store: ContentStore) -> tuple[dict[str, Candidate], list[Verdict]]:
    candidates = {cid: _candidate(cid, store) for cid in ("c3", "c1", "c2")}
    verdicts = [
        _verdict("c3", "legit", 0.95),
        _verdict("c1", "impersonation", 0.95),
        _verdict("c2", "suspicious", 0.6),
    ]
    return candidates, verdicts


def test_decide_and_sign_chains_one_receipt_per_verdict(tmp_path):
    store = ContentStore(tmp_path)
    candidates, verdicts = _batch(store)
    packages = decide_and_sign(candidates, verdicts, _signer(), TriagePolicy(), T0)

    assert [p.manifest.candidate_id for p in packages] == ["c1", "c2", "c3"]
    assert [p.manifest.outcome for p in packages] == ["escalate", "escalate", "reject"]
    for p in packages:
        assert p.manifest.automated is True
        assert p.manifest.decided_by == TriagePolicy().version
        assert p.manifest.decided_by.startswith("bid-triage-v1+")
        assert p.manifest.authority == "triage-policy"
        assert p.manifest.created_at == T0
        assert p.manifest.asset_hashes  # the receipts pin real stored bytes
    assert packages[0].manifest.prev_manifest_hash == GENESIS
    for before, after in zip(packages, packages[1:], strict=False):
        assert after.manifest.prev_manifest_hash == chain_link(before)

    ok, reason = evidence.verify_chain(packages, KEY, store)
    assert ok, reason
    ok, reason = evidence.verify_chain_public(packages, store)
    assert ok, reason


def test_decide_and_sign_continues_an_existing_chain(tmp_path):
    store = ContentStore(tmp_path)
    candidates, verdicts = _batch(store)
    first = decide_and_sign(candidates, verdicts[:1], _signer(), TriagePolicy(), T0)
    more = decide_and_sign(candidates, verdicts[1:], _signer(), TriagePolicy(),
                           T0 + timedelta(hours=1), prev_manifest_hash=chain_link(first[-1]))
    assert more[0].manifest.prev_manifest_hash == chain_link(first[-1])
    ok, reason = evidence.verify_chain(first + more, KEY, store)
    assert ok, reason


def test_decide_and_sign_is_deterministic(tmp_path):
    store = ContentStore(tmp_path)
    candidates, verdicts = _batch(store)
    a = decide_and_sign(candidates, verdicts, _signer(), TriagePolicy(), T0)
    b = decide_and_sign(candidates, list(reversed(verdicts)), _signer(), TriagePolicy(), T0)
    assert [p.model_dump_json() for p in a] == [p.model_dump_json() for p in b]


def test_decide_and_sign_rejects_bad_input(tmp_path):
    store = ContentStore(tmp_path)
    candidates, verdicts = _batch(store)
    with pytest.raises(ValueError, match="no candidate"):
        decide_and_sign(candidates, verdicts + [_verdict("c404")], _signer(), TriagePolicy(), T0)
    with pytest.raises(ValueError, match="more than one verdict"):
        decide_and_sign(candidates, verdicts + [_verdict("c1")], _signer(), TriagePolicy(), T0)


def test_policy_version_changes_with_thresholds():
    base = TriagePolicy()
    assert base.version == TriagePolicy().version
    assert TriagePolicy(auto_reject_min_confidence=0.9).version != base.version
    assert TriagePolicy(auto_confirm_min_confidence=0.95).version != base.version
    assert TriagePolicy(policy_id="other").version.split("+")[1] == base.version.split("+")[1]


def test_public_verify_catches_a_deleted_receipt(tmp_path):
    store = ContentStore(tmp_path)
    candidates, verdicts = _batch(store)
    packages = decide_and_sign(candidates, verdicts, _signer(), TriagePolicy(), T0)
    assert len(packages) >= 3
    # Drop the middle receipt and rewrite the unsigned HMAC field of the one
    # before it so a link computed over HMACs would still line up.
    forged = [p.model_copy(deep=True) for p in packages]
    forged[0].manifest_hmac = packages[1].manifest_hmac
    del forged[1]
    ok, reason = evidence.verify_chain_public(forged, store)
    assert not ok and "chain break" in reason
