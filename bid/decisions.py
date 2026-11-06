"""
Triage decisions and open holds.

Every decision on a candidate - confirm, reject, escalate or release - gets the
same signed receipt through EvidenceSigner.package, so a reject or an
escalation is as reviewable as a confirm.

Division of work between the triage policy and people:

  - A person confirms findings by default. The triage policy only rejects
    clear negatives and escalates everything else to a person.
  - An automatic confirm can be enabled (auto_confirm_min_confidence). Its
    receipt is still an open hold until a person looks at it, that is until a
    later receipt signed by a person becomes the latest one for the candidate.
  - A release reverses a confirm and is never automated (see governance.py).

The read-only views (latest_by_candidate, open_holds, overdue_holds, coverage)
take receipts in chain order: a later receipt for a candidate replaces an
earlier one.

Time is always a parameter; nothing here reads a clock. A naive datetime is
read as UTC, never as local time.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from functools import cached_property
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping, Optional, get_args

from .evidence import _hash, chain_link
from .models import (
    OUTCOMES,
    POSITIVE_LABELS,
    AnalystDecision,
    Candidate,
    EvidencePackage,
    EvidenceSigner,
    Label,
    PolicyPackRef,
    Verdict,
)

# Declared authority on every receipt the triage policy signs.
TRIAGE_AUTHORITY = "triage-policy"

# The clear negatives: the only labels the triage policy may reject without a
# person. Positive labels and "suspicious" always reach a person.
REJECTABLE_LABELS: frozenset[str] = frozenset(get_args(Label)) - POSITIVE_LABELS - {"suspicious"}


def _confidence(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number in [0, 1], got {value!r}")
    if not 0.0 <= value <= 1.0:  # NaN fails this comparison as well
        raise ValueError(f"{name} must be in [0, 1], got {value!r}")
    return float(value)


@dataclass(frozen=True)
class TriagePolicy:
    """Thresholds for automated triage decisions.

    Automated receipts record `version` as decided_by: the policy id plus a
    short hash of the thresholds, so receipts signed under two configurations
    stay distinguishable even when the id is not changed.
    """

    policy_id: str = "bid-triage-v1"
    auto_reject_labels: frozenset[str] = frozenset({"legit", "fan"})
    auto_reject_min_confidence: float = 0.8
    # None disables automatic confirms: every finding then waits for a person.
    auto_confirm_min_confidence: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ValueError("policy_id must be a non-empty string")
        if isinstance(self.auto_reject_labels, str):
            raise ValueError("auto_reject_labels must be a collection of labels, not one string")
        try:
            labels = frozenset(self.auto_reject_labels)
        except TypeError as e:
            raise ValueError(f"auto_reject_labels must be a collection of labels: {e}") from e
        not_rejectable = labels - REJECTABLE_LABELS
        if not_rejectable:
            raise ValueError(
                f"auto_reject_labels may only hold clear negatives {sorted(REJECTABLE_LABELS)}, "
                f"got {sorted(map(str, not_rejectable))}"
            )
        # Normalised in place; the dataclass is frozen, hence object.__setattr__.
        object.__setattr__(self, "auto_reject_labels", labels)
        object.__setattr__(
            self,
            "auto_reject_min_confidence",
            _confidence("auto_reject_min_confidence", self.auto_reject_min_confidence),
        )
        if self.auto_confirm_min_confidence is not None:
            confirm_at = _confidence("auto_confirm_min_confidence", self.auto_confirm_min_confidence)
            if confirm_at < 0.5:
                raise ValueError(
                    f"auto_confirm_min_confidence must be at least 0.5 when set, got {confirm_at!r}"
                )
            object.__setattr__(self, "auto_confirm_min_confidence", confirm_at)

    @cached_property
    def version(self) -> str:
        """policy_id + "+" + the first 8 hex digits of a hash of the thresholds."""
        digest = _hash({
            "auto_reject_labels": sorted(self.auto_reject_labels),
            "auto_reject_min_confidence": self.auto_reject_min_confidence,
            "auto_confirm_min_confidence": self.auto_confirm_min_confidence,
        })
        return f"{self.policy_id}+{digest[:8]}"


def _triage(verdict: Verdict, policy: TriagePolicy) -> tuple[str, str]:
    """(outcome, reason) for one verdict. Rules apply in order; the first match wins."""
    label, conf = verdict.label, verdict.confidence
    if verdict.injection_flagged:
        return "escalate", "untrusted content tried to steer the classifier; a person reviews it"
    rc = verdict.recheck
    if rc is not None and not rc.agrees:
        return "escalate", (
            f"cross-family recheck ({rc.family}: {rc.label}) disagrees with the primary "
            f"label {label}; a person reviews it"
        )
    if label in POSITIVE_LABELS:
        confirm_at = policy.auto_confirm_min_confidence
        if confirm_at is None:
            return "escalate", f"{label} at confidence {conf}; a person confirms findings"
        if conf >= confirm_at:
            return "confirm", (
                f"automatic confirm: {label} at confidence {conf} >= {confirm_at}; "
                "open hold until a person reviews it"
            )
        return "escalate", (
            f"{label} at confidence {conf} is below the auto-confirm threshold {confirm_at}; "
            "a person confirms findings"
        )
    if label == "suspicious":
        return "escalate", f"suspicious at confidence {conf}; a person decides"
    if label in policy.auto_reject_labels:
        reject_at = policy.auto_reject_min_confidence
        if conf >= reject_at:
            return "reject", f"clear negative: {label} at confidence {conf} >= {reject_at}"
        return "escalate", (
            f"{label} at confidence {conf} is below the auto-reject threshold {reject_at}; "
            "a person decides"
        )
    return "escalate", f"{label} is not auto-rejected under {policy.policy_id}; a person decides"


def auto_decision(verdict: Verdict, policy: TriagePolicy, decided_at: datetime) -> AnalystDecision:
    """The triage policy's decision on one verdict.

    Order: an injection flag escalates; a disagreeing cross-family recheck
    escalates; a positive label is confirmed only when automatic confirms are
    enabled and the confidence reaches the threshold, else escalated;
    "suspicious" escalates; a clear negative at or above the reject threshold is
    rejected; anything else escalates. The reason is kept as the note.
    """
    outcome, reason = _triage(verdict, policy)
    return AnalystDecision(
        candidate_id=verdict.candidate_id,
        analyst_id=policy.version,
        decision=outcome,
        decided_at=decided_at,
        note=reason,
        authority=TRIAGE_AUTHORITY,
        automated=True,
    )


def as_utc(dt: datetime) -> datetime:
    """dt as an aware UTC datetime. A naive datetime is read as UTC."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def latest_by_candidate(packages: Iterable[EvidencePackage]) -> dict[str, EvidencePackage]:
    """The last receipt per candidate, in chain order."""
    latest: dict[str, EvidencePackage] = {}
    for pkg in packages:
        latest[pkg.manifest.candidate_id] = pkg
    return latest


def is_open_hold(pkg: EvidencePackage) -> bool:
    """An escalation waits for a person; so does a confirm the policy made alone."""
    m = pkg.manifest
    return m.outcome == "escalate" or (m.outcome == "confirm" and m.automated)


def open_holds(packages: Iterable[EvidencePackage]) -> list[EvidencePackage]:
    """Latest receipts that still wait for a person, oldest first.

    Sorted by (created_at, candidate_id) so the order is stable.
    """
    holds = [pkg for pkg in latest_by_candidate(packages).values() if is_open_hold(pkg)]
    return sorted(holds, key=lambda p: (as_utc(p.manifest.created_at), p.manifest.candidate_id))


def _sla_window(sla_hours: float) -> timedelta:
    if (
        isinstance(sla_hours, bool)
        or not isinstance(sla_hours, (int, float))
        or not math.isfinite(sla_hours)
        or sla_hours <= 0
    ):
        raise ValueError(f"sla_hours must be a positive number of hours, got {sla_hours!r}")
    return timedelta(hours=sla_hours)


def overdue_holds(
    packages: Iterable[EvidencePackage], now: datetime, sla_hours: float
) -> list[EvidencePackage]:
    """Open holds whose SLA has run out: created_at + sla_hours <= now.

    A hold is overdue at its deadline, not one tick after it.
    """
    window = _sla_window(sla_hours)
    now_utc = as_utc(now)
    return [p for p in open_holds(packages) if as_utc(p.manifest.created_at) + window <= now_utc]


def coverage(candidate_ids: Iterable[str], packages: Iterable[EvidencePackage]) -> dict:
    """Receipt coverage for a set of candidates.

    Only receipts for the given candidates count, so with_receipt + len(missing)
    equals total and the by_outcome counts add up to with_receipt. A candidate
    without any receipt is listed under missing, never dropped silently.
    """
    if isinstance(candidate_ids, str):
        raise ValueError("candidate_ids must be a collection of ids, not one string")
    ids = set(candidate_ids)
    latest = {cid: pkg for cid, pkg in latest_by_candidate(packages).items() if cid in ids}
    by_outcome = {outcome: 0 for outcome in OUTCOMES}
    for pkg in latest.values():
        by_outcome[pkg.manifest.outcome] += 1
    return {
        "total": len(ids),
        "with_receipt": len(latest),
        "missing": sorted(ids - latest.keys()),
        "by_outcome": by_outcome,
        "open_holds": sorted(cid for cid, pkg in latest.items() if is_open_hold(pkg)),
    }


def decide_and_sign(
    candidates_by_id: Mapping[str, Candidate],
    verdicts: Iterable[Verdict],
    signer: EvidenceSigner,
    policy: TriagePolicy,
    decided_at: datetime,
    prev_manifest_hash: Optional[str] = None,
    *,
    policy_pack: Optional[PolicyPackRef] = None,
    attestation_hash: Optional[str] = None,
) -> list[EvidencePackage]:
    """One automated decision and one chained receipt per verdict.

    Verdicts are processed in candidate_id order. The first receipt links to
    prev_manifest_hash (None starts a new chain); each later one links to the
    receipt before it (evidence.chain_link). The receipts are returned, not
    stored: the caller appends them to its chain in this order. policy_pack and
    attestation_hash are recorded in every receipt.
    """
    ordered = sorted(verdicts, key=lambda v: v.candidate_id)
    seen: set[str] = set()
    for v in ordered:
        if v.candidate_id in seen:
            raise ValueError(f"more than one verdict for candidate {v.candidate_id!r}")
        seen.add(v.candidate_id)
        if v.candidate_id not in candidates_by_id:
            raise ValueError(f"no candidate for verdict {v.candidate_id!r}")

    packages: list[EvidencePackage] = []
    prev = prev_manifest_hash
    for v in ordered:
        decision = auto_decision(v, policy, decided_at)
        pkg = signer.package(candidates_by_id[v.candidate_id], v, decision, prev, decided_at,
                             policy_pack=policy_pack, attestation_hash=attestation_hash)
        packages.append(pkg)
        prev = chain_link(pkg)
    return packages
