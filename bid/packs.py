"""
Policy packs: what a notice or a record has to contain under one rule or in one
jurisdiction, mapped to the fields this tool records.

A pack is a JSON file (bundled ones live in bid/policy_packs). Two kinds:

- "notice": requirements for one outgoing notice, checked against a projection
  (for example platform_ip_report). check_notice() says which requirements the
  projection already carries and which the operator has to add before filing.
- "evidence": requirements for the record an organisation keeps of its own
  handling of impersonation. best_effort_report() lists, per requirement, what
  the signed receipts and the governance journal show.

Every pack declares a review_status. Whether a mapping is complete for a given
organisation is a legal question; reports print the status and never state
that a record is sufficient, compliant or admissible.

The pack identity (id, version, sha256 of its canonical JSON) rides in every
receipt signed under it (EvidenceManifest.policy_pack), so a receipt names the
rule set it was produced under.

    bid packs list
    bid packs check-notice projection.json --pack eu-dsa-art16
    bid packs report receipts.jsonl --pack generic-best-effort \
        [--store RUN_DIR --pubkey HEX --journal governance.jsonl \
         --governance governance.json --now 2026-07-04T12:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from . import paths
from .evidence import _hash, manifest_hash
from .models import Candidate, EvidencePackage, GovernancePackage, PolicyPackRef

PACK_DIR = paths.PACKAGE_DIR / "policy_packs"
REPORT_SCHEMA = "bid.best_effort_report/v1"
NOTICE_CHECK_SCHEMA = "bid.notice_check/v1"

DISCLAIMER = ("This report lists what the signed records show against the pack's "
              "requirements. It is not legal advice and does not state that the "
              "records are sufficient, compliant or admissible for any purpose.")


class Requirement(BaseModel):
    id: str
    text: str
    supplied_by: Literal["tool", "operator"] = "tool"
    # notice packs: dotted paths into the projection; "a|b" accepts either path.
    # evidence packs: metric keys of evidence_summary().
    fields: list[str] = Field(default_factory=list)
    basis: Optional[str] = None  # the provision this requirement comes from


class PolicyPack(BaseModel):
    id: str
    version: str
    title: str
    kind: Literal["notice", "evidence"]
    jurisdiction: str
    source: Optional[str] = None
    review_status: Literal["unreviewed", "reviewed", "template"]
    applies_to: Optional[str] = None  # projection kind, for notice packs
    notes: str = ""
    requirements: list[Requirement]


# ---------------------------------------------------------------------------
# Loading and identity
# ---------------------------------------------------------------------------


def list_packs() -> list[str]:
    return sorted(p.stem for p in PACK_DIR.glob("*.json"))


def load_pack(name_or_path: str | Path) -> PolicyPack:
    """A bundled pack by id, or a pack file by path."""
    p = Path(name_or_path)
    if not p.suffix:
        p = PACK_DIR / f"{name_or_path}.json"
    pack = PolicyPack.model_validate_json(p.read_text(encoding="utf-8"))
    ids = [r.id for r in pack.requirements]
    if len(ids) != len(set(ids)):
        raise ValueError(f"pack {pack.id}: duplicate requirement ids")
    if pack.kind == "notice" and not pack.applies_to:
        raise ValueError(f"pack {pack.id}: a notice pack names the projection it applies_to")
    if pack.kind == "evidence":
        unknown = sorted({f for r in pack.requirements for f in r.fields} - set(METRICS))
        if unknown:
            raise ValueError(f"pack {pack.id}: unknown metrics {unknown}")
    return pack


def pack_ref(pack: PolicyPack) -> PolicyPackRef:
    """What a receipt records about the pack in force: id, version and content hash."""
    return PolicyPackRef(id=pack.id, version=pack.version, sha256=_hash(pack))


def _pack_header(pack: PolicyPack) -> dict:
    ref = pack_ref(pack)
    return {"id": ref.id, "version": ref.version, "sha256": ref.sha256, "title": pack.title,
            "jurisdiction": pack.jurisdiction, "source": pack.source,
            "review_status": pack.review_status}


def _utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0, tzinfo=None).isoformat() + "Z"


# ---------------------------------------------------------------------------
# Notice packs
# ---------------------------------------------------------------------------


def _lookup(obj, dotted: str):
    for part in dotted.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def _present(value) -> bool:
    return value not in (None, "", [], {})


def check_notice(projection: dict, pack: PolicyPack) -> dict:
    """Which of the pack's requirements the projection carries, and which the
    operator has to add before the notice is filed."""
    if pack.kind != "notice":
        raise ValueError(f"pack {pack.id} is an {pack.kind} pack, not a notice pack")
    expected = f"bid.projection.{pack.applies_to}/v1"
    if projection.get("schema") != expected:
        raise ValueError(f"pack {pack.id} applies to {expected}, got {projection.get('schema')!r}")
    rows = []
    for req in pack.requirements:
        if req.supplied_by == "operator":
            rows.append({"id": req.id, "text": req.text, "basis": req.basis, "status": "operator"})
            continue
        missing = [f for f in req.fields
                   if not any(_present(_lookup(projection, alt)) for alt in f.split("|"))]
        rows.append({"id": req.id, "text": req.text, "basis": req.basis,
                     "status": "gap" if missing else "met", "missing_fields": missing})
    return {
        "schema": NOTICE_CHECK_SCHEMA,
        "pack": _pack_header(pack),
        "projection": projection.get("schema"),
        "manifest_hash": projection.get("manifest_hash"),
        "requirements": rows,
        "operator_must_add": [r["id"] for r in rows if r["status"] == "operator"],
        "gaps": [r["id"] for r in rows if r["status"] == "gap"],
        "notice": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# Evidence packs
# ---------------------------------------------------------------------------

# metric key -> what it measures (the vocabulary evidence packs refer to)
METRICS: dict[str, str] = {
    "receipts.signed": "signed receipts in the period",
    "receipts.sourced": "receipts that name the sensor and the stored raw observation",
    "decisions.accountable": "receipts that name who decided and under what authority",
    "decisions.outcomes": "receipts per outcome, and how many were automated",
    "model.trace": "receipts that name the model, its family and the prompt template",
    "model.independent_recheck": "rechecks run by a different model family than the classifier",
    "integrity.public_signature": "receipts whose signature and chain verify with the public key alone",
    "holds.escalated": "held findings past the review deadline that were escalated",
    "releases.accountable": "reversals that name the person, their authority and the reversed receipt",
    "deployment.attested": "receipts bound to a recorded deployment attestation",
    "queue.stop_authority": "people declared able to halt the queue",
    "detection.time_to_decision": "hours from first sighting to the first signed decision",
}


def _metric(met: Optional[bool], value, detail: str) -> dict:
    # met: True / False, or None when the metric does not apply or was not checked
    return {"met": met, "value": value, "detail": detail}


def evidence_summary(packages: list[EvidencePackage], *, store=None,
                     journal: Optional[list[GovernancePackage]] = None,
                     config=None, now: Optional[datetime] = None,
                     candidates: Optional[list[Candidate]] = None,
                     pubkey: Optional[str] = None) -> dict[str, dict]:
    """Every metric in METRICS over one set of receipts. Inputs that were not
    given (store, journal, governance config, now, candidates) leave the metrics
    that need them unchecked rather than failed. `pubkey` pins the signing key
    for the public check; without it the receipts are checked against the key
    they name, and the reason says so."""
    n = len(packages)
    ms = [p.manifest for p in packages]
    out: dict[str, dict] = {}

    out["receipts.signed"] = _metric(n > 0, n, f"{n} signed receipts")
    sourced = sum(1 for m in ms if m.source.sensor_name and m.source.raw_observation_ref)
    out["receipts.sourced"] = _metric(n > 0 and sourced == n, sourced, f"{sourced}/{n}")

    accountable = sum(1 for m in ms if m.decided_by and m.authority)
    out["decisions.accountable"] = _metric(n > 0 and accountable == n, accountable, f"{accountable}/{n}")

    by_outcome = {o: sum(1 for m in ms if m.outcome == o) for o in ("confirm", "reject", "escalate", "release")}
    automated = sum(1 for m in ms if m.automated)
    out["decisions.outcomes"] = _metric(n > 0, {**by_outcome, "automated": automated},
                                        ", ".join(f"{k} {v}" for k, v in by_outcome.items())
                                        + f"; automated {automated}")

    traced = sum(1 for m in ms if any(t.role == "primary" and t.family and t.prompt_template
                                      for t in m.model_trace))
    out["model.trace"] = _metric(n > 0 and traced == n, traced, f"{traced}/{n}")

    rechecked = independent = 0
    for m in ms:
        primary = [t for t in m.model_trace if t.role == "primary"]
        for t in (t for t in m.model_trace if t.role == "recheck"):
            rechecked += 1
            independent += bool(primary) and t.family != primary[0].family
    out["model.independent_recheck"] = (
        _metric(None, 0, "no recheck ran") if rechecked == 0
        else _metric(independent == rechecked, independent, f"{independent}/{rechecked} rechecks cross-family"))

    if store is None:
        out["integrity.public_signature"] = _metric(None, None, "not checked: no asset store given")
    else:
        from .evidence import verify_chain_public
        ok, reason = verify_chain_public(packages, store, pubkey)
        if ok and not pubkey:
            reason += "; key not pinned (pass --pubkey with the published key)"
        out["integrity.public_signature"] = _metric(n > 0 and ok, ok, reason)

    records = [g.record for g in (journal or [])]
    if journal is None or config is None or now is None:
        out["holds.escalated"] = _metric(None, None, "not checked: needs the journal, the config and a time")
    else:
        from .decisions import overdue_holds
        escalated = {r.subject for r in records if r.kind == "hold_sla_escalation"}
        overdue = overdue_holds(packages, now, config.hold_sla_hours)
        missed = [p.manifest.candidate_id for p in overdue if manifest_hash(p) not in escalated]
        out["holds.escalated"] = _metric(not missed, len(overdue) - len(missed),
                                         f"{len(overdue)} overdue holds, {len(missed)} not escalated"
                                         + (f": {', '.join(sorted(missed))}" if missed else ""))

    releases = [m for m in ms if m.outcome == "release"]
    ok_rel = sum(1 for m in releases if m.decided_by and m.authority and m.supersedes and not m.automated)
    out["releases.accountable"] = (
        _metric(None, 0, "no releases") if not releases
        else _metric(ok_rel == len(releases), ok_rel, f"{ok_rel}/{len(releases)}"))

    if journal is None:
        out["deployment.attested"] = _metric(None, None, "not checked: no governance journal given")
    else:
        known = {_hash(r.payload) for r in records if r.kind == "deployment_attestation"}
        bound = sum(1 for m in ms if m.attestation_hash and m.attestation_hash in known)
        out["deployment.attested"] = _metric(n > 0 and bound == n, bound,
                                             f"{bound}/{n} receipts name a recorded attestation")

    if config is None:
        out["queue.stop_authority"] = _metric(None, None, "not checked: no governance config given")
    else:
        stops = sorted(config.stop_authority)
        halts = sum(1 for r in records if r.kind == "queue_halt")
        out["queue.stop_authority"] = _metric(bool(stops), stops,
                                              f"{len(stops)} declared; {halts} halts recorded")

    if candidates is None:
        out["detection.time_to_decision"] = _metric(None, None, "not checked: no candidates given")
    else:
        seen = {c.id: c.first_seen for c in candidates}
        first: dict[str, datetime] = {}
        for m in ms:
            if m.candidate_id in seen and m.candidate_id not in first:
                first[m.candidate_id] = m.created_at
        hours = sorted((_aware(first[c]) - _aware(seen[c])) / timedelta(hours=1) for c in first)
        out["detection.time_to_decision"] = (
            _metric(None, None, "no candidate matches a receipt") if not hours
            else _metric(True, {"median_hours": round(statistics.median(hours), 2),
                                "max_hours": round(hours[-1], 2), "n": len(hours)},
                         f"median {statistics.median(hours):.2f} h over {len(hours)} findings"))
    return out


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def best_effort_report(packages: list[EvidencePackage], pack: PolicyPack, **inputs) -> dict:
    """Requirement-by-requirement account of what the records show. inputs are
    passed to evidence_summary(); "now" also dates the report."""
    if pack.kind != "evidence":
        raise ValueError(f"pack {pack.id} is a {pack.kind} pack, not an evidence pack")
    summary = evidence_summary(packages, **inputs)
    rows = []
    for req in pack.requirements:
        if req.supplied_by == "operator":
            status = "operator"
        else:
            states = [summary[f]["met"] for f in req.fields]
            if any(s is False for s in states):
                status = "gap"
            elif all(s is True for s in states):
                status = "met"
            elif all(s is None for s in states):
                status = "not_checked"
            else:
                status = "partial"
        rows.append({"id": req.id, "text": req.text, "basis": req.basis, "status": status,
                     "evidence": {f: summary[f] for f in req.fields}})
    created = [_aware(p.manifest.created_at) for p in packages]
    now = inputs.get("now")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "schema": REPORT_SCHEMA,
        "pack": _pack_header(pack),
        "period": {"from": _utc(min(created)) if created else None,
                   "to": _utc(max(created)) if created else None},
        "as_of": _utc(now) if now else None,
        "receipts": len(packages),
        "requirements": rows,
        "status_counts": dict(sorted(counts.items())),
        "notice": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path, model):
    return [model.model_validate_json(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Policy packs: notice checks and best-effort reports")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list the bundled packs")
    n = sub.add_parser("check-notice", help="check one projection against a notice pack")
    n.add_argument("projection", type=Path)
    n.add_argument("--pack", required=True)
    r = sub.add_parser("report", help="best-effort report over signed receipts")
    r.add_argument("receipts", type=Path, help="JSONL of evidence receipts")
    r.add_argument("--pack", default="generic-best-effort")
    r.add_argument("--store", type=Path, help="asset store, to verify signatures and asset hashes")
    r.add_argument("--pubkey", help="published Ed25519 public key (hex) the receipts must be signed with")
    r.add_argument("--journal", type=Path, help="governance journal (JSONL)")
    r.add_argument("--governance", type=Path, help="governance config (JSON)")
    r.add_argument("--now", help="report time, ISO 8601 (needed for the hold-deadline check)")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for name in list_packs():
            p = load_pack(name)
            print(f"{p.id:24s} {p.kind:8s} {p.jurisdiction:6s} {p.review_status:10s} {p.title}")
        return 0
    if args.cmd == "check-notice":
        out = check_notice(json.loads(args.projection.read_text(encoding="utf-8")), load_pack(args.pack))
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    from .storage import ContentStore
    inputs: dict = {}
    if args.store:
        inputs["store"] = ContentStore(args.store)
    if args.pubkey:
        inputs["pubkey"] = args.pubkey
    if args.journal:
        from .governance import GovernanceJournal
        inputs["journal"] = GovernanceJournal(args.journal).packages()  # a missing file is an empty journal
    if args.governance:
        from .governance import GovernanceConfig
        inputs["config"] = GovernanceConfig.load(args.governance)
    if args.now:
        inputs["now"] = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
    out = best_effort_report(_read_jsonl(args.receipts, EvidencePackage), load_pack(args.pack), **inputs)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
