"""
Operator console backend: the pipeline, a person's decisions and governance, as JSON.

Each console run is an ordinary run directory, laid out like the one `bid run`
writes (receipts.jsonl, cases.jsonl, content-addressed assets, receipt_sample.json,
ed25519_pubkey.txt) plus run.json with the run summary, kept under
<console root>/runs/<run id>/. A run never overwrites an earlier one, and
`bid verify`, `bid project`, `bid governance` and `bid packs report` work on any of
them with --run-dir.

The triage policy signs a receipt for every classified candidate: it rejects clear
negatives and escalates the rest to a person. A person's confirm, reject or
escalation is appended to the same chain. Reversing a person's confirm takes a
release by a declared releaser (governance.release).

Queue stop, releasers and the hold deadline come from the deployment's governance
settings and journal, which the command line uses too: a stop called here also
stops `bid run` and `bid project`, and the other way round. A stop halts automation
and exports, not people: decisions can still be recorded. Overdue holds are shown
here and recorded by `bid governance escalate` (run it on a schedule).

The label ledger and the applied operating point sit in the console root and
accumulate across runs. The operating point marks which findings clear the
calibrated threshold; it never changes a signed decision.

Times are the real UTC clock unless the caller passes `now`. Functions raise
PermissionError (no authority), LookupError (no run or no such candidate),
QueueStopped (the queue is halted) or ValueError (a request the current state does
not allow); the server maps them to HTTP status codes.
"""
from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import paths, records
from .classify import build_classifier
from .decisions import (
    TriagePolicy,
    as_utc,
    auto_decision,
    coverage,
    latest_by_candidate,
    open_holds,
    overdue_holds,
)
from .evidence import (
    DEFAULT_HMAC_KEY,
    Ed25519Dsse,
    HmacEvidenceSigner,
    chain_link,
    manifest_hash,
    verify_chain,
    verify_chain_public,
    verify_package_public,
)
from .families import model_family
from .feedback import FeedbackLabel, LabelLedger, fused_score, recalibrate, uncertainty
from .governance import GovernanceConfig, GovernanceJournal, halt_queue, release, resume_queue
from .metrics import cut_ratio, precision_at_k, recall
from .models import AnalystDecision, EvidencePackage, PolicyPackRef, Verdict
from .rank import _LABEL_RANK, rank
from .run_pipeline import (
    ANALYST_AUTHORITY,
    detect,
    load_brands,
    load_cti_badlist,
    load_labels,
    sign_decisions,
)
from .storage import ContentStore

PERSON_DECISIONS = ("confirm", "reject", "escalate")
RUN_SUMMARY = "run.json"
SAMPLE = "receipt_sample.json"
LABELS = "feedback_labels.jsonl"
OPERATING_POINT = "active_policy.json"
_RUNS = "runs"
# Fused-score operating point before any calibration has been applied.
_DEFAULT_THRESHOLD = 0.85


class QueueStopped(Exception):
    """The queue is halted: no run and no export until it is resumed."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now(now: Optional[datetime]) -> datetime:
    return as_utc(now) if now is not None else datetime.now(timezone.utc)


def _utc_z(dt: datetime) -> str:
    return as_utc(dt).isoformat().replace("+00:00", "Z")


def _signer() -> HmacEvidenceSigner:
    return HmacEvidenceSigner(DEFAULT_HMAC_KEY, dsse=Ed25519Dsse())


def _public_key() -> str:
    """The deployment's own signing key: console checks pin it."""
    return Ed25519Dsse().public_key_hex()


def _actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise ValueError("say who is acting: every decision is recorded under a named person")
    return actor


def default_journal() -> GovernanceJournal:
    """The deployment's governance journal, shared with the command line."""
    return GovernanceJournal(paths.data_dir() / "governance.jsonl", dsse=Ed25519Dsse())


def current_run(root: Path) -> Optional[Path]:
    """The newest complete run directory under `root`, or None before the first run."""
    runs = Path(root) / _RUNS
    if not runs.is_dir():
        return None
    complete = sorted(p for p in runs.iterdir() if (p / RUN_SUMMARY).is_file())
    return complete[-1] if complete else None


def _require_run(root: Path) -> Path:
    run_dir = current_run(root)
    if run_dir is None:
        raise LookupError("no console run yet; run the pipeline first")
    return run_dir


def _new_run_dir(root: Path, now: datetime) -> Path:
    base = as_utc(now).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir, n = Path(root) / _RUNS / base, 1
    while run_dir.exists():
        run_dir, n = Path(root) / _RUNS / f"{base}-{n}", n + 1
    run_dir.mkdir(parents=True)
    return run_dir


def _case_and_latest(run_dir: Path, candidate_id: str):
    case = records.read_cases(run_dir).get(candidate_id)
    chain = records.read_receipts(run_dir)
    latest = latest_by_candidate(chain).get(candidate_id)
    if case is None or latest is None:
        raise LookupError(f"no receipt for candidate {candidate_id!r} in the current run")
    return case, chain, latest


def receipt_view(pkg: EvidencePackage) -> dict:
    """What the console shows of one receipt."""
    m = pkg.manifest
    return {
        "manifest_hash": manifest_hash(pkg),
        "outcome": m.outcome,
        "decided_by": m.decided_by,
        "authority": m.authority,
        "automated": m.automated,
        "created_at": _utc_z(m.created_at),
        "supersedes": m.supersedes,
        "policy_version": m.policy_version,
    }


def _signed(run_dir: Path, chain: list[EvidencePackage], pkg: EvidencePackage) -> dict:
    """A receipt and its place in the chain, with the whole chain re-verified on
    the public key alone."""
    target = manifest_hash(pkg)
    index = next(i for i, p in enumerate(chain) if manifest_hash(p) == target)
    pub_ok, pub_reason = verify_chain_public(chain, ContentStore(run_dir), _public_key())
    return {"receipt": receipt_view(pkg),
            "chain": {"index": index, "length": len(chain), "pub_ok": pub_ok, "pub_reason": pub_reason}}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def _official_logos(store: ContentStore, brands_file: Path) -> dict[str, str]:
    """brand id -> content hash of its first official logo, stored in the run."""
    raw = json.loads(brands_file.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for b in raw.values():
        logos = b.get("official_logo_assets", [])
        if logos:
            out[b["id"]] = store.put_bytes((brands_file.parent / logos[0]).read_bytes())
    return out


def run_pipeline_api(root: Path, k: int = 10, live: bool = False, model: Optional[str] = None,
                     embeddings: bool = False, broad: bool = False, *,
                     now: Optional[datetime] = None, journal: Optional[GovernanceJournal] = None,
                     brands_file: Optional[Path] = None, triage: Optional[TriagePolicy] = None,
                     policy_pack: Optional[PolicyPackRef] = None,
                     attestation_hash: Optional[str] = None) -> dict:
    """Detect, triage and sign into a new run directory, then return its view.

    Refused while the queue is stopped: a stop halts automation, model calls
    included.
    """
    root = Path(root)
    now = _now(now)
    journal = journal or default_journal()
    if journal.is_halted():
        raise QueueStopped("the queue is stopped; no run until someone with stop authority resumes it")
    policy = triage or TriagePolicy()
    brands_file = Path(brands_file) if brands_file else paths.FIXTURES / "brands.json"

    run_dir = _new_run_dir(root, now)
    store = ContentStore(run_dir)
    brands = load_brands(embeddings=embeddings, brands_file=brands_file)
    cti = load_cti_badlist()
    labels = load_labels()
    classifier = build_classifier(cti, store=store, model=model, live=live)
    from .sensors.factory import build_sensors
    # broad attaches the live keyless sensors (app store, look-alike domains,
    # certificate logs); social ingestion stays the fixture sensor.
    sensors = build_sensors(brands=brands, broad=broad)
    det = detect(store, brands, cti, classifier, sensors, embeddings=embeddings)

    t0 = time.perf_counter()
    packages = sign_decisions(det, _signer(), policy, now, simulate_analyst=False,
                              policy_pack=policy_pack, attestation_hash=attestation_hash)
    time_to_evidence = time.perf_counter() - t0
    records.write_cases(run_dir, [records.Case(candidate=det.survivor_by_id[v.candidate_id], verdict=v)
                                  for v in det.verdicts])
    records.write_receipts(run_dir, packages)
    sample = next((p for p in packages if p.manifest.asset_hashes), packages[0] if packages else None)
    if sample is not None:
        (run_dir / SAMPLE).write_text(sample.model_dump_json(indent=2), encoding="utf-8")
        (run_dir / "ed25519_pubkey.txt").write_text(sample.ed25519_pubkey or "", encoding="utf-8")

    ranked_all: list[Verdict] = []
    brand_rows = []
    for brand in det.brands:
        own = [v for v in det.verdicts if det.survivor_by_id[v.candidate_id].brand_id == brand.id]
        ranked = rank(own, k=k)
        ranked_all.extend(ranked)
        brand_rows.append({"id": brand.id, "name": brand.name, "official_handles": brand.official_handles,
                           "official_domains": brand.official_domains, "aliases": brand.aliases,
                           "ranked": [v.candidate_id for v in ranked]})
    ordered = sorted(ranked_all, key=lambda v: (_LABEL_RANK.get(v.label, 0), v.confidence, v.candidate_id),
                     reverse=True)
    total_in = len(det.candidates)
    health = [s.health() for s in sensors]
    summary = {
        "run_id": run_dir.name,
        "created_at": _utc_z(now),
        "classifier": classifier.model_id,
        "triage_policy": policy.version,
        "sensors": health,
        # A live run without an API key falls back to the offline classifier;
        # live_effective says which one ran, so a model call is never claimed
        # when none happened.
        "mode": {"live_requested": live, "embeddings": embeddings, "broad": broad,
                 "live_effective": live and not classifier.model_id.startswith("mock"),
                 "live_sensors": sum(1 for h in health if h.get("mode") == "live"),
                 "discovery_mode": ("broad: live app store, look-alike domains and certificate logs "
                                    "(social ingestion from fixtures)") if broad
                                   else "default: offline fixtures"},
        "metrics": {
            "candidates": total_in, "survivors": len(det.survivors),
            # Only labelled candidates enter precision and recall; candidates from
            # live sensors are triaged but never silently scored.
            "labeled": sum(1 for c in det.candidates if c.id in labels),
            "unlabeled": sum(1 for c in det.candidates if c.id not in labels),
            "dropped": total_in - len(det.survivors),
            "cut_ratio": round(cut_ratio(total_in, len(det.survivors)), 3),
            "precision_at_5": round(precision_at_k(ordered, labels, 5), 3),
            "recall": round(recall(det.verdicts, labels), 3),
            "cost_usd": round(sum(v.cost_usd for v in det.verdicts), 6),
            "time_to_evidence_s": round(time_to_evidence, 4),
            "injection_seen": sum(1 for v in det.verdicts if v.injection_flagged),
        },
        "brands": brand_rows,
        "official_logos": _official_logos(store, brands_file),
        "triage_reasons": {v.candidate_id: auto_decision(v, policy, now).note for v in det.verdicts},
    }
    (run_dir / RUN_SUMMARY).write_text(json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8")
    return run_view(root, run_dir=run_dir)


def _queue_item(case: records.Case, pkg: Optional[EvidencePackage], triage_reason: Optional[str],
                threshold: float, official_logo: Optional[str]) -> dict:
    c, v = case.candidate, case.verdict
    signals = v.signals.model_dump()
    fused = round(fused_score(signals), 3)
    rc = v.recheck
    return {
        "candidate_id": c.id, "handle": c.handle, "display_name": c.display_name, "bio": c.bio,
        "link": c.link_in_bio_url, "platform": c.platform,
        "label": v.label, "confidence": v.confidence, "reasoning": v.reasoning,
        "injection_flagged": v.injection_flagged, "signals": signals,
        "fused_score": fused,
        "calibrated_band": "above_threshold" if fused >= threshold else "below_threshold",
        "uncertainty": uncertainty(v.confidence, v.label, signals),
        "asset": f"/api/asset/{c.assets[0].sha256}" if c.assets else None,
        "official_asset": f"/api/asset/{official_logo}" if official_logo else None,
        # The prompt template is versioned like the model: both are part of the decision.
        "model": {"id": v.model_id, "family": v.model_family or model_family(v.model_id),
                  "prompt_template": v.prompt_template or None},
        "recheck": None if rc is None else {"model_id": rc.model_id, "family": rc.family,
                                            "label": rc.label, "agrees": rc.agrees},
        "redactions": v.redactions,
        "triage_reason": triage_reason,
        "receipt": receipt_view(pkg) if pkg is not None else None,
    }


def _sample_view(run_dir: Path) -> Optional[dict]:
    p = run_dir / SAMPLE
    if not p.exists():
        return None
    pkg = EvidencePackage.model_validate_json(p.read_text(encoding="utf-8"))
    m = pkg.manifest
    return {"candidate_id": m.candidate_id, "outcome": m.outcome, "policy_version": m.policy_version,
            "manifest_hash": manifest_hash(pkg)}


def run_view(root: Path, *, run_dir: Optional[Path] = None) -> dict:
    """The current run as the console shows it, rebuilt from disk: the run summary,
    the cases, and the receipt chain as it stands now."""
    root = Path(root)
    run_dir = Path(run_dir) if run_dir else _require_run(root)
    summary = json.loads((run_dir / RUN_SUMMARY).read_text(encoding="utf-8"))
    cases = records.read_cases(run_dir)
    chain = records.read_receipts(run_dir)
    store = ContentStore(run_dir)
    latest = latest_by_candidate(chain)
    cov = coverage(list(cases), chain)
    threshold = active_operating_point(root)["decision_threshold"]
    logos = summary.get("official_logos", {})
    reasons = summary.get("triage_reasons", {})
    brands = []
    for b in summary["brands"]:
        queue = [_queue_item(cases[cid], latest.get(cid), reasons.get(cid), threshold, logos.get(b["id"]))
                 for cid in b["ranked"] if cid in cases]
        brands.append({"id": b["id"], "name": b["name"], "official_handles": b["official_handles"],
                       "official_domains": b["official_domains"], "aliases": b["aliases"], "queue": queue})
    chain_ok, chain_reason = verify_chain(chain, DEFAULT_HMAC_KEY, store)
    pub_ok, pub_reason = verify_chain_public(chain, store, _public_key())
    return {
        "run_id": summary["run_id"], "created_at": summary["created_at"],
        "classifier": summary["classifier"], "sensors": summary["sensors"], "mode": summary["mode"],
        "metrics": {**summary["metrics"], "packages": len(chain), "open_holds": len(cov["open_holds"])},
        "brands": brands,
        "evidence": {
            "chain_ok": chain_ok, "pub_ok": pub_ok, "chain_reason": chain_reason, "pub_reason": pub_reason,
            "by_outcome": cov["by_outcome"], "coverage": f"{cov['with_receipt']}/{cov['total']}",
            "triage_policy": summary["triage_policy"], "sample": _sample_view(run_dir),
        },
    }


# ---------------------------------------------------------------------------
# A person's decisions
# ---------------------------------------------------------------------------


def _record_label(root: Path, case: records.Case, decision: str, analyst_id: str, now: datetime) -> dict:
    ledger = LabelLedger(Path(root) / LABELS)
    v = case.verdict
    rec = ledger.append(FeedbackLabel(
        candidate_id=case.candidate.id, brand_id=case.candidate.brand_id, label=v.label,
        decision=decision, analyst_id=analyst_id, decided_at=_utc_z(now),
        signals=v.signals.model_dump(), model_label=v.label))
    ok, reason = ledger.verify()
    return {"record_hmac": rec.record_hmac[:16], "ledger_verified": ok, "ledger_reason": reason}


def decide(root: Path, candidate_id: str, decision: str, analyst_id: str, *, note: str = "",
           now: Optional[datetime] = None, policy_pack: Optional[PolicyPackRef] = None,
           attestation_hash: Optional[str] = None) -> dict:
    """Sign a person's confirm, reject or escalation into the current run's chain.

    Allowed while the queue is stopped. A person's confirm stands until a declared
    releaser releases it; confirming it again returns the existing receipt.
    Confirms and rejects also go into the label ledger used for calibration.
    """
    if decision not in PERSON_DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(PERSON_DECISIONS)}, not {decision!r}")
    analyst_id = _actor(analyst_id)
    root = Path(root)
    run_dir = _require_run(root)
    now = _now(now)
    case = records.read_cases(run_dir).get(candidate_id)
    if case is None:
        raise LookupError(f"candidate {candidate_id!r} is not in the current run")
    chain = records.read_receipts(run_dir)
    latest = latest_by_candidate(chain).get(candidate_id)
    if latest is not None and latest.manifest.outcome == "confirm" and not latest.manifest.automated:
        if decision == "confirm":
            return {**_signed(run_dir, chain, latest), "already_signed": True, "feedback": None}
        raise ValueError("a person confirmed this finding; reversing it takes a release by a declared releaser")
    person = AnalystDecision(candidate_id=candidate_id, analyst_id=analyst_id, decision=decision,
                             decided_at=now, note=note.strip() or None, authority=ANALYST_AUTHORITY)
    pkg = _signer().package(case.candidate, case.verdict, person, chain_link(chain[-1] if chain else None), now,
                            policy_pack=policy_pack, attestation_hash=attestation_hash)
    records.append_receipts(run_dir, [pkg])
    chain.append(pkg)
    feedback = _record_label(root, case, decision, analyst_id, now) if decision != "escalate" else None
    return {**_signed(run_dir, chain, pkg), "feedback": feedback}


def release_api(root: Path, candidate_id: str, actor: str, reason: str, config: GovernanceConfig, *,
                now: Optional[datetime] = None, policy_pack: Optional[PolicyPackRef] = None,
                attestation_hash: Optional[str] = None) -> dict:
    """Reverse a confirm. Only a declared releaser may, and the reason is signed in."""
    actor = _actor(actor)
    if not (reason or "").strip():
        raise ValueError("a release needs a reason; it is recorded in the signed receipt")
    run_dir = _require_run(Path(root))
    case, chain, latest = _case_and_latest(run_dir, candidate_id)
    pkg = release(case.candidate, case.verdict, latest, _signer(), config, actor, reason.strip(), _now(now),
                  chain_link(chain[-1]), policy_pack=policy_pack, attestation_hash=attestation_hash)
    records.append_receipts(run_dir, [pkg])
    chain.append(pkg)
    return _signed(run_dir, chain, pkg)


# ---------------------------------------------------------------------------
# Governance and export
# ---------------------------------------------------------------------------


def set_queue(stop: bool, actor: str, reason: str, config: GovernanceConfig, *,
              journal: Optional[GovernanceJournal] = None, now: Optional[datetime] = None) -> dict:
    """Stop or resume the queue. Only people with declared stop authority may."""
    journal = journal or default_journal()
    record = (halt_queue if stop else resume_queue)(journal, config, _actor(actor), (reason or "").strip(),
                                                     _now(now)).record
    return {"ok": True, "kind": record.kind, "actor": record.actor, "created_at": _utc_z(record.created_at)}


def governance_state(root: Path, config: GovernanceConfig, config_source: str, *,
                     journal: Optional[GovernanceJournal] = None, now: Optional[datetime] = None) -> dict:
    """Settings, queue state and holds of the current run. Read-only.

    The queue is stopped when the journal's latest stop or resume record is a stop,
    as for the command line. A journal that cannot be read counts as stopped (runs
    and exports are refused then too); one that reads but does not verify is
    reported in journal_ok.
    """
    journal = journal or default_journal()
    now = _now(now)
    run_dir = current_run(Path(root))
    chain = records.read_receipts(run_dir) if run_dir else []
    unreadable = None
    try:
        events = [p.record for p in journal.packages() if p.record.kind in ("queue_halt", "queue_resume")]
    except ValueError as e:
        events, unreadable = [], str(e)
    journal_ok, journal_reason = journal.verify()
    last = events[-1] if events else None
    stopped = last is not None and last.kind == "queue_halt"
    if unreadable:
        halt_reason = f"the governance journal cannot be read: {unreadable}"
    else:
        halt_reason = (last.payload.get("reason") or None) if stopped else None
    return {
        "usable_default": config.usable_default,
        "ask_contact": config.ask_contact,
        "stop_statement": config.stop_statement,
        "stop_authority": list(config.stop_authority),
        "releasers": [f"{r.id} ({r.authority})" for r in config.releasers],
        "hold_sla_hours": config.hold_sla_hours,
        "halted": stopped or unreadable is not None,
        "halted_by": last.actor if stopped else None,
        "halt_reason": halt_reason,
        "open_holds": [p.manifest.candidate_id for p in open_holds(chain)],
        "overdue_holds": [p.manifest.candidate_id for p in overdue_holds(chain, now, config.hold_sla_hours)],
        "journal_ok": journal_ok,
        "journal_reason": journal_reason,
        "config_source": config_source,
        "run_id": run_dir.name if run_dir else None,
    }


def project_api(root: Path, candidate_id: str, kind: str = "all", *,
                journal: Optional[GovernanceJournal] = None) -> dict:
    """Report payloads projected from a confirmed finding's signed receipt.

    Nothing is sent. Refused while the queue is stopped and for any candidate
    whose latest receipt is not a confirm (a released confirm included).
    """
    from .projections import PROJECTIONS, project, project_all

    journal = journal or default_journal()
    if journal.is_halted():
        raise QueueStopped("the queue is stopped; nothing is exported until it is resumed")
    if kind != "all" and kind not in PROJECTIONS:
        raise ValueError(f"unknown projection {kind!r}; expected all or one of {', '.join(PROJECTIONS)}")
    run_dir = _require_run(Path(root))
    case, _, latest = _case_and_latest(run_dir, candidate_id)
    if latest.manifest.outcome != "confirm":
        raise ValueError(f"only a confirmed finding is exported; the latest receipt is {latest.manifest.outcome!r}")
    summary = json.loads((run_dir / RUN_SUMMARY).read_text(encoding="utf-8"))
    brand_name = next((b["name"] for b in summary["brands"] if b["id"] == case.candidate.brand_id), None)
    if kind == "all":
        out = project_all(case.candidate, case.verdict, latest, brand_name=brand_name)
    else:
        out = project(kind, case.candidate, case.verdict, latest, brand_name=brand_name)
    return {"projection": out, "receipt": receipt_view(latest)}


def asset_path(root: Path, sha256: str) -> Optional[Path]:
    """File of a stored asset of the current run, or None. `sha256` must be 64
    lower-case hex digits, so the result always stays inside the run directory."""
    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        raise ValueError("not a sha256 content address")
    run_dir = current_run(Path(root))
    if run_dir is None or not ContentStore(run_dir).exists(sha256):
        return None
    return run_dir / sha256


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _sample(root: Path) -> tuple[Optional[Path], Optional[EvidencePackage]]:
    run_dir = current_run(Path(root))
    if run_dir is None or not (run_dir / SAMPLE).exists():
        return run_dir, None
    return run_dir, EvidencePackage.model_validate_json((run_dir / SAMPLE).read_text(encoding="utf-8"))


def verify_sample(root: Path) -> dict:
    """Third-party check of the run's sample receipt: public key only, no secret."""
    run_dir, pkg = _sample(root)
    if pkg is None:
        return {"ok": False, "reason": "no sample receipt; run the pipeline first", "shared_secret_used": False}
    ok, reason = verify_package_public(pkg, ContentStore(run_dir), _public_key())
    return {"ok": ok, "reason": reason, "shared_secret_used": False, "pubkey": _public_key(),
            "candidate_id": pkg.manifest.candidate_id, "signed_at": _utc_z(pkg.manifest.created_at)}


def tamper_sample(root: Path) -> dict:
    """Verify the sample receipt against a copy of its assets with one byte added.
    The check must fail. The run's own store is never modified."""
    run_dir, pkg = _sample(root)
    if pkg is None:
        return {"detected": False, "reason": "no sample receipt; run the pipeline first"}
    if not pkg.manifest.asset_hashes:
        return {"detected": False, "reason": "the sample receipt binds no asset bytes"}
    store = ContentStore(run_dir)
    with tempfile.TemporaryDirectory() as tmp:
        copy = ContentStore(Path(tmp))
        for digest in pkg.manifest.asset_hashes:
            copy.tamper(digest, store.get_bytes(digest))  # same bytes under the same address
        first = pkg.manifest.asset_hashes[0]
        copy.tamper(first, store.get_bytes(first) + b"X")
        ok, reason = verify_package_public(pkg, copy, _public_key())
    return {"detected": not ok, "reason": reason}


# ---------------------------------------------------------------------------
# Calibration (review order only, never a signed decision)
# ---------------------------------------------------------------------------


def _labelled(root: Path) -> list[dict]:
    return [{"signals": rec.signals,
             "truth": rec.label in {"impersonation", "fraud"} and rec.decision == "confirm"}
            for rec in LabelLedger(Path(root) / LABELS).labels()]


def active_operating_point(root: Path) -> dict:
    """The applied, versioned operating point, else the default threshold."""
    p = Path(root) / OPERATING_POINT
    if p.exists():
        try:
            cfg = json.loads(p.read_text(encoding="utf-8"))
            return {"decision_threshold": float(cfg["decision_threshold"]),
                    "version_hash": cfg.get("version_hash"), "applied": True,
                    "n_labels": cfg.get("n_labels")}
        except (ValueError, KeyError, TypeError):
            pass
    return {"decision_threshold": _DEFAULT_THRESHOLD, "version_hash": None, "applied": False}


def apply_recalibration(root: Path, precision_target: float = 0.9) -> dict:
    """Recompute the operating point from the label ledger and keep it for later
    runs. Needs at least three labels."""
    labelled = _labelled(root)
    if len(labelled) < 3:
        return {"applied": False, "reason": f"need at least 3 labels, have {len(labelled)}"}
    cfg = recalibrate(labelled, precision_target=precision_target)
    out = {"decision_threshold": cfg["decision_threshold"], "version_hash": cfg["version_hash"],
           "n_labels": cfg["n_labels"], "achieved": cfg["achieved"],
           "met_target": cfg.get("met_target", False)}
    Path(root).mkdir(parents=True, exist_ok=True)
    (Path(root) / OPERATING_POINT).write_text(json.dumps(out, indent=1), encoding="utf-8")
    return {"applied": True, **out}


def feedback_summary(root: Path) -> dict:
    """Ledger statistics and integrity, the threshold the labels support, and the
    operating point in force."""
    ledger = LabelLedger(Path(root) / LABELS)
    labelled = _labelled(root)
    ok, reason = ledger.verify()
    return {"stats": ledger.stats(), "chain_ok": ok, "chain_reason": reason,
            "recalibration": recalibrate(labelled) if len(labelled) >= 3 else None,
            "operating_point": active_operating_point(root)}
