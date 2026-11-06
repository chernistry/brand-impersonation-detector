"""
Governance: who may release a confirm, who may stop the queue, and how long a
hold may stay open.

GovernanceConfig is declared configuration (see load_config and the bundled
example bid/fixtures/governance.json).
GovernanceJournal records the events that are not a decision on one candidate -
a queue halt or resume, a hold that aged past its SLA - signed the same way as
an evidence receipt: an HMAC chain for the internal journal and, when a DSSE
signer is given, an Ed25519/DSSE envelope a third party verifies with the
public key alone.

Rules enforced here:

  - A release reverses a confirm. It is done by a named person listed as a
    releaser, under the authority declared for them, and its receipt names the
    receipt it reverses (supersedes = manifest hash of the confirm).
  - Anyone with declared stop authority can halt or resume the queue. Every
    call is recorded with the reason given.
  - An open hold older than hold_sla_hours gets exactly one
    hold_sla_escalation record per hold receipt.

Time is always a parameter; nothing here reads a clock except the command line
(bid governance ...), which records the current UTC time unless --now is given.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import sys
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from pydantic import ValidationError

from . import decisions
from .evidence import DEFAULT_HMAC_KEY, Ed25519Dsse, _canonical, _hash, dsse_verify, manifest_hash
from .models import (
    AnalystDecision,
    Candidate,
    EvidencePackage,
    EvidenceSigner,
    GovernanceKind,
    GovernancePackage,
    GovernanceRecord,
    PolicyPackRef,
    Verdict,
)

GOVERNANCE_PAYLOAD_TYPE = "application/vnd.brand-impersonation-detector.governance+json"
STOP_AUTHORITY = "stop-authority"  # declared authority on queue halt and resume records
SLA_MONITOR_ACTOR = "bid-sla-monitor"  # actor on hold_sla_escalation records

_GENESIS = "0" * 64  # prev_record_hash of the first record in a journal


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _as_tuple(value: Any, name: str) -> tuple:
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    raise ValueError(f"{name} must be a list, got {type(value).__name__}")


@dataclass(frozen=True)
class Releaser:
    """A person who may release a confirm, and the authority they act under."""

    id: str
    authority: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("releaser id must be a non-empty string")
        if not isinstance(self.authority, str) or not self.authority.strip():
            raise ValueError(f"releaser {self.id!r} must declare a non-empty authority")


def _releaser_from(item: Any, index: int) -> Releaser:
    if isinstance(item, Releaser):
        return item
    if not isinstance(item, Mapping):
        raise ValueError(f"releasers[{index}] must be an object with id and authority")
    extra = sorted(set(map(str, item)) - {"id", "authority"})
    if extra:
        raise ValueError(f"releasers[{index}] has unknown key(s): {', '.join(extra)}")
    if "id" not in item or "authority" not in item:
        raise ValueError(f"releasers[{index}] needs both id and authority")
    try:
        return Releaser(id=item["id"], authority=item["authority"])
    except ValueError as e:
        raise ValueError(f"releasers[{index}]: {e}") from e


@dataclass(frozen=True)
class GovernanceConfig:
    """Declared governance settings. Invalid values raise ValueError."""

    # Guidance shown next to the decision controls.
    usable_default: str = "Not sure? Escalate. Escalating is the expected choice when in doubt."
    # Who to ask when a case is unclear; empty means not configured.
    ask_contact: str = ""
    # People who may release a confirm.
    releasers: tuple[Releaser, ...] = ()
    # Actor ids that may halt and resume the queue.
    stop_authority: tuple[str, ...] = ()
    stop_statement: str = (
        "Calling stop is part of the job and is never held against the person who calls it."
    )
    # How long an open hold may wait for a person before it is escalated.
    hold_sla_hours: float = 24.0

    def __post_init__(self) -> None:
        for name in ("usable_default", "ask_contact", "stop_statement"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        releasers = _as_tuple(self.releasers, "releasers")
        seen: set[str] = set()
        for r in releasers:
            if not isinstance(r, Releaser):
                raise ValueError(f"releasers must hold Releaser entries, got {type(r).__name__}")
            if r.id in seen:
                raise ValueError(f"duplicate releaser id {r.id!r}")
            seen.add(r.id)
        stoppers = _as_tuple(self.stop_authority, "stop_authority")
        for actor in stoppers:
            if not isinstance(actor, str) or not actor.strip():
                raise ValueError("stop_authority entries must be non-empty actor ids")
        sla = self.hold_sla_hours
        if isinstance(sla, bool) or not isinstance(sla, (int, float)) or not math.isfinite(sla) or sla <= 0:
            raise ValueError(f"hold_sla_hours must be a positive number, got {sla!r}")
        # Normalised in place; the dataclass is frozen, hence object.__setattr__.
        object.__setattr__(self, "releasers", releasers)
        object.__setattr__(self, "stop_authority", stoppers)
        object.__setattr__(self, "hold_sla_hours", float(sla))

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> GovernanceConfig:
        """Build from a parsed JSON object. Unknown keys are an error, so a
        misspelt setting fails loudly instead of falling back to its default."""
        if not isinstance(d, Mapping):
            raise ValueError("governance config must be a JSON object")
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(map(str, d)) - known)
        if unknown:
            raise ValueError(f"unknown governance config key(s): {', '.join(unknown)}")
        kwargs: dict[str, Any] = {
            k: d[k] for k in known if k in d and k not in ("releasers", "stop_authority")
        }
        if "releasers" in d:
            items = _as_tuple(d["releasers"], "releasers")
            kwargs["releasers"] = tuple(_releaser_from(item, i) for i, item in enumerate(items))
        if "stop_authority" in d:
            kwargs["stop_authority"] = _as_tuple(d["stop_authority"], "stop_authority")
        return cls(**kwargs)

    @classmethod
    def load(cls, path: str | Path) -> GovernanceConfig:
        """Read a JSON config file. A missing file raises FileNotFoundError; any
        invalid content raises ValueError naming the file."""
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"{p}: not valid JSON: {e}") from e
        try:
            return cls.from_dict(data)
        except ValueError as e:
            raise ValueError(f"{p}: {e}") from e

    def releaser(self, actor_id: str) -> Optional[Releaser]:
        for r in self.releasers:
            if r.id == actor_id:
                return r
        return None

    def may_stop(self, actor_id: str) -> bool:
        return bool(actor_id) and actor_id in self.stop_authority


EXAMPLE_CONFIG = Path(__file__).resolve().parent / "fixtures" / "governance.json"


def load_config(path: str | Path | None = None) -> tuple[GovernanceConfig, str]:
    """The deployment's governance settings and where they came from.

    `path` when given (it must exist); else $BID_DATA_DIR/governance.json; else
    the bundled example, whose people are placeholders. The command line and the
    console both read settings here, so they agree on who may stop the queue
    and who may release.
    """
    from . import paths

    if path is not None:
        return GovernanceConfig.load(path), str(path)
    deployed = paths.data_dir() / "governance.json"
    if deployed.exists():
        return GovernanceConfig.load(deployed), str(deployed)
    return (GovernanceConfig.load(EXAMPLE_CONFIG),
            f"bundled example with placeholder people; copy it to {deployed} and edit it")


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------


def record_hash(pkg: GovernancePackage) -> str:
    """sha256 of the canonical record: the link the next record carries, and the
    identity other records use to refer to this one."""
    return _hash(pkg.record)


def _record_hmac(key: str, record: GovernanceRecord, prev: str) -> str:
    body = _canonical(record) + prev.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


class GovernanceJournal:
    """Append-only JSONL journal of GovernancePackage lines.

    record_hmac = HMAC(key, canonical(record) || prev_record_hash), where
    prev_record_hash is the sha256 of the previous canonical record (64 zeros
    for the first one). With a DSSE signer, each record is also wrapped in an
    Ed25519/DSSE envelope; since the link sits inside the signed record, a third
    party with the public key alone detects a deleted or reordered record.

    Every read goes to the file, so verify() checks what is on disk now rather
    than a copy held in memory. append() does not lock the file: one writer at
    a time.
    """

    def __init__(
        self,
        path: str | Path,
        hmac_key: str = DEFAULT_HMAC_KEY,
        dsse: Ed25519Dsse | None = None,
    ):
        self.path = Path(path)
        self._key = hmac_key
        self._dsse = dsse

    def packages(self) -> list[GovernancePackage]:
        """All records in file order. An unreadable line raises ValueError."""
        if not self.path.exists():
            return []
        out: list[GovernancePackage] = []
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                out.append(GovernancePackage.model_validate_json(line))
            except ValidationError as e:
                first = e.errors()[0].get("msg", "invalid") if e.errors() else "invalid"
                raise ValueError(
                    f"{self.path} line {lineno}: not a governance package ({first})"
                ) from e
        return out

    def append(
        self,
        kind: GovernanceKind,
        actor: str,
        created_at: datetime,
        *,
        authority: Optional[str] = None,
        subject: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> GovernancePackage:
        """Sign one record, chain it to the last one on disk and append it."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("a governance record needs a named actor")
        existing = self.packages()
        prev = record_hash(existing[-1]) if existing else _GENESIS
        record = GovernanceRecord(
            kind=kind,
            actor=actor,
            authority=authority,
            subject=subject,
            payload=dict(payload or {}),
            prev_record_hash=prev,
            created_at=created_at,
        )
        mac = _record_hmac(self._key, record, prev)
        env = pub = None
        if self._dsse is not None:
            env = self._dsse.sign(_canonical(record), GOVERNANCE_PAYLOAD_TYPE)
            pub = self._dsse.public_key_hex()
        pkg = GovernancePackage(record=record, record_hmac=mac, dsse_envelope=env, ed25519_pubkey=pub)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(pkg.model_dump_json() + "\n")
        return pkg

    def verify(self) -> tuple[bool, str]:
        """Recompute the HMAC chain. Needs the journal's HMAC key."""
        try:
            pkgs = self.packages()
        except ValueError as e:
            return False, str(e)
        prev = _GENESIS
        for i, pkg in enumerate(pkgs):
            if pkg.record.prev_record_hash != prev:
                return False, f"chain break at record {i}: prev_record_hash mismatch"
            expected = _record_hmac(self._key, pkg.record, prev)
            if not hmac.compare_digest(expected, pkg.record_hmac):
                return False, f"record {i}: HMAC mismatch (record or chain link altered)"
            prev = record_hash(pkg)
        return True, f"governance journal of {len(pkgs)} record(s) verified"

    def verify_public(self, pubkey_hex: Optional[str] = None) -> tuple[bool, str]:
        """Check every DSSE signature and every chain link with a public key only.

        The key is pubkey_hex when given, else the public half of this journal's
        own DSSE signer, else the key embedded in the first record. In the last
        case the result shows the journal is consistent under one key, not who
        holds that key; pass pubkey_hex to pin it for a third-party check.
        """
        try:
            pkgs = self.packages()
        except ValueError as e:
            return False, str(e)
        expected_key = pubkey_hex or (self._dsse.public_key_hex() if self._dsse is not None else None)
        if expected_key is not None:
            expected_key = expected_key.lower()
        prev = _GENESIS
        for i, pkg in enumerate(pkgs):
            if pkg.record.prev_record_hash != prev:
                return False, f"chain break at record {i}: prev_record_hash mismatch"
            env, key = pkg.dsse_envelope, pkg.ed25519_pubkey
            if not env or not key:
                return False, f"record {i}: no DSSE envelope (nothing to verify without the HMAC key)"
            if expected_key is None:
                expected_key = key.lower()
            if key.lower() != expected_key:
                return False, f"record {i}: signed under a different public key"
            if env.get("payloadType") != GOVERNANCE_PAYLOAD_TYPE:
                return False, f"record {i}: unexpected DSSE payload type"
            ok, reason = dsse_verify(env, expected_key)
            if not ok:
                return False, f"record {i}: DSSE signature invalid: {reason}"
            if base64.b64decode(env["payload"]) != _canonical(pkg.record):
                return False, f"record {i}: signed payload does not match the record (tampered)"
            prev = record_hash(pkg)
        return True, f"governance journal of {len(pkgs)} record(s) verified with the public key only"

    def is_halted(self) -> bool:
        """True when the latest queue_halt / queue_resume record is a halt.

        Reads the records without verifying them; call verify() first where a
        tampered journal must not be trusted.
        """
        for pkg in reversed(self.packages()):
            if pkg.record.kind in ("queue_halt", "queue_resume"):
                return pkg.record.kind == "queue_halt"
        return False


# ---------------------------------------------------------------------------
# Queue stop
# ---------------------------------------------------------------------------


def _queue_event(
    kind: GovernanceKind,
    journal: GovernanceJournal,
    config: GovernanceConfig,
    actor: str,
    reason: str,
    now: datetime,
) -> GovernancePackage:
    if not config.may_stop(actor):
        raise PermissionError(f"{actor!r} has no declared stop authority")
    return journal.append(kind, actor, now, authority=STOP_AUTHORITY, payload={"reason": reason})


def halt_queue(
    journal: GovernanceJournal,
    config: GovernanceConfig,
    actor: str,
    reason: str,
    now: datetime,
) -> GovernancePackage:
    """Halt the queue. Anyone listed with stop authority may do it, at any time,
    and every call is recorded with the reason given."""
    return _queue_event("queue_halt", journal, config, actor, reason, now)


def resume_queue(
    journal: GovernanceJournal,
    config: GovernanceConfig,
    actor: str,
    reason: str,
    now: datetime,
) -> GovernancePackage:
    """Resume a halted queue. Same authority and recording as halt_queue."""
    return _queue_event("queue_resume", journal, config, actor, reason, now)


# ---------------------------------------------------------------------------
# Release
# ---------------------------------------------------------------------------


def release(
    candidate: Candidate,
    verdict: Verdict,
    released_pkg: EvidencePackage,
    signer: EvidenceSigner,
    config: GovernanceConfig,
    actor: str,
    reason: str,
    now: datetime,
    prev_manifest_hash: Optional[str],
    *,
    policy_pack: Optional[PolicyPackRef] = None,
    attestation_hash: Optional[str] = None,
) -> EvidencePackage:
    """Sign a release that reverses the confirm in released_pkg.

    Only a declared releaser may release, under the authority declared for
    them. The receipt names the reversed receipt by its manifest hash.
    """
    releaser = config.releaser(actor)
    if releaser is None:
        raise PermissionError(f"{actor!r} is not a declared releaser")
    m = released_pkg.manifest
    if m.outcome != "confirm":
        raise ValueError(f"only a confirm can be released; the receipt outcome is {m.outcome!r}")
    if m.candidate_id != candidate.id:
        raise ValueError(
            f"the receipt is for candidate {m.candidate_id!r}, not {candidate.id!r}"
        )
    decision = AnalystDecision(
        candidate_id=candidate.id,
        analyst_id=releaser.id,
        decision="release",
        decided_at=now,
        note=reason,
        authority=releaser.authority,
    )
    return signer.package(
        candidate,
        verdict,
        decision,
        prev_manifest_hash,
        now,
        policy_pack=policy_pack,
        attestation_hash=attestation_hash,
        supersedes=manifest_hash(released_pkg),
    )


def verify_release(release_pkg: EvidencePackage, released_pkg: EvidencePackage) -> tuple[bool, str]:
    """Check that release_pkg is a release of the confirm in released_pkg.

    Structural check only; signatures are checked by evidence.verify_chain or
    evidence.verify_package_public.
    """
    rel, old = release_pkg.manifest, released_pkg.manifest
    if rel.outcome != "release":
        return False, f"receipt outcome is {rel.outcome!r}, not release"
    if old.outcome != "confirm":
        return False, f"the reversed receipt is a {old.outcome!r}; only a confirm can be released"
    if rel.candidate_id != old.candidate_id:
        return False, "the release and the reversed receipt name different candidates"
    if rel.automated or not rel.decided_by:
        return False, "a release must be decided by a named person, not by the triage policy"
    if not rel.authority:
        return False, "the release declares no authority"
    expected = manifest_hash(released_pkg)
    if rel.supersedes != expected:
        return False, "supersedes does not name the reversed receipt"
    return True, f"release of confirm {expected[:16]} for candidate {rel.candidate_id}"


# ---------------------------------------------------------------------------
# Hold SLA
# ---------------------------------------------------------------------------


def _utc_z(dt: datetime) -> str:
    return decisions.as_utc(dt).isoformat().replace("+00:00", "Z")


def escalate_overdue(
    packages: Iterable[EvidencePackage],
    journal: GovernanceJournal,
    config: GovernanceConfig,
    now: datetime,
) -> list[GovernancePackage]:
    """Record one hold_sla_escalation per overdue hold receipt.

    The record's subject is the manifest hash of the hold, so calling this
    again records nothing new for the same hold. A later hold receipt for the
    same candidate is a new subject and is escalated on its own schedule.
    Returns the records appended by this call.
    """
    overdue = decisions.overdue_holds(packages, now, config.hold_sla_hours)
    if not overdue:
        return []
    done = {
        pkg.record.subject
        for pkg in journal.packages()
        if pkg.record.kind == "hold_sla_escalation"
    }
    appended: list[GovernancePackage] = []
    for hold in overdue:
        subject = manifest_hash(hold)
        if subject in done:
            continue
        m = hold.manifest
        appended.append(journal.append(
            "hold_sla_escalation",
            SLA_MONITOR_ACTOR,
            now,
            subject=subject,
            payload={
                "candidate_id": m.candidate_id,
                "outcome": m.outcome,
                "held_since": _utc_z(m.created_at),
                "sla_hours": config.hold_sla_hours,
            },
        ))
        done.add(subject)
    return appended


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _cli_now(value: Optional[str]) -> datetime:
    """--now when given (reproducible runs), else the current UTC time."""
    if value:
        return decisions.as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    return datetime.now(timezone.utc)


def main(argv: Optional[list[str]] = None) -> int:
    from . import paths, records

    def shared(parser: argparse.ArgumentParser, default) -> None:
        # Accepted before or after the subcommand; the subcommand copies use
        # SUPPRESS so they never overwrite a value given before it.
        parser.add_argument("--config", type=Path, default=default,
                            help="governance settings (default: $BID_DATA_DIR/governance.json, "
                                 "else the bundled example)")
        parser.add_argument("--journal", type=Path, default=default,
                            help="journal (default: $BID_DATA_DIR/governance.jsonl)")
        parser.add_argument("--run-dir", type=Path, default=default,
                            help="receipts and cases (default: $BID_DATA_DIR/pipeline)")
        parser.add_argument("--now", default=default, help="time to record, ISO 8601 (default: now, UTC)")

    ap = argparse.ArgumentParser(description="Queue stop, releases and hold deadlines")
    shared(ap, None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def command(name: str, text: str) -> argparse.ArgumentParser:
        s = sub.add_parser(name, help=text)
        shared(s, argparse.SUPPRESS)
        return s

    for name, text in (("halt", "halt the queue"), ("resume", "resume a halted queue")):
        s = command(name, text)
        s.add_argument("--actor", required=True)
        s.add_argument("--reason", default="")
    r = command("release", "reverse a confirm (declared releasers only)")
    r.add_argument("--candidate", required=True)
    r.add_argument("--actor", required=True)
    r.add_argument("--reason", required=True)
    command("escalate", "record holds that are past the review deadline")
    command("status", "queue state, open holds and overdue holds")
    v = command("verify", "verify the journal (HMAC key, then public key)")
    v.add_argument("--pubkey", help="pin the Ed25519 public key (hex) for the public check")
    args = ap.parse_args(argv)

    config, config_source = load_config(args.config)
    journal = GovernanceJournal(args.journal or paths.data_dir() / "governance.jsonl",
                                dsse=Ed25519Dsse())
    run_dir = args.run_dir or paths.store_dir("pipeline")
    now = _cli_now(args.now)

    try:
        if args.cmd in ("halt", "resume"):
            fn = halt_queue if args.cmd == "halt" else resume_queue
            pkg = fn(journal, config, args.actor, args.reason, now)
            print(f"{pkg.record.kind} recorded by {args.actor} at {_utc_z(now)}")
            return 0
        if args.cmd == "release":
            from .evidence import HmacEvidenceSigner, chain_link
            chain = records.read_receipts(run_dir)
            latest = decisions.latest_by_candidate(chain).get(args.candidate)
            case = records.read_cases(run_dir).get(args.candidate)
            if latest is None or case is None:
                print(f"no receipt or case for {args.candidate!r} in {run_dir}", file=sys.stderr)
                return 2
            pkg = release(case.candidate, case.verdict, latest, HmacEvidenceSigner(dsse=Ed25519Dsse()),
                          config, args.actor, args.reason, now, chain_link(chain[-1]))
            records.append_receipts(run_dir, [pkg])
            print(f"release of {args.candidate} signed by {args.actor}; supersedes {pkg.manifest.supersedes[:16]}")
            return 0
        if args.cmd == "escalate":
            added = escalate_overdue(records.read_receipts(run_dir), journal, config, now)
            print(f"{len(added)} hold(s) escalated")
            return 0
        if args.cmd == "status":
            chain = records.read_receipts(run_dir)
            overdue = decisions.overdue_holds(chain, now, config.hold_sla_hours)
            print(json.dumps({
                "halted": journal.is_halted(),
                "open_holds": [p.manifest.candidate_id for p in decisions.open_holds(chain)],
                "overdue_holds": [p.manifest.candidate_id for p in overdue],
                "hold_sla_hours": config.hold_sla_hours,
                "stop_authority": list(config.stop_authority),
                "releasers": [r.id for r in config.releasers],
                "settings_from": config_source,
            }, indent=2))
            return 0
        ok, reason = journal.verify()
        pub_ok, pub_reason = journal.verify_public(args.pubkey)
        print(f"hmac:   {reason}\npublic: {pub_reason}")
        return 0 if ok and pub_ok else 1
    except (PermissionError, ValueError) as e:
        print(f"bid governance {args.cmd}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
