"""
Report projections of one signed evidence receipt.

A confirmed finding is filed in several places: a threat-intelligence platform
(STIX 2.1), a platform's intellectual-property report form, a registrar abuse
desk, a fraud-operations desk and the internal findings log. Each projection is a
pure function of the signed receipt (EvidencePackage) and the candidate and
verdict it was signed over:

- no wall clock: every timestamp is a signed or observed value, rendered in UTC;
- no network and no randomness;
- two runs over the same receipt give byte-identical canonical_bytes().

Every projection except "stix" carries the manifest hash, the manifest HMAC and
the policy version, so a filed report can be matched back to its receipt and the
receipt checked offline (see verify_receipt.py). The STIX bundle carries the same
anchor in its indicator's external reference.

Nothing here submits anything. A projection is a payload that an operator reviews
and files; any statement a recipient requires from the notifier (for example a
good-faith statement) is the operator's to make, not this tool's.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .domains import registrable
from .evidence import _hash, context_hash, manifest_hash
from .models import Candidate, DetSignals, EvidencePackage, Verdict
from .stix_export import as_utc, to_stix_bundle

PROJECTIONS: tuple[str, ...] = ("stix", "platform_ip_report", "registrar_abuse", "fraud_desk", "finding")

# Sensors whose platform_uid is itself a domain name.
_DOMAIN_PLATFORMS = frozenset({"dns_typosquat", "ct_log"})

# Short review steps for a fraud desk, chosen by verdict label.
_CHECKLISTS: dict[str, tuple[str, ...]] = {
    "fraud": (
        "Check the listed URLs for payment, credential or personal-data collection",
        "Search customer reports and transactions for the listed indicators",
        "Decide whether to block the listed domains and URLs in customer channels",
    ),
    "impersonation": (
        "Confirm the account is not run by the brand or an authorized partner",
        "Search customer reports for contact from the listed handles",
        "Watch the listed domains and URLs for payment or credential collection",
    ),
}
_DEFAULT_CHECKLIST: tuple[str, ...] = (
    "Re-check the classification against the signed receipt before acting",
    "Search customer reports for the listed indicators",
)

# Unicode categories shown as escapes in the plain-text report: control, format
# (invisible) and line/paragraph separator characters.
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


class NotApplicable(ValueError):
    """The projection does not fit this finding, for example a registrar abuse
    report for a finding that has no domain."""


def canonical_bytes(obj) -> bytes:
    """Deterministic serialization of a projection: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Shared pieces
# ---------------------------------------------------------------------------


def _check_receipt(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage) -> None:
    m = pkg.manifest
    if m.outcome != "confirm":
        raise ValueError("only confirmed findings are projected")
    if candidate.id != m.candidate_id or verdict.candidate_id != m.candidate_id:
        raise ValueError("candidate, verdict and receipt must refer to the same candidate")
    # The report must describe exactly what was signed, not an edited copy.
    if _hash(verdict) != m.verdict_hash:
        raise ValueError("verdict does not match the one the receipt was signed over")
    if m.context_hash and context_hash(candidate, verdict) != m.context_hash:
        raise ValueError("candidate does not match the one the receipt was signed over")


def _utc_seconds(dt: datetime) -> str:
    """YYYY-MM-DDTHH:MM:SSZ in UTC. A naive datetime is taken to be UTC."""
    return as_utc(dt).replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def _header(kind: str, pkg: EvidencePackage) -> dict:
    """The receipt anchor carried by every projection except "stix"."""
    m = pkg.manifest
    return {
        "schema": f"bid.projection.{kind}/v1",
        "manifest_hash": manifest_hash(pkg),
        "manifest_hmac": pkg.manifest_hmac,
        "policy_version": m.policy_version,
        "brand_id": m.brand_id,
        "decided_at": _utc_seconds(m.created_at),
        "evidence": {
            "asset_hashes": list(m.asset_hashes),
            "context_hash": m.context_hash,
            "ed25519_pubkey": pkg.ed25519_pubkey,
        },
    }


def _clean_host(value: str | None) -> str | None:
    """A lowercase DNS name, or None for an empty value or an IP address."""
    host = (value or "").strip().strip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None  # an IP address has no registrar


def _link_host(candidate: Candidate) -> str | None:
    """Host name of the candidate's link, when it is a DNS name."""
    url = (candidate.link_in_bio_url or "").strip()
    if not url:
        return None
    try:
        host = urlsplit(url if "://" in url else "//" + url).hostname
    except ValueError:  # malformed URL, for example an unbalanced IPv6 bracket
        return None
    return _clean_host(host)


def _uid_domain(candidate: Candidate) -> str | None:
    """platform_uid, when the sensor that found the candidate reports domains."""
    if candidate.platform in _DOMAIN_PLATFORMS:
        return _clean_host(candidate.platform_uid)
    return None


def _link_is_official(verdict: Verdict) -> bool:
    # A link to an official brand domain is the brand's own property: it is never
    # listed as a suspect indicator or reported to a registrar.
    return verdict.signals.domain_is_legit is True


def _suspect_urls(candidate: Candidate, verdict: Verdict) -> list[str]:
    if not candidate.link_in_bio_url or _link_is_official(verdict):
        return []
    return [candidate.link_in_bio_url]


def _signal_phrases(s: DetSignals) -> list[str]:
    """Readable phrases for the non-null signals, in a fixed order."""
    out: list[str] = []
    if s.handle_similarity is not None:
        out.append(f"handle similarity {s.handle_similarity:.2f} to an official handle")
    if s.logo_phash_hamming is not None:
        unit = "bit" if s.logo_phash_hamming == 1 else "bits"
        out.append(f"logo pHash distance {s.logo_phash_hamming} {unit} from an official logo")
    if s.alias_in_text is not None:
        out.append("brand name or alias in the account text" if s.alias_in_text
                   else "no brand name or alias in the account text")
    if s.domain_intention_mismatch is not None:
        out.append("linked domain is not an official brand domain" if s.domain_intention_mismatch
                   else "no official-domain mismatch")
    if s.domain_in_cti_badlist is not None:
        out.append("linked domain is on a known-bad domain list" if s.domain_in_cti_badlist
                   else "linked domain is not on a known-bad domain list")
    return out


def _description(candidate: Candidate, verdict: Verdict, brand: str) -> str:
    subject = candidate.handle or candidate.platform_uid
    head = (f"The reported content {subject} on {candidate.platform} was classified as "
            f"{verdict.label} for the brand {brand}")
    phrases = _signal_phrases(verdict.signals)
    if not phrases:
        return head + "; no deterministic signals were recorded."
    return head + "; signals: " + ", ".join(phrases) + "."


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def _stix(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
          brand_name: str | None, campaign_edges: list | None) -> dict:
    return to_stix_bundle(candidate, verdict, pkg, campaign_edges)


def _platform_ip_report(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
                        brand_name: str | None, campaign_edges: list | None) -> dict:
    report = _header("platform_ip_report", pkg)
    report.update({
        "report_type": "trademark_impersonation",
        "rights_owner": {"brand_id": pkg.manifest.brand_id, "brand_name": brand_name},
        "reported_content": {
            "platform": candidate.platform,
            "platform_uid": candidate.platform_uid,
            "handle": candidate.handle,
            "display_name": candidate.display_name,
            "url": candidate.link_in_bio_url,
        },
        "description": _description(candidate, verdict, brand_name or pkg.manifest.brand_id),
        # Any good-faith or accuracy statement the platform asks for is made by
        # the operator who files the report, never by this tool.
        "notifier_statement_required": True,
    })
    return report


def _registrar_domain(candidate: Candidate, verdict: Verdict) -> str:
    host = _link_host(candidate)
    if host is not None:
        if _link_is_official(verdict):
            raise NotApplicable("linked domain is an official brand domain")
        return host
    uid = _uid_domain(candidate)
    if uid is not None:
        return uid
    raise NotApplicable("no domain")


def _registrar_abuse(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
                     brand_name: str | None, campaign_edges: list | None) -> dict:
    domain = _registrar_domain(candidate, verdict)
    report = _header("registrar_abuse", pkg)
    report.update({
        "domain": domain,
        "registrable_domain": registrable(domain),
        "abuse_type": "phishing" if verdict.label == "fraud" else "brand_impersonation",
        "evidence_urls": _suspect_urls(candidate, verdict),
        "first_seen": _utc_seconds(candidate.first_seen),
    })
    report["text"] = render_registrar_abuse_text(report)
    return report


def _fraud_desk(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
                brand_name: str | None, campaign_edges: list | None) -> dict:
    report = _header("fraud_desk", pkg)
    link_host = None if _link_is_official(verdict) else _link_host(candidate)
    report.update({
        "case_id": "bid-" + report["manifest_hash"][:16],
        "channel": candidate.platform,
        "label": verdict.label,
        "confidence": verdict.confidence,
        "indicators": {
            "handles": sorted({candidate.handle} if candidate.handle else set()),
            "domains": sorted({d for d in (link_host, _uid_domain(candidate)) if d}),
            "urls": sorted(set(_suspect_urls(candidate, verdict))),
        },
        "signals": verdict.signals.model_dump(exclude_none=True),
        "review_checklist": list(_CHECKLISTS.get(verdict.label, _DEFAULT_CHECKLIST)),
    })
    return report


def _finding(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
             brand_name: str | None, campaign_edges: list | None) -> dict:
    report = _header("finding", pkg)
    report.update({
        "finding_id": "bid-" + report["manifest_hash"][:16],
        "platform": candidate.platform,
        "subject": candidate.handle or candidate.platform_uid,
        "label": verdict.label,
        "confidence": verdict.confidence,
        "reasoning": verdict.reasoning,
        "model_trace": [t.model_dump() for t in pkg.manifest.model_trace],
        "outcome": pkg.manifest.outcome,
    })
    return report


_BUILDERS = {
    "stix": _stix,
    "platform_ip_report": _platform_ip_report,
    "registrar_abuse": _registrar_abuse,
    "fraud_desk": _fraud_desk,
    "finding": _finding,
}


def project(kind: str, candidate: Candidate, verdict: Verdict, pkg: EvidencePackage, *,
            brand_name: str | None = None, campaign_edges: list | None = None) -> dict:
    """Project one confirmed, signed finding into the report format `kind`.

    Raises ValueError for an unknown kind, for a receipt whose outcome is not
    "confirm", and for a candidate or verdict other than the one the receipt was
    signed for. Raises NotApplicable (a ValueError) when the format does not fit
    the finding. campaign_edges is an unsigned sidecar used by "stix" only.
    """
    builder = _BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"unknown projection {kind!r}; expected one of: {', '.join(PROJECTIONS)}")
    _check_receipt(candidate, verdict, pkg)
    return builder(candidate, verdict, pkg, brand_name, campaign_edges)


def project_all(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage, *,
                brand_name: str | None = None, campaign_edges: list | None = None) -> dict:
    """Every projection of one confirmed finding, plus the reason each format
    that does not fit was skipped. Both mappings have sorted keys."""
    _check_receipt(candidate, verdict, pkg)
    projections: dict[str, dict] = {}
    not_applicable: dict[str, str] = {}
    for kind in sorted(PROJECTIONS):
        try:
            projections[kind] = project(kind, candidate, verdict, pkg,
                                        brand_name=brand_name, campaign_edges=campaign_edges)
        except NotApplicable as exc:
            not_applicable[kind] = str(exc)
    return {"projections": projections, "not_applicable": not_applicable}


# ---------------------------------------------------------------------------
# Registrar abuse e-mail body
# ---------------------------------------------------------------------------


def _inline(value, missing: str = "not recorded") -> str:
    """One line of text. Control, invisible-format and line-separator characters
    are shown as escapes, so observed data cannot add lines to the message or
    hide characters in it."""
    if value is None or value == "":
        return missing
    out = []
    for ch in str(value):
        if unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out)


def render_registrar_abuse_text(report: dict) -> str:
    """Plain-text e-mail body for a registrar abuse desk, built only from `report`.

    No markdown and no wall clock: the same report always renders the same text.
    The "text" key itself is not read. The sender, the signature and any statement
    the recipient requires are added by the operator who files the report.
    """
    evidence = report.get("evidence") or {}
    abuse = _inline(str(report.get("abuse_type") or "").replace("_", " "))
    urls = report.get("evidence_urls") or []
    assets = evidence.get("asset_hashes") or []

    lines = [
        f"This report concerns {abuse} on the domain {_inline(report.get('domain'))}.",
        "",
        f"Domain: {_inline(report.get('domain'))}",
        f"Registrable domain: {_inline(report.get('registrable_domain'))}",
        f"Abuse type: {abuse}",
        f"Brand: {_inline(report.get('brand_id'))}",
        f"First seen: {_inline(report.get('first_seen'))}",
        f"Decided at: {_inline(report.get('decided_at'))}",
        "",
        "Evidence URLs:" if urls else "Evidence URLs: none recorded",
    ]
    lines += [f"  {_inline(u)}" for u in urls]
    lines += [
        "",
        "The finding was confirmed and recorded in a signed evidence receipt:",
        f"  Manifest hash (SHA-256): {_inline(report.get('manifest_hash'))}",
        f"  Manifest HMAC: {_inline(report.get('manifest_hmac'))}",
        f"  Policy version: {_inline(report.get('policy_version'))}",
        f"  Ed25519 public key: {_inline(evidence.get('ed25519_pubkey'))}",
        f"  Context hash: {_inline(evidence.get('context_hash'))}",
        "  Asset hashes:" if assets else "  Asset hashes: none",
    ]
    lines += [f"    {_inline(a)}" for a in assets]
    lines += [
        "",
        "Please review the domain under your abuse policy.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    from . import paths, records
    from .decisions import latest_by_candidate

    ap = argparse.ArgumentParser(description="Project a confirmed finding into report formats")
    ap.add_argument("candidate", help="candidate id")
    ap.add_argument("--kind", choices=(*PROJECTIONS, "all"), default="all")
    ap.add_argument("--run-dir", type=Path, help="receipts and cases (default: $BID_DATA_DIR/pipeline)")
    ap.add_argument("--journal", type=Path, help="governance journal (default: $BID_DATA_DIR/governance.jsonl)")
    ap.add_argument("--brand-name", help="brand name to put in the reports")
    ap.add_argument("--text", action="store_true", help="print the registrar abuse e-mail body only")
    args = ap.parse_args(argv)

    from .governance import GovernanceJournal
    if GovernanceJournal(args.journal or paths.data_dir() / "governance.jsonl").is_halted():
        print("bid project: the queue is halted; nothing is projected until it is resumed", file=sys.stderr)
        return 3
    run_dir = args.run_dir or paths.store_dir("pipeline")
    latest = latest_by_candidate(records.read_receipts(run_dir)).get(args.candidate)
    case = records.read_cases(run_dir).get(args.candidate)
    if latest is None or case is None:
        print(f"bid project: no receipt or case for {args.candidate!r} in {run_dir}", file=sys.stderr)
        return 2
    try:
        kind = "registrar_abuse" if args.text else args.kind
        if kind == "all":
            out = project_all(case.candidate, case.verdict, latest, brand_name=args.brand_name)
        else:
            out = project(kind, case.candidate, case.verdict, latest, brand_name=args.brand_name)
    except ValueError as e:  # includes NotApplicable
        print(f"bid project: {e}", file=sys.stderr)
        return 2
    print(out["text"] if args.text else json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
