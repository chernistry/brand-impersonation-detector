"""
STIX 2.1 export - the signed evidence package, projected into a format that
threat-intelligence platforms can ingest.

Design: the bundle is a deterministic
projection of the signed evidence package, not a fresh document. Every STIX id is
derived by uuid5 from the manifest hash + content, and every timestamp is the
manifest's own signed `created_at` converted to UTC - so two exports of the same
signed decision are byte-identical on any machine, and the bundle is anchored to
the HMAC/Ed25519 receipt via an external reference carrying the manifest_hmac,
the SHA-256 manifest hash and the policy_version. Without the receipt the bundle
has no anchor; the exported record is only as trustworthy as the signed decision
it projects.

Correlation: an optional campaign graph (from enrich.pivot on the
suspect's own link domain - sibling certs, shared-IP infra, OpenPhish hits) is
projected as an Infrastructure SDO + relationships, linking the social
impersonation to the phishing infrastructure behind it. That enrichment is a
best-effort, keyless, network sidecar - NOT part of the signed deterministic core.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .evidence import manifest_hash
from .models import Candidate, EvidencePackage, Verdict

# Fixed namespace so every STIX id is a deterministic function of its content.
_NS = uuid.UUID("3f1c2a7e-5b9d-4e48-9a63-0c7d21b8e5a4")

_LABEL_TO_STIX = {
    "fraud": ["fraudulent-site", "impersonation"],
    "impersonation": ["impersonation"],
    "suspicious": ["anomalous-activity"],
}


def _id(kind: str, *parts: str) -> str:
    seed = "|".join(parts)
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + seed)}"


def as_utc(dt: datetime) -> datetime:
    """The same instant in UTC. A naive datetime is taken to be UTC already."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ts(dt: datetime) -> str:
    # STIX 2.1 timestamps are RFC 3339 in UTC with a trailing Z, and created and
    # modified are precise to the millisecond. The value is the manifest's SIGNED
    # created_at (no wall clock) converted to UTC, so the output does not depend on
    # the local time zone of the machine that runs the export.
    return as_utc(dt).replace(tzinfo=None).isoformat(timespec="milliseconds") + "Z"


def _pattern_str(value: str) -> str:
    """A quoted STIX pattern string literal: backslash and single quote escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def to_stix_bundle(candidate: Candidate, verdict: Verdict, pkg: EvidencePackage,
                   campaign_edges: list | None = None) -> dict:
    """Project one signed decision into a STIX 2.1 bundle. Deterministic."""
    m = pkg.manifest
    ts = _ts(m.created_at)
    objs: list[dict] = []

    identity_id = _id("identity", "brand-impersonation-detector")
    objs.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": ts, "modified": ts, "name": "brand-impersonation-detector", "identity_class": "organization",
    })

    # The impersonation indicator: a STIX pattern over the suspect handle/domain.
    # Values come from untrusted candidate data, so they are escaped as STIX
    # pattern string literals (a quote in a handle must not end the literal).
    observable = candidate.link_in_bio_url or candidate.handle or candidate.platform_uid
    if (candidate.link_in_bio_url or "").startswith("http"):
        pattern = f"[url:value = {_pattern_str(candidate.link_in_bio_url)}]"
    else:
        pattern = f"[user-account:account_login = {_pattern_str(candidate.handle or candidate.platform_uid)}]"
    indicator_id = _id("indicator", m.candidate_id, m.verdict_hash)
    objs.append({
        "type": "indicator", "spec_version": "2.1", "id": indicator_id,
        "created": ts, "modified": ts, "created_by_ref": identity_id,
        "name": f"{verdict.label} impersonation of {m.brand_id}: {candidate.handle or observable}",
        "description": verdict.reasoning,
        "indicator_types": _LABEL_TO_STIX.get(verdict.label, ["anomalous-activity"]),
        "pattern": pattern, "pattern_type": "stix",
        "valid_from": ts, "confidence": int(round(verdict.confidence * 100)),
        # anchor back to the signed, offline-verifiable receipt:
        "external_references": [{
            "source_name": "bid-evidence",
            "external_id": pkg.manifest_hmac,
            "description": f"policy_version={m.policy_version}; ed25519_pubkey={(pkg.ed25519_pubkey or '')[:32]}",
            "hashes": {"SHA-256": manifest_hash(pkg)},
        }],
        "labels": [f"platform:{candidate.platform}", f"brand:{m.brand_id}"],
    })

    # Optional: the phishing infrastructure behind the social lure (holistic link).
    edges = campaign_edges or []
    if edges:
        infra_id = _id("infrastructure", m.candidate_id, "campaign")
        siblings = sorted({str(e[2]) for e in edges if len(e) >= 3})[:12]
        objs.append({
            "type": "infrastructure", "spec_version": "2.1", "id": infra_id,
            "created": ts, "modified": ts, "created_by_ref": identity_id,
            "name": f"campaign infrastructure correlated to {candidate.handle or observable}",
            "infrastructure_types": ["phishing"],
            "description": "keyless OSINT correlation (crt.sh / DoH / urlscan / RDAP / ASN / OpenPhish); best-effort sidecar, not signed",
            "labels": [f"edge:{s}" for s in siblings],
        })
        objs.append({
            "type": "relationship", "spec_version": "2.1",
            "id": _id("relationship", indicator_id, infra_id),
            "created": ts, "modified": ts,
            "relationship_type": "indicates",
            "source_ref": indicator_id, "target_ref": infra_id,
        })

    return {"type": "bundle", "id": _id("bundle", m.candidate_id, pkg.manifest_hmac), "objects": objs}
