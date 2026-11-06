"""
Deployment profiles, and an attestation of the settings actually in effect.

A profile (bid/profiles/<name>.json) declares four controls:

  egress          per-component host allowlist that bid.net enforces on every
                  outbound HTTP request, redirects included (null = unrestricted)
  redact_pii      strip PII from scraped text before any hosted model call
  zero_retention  request zero-data-retention routing from the hosted model API
  llm_base_url    model endpoint (null = BID_LLM_BASE_URL, else OpenRouter)

plus allow_timestamp_anchor (whether the RFC-3161 timestamp request may leave the
host) and free-text notes. The "default" profile reproduces the historical
behaviour exactly.

apply() puts a profile into effect for the process. effective_settings() reads the
settings back from runtime state (the active egress policy, the bid.classify
settings, BID_LLM_BASE_URL), not from the profile file, and attestation_payload()
binds them to the profile hash, the package version and the dependency versions.
put_in_force() does all three for a caller: apply, record the payload in the
governance journal as kind "deployment_attestation", return its hash.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from importlib import metadata
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import anchor, classify, net

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
ATTESTATION_SCHEMA = "bid.deployment_attestation/v1"
PACKAGE = "brand-impersonation-detector"
KEY_DEPENDENCIES = (
    "pydantic", "httpx", "cryptography", "Pillow", "imagehash", "numpy",
    "tldextract", "confusable_homoglyphs", "rapidfuzz", "dnstwist",
)
# The timestamp authorities anchor.timestamp() contacts.
_TSA_URLS = (anchor.FREETSA, anchor.SIGSTORE_TSA)
# A bare profile name (no path separator, no extension) selects a bundled profile.
_BUNDLED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


def _canonical(obj) -> bytes:
    """Canonical JSON bytes, in the same form evidence.py signs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(obj) -> str:
    return hashlib.sha256(_canonical(obj)).hexdigest()


class DeploymentProfile(BaseModel):
    """A declared deployment profile. Unknown keys and loosely typed values are
    rejected, so a misspelt control cannot silently fall back to a default."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1)
    egress: dict[str, list[str]] | None
    redact_pii: bool
    zero_retention: bool
    llm_base_url: str | None
    allow_timestamp_anchor: bool
    notes: str = ""

    def egress_policy(self) -> net.EgressPolicy:
        if self.egress is None:
            return net.EgressPolicy(None)
        return net.EgressPolicy({component: tuple(hosts) for component, hosts in self.egress.items()})

    @model_validator(mode="after")
    def _check_consistency(self) -> "DeploymentProfile":
        policy = self.egress_policy()  # rejects malformed host patterns
        if self.llm_base_url is not None:
            parts = urlsplit(self.llm_base_url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError("llm_base_url must be an http or https URL with a host")
            if not policy.allows("classifier", self.llm_base_url):
                raise ValueError("the egress map does not let component 'classifier' reach llm_base_url")
        if not self.allow_timestamp_anchor and (self.egress is None or self.egress.get("anchor")):
            raise ValueError(
                "allow_timestamp_anchor is false, so the egress map must give component "
                "'anchor' an empty list (or omit it)"
            )
        return self

    def sha256(self) -> str:
        """SHA-256 of the canonical JSON of the profile (defaults included)."""
        return _sha256(self.model_dump(mode="json"))


def load_profile(name_or_path: str | os.PathLike) -> DeploymentProfile:
    """Load a bundled profile by name (bid/profiles/<name>.json) or a profile file by path."""
    if isinstance(name_or_path, str) and _BUNDLED_NAME.fullmatch(name_or_path):
        path = PROFILE_DIR / f"{name_or_path}.json"
        if not path.is_file():
            bundled = sorted(p.stem for p in PROFILE_DIR.glob("*.json"))
            raise FileNotFoundError(
                f"no bundled profile {name_or_path!r} (bundled: {', '.join(bundled)}); "
                "pass a file path to load another profile"
            )
    else:
        path = Path(name_or_path)
    return DeploymentProfile.model_validate_json(path.read_text(encoding="utf-8"))


def apply(profile: DeploymentProfile) -> None:
    """Put `profile` into effect for this process: activate its egress policy and set
    the model-call settings in bid.classify."""
    # Build everything first, so a failure cannot leave a half-applied profile.
    policy = profile.egress_policy()
    base_url = classify.resolve_base_url(profile.llm_base_url)
    net.activate(policy)
    classify.redact_pii = profile.redact_pii
    classify.zero_retention = profile.zero_retention
    classify.base_url = base_url


def _public_url(url: str | None) -> str | None:
    """URL without user info, query or fragment: the attestation is a shareable
    record and must not carry credentials embedded in a configured URL."""
    if not url:
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:  # malformed port: report the URL without it
        port = None
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _describe(policy: net.EgressPolicy, base_url: str, redact_pii: bool, zero_retention: bool) -> dict:
    """Settings description shared by the runtime read-back and the profile expectation."""
    return {
        "egress": policy.describe(),
        "classifier": {
            "base_url": _public_url(base_url),
            "egress_allowed": policy.allows("classifier", base_url),
            "redact_pii": redact_pii,
            "zero_retention": zero_retention,
            # True when model requests carry OpenRouter's zero-data-retention routing
            # fields; a self-hosted endpoint gets none (its operator controls retention).
            "zdr_routing": bool(zero_retention and classify.is_openrouter_url(base_url)),
        },
        "timestamp_anchor": {
            "egress_allowed": any(policy.allows("anchor", u) for u in _TSA_URLS),
        },
    }


def effective_settings() -> dict:
    """Settings in effect, read from the running process rather than from any file."""
    settings = _describe(net.active(), classify.base_url, classify.redact_pii, classify.zero_retention)
    settings["env"] = {"BID_LLM_BASE_URL": _public_url(os.environ.get("BID_LLM_BASE_URL"))}
    return settings


def package_version() -> str:
    try:
        return metadata.version(PACKAGE)
    except metadata.PackageNotFoundError:
        return "0+unknown"


def dependency_versions() -> dict[str, str | None]:
    """Installed versions of the key dependencies, sorted by name (None = not installed)."""
    versions: dict[str, str | None] = {}
    for name in sorted(KEY_DEPENDENCIES):
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def put_in_force(profile: DeploymentProfile, deployment_id: str, journal, now) -> str:
    """apply() `profile`, record its attestation in the governance journal (kind
    "deployment_attestation") and return the attestation hash every receipt
    signed under it carries. `journal` is a governance.GovernanceJournal."""
    from .evidence import _hash

    apply(profile)
    payload = attestation_payload(profile, deployment_id)
    journal.append("deployment_attestation", deployment_id, now,
                   authority="deployment", subject=deployment_id, payload=payload)
    return _hash(payload)


def attestation_payload(profile: DeploymentProfile, deployment_id: str) -> dict:
    """Attestation of the deployment as it runs now. Deterministic for the same state.

    profile_in_effect is true only when the runtime settings equal the settings that
    applying `profile` would produce, so naming a profile that was not applied (or
    that was changed after apply()) shows up as false rather than as a claim.
    """
    effective = effective_settings()
    expected = _describe(
        profile.egress_policy(),
        classify.resolve_base_url(profile.llm_base_url),
        profile.redact_pii,
        profile.zero_retention,
    )
    runtime = {key: value for key, value in effective.items() if key != "env"}
    deps = dependency_versions()
    return {
        "schema": ATTESTATION_SCHEMA,
        "deployment_id": deployment_id,
        "profile_name": profile.name,
        "profile_sha256": profile.sha256(),
        "profile_in_effect": runtime == expected,
        "effective_settings": effective,
        "package_version": package_version(),
        "python_version": platform.python_version(),
        "dependency_versions": deps,
        "dependency_versions_sha256": _sha256(deps),
    }
