"""
Canonical pipeline contracts.

These are the fixed seams. Sensors are swappable, the pipeline shape is fixed,
the evidence receipt is verifiable offline.

Nothing here depends on how an observation was obtained. Any Sensor emits the
same RawObservation, so everything downstream is identical whether a Candidate
came from a public search, an ad-library query, or another source.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterator, Literal, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Sensor seam
# ---------------------------------------------------------------------------


class RawObservation(BaseModel):
    """Whatever a source gave us, verbatim. Sensors observe, they do NOT judge."""

    sensor_name: str
    observed_at: datetime
    platform: str  # "app_store" | "meta_ads" | "local_search" | ...
    platform_uid: str  # bundleId, ad id, profile id - stable per platform
    payload: dict  # raw source blob, kept as-is for lineage
    asset_urls: list[str] = Field(default_factory=list)  # icons / creatives to fetch


class Brand(BaseModel):
    id: str
    name: str
    official_handles: list[str]
    official_logo_hashes: list[str]  # pHash of known-good logos (see filters.py)
    regions: list[str]
    cti_brand_ref: Optional[str] = None
    # Brand knowledge (keyless, from Wikidata via brand_kb.py).
    # Aliases = alternate names -> textual brand intention (logo-less impersonation).
    # official_domains = brand-intention invariant: presents as the brand but domain is not official.
    aliases: list[str] = Field(default_factory=list)
    official_domains: list[str] = Field(default_factory=list)
    official_logo_clip: list = Field(default_factory=list)  # CLIP vectors (embeddings mode)


@runtime_checkable
class Sensor(Protocol):
    """The sensor seam: every observation source implements this Protocol."""

    def name(self) -> str: ...

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]: ...

    def health(self) -> dict: ...  # last_scan, error_rate, ban_rate heartbeat


# ---------------------------------------------------------------------------
# Candidate (normalized)
# ---------------------------------------------------------------------------


class Asset(BaseModel):
    sha256: str  # content address = storage key
    media_type: str
    phash: Optional[str] = None  # perceptual hash if image (simhash fallback if Pillow/imagehash are unavailable)


class Candidate(BaseModel):
    id: str
    brand_id: str
    sensor_name: str
    platform: str
    platform_uid: str
    handle: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    link_in_bio_url: Optional[str] = None
    assets: list[Asset] = Field(default_factory=list)
    dedup_key: str  # (platform, platform_uid) + avatar phash
    raw_observation_ref: str  # sha256 of the stored RawObservation
    status: Literal["new", "classified", "queued", "decided", "packaged"] = "new"
    first_seen: datetime
    logo_clip_cosine: Optional[float] = None  # max CLIP cosine to a brand logo (embeddings mode)


# ---------------------------------------------------------------------------
# Verdict (classifier output)
# ---------------------------------------------------------------------------


class DetSignals(BaseModel):
    """Cheap deterministic signals computed BEFORE any LLM call."""

    handle_edit_distance: Optional[int] = None  # raw folded Levenshtein (kept for lineage)
    handle_similarity: Optional[float] = None  # length-normalized Jaro-Winkler in [0,1]
    handle_contains_brand: Optional[bool] = None  # official handle is a substring (combosquat)
    logo_phash_hamming: Optional[int] = None
    logo_clip_cosine: Optional[float] = None  # semantic logo similarity (embeddings mode)
    domain_in_cti_badlist: Optional[bool] = None
    # UTS-39 confusable + brand-intention signals
    mixed_script_handle: Optional[bool] = None  # homoglyph-attack tell
    alias_in_text: Optional[bool] = None  # brand alias appears in handle/name/bio
    domain_is_legit: Optional[bool] = None  # link domain IS an official brand domain
    domain_intention_mismatch: Optional[bool] = None  # presents brand but domain not legit


Label = Literal["legit", "fan", "suspicious", "impersonation", "fraud"]
POSITIVE_LABELS: frozenset[str] = frozenset({"impersonation", "fraud"})


class Recheck(BaseModel):
    """Second opinion on a verdict from a model of a DIFFERENT family.

    A judge that shares the classifier's model family shares its blind spots, so
    the recheck family is required to differ (see classify.RecheckingClassifier).
    """

    model_id: str
    family: str
    label: Label
    confidence: float
    prompt_hash: str
    agrees: bool  # both on the same side of the positive/negative line


class Verdict(BaseModel):
    candidate_id: str
    label: Label
    confidence: float  # 0..1
    signals: DetSignals
    reasoning: str
    model_id: str
    prompt_hash: str  # reproducibility anchor
    input_hashes: list[str]  # frozen asset hashes seen at decision time
    injection_flagged: bool = False  # untrusted content tried to steer -> a signal
    cost_usd: float = 0.0  # from the classifier cost meter (0 in mock mode)
    model_family: str = ""  # see families.model_family; "" = not recorded
    prompt_template: str = ""  # versioned id of the prompt template that produced prompt_hash
    redactions: int = 0  # PII spans removed from the text before any model call
    recheck: Optional[Recheck] = None


@runtime_checkable
class Classifier(Protocol):
    def classify(self, candidate: Candidate, brand: Brand) -> Verdict: ...


# Every decision on a candidate, including a reject, an escalation and a later
# release, gets the same signed receipt (see evidence.py). A decision without a
# receipt is a visible gap in the chain, not a silent absence.
Outcome = Literal["confirm", "reject", "escalate", "release"]
OUTCOMES: tuple[str, ...] = ("confirm", "reject", "escalate", "release")


class AnalystDecision(BaseModel):
    candidate_id: str
    analyst_id: str  # person, or the policy id when automated
    decision: Outcome
    decided_at: datetime
    note: Optional[str] = None
    authority: Optional[str] = None  # declared authority the decision was taken under
    automated: bool = False  # decided by the triage policy, not by a person


# ---------------------------------------------------------------------------
# Evidence package (HMAC-chained receipt)
# ---------------------------------------------------------------------------


EVIDENCE_SCHEMA = "bid.evidence/v2"


class SourceRef(BaseModel):
    """Where the candidate came from: the sensor and the stored raw observation."""

    sensor_name: str
    platform: str
    platform_uid: str
    raw_observation_ref: str  # sha256 of the stored RawObservation


class ModelTrace(BaseModel):
    """One model that contributed to the verdict a decision was taken on."""

    role: Literal["primary", "recheck"]
    model_id: str
    family: str
    prompt_hash: str
    prompt_template: str = ""


class PolicyPackRef(BaseModel):
    """The jurisdiction policy pack in force when the receipt was signed."""

    id: str
    version: str
    sha256: str


class EvidenceManifest(BaseModel):
    """The signed body. Binds a decision to the exact bytes seen at decision time.

    The same schema covers every outcome (confirm, reject, escalate, release), so
    a reject is as reviewable as a confirm.
    """

    schema_version: str = EVIDENCE_SCHEMA
    outcome: Outcome
    candidate_id: str
    decision_id: str
    brand_id: str
    source: SourceRef
    asset_hashes: list[str]  # content-addressed, bind payload to bytes
    context_hash: str  # hash of the candidate text and signals the classifier saw
    model_trace: list[ModelTrace]
    verdict_hash: str
    decision_hash: str
    decided_by: str  # analyst id, or the triage policy id when automated
    authority: Optional[str] = None  # declared authority the decision was taken under
    automated: bool = False
    policy_version: Optional[str] = None  # hash of thresholds+model+code_rev (reproducible learning)
    policy_pack: Optional[PolicyPackRef] = None
    attestation_hash: Optional[str] = None  # deployment attestation in force (see attestation.py)
    supersedes: Optional[str] = None  # manifest hash of the receipt a release reverses
    # sha256 of the previous receipt's canonical manifest (64 zeros for the first).
    # A public value, so a holder of the public key alone can check the chain.
    prev_manifest_hash: Optional[str]
    created_at: datetime


class EvidencePackage(BaseModel):
    manifest: EvidenceManifest
    manifest_hmac: str  # HMAC(key, canonical_manifest || prev_manifest_hash)
    # Ed25519/DSSE envelope: a third party verifies against the PUBLIC key with
    # no shared secret. The HMAC chain is the internal journal; the asymmetric
    # envelope is a second signer behind the same seam.
    dsse_envelope: Optional[dict] = None
    ed25519_pubkey: Optional[str] = None


@runtime_checkable
class EvidenceSigner(Protocol):
    def package(
        self,
        candidate: Candidate,
        verdict: Verdict,
        decision: AnalystDecision,
        prev_manifest_hash: Optional[str],
        created_at: datetime,
        policy_version: Optional[str] = None,
        policy_pack: Optional[PolicyPackRef] = None,
        attestation_hash: Optional[str] = None,
        supersedes: Optional[str] = None,
    ) -> EvidencePackage: ...


# ---------------------------------------------------------------------------
# Governance journal (events that are not a decision on one candidate)
# ---------------------------------------------------------------------------

GOVERNANCE_SCHEMA = "bid.governance/v1"
GovernanceKind = Literal[
    "queue_halt",  # someone with stop authority paused the queue
    "queue_resume",
    "hold_sla_escalation",  # an open hold aged past its SLA
    "deployment_attestation",  # the deployment profile actually in effect
    "conduct_scorecard",  # periodic classifier review on the frozen golden set
]


class GovernanceRecord(BaseModel):
    schema_version: str = GOVERNANCE_SCHEMA
    kind: GovernanceKind
    actor: str
    authority: Optional[str] = None
    subject: Optional[str] = None  # candidate id, manifest hash, deployment id, ...
    payload: dict = Field(default_factory=dict)
    prev_record_hash: str  # sha256 of the previous canonical record (64 zeros first)
    created_at: datetime


class GovernancePackage(BaseModel):
    """A governance record signed the same way as an evidence package."""

    record: GovernanceRecord
    record_hmac: str
    dsse_envelope: Optional[dict] = None
    ed25519_pubkey: Optional[str] = None
