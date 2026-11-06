"""
Signed evidence packaging.

Each confirmed impersonation becomes an EvidencePackage whose manifest is
HMAC-chained to the previous package:

    manifest_hmac = HMAC(key, canonical(manifest) || prev_manifest_hash)

That makes the sequence a Merkle-style chain: insert, remove, reorder, or alter
any package and the recomputed chain no longer matches. The manifest also pins
the content-addressed asset hashes, so editing an asset on disk (even under its
old key) is caught when verification recomputes the hashes from the stored bytes.

Verification is fully offline and needs only the shared key + the stored assets.
No network, no service.

Exported artifacts: HMAC is symmetric, so it verifies only for the key holder.
The artefact shared with a third party is an Ed25519/DSSE envelope (optionally
with an RFC-3161 timestamp sidecar), verifiable against a PUBLIC key by someone
who holds no secret. That signer sits behind the same EvidenceSigner seam; the
HMAC chain stays as the internal journal.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import Optional

from .families import model_family
from .models import (
    AnalystDecision,
    Candidate,
    EvidenceManifest,
    EvidencePackage,
    ModelTrace,
    PolicyPackRef,
    SourceRef,
    Verdict,
)
from .storage import ContentStore, sha256_hex

# The default key is a public development placeholder: receipts signed with it are
# reproducible but NOT trustworthy. Set BID_HMAC_KEY (from a secret store / KMS) for
# any real use. It is a param/env value so replays are deterministic.
# Public development placeholders. An empty variable counts as unset.
DEV_HMAC_KEY = "dev-hmac-key-not-for-production"
DEV_ED25519_SEED = "dev-ed25519-seed-not-for-production"
DEFAULT_HMAC_KEY = os.environ.get("BID_HMAC_KEY") or DEV_HMAC_KEY

_GENESIS = "0" * 64  # prev_manifest_hash for the very first package in a chain


def _canonical(obj) -> bytes:
    """Deterministic serialization so hashing is reproducible across runs."""
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump(mode="json")
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(obj) -> str:
    return sha256_hex(_canonical(obj))


def _hmac(key: str, manifest: EvidenceManifest, prev: str) -> str:
    body = _canonical(manifest) + prev.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def manifest_hash(pkg: EvidencePackage) -> str:
    """Content hash of a signed manifest. A release names the receipt it reverses
    by this value, and every projection (STIX, abuse report, ...) carries it."""
    return _hash(pkg.manifest)


def chain_link(pkg: Optional[EvidencePackage]) -> Optional[str]:
    """The prev_manifest_hash for the receipt signed after pkg (None: a new chain).

    The link is the public manifest hash, not the HMAC: the manifest is covered
    by the DSSE signature, so a third party holding only the public key can
    detect a receipt deleted from, or moved within, the chain.
    """
    return None if pkg is None else manifest_hash(pkg)


def context_hash(candidate: Candidate, verdict: Verdict) -> str:
    """Hash of exactly what the classifier was shown: the candidate's text fields,
    its asset hashes and the deterministic signals."""
    return _hash({
        "handle": candidate.handle,
        "display_name": candidate.display_name,
        "bio": candidate.bio,
        "link_in_bio_url": candidate.link_in_bio_url,
        "asset_hashes": [a.sha256 for a in candidate.assets],
        "signals": verdict.signals.model_dump(mode="json"),
    })


def model_trace(verdict: Verdict) -> list[ModelTrace]:
    """The primary classifier and, if present, the cross-family recheck."""
    trace = [ModelTrace(
        role="primary",
        model_id=verdict.model_id,
        family=verdict.model_family or model_family(verdict.model_id),
        prompt_hash=verdict.prompt_hash,
        prompt_template=verdict.prompt_template,
    )]
    if verdict.recheck is not None:
        rc = verdict.recheck
        trace.append(ModelTrace(role="recheck", model_id=rc.model_id, family=rc.family,
                                prompt_hash=rc.prompt_hash))
    return trace


class HmacEvidenceSigner:
    """Builds HMAC-chained evidence packages. Deterministic given the same inputs.

    Internal journal (HMAC) is always produced. If an `Ed25519Dsse` signer is
    passed, the SAME manifest is also wrapped in a DSSE envelope + Ed25519
    signature = the artefact shared with a third party who holds no shared secret.
    """

    def __init__(self, key: str = DEFAULT_HMAC_KEY, dsse: "Ed25519Dsse | None" = None):
        self._key = key
        self._dsse = dsse

    def public_key_hex(self) -> Optional[str]:
        """The public half of the DSSE signing key, or None without a DSSE signer."""
        return self._dsse.public_key_hex() if self._dsse is not None else None

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
    ) -> EvidencePackage:
        """Sign one decision on one candidate. Every outcome uses this path, so a
        reject or an escalation is as verifiable as a confirm."""
        if decision.candidate_id != candidate.id or verdict.candidate_id != candidate.id:
            raise ValueError("decision, verdict and candidate must refer to the same candidate")
        if decision.decision == "release" and not supersedes:
            raise ValueError("a release must name the receipt it reverses (supersedes)")
        if decision.decision != "release" and supersedes:
            raise ValueError("only a release may supersede another receipt")
        # Bind the policy identity (thresholds + classifier + code rev) into the
        # signed body. Default: derive it from the verdict's own model_id + the
        # live thresholds, so a receipt always says which policy produced it.
        if policy_version is None:
            from .policy import policy_version as _pv
            policy_version = _pv(verdict.model_id)
        decision_hash = _hash(decision)
        manifest = EvidenceManifest(
            outcome=decision.decision,
            candidate_id=candidate.id,
            decision_id=f"dec_{decision_hash[:24]}",
            brand_id=candidate.brand_id,
            source=SourceRef(
                sensor_name=candidate.sensor_name,
                platform=candidate.platform,
                platform_uid=candidate.platform_uid,
                raw_observation_ref=candidate.raw_observation_ref,
            ),
            asset_hashes=[a.sha256 for a in candidate.assets],
            context_hash=context_hash(candidate, verdict),
            model_trace=model_trace(verdict),
            verdict_hash=_hash(verdict),
            decision_hash=decision_hash,
            decided_by=decision.analyst_id,
            authority=decision.authority,
            automated=decision.automated,
            policy_version=policy_version,
            policy_pack=policy_pack,
            attestation_hash=attestation_hash,
            supersedes=supersedes,
            prev_manifest_hash=prev_manifest_hash or _GENESIS,
            created_at=created_at,
        )
        mac = _hmac(self._key, manifest, manifest.prev_manifest_hash)
        env = pub = None
        if self._dsse is not None:
            env = self._dsse.sign(_canonical(manifest), DSSE_PAYLOAD_TYPE)
            pub = self._dsse.public_key_hex()
        return EvidencePackage(
            manifest=manifest, manifest_hmac=mac, dsse_envelope=env, ed25519_pubkey=pub
        )


# ===========================================================================
# Ed25519 / DSSE - the exported artefact
# ===========================================================================
# HMAC above is symmetric: it proves tamper-evidence only to the key holder.
# A third party holds no shared secret, so it can NOT verify an HMAC, and if it
# were given the key it could forge one. The artefact exported to a reviewer is
# therefore ASYMMETRIC: a DSSE envelope signed with Ed25519, verifiable against
# a PUBLIC key by a party that does not need to trust the signer's infrastructure.
#
# DSSE PAE (pre-authentication encoding) prevents payload-type confusion.

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DSSE_PAYLOAD_TYPE = "application/vnd.brand-impersonation-detector.evidence+json"

# The default seed is a public development placeholder, fixed so replay is
# byte-identical. Set BID_ED25519_SEED for any real use; a production deployment
# should derive the private key from a KMS/HSM instead.
DEFAULT_ED25519_SEED = os.environ.get("BID_ED25519_SEED") or DEV_ED25519_SEED


def development_keys() -> list[str]:
    """Signing settings still on their public development values. Anyone can
    sign under those, so receipts made with them prove nothing."""
    from .feedback import DEV_LEDGER_KEY, _LEDGER_KEY

    dev = [("BID_HMAC_KEY", DEFAULT_HMAC_KEY == DEV_HMAC_KEY),
           ("BID_ED25519_SEED", DEFAULT_ED25519_SEED == DEV_ED25519_SEED),
           ("BID_LEDGER_KEY", _LEDGER_KEY == DEV_LEDGER_KEY)]
    return [name for name, is_dev in dev if is_dev]


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (in-toto spec).

    DSSEv1 SP len(type) SP type SP len(payload) SP payload
    """
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


class Ed25519Dsse:
    """Ed25519 signer producing DSSE envelopes. Verifiable with the public key alone."""

    def __init__(self, seed: str = DEFAULT_ED25519_SEED):
        # Deterministic 32-byte seed from a passphrase so replays are identical.
        seed32 = hashlib.sha256(seed.encode("utf-8")).digest()
        self._sk = Ed25519PrivateKey.from_private_bytes(seed32)
        self._pk = self._sk.public_key()

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self._pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, payload: bytes, payload_type: str = DSSE_PAYLOAD_TYPE) -> dict:
        sig = self._sk.sign(_dsse_pae(payload_type, payload))
        return {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"keyid": "bid-ed25519", "sig": base64.b64encode(sig).decode("ascii")}],
        }


def dsse_verify(envelope: dict, pubkey_hex: str) -> tuple[bool, str]:
    """Verify a DSSE envelope against a PUBLIC key only. No shared secret. No network.

    A party that holds no shared secret can still prove the payload was signed by
    the holder of the private key and was not altered.
    """
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        payload = base64.b64decode(envelope["payload"])
        ptype = envelope["payloadType"]
        pae = _dsse_pae(ptype, payload)
        for s in envelope["signatures"]:
            sig = base64.b64decode(s["sig"])
            try:
                pk.verify(sig, pae)
                return True, "ok"
            except InvalidSignature:
                continue
        return False, "no valid Ed25519 signature for this public key"
    except Exception as e:  # malformed envelope
        return False, f"envelope error: {e}"


def verify_package_public(
    pkg: EvidencePackage,
    store: ContentStore,
    pubkey_hex: Optional[str] = None,
) -> tuple[bool, str]:
    """Third-party offline verify using a public key and the stored bytes only.

    Does NOT use the HMAC secret. This is what an external reviewer runs.
    Checks: (1) the receipt is signed by `pubkey_hex` when it is given, (2) the
    DSSE Ed25519 signature over the manifest, with the evidence payload type,
    (3) the manifest in the signed payload matches the package manifest, (4) every
    asset re-hashes to its content address from the stored bytes.

    Without `pubkey_hex` the check uses the key the receipt names, which proves
    the receipt is intact under that key, not who holds it: anyone can re-sign a
    forged receipt with a key of their own. A reviewer pins the deployment's
    published key.
    """
    if not pkg.dsse_envelope or not pkg.ed25519_pubkey:
        return False, "no DSSE envelope (nothing to verify without a shared secret)"
    key = pkg.ed25519_pubkey.strip().lower()
    if pubkey_hex is not None and key != pubkey_hex.strip().lower():
        return False, "signed under a different public key than the one expected"
    if pkg.dsse_envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return False, "unexpected DSSE payload type (not an evidence receipt)"
    ok, reason = dsse_verify(pkg.dsse_envelope, key)
    if not ok:
        return False, f"DSSE signature invalid: {reason}"
    signed_payload = base64.b64decode(pkg.dsse_envelope["payload"])
    if signed_payload != _canonical(pkg.manifest):
        return False, "signed payload does not match the package manifest (tampered)"
    for digest in pkg.manifest.asset_hashes:
        if not store.exists(digest):
            return False, f"asset {digest[:12]} missing from store"
        if sha256_hex(store.get_bytes(digest)) != digest:
            return False, f"asset {digest[:12]} bytes tampered (hash no longer matches)"
    return True, "ok"


def verify_chain_public(
    packages: list[EvidencePackage],
    store: ContentStore,
    pubkey_hex: Optional[str] = None,
) -> tuple[bool, str]:
    """Verify a whole chain with a public key only + the prev-hash links.

    Each link is the hash of the previous signed manifest, so deleting or
    reordering a receipt breaks a signed value. Every receipt must be signed by
    the same key: `pubkey_hex` when given, else the key of the first receipt.
    Dropping receipts from the END of a chain is only detectable against a
    separately anchored chain head (see anchor.py).
    """
    prev = _GENESIS
    expected = pubkey_hex.strip().lower() if pubkey_hex else None
    for i, pkg in enumerate(packages):
        if pkg.manifest.prev_manifest_hash != prev:
            return False, f"chain break at package {i}: prev_manifest_hash mismatch"
        if expected is None and pkg.ed25519_pubkey:
            expected = pkg.ed25519_pubkey.strip().lower()
        ok, reason = verify_package_public(pkg, store, expected)
        if not ok:
            return False, f"package {i} failed: {reason}"
        prev = manifest_hash(pkg)
    return True, f"chain of {len(packages)} package(s) verified offline with PUBLIC key only"


# --- offline verification ---------------------------------------------------


def verify_package(
    pkg: EvidencePackage,
    key: str,
    store: ContentStore,
) -> tuple[bool, str]:
    """Recompute this package's HMAC and re-hash its assets from stored bytes.

    Returns (ok, reason). No network. Any edit to the manifest, the referenced
    verdict/decision hashes, or the underlying asset bytes flips ok to False.
    """
    expected = _hmac(key, pkg.manifest, pkg.manifest.prev_manifest_hash)
    if not hmac.compare_digest(expected, pkg.manifest_hmac):
        return False, "manifest HMAC mismatch (manifest or chain link altered)"

    for digest in pkg.manifest.asset_hashes:
        if not store.exists(digest):
            return False, f"asset {digest[:12]} missing from store"
        recomputed = sha256_hex(store.get_bytes(digest))
        if recomputed != digest:
            return False, f"asset {digest[:12]} bytes tampered (hash no longer matches)"
    return True, "ok"


def verify_chain(
    packages: list[EvidencePackage],
    key: str,
    store: ContentStore,
) -> tuple[bool, str]:
    """Verify a whole chain: each package individually, plus the prev-hash links."""
    prev = _GENESIS
    for i, pkg in enumerate(packages):
        if pkg.manifest.prev_manifest_hash != prev:
            return False, f"chain break at package {i}: prev_manifest_hash mismatch"
        ok, reason = verify_package(pkg, key, store)
        if not ok:
            return False, f"package {i} failed: {reason}"
        # The next link is THIS manifest's public hash (see chain_link).
        prev = manifest_hash(pkg)
    return True, f"chain of {len(packages)} package(s) verified offline"
