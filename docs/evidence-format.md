# Evidence format

Every decision on a candidate gets one signed receipt: a triage reject, an
escalation, a confirm by a person, and a release that reverses a confirm. The
format is the same for all four outcomes, so a reject can be reviewed as closely
as a confirm. Receipts form one chain per run directory.

Schema id: `bid.evidence/v2`. Models: `EvidenceManifest` and `EvidencePackage` in
[`bid/models.py`](../bid/models.py). Signing and verification:
[`bid/evidence.py`](../bid/evidence.py).

## Receipt

A receipt (`EvidencePackage`) has four parts:

| Field | Content |
|---|---|
| `manifest` | the signed body, below |
| `manifest_hmac` | HMAC-SHA256 under `BID_HMAC_KEY` over the canonical manifest followed by `prev_manifest_hash`; the internal check |
| `dsse_envelope` | a DSSE envelope with an Ed25519 signature over the canonical manifest; the public check |
| `ed25519_pubkey` | hex public key the envelope was signed with |

One receipt from a fixture run, values shortened:

```json
{
  "manifest": {
    "schema_version": "bid.evidence/v2",
    "outcome": "confirm",
    "candidate_id": "cand_local_s...",
    "decision_id": "dec_95844f09...",
    "brand_id": "covelle",
    "source": {
      "sensor_name": "local_search",
      "platform": "local_search",
      "platform_uid": "covelle_global",
      "raw_observation_ref": "660b5f710745..."
    },
    "asset_hashes": ["f741bfcc43c9..."],
    "context_hash": "c703668fb3a9...",
    "model_trace": [
      {"role": "primary", "model_id": "mock-determi...", "family": "rules",
       "prompt_hash": "88887a88b0ff...", "prompt_template": "bid-prompt-v..."}
    ],
    "verdict_hash": "bdabfa12c84b...",
    "decision_hash": "95844f0909f0...",
    "decided_by": "analyst_01",
    "authority": "brand-protec...",
    "automated": false,
    "policy_version": "d4da655b27e46b25",
    "policy_pack": null,
    "attestation_hash": null,
    "supersedes": null,
    "prev_manifest_hash": "1498d3b4e3ee...",
    "created_at": "2026-07-03T12:00:00Z"
  },
  "manifest_hmac": "6222033febd5...",
  "dsse_envelope": {
    "payloadType": "application/vnd.brand-impersonation-detector.evidence+json",
    "payload": "eyJhc3NldF9o...",
    "signatures": [{"keyid": "bid-ed25519", "sig": "3VVosUEyBGoj..."}]
  },
  "ed25519_pubkey": "02d71f863a7f..."
}
```

## Manifest fields

| Field | Meaning |
|---|---|
| `schema_version` | `bid.evidence/v2` |
| `outcome` | `confirm`, `reject`, `escalate` or `release` |
| `candidate_id`, `brand_id` | the candidate and the brand it was checked against |
| `decision_id` | `dec_` + the first 24 hex characters of `decision_hash` |
| `source` | sensor name, platform, platform identifier, and the SHA-256 of the stored raw observation |
| `asset_hashes` | SHA-256 of every stored asset (icon, banner, ad creative) the candidate carried |
| `context_hash` | hash of what the classifier was shown: handle, display name, bio, link, asset hashes and the deterministic signals |
| `model_trace` | the primary model and, if run, the recheck model: model id, model family, prompt hash, prompt template id |
| `verdict_hash`, `decision_hash` | hashes of the full verdict and decision objects, which are kept in `cases.jsonl` |
| `decided_by` | the person, or the triage policy version for automated receipts |
| `authority` | the declared authority the decision was taken under |
| `automated` | `true` when the triage policy decided without a person |
| `policy_version` | 16 hex characters of the SHA-256 over the routing thresholds, the classifier model id and the policy code revision ([`bid/policy.py`](../bid/policy.py)) |
| `policy_pack` | id, version and SHA-256 of the policy pack in force, if any ([policy-packs.md](policy-packs.md)) |
| `attestation_hash` | hash of the deployment attestation in force, if any ([deployment.md](deployment.md#profiles-and-attestation)) |
| `supersedes` | for a release: the manifest hash of the confirm it reverses |
| `prev_manifest_hash` | the manifest hash of the previous receipt in the chain; 64 zeros for the first |
| `created_at` | decision time, UTC |

## Hashes and canonical form

- Canonical JSON: the model dumped in JSON mode, then
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))` with ASCII escaping,
  encoded as UTF-8.
- `manifest_hash` = SHA-256 of the canonical manifest. Projections carry it, a
  release names the reversed receipt by it, and the next receipt links to it.
- `manifest_hmac` = HMAC-SHA256(`BID_HMAC_KEY`, canonical(manifest) ‖ `prev_manifest_hash`).
- The DSSE signature covers the DSSE pre-authentication encoding
  `DSSEv1 <len(type)> <type> <len(payload)> <payload>`, where the payload is the
  canonical manifest. The signing key is derived as SHA-256(`BID_ED25519_SEED`),
  so the same seed always yields the same key.
- Assets and raw observations are stored under their SHA-256 in the run
  directory ([`bid/storage.py`](../bid/storage.py)).

## Chain

Each manifest carries the manifest hash of the receipt before it. The link is a
public value covered by the signature, so a holder of the public key alone can
detect a receipt removed from the middle of the chain or moved within it.

Removing receipts from the end of a chain leaves a valid shorter chain. To make
that detectable, `bid run --anchor` asks an RFC-3161 timestamp authority to
timestamp the DSSE signature of the last receipt and writes
`chain_head.rfc3161.json`:

```json
{"receipts": 21, "manifest_hash": "<hash of the last receipt>", "timestamp": {...}}
```

The token shows the chain held at least that many receipts at that time. The
timestamp is outside the signed core, since a timestamp authority returns a
different token each time. The module checks that the token binds to the signed
bytes; it does not validate the authority's certificate chain.

## Verification

Two checks, for two audiences:

| Check | Needs | Run by | Command |
|---|---|---|---|
| Internal | `BID_HMAC_KEY`, the run directory | the operator | `bid run` prints it; `verify_chain` in Python |
| Public | the published public key, the run directory | anyone | `bid verify` |

```bash
bid verify <run-dir>/receipts.jsonl --pubkey <hex>
bid verify <run-dir>/receipt_sample.json --pubkey <hex>
```

The public check, per receipt:

1. the receipt names the pinned public key (`--pubkey`);
2. the DSSE payload type is the evidence type;
3. the Ed25519 signature verifies;
4. the signed payload equals the canonical manifest;
5. every asset in `asset_hashes` exists in the store and re-hashes to its address.

For a chain it also checks every `prev_manifest_hash` link and that every
receipt is signed by the same key. Exit code 0 means verified, 2 means rejected.

Without `--pubkey` the command checks the receipts against the key they name
and says the key is not pinned. That shows the receipts are intact; it does not
show who signed them, because anyone can sign a forged receipt with a key of
their own. Publish the deployment's public key through a channel you control
and pin it.

## What a receipt does not prove

- That the verdict is right. It proves which model, prompt, thresholds and
  person produced the decision, and what they were shown.
- That the observation reflects the platform today. Content changes; the
  receipt binds the bytes seen at decision time.
- Legal sufficiency or admissibility in any jurisdiction.

## Governance records

Events that are not a decision on one candidate (queue stop and resume, hold
escalations, deployment attestations, conduct reviews) go to a separate journal
with the same construction: schema `bid.governance/v1`, `record_hmac` over the
canonical record followed by `prev_record_hash`, and a DSSE envelope with the
payload type `application/vnd.brand-impersonation-detector.governance+json`.
See [governance.md](governance.md).
