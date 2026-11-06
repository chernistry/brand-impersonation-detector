"""
Standalone offline receipt verifier: `bid verify`.

A reviewer who receives a receipt (JSON) or a whole chain (receipts.jsonl) plus
the stored assets runs this, with no shared secret and no network:

    bid verify <run-dir>/receipt_sample.json --pubkey <hex>
    bid verify <run-dir>/receipts.jsonl --pubkey <hex>

It checks the Ed25519/DSSE signature of every receipt, that the signed manifest
matches, that every asset re-hashes from the stored bytes and, for a chain, that
no receipt was deleted or reordered. --pubkey pins the deployment's published
signing key; without it the result only shows the receipts are intact under the
key they name. Assets are read from --store, by default the receipt's own
directory (a run directory holds both). Exit 0 = verified, 2 = rejected.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .evidence import verify_chain_public, verify_package_public
from .models import EvidencePackage
from .storage import ContentStore


def _load(path: Path) -> list[EvidencePackage]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [EvidencePackage.model_validate_json(line) for line in text.splitlines() if line.strip()]
    return [EvidencePackage.model_validate_json(text)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline public-key evidence verifier")
    ap.add_argument("receipt", type=Path, help="a receipt (.json) or a chain of receipts (.jsonl)")
    ap.add_argument("--store", type=Path, help="directory of the content-addressed assets "
                                               "(default: the receipt's directory)")
    ap.add_argument("--pubkey", help="expected Ed25519 public key (hex), published by the deployment")
    args = ap.parse_args(argv)

    packages = _load(args.receipt)
    if not packages:
        print(f"RESULT: REJECTED  (no receipts in {args.receipt})")
        return 2
    store = ContentStore(args.store or args.receipt.parent)
    first = packages[0]
    print("Receipts     :", args.receipt, f"({len(packages)})")
    print("Candidate    :", first.manifest.candidate_id if len(packages) == 1 else "(chain)")
    print("Signed at    :", first.manifest.created_at if len(packages) == 1 else "(chain)")
    print("Signing key  :", first.ed25519_pubkey or "(none)")
    print("Key pinned   :", "yes" if args.pubkey else "NO - pass --pubkey to rule out a re-signed receipt")
    print("Shared secret: NONE required")
    print("-" * 60)

    if args.receipt.suffix == ".jsonl":
        ok, reason = verify_chain_public(packages, store, args.pubkey)
    else:
        ok, reason = verify_package_public(first, store, args.pubkey)
    if ok:
        print("RESULT: VERIFIED  (signatures valid, manifests intact, assets match)")
        return 0
    print(f"RESULT: REJECTED  ({reason})")
    return 2


if __name__ == "__main__":
    sys.exit(main())
