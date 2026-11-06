"""
Content-addressed asset store. hash = key.

Every asset (icon, ad creative, screenshot) is stored under its SHA-256. This is
the anchor the whole lineage chain hangs off: tamper with an asset and its hash
changes, which breaks every downstream link that referenced it.

The default backend is a local directory. An S3-compatible bucket with
object-lock can be substituted behind the same interface (put_bytes / get_bytes).
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ContentStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, data: bytes) -> str:
        """Store bytes, return the content address (sha256 hex)."""
        digest = sha256_hex(data)
        path = self.root / digest
        if not path.exists():
            path.write_bytes(data)
        return digest

    def get_bytes(self, digest: str) -> bytes:
        return (self.root / digest).read_bytes()

    def exists(self, digest: str) -> bool:
        return (self.root / digest).exists()

    def tamper(self, digest: str, new_bytes: bytes) -> None:
        """Test-only: overwrite a stored object under its OLD key to simulate an
        attacker editing an asset after the fact. Verification must catch this."""
        (self.root / digest).write_bytes(new_bytes)
