"""
RFC-3161 trusted-timestamp anchor for the evidence receipt (keyless).

The Ed25519/DSSE signature proves WHO signed and that nothing was altered, but
the timestamp is the signer's own wall clock, which a third party could dispute. An
RFC-3161 token from an independent Timestamp Authority (TSA) proves the signature
existed at a time neither party can backdate. RFC-3161 is the eIDAS/ETSI-
recognised standard. It is used KEYLESS: a plain no-account POST (NOT the Fulcio
OIDC "keyless signing" flow, which needs a login).

Scope: this makes the receipt "trusted-timestamped, tamper-evident,
independently verifiable". It is not a claim of legal admissibility - that is
jurisdiction-specific. Full X.509 chain validation to the TSA root is not
implemented; this module verifies that the token binds to the exact bytes and
carries an independent generation time.

The timestamp is a SIDECAR: it is non-deterministic by design (the TSA stamps
real time), so it lives outside the byte-identical signed core and is checked by
"verifies offline", never by byte-equality.
"""
from __future__ import annotations

import base64
import hashlib

from .useragent import user_agent

SIGSTORE_TSA = "https://timestamp.sigstore.dev/api/v1/timestamp"
FREETSA = "https://freetsa.org/tsr"
_HDR = {"Content-Type": "application/timestamp-query", "User-Agent": user_agent()}


def timestamp(data: bytes, url: str = FREETSA, timeout: float = 30.0) -> dict | None:
    """Get a real RFC-3161 token over `data` from a TSA. None on failure (graceful).

    Falls back to the sigstore TSA if the primary fails. Returns a sidecar dict.
    """
    try:
        from rfc3161_client import HashAlgorithm, TimestampRequestBuilder, decode_timestamp_response

        from . import net

        req = TimestampRequestBuilder().hash_algorithm(HashAlgorithm.SHA256).data(data).build()
        r = net.post("anchor", url, content=req.as_bytes(), headers=_HDR, timeout=timeout)
        r.raise_for_status()
        tsr = decode_timestamp_response(r.content)
        return {
            "tsa_url": url,
            "token_b64": base64.b64encode(r.content).decode("ascii"),
            "gen_time": tsr.tst_info.gen_time.isoformat(),
            "data_sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception:
        if url != SIGSTORE_TSA:
            return timestamp(data, url=SIGSTORE_TSA, timeout=timeout)
        return None


def verify_timestamp(sidecar: dict, data: bytes) -> tuple[bool, str]:
    """Offline: decode the token and confirm its message imprint == sha256(data).

    Proves the trusted timestamp binds to exactly these bytes and yields the
    independent generation time. (Full TSA-cert chain validation is not implemented.)
    """
    try:
        from rfc3161_client import decode_timestamp_response

        tok = base64.b64decode(sidecar["token_b64"])
        tsr = decode_timestamp_response(tok)
        imprint = tsr.tst_info.message_imprint.message
        if bytes(imprint) != hashlib.sha256(data).digest():
            return False, "message imprint does not match the data (timestamp is for other bytes)"
        return True, (f"RFC-3161 token binds this data at {tsr.tst_info.gen_time.isoformat()} "
                      f"(TSA {sidecar.get('tsa_url')})")
    except Exception as e:
        return False, f"timestamp verify error: {type(e).__name__}: {e}"


if __name__ == "__main__":
    # self-test
    d = b"bid evidence dsse signature bytes"
    s = timestamp(d)
    if not s:
        print("no TSA reachable (offline?)")
        raise SystemExit(0)
    print("got token from", s["tsa_url"], "at", s["gen_time"])
    print("verify(correct data):", verify_timestamp(s, d))
    print("verify(tampered data):", verify_timestamp(s, d + b"X"))
