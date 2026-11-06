"""Public-key verification: a pinned signer, one key per chain, the standalone verifier."""
from datetime import datetime, timezone

import pytest

from bid import api, records
from bid.evidence import Ed25519Dsse, _canonical, verify_chain_public, verify_package_public
from bid.storage import ContentStore
from bid.verify_receipt import main as verify_main

NOW = datetime(2026, 11, 6, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def run_dir(tmp_path):
    api.run_pipeline_api(tmp_path, k=10, now=NOW)
    return api.current_run(tmp_path)


def _resigned(pkg, seed="someone-else"):
    other = Ed25519Dsse(seed=seed)
    forged = pkg.model_copy(deep=True)
    forged.dsse_envelope = other.sign(_canonical(forged.manifest))
    forged.ed25519_pubkey = other.public_key_hex()
    return forged


def test_resigned_receipt_fails_only_against_the_pinned_key(run_dir):
    store = ContentStore(run_dir)
    pkg = records.read_receipts(run_dir)[0]
    real = Ed25519Dsse().public_key_hex()
    forged = _resigned(pkg)
    # Under the key it names, a re-signed receipt is intact: the pin is what tells them apart.
    assert verify_package_public(forged, store)[0]
    ok, reason = verify_package_public(forged, store, real)
    assert not ok and "different public key" in reason
    assert verify_package_public(pkg, store, real.upper())[0]


def test_chain_must_be_signed_by_one_key(run_dir):
    store = ContentStore(run_dir)
    chain = records.read_receipts(run_dir)
    assert verify_chain_public(chain, store)[0]
    mixed = chain[:2] + [_resigned(chain[2])] + chain[3:]
    ok, reason = verify_chain_public(mixed, store)
    assert not ok and "package 2" in reason


def test_payload_type_is_checked(run_dir):
    store = ContentStore(run_dir)
    pkg = records.read_receipts(run_dir)[0].model_copy(deep=True)
    pkg.dsse_envelope["payloadType"] = "application/vnd.something-else+json"
    ok, reason = verify_package_public(pkg, store)
    assert not ok and "payload type" in reason


def test_standalone_verifier_pins_the_key_and_reads_chains(run_dir, capsys):
    real = Ed25519Dsse().public_key_hex()
    other = Ed25519Dsse(seed="someone-else").public_key_hex()
    assert verify_main([str(run_dir / "receipt_sample.json"), "--pubkey", real]) == 0
    assert verify_main([str(run_dir / "receipts.jsonl"), "--pubkey", real]) == 0
    assert verify_main([str(run_dir / "receipts.jsonl"), "--pubkey", other]) == 2
    assert verify_main([str(run_dir / "receipts.jsonl")]) == 0
    assert "pass --pubkey" in capsys.readouterr().out
