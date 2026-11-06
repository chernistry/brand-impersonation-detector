"""
End-to-end pipeline driver. Runs with no API keys and no accounts:

    bid run                       (or: python -m bid.run_pipeline)

It runs every stage on bundled fixtures:

    sensors -> normalize -> dedup -> cheap filters (cut) -> classify -> rank
            -> triage policy: a signed receipt for EVERY verdict (clear
               negatives rejected, everything else escalated to a person)
            -> simulated analyst confirms the escalated positive findings
            -> offline chain verify (HMAC, then public key only)
            -> one-byte tamper (must FAIL) -> metrics, receipt coverage

Fixture runs are deterministic: the clock, the HMAC key and the signing seed are
fixed inputs, the rule-based classifier is deterministic, and ranking has a
stable tiebreak. Two runs produce byte-identical evidence packages.

The run directory (default $BID_DATA_DIR/pipeline) receives receipts.jsonl and
cases.jsonl (see records.py), the content-addressed assets, and a sample receipt
with its public key for `bid verify`.

Options for real scans: --brands (your brand file), --sensors broad (live App
Store, look-alike domains, certificate logs), --live (hosted classifier),
--recheck (cross-family recheck model), --clock utc, --profile (deployment
profile; its attestation is recorded and bound into every receipt).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from . import paths, records
from .classify import build_classifier
from .decisions import TriagePolicy, coverage, decide_and_sign, open_holds
from .evidence import (
    DEFAULT_ED25519_SEED,
    DEFAULT_HMAC_KEY,
    DEV_ED25519_SEED,
    DEV_HMAC_KEY,
    Ed25519Dsse,
    HmacEvidenceSigner,
    chain_link,
    manifest_hash,
    verify_chain,
    verify_chain_public,
    verify_package,
    verify_package_public,
)
from .filters import asset_phash, stage_a
from .metrics import cut_ratio, precision_at_k, recall
from .models import (
    AnalystDecision,
    Brand,
    Candidate,
    DetSignals,
    EvidencePackage,
    PolicyPackRef,
    Verdict,
)
from .normalize import dedup, normalize
from .rank import rank
from .sensors.base import FIXTURES
from .storage import ContentStore

# Fixed decision time so fixture evidence packages replay byte-identically.
FIXED_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
POSITIVE_LABELS = {"impersonation", "fraud"}
ANALYST_ID = "analyst_01"
ANALYST_AUTHORITY = "brand-protection analyst"
DEFAULT_LOOKBACK = timedelta(days=7)


def _load_brand_kb(directory: Path) -> dict:
    p = directory / "brand_kb.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _match_kb(name: str, kb: dict) -> dict:
    """Match a brand name to a KB entry (exact, else substring both ways)."""
    if name in kb:
        return kb[name]
    nl = name.lower()
    for k, v in kb.items():
        kl = k.lower()
        if nl in kl or kl in nl:
            return v
    return {}


def load_brands(embeddings: bool = False, brands_file: Optional[Path] = None) -> list[Brand]:
    """Load brands, compute each brand's official logo pHash, enrich from the brand KB.

    brands_file defaults to the bundled fixtures. Logo paths are relative to the
    brands file, and a brand_kb.json next to it supplies aliases and official
    domains. In embeddings mode, also precompute CLIP vectors of the official
    logos for the semantic-similarity tier.
    """
    path = Path(brands_file) if brands_file else FIXTURES / "brands.json"
    raw = json.loads(path.read_text())
    kb = _load_brand_kb(path.parent)
    clip_ok = False
    if embeddings:
        from . import embeddings as _emb
        clip_ok = _emb.available()
    brands = []
    for b in raw.values():
        logo_bytes = [(path.parent / p).read_bytes() for p in b.get("official_logo_assets", [])]
        logo_hashes = [asset_phash(x) for x in logo_bytes]
        clip_vecs = []
        if clip_ok:
            from . import embeddings as _emb
            for x in logo_bytes:
                v = _emb.clip_image_vector(x)
                if v is not None:
                    clip_vecs.append([round(float(z), 6) for z in v.tolist()])
        kb_entry = _match_kb(b["name"], kb)
        brands.append(
            Brand(
                id=b["id"],
                name=b["name"],
                official_handles=b["official_handles"],
                official_logo_hashes=logo_hashes,
                regions=b.get("regions", []),
                cti_brand_ref=b.get("cti_brand_ref"),
                aliases=kb_entry.get("aliases", []),
                official_domains=kb_entry.get("domains", []),
                official_logo_clip=clip_vecs,
            )
        )
    return brands


def load_cti_badlist(path: Optional[Path] = None) -> set[str]:
    raw = json.loads((Path(path) if path else FIXTURES / "cti_badlist.json").read_text())
    return set(raw.get("known_bad_registrable_domains", []))


def load_labels() -> dict[str, bool]:
    raw = json.loads((FIXTURES / "labels.json").read_text())
    return dict(raw.get("labels", {}))


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    """Everything the detection stages produced for one run."""

    brands: list[Brand]
    brand_by_id: dict[str, Brand]
    candidates: list[Candidate]          # after dedup
    survivors: list[Candidate]           # kept by the cheap filters
    signals: dict[str, DetSignals]       # stage-A signals of every candidate
    verdicts: list[Verdict]              # one per survivor, in survivor order
    survivor_by_id: dict[str, Candidate] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.survivor_by_id = {c.id: c for c in self.survivors}


def detect(store: ContentStore, brands: list[Brand], cti: set[str], classifier, sensors,
           *, since: datetime = FIXED_NOW, embeddings: bool = False) -> Detection:
    """Scan, normalize, deduplicate, filter and classify. Shared by the CLI run
    and the operator console, so both see exactly the same candidates."""
    candidates: list[Candidate] = []
    for brand in brands:
        for sensor in sensors:
            for obs in sensor.scan(brand, since=since):
                candidates.append(normalize(obs, brand, store))
    candidates = dedup(candidates)
    brand_by_id = {b.id: b for b in brands}

    # Embeddings mode: semantic CLIP logo similarity, fused with pHash downstream.
    if embeddings:
        from . import embeddings as _emb
        if _emb.available():
            for c in candidates:
                brand = brand_by_id.get(c.brand_id)
                if not brand or not brand.official_logo_clip or not c.assets:
                    continue
                v = _emb.clip_image_vector(store.get_bytes(c.assets[0].sha256))
                if v is not None:
                    c.logo_clip_cosine = round(max(_emb.cosine(v, bv) for bv in brand.official_logo_clip), 3)

    survivors: list[Candidate] = []
    signals: dict[str, DetSignals] = {}
    for c in candidates:
        s, keep = stage_a(c, brand_by_id[c.brand_id], cti)
        signals[c.id] = s
        if keep:
            survivors.append(c)
    verdicts = [classifier.classify(c, brand_by_id[c.brand_id]) for c in survivors]
    return Detection(brands, brand_by_id, candidates, survivors, signals, verdicts)


def sign_decisions(det: Detection, signer: HmacEvidenceSigner, policy: TriagePolicy,
                   decided_at: datetime, *, simulate_analyst: bool = True,
                   policy_pack: Optional[PolicyPackRef] = None,
                   attestation_hash: Optional[str] = None) -> list[EvidencePackage]:
    """A triage receipt for every verdict, then (fixture runs) the simulated
    analyst's confirm of each escalated positive finding, all in one chain."""
    extra = {"policy_pack": policy_pack, "attestation_hash": attestation_hash}
    packages = decide_and_sign(det.survivor_by_id, det.verdicts, signer, policy, decided_at, **extra)
    if not simulate_analyst:
        return packages
    # The model ranks, a person decides. The fixture run plays the person and
    # confirms the escalated positive findings; a real analyst does this in the
    # console. Everything else stays an open hold.
    verdict_by_id = {v.candidate_id: v for v in det.verdicts}
    for hold in open_holds(packages):
        v = verdict_by_id[hold.manifest.candidate_id]
        if v.label not in POSITIVE_LABELS:
            continue
        person = AnalystDecision(candidate_id=v.candidate_id, analyst_id=ANALYST_ID, decision="confirm",
                                 decided_at=decided_at, note=f"Confirmed {v.label} on the ranked queue.",
                                 authority=ANALYST_AUTHORITY)
        packages.append(signer.package(det.survivor_by_id[v.candidate_id], v, person,
                                       chain_link(packages[-1]), decided_at, **extra))
    return packages


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def run(store_dir: Path, hmac_key: str, k: int, live: bool = False,
        model: str | None = None, anchor: bool = False, embeddings: bool = False, *,
        recheck_model: str | None = None, sensors: str = "fixtures",
        brands_file: Optional[Path] = None, now: Optional[datetime] = None,
        triage: Optional[TriagePolicy] = None, policy_pack: Optional[PolicyPackRef] = None,
        attestation_hash: Optional[str] = None, simulate_analyst: bool = True) -> dict:
    store_dir = Path(store_dir)
    store = ContentStore(store_dir)
    decided_at = now or FIXED_NOW
    since = FIXED_NOW if now is None else now - DEFAULT_LOOKBACK
    brands = load_brands(embeddings=embeddings, brands_file=brands_file)
    cti = load_cti_badlist()
    labels = load_labels()
    classifier = build_classifier(cti, store=store, model=model, live=live, recheck_model=recheck_model)
    signer = HmacEvidenceSigner(hmac_key, dsse=Ed25519Dsse())  # asymmetric signer for the export
    policy = triage or TriagePolicy()

    from .sensors.factory import build_sensors
    sensor_list = build_sensors(brands=brands, broad=(sensors == "broad"))

    print("=" * 70)
    print("BRAND-IMPERSONATION DETECTION PIPELINE")
    print("=" * 70)
    print("Sensors:", ", ".join(s.name() for s in sensor_list))
    print("Classifier:", classifier.model_id)
    print("Triage policy:", policy.version)
    print()
    for s in sensor_list:
        print("  health:", s.health())
    print()

    # 1-3) SCAN -> NORMALIZE -> CHEAP FILTERS -> CLASSIFY ----------------------
    det = detect(store, brands, cti, classifier, sensor_list, since=since, embeddings=embeddings)
    total_in = len(det.candidates)
    dropped = total_in - len(det.survivors)
    verdicts = det.verdicts
    total_cost = sum(v.cost_usd for v in verdicts)

    # 4) RANK top-k per brand -------------------------------------------------
    ranked_all: list[Verdict] = []
    print("-" * 70)
    print("RANKED ANALYST QUEUE (top-k per brand)")
    print("-" * 70)
    for brand in det.brands:
        bverdicts = [v for v in verdicts if det.survivor_by_id[v.candidate_id].brand_id == brand.id]
        ranked = rank(bverdicts, k=k)
        ranked_all.extend(ranked)
        print(f"\n[{brand.name}]")
        for i, v in enumerate(ranked, 1):
            flag = " INJECTION" if v.injection_flagged else ""
            print(f"  {i}. {v.label:14s} conf={v.confidence:.2f} {v.candidate_id}{flag}")
            print(f"       {v.reasoning}")

    # 5) TRIAGE + SIMULATED ANALYST -> SIGNED RECEIPTS ------------------------
    t0 = time.perf_counter()
    packages = sign_decisions(det, signer, policy, decided_at, simulate_analyst=simulate_analyst,
                              policy_pack=policy_pack, attestation_hash=attestation_hash)
    time_to_evidence = time.perf_counter() - t0
    cov = coverage([c.id for c in det.survivors], packages)

    # 6) OFFLINE VERIFY + TAMPER TEST -----------------------------------------
    # (a) internal journal: HMAC chain (shared secret)
    chain_ok, chain_reason = verify_chain(packages, hmac_key, store)
    # (b) exported artifact: the PUBLIC key only, no shared secret. This is what
    #     an external reviewer runs.
    pub_ok, pub_reason = verify_chain_public(packages, store, signer.public_key_hex())

    tamper_detected = False
    tamper_reason = "no receipt with a stored asset to tamper with"
    manifest_tamper_caught = False
    victim = next((p for p in packages if p.manifest.asset_hashes), None)
    if victim is not None:
        # asset-byte tamper (caught by both HMAC and the public-key asset re-hash)
        digest = victim.manifest.asset_hashes[0]
        original = store.get_bytes(digest)
        store.tamper(digest, original + b" X")
        ok_after, tamper_reason = verify_package(victim, hmac_key, store)
        tamper_detected = not ok_after
        store.tamper(digest, original)
        # manifest tamper (flip a signed field): the asymmetric signature must
        # catch it with the PUBLIC key alone.
        forged = victim.model_copy(deep=True)
        forged.manifest.brand_id = forged.manifest.brand_id + "_forged"
        ok_forged, _ = verify_package_public(forged, store)
        manifest_tamper_caught = not ok_forged

    # (c) OPTIONAL RFC-3161 trusted-timestamp SIDECAR over the DSSE signature of
    # the chain head (the last receipt). It shows the chain held at least this
    # many receipts at that time, so a later truncation is detectable. A network
    # call, non-deterministic by design, so it is NOT part of the signed core or
    # the determinism digest.
    sample = next((p for p in packages if p.manifest.outcome == "confirm"), packages[0] if packages else None)
    head = packages[-1] if packages else None
    ts_ok, ts_reason, ts_sidecar = None, "", None
    if anchor and head is not None:
        import base64 as _b64

        from . import anchor as _anchor
        _sig = _b64.b64decode(head.dsse_envelope["signatures"][0]["sig"])
        ts_sidecar = _anchor.timestamp(_sig)
        if ts_sidecar:
            ts_ok, ts_reason = _anchor.verify_timestamp(ts_sidecar, _sig)
        else:
            ts_ok, ts_reason = False, "no TSA reachable (offline?)"

    # 7) METRICS ----------------------------------------------------------------
    ordered = sorted(ranked_all, key=_score_key, reverse=True)
    labeled = sum(1 for c in det.candidates if c.id in labels)
    p5 = precision_at_k(ordered, labels, 5)
    p10 = precision_at_k(ordered, labels, 10)
    rec = recall(verdicts, labels)
    cut = cut_ratio(total_in, len(det.survivors))
    inj_total = sum(1 for v in verdicts if v.injection_flagged)
    inj_flips = sum(1 for v in verdicts if v.injection_flagged and v.label == "legit")

    # Deterministic fingerprint of all evidence (manifests + HMAC + Ed25519
    # signatures). Two fixture runs give the same digest; wall-clock
    # time-to-evidence varies and is not part of the claim.
    _bundle = "".join(p.model_dump_json() for p in sorted(packages, key=lambda x: x.manifest.candidate_id))
    bundle_digest = hashlib.sha256(_bundle.encode()).hexdigest()[:16]

    def _metric(value: float) -> str:
        return f"{value:.2f}" if labeled else "n/a (no labelled candidates)"

    print("\n" + "=" * 70)
    print("METRICS")
    print("=" * 70)
    rows = [
        ("candidates ingested", total_in),
        ("dropped by cheap filters", f"{dropped} (cut ratio {cut:.0%})"),
        ("classified", len(det.survivors)),
        ("precision@5", _metric(p5)),
        ("precision@10", _metric(p10)),
        ("recall vs labels", _metric(rec)),
        ("classifier", classifier.model_id),
        ("cost total / per-item (USD)", f"{total_cost:.6f} / {total_cost/max(len(verdicts),1):.6f}"),
        ("signed receipts", len(packages)),
        ("receipt coverage", f"{cov['with_receipt']}/{cov['total']}"
                             + (f" MISSING {', '.join(cov['missing'])}" if cov["missing"] else "")),
        ("latest receipt per candidate",
         ", ".join(f"{o} {n}" for o, n in cov["by_outcome"].items())),
        ("open holds (wait for a person)", len(cov["open_holds"])),
        ("time-to-evidence (s)", f"{time_to_evidence:.4f}"),
        ("injection attempts seen", inj_total),
        ("injection-induced flips", inj_flips),
        ("HMAC chain verify (internal)", "PASS" if chain_ok else f"FAIL: {chain_reason}"),
        ("PUBLIC-KEY verify (no shared secret)", "PASS" if pub_ok else f"FAIL: {pub_reason}"),
        ("asset-byte tamper detected", "PASS (FAIL as expected)" if tamper_detected else "NO"),
        ("manifest tamper caught (asymmetric)", "PASS (FAIL as expected)" if manifest_tamper_caught else "NO"),
        ("evidence bundle sha256 (determinism)", bundle_digest),
    ]
    if anchor:
        rows.append(("RFC-3161 trusted timestamp (sidecar)",
                     f"PASS - {ts_reason}" if ts_ok else f"n/a: {ts_reason}"))
    for name, val in rows:
        print(f"  {name:38s}: {val}")
    print()
    print("hmac :", chain_reason)
    print("pub  :", pub_reason)
    print("tamper:", tamper_reason)

    # Persist the chain and the cases it was signed over, plus a sample receipt
    # and its public key for the standalone verifier (what you would give an
    # external reviewer).
    records.write_receipts(store_dir, packages)
    records.write_cases(store_dir, [records.Case(candidate=det.survivor_by_id[v.candidate_id], verdict=v)
                                    for v in verdicts])
    if sample is not None:
        (store_dir / "receipt_sample.json").write_text(sample.model_dump_json(indent=2))
        (store_dir / "ed25519_pubkey.txt").write_text(sample.ed25519_pubkey or "")
        if ts_sidecar:
            (store_dir / "chain_head.rfc3161.json").write_text(json.dumps(
                {"receipts": len(packages), "manifest_hash": manifest_hash(head), "timestamp": ts_sidecar},
                indent=2))
        print(f"\nreceipts -> {store_dir}/{records.RECEIPTS} (cases: {records.CASES})")
        print("verify the chain with the public key alone:")
        print(f"  bid verify {store_dir}/{records.RECEIPTS} --pubkey {sample.ed25519_pubkey}")
    print("=" * 70)

    from .policy import policy_version as _policy_version
    return {
        "total_in": total_in,
        "dropped": dropped,
        "survivors": len(det.survivors),
        "precision_at_5": p5,
        "precision_at_10": p10,
        "recall": rec,
        "packages": len(packages),
        "receipts_by_outcome": cov["by_outcome"],
        "coverage_missing": cov["missing"],
        "open_holds": cov["open_holds"],
        "chain_ok": chain_ok,
        "pub_ok": pub_ok,
        "tamper_detected": tamper_detected,
        "manifest_tamper_caught": manifest_tamper_caught,
        "injection_flips": inj_flips,
        # reproducible-learning anchors: same config -> same policy_version, and
        # the same inputs -> byte-identical signed bundle. replay asserts both.
        "policy_version": _policy_version(classifier.model_id),
        "bundle_digest": bundle_digest,
    }


def _score_key(v: Verdict):
    from .rank import _LABEL_RANK

    return (_LABEL_RANK.get(v.label, 0), v.confidence, v.candidate_id)


def load_dotenv() -> None:
    """Load ./.env into os.environ if present (never overrides an existing var)."""
    import os

    env = Path(".env")
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Brand-impersonation detection pipeline")
    parser.add_argument("--run-dir", "--store", dest="run_dir", default=None,
                        help="run directory: receipts, cases and assets (default: $BID_DATA_DIR/pipeline)")
    parser.add_argument("--hmac-key", default=DEFAULT_HMAC_KEY, help="HMAC key for the evidence chain")
    parser.add_argument("--k", type=int, default=10, help="top-k per brand for the queue")
    parser.add_argument("--brands", type=Path, default=None,
                        help="brands file (default: bundled fixtures); logo paths are relative to it")
    parser.add_argument("--sensors", choices=("fixtures", "broad"), default="fixtures",
                        help="broad adds live App Store, look-alike domain and certificate-log sensors")
    parser.add_argument("--live", action="store_true", help="use the hosted classifier (needs BID_LLM_API_KEY, or OPENROUTER_API_KEY for openrouter.ai)")
    parser.add_argument("--model", default=None, help="hosted model id for --live")
    parser.add_argument("--recheck", default=None,
                        help="recheck model of a different family: 'signals' offline, a hosted id with --live")
    parser.add_argument("--clock", choices=("fixed", "utc"), default="fixed",
                        help="fixed: deterministic fixture time; utc: the current time")
    parser.add_argument("--policy-pack", default=None, help="policy pack recorded in every receipt (bid packs list)")
    parser.add_argument("--profile", default=None,
                        help="deployment profile (default, sovereign or a path); its attestation is "
                             "recorded in the governance journal and bound into every receipt")
    parser.add_argument("--deployment-id", default="bid-run", help="deployment name in the attestation record")
    parser.add_argument("--journal", type=Path, default=None,
                        help="governance journal (default: $BID_DATA_DIR/governance.jsonl)")
    parser.add_argument("--anchor", action="store_true", help="add a real RFC-3161 trusted-timestamp sidecar (network)")
    parser.add_argument("--embeddings", action="store_true", help="enable the CLIP semantic-logo tier (needs fastembed)")
    args = parser.parse_args(argv)

    if args.live or args.sensors == "broad":
        load_dotenv()
    run_dir = Path(args.run_dir) if args.run_dir else paths.store_dir("pipeline")
    now = datetime.now(timezone.utc) if args.clock == "utc" else None

    from .governance import GovernanceJournal
    journal = GovernanceJournal(args.journal or paths.data_dir() / "governance.jsonl",
                                hmac_key=args.hmac_key, dsse=Ed25519Dsse())
    if journal.is_halted():
        print("The queue is halted (see `bid governance status`); no decisions are signed until it is resumed.")
        return 3

    pack_ref = None
    if args.policy_pack:
        from .packs import load_pack, pack_ref as _ref
        pack_ref = _ref(load_pack(args.policy_pack))
    attestation_hash = None
    if args.profile:
        from .attestation import load_profile, put_in_force
        attestation_hash = put_in_force(load_profile(args.profile), args.deployment_id,
                                        journal, now or FIXED_NOW)

    result = run(run_dir, args.hmac_key, args.k, live=args.live, model=args.model, anchor=args.anchor,
                 embeddings=args.embeddings, recheck_model=args.recheck, sensors=args.sensors,
                 brands_file=args.brands, now=now, policy_pack=pack_ref, attestation_hash=attestation_hash)

    dev = [name for name, on in (("BID_HMAC_KEY", args.hmac_key == DEV_HMAC_KEY),
                                 ("BID_ED25519_SEED", DEFAULT_ED25519_SEED == DEV_ED25519_SEED)) if on]
    if dev:
        print(f"Development signing keys in use ({', '.join(dev)}): anyone can sign under them, "
              "so these receipts are for trying the tool out, not evidence.")

    # Non-zero exit if any load-bearing check fails, so CI can gate on it.
    ok = all([
        result["chain_ok"],
        result["pub_ok"],
        result["tamper_detected"],
        result["manifest_tamper_caught"],
        not result["coverage_missing"],
    ])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
