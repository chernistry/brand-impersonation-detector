"""
Live example of the two keyless domain sensors: typosquat + CT-log.

    python -m bid.demo_sensors --brand WrenvalePay --domain wrenvalepay.test
    python -m bid.demo_sensors --brand WrenvalePay --domain wrenvalepay.test --live      # + real LLM
    python -m bid.demo_sensors --brand WrenvalePay --domain wrenvalepay.test --tranco     # + live Tranco allowlist

Both sensors hit the live internet with no key and no account:
  - dns_typosquat: dnstwist permutations of the brand domain, kept only if they
    RESOLVE via dns.google DoH (registered lookalikes).
  - ct_log:        crt.sh certificate-transparency search for the brand string,
    recent certs on non-official / non-allowlisted domains.

It runs the same downstream stages as the offline pipeline (normalize -> cheap
filters -> classify -> rank), so a domain candidate is treated identically to a
social-profile candidate. Read-only and cached.
"""
from __future__ import annotations

import argparse

from . import paths
from .classify import build_classifier
from .filters import stage_a
from .models import Brand
from .normalize import normalize
from .rank import rank
from .run_pipeline import FIXED_NOW, load_dotenv
from .sensors.allowlist import Allowlist
from .sensors.ct_logs import CTLogSensor
from .sensors.typosquat import TyposquatSensor
from .storage import ContentStore


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live typosquat + CT-log sensor example")
    ap.add_argument("--brand", default="WrenvalePay")
    ap.add_argument("--domain", default="wrenvalepay.test", help="official brand domain (seed)")
    ap.add_argument("--handles", default="", help="comma-separated official handles")
    ap.add_argument("--max-resolving", type=int, default=25)
    ap.add_argument("--lookback-days", type=int, default=30)
    ap.add_argument("--live", action="store_true", help="classify with the real OpenRouter model")
    ap.add_argument("--tranco", action="store_true", help="overlay the live Tranco top-N allowlist")
    args = ap.parse_args(argv)
    if args.live:
        load_dotenv()

    store = ContentStore(paths.store_dir("demo-sensors"))
    allow = Allowlist(load_live=args.tranco, extra={args.domain})
    print("allowlist:", allow.health())

    official_reg = args.domain.lower()
    # The brand's own domain SLD is treated as an official "handle" so the cheap
    # handle-distance filter recognises a typosquat SLD as brand-adjacent.
    dom_sld = official_reg.split(".")[0]
    handles = [h.strip() for h in args.handles.split(",") if h.strip()] or [dom_sld]
    handles = list(dict.fromkeys(handles + [dom_sld]))

    brand = Brand(
        id="live", name=args.brand, official_handles=handles,
        official_logo_hashes=[], regions=["GLOBAL"],
        aliases=[args.brand], official_domains=[official_reg],
    )

    sensors = [
        TyposquatSensor(allowlist=allow, max_resolving=args.max_resolving),
        CTLogSensor(allowlist=allow, lookback_days=args.lookback_days),
    ]

    all_obs = []
    for s in sensors:
        print(f"\nscanning with {s.name()} ...")
        obs = list(s.scan(brand, since=FIXED_NOW))
        print("  health:", s.health())
        all_obs.extend(obs)

    if not all_obs:
        print("\nNo observations (offline, no matches, or crt.sh 502). Nothing to classify.")
        return 0

    candidates = [normalize(o, brand, store) for o in all_obs]
    classifier = build_classifier(set(), store=store, live=args.live)
    print(f"\nclassifier: {classifier.model_id}")

    rows = []
    for c in candidates:
        signals, keep = stage_a(c, brand, set())
        if not keep:
            continue
        v = classifier.classify(c, brand)
        rows.append((v, c, signals))

    ranked = rank([v for v, _, _ in rows], k=len(rows))
    cand_by_id = {c.id: c for _, c, _ in rows}
    sig_by_id = {v.candidate_id: s for v, _, s in rows}

    print("-" * 82)
    print(f"DOMAIN CANDIDATES SCORED vs {args.brand!r}  "
          f"({len(candidates)} observed, {len(rows)} survived cheap filters)")
    print("-" * 82)
    for i, v in enumerate(ranked, 1):
        c = cand_by_id[v.candidate_id]
        s = sig_by_id[v.candidate_id]
        print(f"{i:2}. {v.label:13s} conf={v.confidence:.2f}  {c.platform:13s} {c.handle}")
        print(f"     handle_dist={s.handle_edit_distance} "
              f"alias_in_text={s.alias_in_text} domain_mismatch={s.domain_intention_mismatch}")
        print(f"     {c.bio}")
    print("-" * 82)
    print("Keyless, read-only, cached. Registered/certified lookalikes only. "
          "Domains are infrastructure, not PII.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
