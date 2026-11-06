"""
Live example of a keyless sensor: the App Store via the iTunes Search API.

    python -m bid.demo_itunes --brand "WrenvalePay"
    python -m bid.demo_itunes --brand "Covelle Pay" --live      # + real LLM classify

It hits the live iTunes Search API (no key, no account), downloads and
perceptual-hashes the real app icons, and runs the same cheap-filter + classify
+ rank pipeline used by the offline run. The top-ranked result is used as the
brand reference (a heuristic - usually the official app), and every other
app is scored for handle/icon similarity to it.

Nothing here creates or touches any account.
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
from .sensors.itunes import ITunesSearchSensor
from .storage import ContentStore


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live iTunes sensor example")
    ap.add_argument("--brand", default="WrenvalePay", help="brand name to search the App Store for")
    ap.add_argument("--country", default="US")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--live", action="store_true", help="classify with the real OpenRouter model")
    args = ap.parse_args(argv)
    if args.live:
        load_dotenv()

    store = ContentStore(paths.store_dir("demo-itunes"))
    sensor = ITunesSearchSensor(country=args.country, limit=args.limit)

    # A provisional brand (handles/logo filled from the top result below).
    brand = Brand(
        id="live", name=args.brand, official_handles=[args.brand.lower().replace(" ", "")],
        official_logo_hashes=[], regions=[args.country],
    )

    print(f"Querying iTunes Search API for {args.brand!r} ({args.country}) ...")
    obs = list(sensor.scan(brand, since=FIXED_NOW))
    print("health:", sensor.health())
    if not obs:
        print("No results (offline or no matches). Nothing to classify.")
        return 0

    candidates = [normalize(o, brand, store) for o in obs]
    # Use the FIRST result as the brand reference (usually the official app).
    ref = candidates[0]
    brand.official_handles = [ (ref.handle or args.brand).lower().replace(" ", "") ]
    brand.official_logo_hashes = [a.phash for a in ref.assets if a.phash]
    print(f"\nReference (assumed official): {ref.display_name!r} by {ref.handle!r}")
    print(f"apps found: {len(candidates)}  reference-logo-phash: "
          f"{brand.official_logo_hashes[0] if brand.official_logo_hashes else 'n/a'}\n")

    classifier = build_classifier(set(), store=store, live=args.live)
    print("classifier:", classifier.model_id, "\n")

    rows = []
    for c in candidates[1:]:  # skip the reference itself
        signals, keep = stage_a(c, brand, set())
        if not keep:
            continue
        v = classifier.classify(c, brand)
        rows.append((v, c, signals))

    ranked = rank([v for v, _, _ in rows], k=args.limit)
    print("-" * 78)
    print(f"STORE APPS SCORED vs {args.brand!r} (handle+icon similarity)")
    print("-" * 78)
    cand_by_id = {c.id: c for _, c, _ in rows}
    sig_by_id = {v.candidate_id: s for v, _, s in rows}
    for i, v in enumerate(ranked, 1):
        c = cand_by_id[v.candidate_id]
        s = sig_by_id[v.candidate_id]
        print(f"{i:2}. {v.label:13s} conf={v.confidence:.2f}  {c.display_name!r} by {c.handle!r}")
        print(f"     handle_dist={s.handle_edit_distance} logo_phash_hamming={s.logo_phash_hamming}")
    print("-" * 78)
    print("Note: reference=top result is a heuristic. For real use the brand's "
          "official handle + logo are known inputs, not inferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
