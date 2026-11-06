"""
Live example of the keyless + token OSINT reverse-pivot / campaign clustering.

    python -m bid.demo_enrich wrenvalepay.test
    SHODAN_API_KEY=... python -m bid.demo_enrich <suspect-domain>

Best-effort, cached, read-only (urlscan search, not submission). Shows how a seed
domain expands into sibling infrastructure that a campaign is built from. Tokens
are read from the environment and never written to the repo.
"""
from __future__ import annotations

import argparse

from .enrich import pivot


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OSINT reverse-pivot example")
    ap.add_argument("domain")
    args = ap.parse_args(argv)
    r = pivot(args.domain)
    print(f"seed: {r['seed']}   favicon_mmh3: {r['favicon_mmh3']}   nodes: {r['node_count']}   edges: {len(r['edges'])}")
    print("\nrelation breakdown:")
    by_rel: dict[str, int] = {}
    for _, _, rel, _src in r["edges"]:
        by_rel[rel] = by_rel.get(rel, 0) + 1
    for rel, n in sorted(by_rel.items()):
        print(f"  {rel:16s} {n}")
    if r["shared_ip_clusters"]:
        print("\nshared-IP clusters (co-hosted = campaign signal):")
        for ip, doms in list(r["shared_ip_clusters"].items())[:5]:
            print(f"  {ip}: {', '.join(doms[:6])}")
    if r["favicon_siblings"]:
        print(f"\nfavicon-reuse siblings (Shodan): {len(r['favicon_siblings'])} hosts")
        for h in r["favicon_siblings"][:6]:
            print(f"  {h.get('ip')}  {h.get('hostnames')}")
    if r["urlscan_observed"]:
        print(f"\nurlscan observed: {len(r['urlscan_observed'])} scans")
        for o in r["urlscan_observed"][:4]:
            print(f"  {o.get('url')}  ip={o.get('ip')}")
    print("\nNote: best-effort keyless OSINT (crt.sh/dns/urlscan) + optional Shodan favicon. "
          "Never cluster on shared cloud IP alone. Read-only; no urlscan submission.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
