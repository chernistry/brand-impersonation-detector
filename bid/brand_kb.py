"""
Brand Knowledge Base - a keyless alias + official-domain lookup.

Reference-based detection relies on a simple invariant that is more robust than
pure visual similarity:

    An account or page that presents itself as brand X but whose link domain is
    NOT one of brand X's legitimate domains is impersonation. Real brands link to
    their own domains, so this rule is high-precision.

It needs a brand knowledge base: multiple ALIASES (alternate names) plus
legitimate DOMAINS per brand. This module builds one from Wikidata, keyless:
Wikidata Search + EntityData REST (no account, just an identifying User-Agent)
gives, per brand: aliases (alternate names) and the official website domain(s).
The result is cached to fixtures/brand_kb.json so the offline pipeline stays
deterministic and needs no network. Fixture brands are fictional and curated by
hand; for real brands:

    python -m bid.brand_kb build "<Brand Name>" "<Another Brand>"

This module intentionally does NOT fetch logos (Wikidata logos are SVG and would
need a rasterization dependency). The alias + legit-domain signals are text-based.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import paths
from .domains import registrable
from .useragent import user_agent

_WD_API = "https://www.wikidata.org/w/api.php"
_WD_ENTITY = "https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
_UA = {"User-Agent": user_agent("brand-impersonation research")}
# The KB that describes the bundled example brands. A deployment keeps its own
# brand_kb.json next to its brands file (bid run --brands DIR/brands.json reads
# DIR/brand_kb.json); `bid brand-kb build --kb DIR/brand_kb.json` writes it.
BUNDLED_KB = paths.FIXTURES / "brand_kb.json"


def _domains_from_websites(sites: list[str]) -> list[str]:
    out = []
    for s in sites:
        d = registrable(s)
        if d and d not in out:
            out.append(d)
    return out


def build_brand(name: str, langs=("en",), timeout: float = 25.0) -> dict | None:
    """Query Wikidata (keyless) for a brand's aliases + official domains."""
    from . import net

    with net.client("brand_kb", timeout=timeout, headers=_UA) as c:
        s = c.get(_WD_API, params={
            "action": "wbsearchentities", "search": name, "language": "en",
            "type": "item", "format": "json", "limit": 1,
        }).json()
        hits = s.get("search") or []
        if not hits:
            return None
        qid = hits[0]["id"]
        ent = c.get(_WD_ENTITY.format(qid=qid)).json()["entities"][qid]

    aliases: list[str] = []
    labels = ent.get("labels", {})
    for lang in langs:
        if lang in labels:
            aliases.append(labels[lang]["value"])
    al = ent.get("aliases", {})
    for lang in langs:
        for a in al.get(lang, []):
            if a["value"] not in aliases:
                aliases.append(a["value"])
    # de-dup, drop bare-domain aliases into domains
    claims = ent.get("claims", {})
    sites = []
    for cl in claims.get("P856", []):  # official website
        v = cl.get("mainsnak", {}).get("datavalue", {}).get("value")
        if isinstance(v, str):
            sites.append(v)
    domains = _domains_from_websites(sites)
    # aliases that are themselves domains -> add to domains, keep as alias too
    for a in list(aliases):
        if "." in a and " " not in a:
            d = registrable(a)
            if d and d not in domains:
                domains.append(d)
    clean_aliases = [a for a in aliases if a and "." not in a]
    return {
        "name": name, "qid": qid,
        "aliases": clean_aliases,
        "domains": domains,
        "description": (ent.get("descriptions", {}).get("en", {}) or {}).get("value", ""),
    }


def load_cache(path: Path = BUNDLED_KB) -> dict:
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_cache(kb: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(kb, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def brand_intention_signals(candidate, brand_entry: dict) -> dict:
    """Brand-intention signals for one candidate against one brand KB entry.

    - alias_in_text: an official alias appears in the candidate handle/name/bio
      (textual brand intention, catches logo-less impersonation).
    - domain_is_legit: candidate link-in-bio domain IS an official brand domain.
    - domain_intention_mismatch: presents brand intention but domain is NOT legit
      = the brand-intention invariant. High-precision impersonation signal.
    """
    blob = " ".join(str(x or "").lower() for x in (
        candidate.handle, candidate.display_name, candidate.bio))
    aliases = [a.lower() for a in brand_entry.get("aliases", [])]
    alias_hit = any(a and a in blob for a in aliases)
    legit = set(brand_entry.get("domains", []))
    cand_dom = registrable(candidate.link_in_bio_url) if candidate.link_in_bio_url else ""
    domain_is_legit = bool(cand_dom) and cand_dom in legit
    # brand intention present if an alias matches (text) - logo/handle handled elsewhere
    mismatch = bool(alias_hit and cand_dom and not domain_is_legit)
    return {
        "alias_in_text": alias_hit,
        "candidate_domain": cand_dom,
        "domain_is_legit": domain_is_legit,
        "domain_intention_mismatch": mismatch,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the keyless brand knowledge base")
    ap.add_argument("cmd", choices=["build", "show"])
    ap.add_argument("names", nargs="*")
    ap.add_argument("--kb", type=Path, default=BUNDLED_KB,
                    help="KB file; build needs one next to your brands file (default: the bundled example)")
    args = ap.parse_args(argv)
    if args.cmd == "build" and args.kb.resolve().is_relative_to(paths.PACKAGE_DIR):
        ap.error("build writes the KB: pass --kb DIR/brand_kb.json next to your brands file "
                 "(the bundled example KB is not overwritten)")
    kb = load_cache(args.kb)
    if args.cmd == "show":
        print(json.dumps(kb, indent=2, ensure_ascii=False))
        return 0
    for name in args.names:
        entry = build_brand(name)
        if entry:
            kb[name] = entry
            print(f"OK  {name:26s} qid={entry['qid']}  aliases={len(entry['aliases'])}  domains={entry['domains']}")
        else:
            print(f"--  {name}: not found on Wikidata")
    save_cache(kb, args.kb)
    print(f"\nsaved {len(kb)} brands -> {args.kb}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
