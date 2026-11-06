"""
Keyless, token-optional OSINT reverse-pivot and campaign clustering.

Given a suspect domain (e.g. a lookalike link-in-bio), expand to sibling phishing
infrastructure and cluster it into a campaign. Every edge cites its source, so the
campaign graph is itself auditable. Sources, in preference order:

  KEYLESS (no account): crt.sh certificate-transparency SANs, CertSpotter CT
    issuances (a crt.sh complement/fallback), dns.google DoH resolution, urlscan.io
    search (existing scans of the domain), plus best-effort feed lookups - PhishStats
    URL search, the Phishing.Database and SANS ISC suspicious-domain lists, and the
    Spamhaus ASN-DROP list of rogue-hosting networks.
  TOKEN (optional, read from env, never committed): Shodan http.favicon.hash
    search (the favicon-reuse pivot, key-gated) via SHODAN_API_KEY.

Every fetch goes through bid.net under component "enrich" (the favicon fetch, which
contacts the suspect host itself, under "enrich:favicon"), so a deployment profile
can restrict which of these hosts may be contacted.

Determinism notes: this is a live-network, best-effort module (crt.sh 502s,
urlscan rate-limits) - responses are cached so a re-run is stable and free. It
uses urlscan SEARCH (read existing scans), never a public submission, so it does
not tip an adversary. ip-api is intentionally NOT used (non-commercial + HTTP).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from . import net, paths
from .domains import registrable
from .net import EgressDenied
from .useragent import user_agent

_CACHE: Path | None = None  # tests override; default paths.cache_dir("enrich")
_UA = {"User-Agent": user_agent()}


def _cached(key: str, fn):
    cache = _CACHE or paths.cache_dir("enrich")
    cache.mkdir(parents=True, exist_ok=True)
    p = cache / (key.replace("/", "_").replace(":", "_")[:120] + ".json")
    if p.exists():
        return json.loads(p.read_text())
    try:
        val = fn()
    except EgressDenied as e:
        # A policy refusal says nothing about the source, so it is not cached: a later
        # run under a wider deployment profile must still be able to fetch.
        return {"_error": f"{type(e).__name__}: {e}"}
    except Exception as e:
        val = {"_error": f"{type(e).__name__}: {e}"}
    p.write_text(json.dumps(val))
    return val


def crtsh_sans(domain: str, limit: int = 40) -> list[dict]:
    """Sibling names sharing certificates (CT logs, keyless)."""
    def _f():
        r = net.get("enrich", f"https://crt.sh/?q=%25.{domain}&output=json&exclude=expired",
                    headers=_UA, timeout=20)  # crt.sh 502s often; fail fast, cache covers re-runs
        return r.json()
    data = _cached(f"crt_{domain}", _f)
    if isinstance(data, dict):
        return []
    names = set()
    for row in data[:400]:
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lstrip("*.").lower()
            if n and "@" not in n:
                names.add(n)
    return [{"name": n, "source": "crt.sh", "relation": "shared_cert"} for n in sorted(names)[:limit]]


def resolve(domain: str) -> list[str]:
    """Resolve A records via dns.google DoH (keyless)."""
    def _f():
        return net.get("enrich", "https://dns.google/resolve", params={"name": domain, "type": "A"},
                       headers=_UA, timeout=15).json()
    j = _cached(f"dns_{domain}", _f)
    return [a["data"] for a in (j.get("Answer") or []) if a.get("type") == 1]


def urlscan_search(domain: str, limit: int = 10) -> list[dict]:
    """Existing urlscan scans of the domain (keyless search, no submission)."""
    def _f():
        return net.get("enrich", "https://urlscan.io/api/v1/search/",
                       params={"q": f"domain:{domain}", "size": limit}, headers=_UA, timeout=25).json()
    j = _cached(f"urlscan_{domain}", _f)
    out = []
    for r in (j.get("results") or [])[:limit]:
        page = r.get("page", {})
        out.append({"url": page.get("url"), "ip": page.get("ip"), "asn": page.get("asn"),
                    "source": "urlscan", "relation": "observed_scan"})
    return out


_DOMAIN_RE = None


def valid_domain(domain: str) -> bool:
    """Only allow sane registrable domains into the OSINT calls (no query injection)."""
    import re
    global _DOMAIN_RE
    if _DOMAIN_RE is None:
        _DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
    return bool(_DOMAIN_RE.match((domain or "").lower()))


def rdap(domain: str) -> dict:
    """Registrant + registration date via rdap.org (keyless). Domain age = the single
    strongest phishing feature; a freshly-registered lookalike is a top signal."""
    def _f():
        r = net.get("enrich", f"https://rdap.org/domain/{domain}",
                    headers={**_UA, "Accept": "application/rdap+json"}, timeout=25,
                    follow_redirects=True)
        return r.json()
    j = _cached(f"rdap_{domain}", _f)
    if not isinstance(j, dict) or "_error" in j:
        return {"registered": None, "registrar": None, "source": "rdap.org"}
    reg = None
    for ev in j.get("events", []):
        if ev.get("eventAction") == "registration":
            reg = ev.get("eventDate")
    registrar = None
    for e in j.get("entities", []):
        if "registrar" in (e.get("roles") or []):
            for v in (e.get("vcardArray", [[], []])[1] or []):
                if v and v[0] == "fn":
                    registrar = v[3]
    return {"registered": reg, "registrar": registrar, "source": "rdap.org"}


def ip_asn(ip: str) -> dict:
    """IP -> ASN + prefix + country via Team-Cymru DNS (over dns.google DoH, keyless).
    Lets us classify cloud/shared vs dedicated hosting - so we NEVER cluster a
    campaign on a shared-cloud IP alone."""
    def _f():
        octets = ".".join(reversed(ip.split(".")))
        return net.get("enrich", "https://dns.google/resolve",
                       params={"name": f"{octets}.origin.asn.cymru.com", "type": "TXT"},
                       headers=_UA, timeout=15).json()
    j = _cached(f"asn_{ip}", _f)
    for a in (j.get("Answer") or []):
        txt = (a.get("data") or "").strip('"')
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) >= 3:
            return {"asn": parts[0], "prefix": parts[1], "cc": parts[2], "source": "cymru"}
    return {"asn": None, "source": "cymru"}


def openphish_hits(domain: str, limit: int = 3) -> list[str]:
    """Check the keyless OpenPhish community feed for URLs on this domain."""
    def _f():
        return {"text": net.get("enrich", "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
                                headers=_UA, timeout=20, follow_redirects=True).text}
    j = _cached("openphish_feed", _f)
    text = j.get("text", "") if isinstance(j, dict) else ""
    return [u for u in text.splitlines() if domain in u][:limit]


def shodan_favicon_siblings(favicon_mmh3: int, limit: int = 20) -> list[dict]:
    """Hosts sharing a favicon (Shodan http.favicon.hash). Needs SHODAN_API_KEY (env)."""
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return []

    def _f():
        return net.get("enrich", "https://api.shodan.io/shodan/host/search",
                       params={"key": key, "query": f"http.favicon.hash:{favicon_mmh3}", "limit": limit},
                       timeout=30).json()
    j = _cached(f"shodan_fav_{favicon_mmh3}", _f)
    out = []
    for m in (j.get("matches") or [])[:limit]:
        out.append({"ip": m.get("ip_str"), "hostnames": m.get("hostnames"), "asn": m.get("asn"),
                    "source": "shodan", "relation": "shared_favicon"})
    return out


def _is_public_host(host: str) -> bool:
    """SSRF guard: resolve the host and reject private/loopback/link-local/reserved IPs."""
    import ipaddress
    import socket

    try:
        for _, _, _, _, sa in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
            ip = ipaddress.ip_address(sa[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


def favicon_mmh3(domain: str) -> int | None:
    """Favicon Shodan-style mmh3 hash. SSRF-guarded (public IP, no redirects, https only).

    Only fetched when a Shodan key is present, since the hash is only used for the
    Shodan favicon pivot; otherwise there is no reason to reach out to the domain.
    """
    if not (os.environ.get("SHODAN_API_KEY")):
        return None
    host = registrable(domain) or domain
    if not _is_public_host(domain.split("://")[-1].split("/")[0]):
        return None
    try:
        import mmh3

        r = net.get("enrich:favicon", f"https://{host}/favicon.ico", headers=_UA, timeout=15, follow_redirects=False)
        if r.status_code != 200 or not r.content:
            return None
        return mmh3.hash(base64.encodebytes(r.content))
    except Exception:
        return None


# --- additional keyless threat-intel sources (best-effort, cached, SSRF-guarded) ---
# Each fetch is host-guarded before it leaves the box, cached to the same on-disk
# cache as the sources above (so re-runs are free), and wrapped so a network/parse
# failure degrades to empty/None instead of raising. All are read-only lookups.

_FEED_SETS: dict[str, tuple[int, frozenset]] = {}


def _norm_asn(asn) -> int | None:
    """Normalise 'AS6725' / '6725' / 6725 -> 6725; anything else -> None."""
    try:
        s = str(asn).strip().upper()
        if s.startswith("AS"):
            s = s[2:]
        return int(s)
    except Exception:
        return None


def _feed_text(cache_key: str, url: str, host: str) -> str:
    """Fetch a plain-text / NDJSON feed once, cache to disk, return its text ("" on failure).

    The public-host guard runs inside the cached closure, so a cache hit never touches
    the network and an SSRF-unsafe host fails closed to empty text.
    """
    def _f():
        if not _is_public_host(host):
            raise RuntimeError("non-public host")
        r = net.get("enrich", url, headers=_UA, timeout=15, follow_redirects=True)
        r.raise_for_status()  # a moved/retired feed returns a 404 HTML page - do not parse it as data
        return {"text": r.text}
    j = _cached(cache_key, _f)
    return j.get("text", "") if isinstance(j, dict) else ""


def _feed_domain_set(cache_key: str, url: str, host: str) -> frozenset:
    """Domain-membership set for a text feed. Cached to disk (fetch once) and memoised
    in-process (built once), so per-domain lookups are O(1) set membership."""
    text = _feed_text(cache_key, url, host)
    cached = _FEED_SETS.get(cache_key)
    if cached is None or cached[0] != len(text):
        names = frozenset(
            ln.strip().lower().lstrip("*.").rstrip(".")
            for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        )
        _FEED_SETS[cache_key] = (len(text), names)
    return _FEED_SETS[cache_key][1]


def certspotter_issuances(domain: str, limit: int = 40) -> list[dict]:
    """Sibling names from CertSpotter CT issuances (keyless). A complement/fallback to
    crt.sh: same shared-cert relation, different CT aggregator, so one covering the other
    when crt.sh 502s. Returns distinct dns_names as sibling records."""
    if not valid_domain(domain):
        return []

    def _f():
        if not _is_public_host("api.certspotter.com"):
            raise RuntimeError("non-public host")
        return net.get(
            "enrich",
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            headers=_UA, timeout=15,
        ).json()
    data = _cached(f"certspotter_{domain}", _f)
    if isinstance(data, dict):  # error sentinel or unexpected shape
        return []
    names = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        for n in (row.get("dns_names") or []):
            n = (n or "").strip().lstrip("*.").lower()
            if n and "@" not in n:
                names.add(n)
    return [{"name": n, "source": "certspotter", "relation": "shared_cert"} for n in sorted(names)[:limit]]


def phishstats_hits(term: str, limit: int = 20) -> list[dict]:
    """Recent phishing URLs whose URL contains `term`, via the keyless PhishStats API.
    Returns a compact [{url, ip, countrycode}] (capped). `term` is sanitised before it
    goes into the _where clause (no filter injection)."""
    import re

    t = (term or "").lower()
    if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,79}$", t):
        return []

    def _f():
        if not _is_public_host("api.phishstats.info"):
            raise RuntimeError("non-public host")
        return net.get(
            "enrich",
            "https://api.phishstats.info/api/phishing",
            params={"_where": f"(url,like,~{t}~)", "_sort": "-id", "_size": 50},
            headers=_UA, timeout=15,
        ).json()
    data = _cached(f"phishstats_{t}", _f)
    if isinstance(data, dict):
        return []
    out = []
    for r in data[:limit]:
        if isinstance(r, dict):
            out.append({"url": r.get("url"), "ip": r.get("ip"), "countrycode": r.get("countrycode")})
    return out


def phishing_database_hit(domain: str) -> dict:
    """Membership check against the Phishing.Database ACTIVE domains feed (keyless).
    The feed is fetched once and cached; the lookup itself is O(1) set membership.
    Returns {"hit": bool, "feed": ..., "source": ...}."""
    if not valid_domain(domain):
        return {"hit": False, "feed": None, "source": "phishing.database"}
    url = ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
           "master/phishing-domains-ACTIVE.txt")
    names = _feed_domain_set("phishdb_active", url, "raw.githubusercontent.com")
    return {"hit": domain.lower() in names, "feed": "phishing-domains-ACTIVE",
            "source": "phishing.database"}


def dshield_suspicious(domain: str) -> bool:
    """Membership check against the SANS ISC low-sensitivity suspicious-domains feed
    (keyless). Fetched once and cached; lookup is O(1) set membership."""
    if not valid_domain(domain):
        return False
    names = _feed_domain_set(
        "dshield_low", "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt", "isc.sans.edu")
    return domain.lower() in names


def _spamhaus_asn_set() -> frozenset:
    """ASN set from the Spamhaus ASN-DROP list. Cached to disk (fetch once) and memoised
    in-process (parsed once)."""
    text = _feed_text("spamhaus_asndrop", "https://www.spamhaus.org/drop/asndrop.json",
                      "www.spamhaus.org")
    cached = _FEED_SETS.get("spamhaus_asndrop")
    if cached is None or cached[0] != len(text):
        asns = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                n = _norm_asn(json.loads(line).get("asn"))
            except Exception:
                n = None
            if n is not None:
                asns.add(n)
        _FEED_SETS["spamhaus_asndrop"] = (len(text), frozenset(asns))
    return _FEED_SETS["spamhaus_asndrop"][1]


def spamhaus_drop_asn(asn) -> bool:
    """True if the ASN is on the Spamhaus ASN-DROP list (networks whose whole space is
    rogue-hosting). Lets us flag campaign infra sitting on a known-bad AS (keyless)."""
    want = _norm_asn(asn)
    if want is None:
        return False
    return want in _spamhaus_asn_set()


def pivot(seed_domain: str) -> dict:
    """Reverse-pivot a seed domain into sibling infra + a simple shared-IP cluster."""
    seed = registrable(seed_domain)
    if not valid_domain(seed):
        return {"seed": seed, "error": "invalid domain", "edges": [], "node_count": 0}
    nodes = {seed: {"kind": "seed"}}
    edges = []
    # CT-log siblings: crt.sh, plus CertSpotter as a complement/fallback (same
    # shared-cert relation, different aggregator, so one covers the other's outages).
    for s in crtsh_sans(seed):
        nodes.setdefault(s["name"], {"kind": "domain"})
        edges.append((seed, s["name"], s["relation"], s["source"]))
    certspotter_siblings = certspotter_issuances(seed)
    for s in certspotter_siblings:
        nodes.setdefault(s["name"], {"kind": "domain"})
        edges.append((seed, s["name"], s["relation"], s["source"]))
    # resolve seed + a few siblings -> IPs
    ip_to_domains: dict[str, set] = {}
    for d in list(nodes)[:12]:
        for ip in resolve(d):
            ip_to_domains.setdefault(ip, set()).add(d)
            nodes.setdefault(ip, {"kind": "ip"})
            edges.append((d, ip, "resolves_to", "dns.google"))
    # co-hosting edges (shared IP = campaign signal, but NEVER cluster on shared cloud IP alone)
    for ip, doms in ip_to_domains.items():
        if len(doms) >= 2:
            for d in doms:
                edges.append((d, ip, "co_hosted", "dns.google"))
    # favicon pivot (token)
    fmh = favicon_mmh3(seed)
    fav_sibs = shodan_favicon_siblings(fmh) if fmh is not None else []
    for h in fav_sibs:
        ip = h.get("ip")
        if ip:
            nodes.setdefault(ip, {"kind": "ip"})
            edges.append((seed, ip, "shared_favicon", "shodan"))
    # keyless enrichment: domain age (RDAP), ASN cloud-vs-dedicated (Cymru), OpenPhish
    whois = rdap(seed)
    seed_ips = [n for n, m in nodes.items() if m.get("kind") == "ip"]
    asns = {ip: ip_asn(ip) for ip in seed_ips[:4]}
    obs = urlscan_search(seed)
    # additional keyless feed lookups: any ASN carrying this infra that is on the
    # Spamhaus ASN-DROP list is a strong rogue-hosting signal.
    drop_asns = sorted({v.get("asn") for v in asns.values() if v.get("asn")})
    asn_drop = {a: spamhaus_drop_asn(a) for a in drop_asns}
    return {
        "seed": seed,
        "favicon_mmh3": fmh,
        "node_count": len(nodes),
        "edges": edges,
        "registered": whois.get("registered"),
        "registrar": whois.get("registrar"),
        "asn": asns,
        "openphish_hits": openphish_hits(seed),
        "shared_ip_clusters": {ip: sorted(d) for ip, d in ip_to_domains.items() if len(d) >= 2},
        "favicon_siblings": fav_sibs,
        "urlscan_observed": obs,
        "certspotter_siblings": certspotter_siblings,
        "phishstats": phishstats_hits(seed),
        "phishing_db": phishing_database_hit(seed),
        "asn_drop": asn_drop,
        "dshield": dshield_suspicious(seed),
    }
