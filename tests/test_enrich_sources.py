"""
Offline invariants for the additional keyless threat-intel sources in bid.enrich.

Network is never touched: every test either pre-seeds the on-disk cache (so the
cached closure is skipped) or forces the live fetch to raise. This pins:
  - the parse/return shape of each new source,
  - input guards (invalid domain / injection-y term -> empty, no fetch),
  - graceful degradation to empty/None/False when the network is down,
  - pivot() only ADDS keys and stays intact offline.
"""
import json

import pytest

import bid.enrich as enrich


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Point enrich's disk cache at a temp dir and clear the in-process feed memo."""
    monkeypatch.setattr(enrich, "_CACHE", tmp_path)
    enrich._FEED_SETS.clear()
    return tmp_path


def _seed(cache_dir, key, value):
    """Write a cache entry exactly where enrich._cached would look for it."""
    p = cache_dir / (key.replace("/", "_").replace(":", "_")[:120] + ".json")
    p.write_text(json.dumps(value))


def _no_network(monkeypatch):
    """Make any live fetch raise, so functions must degrade (public host allowed so
    we exercise the fetch path, not the SSRF short-circuit). Every enrich fetch goes
    through bid.net.get, so that is the seam to cut."""
    monkeypatch.setattr(enrich, "_is_public_host", lambda host: True)

    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(enrich.net, "get", boom)


# --- CertSpotter ------------------------------------------------------------

def test_certspotter_parses_distinct_dns_names(cache):
    _seed(cache, "certspotter_evil.example", [
        {"id": "1", "dns_names": ["*.evil.example", "login.evil.example", "abuse@evil.example"]},
        {"id": "2", "dns_names": ["login.evil.example", "pay.evil.example"]},
    ])
    sibs = enrich.certspotter_issuances("evil.example")
    names = {s["name"] for s in sibs}
    assert names == {"evil.example", "login.evil.example", "pay.evil.example"}  # deduped, *. stripped, @ dropped
    assert all(s["source"] == "certspotter" and s["relation"] == "shared_cert" for s in sibs)


def test_certspotter_rejects_bad_domain(cache):
    assert enrich.certspotter_issuances("not a domain!") == []


def test_certspotter_offline_safe(cache, monkeypatch):
    _no_network(monkeypatch)
    assert enrich.certspotter_issuances("evil.example") == []


# --- PhishStats -------------------------------------------------------------

def test_phishstats_compact_records(cache):
    _seed(cache, "phishstats_evil.example", [
        {"url": "http://evil.example/login", "ip": "203.0.113.5", "countrycode": "RU", "extra": 1},
        {"url": "http://evil.example/pay", "ip": "203.0.113.6", "countrycode": "CN"},
    ])
    hits = enrich.phishstats_hits("evil.example")
    assert hits == [
        {"url": "http://evil.example/login", "ip": "203.0.113.5", "countrycode": "RU"},
        {"url": "http://evil.example/pay", "ip": "203.0.113.6", "countrycode": "CN"},
    ]


def test_phishstats_rejects_injection_term(cache):
    # A term that could break out of the (url,like,~..~) filter must never be sent.
    assert enrich.phishstats_hits("a)~,(b") == []


def test_phishstats_offline_safe(cache, monkeypatch):
    _no_network(monkeypatch)
    assert enrich.phishstats_hits("evil.example") == []


# --- Phishing.Database + DShield feeds --------------------------------------

def test_phishing_database_membership(cache):
    _seed(cache, "phishdb_active", {"text": "good.example\nevil.example\npay-evil.example\n"})
    assert enrich.phishing_database_hit("evil.example")["hit"] is True   # case-insensitive
    assert enrich.phishing_database_hit("evil.example")["feed"] == "phishing-domains-ACTIVE"
    assert enrich.phishing_database_hit("clean.example")["hit"] is False


def test_phishing_database_rejects_bad_domain(cache):
    r = enrich.phishing_database_hit("bad domain")
    assert r == {"hit": False, "feed": None, "source": "phishing.database"}


def test_dshield_membership(cache):
    _seed(cache, "dshield_low", {"text": "# header comment\nbad-site.tk\nlure.xyz\n"})
    assert enrich.dshield_suspicious("bad-site.tk") is True
    assert enrich.dshield_suspicious("header") is False  # comment line not a member
    assert enrich.dshield_suspicious("nope.example") is False


def test_dshield_offline_safe(cache, monkeypatch):
    _no_network(monkeypatch)
    assert enrich.dshield_suspicious("evil.example") is False


# --- Spamhaus ASN-DROP ------------------------------------------------------

def test_spamhaus_drop_asn(cache):
    _seed(cache, "spamhaus_asndrop", {"text": (
        '{"asn":6725,"rir":"ripencc","cc":"US"}\n'
        '{"type":"metadata","timestamp":1}\n'
        '{"asn":9009,"cc":"NL"}\n'
    )})
    assert enrich.spamhaus_drop_asn("AS6725") is True   # AS-prefixed
    assert enrich.spamhaus_drop_asn(9009) is True       # int
    assert enrich.spamhaus_drop_asn("1234") is False
    assert enrich.spamhaus_drop_asn(None) is False


def test_spamhaus_offline_safe(cache, monkeypatch):
    _no_network(monkeypatch)
    assert enrich.spamhaus_drop_asn("AS6725") is False


# --- pivot() only ADDS keys and stays intact offline ------------------------

def test_pivot_adds_new_keys_without_breaking_shape(cache, monkeypatch):
    _no_network(monkeypatch)  # every source degrades to empty/None/False
    r = enrich.pivot("evil.example")
    # existing return shape preserved
    for k in ("seed", "favicon_mmh3", "node_count", "edges", "registered", "registrar",
              "asn", "openphish_hits", "shared_ip_clusters", "favicon_siblings",
              "urlscan_observed"):
        assert k in r, f"existing key {k} disappeared"
    # new keys added with graceful-empty defaults
    assert r["certspotter_siblings"] == []
    assert r["phishstats"] == []
    assert r["phishing_db"] == {"hit": False, "feed": "phishing-domains-ACTIVE",
                                "source": "phishing.database"}
    assert r["asn_drop"] == {}
    assert r["dshield"] is False
    assert r["seed"] == "evil.example"
