"""
Egress allowlist invariants for bid.net. Network is never touched: every request
goes to an httpx.MockTransport that records what it was asked to send.

Pins:
  - the default policy is unrestricted, so historical behaviour is unchanged,
  - exact hosts and "*.suffix" wildcards (subdomains only) are honoured,
  - a component missing from the map, or mapped to an empty list, is denied,
  - a denied request never reaches the transport,
  - every redirect hop is checked, so a redirect to a non-listed host is refused,
  - get()/post() pass request and client keyword arguments through unchanged.
"""
import httpx
import pytest

from bid import net
from bid.net import EgressDenied, EgressPolicy


@pytest.fixture(autouse=True)
def restore_policy():
    previous = net.active()
    yield
    net.activate(previous)


def recorder(redirects=None):
    """MockTransport that records requests; `redirects` maps host -> Location."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        target = (redirects or {}).get(request.url.host)
        if target:
            return httpx.Response(302, headers={"Location": target})
        return httpx.Response(200, json={"host": request.url.host})

    return seen, httpx.MockTransport(handler)


def test_default_policy_is_unrestricted():
    assert net.active().unrestricted
    assert net.active().describe() == {"mode": "unrestricted"}
    assert EgressPolicy().allows("any:component", "https://anything.example/x")
    seen, transport = recorder()
    r = net.get("sensor:whatever", "https://not-listed.example/", transport=transport)
    assert r.status_code == 200 and len(seen) == 1


def test_exact_host_allow_and_deny():
    p = EgressPolicy({"enrich": ("crt.sh", "dns.google")})
    assert p.allows("enrich", "https://crt.sh/?q=%25lorvanne%25&output=json")
    assert p.allows("enrich", "https://DNS.Google./resolve")  # case and trailing dot
    assert not p.allows("enrich", "https://evil.example/")
    assert not p.allows("enrich", "https://sub.crt.sh/")  # exact means exact
    assert not p.allows("enrich", "not a url")


def test_wildcard_matches_subdomains_only():
    p = EgressPolicy({"c": ("*.example.org",)})
    assert p.allows("c", "https://a.example.org/")
    assert p.allows("c", "https://a.b.example.org/")
    assert not p.allows("c", "https://example.org/")  # bare domain is not a subdomain
    assert not p.allows("c", "https://badexample.org/")
    assert not p.allows("c", "https://example.org.evil.test/")


def test_missing_component_and_empty_list_are_denied():
    p = EgressPolicy({"enrich": ("crt.sh",), "anchor": ()})
    assert not p.allows("classifier", "https://crt.sh/")  # component not in the map
    assert not p.allows("anchor", "https://freetsa.org/tsr")  # empty list
    with pytest.raises(EgressDenied) as exc:
        p.check("classifier", "https://crt.sh/?token=secret")
    assert isinstance(exc.value, PermissionError)
    assert exc.value.component == "classifier" and exc.value.host == "crt.sh"
    assert "secret" not in str(exc.value)  # never echoes the query string


def test_userinfo_cannot_spoof_the_host():
    p = EgressPolicy({"c": ("crt.sh",)})
    assert not p.allows("c", "https://crt.sh@evil.example/")
    assert not p.allows("c", "https://crt.sh.evil.example/")


def test_denied_request_never_reaches_the_transport():
    net.activate(EgressPolicy({"sensor:ct_logs": ("crt.sh",)}))
    seen, transport = recorder()
    with pytest.raises(EgressDenied):
        net.get("sensor:ct_logs", "https://evil.example/", transport=transport)
    with pytest.raises(EgressDenied):
        net.get("sensor:other", "https://crt.sh/", transport=transport)
    assert seen == []


def test_redirect_to_denied_host_is_blocked():
    net.activate(EgressPolicy({"allowlist": ("tranco-list.eu",)}))
    seen, transport = recorder(redirects={"tranco-list.eu": "https://mirror.evil.example/top-1m.csv.zip"})
    with pytest.raises(EgressDenied) as exc:
        net.get("allowlist", "https://tranco-list.eu/top-1m.csv.zip",
                follow_redirects=True, transport=transport)
    assert exc.value.host == "mirror.evil.example"
    assert [r.url.host for r in seen] == ["tranco-list.eu"]  # the second hop was never sent


def test_redirect_within_allowlist_is_followed():
    net.activate(EgressPolicy({"c": ("a.example.org", "*.cdn.example.org")}))
    seen, transport = recorder(redirects={"a.example.org": "https://eu.cdn.example.org/file"})
    with net.client("c", transport=transport, follow_redirects=True) as c:
        r = c.get("https://a.example.org/file")
    assert r.status_code == 200
    assert [x.url.host for x in seen] == ["a.example.org", "eu.cdn.example.org"]


def test_get_and_post_pass_arguments_through():
    net.activate(EgressPolicy({"anchor": ("freetsa.org",), "enrich": ("dns.google",)}))
    seen, transport = recorder()
    r = net.get("enrich", "https://dns.google/resolve", params={"name": "x.test", "type": "A"},
                headers={"User-Agent": "bid-test"}, timeout=7.0, transport=transport)
    assert r.json() == {"host": "dns.google"}
    req = seen[-1]
    assert req.method == "GET"
    assert dict(req.url.params) == {"name": "x.test", "type": "A"}
    assert req.headers["User-Agent"] == "bid-test"
    assert req.extensions["timeout"]["read"] == 7.0

    net.post("anchor", "https://freetsa.org/tsr", content=b"\x30\x00",
             headers={"Content-Type": "application/timestamp-query"}, transport=transport)
    req = seen[-1]
    assert req.method == "POST" and req.content == b"\x30\x00"
    assert req.headers["Content-Type"] == "application/timestamp-query"


def test_caller_event_hooks_still_run():
    calls = []
    seen, transport = recorder()
    with net.client("c", transport=transport, event_hooks={"request": [calls.append]}) as c:
        c.get("https://a.example.org/")
    assert len(calls) == 1 and len(seen) == 1


def test_policy_is_read_only_and_patterns_are_validated():
    hosts = ["crt.sh"]
    p = EgressPolicy({"enrich": hosts})
    hosts.append("evil.example")  # mutating the caller's list changes nothing
    assert not p.allows("enrich", "https://evil.example/")
    with pytest.raises(TypeError):
        p.allow["enrich"] = ("evil.example",)
    for bad in ("https://crt.sh", "crt.sh:443", "*", "*.10.0.0.1", "", "a b"):
        with pytest.raises(ValueError):
            EgressPolicy({"c": [bad]})
    with pytest.raises(ValueError):
        EgressPolicy({"c": "crt.sh"})  # a bare string, not a list of hosts


def test_activate_returns_previous_policy():
    restricted = EgressPolicy({"c": ("crt.sh",)})
    previous = net.activate(restricted)
    assert previous.unrestricted and net.active() is restricted
    with pytest.raises(TypeError):
        net.activate({"c": ["crt.sh"]})
