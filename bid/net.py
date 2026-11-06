"""
Outbound HTTP with a per-component egress allowlist.

Every outbound HTTP request the package makes goes through client() (or the get()
and post() helpers built on it) under a component name, for example "enrich",
"classifier" or "sensor:ct_logs". The active EgressPolicy decides which hosts each
component may reach. The check runs in an httpx request event hook, so it covers
every hop of a followed redirect, not only the first URL.

The default policy is unrestricted (allow=None): nothing is refused and the
historical behaviour is unchanged. A deployment profile (see attestation.py)
activates a restricted policy for the whole process.

This guards the package's own call sites. It is not a sandbox: code that builds its
own httpx client, or uses another HTTP library, is not covered.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

import httpx


class EgressDenied(PermissionError):
    """An outbound request was refused by the active egress policy.

    The message and attributes name the component and the host only, never the full
    URL, because query strings can carry credentials (for example an access token).
    """

    def __init__(self, message: str, *, component: str = "", host: str = ""):
        super().__init__(message)
        self.component = component
        self.host = host


# A host name made of DNS labels: ASCII letters, digits, underscores and inner
# hyphens. Internationalised names are written in their punycode form.
_NAME_RE = re.compile(
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
)


def _canonical_host(host: str) -> str:
    """Lower case, no trailing dot, IP addresses in their compressed form."""
    host = host.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return host


def _canonical_pattern(pattern: str) -> str:
    """Validate one host pattern and return its canonical form."""
    if not isinstance(pattern, str):
        raise ValueError(f"host pattern must be a string, got {type(pattern).__name__}")
    canonical = _canonical_host(pattern)
    wildcard = canonical.startswith("*.")
    name = canonical[2:] if wildcard else canonical
    try:
        ipaddress.ip_address(name)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip and not wildcard:
        return name
    if not is_ip and _NAME_RE.fullmatch(name):
        return canonical
    raise ValueError(
        f"invalid host pattern {pattern!r}: use an exact host such as 'crt.sh' "
        "or a suffix wildcard such as '*.example.org'"
    )


def _url_host(url) -> str:
    """Canonical host of `url` as it goes on the wire, or "" when there is none."""
    try:
        raw = httpx.URL(str(url)).raw_host
    except Exception:  # an unparsable URL has no host, so a restricted policy denies it
        return ""
    return _canonical_host(raw.decode("ascii", "replace")) if raw else ""


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.org": subdomains only, not the bare domain
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass(frozen=True)
class EgressPolicy:
    """Per-component host allowlist. allow=None means unrestricted (the default).

    Keys are component names; values are host patterns, either an exact host
    ("crt.sh") or a suffix wildcard ("*.example.org", which matches any subdomain but
    not example.org itself). When allow is not None, a component that is missing
    from it, or that maps to an empty list, may reach no host at all.

    Patterns are validated, de-duplicated and sorted on construction, and the map is
    copied into a read-only view, so a policy cannot change after activation.
    """

    allow: Mapping[str, tuple[str, ...]] | None = None

    def __post_init__(self) -> None:
        if self.allow is None:
            return
        if not isinstance(self.allow, Mapping):
            raise TypeError("allow must be a mapping of component -> host patterns, or None")
        frozen: dict[str, tuple[str, ...]] = {}
        for component, patterns in self.allow.items():
            if isinstance(patterns, str):
                raise ValueError(f"hosts for component {component!r} must be a list, not a string")
            frozen[str(component)] = tuple(sorted({_canonical_pattern(p) for p in patterns}))
        object.__setattr__(self, "allow", MappingProxyType(frozen))

    @property
    def unrestricted(self) -> bool:
        return self.allow is None

    def allows(self, component: str, url) -> bool:
        """True when `component` may send a request to the host of `url`."""
        if self.allow is None:
            return True
        host = _url_host(url)
        return bool(host) and any(_host_matches(host, p) for p in self.allow.get(component, ()))

    def check(self, component: str, url) -> None:
        """Raise EgressDenied unless `component` may reach the host of `url`."""
        if not self.allows(component, url):
            host = _url_host(url)
            raise EgressDenied(
                f"egress denied: component {component!r} may not reach host "
                f"{host or '(none)'!r} under the active policy",
                component=component,
                host=host,
            )

    def describe(self) -> dict:
        """JSON-ready description, used by the deployment attestation."""
        if self.allow is None:
            return {"mode": "unrestricted"}
        return {"mode": "allowlist", "allow": {c: list(p) for c, p in sorted(self.allow.items())}}


UNRESTRICTED = EgressPolicy()
_active: EgressPolicy = UNRESTRICTED


def activate(policy: EgressPolicy) -> EgressPolicy:
    """Make `policy` the process-wide egress policy and return the previous one."""
    global _active
    if not isinstance(policy, EgressPolicy):
        raise TypeError("activate() needs an EgressPolicy")
    previous, _active = _active, policy
    return previous


def active() -> EgressPolicy:
    """The egress policy currently in effect."""
    return _active


def client(component: str, **kwargs) -> httpx.Client:
    """An httpx.Client whose every request, including each redirect hop, is checked
    against the policy in effect at send time for `component`.

    Keyword arguments pass through to httpx.Client unchanged (timeouts, headers,
    follow_redirects, transport=httpx.MockTransport(...) in tests, and so on).
    """
    hooks = dict(kwargs.pop("event_hooks", None) or {})

    def _check(req: httpx.Request) -> None:
        active().check(component, str(req.url))

    # Run after any caller hook, so the URL that is checked is the URL that is sent.
    hooks["request"] = [*hooks.get("request", ()), _check]
    return httpx.Client(event_hooks=hooks, **kwargs)


# Keyword arguments that belong to the request rather than to the client. This is
# the same split httpx.request() makes; everything else (timeout, cookies, proxy,
# verify, transport, ...) configures the client.
_REQUEST_KWARGS = frozenset(
    {"params", "headers", "content", "data", "files", "json", "auth", "follow_redirects", "extensions"}
)


def request(component: str, method: str, url, **kwargs) -> httpx.Response:
    """One request through client(): the checked equivalent of httpx.request()."""
    request_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in _REQUEST_KWARGS}
    with client(component, **kwargs) as c:
        return c.request(method, url, **request_kwargs)


def get(component: str, url, **kwargs) -> httpx.Response:
    """Checked equivalent of httpx.get()."""
    return request(component, "GET", url, **kwargs)


def post(component: str, url, **kwargs) -> httpx.Response:
    """Checked equivalent of httpx.post()."""
    return request(component, "POST", url, **kwargs)
