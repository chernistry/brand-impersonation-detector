"""
Public-suffix-aware registrable-domain extraction.

The naive "last two labels" breaks on multi-part suffixes (.co.uk, .com.au),
which matters here: a brand on <brand>.co.uk must not make "co.uk" itself a
legit domain, which would match everything and defeat the domain-intention rule.
tldextract uses the Public Suffix List and gets it right; a small offline
fallback covers the common multi-part suffixes if tldextract is unavailable.

The RFC 2606 reserved TLDs (.test, .example, .invalid, .localhost) are not in the
Public Suffix List; they are registered here as suffixes so that the fictional
fixture brands (e.g. lorvanne-bank.test) resolve to a proper registrable domain.
"""
from __future__ import annotations

import os
import tempfile

_RESERVED_TLDS = ("test", "example", "invalid", "localhost")

try:  # pragma: no cover - import guard
    import tldextract as _tld

    # suffix_list_urls=() pins the Public Suffix List snapshot bundled with
    # tldextract: no network fetch on first use, and the same input gives the
    # same registrable domain on every machine and every day. Private suffixes
    # (github.io, pages.dev, web.app, ...) count as suffixes: a brand page on
    # brand.github.io must not make all of github.io look official.
    _EXT = _tld.TLDExtract(cache_dir=os.path.join(tempfile.gettempdir(), "bid_tldextract"),
                           suffix_list_urls=(), extra_suffixes=_RESERVED_TLDS,
                           include_psl_private_domains=True)
    _HAVE_TLD = True
except Exception:  # pragma: no cover
    _HAVE_TLD = False

# Common multi-part public suffixes for the offline fallback (not exhaustive).
_MULTI = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au",
    "co.jp", "com.br", "co.za", "com.sg", "co.nz", "com.tr", "com.mx",
}


def _host(url_or_domain: str) -> str:
    u = (url_or_domain or "").split("://", 1)[-1]
    return u.split("/", 1)[0].split("?", 1)[0].split("@")[-1].lower().strip(".")


def registrable(url_or_domain: str) -> str:
    """Registrable (eTLD+1) domain. Public-suffix aware."""
    host = _host(url_or_domain)
    if not host:
        return ""
    if _HAVE_TLD:
        e = _EXT(host)
        # tldextract >= 5.3 renamed registered_domain; read the new name when present.
        reg = (e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix")
               else e.registered_domain)
        return reg or e.domain or host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
