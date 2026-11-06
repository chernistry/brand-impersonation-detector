"""Shared HTTP User-Agent for outbound sensor/enrichment requests.

Public APIs (Wikidata, crt.sh, Bluesky, ...) ask automated clients to identify
themselves. Set BID_CONTACT (e.g. an abuse/contact address or project URL) so
operators of those services can reach you; it is appended to the User-Agent.
"""
from __future__ import annotations

import os

from . import __version__


def user_agent(extra: str = "") -> str:
    parts = [f"brand-impersonation-detector/{__version__}"]
    details = [d for d in (extra, os.environ.get("BID_CONTACT", "").strip()) if d]
    if details:
        parts.append("(" + "; ".join(details) + ")")
    return " ".join(parts)
