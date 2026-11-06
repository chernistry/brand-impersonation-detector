"""
Username-enumeration sensor (WhatsMyName rules), keyless.

A proactive discovery vector: instead of waiting to OBSERVE a fake in a feed,
we PREDICT its handle and check whether someone has already registered it. Given a
brand's official handles we generate the look-alike permutation space (leet /
homoglyph, combosquat brand+suffix, transposition/omission/insertion typos, dot/
underscore variants) and check existence across the highest-value social platforms
using the community-maintained WhatsMyName dataset (CC BY-SA 4.0; fetched at runtime
and cached locally, never bundled with this repository). A registered look-alike
handle is a candidate impersonation found before it has posted anything.

Keyless + read-only: every check is a single unauthenticated GET to the platform's
own public profile/oembed/existence endpoint; we submit nothing and create no
account. Rate-polite: permutations and platforms are capped, requests are spaced,
and the WMN ruleset is cached to disk. Non-deterministic (the live web) -> this is a
hash-anchored sidecar, never part of the signed evidence core.

Note: existence != malicious. A registered look-alike handle is a lead for the
classifier + analyst, not proof of impersonation on its own.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .. import paths
from ..models import Brand, RawObservation
from ..useragent import user_agent

_WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_CACHE: Path | None = None  # tests override; default paths.cache_dir("username-enum")
_UA = {"User-Agent": user_agent("read-only")}

# Highest-value platforms for brand/bank impersonation whose existence check is
# reliably keyless today (profile page, oembed, or availability endpoint).
DEFAULT_PLATFORMS = ["Telegram", "TikTok", "Reddit", "X", "Snapchat", "Threads", "YouTube", "Pinterest"]

# Human-facing profile URL for platforms whose WMN check hits an API/oembed endpoint
# (so the emitted lead links to the actual profile, not the check endpoint).
_PROFILE_URL = {
    "TikTok": "https://www.tiktok.com/@{account}",
    "X": "https://x.com/{account}",
    "Reddit": "https://www.reddit.com/user/{account}",
    "YouTube": "https://www.youtube.com/@{account}",
}

_LEET = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
_SUFFIXES = ["support", "secure", "verify", "help", "official", "team",
             "care", "service", "app", "online", "us", "global"]


def _leet_variants(base: str) -> list[str]:
    out = []
    for i, c in enumerate(base):
        if c.lower() in _LEET:
            out.append(base[:i] + _LEET[c.lower()] + base[i + 1:])
    return out


def _typos(base: str) -> list[str]:
    out = []
    if len(base) >= 4:
        for i in range(1, len(base) - 1):
            out.append(base[:i] + base[i + 1] + base[i] + base[i + 2:])  # transpose
            out.append(base[:i] + base[i + 1:])                          # omit
    return out


def permutations(official_handles: list[str], limit: int = 16) -> list[str]:
    """Deterministic look-alike handle space around the official handles."""
    seen: dict[str, None] = {}
    for base in official_handles:
        base = base.lstrip("@")
        cands = (_leet_variants(base)
                 + [f"{base}{s}" for s in _SUFFIXES]
                 + [f"{base}_{s}" for s in _SUFFIXES[:4]]
                 + [f"{base}.{s}" for s in _SUFFIXES[:2]]
                 + _typos(base))
        for c in cands:
            if c and c.lower() != base.lower() and c not in seen:
                seen[c] = None
    return list(seen)[:limit]


class UsernameEnumSensor:
    """Registered-look-alike-handle sensor. Live network access, no key."""

    def __init__(self, platforms: list[str] | None = None, max_permutations: int = 16,
                 timeout: float = 8.0, delay: float = 0.12):
        self.platforms = platforms or DEFAULT_PLATFORMS
        self.max_permutations = max_permutations
        self.timeout = timeout
        self.delay = delay
        self._last_error: str | None = None
        self._last_count = 0
        self._checked = 0

    def name(self) -> str:
        return "username_enum"

    def _wmn_sites(self) -> dict:
        cache_root = _CACHE or paths.cache_dir("username-enum")
        cache_root.mkdir(parents=True, exist_ok=True)
        cache = cache_root / "wmn-data.json"
        if cache.exists():
            data = json.loads(cache.read_text())
        else:
            from .. import net
            r = net.get("sensor:username_enum", _WMN_URL, timeout=self.timeout, headers=_UA)
            r.raise_for_status()
            data = r.json()
            cache.write_text(json.dumps(data))
        return {s["name"]: s for s in data.get("sites", [])}

    @staticmethod
    def _exists(site: dict, text: str, status: int) -> bool:
        """WhatsMyName detection: present iff the existence code+string match and the
        missing-string is absent."""
        e_code = site.get("e_code")
        e_string = site.get("e_string") or ""
        m_string = site.get("m_string") or ""
        if e_code is not None and status != e_code:
            return False
        if e_string and e_string not in text:
            return False
        if m_string and m_string in text:
            return False
        return bool(e_string) or e_code is not None

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        from .. import net
        try:
            sites = self._wmn_sites()
        except Exception as e:
            self._last_error = f"{type(e).__name__}: {e}"
            self._last_count = 0
            return
        self._last_error = None
        self._checked = 0
        emitted = 0
        handles = permutations(brand.official_handles, self.max_permutations)
        checks = [(name, sites[name]) for name in self.platforms if name in sites]
        with net.client("sensor:username_enum", timeout=self.timeout, headers=_UA,
                        follow_redirects=True) as c:
            for handle in handles:
                for pname, site in checks:
                    url = site["uri_check"].replace("{account}", handle)
                    self._checked += 1
                    try:
                        r = c.get(url)
                        found = self._exists(site, r.text, r.status_code)
                    except Exception:
                        found = False
                    if self.delay:
                        time.sleep(self.delay)
                    if not found:
                        continue
                    profile = (_PROFILE_URL[pname].replace("{account}", handle)
                               if pname in _PROFILE_URL
                               else site["uri_check"].replace("{account}", handle).split("?")[0])
                    emitted += 1
                    yield RawObservation(
                        sensor_name=self.name(),
                        observed_at=since,
                        platform=pname.lower(),
                        platform_uid=f"{pname.lower()}_{handle}",
                        payload={
                            "handle": handle,
                            "display_name": handle,
                            "bio": f"registered look-alike of @{brand.official_handles[0]} "
                                   f"on {pname} (username-enumeration hit)",
                            "link_in_bio_url": profile,
                            "platform_name": pname,
                        },
                        asset_urls=[],  # avatar fetch is a later enrichment step
                    )
        self._last_count = emitted

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "live",
            "last_count": self._last_count,
            "checked": self._checked,
            "error_rate": 1.0 if self._last_error else 0.0,
            "ban_rate": 0.0,  # no accounts are used: nothing to ban
            "note": self._last_error
            or "WhatsMyName existence checks over look-alike handle permutations (keyless).",
        }
