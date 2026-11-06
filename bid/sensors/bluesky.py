"""
Bluesky live discovery sensor (AT Protocol), no API key or account needed.

Bluesky is an OPEN social protocol: its AppView exposes a public, unauthenticated
search (public.api.bsky.app) so we can look up accounts whose handle or display
name matches a brand or a look-alike without an account, a token, or scraping.
It complements username enumeration: enumeration confirms a predicted handle
exists, this surfaces accounts we did not predict by matching the brand text.

Each returned actor carries a real avatar URL, so the pipeline downloads and
perceptual-hashes the real profile picture for the visual tier. Read-only: a single
GET to the public search endpoint; we submit nothing. Non-deterministic (the live
network) -> hash-anchored sidecar, never part of the signed evidence core.

Limitation: Bluesky is much smaller than the large social networks, so coverage is
a slice of the social surface, not the whole of it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterator

from ..models import Brand, RawObservation
from ..useragent import user_agent

_ENDPOINT = "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors"
_UA = {"User-Agent": user_agent("read-only")}


class BlueskySensor:
    """Open-social-protocol sensor. Live network access, no key."""

    def __init__(self, limit: int = 25, timeout: float = 15.0):
        self.limit = limit
        self.timeout = timeout
        self._last_error: str | None = None
        self._last_count = 0

    def name(self) -> str:
        return "bluesky"

    def _queries(self, brand: Brand) -> list[str]:
        qs = [brand.name] + list(brand.official_handles) + list(getattr(brand, "aliases", []))
        # dedup, keep short
        seen, out = set(), []
        for q in qs:
            q = (q or "").strip()
            if q and q.lower() not in seen:
                seen.add(q.lower())
                out.append(q)
        return out[:4]

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        from .. import net
        official = {h.lower().lstrip("@") for h in brand.official_handles}
        emitted = 0
        seen: set[str] = set()
        self._last_error = None
        try:
            with net.client("sensor:bluesky", timeout=self.timeout, headers=_UA) as c:
                for q in self._queries(brand):
                    r = c.get(_ENDPOINT, params={"q": q, "limit": self.limit})
                    if r.status_code != 200:
                        continue
                    for a in r.json().get("actors", []):
                        handle = (a.get("handle") or "").strip()
                        if not handle or handle in seen:
                            continue
                        # a bare handle equal to an official handle prefix is the real
                        # account; skip only exact-official, keep look-alikes.
                        short = handle.split(".")[0].lower()
                        if short in official:
                            continue
                        seen.add(handle)
                        avatar = a.get("avatar")
                        emitted += 1
                        yield RawObservation(
                            sensor_name=self.name(),
                            observed_at=since,
                            platform="bluesky",
                            platform_uid=a.get("did") or handle,
                            payload={
                                "handle": short,
                                "display_name": a.get("displayName") or handle,
                                "bio": a.get("description") or "",
                                "link_in_bio_url": f"https://bsky.app/profile/{handle}",
                                "bsky_handle": handle,
                            },
                            asset_urls=[avatar] if avatar else [],
                        )
        except Exception as e:
            self._last_error = f"{type(e).__name__}: {e}"
        self._last_count = emitted

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "live",
            "last_count": self._last_count,
            "error_rate": 1.0 if self._last_error else 0.0,
            "ban_rate": 0.0,
            "note": self._last_error
            or "Bluesky public AppView actor search (keyless, open protocol).",
        }
