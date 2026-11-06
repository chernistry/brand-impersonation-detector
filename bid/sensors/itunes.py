"""
Apple App Store sensor via the iTunes Search API.

A keyless sensor: no token, no proxy and no account. The iTunes Search API is a
public JSON endpoint documented by Apple for this kind of lookup. It hits the
live internet.

    https://itunes.apple.com/search?term=<brand>&entity=software

Each result becomes a RawObservation with the app's real artwork URL, so the
pipeline downloads and content-addresses the real icon and perceptual-hashes it.
Offline safety: if the network is unavailable the sensor yields nothing and its
health() says so, so it never breaks a run; it is opt-in (demo_itunes.py or the
broad sensor mode), not part of the default deterministic pipeline.
"""
from __future__ import annotations

from datetime import datetime

from ..models import Brand, RawObservation

_ENDPOINT = "https://itunes.apple.com/search"


class ITunesSearchSensor:
    """App Store impersonation sensor. Live network access, no key."""

    def __init__(self, country: str = "US", limit: int = 25, timeout: float = 20.0):
        self.country = country
        self.limit = limit
        self.timeout = timeout
        self._last_error: str | None = None
        self._last_count = 0

    def name(self) -> str:
        return "itunes_search"

    def scan(self, brand: Brand, since: datetime):
        from .. import net

        params = {
            "term": brand.name,
            "entity": "software",
            "country": self.country,
            "limit": self.limit,
        }
        try:
            with net.client("sensor:itunes", timeout=self.timeout) as c:
                r = c.get(_ENDPOINT, params=params)
                r.raise_for_status()
                results = r.json().get("results", [])
        except Exception as e:  # network/parse error -> yield nothing, record it
            self._last_error = f"{type(e).__name__}: {e}"
            self._last_count = 0
            return

        self._last_error = None
        self._last_count = len(results)
        for app in results:
            uid = str(app.get("trackId") or app.get("bundleId") or app.get("trackName"))
            artwork = app.get("artworkUrl512") or app.get("artworkUrl100") or app.get("artworkUrl60")
            yield RawObservation(
                sensor_name=self.name(),
                observed_at=since,
                platform="app_store",
                platform_uid=uid,
                payload={
                    "handle": app.get("sellerName"),
                    "display_name": app.get("trackName"),
                    "app_name": app.get("trackName"),
                    "seller": app.get("sellerName"),
                    "bio": (app.get("description") or "")[:600],
                    "link_in_bio_url": app.get("sellerUrl") or app.get("trackViewUrl"),
                    "bundleId": app.get("bundleId"),
                    "genres": app.get("genres"),
                },
                asset_urls=[artwork] if artwork else [],
            )

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "live",
            "last_count": self._last_count,
            "error_rate": 1.0 if self._last_error else 0.0,
            "ban_rate": 0.0,
            "note": self._last_error or "iTunes Search API - keyless, global",
        }
