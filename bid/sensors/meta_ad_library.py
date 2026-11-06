"""
Meta Ad Library sensor.

Hits the REAL public Graph Ad Library API when META_AD_LIBRARY_TOKEN is set,
and falls back to bundled MOCK fixtures when it is not, so the pipeline runs with
no setup.

Known constraint: commercial-ad data via the official Ad Library API is limited to
EU/UK. US and other commercial ads are not available through the API (only
political and social-issue ads are global). This sensor is therefore scoped to
EU/UK brands in live mode, and health() reports that scoping so the output is not
mistaken for coverage of a region the API cannot serve.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterator

from ..models import Brand, RawObservation
from .base import load_fixture

_API_URL = "https://graph.facebook.com/v19.0/ads_archive"
_EU_UK = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "GB",
}


class MetaAdLibrarySensor:
    """Sensor impl #2. Same Protocol as every other sensor."""

    def __init__(self, token: str | None = None):
        # The token comes from the environment. Absent -> mock mode, which is
        # the default so the pipeline is runnable offline.
        self._token = token or os.environ.get("META_AD_LIBRARY_TOKEN")
        self._last_error_rate = 0.0
        self._mode = "live" if self._token else "mock"

    def name(self) -> str:
        return "meta_ad_library"

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        if self._token:
            yield from self._scan_live(brand, since)
        else:
            yield from self._scan_mock(brand, since)

    # --- live path (only runs when a token is present) ---------------------
    def _scan_live(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        from .. import net  # imported lazily so the mock path has no hard dep on network libs

        countries = [r for r in brand.regions if r in _EU_UK]
        if not countries:
            # Refuse to pretend: the API cannot serve commercial ads outside EU/UK.
            self._last_error_rate = 1.0
            return
        params = {
            "search_terms": brand.name,
            "ad_reached_countries": ",".join(countries),
            "ad_type": "ALL",
            "fields": "id,ad_creative_bodies,ad_snapshot_url,page_name,"
            "ad_delivery_start_time",
            "access_token": self._token,
            "limit": 50,
        }
        resp = net.get("sensor:meta_ad_library", _API_URL, params=params, timeout=30.0)
        resp.raise_for_status()
        for ad in resp.json().get("data", []):
            yield RawObservation(
                sensor_name=self.name(),
                observed_at=datetime.now(timezone.utc),
                platform="meta_ads",
                platform_uid=str(ad.get("id")),
                payload=ad,
                asset_urls=[ad["ad_snapshot_url"]] if ad.get("ad_snapshot_url") else [],
            )

    # --- mock path (default, zero setup) -----------------------------------
    def _scan_mock(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        data = load_fixture("ad_library_mock.json")
        for ad in data.get(brand.id, []):
            yield RawObservation(
                sensor_name=self.name(),
                observed_at=datetime.fromisoformat(ad["observed_at"]),
                platform="meta_ads",
                platform_uid=ad["platform_uid"],
                payload=ad["payload"],
                asset_urls=ad.get("asset_urls", []),
            )

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": self._mode,
            "error_rate": self._last_error_rate,
            "ban_rate": 0.0,  # no accounts are used: nothing to ban
            "note": "commercial ads EU/UK only via official API (HIGH confidence)",
        }
