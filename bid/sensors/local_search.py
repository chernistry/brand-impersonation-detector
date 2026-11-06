"""
Local-fixtures search sensor.

A fully offline sensor that stands in for a platform-search path. It reads a
bundled fixture of "profiles found by searching the brand name" and emits them
as RawObservations.

It demonstrates the Sensor Protocol: several sensors, one contract, and the
pipeline downstream cannot tell them apart. Adding a new source means adding one
more sensor.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterator

from ..models import Brand, RawObservation
from .base import load_fixture


class LocalSearchSensor:
    """Sensor impl #1. Offline and deterministic."""

    def name(self) -> str:
        return "local_search"

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        data = load_fixture("local_search_mock.json")
        for prof in data.get(brand.id, []):
            yield RawObservation(
                sensor_name=self.name(),
                observed_at=datetime.fromisoformat(prof["observed_at"]),
                platform=prof.get("platform", "local_search"),
                platform_uid=prof["platform_uid"],
                payload=prof["payload"],
                asset_urls=prof.get("asset_urls", []),
            )

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "mock",
            "error_rate": 0.0,
            "ban_rate": 0.0,
            "note": "fixture-backed stand-in for platform search",
        }
