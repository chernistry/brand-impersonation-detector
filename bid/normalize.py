"""
Normalization: collapse every RawObservation into one canonical Candidate.

This is where the first lineage record is written: the raw observation is
hashed and stored, every asset is fetched and content-addressed by SHA-256, and
a perceptual hash is computed for image assets. Tampering with any of those
bytes later changes the hash and breaks the chain.

Asset fetching branches on the URL:
  - http(s)://  -> real download via bid.net, component "asset_fetch" (the live
                   Ad Library path)
  - anything else -> read a bundled fixture file (the offline default)

so the offline default needs no network, while the same code fetches real
creatives when a sensor returns real URLs.
"""
from __future__ import annotations

import json

from .filters import asset_phash
from .models import Asset, Brand, Candidate, RawObservation
from .sensors.base import FIXTURES
from .storage import ContentStore

_IMAGE_HINTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", "icon", "logo", "creative")


def _sniff_image(data: bytes) -> str | None:
    """Detect image type from magic bytes, not the URL. Real CDN avatar URLs are
    extension-less, so URL-substring gating silently skips the live-scraped case
    that matters most. Returns a media type or None."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:4] == b"<svg" or data[:5] == b"<?xml":
        return "image/svg+xml"
    return None


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fetch_asset_bytes(url: str) -> bytes:
    if url.startswith(("http://", "https://")):
        from . import net

        resp = net.get("asset_fetch", url, timeout=30.0)
        resp.raise_for_status()
        return resp.content
    # Fixture-relative path (default offline path).
    return (FIXTURES / url).read_bytes()


def _looks_like_image(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in _IMAGE_HINTS)


def normalize(obs: RawObservation, brand: Brand, store: ContentStore) -> Candidate:
    # Anchor the raw observation itself.
    raw_ref = store.put_bytes(_canonical_bytes(obs.model_dump(mode="json")))

    assets: list[Asset] = []
    for url in obs.asset_urls:
        data = _fetch_asset_bytes(url)
        digest = store.put_bytes(data)
        # Sniff the actual bytes; fall back to the URL hint only for empty/odd data.
        media = _sniff_image(data) or (
            "image/png" if _looks_like_image(url) else "application/octet-stream")
        phash = asset_phash(data) if media.startswith("image/") and media != "image/svg+xml" else None
        assets.append(Asset(sha256=digest, media_type=media, phash=phash))

    p = obs.payload
    handle = p.get("handle") or p.get("page_name") or p.get("seller")
    avatar_phash = assets[0].phash if assets else ""
    dedup_key = f"{obs.platform}:{obs.platform_uid}:{avatar_phash or ''}"

    return Candidate(
        id=f"cand_{obs.platform}_{obs.platform_uid}",
        brand_id=brand.id,
        sensor_name=obs.sensor_name,
        platform=obs.platform,
        platform_uid=obs.platform_uid,
        handle=handle,
        display_name=p.get("display_name") or p.get("app_name") or p.get("page_name"),
        bio=p.get("bio") or p.get("description"),
        link_in_bio_url=p.get("link_in_bio_url") or p.get("landing_url"),
        assets=assets,
        dedup_key=dedup_key,
        raw_observation_ref=raw_ref,
        status="new",
        first_seen=obs.observed_at,
    )


def dedup(candidates: list[Candidate]) -> list[Candidate]:
    """Same fake seen by two sensors = one Candidate. Keep first, drop repeats."""
    seen: dict[str, Candidate] = {}
    for c in candidates:
        if c.dedup_key not in seen:
            seen[c.dedup_key] = c
    return list(seen.values())
