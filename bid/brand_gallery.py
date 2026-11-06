"""
Brand roster loader for scale work.

The bundled fixtures ship five fictional brands. For larger runs you may want a
wider roster of company names, official social handles, website domains and
logos. This module reads such a roster from a local, read-only directory that you
supply (it is never bundled): a `companies/*.json` record per company plus the
logo images the records point to.

The directory is read in place. Nothing is copied into the repo and no HTTP
requests are made: everything is filesystem + Pillow. If the directory is not
configured (set BID_BRAND_RECORDS_DIR), `available()` is False and every loader
returns an empty list so callers and tests stay green.

Per-company record schema (fields used):

    name         str    company display name
    logoFile     str    e.g. "logos/example_brand-logo.png" (relative to root)
    websiteUrl   str    e.g. "http://www.example-brand.test"  -> official domain
    linkedinId   str    LinkedIn handle/slug                       (nullable)
    xId          str    X handle                                   (nullable)
    facebookId   str    Facebook handle                            (nullable)

The record filename stem is the stable company id.

Everything is deterministic: companies are walked in sorted-id order, handles
are emitted in a fixed source order, so two runs produce identical output.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .domains import registrable
from .filters import asset_phash

# Location of the read-only roster directory, taken from the environment.
_ENV_ROOT = "BID_BRAND_RECORDS_DIR"

# Social fields in a record, in the fixed order we emit handles.
_HANDLE_FIELDS = ("linkedinId", "xId", "facebookId")

_DEFAULT_REGIONS = ["GLOBAL"]


def _root() -> Path:
    return Path(os.environ.get(_ENV_ROOT, ""))


def _companies_dir() -> Path:
    return _root() / "companies"


def available() -> bool:
    """True when a roster directory is configured and readable."""
    try:
        return bool(os.environ.get(_ENV_ROOT)) and _companies_dir().is_dir()
    except Exception:  # pragma: no cover - defensive against odd mount states
        return False


def _company_files() -> list[Path]:
    """Company record paths in stable (sorted-id) order."""
    try:
        return sorted(_companies_dir().glob("*.json"), key=lambda p: p.stem)
    except Exception:  # pragma: no cover
        return []


def _handles(record: dict) -> list[str]:
    """Official social handles, fixed order, empties dropped."""
    out: list[str] = []
    for field in _HANDLE_FIELDS:
        v = record.get(field)
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
    return out


def _domains(record: dict) -> list[str]:
    """Registrable official domain(s) derived from the website field."""
    url = record.get("websiteUrl")
    if not isinstance(url, str) or not url.strip():
        return []
    reg = registrable(url)
    return [reg] if reg else []


def _logo_path(record: dict) -> Optional[str]:
    """Absolute path to the company's logo image, if the file is present."""
    rel = record.get("logoFile")
    if not isinstance(rel, str) or not rel.strip():
        return None
    p = _root() / rel
    try:
        if p.is_file():
            return str(p)
    except Exception:  # pragma: no cover
        return None
    return None


def _logo_phash(logo_path: Optional[str]) -> Optional[str]:
    """pHash the logo image. None if missing/unreadable (brand still returned)."""
    if not logo_path:
        return None
    try:
        data = Path(logo_path).read_bytes()
    except Exception:
        return None
    if not data:
        return None
    try:
        return asset_phash(data)
    except Exception:  # pragma: no cover - asset_phash already guards internally
        return None


def _to_gallery(cid: str, record: dict, with_logos: bool) -> Optional[dict]:
    """Project one roster record into a gallery brand dict, or None if unusable.

    Usable = non-empty name AND at least one official domain or handle.
    """
    name = record.get("name")
    name = name.strip() if isinstance(name, str) else ""
    if not name:
        return None
    handles = _handles(record)
    domains = _domains(record)
    if not handles and not domains:
        return None

    brand: dict = {
        "id": cid,
        "name": name,
        "official_handles": handles,
        "official_domains": domains,
    }
    logo_path = _logo_path(record)
    if with_logos:
        brand["logo_phash"] = _logo_phash(logo_path)
    else:
        brand["logo_path"] = logo_path
    return brand


def load_brands(limit: Optional[int] = None, with_logos: bool = False) -> list[dict]:
    """Load brand records from the roster directory.

    Returns a deterministic, sorted-by-id list of well-formed brand dicts:

        {id, name, official_handles: [...], official_domains: [...],
         logo_path}                         # with_logos=False
        {..., logo_phash}                   # with_logos=True (None if unreadable)

    Malformed records are skipped. If no roster is configured, returns [].
    """
    if not available():
        return []
    out: list[dict] = []
    for path in _company_files():
        try:
            record = json.loads(path.read_text())
        except Exception:
            continue  # skip malformed / unreadable record
        if not isinstance(record, dict):
            continue
        brand = _to_gallery(path.stem, record, with_logos)
        if brand is None:
            continue
        out.append(brand)
        if limit is not None and len(out) >= limit:
            break
    return out


def to_brands(limit: Optional[int] = None, with_logos: bool = False):
    """Convert gallery records into `bid.models.Brand` objects.

    Mirrors `run_pipeline.load_brands` construction: official_logo_hashes carries
    the pHash of the official logo (via `bid.filters.asset_phash`) when
    with_logos=True and the image was readable, otherwise an empty list. Returns
    [] when no roster is configured.
    """
    from .models import Brand

    brands = []
    for g in load_brands(limit=limit, with_logos=with_logos):
        logo_hashes: list[str] = []
        if with_logos and g.get("logo_phash"):
            logo_hashes = [g["logo_phash"]]
        brands.append(
            Brand(
                id=g["id"],
                name=g["name"],
                official_handles=g["official_handles"],
                official_logo_hashes=logo_hashes,
                regions=list(_DEFAULT_REGIONS),
                official_domains=g["official_domains"],
            )
        )
    return brands
