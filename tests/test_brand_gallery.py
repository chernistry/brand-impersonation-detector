"""
Brand roster loader tests.

The loader reads an optional, user-supplied roster directory (BID_BRAND_RECORDS_DIR).
The tests build a small synthetic roster in a temp directory, and also pin the
empty-list contract when no roster is configured.
"""
import io
import json

import pytest
from PIL import Image

from bid import brand_gallery as bg
from bid.models import Brand


def _logo_png(color) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def roster(tmp_path, monkeypatch):
    (tmp_path / "companies").mkdir()
    (tmp_path / "logos").mkdir()
    records = {
        "0001": {"name": "Alpha Example", "logoFile": "logos/alpha.png",
                 "websiteUrl": "http://www.alpha-example.test", "xId": "alphaexample"},
        "0002": {"name": "Beta Example", "logoFile": "logos/beta.png",
                 "websiteUrl": "https://beta-example.test/", "linkedinId": "beta-example",
                 "facebookId": "betaexample"},
        "0003": {"name": "Gamma Example", "websiteUrl": "https://gamma-example.test"},
        "0004": {"name": "No Identity"},          # neither handle nor domain -> skipped
        "0005": {"name": "   ", "xId": "blank"},  # blank name -> skipped
    }
    for cid, rec in records.items():
        (tmp_path / "companies" / f"{cid}.json").write_text(json.dumps(rec))
    (tmp_path / "companies" / "0006.json").write_text("{not json")  # malformed -> skipped
    (tmp_path / "logos" / "alpha.png").write_bytes(_logo_png((200, 30, 30)))
    (tmp_path / "logos" / "beta.png").write_bytes(_logo_png((30, 30, 200)))
    monkeypatch.setenv("BID_BRAND_RECORDS_DIR", str(tmp_path))
    return tmp_path


def test_absent_roster_yields_empty_list(monkeypatch):
    """Contract when no roster is configured: no brands, no error."""
    monkeypatch.delenv("BID_BRAND_RECORDS_DIR", raising=False)
    assert not bg.available()
    assert bg.load_brands() == []
    assert bg.load_brands(limit=5) == []
    assert bg.to_brands(limit=3) == []


def test_load_brands_skips_unusable_records(roster):
    assert bg.available()
    brands = bg.load_brands()
    assert [b["id"] for b in brands] == ["0001", "0002", "0003"]
    by_id = {b["id"]: b for b in brands}
    assert by_id["0001"]["official_domains"] == ["alpha-example.test"]
    assert by_id["0001"]["official_handles"] == ["alphaexample"]
    assert by_id["0002"]["official_handles"] == ["beta-example", "betaexample"]  # fixed field order
    assert by_id["0003"]["official_handles"] == []
    for b in brands:
        assert "logo_path" in b  # with_logos=False -> logo_path key present
    assert by_id["0003"]["logo_path"] is None


def test_load_brands_is_deterministic_sorted_and_limited(roster):
    a = bg.load_brands(limit=2)
    b = bg.load_brands(limit=2)
    assert a == b
    assert [x["id"] for x in a] == ["0001", "0002"]
    ids = [x["id"] for x in bg.load_brands()]
    assert ids == sorted(ids)


def test_with_logos_returns_phash_key(roster):
    brands = bg.load_brands(with_logos=True)
    by_id = {b["id"]: b for b in brands}
    for b in brands:
        assert "logo_phash" in b
    assert isinstance(by_id["0001"]["logo_phash"], str) and by_id["0001"]["logo_phash"]
    assert by_id["0003"]["logo_phash"] is None  # no logo file


def test_to_brands_yields_valid_brand_instances(roster):
    brands = bg.to_brands(limit=3)
    assert len(brands) == 3
    for br in brands:
        assert isinstance(br, Brand)
        assert br.id and br.name.strip()
        assert br.official_handles or br.official_domains
        assert br.official_logo_hashes == []  # with_logos=False


def test_to_brands_with_logos_populates_hashes(roster):
    brands = bg.to_brands(with_logos=True)
    by_id = {b.id: b for b in brands}
    assert len(by_id["0001"].official_logo_hashes) == 1
    assert by_id["0003"].official_logo_hashes == []
    for br in brands:
        for h in br.official_logo_hashes:
            assert isinstance(h, str) and len(h) == 16  # 16-hex pHash digest
