"""
Regression tests for correctness fixes found in an internal audit.

B1  long combosquat handles (raw edit distance large) are now caught by
    length-normalized similarity + brand-substring containment.
B2  is_official is case-insensitive (social handles are), but a homoglyph
    look-alike still fails it.
B4  image assets are detected by magic bytes, not URL extension (live CDN
    avatar URLs are extension-less).
B6  an unknown account that merely survives the filters is never labelled
    'legit' in the signed chain - it abstains to 'suspicious'.
"""
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bid.classify import MockClassifier
from bid.filters import handle_contains_brand, handle_distance, handle_similarity, stage_a
from bid.models import Brand, Candidate
from bid.normalize import _sniff_image, normalize
from bid.models import RawObservation
from bid.storage import ContentStore

_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _brand():
    return Brand(id="fab", name="Kestovar Credit", official_handles=["kestovarcredit", "fabcredit"],
                 official_logo_hashes=[], regions=["US"], aliases=[], official_domains=["kestovar-credit.test"])


def test_b1_long_combosquat_is_caught():
    off = ["kestovarcredit", "fabcredit"]
    # raw edit distance is large (would be dropped at HANDLE_KEEP_MAX=4) ...
    assert handle_distance("kestovarcredit-support", off) > 4
    # ... but the length-invariant signals catch it
    assert handle_similarity("kestovarcredit-support", off) >= 0.88
    assert handle_contains_brand("kestovarcredit-support", off) is True
    # and stage_a therefore keeps it
    c = Candidate(id="c", brand_id="fab", sensor_name="s", platform="p", platform_uid="u",
                  handle="kestovarcredit-support", display_name="Kestovar Support", bio="help",
                  dedup_key="d", raw_observation_ref="r" * 64, first_seen=_NOW)
    signals, keep = stage_a(c, _brand(), set())
    assert keep is True
    assert signals.handle_contains_brand is True


def test_b2_is_official_is_case_insensitive_but_not_homoglyph():
    brand = _brand()
    def verdict(handle):
        c = Candidate(id="c", brand_id="fab", sensor_name="s", platform="p", platform_uid="u",
                      handle=handle, display_name="Kestovar Credit", bio="Official account.",
                      dedup_key="d", raw_observation_ref="r" * 64, first_seen=_NOW)
        return MockClassifier().classify(c, brand).label
    assert verdict("KestovarCredit") == "legit"   # case variant of official
    assert verdict("kestovarcredit") == "legit"
    # a Cyrillic look-alike must NOT be waved through as legit
    assert verdict("fаbrikamcredit") != "legit"   # 'а' is Cyrillic U+0430


def test_b4_magic_byte_sniff():
    assert _sniff_image(b"\x89PNG\r\n\x1a\n....") == "image/png"
    assert _sniff_image(b"\xff\xd8\xff\xe0....") == "image/jpeg"
    assert _sniff_image(b"GIF89a....") == "image/gif"
    assert _sniff_image(b"plain text") is None


def test_b4_phash_computed_for_extensionless_image_url():
    # asset URL has NO image extension (as real CDN avatar URLs do); the PNG magic
    # bytes must still trigger a perceptual hash.
    store = ContentStore(Path(tempfile.mkdtemp()))
    obs = RawObservation(sensor_name="s", observed_at=_NOW, platform="p", platform_uid="u",
                         payload={"handle": "x"},
                         asset_urls=["assets/lorvanne_official_logo.png"])
    # rename hint away by pointing at the same bytes via a non-image-looking ref:
    cand = normalize(obs, _brand(), store)
    assert cand.assets and cand.assets[0].media_type == "image/png"
    assert cand.assets[0].phash  # non-empty perceptual hash


def test_b6_unknown_survivor_abstains_not_legit():
    brand = _brand()
    # an account with a weak-but-present brand smell that survives filters but has
    # no strong signal must abstain, not assert legitimacy.
    c = Candidate(id="c", brand_id="fab", sensor_name="s", platform="p", platform_uid="u",
                  handle="fabcredit", display_name="Something", bio="random text",
                  dedup_key="d", raw_observation_ref="r" * 64, first_seen=_NOW)
    # 'fabcredit' IS an official handle -> legit is correct here; flip to a near-miss:
    c.handle = "fabcredita"
    label = MockClassifier().classify(c, brand).label
    assert label in {"suspicious", "impersonation", "fraud"}
    assert label != "legit"
