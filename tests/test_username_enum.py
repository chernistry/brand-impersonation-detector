"""
Offline invariants for the live username-enumeration sensor. The network scan is
best-effort and not tested here; these pin the deterministic parts: the look-alike
permutation grammar and the WhatsMyName existence-detection logic.
"""
from bid.sensors.username_enum import UsernameEnumSensor, permutations


def test_permutations_cover_attack_families():
    p = permutations(["wrenvalepay"], limit=40)
    assert "wr3nvalepay" in p or "p4ypal" in p or "payp4l" in p   # leet/homoglyph
    assert "wrenvalepaysupport" in p                              # combosquat
    assert "wrenvalepay_support" in p                             # separator combosquat
    assert all(x.lower() != "wrenvalepay" for x in p)             # never the official itself
    # deterministic
    assert permutations(["wrenvalepay"], limit=40) == p


def test_wmn_existence_detection():
    # existence = status==e_code AND e_string present AND m_string absent
    telegram = {"e_code": 200, "e_string": "tgme_page_title", "m_string": "noindex, nofollow"}
    assert UsernameEnumSensor._exists(telegram, "<div class=tgme_page_title>x</div>", 200) is True
    assert UsernameEnumSensor._exists(telegram, "meta noindex, nofollow", 200) is False   # missing marker
    assert UsernameEnumSensor._exists(telegram, "tgme_page_title", 404) is False           # wrong code
    tiktok = {"e_code": 200, "e_string": '"author_url":', "m_string": '"code":400'}
    assert UsernameEnumSensor._exists(tiktok, '{"author_url":"..."}', 200) is True
    assert UsernameEnumSensor._exists(tiktok, '{"code":400}', 400) is False


def test_health_shape():
    h = UsernameEnumSensor().health()
    assert h["sensor"] == "username_enum"
    assert h["mode"] == "live"
    assert "ban_rate" in h
