"""
Deterministic synthetic corpus of fake social accounts, modelled on the attack
families real brand-impersonation programmes actually see. This exists to STRESS
the pipeline at volume and to measure per-family recall - not to claim field
accuracy (the corpus is self-labelled by construction; see scale_test.py).

Every candidate is generated from a seeded RNG keyed by its index, so the whole
corpus is byte-reproducible: two runs produce identical candidates and identical
metrics. No network, no wall-clock.

Attack families (with ground-truth intent):
  legit          - the brand's own exact-handle account                (benign)
  fan            - self-declared unaffiliated fan/parody                (benign)
  unrelated      - shares only a generic dictionary word with the brand (benign)
  homoglyph      - leet/confusable handle + cloned logo                 (impersonation)
  combosquat     - brand + suffix (support/secure/verify/...)           (impersonation)
  typo           - transposition/omission/insertion of the handle       (impersonation)
  lookalike_link - presents as brand, link domain is a non-official LA   (impersonation)
  cti_link       - link domain is on the CTI bad-list                   (fraud)
  cred_phish     - bio explicitly solicits credentials/card/account     (fraud)

The family -> ground-truth-positive map is the single source of truth for scoring.
"""
from __future__ import annotations

import random

from ..models import Brand, RawObservation
from ..run_pipeline import FIXED_NOW, load_brands

# Which families are true brand impersonations the pipeline must surface.
POSITIVE_FAMILIES = {"homoglyph", "combosquat", "typo", "lookalike_link", "cti_link", "cred_phish"}
FRAUD_FAMILIES = {"cti_link", "cred_phish"}  # the ideal label is fraud, not just impersonation
BENIGN_FAMILIES = {"legit", "fan", "unrelated"}

# CTI bad-list domains the fixtures know about (see cti_badlist.json), so a
# cti_link candidate reproduces the real reverse-pivot signal. One per brand.
_CTI_BAD = {
    "lorvanne": "lorvanne-secure.test", "covelle": "covelle-verify.test",
    "kestovar": "kestovar-secure.test", "tamberlyn": "tamberlyn-verify.test",
    "alderine": "alderine-secure.test",
}

_LEET = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
_SUFFIXES = ["support", "secure", "verify", "help", "official", "rewards",
             "promo", "giveaway", "care", "team", "online", "service", "us", "app"]
_TLDS = ["net", "co", "info", "online", "site", "live", "vip", "xyz"]
_CRED_BIOS = [
    "Verify your identity here to avoid suspension.",
    "DM us your account number to unlock your card.",
    "Security team. Confirm your card details now.",
    "Your account is locked. Send your login to restore access.",
    "Update your card CVV to keep your account active.",
]
_LURE_BIOS = [
    "Limited promotion. Tap to claim your reward now.",
    "Special offer for customers, verify to receive.",
    "Congratulations winner. Claim your prize today.",
    "Official support line, message us to reactivate.",
    "Exclusive cashback event. Act before it expires.",
]
_FAN_BIOS = [
    "Unofficial fan account. We are not affiliated with the bank.",
    "Fan page. Not the official account, just love the brand.",
    "Parody account. Not affiliated with anyone.",
]
_UNRELATED = [
    ("shoes", "Lorvanne Shoes Outlet", "Cheapest sneakers in town. Free shipping."),
    ("cafe", "Harbor Light Cafe", "Fresh coffee and pastries downtown."),
    ("gym", "Prime Fitness Club", "Personal training and group classes."),
    ("books", "Corner Bookshop", "Used and rare books, open daily."),
]


def _leetify(s: str, rng: random.Random) -> str:
    chars = list(s)
    swaps = [i for i, c in enumerate(chars) if c.lower() in _LEET]
    if swaps:
        i = rng.choice(swaps)
        chars[i] = _LEET[chars[i].lower()]
    return "".join(chars)


def _typo(s: str, rng: random.Random, avoid: frozenset[str] = frozenset()) -> str:
    """One transposition, omission or insertion. A result that equals the input or
    another official handle is not a typo (swapping a doubled letter is a no-op), so
    draw again; the draw sequence stays deterministic for a seeded rng."""
    if len(s) < 4:
        return s + rng.choice("aeiou")
    taken = avoid | {s}
    for _ in range(32):
        mode = rng.choice(["transpose", "omit", "insert"])
        i = rng.randint(1, len(s) - 2)
        if mode == "transpose":
            out = s[:i] + s[i + 1] + s[i] + s[i + 2:]
        elif mode == "omit":
            out = s[:i] + s[i + 1:]
        else:
            out = s[:i] + rng.choice("aeioulnrst") + s[i:]
        if out.lower() not in taken:
            return out
    return s + rng.choice("aeiou")


def _logo_for(family: str, brand_id: str, rng: random.Random) -> list[str]:
    """Map a family to a bundled logo fixture so pHash/CLIP fire realistically. Every
    brand in brands.json ships official + fake1..4 + fan logos (see
    fixtures/gen_assets.py), so this is generic across all fixture brands."""
    fakes = [f"assets/{brand_id}_fake{i}_logo.png" for i in (1, 2, 3, 4)]
    official = f"assets/{brand_id}_official_logo.png"
    unrelated = ["assets/shoes_logo.png", "assets/national_retail_logo.png",
                 "assets/covelle_unrelated_logo.png"]
    if family == "legit":
        return [official]
    if family == "fan":
        return [f"assets/{brand_id}_fan_logo.png"]
    if family == "unrelated":
        return [rng.choice(unrelated)]
    return [rng.choice(fakes)]  # impersonation/fraud families clone the logo


def _handle_and_link(family: str, brand: Brand, rng: random.Random, idx: int):
    base = brand.official_handles[0]
    dom_root = base.replace("_", "").replace("bank", "").strip("_") or base
    if family == "legit":
        return brand.official_handles[idx % len(brand.official_handles)], None
    if family == "fan":
        return f"{base}fans{idx}", None
    if family == "unrelated":
        u = _UNRELATED[idx % len(_UNRELATED)]
        return f"{u[0]}{idx}", None
    if family == "homoglyph":
        return _leetify(base, rng), None
    if family == "typo":
        avoid = frozenset(h.lower() for h in brand.official_handles)
        return _typo(base, rng, avoid), None
    if family == "combosquat":
        return f"{base}-{rng.choice(_SUFFIXES)}", None
    if family == "lookalike_link":
        tld = rng.choice(_TLDS)
        return f"{base}_{rng.choice(_SUFFIXES)}", f"https://{dom_root}-rewards.{tld}/claim"
    if family == "cti_link":
        return f"{base}-{rng.choice(['support', 'secure', 'verify'])}", f"https://{_CTI_BAD.get(brand.id, 'lorvanne-secure.test')}/login"
    if family == "cred_phish":
        return _leetify(base, rng), None
    return base, None


def _display_bio(family: str, brand: Brand, rng: random.Random, idx: int):
    if family == "legit":
        return brand.name, f"Official verified account of {brand.name}."
    if family == "fan":
        return f"{brand.name} Fans", _FAN_BIOS[idx % len(_FAN_BIOS)]
    if family == "unrelated":
        u = _UNRELATED[idx % len(_UNRELATED)]
        return u[1], u[2]
    if family == "cred_phish" or family == "cti_link":
        return f"{brand.name} {rng.choice(['Secure', 'Support', 'Security'])}", rng.choice(_CRED_BIOS)
    return f"{brand.name} {rng.choice(['Promo', 'Rewards', 'Official', 'Global'])}", rng.choice(_LURE_BIOS)


def generate_corpus(per_brand: int = 100, seed: int = 20260712, brands: list[Brand] | None = None):
    """Yield (RawObservation, brand_id, family, is_positive) tuples, deterministic."""
    brands = brands or load_brands()
    # Distribution over families per brand (weighted toward attacks, some benign).
    plan = (["homoglyph"] * 12 + ["combosquat"] * 22 + ["typo"] * 14 +
            ["lookalike_link"] * 16 + ["cti_link"] * 8 + ["cred_phish"] * 12 +
            ["fan"] * 6 + ["unrelated"] * 8 + ["legit"] * 2)
    out = []
    n = 0
    for brand in brands:
        for i in range(per_brand):
            family = plan[i % len(plan)]
            rng = random.Random(f"{seed}:{brand.id}:{i}")
            handle, link = _handle_and_link(family, brand, rng, i)
            display, bio = _display_bio(family, brand, rng, i)
            uid = f"{family}_{i:03d}"
            obs = RawObservation(
                sensor_name="corpus_synth",
                observed_at=FIXED_NOW,
                platform="corpus",
                platform_uid=f"{brand.id}_{uid}",
                payload={"handle": handle, "display_name": display, "bio": bio,
                         "link_in_bio_url": link},
                asset_urls=_logo_for(family, brand.id, rng),
            )
            out.append((obs, brand.id, family, family in POSITIVE_FAMILIES))
            n += 1
    return out
