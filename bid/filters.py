"""
Stage A: cheap deterministic filters. NO LLM here.

Purpose: reduce raw brand-search noise (a brand-name query can return thousands of
unrelated hits) to a small candidate set at near-zero cost, before any
vision-LLM call. Cut bulk cheaply, then let the expensive classifier look only
at survivors.

Two signals:
  1. handle distance   - homoglyph-fold then Levenshtein vs the brand's official
                         handles. A near-miss handle is a strong impersonation cue.
  2. logo similarity   - perceptual-hash (imagehash pHash) Hamming distance, with
                         a byte-level simhash fallback when imagehash/Pillow are
                         unavailable. Similar logos -> small Hamming distance.
                         Optional CLIP cosine (embeddings mode) adds a semantic tier.

Everything is pure Python. No native deps, runs in milliseconds.
"""
from __future__ import annotations

import hashlib
import unicodedata

from .domains import registrable as _registrable  # public-suffix aware (eTLD+1)

# Leetspeak layer, applied ON TOP of the Unicode confusables fold (UTS-39 does
# not treat leetspeak as confusable). Small hand table as the offline fallback.
_LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"}
_FALLBACK_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ո": "n", "ⅼ": "l", **_LEET,
}
_STRIP = set(" _.-​‌‍")  # spaces, separators, zero-width joiners

# Full Unicode UTS-39 confusables fold (Cyrillic/Greek/fullwidth/math-bold/etc).
try:  # pragma: no cover - import guard
    from confusable_homoglyphs import confusables as _conf

    _HAVE_CONF = True
except Exception:  # pragma: no cover
    _HAVE_CONF = False


def _fold_char(ch: str) -> str:
    """Map one confusable char to its Latin ASCII homoglyph (UTS-39)."""
    if ch.isascii():
        return ch
    if _HAVE_CONF:
        res = _conf.is_confusable(ch, preferred_aliases=["latin"])
        if res:
            for h in res[0].get("homoglyphs", []):
                c = h["c"]
                if len(c) == 1 and c.isascii() and c.isalnum():
                    return c.lower()
    return _FALLBACK_HOMOGLYPHS.get(ch, ch)


def normalize_handle(handle: str) -> str:
    """Lowercase, NFKC-normalize, fold Unicode confusables + leetspeak, strip separators.

    Folds Cyrillic 'wrenvalepаy' (Cyrillic a), fullwidth 'ｗｉｎｇｔｉｐｐａｙ', and math-bold
    variants all to 'wrenvalepay', which is what makes homoglyph impersonation handles collapse onto
    the official handle for the edit-distance check.
    """
    s = unicodedata.normalize("NFKC", handle).lower()
    out = []
    for ch in s:
        if ch in _STRIP:
            continue
        f = _fold_char(ch)
        out.append(_LEET.get(f, f))
    return "".join(out)


def is_mixed_script(handle: str) -> bool:
    """True if the handle mixes scripts (a strong homoglyph-attack signal, UTS-39)."""
    if _HAVE_CONF:
        try:
            return bool(_conf.is_dangerous(handle))
        except Exception:
            return False
    return any(not c.isascii() for c in handle)


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance. Pure Python, fine at fixture scale."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def handle_distance(handle: str, official_handles: list[str]) -> int:
    """Min folded edit distance to any official handle. 0 = folds to an official
    handle exactly (a homoglyph/leet lookalike). RAW distance, kept for lineage;
    it does NOT scale with length, so pair it with handle_similarity below."""
    n = normalize_handle(handle)
    return min(levenshtein(n, normalize_handle(h)) for h in official_handles)


def handle_similarity(handle: str, official_handles: list[str]) -> float:
    """Length-normalized similarity (Jaro-Winkler, [0,1]) to the nearest official
    handle after folding. Fixes the long-handle blind spot: 'kestovarcredit-support'
    scores high here even though its raw edit distance is large."""
    from rapidfuzz.distance import JaroWinkler
    n = normalize_handle(handle)
    return max(JaroWinkler.similarity(n, normalize_handle(h)) for h in official_handles)


def handle_contains_brand(handle: str, official_handles: list[str]) -> bool:
    """True if a (>=4 char) official handle is a substring of the folded candidate
    handle, or vice versa. Catches combosquats ('lorvannebank-support' -> contains
    'lorvannebank') that a fixed edit-distance cutoff would drop."""
    n = normalize_handle(handle)
    for h in official_handles:
        fh = normalize_handle(h)
        if len(fh) >= 4 and (fh in n or (len(n) >= 4 and n in fh)):
            return True
    return False


# --- byte-level fallback hash (simhash over character 3-grams) --------------
# A locality-sensitive hash over bytes, not pixels. Used only when imagehash is
# unavailable: similar byte content -> small Hamming distance.

_HASH_BITS = 64


def simhash(data: bytes) -> str:
    """64-bit simhash of the byte content, returned as 16 hex chars."""
    text = data.decode("utf-8", errors="ignore").lower()
    tokens = [text[i : i + 3] for i in range(max(len(text) - 2, 1))] or [text]
    vector = [0] * _HASH_BITS
    for tok in tokens:
        h = int.from_bytes(hashlib.md5(tok.encode()).digest()[:8], "big")
        for bit in range(_HASH_BITS):
            vector[bit] += 1 if (h >> bit) & 1 else -1
    out = 0
    for bit in range(_HASH_BITS):
        if vector[bit] > 0:
            out |= 1 << bit
    return f"{out:016x}"


def hamming(hex_a: str, hex_b: str) -> int:
    """Bit-difference between two 64-bit hex digests."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


# --- perceptual hash over pixels (imagehash pHash) ---------------------------
# imagehash.phash runs a DCT over the actual image, so visually-similar logos land within a few Hamming bits and
# unrelated logos are far. Same 64-bit hex space as simhash, so `hamming()` and
# every downstream threshold are unchanged. Falls back to simhash if imagehash
# is unavailable, so the pure-python path still runs.
try:  # pragma: no cover - import guard
    import io as _io

    import imagehash as _imagehash
    from PIL import Image as _Image

    _HAVE_IMAGEHASH = True
except Exception:  # pragma: no cover
    _HAVE_IMAGEHASH = False


def asset_phash(data: bytes) -> str | None:
    """Perceptual hash of an image asset as 16 hex chars, or None if not an image.

    Uses imagehash.phash (DCT-based pHash) when available; otherwise falls
    back to the byte-simhash so the pipeline still produces a comparable digest.
    """
    if _HAVE_IMAGEHASH:
        try:
            img = _Image.open(_io.BytesIO(data))
            return str(_imagehash.phash(img))  # 16 hex chars, parseable by hamming()
        except Exception:
            pass
    return simhash(data)


def logo_hamming(phash: str | None, official_logo_hashes: list[str]) -> int | None:
    """Min Hamming distance from this asset's phash to any known-good logo hash."""
    if not phash or not official_logo_hashes:
        return None
    return min(hamming(phash, ref) for ref in official_logo_hashes)


# --- Stage A decision -------------------------------------------------------

# Tuned conservatively: recall is protected by keeping the gate loose. Anything
# that even smells like the brand survives to the LLM stage; only clearly
# unrelated hits are dropped here.
HANDLE_KEEP_MAX = 4  # keep if handle within 4 edits of an official handle
HANDLE_SIM_MIN = 0.88  # keep if length-normalized handle similarity >= this
LOGO_KEEP_MAX = 22  # keep if logo within 22 bits of a known-good logo
CLIP_KEEP_MIN = 0.80  # keep if CLIP cosine to a brand logo >= 0.80 (semantic, embeddings mode)


def stage_a(candidate, brand, cti_badlist: set[str]) -> tuple["DetSignals", bool]:  # noqa: F821
    """Compute cheap signals and a keep/drop decision.

    Returns (signals, keep). `keep=False` means the candidate is dropped BEFORE
    any LLM call. The cut ratio is reported so the cascade's effect is measurable.
    """
    from .models import DetSignals  # local import to avoid a cycle

    handle_ed = (
        handle_distance(candidate.handle, brand.official_handles)
        if candidate.handle
        else None
    )
    handle_sim = (
        round(handle_similarity(candidate.handle, brand.official_handles), 3)
        if candidate.handle else None
    )
    handle_contains = (
        handle_contains_brand(candidate.handle, brand.official_handles)
        if candidate.handle else None
    )
    logo_ham = None
    for asset in candidate.assets:
        h = logo_hamming(asset.phash, brand.official_logo_hashes)
        if h is not None:
            logo_ham = h if logo_ham is None else min(logo_ham, h)

    cand_dom = _registrable(candidate.link_in_bio_url) if candidate.link_in_bio_url else ""
    domain_bad = (cand_dom in cti_badlist) if cand_dom else None

    # Brand-intention signals from the brand knowledge base.
    blob = " ".join(str(x or "").lower() for x in
                    (candidate.handle, candidate.display_name, candidate.bio))
    # The brand NAME is the strongest alias (what an impersonator copies), plus any
    # Wikidata aliases. Textual brand intention = any of these as a WHOLE-WORD match
    # (word boundaries avoid "chase" matching inside "purchase").
    import re
    alias_terms = [brand.name] + list(getattr(brand, "aliases", []))
    alias_hit = any(a and re.search(r"\b" + re.escape(a.lower()) + r"\b", blob) for a in alias_terms)
    legit_domains = set(getattr(brand, "official_domains", []))
    domain_is_legit = bool(cand_dom) and cand_dom in legit_domains
    handle_close = (
        (handle_ed is not None and handle_ed <= HANDLE_KEEP_MAX)
        or (handle_sim is not None and handle_sim >= HANDLE_SIM_MIN)
        or bool(handle_contains)
    )
    presents_intention = (
        handle_close
        or (logo_ham is not None and logo_ham <= LOGO_KEEP_MAX)
        or alias_hit
    )
    # Invariant: presents as the brand but the link domain is not one of
    # the brand's official domains. High-precision impersonation signal.
    domain_mismatch = bool(presents_intention and cand_dom and not domain_is_legit)

    clip_cos = getattr(candidate, "logo_clip_cosine", None)

    signals = DetSignals(
        handle_edit_distance=handle_ed,
        handle_similarity=handle_sim,
        handle_contains_brand=handle_contains,
        logo_phash_hamming=logo_ham,
        logo_clip_cosine=clip_cos,
        domain_in_cti_badlist=domain_bad,
        mixed_script_handle=is_mixed_script(candidate.handle) if candidate.handle else None,
        alias_in_text=alias_hit,
        domain_is_legit=domain_is_legit,
        domain_intention_mismatch=domain_mismatch,
    )

    # Keep if ANY signal points at the brand. Union, not intersection, protects recall.
    keep = bool(
        handle_close
        or (logo_ham is not None and logo_ham <= LOGO_KEEP_MAX)
        or (clip_cos is not None and clip_cos >= CLIP_KEEP_MIN)
        or domain_bad or alias_hit or domain_mismatch
    )
    return signals, keep


