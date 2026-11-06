"""
Generate deterministic synthetic logo PNGs for the fixtures.

Every image is drawn from basic shapes and text; nothing is downloaded and no
real brand artwork is used. The images are real pixels so that:
  1. perceptual hashing (imagehash.phash) runs on real image data;
  2. a vision-LLM classifier has a genuine image to look at.

Design so pHash is meaningful: each fictional brand has a 160x160 logo with its
own palette, mark (initials) and layout. The OFFICIAL logo and its FAKES share
the layout and use near-identical colours (small pHash Hamming distance), while
logos of different brands and the unrelated logos use a different layout and
palette (large Hamming distance).

Text is rendered with Pillow's bundled default font, so the output does not
depend on fonts installed on the machine.

    python bid/fixtures/gen_assets.py     # (re)writes bid/fixtures/assets/*.png
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
SIZE = 160

# brand id -> (bg RGB, accent RGB, initials, wordmark, layout)
BRANDS = {
    "lorvanne": ((18, 42, 92), (212, 175, 55), "LB", "LORVANNE", "bottom_bar"),
    "covelle": ((140, 20, 30), (240, 240, 240), "CP", "COVELLE", "top_bar"),
    "kestovar": ((20, 90, 80), (235, 200, 90), "KC", "KESTOVAR", "left_bar"),
    "tamberlyn": ((70, 40, 120), (250, 170, 60), "TS", "TAMBERLYN", "circle"),
    "alderine": ((30, 30, 34), (90, 190, 220), "AT", "ALDERINE", "diagonal"),
}

# Variant -> (bg delta, accent delta, initials transform, wordmark transform).
# Fakes perturb colours slightly and swap characters for look-alikes.
_DIGIT = {"O": "0", "B": "8", "I": "1", "S": "5", "T": "7", "A": "4"}


def _swap_initial(initials: str) -> str:
    for i, ch in enumerate(initials):
        if ch in _DIGIT:
            return initials[:i] + _DIGIT[ch] + initials[i + 1:]
    return initials


def _zero_homoglyph(word: str) -> str:
    for ch, glyph in (("O", "0"), ("I", "1"), ("E", "3")):
        if ch in word:
            return word.replace(ch, glyph, 1)
    return word


VARIANTS = {
    "official": ((0, 0, 0), (0, 0, 0), lambda i: i, lambda w: w),
    "fake1": ((2, 2, 4), (-2, -3, -3), lambda i: i, lambda w: w),  # near-identical
    "fake2": ((-2, -2, -4), (2, 3, 3), _swap_initial, lambda w: w),  # digit swap
    "fake3": ((4, 4, 6), (-4, -5, -5), lambda i: i, _zero_homoglyph),  # homoglyph
    "fake4": ((0, -2, -2), (3, 1, 0), lambda i: i, lambda w: w),  # promo-ad variant
    "fan": ((6, 10, 12), (-12, -10, 5), lambda i: i, lambda w: "FANCLUB"),  # close-ish
}

# Unrelated logos: different layout and palette (should be far from every bank).
UNRELATED = {
    "covelle_unrelated_logo": ((255, 200, 0), (40, 130, 70), "GX", "GARDEN", "top_bar"),
    "shoes_logo": ((235, 120, 30), (30, 30, 30), "SS", "SHOES", "circle"),
    "national_retail_logo": ((215, 215, 215), (190, 230, 190), "NR", "RETAIL", "diagonal"),
}


def _font(size: int):
    try:
        return ImageFont.load_default(size=size)  # Pillow >= 10.1, bundled font
    except TypeError:  # pragma: no cover - very old Pillow
        return ImageFont.load_default()


def _shift(rgb, delta):
    return tuple(max(0, min(255, c + d)) for c, d in zip(rgb, delta, strict=True))


def _centered(d, text, font, cx, y, fill):
    tb = d.textbbox((0, 0), text, font=font)
    d.text((cx - (tb[2] - tb[0]) / 2 - tb[0], y), text, font=font, fill=fill)


def draw_logo(bg, accent, initials, wordmark, layout) -> Image.Image:
    img = Image.new("RGB", (SIZE, SIZE), bg)
    d = ImageDraw.Draw(img)
    big, small = _font(70), _font(15)
    if layout == "bottom_bar":
        d.rectangle([0, SIZE - 34, SIZE, SIZE], fill=accent)
        _centered(d, initials, big, SIZE / 2, 18, accent)
        _centered(d, wordmark, small, SIZE / 2, SIZE - 28, bg)
    elif layout == "top_bar":
        d.rectangle([0, 0, SIZE, 34], fill=accent)
        _centered(d, wordmark, small, SIZE / 2, 9, bg)
        _centered(d, initials, big, SIZE / 2, 62, accent)
    elif layout == "left_bar":
        d.rectangle([0, 0, 34, SIZE], fill=accent)
        _centered(d, initials, big, 34 + (SIZE - 34) / 2, 28, accent)
        _centered(d, wordmark, small, 34 + (SIZE - 34) / 2, 120, accent)
    elif layout == "circle":
        d.ellipse([20, 14, SIZE - 20, SIZE - 26], fill=accent)
        _centered(d, initials, big, SIZE / 2, 32, bg)
        _centered(d, wordmark, small, SIZE / 2, SIZE - 24, accent)
    else:  # diagonal
        d.polygon([(0, SIZE), (SIZE, 40), (SIZE, SIZE)], fill=accent)
        _centered(d, initials, big, SIZE / 2, 10, accent)
        _centered(d, wordmark, small, SIZE * 0.68, SIZE - 26, bg)
    return img


def all_specs() -> dict[str, tuple]:
    specs = {}
    for brand_id, (bg, accent, initials, wordmark, layout) in BRANDS.items():
        for variant, (dbg, dacc, f_init, f_word) in VARIANTS.items():
            specs[f"{brand_id}_{variant}_logo"] = (
                _shift(bg, dbg), _shift(accent, dacc), f_init(initials), f_word(wordmark), layout)
    specs.update(UNRELATED)
    return specs


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    for name, spec in all_specs().items():
        out = ASSETS / f"{name}.png"
        draw_logo(*spec).save(out, format="PNG", optimize=False, compress_level=6)
        print("wrote", out.name)


if __name__ == "__main__":
    main()
