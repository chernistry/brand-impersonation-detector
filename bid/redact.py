"""
PII redaction for scraped text before it is sent to a hosted model.

redact() replaces e-mail addresses with "[email]", phone numbers with "[phone]",
payment card numbers (Luhn-valid only) with "[card]" and IBANs (mod-97 valid only)
with "[iban]", and returns the new text with the number of replacements.

URLs, domain names and IP addresses are never modified: they are the indicators
this tool exists to find. Nothing inside a URL is replaced, and no number is carved
out of a domain name, an IP address or a date.

The number rules are deliberately broad: a run of 8 to 15 digits with phone-style
separators is treated as a phone number. Over-redaction only removes context from an
advisory model prompt; the deterministic signals are always computed on the raw
text (see classify.OpenRouterClassifier).
"""
from __future__ import annotations

import re

EMAIL = "[email]"
PHONE = "[phone]"
CARD = "[card]"
IBAN = "[iban]"

# DNS label: letter or digit at both ends, hyphens inside. \w keeps non-ASCII names
# intact on purpose, since a homoglyph domain is itself an indicator.
_LABEL = r"[^\W_](?:[\w-]{0,61}[^\W_])?"
# Top-level label: starts with a letter, at least two characters.
_TLD = r"[^\W\d_](?:[\w-]{0,61}[^\W_])"
_DOMAIN = rf"(?:{_LABEL}\.)+{_TLD}"

# URLs with a scheme, "www." URLs and bare "domain/path" URLs. The scheme length is
# bounded so a long run of scheme characters cannot force quadratic backtracking.
_URL_RE = re.compile(rf"(?:\b[a-z][a-z0-9+.-]{{0,31}}://|\bwww\.)\S+|(?<![\w.@-]){_DOMAIN}/\S*", re.I)
_DOMAIN_RE = re.compile(rf"(?<![\w.-]){_DOMAIN}(?![\w-])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
# ISO dates (optionally with a time), day-first dates and year ranges: all shaped
# like phone numbers, none of them a phone number.
_DATE_RE = re.compile(
    r"(?<![\w.-])(?:"
    r"(?:19|20)\d\d-\d\d?-\d\d?(?:[T ]\d\d?:\d\d(?::\d\d)?)?"
    r"|\d\d?[./-]\d\d?[./-](?:19|20)\d\d"
    r"|(?:19|20)\d\d ?[-/] ?(?:19|20)\d\d"
    r")(?![\w-])"
)
_EMAIL_RE = re.compile(rf"(?<![\w.%+-])[\w.%+-]+@{_DOMAIN}(?![\w-])")
# IBAN as printed: country code, check digits, then the account part in groups of
# four (spaces optional) with a shorter final group. Upper case only.
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d\d(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])"
)
# A run of digits joined by single separators (space, dot, hyphen) or parenthesised
# area codes, with an optional leading "+". It may not start or end inside a word or
# inside a longer number. The repeat is bounded so scraped input cannot force long
# backtracking.
_NUMBER_RE = re.compile(
    r"(?<![\w+])(?<!\d[ .-])\+?(?:\(\d{1,5}\)|\d)(?:[ .-]?(?:\(\d{1,5}\)|\d)){0,24}(?!\w)(?![ .-]\d)"
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(candidate: str) -> bool:
    compact = candidate.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def _iban_end(text: str, start: int, end: int) -> int | None:
    """End of the longest valid IBAN that starts at `start` and ends on a group
    boundary at or before `end` (a trailing upper-case word or number may have been
    swallowed as one more group). None when there is none."""
    while end > start:
        if _iban_ok(text[start:end]):
            return end
        cut = text.rfind(" ", start, end)
        if cut <= start:
            return None
        end = cut
    return None


def _number_label(run: str) -> str | None:
    digits = re.sub(r"\D", "", run)
    # Card numbers are printed with spaces or dashes only, never "+", "(" or dots.
    if 13 <= len(digits) <= 19 and not re.search(r"[+(.]", run) and _luhn_ok(digits):
        return CARD
    if 8 <= len(digits) <= 15:
        return PHONE
    return None


def redact(text: str | None) -> tuple[str | None, int]:
    """Return `text` with PII replaced by placeholders, and the number of replacements.

    None and empty text are returned unchanged with a count of 0.
    """
    if not text:
        return text, 0

    # One flag per character: 1 means no rule may replace that character.
    kept = bytearray(len(text))

    def keep(start: int, end: int) -> None:
        kept[start:end] = b"\x01" * (end - start)

    def is_free(start: int, end: int) -> bool:
        return kept.find(1, start, end) < 0

    for m in _URL_RE.finditer(text):
        keep(*m.span())
    hits: list[tuple[int, int, str]] = []
    for m in _EMAIL_RE.finditer(text):
        if is_free(*m.span()):
            hits.append((m.start(), m.end(), EMAIL))

    # Numbers may not be carved out of domains, IP addresses, dates or e-mails either.
    for regex in (_DOMAIN_RE, _IPV4_RE, _DATE_RE):
        for m in regex.finditer(text):
            keep(*m.span())
    for start, end, _ in hits:
        keep(start, end)

    for m in _IBAN_RE.finditer(text):
        if not is_free(*m.span()):
            continue
        end = _iban_end(text, m.start(), m.end())
        if end is None:
            keep(*m.span())  # IBAN-shaped but not valid: leave the token whole
        else:
            hits.append((m.start(), end, IBAN))
            keep(m.start(), end)

    for m in _NUMBER_RE.finditer(text):
        if not is_free(*m.span()):
            continue
        label = _number_label(m.group())
        if label:
            hits.append((m.start(), m.end(), label))

    if not hits:
        return text, 0
    out: list[str] = []
    pos = 0
    for start, end, label in sorted(hits):
        out.append(text[pos:start])
        out.append(label)
        pos = end
    out.append(text[pos:])
    return "".join(out), len(hits)
