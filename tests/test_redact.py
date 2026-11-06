"""
PII redaction invariants for bid.redact.

Pins:
  - each PII type is replaced by its placeholder and counted,
  - cards need a valid Luhn checksum and IBANs a valid mod-97 checksum,
  - URLs, domain names, IP addresses and dates are never modified, because they
    are the indicators the tool exists to find,
  - None and empty text pass through.
"""
import pytest

from bid.redact import redact


@pytest.mark.parametrize("text,expected", [
    ("write to jane.doe@example.com today", "write to [email] today"),
    ("support: help+bank@lorvanne-support.co.uk.", "support: [email]."),
    ("mailto:jane@example.com", "mailto:[email]"),
])
def test_email(text, expected):
    assert redact(text) == (expected, 1)


@pytest.mark.parametrize("phone", [
    "+1 (555) 123-4567",
    "+44 20 7946 0958",
    "020-7946-0958",
    "+447700900123",
    "555.123.4567",
    "6123 4567",
])
def test_phone(phone):
    assert redact(f"call {phone} now") == ("call [phone] now", 1)


def test_short_numbers_are_not_phones():
    for text in ("ext 555-1234", "order 1234567", "since 2019"):
        assert redact(text) == (text, 0)


@pytest.mark.parametrize("card", [
    "4111 1111 1111 1111",     # Visa test number
    "4111-1111-1111-1111",
    "5555555555554444",        # Mastercard test number
    "3782 822463 10005",       # Amex test number (15 digits)
])
def test_card(card):
    assert redact(f"card {card} ok") == ("card [card] ok", 1)


def test_card_requires_luhn():
    text = "card 4111 1111 1111 1112 ok"  # last digit breaks the checksum
    assert redact(text) == (text, 0)


@pytest.mark.parametrize("iban", [
    "DE89 3704 0044 0532 0130 00",
    "GB82WEST12345698765432",
    "GB82 WEST 1234 5698 7654 32",
    "NO93 8601 1117 947",          # shortest format (15 characters)
])
def test_iban(iban):
    assert redact(f"IBAN {iban} thanks") == ("IBAN [iban] thanks", 1)


def test_iban_requires_mod97():
    for text in ("IBAN DE89 3704 0044 0532 0130 01 thanks",
                 "IBAN GB82 WEST 1234 5698 7654 33 thanks"):
        assert redact(text) == (text, 0)  # left whole, not partly redacted as a phone


def test_iban_followed_by_an_upper_case_group():
    assert redact("BE68 5390 0754 7034 2024 ref") == ("[iban] 2024 ref", 1)


def test_urls_domains_and_ips_are_never_touched():
    for text in (
        "Login https://secure-lorvanne.test/verify?acct=4111111111111111&m=jane@example.com",
        "http://lorvanne.test@203.0.113.9/login",          # userinfo trick stays visible
        "lorvanne-bank.test/support?phone=+15551234567",    # bare domain with a path
        "www.lorvanne-0800123456.test",
        "visit lorvanne-0800123456.test or the homoglyph аррӏе-0800123456.com",  # Cyrillic letters
        "registered lookalike of wrenvalepay.test (dnstwist:homoglyph), resolves to 203.0.113.7, 198.51.100.2",
        "CT-log cert for secure.wrenvalepay-login.tk issued by R3 (not_before 2026-07-02)",
        "Est. 2019-2026, renewed 03.07.2026",
        "@lorvanne_bank official",
    ):
        assert redact(text) == (text, 0), text


def test_mixed_text_counts_every_replacement():
    text = ("DM jane@example.com or call +1 555 123 4567, pay 4111 1111 1111 1111 "
            "to DE89 3704 0044 0532 0130 00 via https://lorvanne-pay.test/?ref=jane@example.com")
    out, count = redact(text)
    assert count == 4
    assert out == ("DM [email] or call [phone], pay [card] "
                   "to [iban] via https://lorvanne-pay.test/?ref=jane@example.com")


def test_none_and_empty():
    assert redact(None) == (None, 0)
    assert redact("") == ("", 0)
    assert redact("no personal data here") == ("no personal data here", 0)
