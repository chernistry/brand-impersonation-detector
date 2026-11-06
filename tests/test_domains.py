from bid.domains import registrable


def test_multi_part_public_suffix():
    assert registrable("https://a.b.example.co.uk/login") == "example.co.uk"


def test_private_suffix_is_a_suffix():
    # A page on one github.io / pages.dev subdomain must not make the whole
    # hosting domain look like one registrable domain.
    assert registrable("brand.github.io") == "brand.github.io"
    assert registrable("https://evil-login.pages.dev/x") == "evil-login.pages.dev"
    assert registrable("brand.github.io") != registrable("evil.github.io")


def test_reserved_fixture_tld():
    assert registrable("https://login.lorvanne-bank.test/x") == "lorvanne-bank.test"
