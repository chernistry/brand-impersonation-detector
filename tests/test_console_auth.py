import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from bid import server  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("BID_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("BID_CONSOLE_TOKEN", raising=False)
    return TestClient(server.app)


def test_page_has_nonce_csp_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">' in r.text
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/").headers["content-security-policy"] != csp  # fresh nonce per request


def test_api_open_without_token(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["auth"] is False


def test_api_needs_token_when_set(client, monkeypatch):
    monkeypatch.setenv("BID_CONSOLE_TOKEN", "s3cret-token-value")
    assert client.get("/api/health").status_code == 401
    ok = client.get("/api/health", headers={"Authorization": "Bearer s3cret-token-value"})
    assert ok.status_code == 200 and ok.json()["auth"] is True
    assert client.get("/api/health", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_login_sets_derived_cookie(client, monkeypatch):
    monkeypatch.setenv("BID_CONSOLE_TOKEN", "s3cret-token-value")
    assert client.post("/api/login", json={"token": "nope"}).status_code == 401
    r = client.post("/api/login", json={"token": "s3cret-token-value"})
    assert r.status_code == 200
    cookie = r.cookies.get("bid_console")
    assert cookie and "s3cret-token-value" not in cookie
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()
    assert client.get("/api/health").status_code == 200  # the client keeps the cookie


def test_refuses_remote_listen_without_token(monkeypatch, capsys):
    monkeypatch.delenv("BID_CONSOLE_TOKEN", raising=False)
    assert server.main(["--host", "0.0.0.0", "--no-open"]) == 2
    assert "BID_CONSOLE_TOKEN" in capsys.readouterr().err


def test_refuses_remote_listen_with_development_signing_keys(monkeypatch, capsys):
    monkeypatch.setenv("BID_CONSOLE_TOKEN", "s3cret-token-value")
    assert server.main(["--host", "0.0.0.0", "--no-open"]) == 2
    err = capsys.readouterr().err
    assert "development signing keys" in err and "BID_ED25519_SEED" in err
