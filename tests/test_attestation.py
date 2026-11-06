"""
Deployment profiles and the runtime attestation (bid.attestation).

The network is never touched: the client factory bid.net.client is wrapped so every
client gets an httpx.MockTransport, while the egress hook stays in place.

Pins:
  - both bundled profiles load, validate and apply,
  - the default profile reproduces the historical settings,
  - effective_settings() reflects runtime state, not the profile file,
  - the attestation payload is deterministic for the same state,
  - the sovereign profile blocks username enumeration and the timestamp anchor,
  - the OpenRouter request body carries zero-data-retention routing and redacted
    text only when the profile asks for it, while the deterministic signals still
    use the raw text.
"""
import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import ValidationError

from bid import anchor, attestation, classify, net
from bid.attestation import DeploymentProfile, apply, attestation_payload, effective_settings, load_profile
from bid.classify import OpenRouterClassifier
from bid.filters import stage_a
from bid.models import Brand, Candidate
from bid.net import EgressDenied
from bid.sensors import username_enum
from bid.sensors.username_enum import UsernameEnumSensor

_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
_VERDICT = {"label": "impersonation", "confidence": 0.8, "reasoning": "lookalike handle",
            "injection_flagged": False, "impersonation_signals": ["handle"]}


@pytest.fixture(autouse=True)
def default_profile_after_each_test(monkeypatch):
    """Run hermetically and leave the process in its default profile state."""
    monkeypatch.delenv("BID_LLM_BASE_URL", raising=False)
    saved = (net.active(), classify.redact_pii, classify.zero_retention, classify.base_url)
    yield
    net.activate(saved[0])
    classify.redact_pii, classify.zero_retention, classify.base_url = saved[1:]


@pytest.fixture
def sent(monkeypatch):
    """Requests that reached the (mock) wire. Egress checks still run first."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json={
                "choices": [{"message": {"content": json.dumps(_VERDICT)}}],
                "usage": {"cost": 0.0},
            })
        return httpx.Response(200, json={})

    real_client = net.client

    def client_with_mock_transport(component, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(component, **kwargs)

    monkeypatch.setattr(net, "client", client_with_mock_transport)
    return requests


def _brand():
    return Brand(id="lv", name="Lorvanne Bank", official_handles=["lorvannebank"],
                 official_logo_hashes=[], regions=["GB"], aliases=["Lorvanne"],
                 official_domains=["lorvanne-bank.test"])


def _candidate():
    return Candidate(
        id="cand_test_1", brand_id="lv", sensor_name="test", platform="test",
        platform_uid="1", handle="lorvannebank_support", display_name="Lorvanne Bank Help",
        bio="Lorvanne support. DM jane.doe@example.com or call +44 20 7946 0958 to unlock your card.",
        link_in_bio_url="https://lorvanne-verify.test/login?ref=jane.doe@example.com",
        dedup_key="test:1", raw_observation_ref="raw1", first_seen=_NOW,
    )


def _classify(tmp_path, monkeypatch, key_env="OPENROUTER_API_KEY"):
    monkeypatch.setenv(key_env, "test-key-not-real")
    clf = OpenRouterClassifier(cache_dir=tmp_path, use_image=False)
    return clf.classify(_candidate(), _brand())


def _chat_requests(requests):
    return [r for r in requests if r.url.path.endswith("/chat/completions")]


# --- profiles --------------------------------------------------------------

def test_bundled_profiles_load():
    default = load_profile("default")
    assert (default.egress, default.redact_pii, default.zero_retention) == (None, False, False)
    assert default.llm_base_url is None and default.allow_timestamp_anchor is True

    sovereign = load_profile("sovereign")
    assert sovereign.redact_pii and sovereign.zero_retention
    assert sovereign.allow_timestamp_anchor is False and sovereign.llm_base_url is None
    for denied in ("sensor:username_enum", "asset_fetch", "enrich:favicon", "anchor"):
        assert sovereign.egress[denied] == []
    assert sovereign.egress["classifier"] == ["openrouter.ai"]
    assert "llm_base_url" in sovereign.notes


def test_default_profile_reproduces_historical_settings():
    apply(load_profile("default"))
    assert net.active().unrestricted
    assert classify.redact_pii is False and classify.zero_retention is False
    assert classify.base_url == "https://openrouter.ai/api/v1"


def test_load_profile_from_path_and_unknown_name(tmp_path):
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({**load_profile("default").model_dump(), "name": "custom"}))
    assert load_profile(str(path)).name == "custom"
    assert load_profile(path).name == "custom"
    with pytest.raises(FileNotFoundError):
        load_profile("no_such_profile")


@pytest.mark.parametrize("change", [
    {"redact_pi": True},                                          # misspelt key
    {"redact_pii": "true"},                                       # loosely typed value
    {"allow_timestamp_anchor": False},                            # anchor not denied by egress
    {"egress": {"classifier": ["https://openrouter.ai"]}},        # not a host pattern
    {"egress": {"classifier": ["openrouter.ai"]}, "llm_base_url": "http://llm.internal:8000/v1"},
    {"llm_base_url": "llm.internal"},                             # no scheme
])
def test_inconsistent_profiles_are_rejected(change):
    data = {**load_profile("default").model_dump(), **change}
    with pytest.raises(ValidationError):
        DeploymentProfile.model_validate(data)


# --- effective settings and the payload -------------------------------------

def test_effective_settings_reflect_apply():
    apply(load_profile("sovereign"))
    s = effective_settings()
    assert s["egress"]["mode"] == "allowlist"
    assert s["egress"]["allow"]["sensor:username_enum"] == []
    assert s["classifier"] == {"base_url": "https://openrouter.ai/api/v1", "egress_allowed": True,
                               "redact_pii": True, "zero_retention": True, "zdr_routing": True}
    assert s["timestamp_anchor"] == {"egress_allowed": False}

    apply(load_profile("default"))
    s = effective_settings()
    assert s["egress"] == {"mode": "unrestricted"}
    assert s["classifier"]["redact_pii"] is False and s["classifier"]["zdr_routing"] is False
    assert s["timestamp_anchor"] == {"egress_allowed": True}


def test_effective_settings_come_from_runtime_not_the_file(monkeypatch):
    sovereign = load_profile("sovereign")
    apply(sovereign)
    assert attestation_payload(sovereign, "dep-1")["profile_in_effect"] is True
    classify.redact_pii = False  # runtime drift after apply()
    assert effective_settings()["classifier"]["redact_pii"] is False
    assert attestation_payload(sovereign, "dep-1")["profile_in_effect"] is False

    default = load_profile("default")
    apply(default)
    monkeypatch.setenv("BID_LLM_BASE_URL", "https://user:secret@eu.openrouter.ai/api/v1?key=abc")
    payload = attestation_payload(default, "dep-1")
    assert payload["profile_in_effect"] is False  # env changed after apply(): not what runs
    assert payload["effective_settings"]["env"]["BID_LLM_BASE_URL"] == "https://eu.openrouter.ai/api/v1"
    assert "secret" not in json.dumps(payload)


def test_payload_is_deterministic_for_the_same_state():
    profile = load_profile("sovereign")
    apply(profile)
    first = attestation_payload(profile, "dep-eu-1")
    second = attestation_payload(load_profile("sovereign"), "dep-eu-1")
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    assert first["deployment_id"] == "dep-eu-1"
    assert first["profile_name"] == "sovereign" and first["profile_in_effect"] is True
    assert first["profile_sha256"] == profile.sha256() and len(first["profile_sha256"]) == 64
    assert first["profile_sha256"] != load_profile("default").sha256()
    assert first["effective_settings"] == effective_settings()
    assert first["package_version"] and first["python_version"].count(".") == 2
    deps = first["dependency_versions"]
    assert list(deps) == sorted(deps) and set(deps) == set(attestation.KEY_DEPENDENCIES)
    canonical = json.dumps(deps, sort_keys=True, separators=(",", ":")).encode()
    assert first["dependency_versions_sha256"] == hashlib.sha256(canonical).hexdigest()

    apply(load_profile("default"))
    assert attestation_payload(profile, "dep-eu-1") != first


# --- enforcement under the sovereign profile --------------------------------

def test_sovereign_blocks_username_enum(sent, tmp_path, monkeypatch):
    apply(load_profile("sovereign"))
    with pytest.raises(EgressDenied):
        net.get("sensor:username_enum", "https://t.me/lorvannebank_support")

    monkeypatch.setattr(username_enum, "_CACHE", tmp_path)  # force the ruleset fetch
    sensor = UsernameEnumSensor(platforms=["Telegram"], delay=0)
    with pytest.raises(EgressDenied):
        sensor._wmn_sites()
    assert list(sensor.scan(_brand(), _NOW)) == []
    assert "EgressDenied" in sensor.health()["note"]
    assert sent == []  # nothing reached the wire

    net.get("sensor:ct_logs", "https://crt.sh/", params={"q": "%lorvanne%", "output": "json"})
    assert [r.url.host for r in sent] == ["crt.sh"]  # a listed host still goes through


def test_sovereign_blocks_the_timestamp_anchor(sent):
    apply(load_profile("sovereign"))
    assert anchor.timestamp(b"receipt bytes") is None  # both TSAs refused, graceful
    assert sent == []


# --- the hosted model request ------------------------------------------------

def test_default_profile_sends_raw_text_without_routing_fields(sent, tmp_path, monkeypatch):
    apply(load_profile("default"))
    verdict = _classify(tmp_path, monkeypatch)
    [request] = _chat_requests(sent)
    assert str(request.url) == "https://openrouter.ai/api/v1/chat/completions"
    body = json.loads(request.content)
    assert "provider" not in body
    prompt = body["messages"][0]["content"][0]["text"]
    assert "jane.doe@example.com" in prompt
    assert verdict.redactions == 0 and verdict.label == "impersonation"


def test_sovereign_profile_redacts_and_requests_zero_retention(sent, tmp_path, monkeypatch):
    apply(load_profile("sovereign"))
    verdict = _classify(tmp_path, monkeypatch)
    [request] = _chat_requests(sent)
    assert request.url.host == "openrouter.ai"
    body = json.loads(request.content)
    assert body["provider"] == {"zdr": True, "data_collection": "deny"}
    prompt = body["messages"][0]["content"][0]["text"]
    assert "jane.doe@example.com" not in prompt.split("link_in_bio_url")[0]
    assert "7946" not in prompt
    assert "[email]" in prompt and "[phone]" in prompt
    assert "lorvanne-verify.test/login?ref=jane.doe@example.com" in prompt  # the link is an indicator
    assert verdict.redactions == 2
    # the deterministic signals are computed on the raw candidate, not the redacted one
    assert verdict.signals == stage_a(_candidate(), _brand(), set())[0]


def test_self_hosted_endpoint_replaces_openrouter(sent, tmp_path, monkeypatch):
    profile = DeploymentProfile(
        name="self-hosted", egress={"classifier": ["llm.internal"]}, redact_pii=True,
        zero_retention=True, llm_base_url="http://llm.internal:8000/v1/",
        allow_timestamp_anchor=False,
    )
    apply(profile)
    verdict = _classify(tmp_path, monkeypatch, key_env="BID_LLM_API_KEY")
    [request] = _chat_requests(sent)
    assert str(request.url) == "http://llm.internal:8000/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer test-key-not-real"
    assert "provider" not in json.loads(request.content)  # routing fields are OpenRouter-only
    assert verdict.redactions == 2
    s = effective_settings()["classifier"]
    assert s["zero_retention"] is True and s["zdr_routing"] is False and s["egress_allowed"] is True
    assert attestation_payload(profile, "dep-onprem")["profile_in_effect"] is True


def test_model_call_denied_by_egress_degrades_to_fallback(sent, tmp_path, monkeypatch):
    apply(load_profile("sovereign"))
    classify.base_url = "https://llm.internal/v1"  # not on the allowlist; the fixture restores it
    verdict = _classify(tmp_path, monkeypatch, key_env="BID_LLM_API_KEY")
    assert sent == []
    assert verdict.label == "suspicious" and "EgressDenied" in verdict.reasoning
    assert effective_settings()["classifier"]["egress_allowed"] is False


def test_openrouter_key_is_never_sent_to_another_endpoint(sent, tmp_path, monkeypatch):
    monkeypatch.delenv("BID_LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key-not-real")
    classify.base_url = "http://llm.internal:8000/v1"  # the fixture restores it
    assert classify.api_key() is None
    with pytest.raises(RuntimeError, match="no API key"):
        OpenRouterClassifier(cache_dir=tmp_path, use_image=False)
    assert sent == []
    assert classify.api_key("https://openrouter.ai/api/v1") == "openrouter-key-not-real"
