"""
Domain-sensor invariants: typosquat + CT-log emit valid, pipeline-fit candidates
and stay offline-safe. Network is mocked so these are deterministic and keyless.

Pins:
  - a resolving typosquat becomes a Candidate that SURVIVES the cheap filter,
  - a CT lookalike cert becomes a Candidate that SURVIVES the cheap filter,
  - both degrade to "yield nothing + healthy heartbeat" when the network fails,
  - the allowlist drops the brand's own domain.
"""
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import bid.enrich as enrich
from bid.filters import stage_a
from bid.models import Brand, RawObservation, Sensor
from bid.normalize import normalize
from bid.sensors.allowlist import Allowlist
from bid.sensors.ct_logs import CTLogSensor
from bid.sensors.typosquat import TyposquatSensor
from bid.storage import ContentStore

NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _brand():
    return Brand(
        id="pp", name="WrenvalePay", official_handles=["wrenvalepay"], official_logo_hashes=[],
        regions=["GLOBAL"], aliases=["WrenvalePay"], official_domains=["wrenvalepay.test"],
    )


def _store():
    return ContentStore(Path(tempfile.mkdtemp()))


def test_both_are_sensors():
    assert isinstance(TyposquatSensor(), Sensor)
    assert isinstance(CTLogSensor(), Sensor)


def test_allowlist_drops_brand_domain():
    al = Allowlist()
    assert al.contains("https://www.wrenvalepay.test/signin")
    assert not al.contains("wrenva1epay.com")


def test_typosquat_resolving_candidate_survives_filter(monkeypatch):
    # Mock DoH: only the lookalike resolves; the brand domain is allowlisted anyway.
    def fake_resolve(domain):
        return ["203.0.113.7"] if "wrenva1epay" in domain or "wrenvalepayy" in domain else []

    monkeypatch.setattr(enrich, "resolve", fake_resolve)
    al = Allowlist(extra={"wrenvalepay.test"})
    sensor = TyposquatSensor(allowlist=al, max_permutations=400, max_resolving=5, delay=0)
    obs = list(sensor.scan(_brand(), NOW))
    assert obs, "expected at least one resolving typosquat"
    for o in obs:
        assert isinstance(o, RawObservation)
        assert o.platform == "dns_typosquat"
        assert o.payload["resolved_ips"]
        assert o.platform_uid != "wrenvalepay.test"  # brand's own domain never emitted
    # pipeline fit: normalize + cheap filter keeps it (edit-distance to brand SLD)
    store = _store()
    brand = _brand()
    kept = [normalize(o, brand, store) for o in obs]
    assert any(stage_a(c, brand, set())[1] for c in kept), "typosquat must survive stage_a"
    assert sensor.health()["error_rate"] == 0.0


def test_ct_log_lookalike_survives_filter(monkeypatch):
    # Mock crt.sh: one official cert (dropped) + two lookalikes on foreign domains.
    fake_rows = [
        {"name_value": "www.wrenvalepay.test\nwrenvalepay.test", "not_before": "2026-07-01T00:00:00",
         "issuer_name": "DigiCert", "id": 1},
        {"name_value": "secure.wrenvalepay-login.tk", "not_before": "2026-07-02T10:00:00",
         "issuer_name": "Let's Encrypt", "id": 2},
        {"name_value": "*.wrenvalepay-verify.xyz", "not_before": "2026-07-03T09:30:00",
         "issuer_name": "Let's Encrypt", "id": 3},
    ]
    monkeypatch.setattr(CTLogSensor, "_crtsh_identity", lambda self, term: fake_rows)
    al = Allowlist(extra={"wrenvalepay.test"})
    sensor = CTLogSensor(allowlist=al, lookback_days=3650)
    brand = _brand()
    obs = list(sensor.scan(brand, NOW))
    regs = {o.platform_uid for o in obs}
    assert "wrenvalepay.test" not in regs  # official domain dropped
    assert {"wrenvalepay-login.tk", "wrenvalepay-verify.xyz"} <= regs
    store = _store()
    kept = [normalize(o, brand, store) for o in obs]
    survived = [c for c in kept if stage_a(c, brand, set())[1]]
    assert len(survived) == len(obs), "every CT lookalike should survive stage_a (alias in domain)"
    assert sensor.health()["error_rate"] == 0.0


def test_typosquat_offline_safe(monkeypatch):
    def boom(domain):
        raise RuntimeError("network down")

    monkeypatch.setattr(enrich, "resolve", boom)
    sensor = TyposquatSensor(allowlist=Allowlist(), max_permutations=50, max_resolving=5, delay=0)
    obs = list(sensor.scan(_brand(), NOW))
    assert obs == []  # no resolutions -> nothing emitted, no crash
    assert sensor.health()["ban_rate"] == 0.0


def test_ct_log_offline_safe(monkeypatch):
    def boom(self, term):
        raise RuntimeError("crt.sh 502")

    monkeypatch.setattr(CTLogSensor, "_crtsh_identity", boom)
    sensor = CTLogSensor()
    obs = list(sensor.scan(_brand(), NOW))
    assert obs == []
    assert sensor.health()["error_rate"] == 1.0  # failure is recorded in health()
