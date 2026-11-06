from __future__ import annotations

from datetime import datetime, timezone

import pytest

from bid.classify import MockClassifier, SignalScoreClassifier
from bid.conduct import golden_set, run_review, scorecard
from bid.evidence import Ed25519Dsse
from bid.governance import GovernanceJournal, record_hash
from bid.run_pipeline import load_cti_badlist
from bid.storage import ContentStore

T0 = datetime(2026, 11, 30, 12, 0, tzinfo=timezone.utc)


def _journal(tmp_path) -> GovernanceJournal:
    return GovernanceJournal(tmp_path / "gov.jsonl", hmac_key="k", dsse=Ed25519Dsse("seed"))


def test_golden_set_version_is_stable(tmp_path):
    a = golden_set(ContentStore(tmp_path / "a"))
    b = golden_set(ContentStore(tmp_path / "b"))
    assert a[2] == b[2] and len(a[2]) == 16
    assert len(a[0]) == len(a[1]) > 0


def test_review_is_signed_and_attests_independence(tmp_path):
    journal = _journal(tmp_path)
    pkg = run_review(journal, period="2026-11", reviewer="brand-protection-lead", now=T0)
    card = pkg.record.payload
    assert pkg.record.kind == "conduct_scorecard"
    assert pkg.record.actor == "brand-protection-lead"
    assert pkg.record.subject == "mock-deterministic-v1"
    assert card["independent"] is True
    assert card["subject"]["family"] != card["supervisor"]["family"]
    assert card["subject"]["prompt_template"].startswith("bid-prompt-v1+")
    assert 0.0 <= card["metrics"]["supervisor_agreement"] <= 1.0
    assert card["drift"] is None
    assert journal.verify()[0] and journal.verify_public()[0]


def test_second_review_records_drift_against_the_first(tmp_path):
    journal = _journal(tmp_path)
    first = run_review(journal, period="2026-10", reviewer="lead", now=T0)
    second = run_review(journal, period="2026-11", reviewer="lead", now=T0)
    drift = second.record.payload["drift"]
    assert drift["previous_record_hash"] == record_hash(first)
    assert drift["previous_period"] == "2026-10"
    assert drift["precision_at_5"] == 0.0 and drift["recall"] == 0.0
    assert drift["thresholds_changed"] == []
    assert drift["label_set_changed"] is False


def test_same_family_supervisor_is_refused(tmp_path):
    cti = load_cti_badlist()
    items, truth, version = golden_set(ContentStore(tmp_path))

    class OtherRules(MockClassifier):
        model_id = "mock-deterministic-v2"

    with pytest.raises(ValueError, match="same model family"):
        scorecard(MockClassifier(cti), OtherRules(cti), items, truth, label_set_version=version,
                  period="2026-11", reviewed_by="lead", cti=cti)
    card = scorecard(MockClassifier(cti), SignalScoreClassifier(cti), items, truth,
                     label_set_version=version, period="2026-11", reviewed_by="lead", cti=cti)
    assert card["golden_set"]["label_set_version"] == version
