import pytest
import os
from datetime import datetime, timezone
from typing import FrozenSet

from bid.classify import (
    MockClassifier, SignalScoreClassifier, OpenRouterClassifier,
    RecheckingClassifier, build_classifier, PROMPT_TEMPLATE_ID
)
from bid.models import Brand, Candidate, DetSignals, Verdict, Label
from bid.eval.agreement import agreement_report
from bid.families import model_family

_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def sample_brand():
    return Brand(id="b1", name="TestBrand", official_handles=["@testbrand"],
                 official_logo_hashes=[], regions=["US"])

@pytest.fixture
def sample_candidate():
    return Candidate(
        id="c1", brand_id="b1", sensor_name="test_sensor", platform="test_platform",
        platform_uid="uid1", handle="@testbrand_official", display_name="Test Brand Official",
        bio="Official account for TestBrand", dedup_key="dk1",
        raw_observation_ref="rawref1", first_seen=_NOW
    )

@pytest.fixture
def cti_badlist():
    return {"bad.com"}

class MockRecheckClassifier:
    """A stub recheck classifier for testing specific recheck outcomes."""
    model_id = "anthropic/stub"

    def __init__(self, cti_badlist: set[str] | None = None, label: Label = "legit", confidence: float = 0.9):
        self._cti = cti_badlist or set()
        self._label = label
        self._confidence = confidence

    def classify(self, candidate: Candidate, brand: Brand) -> Verdict:
        return Verdict(
            candidate_id=candidate.id,
            label=self._label,
            confidence=self._confidence,
            signals=DetSignals(),
            reasoning="stub recheck",
            model_id=self.model_id,
            prompt_hash="recheck_prompt_hash",
            input_hashes=[],
            cost_usd=0.01,
            model_family=model_family(self.model_id),
            prompt_template=PROMPT_TEMPLATE_ID,
        )

def test_rechecking_classifier_same_family_raises_value_error(cti_badlist):
    primary = MockClassifier(cti_badlist)
    # Create a subclass to get a different model_id but same family
    class MockClassifierSubclass(MockClassifier):
        model_id = "mock-deterministic-v2"
    recheck = MockClassifierSubclass(cti_badlist)

    with pytest.raises(ValueError, match="Primary and recheck classifiers must be from different model families"):
        RecheckingClassifier(primary, recheck, frozenset(), 0.0)

def test_build_classifier_mock_plus_signals(cti_badlist):
    classifier = build_classifier(cti_badlist, recheck_model="signals")
    assert isinstance(classifier, RecheckingClassifier)
    assert isinstance(classifier._primary, MockClassifier)
    assert isinstance(classifier._recheck, SignalScoreClassifier)
    assert model_family(classifier._primary.model_id) != model_family(classifier._recheck.model_id)

def test_verdict_triggers_recheck_carries_recheck_data(sample_candidate, sample_brand, cti_badlist):
    # Setup primary to return a label that triggers recheck or low confidence
    class TriggeringMockClassifier(MockClassifier):
        def classify(self, candidate: Candidate, brand: Brand) -> Verdict:
            verdict = super().classify(candidate, brand)
            # Force a label that triggers recheck_labels or low confidence
            return verdict.model_copy(update={"label": "impersonation", "confidence": 0.5})

    primary = TriggeringMockClassifier(cti_badlist)
    recheck = SignalScoreClassifier(cti_badlist)

    # Use default recheck_labels and low_confidence from build_classifier
    recheck_labels: FrozenSet[Label] = frozenset({"impersonation", "fraud", "suspicious"})
    low_confidence = 0.6
    classifier = RecheckingClassifier(primary, recheck, recheck_labels, low_confidence)

    verdict = classifier.classify(sample_candidate, sample_brand)

    assert verdict.recheck is not None
    assert verdict.recheck.family == "signals"
    assert verdict.recheck.model_id == recheck.model_id
    assert verdict.cost_usd == 0.0  # both offline classifiers cost nothing

def test_constructed_disagreement_gives_agrees_false(sample_candidate, sample_brand, cti_badlist):
    # Primary gives "impersonation", recheck gives "legit"
    class PrimaryImpersonationClassifier(MockClassifier):
        def classify(self, candidate: Candidate, brand: Brand) -> Verdict:
            verdict = super().classify(candidate, brand)
            return verdict.model_copy(update={"label": "impersonation", "confidence": 0.7}) # Trigger recheck

    primary = PrimaryImpersonationClassifier(cti_badlist)
    recheck = MockRecheckClassifier(cti_badlist, label="legit") # Different side

    recheck_labels: FrozenSet[Label] = frozenset({"impersonation"})
    low_confidence = 0.6
    classifier = RecheckingClassifier(primary, recheck, recheck_labels, low_confidence)

    verdict = classifier.classify(sample_candidate, sample_brand)

    assert verdict.recheck is not None
    assert verdict.recheck.agrees is False
    assert verdict.recheck.label == "legit" # Recheck's label
    assert verdict.label == "impersonation" # Primary's label preserved

def test_verdicts_carry_prompt_template_and_model_family(sample_candidate, sample_brand, cti_badlist):
    mock_cls = MockClassifier(cti_badlist)
    signal_cls = SignalScoreClassifier(cti_badlist)

    mock_verdict = mock_cls.classify(sample_candidate, sample_brand)
    signal_verdict = signal_cls.classify(sample_candidate, sample_brand)

    assert mock_verdict.prompt_template.startswith("bid-prompt-v1+")
    assert mock_verdict.model_family == "rules" # mock-deterministic-v1 -> rules

    assert signal_verdict.prompt_template.startswith("bid-prompt-v1+")
    assert signal_verdict.model_family == "signals" # signals-fused-v1 -> signals

def test_build_classifier_recheck_model_signals_returns_rechecking_classifier(cti_badlist):
    classifier = build_classifier(cti_badlist, recheck_model="signals")
    assert isinstance(classifier, RecheckingClassifier)
    assert isinstance(classifier._primary, MockClassifier)
    assert isinstance(classifier._recheck, SignalScoreClassifier)

def test_build_classifier_recheck_model_openrouter_needs_live_and_key(cti_badlist):
    # Without --live and OPENROUTER_API_KEY
    os.environ.pop("OPENROUTER_API_KEY", None)
    with pytest.raises(RuntimeError, match="recheck model needs --live and an API key"):
        build_classifier(cti_badlist, live=False, recheck_model="google/gemini-2.5-flash-lite")

    # With --live but no OPENROUTER_API_KEY
    with pytest.raises(RuntimeError, match="recheck model needs --live and an API key"):
        build_classifier(cti_badlist, live=True, recheck_model="google/gemini-2.5-flash-lite")

    # With --live and OPENROUTER_API_KEY (mocking it for test)
    os.environ["OPENROUTER_API_KEY"] = "sk-testkey"
    try:
        with pytest.raises(ValueError, match="different model families"):
            build_classifier(cti_badlist, live=True, recheck_model="google/gemini-2.5-flash-lite")
        classifier = build_classifier(cti_badlist, live=True, recheck_model="anthropic/claude-sonnet-4.5")
        assert isinstance(classifier, RecheckingClassifier)
        assert isinstance(classifier._primary, OpenRouterClassifier) # Primary will be OpenRouter as live=True
        assert isinstance(classifier._recheck, OpenRouterClassifier)
        assert model_family(classifier._primary.model_id) != model_family(classifier._recheck.model_id)
    finally:
        os.environ.pop("OPENROUTER_API_KEY")

def test_agreement_report_same_family_and_cross_family_means(sample_candidate, sample_brand, cti_badlist):
    # Classifiers from same family
    class MockClassifierA(MockClassifier):
        model_id = "mock-rules-a"
    class MockClassifierB(MockClassifier):
        model_id = "mock-rules-b"

    # Classifier from different family
    class OtherFamilyClassifier(SignalScoreClassifier):
        model_id = "other-family-signals"

    cls_a = MockClassifierA(cti_badlist)
    cls_b = MockClassifierB(cti_badlist)
    cls_c = OtherFamilyClassifier(cti_badlist)

    classifiers = [cls_a, cls_b, cls_c]
    items = [(sample_candidate, sample_brand)] # Use a single item for simplicity

    report = agreement_report(classifiers, items)

    assert "pairs" in report
    assert len(report["pairs"]) == 3 # (A,B), (A,C), (B,C)

    # Check same_family for (A,B) pair
    ab_pair = next(p for p in report["pairs"] if p["a"] == cls_a.model_id and p["b"] == cls_b.model_id)
    assert ab_pair["same_family"] is True
    assert ab_pair["family_a"] == "rules"
    assert ab_pair["family_b"] == "rules"

    # Check cross_family for (A,C) pair
    ac_pair = next(p for p in report["pairs"] if p["a"] == cls_a.model_id and p["b"] == cls_c.model_id)
    assert ac_pair["same_family"] is False
    assert ac_pair["family_a"] == "rules"
    assert ac_pair["family_b"] == "other-family-signals"  # unknown ids are their own family

    # Check same_family_mean and cross_family_mean are computed
    assert report["same_family_mean"] is not None
    assert report["cross_family_mean"] is not None

    # For a single item and deterministic classifiers, agreement should be 1.0 or 0.0 based on labels
    # MockClassifier and SignalScoreClassifier might give different labels for a generic candidate
    # if it doesn't match specific rules. For this test, we just check existence and types.
    assert isinstance(report["same_family_mean"], float)
    assert isinstance(report["cross_family_mean"], float)
