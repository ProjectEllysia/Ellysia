"""Política de puntuación versionada y perfiles de sensibilidad.

``services/scoring.py`` reúne techo, suelos, umbrales, perfil y pesos en una
política que se guarda con cada análisis. Estos tests fijan cómo se desplazan
los umbrales, que la versión cambie con cualquier regla del juego y que un
snapshot guardado reconstruya la misma política.
"""

from __future__ import annotations

import logging

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.iris.services.registry import RuleResult
from src.modules.features.iris.services.scoring import (
    PROFILE_BALANCED,
    PROFILE_LENIENT,
    PROFILE_STRICT,
    ScoringPolicy,
    current_policy,
    policy_for_profile,
)

pytestmark = pytest.mark.unit


def _policy(profile: str = PROFILE_BALANCED, **extra) -> ScoringPolicy:
    return policy_for_profile(profile, 80, 55, **extra)


def test_profiles_shift_both_thresholds():
    assert (_policy(PROFILE_BALANCED).legitimate_threshold, _policy(PROFILE_BALANCED).suspicious_threshold) == (80, 55)
    assert (_policy(PROFILE_STRICT).legitimate_threshold, _policy(PROFILE_STRICT).suspicious_threshold) == (85, 60)
    assert (_policy(PROFILE_LENIENT).legitimate_threshold, _policy(PROFILE_LENIENT).suspicious_threshold) == (75, 50)


def test_an_unknown_profile_falls_back_to_balanced(caplog):
    with caplog.at_level(logging.WARNING):
        policy = _policy("paranoico")
    assert policy.profile == PROFILE_BALANCED
    assert policy.legitimate_threshold == 80
    assert "paranoico" in caplog.text


def test_changing_profile_twice_does_not_accumulate_offsets():
    policy = _policy(PROFILE_STRICT).with_profile(PROFILE_LENIENT).with_profile(PROFILE_BALANCED)
    assert (policy.legitimate_threshold, policy.suspicious_threshold) == (80, 55)


def test_verdict_for_uses_the_policy_thresholds():
    assert _policy(PROFILE_LENIENT).verdict_for(77) == "Legitimate"
    assert _policy(PROFILE_BALANCED).verdict_for(77) == "Suspicious"
    assert _policy(PROFILE_STRICT).verdict_for(57) == "Phishing"


def test_aggregate_floors_each_family_but_not_unfamilied_rules():
    rules_defs = [{"family": "links"}, {"family": "links"}, {"family": ""}]
    results = [RuleResult(score=-25, verdict="fail"), RuleResult(score=-25, verdict="fail"),
               RuleResult(score=-3, verdict="fail")]
    assert _policy().aggregate(rules_defs, results) == 100 - 30 - 3


def test_a_passing_rule_never_adds_points():
    assert _policy().aggregate([{"family": "auth"}], [RuleResult(score=5, verdict="pass")]) == 100


def test_the_snapshot_round_trips_to_the_same_policy():
    policy = _policy(PROFILE_STRICT, weight_overrides={"body_links.floor": -20.0},
                     datasets_fingerprint="iris-data:abc", app_version="0.5.10")
    assert ScoringPolicy.from_snapshot(policy.snapshot("iris-rules:46:x")) == policy


def test_the_version_is_stable_and_changes_with_any_rule_of_the_game():
    policy = _policy(datasets_fingerprint="iris-data:abc")
    version = policy.version("iris-rules:46:x")

    assert version.startswith("iris-scoring:")
    assert len(version) <= 64
    assert _policy(datasets_fingerprint="iris-data:abc").version("iris-rules:46:x") == version
    assert policy.with_profile(PROFILE_STRICT).version("iris-rules:46:x") != version
    assert policy.with_weight_overrides({"dmarc.fail": -20}).version("iris-rules:46:x") != version
    assert _policy(datasets_fingerprint="iris-data:def").version("iris-rules:46:x") != version
    assert policy.version("iris-rules:47:y") != version


def test_current_policy_reads_the_configuration(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(sensitivity_profile=PROFILE_STRICT))
    monkeypatch.setattr(CR, "get_iris_scoring_overrides", lambda: {"dmarc.fail": -20.0})

    policy = current_policy()

    assert policy.profile == PROFILE_STRICT
    assert (policy.legitimate_threshold, policy.suspicious_threshold) == (85, 60)
    assert policy.weight_overrides == {"dmarc.fail": -20.0}
    assert policy.datasets_fingerprint.startswith("iris-data:")


def test_weight_overrides_apply_only_inside_their_block():
    """El replay compara pesos sin tocar la configuración compartida."""
    assert CR.get_iris_scoring_weight("demo.weight", -4) == -4
    with CR.scoring_weight_overrides({"demo.weight": -9}):
        assert CR.get_iris_scoring_weight("demo.weight", -4) == -9
        assert CR.get_iris_scoring_weight("otro.peso", -2) == -2
    assert CR.get_iris_scoring_weight("demo.weight", -4) == -4
