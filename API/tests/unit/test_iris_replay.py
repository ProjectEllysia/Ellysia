"""Replay offline de políticas de puntuación.

``services/replay.py`` responde a "¿qué habría decidido Iris con otra
versión?" sobre un corpus: qué veredictos cambian, qué gates aparecen o
desaparecen y cómo quedan los falsos positivos y negativos de cada política.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.services.quality import detector_version
from src.modules.features.iris.services.replay import CORPUS_DIRECTORY, ReplaySample, load_corpus, replay
from src.modules.features.iris.services.rules import iris_rules
from src.modules.features.iris.services.scoring import PROFILE_STRICT, current_policy, policy_for_profile

pytestmark = pytest.mark.unit

_CORPUS = CORPUS_DIRECTORY


def _fake_evaluate(raw: str, policy):
    """Motor de juguete: el mensaje es su propio score; strict añade un gate."""
    score = float(raw)
    return {
        "verdict": policy.verdict_for(score),
        "totalScore": score,
        "gateReasons": ["gate estricto"] if policy.profile == PROFILE_STRICT else [],
        "rules": [("Body Links", -10.0)] if score < 80 else [],
        "unevaluatedRules": [],
    }


def test_replay_reports_what_changes_against_the_baseline():
    samples = [
        ReplaySample("limpio", "95", "legitimate"),
        ReplaySample("frontera", "82", "legitimate"),
        ReplaySample("sospechoso", "60", "malicious"),
    ]
    policies = {"vigente": policy_for_profile("balanced", 80, 55),
                "estricta": policy_for_profile(PROFILE_STRICT, 80, 55)}

    report = replay(samples, policies, _fake_evaluate, {"Body Links": "links"}, "iris-rules:1:x")

    assert report["baseline"] == "vigente"
    assert report["changedCount"] == 1
    by_id = {entry["id"]: entry for entry in report["samples"]}
    assert by_id["frontera"]["verdictChanged"] is True
    assert by_id["frontera"]["results"]["vigente"]["verdict"] == "Legitimate"
    assert by_id["frontera"]["results"]["estricta"]["verdict"] == "Suspicious"
    assert by_id["limpio"]["gateChanges"]["estricta"] == {"added": ["gate estricto"], "removed": []}
    assert report["policies"]["vigente"]["metrics"]["overall"]["falsePositives"] == 0
    assert report["policies"]["estricta"]["metrics"]["overall"]["falsePositives"] == 1
    assert report["policies"]["vigente"]["scoringVersion"] != report["policies"]["estricta"]["scoringVersion"]


def test_replay_needs_at_least_one_policy():
    with pytest.raises(ValueError):
        replay([], {}, _fake_evaluate, {}, "d")


def test_the_real_engine_over_the_corpus_measures_a_candidate_before_deploying():
    """El caso de uso: comparar la política vigente con una candidata sobre el
    corpus. Una candidata absurda (nada puede salir Legitimate) se delata como
    cuatro falsos positivos nuevos antes de llegar a producción."""
    version, samples = load_corpus(_CORPUS)
    rules_defs = iris_rules.get_rules()
    family_of = {rule_def["name"]: rule_def.get("family") or "" for rule_def in rules_defs}
    baseline = current_policy()
    candidate = replace(baseline, legitimate_threshold=101.0)

    report = replay(samples, {"vigente": baseline, "candidata": candidate},
                    IrisManager.evaluate_raw, family_of, detector_version(rules_defs))

    assert version
    vigente = report["policies"]["vigente"]["metrics"]["overall"]
    candidata = report["policies"]["candidata"]["metrics"]["overall"]
    assert (vigente["falsePositives"], vigente["falseNegatives"]) == (0, 0)
    assert candidata["falsePositives"] == 4
    assert report["changedCount"] == 4
