"""Cada análisis guarda la política con la que se decidió.

Cambiar umbrales, perfil o pesos ya no reinterpreta en silencio los análisis
hechos: cada uno lleva su snapshot y su versión, y con ellos se puede
reconstruir esa política —volver a ella— o preguntar qué habría decidido otra.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.scoring import PROFILE_STRICT, ScoringPolicy
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration

_LEGIT = (Path(__file__).resolve().parents[1] / "fixtures" / "iris" / "legit_bank_alert.eml").read_text(
    encoding="utf-8")


def _analyze(app, user_id: int, raw: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


def test_an_analysis_stores_its_scoring_snapshot_and_version(client, app, root_user, root_headers):
    analysis_id = _analyze(app, root_user.id, _LEGIT)

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    snapshot = report["scoringSnapshot"]
    assert snapshot["profile"] == "balanced"
    assert (snapshot["legitimateThreshold"], snapshot["suspiciousThreshold"]) == (80, 55)
    assert snapshot["detectorVersion"] == report["detectorVersion"]
    assert snapshot["datasetsFingerprint"].startswith("iris-data:")
    assert report["scoringVersion"].startswith("iris-scoring:")


def test_the_sensitivity_profile_is_recorded_with_the_analysis(app, root_user, monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(sensitivity_profile=PROFILE_STRICT))
    analysis_id = _analyze(app, root_user.id, _LEGIT)

    with app.app_context():
        with UnitOfWork() as uow:
            snapshot = IrisAnalysisRepository(uow).get_by_id(analysis_id).scoring_snapshot

    assert snapshot["profile"] == PROFILE_STRICT
    assert snapshot["legitimateThreshold"] == 85


def test_a_stored_snapshot_reproduces_the_stored_verdict_and_another_policy_can_differ(app, root_user):
    """Rollback: la política reconstruida desde el snapshot decide lo mismo
    que decidió; una política distinta responde qué habría pasado con ella."""
    analysis_id = _analyze(app, root_user.id, _LEGIT)

    with app.app_context():
        manager = IrisManager()
        with UnitOfWork() as uow:
            analysis = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            stored_policy = ScoringPolicy.from_snapshot(analysis.scoring_snapshot)
            stored_verdict, stored_version = analysis.verdict, analysis.scoring_version

        same = manager.evaluate_analysis_under(analysis_id, root_user.id, stored_policy)
        other = manager.evaluate_analysis_under(
            analysis_id, root_user.id, replace(stored_policy, legitimate_threshold=101.0),
        )

    assert stored_verdict == "Legitimate"
    assert same["verdict"] == stored_verdict
    assert same["scoringVersion"] == stored_version
    assert same["storedScoringVersion"] == stored_version
    assert other["verdict"] != stored_verdict
    assert other["scoringVersion"] != stored_version
