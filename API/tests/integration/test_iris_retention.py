"""Tests de integración de la retención de Iris (M09/B17/B19):
``services/retention.py`` y las dos consultas de ``IrisAnalysisRepository``
en las que se apoya.

Cubre las dos mitades del job (purgar solo el raw vencido, borrar el
análisis entero cuando hay un límite duro configurado), que ninguna de las
dos deja huérfanos (``IrisRuleResult``), y que volver a ejecutar el job sin
datos nuevos no hace nada (idempotencia -- el criterio de cierre de M09).
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest

import src.modules.features.iris.services.retention as retention_mod
import src.modules.system.config_reading as CR
from src.modules.features.iris.model import IrisAnalysis, IrisRawMessage, IrisRuleResult
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


def _save_analysis(app, user_id: int, created_at=None) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            kwargs = dict(
                raw_headers="From: a@b.com\r\nSubject: Hi\r\n",
                user_id=user_id, status="finished",
            )
            if created_at is not None:
                kwargs["created_at"] = created_at
            analysis = IrisAnalysis(**kwargs)
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _has_raw(app, analysis_id: int) -> bool:
    with app.app_context():
        with UnitOfWork() as uow:
            return uow.session.query(IrisRawMessage).filter(
                IrisRawMessage.analysis_id == analysis_id
            ).first() is not None


def _analysis_exists(app, analysis_id: int) -> bool:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id) is not None


# ----------------------------------------------------- repository: raw purge

def test_purge_raw_messages_older_than_only_affects_old_rows(app, regular_user):
    old_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=100))
    recent_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=1))

    with app.app_context():
        with UnitOfWork() as uow:
            purged = IrisAnalysisRepository(uow).purge_raw_messages_older_than(
                utcnow_naive() - timedelta(days=90)
            )

    assert purged == 1
    assert not _has_raw(app, old_id)
    assert _has_raw(app, recent_id)
    assert _analysis_exists(app, old_id)  # el análisis en sí sobrevive


def test_purge_raw_messages_is_idempotent(app, regular_user):
    _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=100))
    cutoff = utcnow_naive() - timedelta(days=90)

    with app.app_context():
        with UnitOfWork() as uow:
            first = IrisAnalysisRepository(uow).purge_raw_messages_older_than(cutoff)
        with UnitOfWork() as uow:
            second = IrisAnalysisRepository(uow).purge_raw_messages_older_than(cutoff)

    assert first == 1
    assert second == 0


# ------------------------------------------------- repository: full deletion

def test_get_analyses_older_than_finds_only_old_rows(app, regular_user):
    old_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=400))
    _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=1))

    with app.app_context():
        with UnitOfWork() as uow:
            found = IrisAnalysisRepository(uow).get_analyses_older_than(
                utcnow_naive() - timedelta(days=365)
            )

    assert [a.id for a in found] == [old_id]


def test_deleting_old_analyses_via_repository_leaves_no_orphaned_rule_results(app, regular_user):
    """B17: el criterio de cierre exige explícitamente que la retención no
    deje huérfanos."""
    old_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=400))
    with app.app_context():
        with UnitOfWork() as uow:
            IrisRuleResultRepository(uow).save(IrisRuleResult(
                analysis_id=old_id, rule_name="SPF", score=-10, verdict="fail",
            ))

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            for analysis in repo.get_analyses_older_than(utcnow_naive() - timedelta(days=365)):
                repo.delete(analysis)

        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).get_by_id(old_id) is None
            assert uow.session.query(IrisRuleResult).filter(
                IrisRuleResult.analysis_id == old_id
            ).first() is None


# ----------------------------------------------------------- run_retention()

def test_run_retention_purges_raw_but_keeps_the_analysis_by_default(app, regular_user):
    """analysisRetentionDays=0 (el default) desactiva el borrado completo --
    "el resultado puede conservarse sin el raw" (B19) es el comportamiento
    por defecto."""
    old_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=100))

    with app.app_context():
        report = retention_mod.run_retention()

    assert report == {"purgedRawMessages": 1, "deletedAnalyses": 0}
    assert not _has_raw(app, old_id)
    assert _analysis_exists(app, old_id)


def test_run_retention_deletes_whole_analyses_when_hard_limit_is_set(app, regular_user):
    old_id = _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=400))

    with mock.patch.object(
        retention_mod.CR, "iris_config",
        lambda: CR.IrisConfig(raw_message_retention_days=90, analysis_retention_days=365),
    ):
        with app.app_context():
            report = retention_mod.run_retention()

    assert report["deletedAnalyses"] == 1
    assert not _analysis_exists(app, old_id)


def test_run_retention_is_idempotent(app, regular_user):
    _save_analysis(app, regular_user.id, created_at=utcnow_naive() - timedelta(days=400))

    with mock.patch.object(
        retention_mod.CR, "iris_config",
        lambda: CR.IrisConfig(raw_message_retention_days=90, analysis_retention_days=365),
    ):
        with app.app_context():
            first = retention_mod.run_retention()
        with app.app_context():
            second = retention_mod.run_retention()

    assert first["deletedAnalyses"] == 1
    assert second == {"purgedRawMessages": 0, "deletedAnalyses": 0}


def test_run_retention_does_not_touch_recent_analyses(app, regular_user):
    recent_id = _save_analysis(app, regular_user.id)

    with app.app_context():
        report = retention_mod.run_retention()

    assert report == {"purgedRawMessages": 0, "deletedAnalyses": 0}
    assert _has_raw(app, recent_id)
    assert _analysis_exists(app, recent_id)
