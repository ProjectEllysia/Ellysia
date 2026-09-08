"""B09: IrisManager.analyze() cobra cuota exactamente por los análisis que de
verdad se crean -- ni por un reintento de Gmail/Graph que reenvía el mismo
mensaje, ni por una carrera perdida contra la UniqueConstraint de
idempotencia.

``QuotaManager.consume_many()`` (el otro artefacto de B09, la generación de
IA que cobra dos claves) tiene su propia cobertura en test_quotas.py.
"""

from __future__ import annotations

from unittest import mock

import pytest

import src.modules.features.iris.managers.analysis as analysis_mod
from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration


class _NoopQueue:
    def submit(self, **kwargs):
        return None


_HEADERS = "From: a@b.com\r\nSubject: Hi\r\n"


def test_analyze_returns_the_existing_id_for_a_known_source_without_charging(
    app, regular_user, set_plan_limits,
):
    """El escenario real del issue: un reintento de sync (Gmail/Graph
    repitiendo un mensaje) para un (connection_id, source_message_uid) ya
    aceptado no debe cobrar una segunda vez ni crear un segundo análisis."""
    set_plan_limits({LimitKey.IRIS_ANALYSES: 1})

    with app.app_context():
        with UnitOfWork() as uow:
            existing = IrisAnalysis(
                raw_headers=_HEADERS, user_id=regular_user.id,
                status="finished", connection_id=99, source_message_uid="msg-1",
            )
            IrisAnalysisRepository(uow).save(existing)
            existing_id = existing.id

        # La cuota ya está agotada (límite 1, y este análisis se creó a
        # mano sin gastarla) -- si analyze() cobrara de nuevo, cortaría.
        QuotaManager().consume(regular_user.id, LimitKey.IRIS_ANALYSES)

        with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
            returned_id = IrisManager().analyze(
                raw_headers=_HEADERS, user_id=regular_user.id,
                connection_id=99, source_message_uid="msg-1",
            )

        assert returned_id == existing_id
        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).used == 1

        with UnitOfWork() as uow:
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert len(analyses) == 1


def test_analyze_charges_quota_normally_for_a_new_message(app, regular_user, set_plan_limits):
    set_plan_limits({LimitKey.IRIS_ANALYSES: 5})

    with app.app_context():
        with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
            IrisManager().analyze(
                raw_headers=_HEADERS, user_id=regular_user.id,
                connection_id=99, source_message_uid="msg-1",
            )

        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).used == 1


def test_analyze_refunds_quota_when_it_loses_the_race_against_the_unique_constraint(
    app, regular_user, set_plan_limits, monkeypatch,
):
    """Simula la carrera que la comprobación de idempotencia por sí sola no
    puede cerrar: dos llamadas leen "no existe" casi a la vez, y solo una
    gana la UniqueConstraint. La perdedora debe quedar en cuota cero, no
    cobrada por un análisis que nunca se creó."""
    set_plan_limits({LimitKey.IRIS_ANALYSES: 5})

    with app.app_context():
        # La fila ya existe de verdad en la base de datos...
        with UnitOfWork() as uow:
            IrisAnalysisRepository(uow).save(IrisAnalysis(
                raw_headers=_HEADERS, user_id=regular_user.id,
                status="finished", connection_id=99, source_message_uid="msg-1",
            ))

        # ...pero se fuerza a analyze() a no verla en su comprobación previa,
        # como si esta llamada hubiera leído justo antes de que la otra
        # confirmara -- lo único que la protege ahora es la constraint.
        monkeypatch.setattr(IrisAnalysisRepository, "get_by_source", lambda self, *a, **k: None)

        with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
            with pytest.raises(Exception):
                IrisManager().analyze(
                    raw_headers=_HEADERS, user_id=regular_user.id,
                    connection_id=99, source_message_uid="msg-1",
                )

        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).used == 0


def test_analyze_manual_submissions_are_unaffected_by_the_idempotency_check(
    app, regular_user, set_plan_limits,
):
    """Sin connection_id/source_message_uid (el envío manual, el flujo
    original) la comprobación de idempotencia no se ejecuta -- dos envíos
    manuales del mismo texto son dos análisis distintos, como siempre."""
    set_plan_limits({LimitKey.IRIS_ANALYSES: 5})

    with app.app_context():
        with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
            first_id = IrisManager().analyze(raw_headers=_HEADERS, user_id=regular_user.id)
            second_id = IrisManager().analyze(raw_headers=_HEADERS, user_id=regular_user.id)

        assert first_id != second_id
        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).used == 2
