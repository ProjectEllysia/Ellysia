"""Un análisis que se rompe acaba en un estado terminal con motivo.

Antes, el parseo y la validación del mensaje vivían **fuera** de todo bloque
``try`` de ``IrisManager._run_analysis``. Una excepción ahí —un parser que
revienta con un ``.eml`` raro, por ejemplo— dejaba la fila en ``running``
para siempre: RQ marcaba el job como fallido, pero nadie escribía en la base
de datos y el usuario veía un análisis que no terminaba nunca.

Estos tests recorren el mismo camino que el worker (``_run_analysis`` a pelo,
que fuera de RQ funciona igual porque ``job_context()`` es un no-op sin job) y
comprueban las tres cosas que el issue pide: estado terminal, ``finishedAt``
presente y una razón consultable que no filtre el correo original.
"""

from __future__ import annotations

from unittest import mock

import pytest

import src.modules.features.iris.managers.analysis as analysis_mod
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.failures import (
    FAILURE_INTERNAL_ERROR,
    FAILURE_INVALID_INPUT,
)
from src.modules.features.iris.model import IrisAnalysis
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration


# Un correo con datos que no deben acabar nunca en la respuesta de la API.
_SENSITIVE_RAW = (
    "From: nomina@empresa.example\r\n"
    "To: victima@empresa.example\r\n"
    "Subject: Cambio de cuenta bancaria\r\n"
    "X-Secreto: ES91-2100-0418-4502-0005-1332\r\n"
    "\r\n"
    "Transfiere la nómina a la nueva cuenta.\r\n"
)


def _make_analysis(app, user_id: int, raw: str = _SENSITIVE_RAW) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _reload(app, analysis_id: int) -> IrisAnalysis:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id)


def test_broken_parser_leaves_a_terminal_state(app, regular_user):
    """El caso literal del issue: ``parse_raw_message`` revienta."""
    analysis_id = _make_analysis(app, regular_user.id)

    with app.app_context():
        with mock.patch.object(analysis_mod, "parse_raw_message",
                               side_effect=RuntimeError("boom en el parser")):
            IrisManager()._run_analysis(analysis_id, _SENSITIVE_RAW)

    analysis = _reload(app, analysis_id)
    assert analysis.status == "failed"
    assert analysis.finished_at is not None
    assert analysis.failure_code == FAILURE_INTERNAL_ERROR


def test_broken_parser_reason_does_not_leak_the_raw_email(app, regular_user):
    """Un ``str(exception)`` de terceros puede arrastrar el fragmento de
    entrada que lo hizo fallar; por eso un error interno se colapsa en un
    mensaje genérico en lugar de propagarse."""
    analysis_id = _make_analysis(app, regular_user.id)
    leaking_error = RuntimeError(f"no pude parsear: {_SENSITIVE_RAW}")

    with app.app_context():
        with mock.patch.object(analysis_mod, "parse_raw_message", side_effect=leaking_error):
            IrisManager()._run_analysis(analysis_id, _SENSITIVE_RAW)

    reason = _reload(app, analysis_id).failure_reason
    assert reason
    assert "ES91-2100-0418-4502-0005-1332" not in reason
    assert "victima@empresa.example" not in reason


def test_unparseable_input_is_invalid_not_internal(app, regular_user):
    """Un texto que no es un correo es culpa del que lo manda, y el motivo
    debe decírselo: ``invalid_input``, no un error interno opaco."""
    analysis_id = _make_analysis(app, regular_user.id, raw="esto no es un correo")

    with app.app_context():
        IrisManager()._run_analysis(analysis_id, "esto no es un correo")

    analysis = _reload(app, analysis_id)
    assert analysis.status == "failed"
    assert analysis.finished_at is not None
    assert analysis.failure_code == FAILURE_INVALID_INPUT
    assert "cabeceras" in analysis.failure_reason


class _NoTaskQueue:
    """Doble mínimo de TaskQueue: el job ya no existe.

    ``GET /iris/status`` consulta primero la cola (ruta rápida para tareas en
    curso) y solo cae a la base de datos si no hay tarea viva. Sin este doble
    la llamada saldría a Redis, que la suite tiene deshabilitado a propósito.
    """

    def get_task_by_external_id(self, external_id, category=None):
        return None


def test_status_endpoint_exposes_the_reason(client, app, regular_user, auth_headers):
    """La razón tiene que ser consultable: ``GET /iris/results/<id>`` exige un
    análisis ``finished``, así que el sitio donde se lee es ``/iris/status``."""
    analysis_id = _make_analysis(app, regular_user.id, raw="esto tampoco es un correo")

    with app.app_context():
        IrisManager()._run_analysis(analysis_id, "esto tampoco es un correo")

    with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoTaskQueue()):
        response = client.get(f"/iris/status?id={analysis_id}",
                              headers=auth_headers(regular_user))

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "failed"
    assert body["failureCode"] == FAILURE_INVALID_INPUT
    assert body["failureReason"]


def test_successful_analysis_carries_no_failure_reason(app, regular_user):
    """Un análisis que termina bien no debe arrastrar un motivo de fallo."""
    raw = (
        "From: alguien@example.com\r\n"
        "To: destino@example.com\r\n"
        "Subject: Hola\r\n"
        "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
        "\r\n"
        "Cuerpo.\r\n"
    )
    analysis_id = _make_analysis(app, regular_user.id, raw=raw)

    with app.app_context():
        IrisManager()._run_analysis(analysis_id, raw)

    analysis = _reload(app, analysis_id)
    assert analysis.status == "finished"
    assert analysis.failure_code is None
    assert analysis.failure_reason is None
