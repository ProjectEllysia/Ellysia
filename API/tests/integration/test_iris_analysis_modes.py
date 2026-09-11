"""Modo de análisis explícito: solo cabeceras o mensaje completo.

El modo se deducía de si el usuario había tocado el textarea después de
arrastrar un ``.eml``: no era una elección, no estaba a la vista y podía
acabar en un error contradictorio —pedir solo cabeceras y recibir un rechazo
por el tamaño del mensaje completo—. Estos tests fijan el contrato: el modo
viaja explícito, el servidor solo valida y usa el campo de ese modo, y
publica qué reglas se quedan sin cobertura en modo cabeceras y el aviso de
sensibilidad del modo completo.
"""

from __future__ import annotations

from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.features.iris.managers import analysis as analysis_mod
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.rules import iris_rules
from src.modules.infrastructure import build_repository
from src.modules.system.taskqueue import Task, TaskStatus

pytestmark = pytest.mark.integration

_HEADERS = "From: Ana <ana@example.com>\nTo: luis@example.com\nSubject: Hola\n"
_MESSAGE = _HEADERS + "Content-Type: text/plain\n\nCuerpo del mensaje con un enlace https://example.com\n"


class _NoopQueue:
    """Cola que acepta el encolado y no ejecuta nada: aquí solo importa qué se guarda."""

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        return Task(id=name or "job", name=name, category=category,
                    external_id=external_id, status=TaskStatus.PENDING)

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None): return None
    def is_recoverable(self, external_id: str, category: Optional[str] = None) -> bool: return True
    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


def _submit(client, headers, body):
    with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
        return client.post("/iris/analyze", headers=headers, json=body)


def _stored_raw(app, analysis_id: int) -> str:
    with app.app_context():
        return build_repository(IrisAnalysisRepository).get_by_id(analysis_id).raw_headers


def test_capabilities_list_the_rules_headers_mode_leaves_uncovered(client, user_headers):
    body = client.get("/iris/capabilities", headers=user_headers).get_json()

    expected = [rule["name"] for rule in iris_rules.get_rules() if rule.get("is_body_dependent")]
    assert body["headersOnlyUncoveredRules"] == expected
    assert "Suspicious Attachments" in body["headersOnlyUncoveredRules"]


def test_capabilities_warn_that_the_full_message_can_contain_sensitive_data(client, user_headers):
    body = client.get("/iris/capabilities", headers=user_headers).get_json()

    assert "sensible" in body["fullMessageNotice"]


def test_headers_mode_analyses_the_headers_even_when_a_message_travels_along(client, app, user_headers):
    response = _submit(client, user_headers, {"mode": "headers", "headers": _HEADERS, "message": _MESSAGE})

    assert response.status_code == 201, response.get_json()
    assert _stored_raw(app, response.get_json()["analysisId"]) == _HEADERS


def test_choosing_headers_mode_never_fails_for_the_size_of_the_unused_message(
        client, user_headers, monkeypatch):
    """El error contradictorio del issue: pedir solo cabeceras y recibir un
    rechazo por el tamaño del ``.eml`` que no se iba a analizar."""
    monkeypatch.setattr(analysis_mod.CR, "iris_config", lambda: analysis_mod.CR.IrisConfig(max_message_bytes=2048))
    import src.modules.features.iris.schemas as schemas_mod
    monkeypatch.setattr(schemas_mod.CR, "iris_config", lambda: schemas_mod.CR.IrisConfig(max_message_bytes=2048))

    oversized = _HEADERS + "\n" + "x" * 5000
    response = _submit(client, user_headers, {"mode": "headers", "headers": _HEADERS, "message": oversized})

    assert response.status_code == 201, response.get_json()


def test_message_mode_analyses_the_full_message(client, app, user_headers):
    response = _submit(client, user_headers, {"mode": "message", "headers": _HEADERS, "message": _MESSAGE})

    assert response.status_code == 201, response.get_json()
    assert _stored_raw(app, response.get_json()["analysisId"]) == _MESSAGE


def test_message_mode_without_a_message_says_so(client, user_headers):
    response = _submit(client, user_headers, {"mode": "message", "headers": _HEADERS})

    assert response.status_code == 422
    assert "message" in str(response.get_json())


def test_headers_mode_without_headers_says_so(client, user_headers):
    response = _submit(client, user_headers, {"mode": "headers", "message": _MESSAGE})

    assert response.status_code == 422
    assert "headers" in str(response.get_json())


def test_without_a_mode_the_full_message_still_takes_priority(client, app, user_headers):
    """Quien no envía ``mode`` (clientes anteriores, la API a mano) sigue igual."""
    response = _submit(client, user_headers, {"headers": _HEADERS, "message": _MESSAGE})

    assert response.status_code == 201, response.get_json()
    assert _stored_raw(app, response.get_json()["analysisId"]) == _MESSAGE
