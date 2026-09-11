"""Tests de integración del módulo Iris (análisis de cabeceras)."""

from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.system.taskqueue import Task, TaskStatus

pytestmark = pytest.mark.integration


class _NoopQueue:
    """Cola que acepta el encolado y no ejecuta nada.

    Los tests de aceptación de tamaño solo miran si la validación del schema
    deja pasar la petición; ejecutar el análisis de verdad no aporta nada y
    saldría a Redis, que la suite tiene deshabilitado.
    """

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


def test_analyze_requires_authentication(client):
    assert client.post("/iris/analyze", json={"headers": "From: a@b.com"}).status_code == 401


def test_analyze_requires_create_attribute(client, stripped_user, auth_headers):
    # Usuario al que le han retirado iris_create.
    resp = client.post("/iris/analyze", headers=auth_headers(stripped_user),
                       json={"headers": "From: a@b.com\nSubject: Hi"})
    assert resp.status_code == 403


def test_list_results_empty(client, regular_user, auth_headers):
    resp = client.get("/iris/results?page=1&per_page=10", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 0


def test_status_unknown_analysis_returns_404(client, regular_user, auth_headers):
    resp = client.get("/iris/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_delete_requires_delete_attribute(client, stripped_user, auth_headers):
    # Sin iris_delete -> 403 antes de tocar la BD.
    resp = client.delete("/iris/results/1", headers=auth_headers(stripped_user))
    assert resp.status_code == 403


def test_analyze_rejects_request_without_headers_or_message(client, root_headers):
    # 'headers' ya no es obligatorio si se envía 'message', pero al
    # menos uno de los dos debe estar presente (validado en el schema).
    resp = client.post("/iris/analyze", headers=root_headers, json={"title": "x"})
    assert resp.status_code == 422


# --------------------------------------------------------------- capacidades

def test_capabilities_requires_authentication(client):
    assert client.get("/iris/capabilities").status_code == 401


def test_capabilities_requires_read_attribute(client, stripped_user, auth_headers):
    resp = client.get("/iris/capabilities", headers=auth_headers(stripped_user))
    assert resp.status_code == 403


def test_capabilities_publishes_the_limit_the_api_actually_enforces(client, regular_user,
                                                                   auth_headers):
    """El frontend tenía su propio tope, y había derivado a 2× del real.

    La única defensa contra que vuelva a derivar es que el número que publica
    este endpoint sea el mismo que aplica la validación, leído del mismo sitio.
    """
    import src.modules.system.config_reading as CR

    resp = client.get("/iris/capabilities", headers=auth_headers(regular_user))

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["maxMessageBytes"] == CR.iris_config().max_message_bytes
    assert body["minHeaders"] == CR.iris_config().min_headers
    assert set(body["analysisModes"]) == {"headers", "message"}


def test_a_message_at_the_published_limit_is_accepted(client, regular_user, auth_headers,
                                                      monkeypatch):
    """Misma entrada, misma decisión: justo en el límite el API acepta."""
    import src.modules.features.iris.schemas as schemas_mod
    import src.modules.features.iris.managers.analysis as analysis_mod

    class _Limited:
        max_message_bytes = 2048
        min_headers = 2
        legitimate_threshold = 80
        suspicious_threshold = 55
        sensitivity_profile = "balanced"

    monkeypatch.setattr(schemas_mod.CR, "iris_config", lambda: _Limited())
    monkeypatch.setattr(analysis_mod.CR, "iris_config", lambda: _Limited())

    limit = client.get("/iris/capabilities",
                       headers=auth_headers(regular_user)).get_json()["maxMessageBytes"]

    prefix = "From: a@b.com\r\nSubject: "
    headers_block = prefix + "x" * (limit - len(prefix))
    assert len(headers_block.encode("utf-8")) == limit

    with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
        resp = client.post("/iris/analyze", headers=auth_headers(regular_user),
                           json={"headers": headers_block})

    assert resp.status_code != 422, resp.get_json()


def test_a_message_over_the_published_limit_is_rejected(client, regular_user, auth_headers,
                                                        monkeypatch):
    """Y un byte por encima lo rechaza, que es la otra mitad del contrato: si
    la UI corta por este número, no puede recibir sorpresas a ninguno de los
    dos lados."""
    import src.modules.features.iris.schemas as schemas_mod
    import src.modules.features.iris.managers.analysis as analysis_mod

    class _Limited:
        max_message_bytes = 2048
        min_headers = 2
        legitimate_threshold = 80
        suspicious_threshold = 55
        sensitivity_profile = "balanced"

    monkeypatch.setattr(schemas_mod.CR, "iris_config", lambda: _Limited())
    monkeypatch.setattr(analysis_mod.CR, "iris_config", lambda: _Limited())

    limit = client.get("/iris/capabilities",
                       headers=auth_headers(regular_user)).get_json()["maxMessageBytes"]

    resp = client.post("/iris/analyze", headers=auth_headers(regular_user),
                       json={"headers": "From: a@b.com\r\nSubject: " + "x" * limit})

    assert resp.status_code == 422
