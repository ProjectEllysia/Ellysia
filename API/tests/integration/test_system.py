"""Tests de integración del módulo system."""

from unittest import mock

import pytest

from src.modules.system.taskqueue import TaskQueue

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    """Doble mínimo para el endpoint /system/tasks (sin Redis).

    El historial guarda tareas terminadas con estados reales
    (completed/failed/cancelled), nunca "history".
    """

    _HISTORY = [
        {"id": "a", "status": "completed", "category": "themis.scan"},
        {"id": "b", "status": "failed", "category": "aegis.generate"},
    ]

    def get_pending(self, category=None):
        return []

    def get_running(self, category=None):
        return []

    def get_history(self, category=None):
        return [t for t in self._HISTORY if category is None or t["category"] == category]


def test_say_hello_is_public(client):
    resp = client.get("/system/say-hello")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_status_requires_authentication(client):
    assert client.get("/system/status").status_code == 401


def test_status_requires_admin_role(client, regular_user, auth_headers):
    assert client.get("/system/status", headers=auth_headers(regular_user)).status_code == 403


def test_get_config_requires_authentication(client):
    assert client.get("/system").status_code == 401


def test_get_config_requires_admin(client, regular_user, auth_headers):
    assert client.get("/system", headers=auth_headers(regular_user)).status_code == 403


def test_admin_reads_full_config(client, admin_user, auth_headers):
    resp = client.get("/system", headers=auth_headers(admin_user))
    assert resp.status_code == 200
    # SecOpsConfig.json contiene appVersion.
    assert "appVersion" in resp.get_json()


def test_task_endpoints_require_admin(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    assert client.get("/system/tasks/status", headers=headers).status_code == 403
    assert client.get("/system/tasks", headers=headers).status_code == 403


def test_history_tab_returns_terminal_tasks(client, admin_user, auth_headers):
    """Regresión: la pestaña Historial manda status=history; el endpoint debe
    devolver TODO el historial (completed/failed/cancelled), no filtrar por un
    estado literal "history" (que siempre daba lista vacía)."""
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        resp = client.get("/system/tasks?status=history", headers=auth_headers(admin_user))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["totalCount"] == 2
    assert {t["id"] for t in data["tasks"]} == {"a", "b"}


def test_history_tab_respects_category_filter(client, admin_user, auth_headers):
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        resp = client.get(
            "/system/tasks?status=history&category=themis.scan",
            headers=auth_headers(admin_user),
        )
    data = resp.get_json()
    assert [t["id"] for t in data["tasks"]] == ["a"]


def test_status_filter_by_concrete_state_still_works(client, admin_user, auth_headers):
    """La rama fina por estado concreto (p. ej. failed) sigue funcionando."""
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        resp = client.get("/system/tasks?status=failed", headers=auth_headers(admin_user))
    data = resp.get_json()
    assert [t["id"] for t in data["tasks"]] == ["b"]
