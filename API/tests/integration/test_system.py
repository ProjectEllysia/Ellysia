"""Tests de integración del módulo system."""

import copy
import json
from unittest import mock

import pytest

import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import TaskQueue

pytestmark = pytest.mark.integration


@pytest.fixture
def _isolated_system_config(tmp_path, monkeypatch):
    """Redirige las escrituras de PUT /system a un fichero temporal (C9).

    Sin esto, los tests que guardan config de verdad escribirían sobre el
    ``SecOpsConfig.json`` real del repo. ``_configs_path`` se monkeypatchea
    para que ``save_full_config`` escriba en el temporal; el global
    ``_configs`` en memoria se restaura al snapshot previo al salir.
    """
    original = CR.get_full_config()
    tmp_file = tmp_path / "SecOpsConfig.json"
    tmp_file.write_text(json.dumps(original, indent=2, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(CR, "_configs_path", tmp_file)
    snapshot = copy.deepcopy(CR._configs)
    yield
    CR._configs = snapshot


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


def test_get_config_requires_root_not_just_admin(client, admin_user, auth_headers):
    # S7: un admin ya no puede leer/mutar toda la config (incl. la política
    # anti-SSRF areLocalIpsAllowed y los parámetros de Argon2) — solo root.
    assert client.get("/system", headers=auth_headers(admin_user)).status_code == 403


def test_root_reads_full_config(client, root_user, auth_headers):
    resp = client.get("/system", headers=auth_headers(root_user))
    assert resp.status_code == 200
    # SecOpsConfig.json contiene appVersion.
    assert "appVersion" in resp.get_json()


def test_update_config_requires_root_not_just_admin(client, admin_user, auth_headers):
    resp = client.put(
        "/system",
        headers=auth_headers(admin_user),
        json={"appVersion": "4.2"},
    )
    assert resp.status_code == 403


def test_get_config_returns_etag_header(client, root_user, auth_headers):
    resp = client.get("/system", headers=auth_headers(root_user))
    assert resp.status_code == 200
    assert resp.headers.get("ETag")


def test_update_config_requires_if_match_header(
    client, root_user, auth_headers, _isolated_system_config
):
    # C9: sin If-Match, se rechaza en vez de sobrescribir a ciegas.
    resp = client.put(
        "/system",
        headers=auth_headers(root_user),
        json={"appVersion": "4.2"},
    )
    assert resp.status_code == 400


def test_update_config_rejects_stale_if_match(
    client, root_user, auth_headers, _isolated_system_config
):
    # C9: dos sesiones root - la segunda usa un ETag ya desactualizado
    # porque la primera guardó primero (con contenido distinto).
    headers = auth_headers(root_user)
    get_resp = client.get("/system", headers=headers)
    stale_etag = get_resp.headers["ETag"]
    config = get_resp.get_json()

    first_write = {**config, "appVersion": "4.2-test-a"}
    first = client.put(
        "/system",
        headers={**headers, "If-Match": stale_etag},
        json=first_write,
    )
    assert first.status_code == 200

    # Reintenta con el ETag viejo: ya no coincide tras el primer guardado.
    second_write = {**config, "appVersion": "4.2-test-b"}
    stale = client.put(
        "/system",
        headers={**headers, "If-Match": stale_etag},
        json=second_write,
    )
    assert stale.status_code == 409


def test_update_config_succeeds_with_matching_if_match(
    client, root_user, auth_headers, _isolated_system_config
):
    headers = auth_headers(root_user)
    get_resp = client.get("/system", headers=headers)
    config = get_resp.get_json()

    resp = client.put(
        "/system",
        headers={**headers, "If-Match": get_resp.headers["ETag"]},
        json=config,
    )
    assert resp.status_code == 200
    assert resp.headers.get("ETag")


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
