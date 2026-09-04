"""Tests de integración del módulo system."""

import copy
import base64
import gzip
import json
from datetime import datetime, timedelta
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


@pytest.fixture
def _isolated_log_file(tmp_path, monkeypatch):
    """Hace que el endpoint lea un log pequeño y controlado por el test."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "secops.log"
    log_path.write_text(
        "\n".join([
            "[+] [INFO] (2026-08-18 10:00:00,000) test.one: inicio",
            "[+] [WARNING] (2026-08-18 10:01:00,000) test.two: aviso",
            "[+] [ERROR] (2026-08-18 10:02:00,000) test.three: fallo",
            "[+] [INFO] (2026-08-18 10:03:00,000) test.one: final",
        ]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(CR, "get_directory_of", lambda _directory: str(log_dir))
    return log_path


def _decode_log_content(response):
    payload = response.get_json()
    compressed = base64.b64decode(payload["content"])
    return payload, gzip.decompress(compressed).decode("utf-8")


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


def test_logs_require_authentication(client):
    assert client.get("/system/logs").status_code == 401


def test_logs_require_admin_role(client, regular_user, auth_headers):
    assert client.get("/system/logs", headers=auth_headers(regular_user)).status_code == 403


def test_admin_reads_last_log_lines(client, admin_user, auth_headers, _isolated_log_file):
    response = client.get(
        "/system/logs?position=tail&per_page=2",
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 200
    payload, content = _decode_log_content(response)
    assert content.splitlines() == [
        "[+] [ERROR] (2026-08-18 10:02:00,000) test.three: fallo",
        "[+] [INFO] (2026-08-18 10:03:00,000) test.one: final",
    ]
    assert payload["totalLines"] == 4
    assert payload["totalPages"] == 2
    assert payload["returnedLines"] == 2
    assert payload["hasNext"] is True
    assert payload["compression"] == "gzip"
    assert payload["encoding"] == "base64"


def test_root_reads_log_and_head_pagination_filters(
    client, root_user, auth_headers, _isolated_log_file
):
    response = client.get(
        "/system/logs",
        query_string={
            "position": "head",
            "per_page": 10,
            "from": "2026-08-18T10:01:00",
            "to": "2026-08-18T10:02:00",
            "level": "ERROR",
            "contains": "FALLO",
        },
        headers=auth_headers(root_user),
    )

    assert response.status_code == 200
    payload, content = _decode_log_content(response)
    assert content.splitlines() == [
        "[+] [ERROR] (2026-08-18 10:02:00,000) test.three: fallo",
    ]
    assert payload["position"] == "head"
    assert payload["totalLines"] == 1
    assert payload["firstLine"] == 3
    assert payload["lastLine"] == 3


def test_log_minimum_level_returns_every_severity_above_it(
    client, admin_user, auth_headers, _isolated_log_file
):
    """`minLevel` evita tener que consultar un nivel cada vez.

    El log de la fixture tiene un WARNING y un ERROR entre dos INFO. Pedir
    `minLevel=WARNING` debe traer los dos en una sola respuesta.
    """
    response = client.get(
        "/system/logs",
        query_string={"position": "head", "minLevel": "WARNING"},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 200
    payload, content = _decode_log_content(response)
    assert content.splitlines() == [
        "[+] [WARNING] (2026-08-18 10:01:00,000) test.two: aviso",
        "[+] [ERROR] (2026-08-18 10:02:00,000) test.three: fallo",
    ]
    assert payload["totalLines"] == 2


def test_log_level_counts_ignore_the_level_filter(
    client, admin_user, auth_headers, _isolated_log_file
):
    """Los contadores describen la ventana, no la página filtrada.

    Quien está mirando solo los errores tiene que poder ver que al lado hay
    avisos; si los contadores se calcularan después del filtro de nivel,
    marcarían cero en todo lo demás y no servirían para nada.
    """
    response = client.get(
        "/system/logs",
        query_string={"position": "head", "level": "ERROR"},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 200
    payload, content = _decode_log_content(response)
    assert content.splitlines() == [
        "[+] [ERROR] (2026-08-18 10:02:00,000) test.three: fallo",
    ]
    assert payload["totalLines"] == 1
    assert payload["levelCounts"] == {
        "DEBUG": 0,
        "INFO": 2,
        "WARNING": 1,
        "ERROR": 1,
        "CRITICAL": 0,
    }


def test_log_level_counts_respect_the_time_window(
    client, admin_user, auth_headers, _isolated_log_file
):
    """Acotar por fecha sí cambia los contadores: son de la ventana pedida."""
    response = client.get(
        "/system/logs",
        query_string={
            "position": "head",
            "from": "2026-08-18T10:01:00",
            "to": "2026-08-18T10:02:00",
        },
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 200
    payload, _content = _decode_log_content(response)
    assert payload["levelCounts"] == {
        "DEBUG": 0,
        "INFO": 0,
        "WARNING": 1,
        "ERROR": 1,
        "CRITICAL": 0,
    }


def test_log_rejects_an_unknown_minimum_level(
    client, admin_user, auth_headers, _isolated_log_file
):
    response = client.get(
        "/system/logs",
        query_string={"minLevel": "TRACE"},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 422


def test_log_last_minutes_uses_the_server_clock(
    client, admin_user, auth_headers, tmp_path, monkeypatch
):
    """La ventana relativa la resuelve el servidor, no el navegador.

    Las marcas del log son hora local de la API y no llevan zona horaria, así
    que "los últimos diez minutos" solo significa lo mismo para todos si lo
    calcula quien escribe el log. El test escribe entradas relativas a la hora
    real de la máquina para que el cálculo sea comprobable.
    """
    now = datetime.now()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    def _entry(minutes_ago, level, message):
        stamp = now - timedelta(minutes=minutes_ago)
        printed = stamp.strftime("%Y-%m-%d %H:%M:%S,") + f"{stamp.microsecond // 1000:03d}"
        return f"[+] [{level}] ({printed}) test: {message}"

    (log_dir / "secops.log").write_text(
        "\n".join([
            _entry(120, "ERROR", "hace dos horas"),
            _entry(45, "WARNING", "hace tres cuartos de hora"),
            _entry(5, "ERROR", "hace cinco minutos"),
        ]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(CR, "get_directory_of", lambda _directory: str(log_dir))

    response = client.get(
        "/system/logs",
        query_string={"position": "head", "lastMinutes": 60},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 200
    payload, content = _decode_log_content(response)
    assert [line.split(": ", 1)[1] for line in content.splitlines()] == [
        "hace tres cuartos de hora",
        "hace cinco minutos",
    ]
    assert payload["windowStart"]
    assert payload["levelCounts"]["ERROR"] == 1


def test_log_rejects_a_relative_and_an_absolute_window_together(
    client, admin_user, auth_headers, _isolated_log_file
):
    """Pedir las dos cosas es ambiguo, y se rechaza en vez de elegir una."""
    response = client.get(
        "/system/logs",
        query_string={"lastMinutes": 30, "from": "2026-08-18T10:00:00"},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_log_query"


def test_log_snapshot_survives_appends(client, admin_user, auth_headers, _isolated_log_file):
    first = client.get(
        "/system/logs?position=tail&per_page=1",
        headers=auth_headers(admin_user),
    )
    assert first.status_code == 200
    first_payload, first_content = _decode_log_content(first)
    assert first_content.endswith("final")

    with _isolated_log_file.open("a", encoding="utf-8") as handle:
        handle.write("[+] [INFO] (2026-08-18 10:04:00,000) test.one: añadido\n")

    second = client.get(
        "/system/logs",
        query_string={
            "position": "tail",
            "page": 2,
            "per_page": 1,
            "snapshot": first_payload["snapshot"],
        },
        headers=auth_headers(admin_user),
    )
    assert second.status_code == 200
    second_payload, second_content = _decode_log_content(second)
    assert second_content.endswith("test.three: fallo")
    assert second_payload["totalLines"] == 4


def test_log_snapshot_rejects_truncation(client, admin_user, auth_headers, _isolated_log_file):
    first = client.get("/system/logs", headers=auth_headers(admin_user))
    assert first.status_code == 200
    snapshot = first.get_json()["snapshot"]

    _isolated_log_file.write_text("[+] [INFO] (2026-08-18 11:00:00,000) test: nuevo\n")
    response = client.get(
        "/system/logs",
        query_string={"snapshot": snapshot},
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 409
    assert response.get_json()["error"] == "log_changed"


def test_logs_return_not_found_when_file_is_missing(
    client, admin_user, auth_headers, tmp_path, monkeypatch
):
    log_dir = tmp_path / "empty-logs"
    log_dir.mkdir()
    monkeypatch.setattr(CR, "get_directory_of", lambda _directory: str(log_dir))

    response = client.get("/system/logs", headers=auth_headers(admin_user))

    assert response.status_code == 404
    assert response.get_json()["error"] == "log_not_found"


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
