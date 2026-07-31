"""Tests de integración del módulo Themis (escaneos y carpetas).

Los escaneos reales (nmap/nikto/openvas) corren en el worker en segundo plano;
aquí se verifica la frontera de autorización y los caminos síncronos de lectura
y de carpetas, sin lanzar herramientas externas ni depender de Redis.
"""

from datetime import datetime

import pytest

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import NmapScan, ScanStatus, ThemisDocument
from src.modules.features.themis.repositories import ScanRepository, ThemisReportRepository

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------- escaneos

_VALID_NMAP_BODY = {"target": "127.0.0.1", "ports": "80"}


def test_start_nmap_requires_authentication(client):
    assert client.post("/themis/nmap", json=_VALID_NMAP_BODY).status_code == 401


def test_start_nmap_requires_create_attribute(client, regular_user, auth_headers):
    # role_user no incluye themis_create en su baseline.
    resp = client.post("/themis/nmap", headers=auth_headers(regular_user),
                       json=_VALID_NMAP_BODY)
    assert resp.status_code == 403


def test_list_results_empty(client, regular_user, auth_headers):
    resp = client.get("/themis/results?type=all&page=1&per_page=10",
                      headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0


def test_stats_for_new_user(client, regular_user, auth_headers):
    resp = client.get("/themis/stats", headers=auth_headers(regular_user))
    assert resp.status_code == 200


def test_scan_detail_not_found(client, regular_user, auth_headers):
    resp = client.get("/themis/results/999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


# -------------------------------------------------------------------- carpetas

def test_folder_crud_roundtrip(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)  # role_user tiene los permisos de carpeta

    created = client.post("/themis/folders", headers=headers, json={"name": "Mi carpeta"})
    assert created.status_code == 201
    folder_id = created.get_json()["folderId"]

    listed = client.get("/themis/folders", headers=headers)
    assert listed.status_code == 200
    names = [f["name"] for f in listed.get_json()["folders"]]
    assert "Mi carpeta" in names

    renamed = client.put(f"/themis/folders/{folder_id}", headers=headers,
                         json={"name": "Renombrada"})
    assert renamed.status_code == 200
    assert renamed.get_json()["name"] == "Renombrada"

    deleted = client.delete(f"/themis/folders/{folder_id}", headers=headers)
    assert deleted.status_code == 200


def test_folder_isolation_between_users(client, make_user, auth_headers):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")

    created = client.post("/themis/folders", headers=auth_headers(owner),
                         json={"name": "Privada"})
    folder_id = created.get_json()["folderId"]

    # Otro usuario no debe poder renombrar la carpeta ajena.
    resp = client.put(f"/themis/folders/{folder_id}", headers=auth_headers(other),
                     json={"name": "Hackeada"})
    assert resp.status_code == 404


# ------------------------------------------------------------------------ SSRF
# S1/S2: Nikto aceptaba cualquier hostname sin pasar por validate_targets()
# (a diferencia de Nmap/OpenVAS), y 'areLocalIpsAllowed' estaba en true en el
# SecOpsConfig.json versionado. Ambos cierran el mismo hueco: sin autorización
# explícita, ningún scanner debe poder alcanzar una IP privada/loopback ni la
# IP de metadata de nube.
#
# 'themis.areLocalIpsAllowed' se deja en true en el SecOpsConfig.json
# versionado a propósito, para desarrollo local (ver CLAUDE.md). Estos tests
# verifican la protección anti-SSRF en sí, así que fuerzan el valor a false
# independientemente de esa config ambiente, igual que TestPrivateIpPolicy en
# tests/unit/test_themis_parsing.py.


@pytest.fixture()
def themis_creator(make_user):
    return make_user(role="role_user", attributes=["themis_create"])


@pytest.fixture(autouse=True)
def _reject_local_ips(monkeypatch):
    monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))


def test_nikto_rejects_loopback_target(client, themis_creator, auth_headers):
    resp = client.post(
        "/themis/nikto", headers=auth_headers(themis_creator),
        json={"target": "127.0.0.1", "timeout": 60},
    )
    assert resp.status_code == 403


def test_nikto_rejects_cloud_metadata_target(client, themis_creator, auth_headers):
    resp = client.post(
        "/themis/nikto", headers=auth_headers(themis_creator),
        json={"target": "169.254.169.254", "timeout": 60},
    )
    assert resp.status_code == 403


def test_nmap_rejects_private_ip_target(client, themis_creator, auth_headers):
    # Nmap ya validaba vía validate_targets(); regresión de S2 (el default de
    # config debe rechazar, no solo el código).
    resp = client.post(
        "/themis/nmap", headers=auth_headers(themis_creator),
        json={"target": "192.168.1.1", "ports": "80"},
    )
    assert resp.status_code == 403


# -------------------------------------------------------------------- B4 CAS
# cancel_scan (API) y el worker terminando el escaneo corren en procesos
# separados; sin un UPDATE atómico con WHERE, la última escritura ganaba sin
# importar cuál reflejaba la realidad.


def _make_scan(app, user_id, status=ScanStatus.RUNNING):
    with app.app_context():
        with UnitOfWork() as uow:
            scan = NmapScan(target="10.0.0.9", user_id=user_id, started_at=datetime.now())
            scan.status = status.value
            ScanRepository(uow).save(scan)
            return scan.id


def test_update_status_if_transitions_when_expected_matches(app, regular_user):
    scan_id = _make_scan(app, regular_user.id, ScanStatus.RUNNING)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            ok = repo.update_status_if(
                scan_id, {ScanStatus.PENDING, ScanStatus.RUNNING}, ScanStatus.CANCELLED
            )
        assert ok is True
        with UnitOfWork() as uow:
            assert ScanRepository(uow).get_by_id(scan_id).status == ScanStatus.CANCELLED.value


def test_update_status_if_noop_when_already_terminal(app, regular_user):
    # Simula: el worker ya marcó el escaneo FINISHED antes de que cancel_scan
    # intente escribir CANCELLED — la escritura no debe pisar el resultado real.
    scan_id = _make_scan(app, regular_user.id, ScanStatus.FINISHED)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            ok = repo.update_status_if(
                scan_id, {ScanStatus.PENDING, ScanStatus.RUNNING}, ScanStatus.CANCELLED
            )
        assert ok is False
        with UnitOfWork() as uow:
            assert ScanRepository(uow).get_by_id(scan_id).status == ScanStatus.FINISHED.value


# ------------------------------------------------------------------------- B8
# get_scan_status() debe usar el mismo vocabulario que scan.status ("finished"),
# no el de TaskStatus ("completed"), cuando cae al fallback de BD (job ya no
# está en TaskQueue).


def test_get_scan_status_fallback_uses_finished_vocabulary(app, regular_user, monkeypatch):
    import src.modules.features.themis.managers.scan as scan_mod

    class _NoTaskQueue:
        def get_task_by_external_id(self, external_id, category=None):
            return None

    monkeypatch.setattr(scan_mod.TaskQueue, "get_instance", lambda: _NoTaskQueue())

    from src.modules.features.themis.managers import NmapScanManager

    scan_id = _make_scan(app, regular_user.id, ScanStatus.FINISHED)
    with app.app_context():
        status = NmapScanManager().get_scan_status(scan_id)
        assert status == "finished"


def test_openvas_scheduled_flow_rejects_private_ip(app):
    # C3: la validación de host único/IP privada vivía solo en el endpoint
    # HTTP; el flujo programado (scheduling._run_openvas_scan) llamaba a
    # OpenVASScanManager.run_scan() directo, sin pasar por validate_targets().
    from src.modules.features.themis.exceptions import PrivateIPRequested
    from src.modules.features.themis.managers import OpenVASScanManager

    with app.app_context():
        with pytest.raises(PrivateIPRequested):
            OpenVASScanManager().run_scan(target="10.0.0.5", user_id=1)


# --------------------------------------------------------------- N1 IDOR docs
# get_documents_by_scan y document-status (por scan_id) no verificaban
# ownership: cualquier usuario con THEMIS_READ podía enumerar los documentos
# (ids, fechas, estado, downloadUrl) de escaneos ajenos.


def _make_scan_with_doc(app, user_id, status=ScanStatus.FINISHED):
    with app.app_context():
        with UnitOfWork() as uow:
            scan = NmapScan(target="10.0.0.9", user_id=user_id, started_at=datetime.now())
            scan.status = status.value
            ScanRepository(uow).save(scan)
            doc = ThemisDocument(
                scan_id=scan.id,
                scan_type="nmap",
                document_type="themis",
                filename="",
                format="pdf",
                status="running",
                user_id=user_id,
                is_ai_generated=0,
            )
            ThemisReportRepository(uow).save(doc)
            return scan.id, doc.id


def test_documents_by_scan_rejects_other_user(client, app, make_user, auth_headers):
    owner = make_user(role="role_user", attributes=["themis_read"])
    other = make_user(role="role_user", attributes=["themis_read"])
    scan_id, _ = _make_scan_with_doc(app, owner.id)

    resp = client.get(
        f"/themis/scan/{scan_id}/documents", headers=auth_headers(other)
    )
    assert resp.status_code == 404


def test_document_status_by_scan_id_rejects_other_user(client, app, make_user, auth_headers):
    owner = make_user(role="role_user", attributes=["themis_read"])
    other = make_user(role="role_user", attributes=["themis_read"])
    scan_id, _ = _make_scan_with_doc(app, owner.id)

    resp = client.get(
        f"/themis/document-status?scan_id={scan_id}", headers=auth_headers(other)
    )
    assert resp.status_code == 404


def test_document_status_by_document_id_rejects_other_user(client, app, make_user, auth_headers):
    owner = make_user(role="role_user", attributes=["themis_read"])
    other = make_user(role="role_user", attributes=["themis_read"])
    _, doc_id = _make_scan_with_doc(app, owner.id)

    resp = client.get(
        f"/themis/document-status?document_id={doc_id}", headers=auth_headers(other)
    )
    assert resp.status_code == 404


# --------------------------------------------------------------- N6 format_scan
# format_scan debe aceptar una instancia ya cargada (_scan=) para evitar
# el re-query por ID en listados paginados.


def test_format_scan_accepts_preloaded_instance(app, regular_user):
    from src.modules.features.themis.managers import NmapScanManager

    scan_id = _make_scan(app, regular_user.id, ScanStatus.FINISHED)
    with app.app_context():
        mgr = NmapScanManager()
        # Cargar la instancia explícitamente y pasarla a format_scan
        scan = mgr.get_scan_by_id(scan_id)
        assert scan is not None
        result = mgr.format_scan(scan_id, _scan=scan)
        assert result["id"] == scan_id
        assert result["scanType"] == "nmap"
        # openPorts y severityBreakdown ahora viven en format_scan (A7)
        assert "openPorts" in result


def test_format_scan_openvas_includes_severity_breakdown(app, regular_user):
    # A7: severityBreakdown antes vivía en el endpoint; ahora en format_scan.
    from src.modules.features.themis.managers import OpenVASScanManager
    from src.modules.features.themis.model import OpenVASScan

    with app.app_context():
        with UnitOfWork() as uow:
            scan = OpenVASScan(target="10.0.0.1", user_id=regular_user.id, started_at=datetime.now())
            scan.status = ScanStatus.FINISHED.value
            scan.task_id = "t1"
            scan.report_id = "r1"
            ScanRepository(uow).save(scan)
            scan_id = scan.id

        mgr = OpenVASScanManager()
        result = mgr.format_scan(scan_id)
        assert "severityBreakdown" in result
        assert set(result["severityBreakdown"].keys()) == {"critical", "high", "medium", "low", "info"}
