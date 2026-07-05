"""Integration tests for the Ellysia engine scan (Fase 0).

Covers the endpoint's authorization/validation boundary and the engine pipeline
end to end: given an Nmap scan's services, the engine persists informational
findings and they surface through the results endpoint. The engine body is run
directly (``_run_ellysia``) rather than through the task queue, mirroring how the
other scan tests avoid Redis/the worker.
"""

from datetime import datetime

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.sentinel.model import NmapScan, NiktoScan, ScanStatus
from src.modules.sentinel.repositories import ScanRepository
from src.modules.sentinel.managers import EllysiaEngineManager

pytestmark = pytest.mark.integration


_PORTS = [
    {"protocol": "80/tcp", "reason": "syn-ack", "product": "Apache httpd",
     "version": "2.4.49", "given_use": "http", "cpe": "cpe:/a:apache:http_server:2.4.49"},
    {"protocol": "22/tcp", "reason": "syn-ack", "product": "OpenSSH",
     "version": "7.4", "given_use": "ssh", "cpe": ""},
]


def _seed_nmap_scan(app, user_id: int) -> int:
    """Persist a finished Nmap scan with two open ports; return its id."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = NmapScan(target="10.0.0.5", user_id=user_id,
                            started_at=datetime.now(), status=ScanStatus.FINISHED.value)
            repo.save(scan)
            host = repo.get_or_create_host("10.0.0.5", "10.0.0.5")
            repo.persist_nmap_results(scan, host, _PORTS)
            scan_id = scan.id
    return scan_id


def _seed_nikto_scan(app, user_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            scan = NiktoScan(target="example.com", user_id=user_id,
                             started_at=datetime.now(), status=ScanStatus.FINISHED.value)
            ScanRepository(uow).save(scan)
            scan_id = scan.id
    return scan_id


# --------------------------------------------------------- endpoint boundary

def test_ellysia_requires_authentication(client):
    assert client.post("/sentinel/ellysia", json={"sourceScanId": 1}).status_code == 401


def test_ellysia_requires_create_attribute(client, regular_user, auth_headers):
    # role_user lacks sentinel_create (same baseline as the Nmap start endpoint).
    resp = client.post("/sentinel/ellysia", headers=auth_headers(regular_user),
                       json={"sourceScanId": 1})
    assert resp.status_code == 403


def test_ellysia_source_scan_not_found(client, admin_user, auth_headers):
    resp = client.post("/sentinel/ellysia", headers=auth_headers(admin_user),
                       json={"sourceScanId": 999999})
    assert resp.status_code == 404


def test_ellysia_rejects_non_nmap_source(client, app, admin_user, auth_headers):
    nikto_id = _seed_nikto_scan(app, admin_user.id)
    resp = client.post("/sentinel/ellysia", headers=auth_headers(admin_user),
                       json={"sourceScanId": nikto_id})
    assert resp.status_code == 400


def test_ellysia_rejects_another_users_source(client, app, make_user, auth_headers):
    owner = make_user(role="role_admin")
    other = make_user(role="role_admin")
    nmap_id = _seed_nmap_scan(app, owner.id)
    # The source scan belongs to `owner`; `other` must not be able to use it.
    resp = client.post("/sentinel/ellysia", headers=auth_headers(other),
                       json={"sourceScanId": nmap_id})
    assert resp.status_code == 404


# ------------------------------------------------------- engine end to end

def test_ellysia_engine_persists_informational_findings(app, admin_user):
    nmap_id = _seed_nmap_scan(app, admin_user.id)

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        escan_id = escan.id
        mgr._run_ellysia(escan_id, nmap_id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan_id)
            escan = repo.get_by_id(escan_id)

            assert escan.status == ScanStatus.FINISHED.value
            assert len(findings) == 2
            assert {f.category for f in findings} == {"open_port"}
            assert all(f.source == "ellysia" and f.qod == 30 for f in findings)
            # The CPE captured from Nmap rode all the way into the finding.
            assert "cpe:/a:apache:http_server:2.4.49" in {f.cpe for f in findings}


def test_ellysia_scan_surfaces_in_results_endpoint(client, app, admin_user, auth_headers):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        mgr._run_ellysia(escan.id, nmap_id)

    resp = client.get("/sentinel/results?type=ellysia&page=1&per_page=10",
                     headers=auth_headers(admin_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["totalCount"] == 1
    result = body["results"][0]
    assert result["scanType"] == "ellysia"
    assert result["sourceScanId"] == nmap_id
    assert result["totalFindings"] == 2
