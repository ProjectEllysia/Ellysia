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
from src.modules.sentinel.repositories import ScanRepository, KbRepository
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


def _seed_kb_apache_cve(app):
    """Seed the KB with CVE-2021-41773 for apache http_server 2.4.49 (+KEV/EPSS)."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
                 "description": "Path traversal", "cwe_ids": ["CWE-22"], "source": "nvd"},
                [{"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )
            repo.upsert_kev({"cve_id": "CVE-2021-41773", "known_ransomware": False,
                             "date_added": None, "due_date": None})
            repo.upsert_epss({"cve_id": "CVE-2021-41773", "score": 0.97,
                              "percentile": 0.99, "scored_at": None})


def test_ellysia_version_match_produces_cve_finding(app, admin_user):
    _seed_kb_apache_cve(app)
    nmap_id = _seed_nmap_scan(app, admin_user.id)  # port 80 = Apache 2.4.49 with CPE

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        mgr._run_ellysia(escan.id, nmap_id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    vuln = vulns[0]
    assert vuln.cve_ids == ["CVE-2021-41773"]
    assert vuln.cvss_score == 7.5
    assert vuln.qod == 70
    assert vuln.confirmed is False
    assert vuln.in_kev is True          # enriched from the KB's KEV table
    assert vuln.epss_score == 0.97
    # The two informational "open port" findings are still there (80 + 22).
    assert sum(1 for f in findings if f.category == "open_port") == 2


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
