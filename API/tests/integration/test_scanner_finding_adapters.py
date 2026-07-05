"""Integration tests for the Nikto/OpenVAS additive Finding write path.

Verifies the dual-write is genuinely additive: the legacy tables (NiktoIncident,
OpenVASScanResult) that PDF/history read are populated exactly as before, and a
normalized Finding row now also exists for correlation.
"""

from datetime import datetime

import pytest

import src.modules.shared._endpoints as endpoints_mod
from src.modules.infrastructure import UnitOfWork
from src.modules.sentinel.model import NiktoScan, OpenVASScan
from src.modules.sentinel.repositories import ScanRepository
from src.modules.sentinel.managers import NiktoScanManager, OpenVASScanManager

pytestmark = pytest.mark.integration


def test_nikto_persist_writes_incident_and_finding(app, admin_user, monkeypatch):
    # Avoid any real DNS resolution inside _persist_scan_results.
    monkeypatch.setattr(
        endpoints_mod, "normalize_target",
        lambda target, resolve_hostname=False: ("10.0.0.5", "10.0.0.5"),
    )
    incidents_data = [{
        "description": "Repositorio Git expuesto", "osvdb_id": "1",
        "method": "GET", "url": "/.git/config", "severity": "CRITICAL",
    }]

    with app.app_context():
        with UnitOfWork() as uow:
            scan = NiktoScan(target="10.0.0.5", user_id=admin_user.id, started_at=datetime.now())
            ScanRepository(uow).save(scan)
            scan_id = scan.id

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            NiktoScanManager()._persist_scan_results(uow, scan, incidents_data)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            rich = repo.get_nikto_rich(scan_id)
            findings = repo.get_findings_by_scan(scan_id)

    # Legacy path untouched — PDF/history still see the incident.
    assert len(rich.incidents) == 1
    assert rich.incidents[0].osvdb_id == "1"

    # Additive Finding.
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "nikto"
    assert f.check_id == "nikto:1"
    assert f.qod == 85
    assert f.confirmed is False
    assert f.host_id is not None
    assert f.dedup_key is not None


def test_openvas_persist_writes_scan_result_and_finding(app, admin_user):
    vulnerabilities_data = [{
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.999", "name": "Apache Path Traversal",
        "severity_score": 9.8, "severity_class": "Critical", "cvss_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N", "cve_ids": "CVE-2021-41773",
        "cert_refs": None, "bugtraq_ids": None, "other_refs": None,
        "summary": "", "description": "Path traversal", "impact": "", "insight": "",
        "affected_software": "", "solution_type": "VendorFix", "solution": "Upgrade",
        "qod_value": 99, "qod_type": "exploit", "family": "Web Servers", "category": "3",
    }]
    scan_results_data = [{
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.999", "host_ip": "10.0.0.5",
        "port": "80/tcp", "threat": "Critical",
    }]

    with app.app_context():
        with UnitOfWork() as uow:
            scan = OpenVASScan(target="10.0.0.5", user_id=admin_user.id,
                              started_at=datetime.now(), task_id="t1", report_id="r1")
            ScanRepository(uow).save(scan)
            scan_id = scan.id

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            domain_data = (vulnerabilities_data, scan_results_data, {"10.0.0.5"})
            OpenVASScanManager()._persist_scan_results(uow, scan, domain_data)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            rich = repo.get_openvas_rich(scan_id)
            findings = repo.get_findings_by_scan(scan_id)

    # Legacy path untouched — PDF/history still see the scan result + vulnerability.
    assert len(rich.results) == 1
    assert rich.results[0].vulnerability.nvt_oid == "1.3.6.1.4.1.25623.1.0.999"

    # Additive Finding.
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "openvas"
    assert f.check_id == "openvas:1.3.6.1.4.1.25623.1.0.999"
    assert f.cve_ids == ["CVE-2021-41773"]
    assert f.category == "outdated_software"
    assert f.port == 80
    assert f.qod == 99
    assert f.confirmed is True
    assert f.host_id is not None
