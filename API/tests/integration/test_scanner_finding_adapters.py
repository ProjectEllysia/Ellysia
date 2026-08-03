"""Integration tests for the Nikto additive Finding write path.

Verifies the dual-write is genuinely additive: the legacy NiktoIncident table
that PDF/history read is populated exactly as before, and a normalized
Finding row now also exists for correlation.

OpenVAS had the same dual-write (OpenVASScanResult) until the scanner was
removed (roadmap §7/§6.3, Ronda 2 — E2); its test was removed with it.
"""

from datetime import datetime

import pytest

import src.modules.shared._endpoints as endpoints_mod
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import NiktoScan
from src.modules.features.themis.repositories import ScanRepository
from src.modules.features.themis.managers import NiktoScanManager

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
