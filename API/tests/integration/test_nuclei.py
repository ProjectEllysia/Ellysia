"""Integration tests for the Nuclei scan write path (roadmap Fase U1).

Verifies ``NucleiScanManager._persist_scan_results`` end to end against a real
``NucleiScan`` row: findings land in the shared ``Finding`` table with
``cve_ids``/``cvss_score``/``check_id``/``feed_version`` populated, repeated
templates collapse within a scan, and — the Definición de Hecho of Fase U1 —
a Nuclei finding shares its ``dedup_key`` with a prior Lybra finding of the
same CVE on the same host/port. No real ``nuclei`` binary involved: the JSONL
payload is injected directly, the same pattern
``tests/integration/test_scanner_finding_adapters.py`` already uses for
Nikto.
"""

from datetime import datetime

import pytest

import src.modules.shared._endpoints as endpoints_mod
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import NucleiScan, LybraScan
from src.modules.features.themis.repositories import ScanRepository
from src.modules.features.themis.managers import NucleiScanManager
from src.modules.features.themis.lybra import compute_dedup_key

pytestmark = pytest.mark.integration


def _nuclei_result(**overrides):
    base = {
        "template-id": "CVE-2021-41773",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "critical",
            "tags": ["cve"],
            "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 9.8},
        },
        "type": "http",
        "host": "https://10.0.0.5:443",
        "matched-at": "https://10.0.0.5:443/icons/.%2e/%2e%2e/etc/passwd",
    }
    base.update(overrides)
    return base


def test_nuclei_persist_writes_findings_with_cve_cvss_and_feed_version(app, admin_user, monkeypatch):
    monkeypatch.setattr(
        endpoints_mod, "normalize_target",
        lambda target, resolve_hostname=False: ("10.0.0.5", "10.0.0.5"),
    )
    results_data = [_nuclei_result()]

    with app.app_context():
        with UnitOfWork() as uow:
            scan = NucleiScan(target="10.0.0.5", user_id=admin_user.id, started_at=datetime.now())
            ScanRepository(uow).save(scan)
            scan_id = scan.id

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            NucleiScanManager()._persist_scan_results(uow, scan, results_data)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(scan_id)

    assert len(findings) == 1
    f = findings[0]
    assert f.source == "nuclei"
    assert f.check_id == "nuclei:CVE-2021-41773"
    assert f.cve_ids == ["CVE-2021-41773"]
    assert f.cvss_score == 9.8
    assert f.category == "outdated_software"
    assert f.port == 443
    assert f.qod == 90
    assert f.confirmed is True
    assert f.host_id is not None
    assert f.dedup_key is not None
    # Fallback until NucleiScanManager._execute_scan's post-hoc patch runs
    # (that override needs a real task with a captured templates_version,
    # which this test — no subprocess — never exercises).
    assert f.feed_version.startswith("nuclei-templates")


def test_repeated_template_across_matched_at_collapses_to_one_finding(app, admin_user, monkeypatch):
    """Nuclei repeats the same template once per matched-at (e.g. one exposed
    path found on several URLs of the same host) — merge_findings must
    collapse those within the scan, not persist one row per URL."""
    monkeypatch.setattr(
        endpoints_mod, "normalize_target",
        lambda target, resolve_hostname=False: ("10.0.0.6", "10.0.0.6"),
    )
    results_data = [
        _nuclei_result(host="https://10.0.0.6:443", **{"matched-at": "https://10.0.0.6:443/a"}),
        _nuclei_result(host="https://10.0.0.6:443", **{"matched-at": "https://10.0.0.6:443/b"}),
    ]

    with app.app_context():
        with UnitOfWork() as uow:
            scan = NucleiScan(target="10.0.0.6", user_id=admin_user.id, started_at=datetime.now())
            ScanRepository(uow).save(scan)
            scan_id = scan.id

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            NucleiScanManager()._persist_scan_results(uow, scan, results_data)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(scan_id)

    assert len(findings) == 1


def test_nuclei_finding_shares_dedup_key_with_prior_lybra_finding_same_cve(app, admin_user, monkeypatch):
    """The Definición de Hecho of Fase U1: a hallazgo Nuclei y uno de Lybra
    sobre la misma CVE, host y puerto deben fundirse — mismo dedup_key."""
    monkeypatch.setattr(
        endpoints_mod, "normalize_target",
        lambda target, resolve_hostname=False: ("10.0.0.7", "10.0.0.7"),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            host = scan_repo.get_or_create_host(hostname="10.0.0.7", ip_address="10.0.0.7")
            host_id = host.id

            lybra_scan = LybraScan(target="10.0.0.7", user_id=admin_user.id, started_at=datetime.now())
            scan_repo.save(lybra_scan)

            lybra_finding = {
                "title": "Apache 2.4.49 Path Traversal", "category": "outdated_software",
                "port": 443, "service": "https", "cve_ids": ["CVE-2021-41773"],
                "cvss_score": 9.8, "source": "lybra", "check_id": "lybra:cve-match@1",
                "qod": 70, "confirmed": False, "state": "open", "host_id": host_id,
            }
            lybra_finding["dedup_key"] = compute_dedup_key(lybra_finding)
            scan_repo.persist_findings(lybra_scan, [lybra_finding])

        with UnitOfWork() as uow:
            scan = NucleiScan(target="10.0.0.7", user_id=admin_user.id, started_at=datetime.now())
            ScanRepository(uow).save(scan)
            nuclei_scan_id = scan.id

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(nuclei_scan_id)
            NucleiScanManager()._persist_scan_results(uow, scan, [_nuclei_result()])

        with UnitOfWork() as uow:
            from src.modules.features.themis.model import Finding
            all_findings = uow.session.query(Finding).filter(Finding.host_id == host_id).all()

    dedup_keys = {f.dedup_key for f in all_findings}
    sources = {f.source for f in all_findings}
    assert dedup_keys == {compute_dedup_key(lybra_finding)}
    assert sources == {"lybra", "nuclei"}
