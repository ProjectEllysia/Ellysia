"""Integration tests for Ellysia Fase 6 ("análisis profundo").

Two things to prove:
1. Corroborator selection/launch: which of Nmap/Nikto/OpenVAS get fired given
   the scan's mode and discovered services, and that a launch failure for one
   never breaks the Ellysia scan itself.
2. Read-time merge: format_scan fuses Ellysia's own findings with the linked
   corroborators' Finding rows (merge_findings, Fase 5) without persisting
   anything new — the actual payoff of the roadmap's "Nmap/Nikto/OpenVAS become
   complements of Ellysia, not the other way around".

Corroborator managers' run_scan is always monkeypatched: it calls
TaskQueue.submit (real RQ+Redis), which this suite never runs against (see
conftest.py — only redis.Redis.ping/close are stubbed for app startup).
"""

from datetime import datetime

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.sentinel.model import NmapScan, NiktoScan, OpenVASScan, ScanStatus
from src.modules.sentinel.repositories import ScanRepository, KbRepository
from src.modules.sentinel.managers import (
    EllysiaEngineManager, ScanManager,
    NmapScanManager, NiktoScanManager, OpenVASScanManager,
)
from src.modules.sentinel.ellysia import DEFAULT_PORTS
from src.modules.sentinel.services.parsing import validate_port

pytestmark = pytest.mark.integration


_HTTP_SSH_PORTS = [
    {"protocol": "80/tcp", "reason": "syn-ack", "product": "Apache httpd",
     "version": "2.4.49", "given_use": "http", "cpe": "cpe:/a:apache:http_server:2.4.49"},
    {"protocol": "22/tcp", "reason": "syn-ack", "product": "OpenSSH",
     "version": "7.4", "given_use": "ssh", "cpe": ""},
]
_SSH_ONLY_PORTS = [_HTTP_SSH_PORTS[1]]


def _seed_nmap_scan(app, user_id: int, ports=None) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = NmapScan(target="10.0.0.5", user_id=user_id,
                            started_at=datetime.now(), status=ScanStatus.FINISHED.value)
            repo.save(scan)
            host = repo.get_or_create_host("10.0.0.5", "10.0.0.5")
            repo.persist_nmap_results(scan, host, ports if ports is not None else _HTTP_SSH_PORTS)
            scan_id = scan.id
    return scan_id


def _seed_openvas_cve_finding(app, user_id: int, cve_id="CVE-2021-41773", qod_value=99) -> int:
    """A finished OpenVAS scan whose additive Finding matches the CVE the
    Ellysia KB matcher would find on the seeded Nmap scan's port 80."""
    vulnerabilities_data = [{
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.999", "name": "Apache Path Traversal",
        "severity_score": 9.8, "severity_class": "Critical", "cvss_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N", "cve_ids": cve_id,
        "cert_refs": None, "bugtraq_ids": None, "other_refs": None,
        "summary": "", "description": "Path traversal", "impact": "", "insight": "",
        "affected_software": "", "solution_type": "VendorFix", "solution": "Upgrade",
        "qod_value": qod_value, "qod_type": "exploit", "family": "Web Servers", "category": "3",
    }]
    scan_results_data = [{
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.999", "host_ip": "10.0.0.5",
        "port": "80/tcp", "threat": "Critical",
    }]
    with app.app_context():
        with UnitOfWork() as uow:
            scan = OpenVASScan(target="10.0.0.5", user_id=user_id, started_at=datetime.now(),
                              status=ScanStatus.FINISHED.value, task_id="t1", report_id="r1")
            ScanRepository(uow).save(scan)
            scan_id = scan.id
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            domain_data = (vulnerabilities_data, scan_results_data, {"10.0.0.5"})
            OpenVASScanManager()._persist_scan_results(uow, scan, domain_data)
    return scan_id


def _seed_kb_apache_cve(app):
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


# ------------------------------------------------------- corroborator launch

def _patch_corroborators(monkeypatch, calls: dict):
    """Stub run_scan on all three corroborator managers; records calls, never
    touches the (Redis-backed) TaskQueue."""
    def make_stub(name, next_id):
        def stub(self, **kwargs):
            calls.setdefault(name, []).append(kwargs)
            return next_id
        return stub
    monkeypatch.setattr(NmapScanManager, "run_scan", make_stub("nmap", 901))
    monkeypatch.setattr(NiktoScanManager, "run_scan", make_stub("nikto", 902))
    monkeypatch.setattr(OpenVASScanManager, "run_scan", make_stub("openvas", 903))


def test_deep_self_discovery_launches_all_three_with_http_service(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(EllysiaEngineManager, "_discover_ports",
                        lambda self, target, ports: [80, 22])

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id, source_scan_id=None)
        mgr._run_ellysia(escan.id, source_scan_id=None, discover_ports=None, deep=True)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert set(calls.keys()) == {"nmap", "nikto", "openvas"}
    assert sorted(escan.deep_scan_ids) == [901, 902, 903]


def test_deep_skips_nmap_when_source_scan_id_present(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id)  # already has HTTP + SSH ports

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_ellysia(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=True)

    # A fresh Nmap corroborator would be redundant: Ellysia already has Nmap ports.
    assert "nmap" not in calls
    assert "nikto" in calls and "openvas" in calls


def test_deep_skips_nikto_without_http_service(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id, ports=_SSH_ONLY_PORTS)

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_ellysia(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=True)

    assert "nikto" not in calls
    assert "openvas" in calls          # unconditional


def test_deep_false_launches_nothing(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id)

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_ellysia(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert calls == {}
    assert escan.deep_scan_ids is None


def test_deep_one_corroborator_failure_does_not_fail_the_scan(app, admin_user, monkeypatch):
    def failing_nikto(self, **kwargs):
        raise RuntimeError("queue unavailable")
    monkeypatch.setattr(NiktoScanManager, "run_scan", failing_nikto)
    monkeypatch.setattr(NmapScanManager, "run_scan", lambda self, **k: 901)
    monkeypatch.setattr(OpenVASScanManager, "run_scan", lambda self, **k: 903)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(EllysiaEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id, source_scan_id=None)
        mgr._run_ellysia(escan.id, source_scan_id=None, discover_ports=None, deep=True)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert escan.status == ScanStatus.FINISHED.value   # Nikto's failure didn't sink the scan
    assert sorted(escan.deep_scan_ids) == [901, 903]    # only the two that succeeded


def test_deep_nmap_port_string_is_valid():
    """Regression guard: DEFAULT_PORTS must build a validate_port-acceptable
    string (strictly ascending, no duplicates) or every deep Nmap launch fails."""
    ports_str = ",".join(str(p) for p in sorted(set(DEFAULT_PORTS)))
    assert validate_port(ports_str) == sorted(set(DEFAULT_PORTS))


# --------------------------------------------------------------- read-time merge

def test_format_scan_merges_corroborator_finding_without_double_counting(app, admin_user):
    _seed_kb_apache_cve(app)
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    openvas_id = _seed_openvas_cve_finding(app, admin_user.id, qod_value=99)

    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_ellysia(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)

        # Simulate what _launch_deep_corroborators would have recorded.
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            e = repo.get_by_id(escan.id)
            e.deep_scan_ids = [openvas_id]

        result = mgr.format_scan(escan.id)

    assert result["deep"] is True
    assert result["deepScanIds"] == [openvas_id]

    cve_findings = [f for f in result["findings"] if f["cveIds"] == ["CVE-2021-41773"]]
    assert len(cve_findings) == 1                        # merged, not duplicated
    merged = cve_findings[0]
    assert set(merged["source"].split(",")) == {"ellysia", "openvas"}
    assert merged["qod"] == 99                            # OpenVAS's stronger signal wins
    assert merged["confirmed"] is True                    # escalated by the OpenVAS side

    # The two open_port informational findings (Ellysia-only) are untouched.
    assert sum(1 for f in result["findings"] if f["category"] == "open_port") == 2


def test_format_scan_without_deep_scan_ids_is_unaffected(app, admin_user):
    """Non-deep scans must format exactly as before the Fase 6 rewrite."""
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = EllysiaEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_ellysia(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)
        result = mgr.format_scan(escan.id)

    assert result["deep"] is False
    assert result["deepScanIds"] == []
    assert result["totalFindings"] == 2


# ------------------------------------------------------------ endpoint boundary

def test_ellysia_endpoint_accepts_deep_flag(client, app, admin_user, auth_headers, monkeypatch):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 555
    monkeypatch.setattr(EllysiaEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/sentinel/ellysia", headers=auth_headers(admin_user),
                       json={"sourceScanId": nmap_id, "deep": True})

    assert resp.status_code == 201
    assert captured.get("deep") is True


def test_ellysia_endpoint_deep_defaults_to_false(client, app, admin_user, auth_headers, monkeypatch):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 556
    monkeypatch.setattr(EllysiaEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/sentinel/ellysia", headers=auth_headers(admin_user),
                       json={"sourceScanId": nmap_id})

    assert resp.status_code == 201
    assert captured.get("deep") is False
