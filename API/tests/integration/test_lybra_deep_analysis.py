"""Integration tests for Lybra Fase 6 ("análisis profundo").

Two things to prove:
1. Corroborator selection/launch: which of Nmap/Nikto/Nuclei get fired given
   the scan's mode and discovered services, and that a launch failure for one
   never breaks the Lybra scan itself. OpenVAS no longer launches here at all
   — removed in E0 of the OpenVAS teardown (roadmap §7/§6.3, Ronda 0); the
   corroborator pool is Nmap + Nikto + Nuclei.
2. Read-time merge: format_scan fuses Lybra's own findings with the linked
   corroborators' Finding rows (merge_findings, Fase 5) without persisting
   anything new — the actual payoff of the roadmap's "Nmap/Nikto/Nuclei
   become complements of Lybra, not the other way around". Any historical
   OpenVAS Finding row (``source="openvas"``) would still merge the same
   way — the merge logic is source-agnostic — but the seed used below is
   Nuclei's now, since nothing produces an OpenVAS Finding anymore.

Corroborator managers' run_scan is always monkeypatched: it calls
TaskQueue.submit (real RQ+Redis), which this suite never runs against (see
conftest.py — only redis.Redis.ping/close are stubbed for app startup).

Nuclei (Fase U2) shares Nikto's gate exactly — both are HTTP-only tools, both
fire only when at least one HTTP-like service was found — so it rides along in
the same scenarios rather than getting a parallel set of tests.
"""

from datetime import datetime

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import NmapScan, NiktoScan, NucleiScan, ScanStatus
from src.modules.features.themis.repositories import ScanRepository, KbRepository
from src.modules.features.themis.managers import (
    LybraEngineManager, ScanManager,
    NmapScanManager, NiktoScanManager, NucleiScanManager,
)
from src.modules.features.themis.lybra import DEFAULT_PORTS
from src.modules.features.themis.services.parsing import validate_port

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


def _seed_nuclei_cve_finding(app, user_id: int, cve_id="CVE-2021-41773") -> int:
    """A finished Nuclei scan whose additive Finding matches the CVE the
    Lybra KB matcher would find on the seeded Nmap scan's port 80.

    Replaces the pre-Ronda-2 OpenVAS seed (roadmap §7/§6.3, Ronda 2 — E2):
    same purpose (a second, independent source reporting the same CVE so the
    merge test below has something real to fuse), different scanner. Nikto
    can't stand in for this — its findings never carry a CVE at all (no CVE,
    no CVSS, no CPE, by design)."""
    results_data = [{
        "template-id": "CVE-2021-41773-path-traversal",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "critical",
            "classification": {"cve-id": [cve_id.lower()], "cvss-score": 9.8},
        },
        "type": "http",
        "matched-at": "http://10.0.0.5:80/",
        "host": "10.0.0.5",
    }]
    with app.app_context():
        with UnitOfWork() as uow:
            scan = NucleiScan(target="10.0.0.5", user_id=user_id, started_at=datetime.now(),
                              status=ScanStatus.FINISHED.value)
            ScanRepository(uow).save(scan)
            scan_id = scan.id
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            NucleiScanManager()._persist_scan_results(uow, scan, results_data)
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
    """Stub run_scan on the three corroborator managers; records calls, never
    touches the (Redis-backed) TaskQueue. OpenVASScanManager is not stubbed
    here — nothing launches it anymore (E0)."""
    def make_stub(name, next_id):
        def stub(self, **kwargs):
            calls.setdefault(name, []).append(kwargs)
            return next_id
        return stub
    monkeypatch.setattr(NmapScanManager, "run_scan", make_stub("nmap", 901))
    monkeypatch.setattr(NiktoScanManager, "run_scan", make_stub("nikto", 902))
    monkeypatch.setattr(NucleiScanManager, "run_scan", make_stub("nuclei", 904))


def test_deep_self_discovery_launches_three_with_http_service(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80, 22])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None, deep=True)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert set(calls.keys()) == {"nmap", "nikto", "nuclei"}
    assert sorted(escan.deep_scan_ids) == [901, 902, 904]


def test_deep_skips_nmap_when_source_scan_id_present(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id)  # already has HTTP + SSH ports

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=True)

    # A fresh Nmap corroborator would be redundant: Lybra already has Nmap ports.
    assert "nmap" not in calls
    assert "nikto" in calls and "nuclei" in calls


def test_deep_skips_nikto_and_nuclei_without_http_service(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id, ports=_SSH_ONLY_PORTS)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=True)

    assert "nikto" not in calls
    assert "nuclei" not in calls       # same HTTP-only gate as Nikto


def test_deep_false_launches_nothing(app, admin_user, monkeypatch):
    calls: dict = {}
    _patch_corroborators(monkeypatch, calls)
    nmap_id = _seed_nmap_scan(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert calls == {}
    assert escan.deep_scan_ids is None


def test_deep_one_corroborator_failure_does_not_fail_the_scan(app, admin_user, monkeypatch):
    def failing_nikto(self, **kwargs):
        raise RuntimeError("queue unavailable")
    monkeypatch.setattr(NiktoScanManager, "run_scan", failing_nikto)
    monkeypatch.setattr(NmapScanManager, "run_scan", lambda self, **k: 901)
    monkeypatch.setattr(NucleiScanManager, "run_scan", lambda self, **k: 904)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None, deep=True)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert escan.status == ScanStatus.FINISHED.value   # Nikto's failure didn't sink the scan
    assert sorted(escan.deep_scan_ids) == [901, 904]   # only the ones that succeeded


def test_deep_nmap_port_string_is_valid():
    """Regression guard: DEFAULT_PORTS must build a validate_port-acceptable
    string (strictly ascending, no duplicates) or every deep Nmap launch fails."""
    ports_str = ",".join(str(p) for p in sorted(set(DEFAULT_PORTS)))
    assert validate_port(ports_str) == sorted(set(DEFAULT_PORTS))


# --------------------------------------------------------------- read-time merge

def test_format_scan_merges_corroborator_finding_without_double_counting(app, admin_user):
    _seed_kb_apache_cve(app)
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    nuclei_id = _seed_nuclei_cve_finding(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)

        # Simulate what _launch_deep_corroborators would have recorded.
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            e = repo.get_by_id(escan.id)
            e.deep_scan_ids = [nuclei_id]

        result = mgr.format_scan(escan.id)

    assert result["deep"] is True
    assert result["deepScanIds"] == [nuclei_id]

    cve_findings = [f for f in result["findings"] if f["cveIds"] == ["CVE-2021-41773"]]
    assert len(cve_findings) == 1                        # merged, not duplicated
    merged = cve_findings[0]
    assert set(merged["source"].split(",")) == {"lybra", "nuclei"}
    assert merged["qod"] == 90                            # Nuclei's stronger signal wins (QOD_NUCLEI_MATCH)
    assert merged["confirmed"] is True                    # escalated by the Nuclei side

    # The two open_port informational findings (Lybra-only) are untouched.
    assert sum(1 for f in result["findings"] if f["category"] == "open_port") == 2


def test_format_scan_without_deep_scan_ids_is_unaffected(app, admin_user):
    """Non-deep scans must format exactly as before the Fase 6 rewrite."""
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, source_scan_id=nmap_id, discover_ports=None, deep=False)
        result = mgr.format_scan(escan.id)

    assert result["deep"] is False
    assert result["deepScanIds"] == []
    assert result["totalFindings"] == 2


# ------------------------------------------------------------ endpoint boundary

def test_lybra_endpoint_accepts_deep_flag(client, app, admin_user, auth_headers, monkeypatch):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 555
    monkeypatch.setattr(LybraEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"sourceScanId": nmap_id, "deep": True})

    assert resp.status_code == 201
    assert captured.get("deep") is True


def test_lybra_endpoint_deep_defaults_to_false(client, app, admin_user, auth_headers, monkeypatch):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 556
    monkeypatch.setattr(LybraEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"sourceScanId": nmap_id})

    assert resp.status_code == 201
    assert captured.get("deep") is False
