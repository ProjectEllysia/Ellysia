"""Integration tests for the Lybra engine scan (Fase 0).

Covers the endpoint's authorization/validation boundary and the engine pipeline
end to end: given an Nmap scan's services, the engine persists informational
findings and they surface through the results endpoint. The engine body is run
directly (``_run_lybra``) rather than through the task queue, mirroring how the
other scan tests avoid Redis/the worker.
"""

from datetime import datetime

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.themis.model import NmapScan, NiktoScan, ScanStatus
from src.modules.themis.repositories import ScanRepository, KbRepository
from src.modules.themis.managers import LybraEngineManager, ScanManager

pytestmark = pytest.mark.integration


_PORTS = [
    {"protocol": "80/tcp", "reason": "syn-ack", "product": "Apache httpd",
     "version": "2.4.49", "given_use": "http", "cpe": "cpe:/a:apache:http_server:2.4.49"},
    {"protocol": "22/tcp", "reason": "syn-ack", "product": "OpenSSH",
     "version": "7.4", "given_use": "ssh", "cpe": ""},
]


def _seed_nmap_scan(app, user_id: int, ports=None) -> int:
    """Persist a finished Nmap scan with the given open ports; return its id."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = NmapScan(target="10.0.0.5", user_id=user_id,
                            started_at=datetime.now(), status=ScanStatus.FINISHED.value)
            repo.save(scan)
            host = repo.get_or_create_host("10.0.0.5", "10.0.0.5")
            repo.persist_nmap_results(scan, host, ports if ports is not None else _PORTS)
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

def test_lybra_requires_authentication(client):
    assert client.post("/themis/lybra", json={"sourceScanId": 1}).status_code == 401


def test_lybra_requires_create_attribute(client, regular_user, auth_headers):
    # role_user lacks themis_create (same baseline as the Nmap start endpoint).
    resp = client.post("/themis/lybra", headers=auth_headers(regular_user),
                       json={"sourceScanId": 1})
    assert resp.status_code == 403


def test_lybra_source_scan_not_found(client, admin_user, auth_headers):
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"sourceScanId": 999999})
    assert resp.status_code == 404


def test_lybra_requires_a_mode(client, admin_user, auth_headers):
    # Neither sourceScanId nor target -> schema rejects it.
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user), json={})
    assert resp.status_code in (400, 422)


def test_lybra_self_discovery_produces_open_port_findings(app, admin_user, monkeypatch):
    # Stub reachability (no real socket) and the connect scan; the rest of the
    # self-discovery pipeline runs for real.
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80, 22])

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="8.8.8.8", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan.id)
            escan = repo.get_by_id(escan.id)

    assert escan.status == ScanStatus.FINISHED.value
    open_ports = [f for f in findings if f.category == "open_port"]
    assert {f.port for f in open_ports} == {80, 22}
    # Self-discovery creates a Host for the target, so findings are anchored.
    assert all(f.host_id is not None for f in findings)


def test_lybra_self_discovery_unreachable_host_fails_without_false_fixed(app, admin_user, monkeypatch):
    """An unreachable host must never look like 'scanned clean, nothing open':
    that would mark every previously-open finding as falsely fixed."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: False))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.99", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan.id)
            escan = repo.get_by_id(escan.id)

    assert escan.status == ScanStatus.FAILED.value
    assert findings == []          # no misleading findings persisted at all


def test_lybra_self_discovery_probe_failure_fails_without_false_fixed(app, admin_user, monkeypatch):
    """Host is reachable, but the connect scan itself blows up unexpectedly:
    must also fail the scan rather than silently proceed with zero findings."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: None)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert escan.status == ScanStatus.FAILED.value


def test_lybra_self_discovery_genuine_zero_ports_still_marks_fixed(app, admin_user, monkeypatch):
    """Discovery running cleanly and finding nothing IS legitimate evidence:
    a previously-open finding on this target should still be marked fixed."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])

    with app.app_context():
        mgr = LybraEngineManager()
        # First scan: port 80 open.
        e1 = mgr._create_scan_record(target="10.0.0.7", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(e1.id, source_scan_id=None, discover_ports=None)

    # Second scan: discovery ran cleanly and genuinely found nothing open.
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [])
    with app.app_context():
        mgr = LybraEngineManager()
        e2 = mgr._create_scan_record(target="10.0.0.7", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(e2.id, source_scan_id=None, discover_ports=None)
        with UnitOfWork() as uow:
            findings2 = ScanRepository(uow).get_findings_by_scan(e2.id)
            e2 = ScanRepository(uow).get_by_id(e2.id)

    assert e2.status == ScanStatus.FINISHED.value
    assert any(f.state == "fixed" and f.category == "open_port" for f in findings2)


def test_lybra_self_discovery_reuses_host_created_by_nmap(app, admin_user):
    """Self-discovery must not create a second Host row for an IP another
    scanner already resolved to a hostname."""
    with app.app_context():
        with UnitOfWork() as uow:
            ScanRepository(uow).get_or_create_host(hostname="server.example.com", ip_address="10.0.0.42")

        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.42", user_id=admin_user.id, source_scan_id=None)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            found = repo.get_host_by_ip("10.0.0.42")
            assert found is not None and found.hostname == "server.example.com"

            host = repo.get_host_by_ip(escan.target) or repo.get_or_create_host(
                hostname=escan.target, ip_address=escan.target,
            )
            all_hosts = uow.session.query(type(host)).filter(type(host).ip_address == "10.0.0.42").all()

        assert host.hostname == "server.example.com"   # reused, not a fresh "10.0.0.42" row
        assert len(all_hosts) == 1                       # no duplicate


def test_lybra_rejects_non_nmap_source(client, app, admin_user, auth_headers):
    nikto_id = _seed_nikto_scan(app, admin_user.id)
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"sourceScanId": nikto_id})
    assert resp.status_code == 400


def test_lybra_rejects_another_users_source(client, app, make_user, auth_headers):
    owner = make_user(role="role_admin")
    other = make_user(role="role_admin")
    nmap_id = _seed_nmap_scan(app, owner.id)
    # The source scan belongs to `owner`; `other` must not be able to use it.
    resp = client.post("/themis/lybra", headers=auth_headers(other),
                       json={"sourceScanId": nmap_id})
    assert resp.status_code == 404


# ------------------------------------------------------- engine end to end

def test_lybra_engine_persists_informational_findings(app, admin_user):
    nmap_id = _seed_nmap_scan(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        escan_id = escan.id
        mgr._run_lybra(escan_id, nmap_id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan_id)
            escan = repo.get_by_id(escan_id)

            assert escan.status == ScanStatus.FINISHED.value
            assert len(findings) == 2
            assert {f.category for f in findings} == {"open_port"}
            assert all(f.source == "lybra" and f.qod == 30 for f in findings)
            # The CPE captured from Nmap rode all the way into the finding,
            # normalized to 2.3 (consistent with version-match findings).
            assert "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" in {f.cpe for f in findings}


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


def test_lybra_version_match_produces_cve_finding(app, admin_user):
    _seed_kb_apache_cve(app)
    nmap_id = _seed_nmap_scan(app, admin_user.id)  # port 80 = Apache 2.4.49 with CPE

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        mgr._run_lybra(escan.id, nmap_id)

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


def test_lybra_active_check_persists_confirmed_finding(app, admin_user, monkeypatch):
    # Enable active checks and stub the HTTP probe so no real network is hit.
    import src.modules.system.config_reading as CR
    from src.modules.themis.lybra import checks as checks_mod
    from src.modules.themis.lybra.checks import Response

    monkeypatch.setattr(CR, "is_lybra_active_checks_enabled", lambda: True)

    def fake_fetch(self, host, port, method, path):
        if path == "/.git/config":
            return Response(200, "[core]\n\trepositoryformatversion = 0\n", {})
        return Response(404, "", {})
    monkeypatch.setattr(checks_mod.HttpProbe, "fetch", fake_fetch)

    nmap_id = _seed_nmap_scan(app, admin_user.id)  # http service on port 80
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        mgr._run_lybra(escan.id, nmap_id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    active = [f for f in findings if f.check_id == "lybra:git-config-exposure@1"]
    assert len(active) == 1
    assert active[0].qod == 99
    assert active[0].confirmed is True
    assert active[0].category == "exposed_path"


def test_lybra_lifecycle_marks_fixed_when_cve_gone(app, admin_user):
    _seed_kb_apache_cve(app)

    # Scan 1 — vulnerable Apache 2.4.49.
    nmap1 = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        e1 = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap1)
        mgr._run_lybra(e1.id, nmap1)

    # Scan 2 — patched Apache 2.4.51 (no CVE match in the KB).
    patched = [dict(_PORTS[0], version="2.4.51", cpe="cpe:/a:apache:http_server:2.4.51"), _PORTS[1]]
    nmap2 = _seed_nmap_scan(app, admin_user.id, patched)
    with app.app_context():
        mgr = LybraEngineManager()
        e2 = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap2)
        mgr._run_lybra(e2.id, nmap2)
        with UnitOfWork() as uow:
            findings2 = ScanRepository(uow).get_findings_by_scan(e2.id)

    # The CVE that disappeared is recorded as fixed; the open ports persist as open.
    fixed = [f for f in findings2 if f.state == "fixed" and f.cve_ids == ["CVE-2021-41773"]]
    assert len(fixed) == 1
    assert any(f.category == "open_port" and f.state == "open" for f in findings2)


def _run_scan_and_get_cve_finding_id(app, user_id, nmap_id):
    mgr = LybraEngineManager()
    escan = mgr._create_scan_record(target="10.0.0.5", user_id=user_id, source_scan_id=nmap_id)
    mgr._run_lybra(escan.id, nmap_id)
    with UnitOfWork() as uow:
        findings = ScanRepository(uow).get_findings_by_scan(escan.id)
        return next(f.id for f in findings if f.cve_ids)


def test_accept_finding_via_endpoint(client, app, admin_user, auth_headers):
    _seed_kb_apache_cve(app)
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        finding_id = _run_scan_and_get_cve_finding_id(app, admin_user.id, nmap_id)

    resp = client.patch(f"/themis/findings/{finding_id}",
                       headers=auth_headers(admin_user), json={"state": "accepted"})
    assert resp.status_code == 200
    assert resp.get_json()["state"] == "accepted"


def test_accept_finding_requires_update_attribute(client, app, regular_user, auth_headers):
    # role_user lacks themis_update.
    resp = client.patch("/themis/findings/1", headers=auth_headers(regular_user),
                       json={"state": "accepted"})
    assert resp.status_code == 403


def test_accept_nonexistent_finding_is_404(client, admin_user, auth_headers):
    resp = client.patch("/themis/findings/999999",
                       headers=auth_headers(admin_user), json={"state": "accepted"})
    assert resp.status_code == 404


def test_lybra_fingerprinting_records_agreement_with_nmap(app, admin_user, monkeypatch):
    # Enable fingerprinting and stub the HTTP probe (no real network).
    import src.modules.system.config_reading as CR
    from src.modules.themis.lybra.checks import HttpProbe, Response

    monkeypatch.setattr(CR, "is_lybra_fingerprinting_enabled", lambda: True)

    def fake_fetch(self, host, port, method, path):
        return Response(200, "<html><title>It works</title></html>",
                        {"server": "Apache/2.4.49 (Unix)"})
    monkeypatch.setattr(HttpProbe, "fetch", fake_fetch)
    monkeypatch.setattr(HttpProbe, "fetch_bytes", lambda self, host, port, path: None)

    nmap_id = _seed_nmap_scan(app, admin_user.id)  # port 80 = Apache httpd 2.4.49 (matches)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, nmap_id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert fingerprints[0].qod == 20
    assert fingerprints[0].confirmed is False
    assert "concuerda con Nmap" in fingerprints[0].title
    assert "no concuerda" not in fingerprints[0].title


def test_lybra_fingerprinting_disabled_by_default(app, admin_user):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id)
        mgr._run_lybra(escan.id, nmap_id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert not any(f.category == "fingerprint" for f in findings)


def test_lybra_fingerprint_fills_cpe_gap_for_self_discovery(app, admin_user, monkeypatch):
    """The point of wiring fingerprint output into CPE resolution: a
    self-discovered service (Fase T, no Nmap involved at all) must still be
    able to match a CVE, using Lybra's own HTTP fingerprint instead of an
    Nmap-emitted CPE. Without this wiring the version matcher has nothing to
    look up and a self-discovery-only scan finds zero CVEs, ever.
    """
    import src.modules.system.config_reading as CR
    from src.modules.themis.lybra.checks import HttpProbe, Response

    _seed_kb_apache_cve(app)
    monkeypatch.setattr(CR, "is_lybra_fingerprinting_enabled", lambda: True)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])

    def fake_fetch(self, host, port, method, path):
        return Response(200, "<html><title>It works</title></html>",
                        {"server": "Apache/2.4.49 (Unix)"})
    monkeypatch.setattr(HttpProbe, "fetch", fake_fetch)
    monkeypatch.setattr(HttpProbe, "fetch_bytes", lambda self, host, port, path: None)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(escan.id, source_scan_id=None, discover_ports=None)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2021-41773"]
    assert vulns[0].qod == 70            # hypothesis-tier, same as an Nmap-sourced match
    assert vulns[0].confirmed is False
    # The fingerprint finding is honest about having no Nmap baseline, but the
    # CVE match went through regardless — that honesty and the detection are
    # independent of each other.
    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert "sin datos de Nmap para comparar" in fingerprints[0].title


def test_lybra_scan_surfaces_in_results_endpoint(client, app, admin_user, auth_headers):
    nmap_id = _seed_nmap_scan(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(
            target="10.0.0.5", user_id=admin_user.id, source_scan_id=nmap_id,
        )
        mgr._run_lybra(escan.id, nmap_id)

    resp = client.get("/themis/results?type=lybra&page=1&per_page=10",
                     headers=auth_headers(admin_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["totalCount"] == 1
    result = body["results"][0]
    assert result["scanType"] == "lybra"
    assert result["sourceScanId"] == nmap_id
    assert result["totalFindings"] == 2
