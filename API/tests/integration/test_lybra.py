"""Integration tests for the Lybra engine scan.

Covers the endpoint's authorization/validation boundary and the engine pipeline
end to end: el motor descubre los servicios por su cuenta (Fase T) o recibe una
lista ya resuelta (payload externo), persiste hallazgos y estos afloran por el
endpoint de resultados. El cuerpo del escaneo se ejecuta directo
(``_run_lybra``) en vez de por la cola de tareas, igual que en los tests de los
demás escáneres, para no depender de Redis ni de un worker.

Hasta L52 casi todos estos tests partían de un escaneo Nmap sembrado a mano: el
motor tenía un modo de arranque que analizaba los servicios que otro escáner ya
había descubierto. Ese modo se retiró junto al resto del acoplamiento con
herramientas de terceros, así que los servicios entran ahora por los dos
caminos que de verdad quedan.
"""

from datetime import datetime

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.model import Finding, ScanStatus
from src.modules.features.themis.repositories import ScanRepository, KbRepository
from src.modules.features.themis.managers import LybraEngineManager, ScanManager, AuthorizedTargetManager
from src.modules.features.themis.lybra import Service

pytestmark = pytest.mark.integration


def _network_services(apache_version: str = "2.4.49") -> list:
    """Los dos servicios de red del escenario base: Apache en el 80 y OpenSSH
    en el 22, con producto, versión y CPE ya resueltos.

    Es un *payload externo* (el modo que usa Hygeia): una lista de servicios
    que el llamante ya resolvió sin que el motor tenga que sondear la red. Antes
    el mismo escenario se montaba sembrando un escaneo Nmap y arrancando Lybra
    sobre él; ese modo ya no existe.
    """
    return [
        Service(port=80, protocol="tcp", name="http", product="Apache httpd",
                version=apache_version, cpe=f"cpe:/a:apache:http_server:{apache_version}"),
        Service(port=22, protocol="tcp", name="ssh", product="OpenSSH", version="7.4"),
    ]


def _stub_self_discovery(monkeypatch, tcp_ports: list, udp_ports: list | None = None) -> None:
    """Sustituye el descubrimiento de puertos y el chequeo de alcanzabilidad.

    Deja correr de verdad todo lo que viene después (fingerprinting, checks
    activos, correlación); lo único que no ocurre es el socket.
    """
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: list(tcp_ports))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports",
                        lambda self, target: list(udp_ports or []))


def _authorize_target(app, user_id: int, target: str = "10.0.0.5") -> None:
    """Add ``target`` to the user's authorized-targets register (roadmap §6).

    Required before Fase F (fingerprinting) or Fase R (active checks) will run
    against it — see ``AuthorizedTargetManager.is_authorized``.
    """
    with app.app_context():
        AuthorizedTargetManager().add(user_id, target)


# --------------------------------------------------------- endpoint boundary

def test_lybra_requires_authentication(client):
    assert client.post("/themis/lybra", json={"target": "203.0.113.9"}).status_code == 401


def test_lybra_requires_create_attribute(client, stripped_user, auth_headers):
    # Usuario al que le han retirado themis_create.
    resp = client.post("/themis/lybra", headers=auth_headers(stripped_user),
                       json={"target": "203.0.113.9"})
    assert resp.status_code == 403


def test_lybra_requires_a_target(client, admin_user, auth_headers):
    # Sin objetivo no hay escaneo: el schema lo rechaza. Antes de L52 valía
    # también un ``sourceScanId`` (un escaneo Nmap previo) en su lugar.
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user), json={})
    assert resp.status_code in (400, 422)


def test_lybra_no_longer_accepts_a_source_scan(client, app, admin_user, auth_headers):
    """L52: lanzar Lybra desde un escaneo de otra herramienta ya no es posible.

    El schema ya no declara ``sourceScanId``, así que mandarlo sin objetivo es
    una petición sin modo válido — se rechaza en la validación, no se ignora en
    silencio dejando que el escaneo salga con un objetivo vacío.
    """
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"sourceScanId": 1})
    assert resp.status_code in (400, 422)


def test_lybra_self_discovery_requires_authorized_target(client, admin_user, auth_headers):
    # Roadmap §6: self-discovery touches the target directly, so it must be
    # in the caller's authorized-targets register before launch is allowed.
    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"target": "203.0.113.9"})
    assert resp.status_code == 403


def test_lybra_run_scan_self_discovery_succeeds_once_authorized(app, admin_user, monkeypatch):
    """Lo que se comprueba aquí es el **registro de objetivos autorizados**, no
    la defensa anti-SSRF, así que el flag se fuerza a permitir IPs privadas.

    Hace falta porque ``203.0.113.9`` es de TEST-NET-3 (RFC 5737, el rango de
    documentación) y Python lo considera privado desde la 3.12: sin forzar el
    flag, el escaneo se rechaza por SSRF antes de llegar a la autorización, y el
    test dejaría de probar lo que dice. Peor aún, lo haría sólo en algunas
    versiones de Python — pasando en el CI (3.11) y fallando en un portátil con
    una más nueva.
    """
    from unittest import mock
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.managers import AuthorizedTargetManager
    from src.modules.features.themis.exceptions import TargetNotAuthorizedError

    monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=True))

    with app.app_context():
        with pytest.raises(TargetNotAuthorizedError):
            LybraEngineManager(task_queue=mock.Mock()).run_scan(
                user_id=admin_user.id, target="203.0.113.9",
            )

        AuthorizedTargetManager().add(admin_user.id, "203.0.113.9")

        scan_id = LybraEngineManager(task_queue=mock.Mock()).run_scan(
            user_id=admin_user.id, target="203.0.113.9",
        )
        assert scan_id is not None


def test_lybra_self_discovery_produces_open_port_findings(app, admin_user, monkeypatch):
    # Stub reachability (no real socket) and the connect scan; the rest of the
    # self-discovery pipeline runs for real.
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80, 22])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="8.8.8.8", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan.id)
            escan = repo.get_by_id(escan.id)

    assert escan.status == ScanStatus.FINISHED.value
    open_ports = [f for f in findings if f.category == "open_port"]
    assert {f.port for f in open_ports} == {80, 22}
    # Self-discovery creates a Host for the target, so findings are anchored.
    assert all(f.host_id is not None for f in findings)


def test_lybra_self_discovery_disambiguates_the_same_port_over_tcp_and_udp(app, admin_user, monkeypatch):
    """Ronda 1 (roadmap §6.3): 161/tcp y 161/udp del mismo host son dos
    servicios distintos y deben sobrevivir como dos hallazgos `open_port` con
    `dedup_key` distintas — el riesgo real que motivó la columna
    `Finding.protocol` y el arreglo de `compute_dedup_key`."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [161])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports",
                        lambda self, target: [161])

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="8.8.4.4", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    open_ports = [f for f in findings if f.category == "open_port" and f.port == 161]
    assert len(open_ports) == 2
    assert {f.protocol for f in open_ports} == {"tcp", "udp"}
    assert len({f.dedup_key for f in open_ports}) == 2
    assert {f.title for f in open_ports} == {
        "Puerto 161/tcp abierto — snmp",
        "Puerto 161/udp abierto — snmp",
    }


def test_lybra_self_discovery_unreachable_host_fails_without_false_fixed(app, admin_user, monkeypatch):
    """An unreachable host must never look like 'scanned clean, nothing open':
    that would mark every previously-open finding as falsely fixed."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: False))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.99", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

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
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert escan.status == ScanStatus.FAILED.value


def test_lybra_blocked_discovery_never_marks_findings_fixed(app, admin_user, monkeypatch):
    """L48-c, la mitad que de verdad duele.

    Un objetivo que bloquea el barrido a mitad de camino producía una lista
    vacía indistinguible de un host limpio, y el ciclo de vida pasaba entonces
    a ``fixed`` todo lo que el escaneo anterior había encontrado abierto: no
    sólo se ocultaba lo que hay, se le decía al usuario que sus
    vulnerabilidades estaban remediadas.

    El transporte ya distingue los dos casos (ver
    ``tests/unit/test_lybra_transport.py``); aquí se comprueba la consecuencia
    aguas abajo: con un descubrimiento bloqueado, el escaneo falla y ningún
    hallazgo previo cambia de estado.
    """
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80, 443])

    with app.app_context():
        mgr = LybraEngineManager()
        first = mgr._create_scan_record(target="10.0.0.31", user_id=admin_user.id)
        mgr._run_lybra(first.id)

    # Segundo escaneo: el objetivo bloquea el barrido — el transporte lo
    # reconoce y devuelve None en vez de una lista vacía.
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: None)
    with app.app_context():
        mgr = LybraEngineManager()
        second = mgr._create_scan_record(target="10.0.0.31", user_id=admin_user.id)
        mgr._run_lybra(second.id)
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            second_findings = repo.get_findings_by_scan(second.id)
            first_findings = repo.get_findings_by_scan(first.id)
            second = repo.get_by_id(second.id)

    assert second.status == ScanStatus.FAILED.value
    assert second_findings == []
    assert not any(finding.state == "fixed" for finding in first_findings)


def test_lybra_self_discovery_genuine_zero_ports_still_marks_fixed(app, admin_user, monkeypatch):
    """Discovery running cleanly and finding nothing IS legitimate evidence:
    a previously-open finding on this target should still be marked fixed."""
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()
        # First scan: port 80 open.
        e1 = mgr._create_scan_record(target="10.0.0.7", user_id=admin_user.id)
        mgr._run_lybra(e1.id)

    # Second scan: discovery ran cleanly and genuinely found nothing open.
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [])
    with app.app_context():
        mgr = LybraEngineManager()
        e2 = mgr._create_scan_record(target="10.0.0.7", user_id=admin_user.id)
        mgr._run_lybra(e2.id)
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
        escan = mgr._create_scan_record(target="10.0.0.42", user_id=admin_user.id)

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


# ------------------------------------------------- Fase 0.9: external payload

def test_lybra_run_scan_payload_mode_requires_target(app, admin_user):
    from unittest import mock

    with app.app_context():
        with pytest.raises(ValueError):
            LybraEngineManager(task_queue=mock.Mock()).run_scan(
                user_id=admin_user.id,
                services=[Service(port=None, protocol="", product="openssl", version="1.1.1")],
            )


def test_lybra_run_scan_payload_mode_does_not_require_authorization(app, admin_user):
    # Unlike self-discovery, launching a payload-mode scan never gates on the
    # authorized-targets register at launch: the mode does not by itself touch
    # the target's network (the register only matters later, and only for the
    # optional deep corroborators — see the test below).
    from unittest import mock

    with app.app_context():
        scan_id = LybraEngineManager(task_queue=mock.Mock()).run_scan(
            user_id=admin_user.id, target="10.9.9.9",
            services=[Service(port=None, protocol="", product="openssl",
                              version="1.1.1", origin="inventory")],
        )
        assert scan_id is not None


def test_lybra_payload_mode_produces_confirmed_inventory_findings(app, admin_user, monkeypatch):
    """End to end: a payload of origin="inventory" services, with no source Nmap
    scan and no network discovery, produces confirmed/high-qod CVE findings and
    never invokes fingerprinting or active checks."""
    _seed_kb_apache_cve(app)

    def _boom(*_a, **_k):
        raise AssertionError("payload mode must never fingerprint or actively check the target")
    monkeypatch.setattr(LybraEngineManager, "_fingerprint_services", _boom)
    monkeypatch.setattr(LybraEngineManager, "_run_active_checks", _boom)

    services = [
        Service(port=None, protocol="", name="", product="Apache httpd",
                version="2.4.49", cpe="cpe:/a:apache:http_server:2.4.49", origin="inventory"),
        Service(port=None, protocol="", name="", product="openssl",
                version="1.1.1", origin="inventory"),
    ]

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.9.9.9", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=services)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan.id)
            escan = repo.get_by_id(escan.id)

    assert escan.status == ScanStatus.FINISHED.value
    # Host resolved by IP identity, same helper self-discovery uses.
    assert all(f.host_id is not None for f in findings)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.cve_ids == ["CVE-2021-41773"]
    assert vuln.qod == 95
    assert vuln.confirmed is True

    packages = [f for f in findings if f.category == "installed_package"]
    assert any("openssl 1.1.1" in f.title for f in packages)
    assert all(f.port is None for f in packages)


def test_lybra_payload_mode_surface_tracking_distinguishes_portless_packages(app, admin_user):
    """Regression: two different installed packages both have port=None, so
    surface tracking cannot key on (port, protocol) alone for them (Fase 0.9)
    — it must fall back to product, or the second package's upsert would
    silently overwrite the first package's tracked row."""
    with app.app_context():
        mgr = LybraEngineManager()

        baseline_services = [
            Service(port=None, protocol="", product="openssl", version="1.1.1", origin="inventory"),
            Service(port=None, protocol="", product="curl", version="7.68.0", origin="inventory"),
        ]
        baseline = mgr._create_scan_record(target="10.9.9.20", user_id=admin_user.id)
        mgr._run_lybra(baseline.id, services_payload=baseline_services)

        with UnitOfWork() as uow:
            tracked = ScanRepository(uow).get_host_services(
                ScanRepository(uow).get_by_id(baseline.id).host_id
            )
        # Both packages kept their own row — no collision on (None, "tcp").
        assert {t.product for t in tracked} == {"openssl", "curl"}

        rescan_services = [
            Service(port=None, protocol="", product="openssl", version="1.1.1n", origin="inventory"),
            Service(port=None, protocol="", product="curl", version="7.68.0", origin="inventory"),
            Service(port=None, protocol="", product="sqlite", version="3.31.1", origin="inventory"),
        ]
        rescan = mgr._create_scan_record(target="10.9.9.20", user_id=admin_user.id)
        mgr._run_lybra(rescan.id, services_payload=rescan_services)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(rescan.id)

    surface = {f.title for f in findings if f.category == "surface_change"}
    assert len(surface) == 2
    assert any("openssl" in t and "1.1.1 -> openssl 1.1.1n" in t for t in surface)
    assert any(t == "Nuevo paquete instalado: sqlite 3.31.1" for t in surface)
    # curl was unchanged — must not appear as a spurious "version change".
    assert not any("curl" in t for t in surface)


# ------------------------------------------------------- engine end to end

def test_lybra_engine_persists_informational_findings(app, admin_user):

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        escan_id = escan.id
        mgr._run_lybra(escan_id, services_payload=_network_services())

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


def test_lybra_surface_change_detects_new_port_and_version_bump(app, admin_user):
    """Fase 5: a host's first Lybra scan sets a silent baseline; a later scan
    with an extra port and a bumped Apache version reports both as
    surface_change findings, without repeating on a third, unchanged scan."""

    with app.app_context():
        mgr = LybraEngineManager()

        baseline = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(baseline.id, services_payload=_network_services())
        with UnitOfWork() as uow:
            baseline_findings = ScanRepository(uow).get_findings_by_scan(baseline.id)
        assert not any(f.category == "surface_change" for f in baseline_findings)

        changed = _network_services(apache_version="2.4.51") + [
            Service(port=3306, protocol="tcp", name="mysql", product="MySQL", version="8.0"),
        ]

        rescan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(rescan.id, services_payload=changed)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(rescan.id)
        surface = {f.title for f in findings if f.category == "surface_change"}
        assert len(surface) == 2
        assert any("Nuevo puerto abierto: 3306" in t for t in surface)
        assert any("2.4.49 -> Apache httpd 2.4.51" in t for t in surface)

        # A third, unchanged scan of the same (now-updated) surface stays quiet.
        stable = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(stable.id, services_payload=changed)
        with UnitOfWork() as uow:
            stable_findings = ScanRepository(uow).get_findings_by_scan(stable.id)
        assert not any(f.category == "surface_change" for f in stable_findings)


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


def test_a_scan_stamps_findings_with_the_state_of_the_knowledge_base(app, admin_user):
    """#270: la marca de reproducibilidad sale del estado real de la KB.

    Era la constante ``"lybra-0"`` para todos los hallazgos por versión, así que
    un hallazgo guardado no podía decir contra qué conocimiento se resolvió.
    Aquí se siembra la KB con fechas conocidas en las tres fuentes y se
    comprueba que el escaneo las estampa.
    """
    from datetime import datetime

    _seed_kb_apache_cve(app)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_kev({"cve_id": "CVE-2021-41773", "known_ransomware": False,
                             "date_added": datetime(2026, 8, 27), "due_date": None})
            repo.upsert_epss({"cve_id": "CVE-2021-41773", "score": 0.97, "percentile": 0.99,
                              "scored_at": datetime(2026, 8, 30)})
            repo.upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N",
                 "severity": "HIGH", "description": "Path traversal", "cwe_ids": ["CWE-22"],
                 "source": "nvd", "last_modified": datetime(2026, 8, 29, 13, 19)},
                [{"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.feed_version == "lybra-kb:nvd=2026-08-29,kev=2026-08-27,epss=2026-08-30"
    # Y la marca cabe entera en la columna, sin recortes silenciosos.
    assert len(vuln.feed_version) <= Finding.__table__.c.feed_version.type.length


def _seed_kb_vsftpd_cve(app):
    """Seed the KB with CVE-2011-2523 (the vsftpd 2.3.4 backdoor)."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2011-2523", "cvss_score": 10.0,
                 "cvss_vector": "CVSS:2.0/AV:N", "severity": "CRITICAL",
                 "description": "vsftpd backdoor", "cwe_ids": ["CWE-78"], "source": "nvd"},
                [{"vendor": "vsftpd_project", "product": "vsftpd", "exact_version": "2.3.4",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )


def _seed_kb_mysql_cve(app):
    """Seed the KB with a made-up CVE for mysql 8.0.34, for the Fase N MySQL
    dissector's CPE-gap-filling test."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2023-99999", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
                 "description": "MySQL test CVE", "cwe_ids": ["CWE-284"], "source": "nvd"},
                [{"vendor": "mysql", "product": "mysql", "exact_version": "8.0.34",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )


def test_lybra_version_match_produces_cve_finding(app, admin_user):
    _seed_kb_apache_cve(app)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

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
    from src.modules.features.themis.lybra import checks as checks_mod
    from src.modules.features.themis.lybra.checks import Response

    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(active_checks=True))

    def fake_fetch(self, host, port, method, path):
        if path == "/.git/config":
            return Response(200, "[core]\n\trepositoryformatversion = 0\n", {})
        return Response(404, "", {})
    monkeypatch.setattr(checks_mod.HttpProbe, "fetch", fake_fetch)

    # Autodescubrimiento: los checks activos sólo corren en el modo que sí toca
    # la red. El puerto 80 se traduce a un servicio "http" por el catálogo de
    # puertos conocidos, que es lo que hace aplicable a este check.
    _stub_self_discovery(monkeypatch, [80])
    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    active = [f for f in findings if f.check_id == "lybra:git-config-exposure@1"]
    assert len(active) == 1
    assert active[0].qod == 99
    assert active[0].confirmed is True
    assert active[0].category == "exposed_path"


def test_lybra_active_check_ftp_anonymous_login_persists_confirmed_finding(app, admin_user, monkeypatch):
    """Fase N: the runtime's first ``type: "network"`` check, wired end to
    end through the real manager (not a bare ``CheckRuntime``).

    Lo que se sustituye es el **socket**, no la sesión: el ``NetworkSession``
    real hace su trabajo, saludo incluido. Un doble por encima de la sesión
    entrega respuestas que el transporte real no produce, y eso fue justo lo
    que ocultó el bug de #265 (ver la nota de ``tests/unit/test_lybra_checks.py``)."""
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.lybra import checks as checks_mod

    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(active_checks=True))

    class _FakeFtpSocket:
        """Un vsftpd de mentira: saluda al conectar y contesta a cada comando."""

        def __init__(self):
            self._buffer = b"220 (vsFTPd 2.3.4)\r\n"
            self._replies = [
                b"331 Please specify the password.\r\n",
                b"230 Login successful.\r\n",
            ]

        def recv(self, size):
            chunk, self._buffer = self._buffer[:size], self._buffer[size:]
            return chunk

        def sendall(self, data):
            if self._replies:
                self._buffer += self._replies.pop(0)

        def close(self):
            pass

    monkeypatch.setattr(
        checks_mod.NetworkProbe, "open",
        lambda self, host, port: checks_mod.NetworkSession(_FakeFtpSocket()),
    )

    _stub_self_discovery(monkeypatch, [21])
    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    active = [f for f in findings if f.check_id == "lybra:ftp-anonymous-login@2"]
    assert len(active) == 1
    assert active[0].qod == 99
    assert active[0].confirmed is True
    assert active[0].category == "default_credentials"
    assert active[0].port == 21


def test_lybra_lifecycle_marks_fixed_when_cve_gone(app, admin_user):
    _seed_kb_apache_cve(app)

    # Scan 1 — vulnerable Apache 2.4.49.
    with app.app_context():
        mgr = LybraEngineManager()
        e1 = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(e1.id, services_payload=_network_services())

    # Scan 2 — patched Apache 2.4.51 (no CVE match in the KB).
    with app.app_context():
        mgr = LybraEngineManager()
        e2 = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(e2.id, services_payload=_network_services(apache_version="2.4.51"))
        with UnitOfWork() as uow:
            findings2 = ScanRepository(uow).get_findings_by_scan(e2.id)

    # The CVE that disappeared is recorded as fixed; the open ports persist as open.
    fixed = [f for f in findings2 if f.state == "fixed" and f.cve_ids == ["CVE-2021-41773"]]
    assert len(fixed) == 1
    assert any(f.category == "open_port" and f.state == "open" for f in findings2)


def _run_scan_and_get_cve_finding_id(app, user_id):
    mgr = LybraEngineManager()
    escan = mgr._create_scan_record(target="10.0.0.5", user_id=user_id)
    mgr._run_lybra(escan.id, services_payload=_network_services())
    with UnitOfWork() as uow:
        findings = ScanRepository(uow).get_findings_by_scan(escan.id)
        return next(f.id for f in findings if f.cve_ids)


def test_accept_finding_via_endpoint(client, app, admin_user, auth_headers):
    _seed_kb_apache_cve(app)
    with app.app_context():
        finding_id = _run_scan_and_get_cve_finding_id(app, admin_user.id)

    resp = client.patch(f"/themis/findings/{finding_id}",
                       headers=auth_headers(admin_user), json={"state": "accepted"})
    assert resp.status_code == 200
    assert resp.get_json()["state"] == "accepted"


def test_accept_finding_requires_update_attribute(client, app, stripped_user, auth_headers):
    # Usuario al que le han retirado themis_update.
    resp = client.patch("/themis/findings/1", headers=auth_headers(stripped_user),
                       json={"state": "accepted"})
    assert resp.status_code == 403


def test_accept_nonexistent_finding_is_404(client, admin_user, auth_headers):
    resp = client.patch("/themis/findings/999999",
                       headers=auth_headers(admin_user), json={"state": "accepted"})
    assert resp.status_code == 404


def test_lybra_fingerprinting_identifies_the_service_on_its_own(app, admin_user, monkeypatch):
    """L52: el hallazgo de fingerprint constata qué identificó Lybra.

    Antes comparaba con el producto/versión que traía el servicio desde Nmap y
    titulaba el hallazgo con el veredicto («concuerda / no concuerda con
    Nmap»). Retirado ese modo de arranque, la lectura propia no está
    subordinada a nada y el hallazgo dice lo que el motor vio y con qué
    dissector.
    """
    # Enable fingerprinting and stub the HTTP probe (no real network).
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.lybra.checks import HttpProbe, Response

    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))

    def fake_fetch(self, host, port, method, path):
        return Response(200, "<html><title>It works</title></html>",
                        {"server": "Apache/2.4.49 (Unix)"})
    monkeypatch.setattr(HttpProbe, "fetch", fake_fetch)
    monkeypatch.setattr(HttpProbe, "fetch_bytes", lambda self, host, port, path: None)

    _stub_self_discovery(monkeypatch, [80])
    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert fingerprints[0].qod == 20
    assert fingerprints[0].confirmed is False
    assert fingerprints[0].title == "Fingerprint propio (HTTP): Apache 2.4.49"
    assert "Nmap" not in fingerprints[0].title


def test_lybra_fingerprinting_skipped_for_unauthorized_target(app, admin_user, monkeypatch):
    # activeChecks/fingerprintingEnabled default to True (roadmap §6): the real
    # gate is per-target authorization, not the config flag. No _authorize_target
    # call here on purpose.
    _stub_self_discovery(monkeypatch, [80])
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert not any(f.category == "fingerprint" for f in findings)


def test_lybra_fingerprinting_config_flag_still_disables_even_if_authorized(app, admin_user, monkeypatch):
    # The config flag is the operator-level kill switch: even an authorized
    # target must not fingerprint if it's turned off deployment-wide.
    import src.modules.system.config_reading as CR
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=False))

    _stub_self_discovery(monkeypatch, [80])
    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert not any(f.category == "fingerprint" for f in findings)


def test_lybra_fingerprint_fills_cpe_gap_for_self_discovery(app, admin_user, monkeypatch):
    """El sentido de enchufar el fingerprint a la resolución de CPE: un
    servicio descubierto por el propio motor (Fase T) tiene que poder casar con
    un CVE a partir de su propia lectura HTTP. Sin ese cableado el matcher de
    versiones no tiene nada que buscar y un escaneo nunca encuentra un CVE.
    """
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.lybra.checks import HttpProbe, Response

    _seed_kb_apache_cve(app)
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports: [80])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    def fake_fetch(self, host, port, method, path):
        return Response(200, "<html><title>It works</title></html>",
                        {"server": "Apache/2.4.49 (Unix)"})
    monkeypatch.setattr(HttpProbe, "fetch", fake_fetch)
    monkeypatch.setattr(HttpProbe, "fetch_bytes", lambda self, host, port, path: None)
    _authorize_target(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2021-41773"]
    assert vulns[0].qod == 70            # tier de hipótesis: la lectura es propia, no confirmada
    assert vulns[0].confirmed is False
    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert fingerprints[0].title == "Fingerprint propio (HTTP): Apache 2.4.49"


def test_lybra_ftp_fingerprint_fills_cpe_gap_for_self_discovery(app, admin_user, monkeypatch):
    """Fase N: FTP se suma a HTTP/SSH como dissector que resuelve el CPE de un
    servicio descubierto por el propio motor (Fase T)."""
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.lybra import FtpProbe

    _seed_kb_vsftpd_cve(app)
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports", lambda self, target, ports: [21])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])
    monkeypatch.setattr(FtpProbe, "fetch", lambda self, host, port: "220 (vsFTPd 2.3.4)")
    _authorize_target(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2011-2523"]
    assert vulns[0].qod == 70
    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert "vsFTPd 2.3.4" in fingerprints[0].title


def test_lybra_mysql_fingerprint_fills_cpe_gap_for_self_discovery(app, admin_user, monkeypatch):
    """Fase N's dissector registry, exercised end to end through the manager:
    MySQL identification flows through _fingerprint_services exactly like
    HTTP/SSH/FTP do, with no special-casing anywhere above the registry."""
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.lybra import MysqlProbe

    _seed_kb_mysql_cve(app)
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports", lambda self, target, ports: [3306])
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])
    monkeypatch.setattr(
        MysqlProbe, "fetch",
        lambda self, host, port: bytes([0x0A]) + b"8.0.34\x00" + b"\x00" * 13,
    )
    _authorize_target(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert len(vulns) == 1
    assert vulns[0].cve_ids == ["CVE-2023-99999"]
    assert vulns[0].qod == 70
    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert "MySQL 8.0.34" in fingerprints[0].title


def test_lybra_scan_surfaces_in_results_endpoint(client, app, admin_user, auth_headers):
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

    resp = client.get("/themis/results?type=lybra&page=1&per_page=10",
                     headers=auth_headers(admin_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["totalCount"] == 1
    result = body["results"][0]
    assert result["scanType"] == "lybra"
    assert result["totalFindings"] == 2
    # L52: la respuesta ya no lleva ``sourceScanId`` ni ``deep``/``deepScanIds``.
    assert "sourceScanId" not in result
    assert "deep" not in result
