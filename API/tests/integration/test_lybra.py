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
from src.modules.features.themis.lybra import PortSweep, Service

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


def _sweep(open_ports, truncated: bool = False) -> PortSweep:
    """El barrido que devuelve un `_discover_ports` sustituido en un test.

    La costura devuelve el :class:`PortSweep` entero y no una lista porque los
    desenlaces son tres —limpio, bloqueado y truncado— y sólo el objeto
    completo los distingue. Este ayudante deja los dobles en una línea.
    """
    return PortSweep(open_ports=tuple(open_ports), refused_ports=(),
                     timed_out_ports=(), unreachable_ports=(),
                     was_truncated=truncated)


def _stub_self_discovery(monkeypatch, tcp_ports: list, udp_ports: list | None = None) -> None:
    """Sustituye el descubrimiento de puertos y el chequeo de alcanzabilidad.

    Deja correr de verdad todo lo que viene después (fingerprinting, checks
    activos, correlación); lo único que no ocurre es el socket.
    """
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: _sweep(tcp_ports))
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


def test_lybra_endpoint_threads_the_aggressive_flag_to_run_scan(
        client, admin_user, auth_headers, monkeypatch):
    """El schema declara ``aggressive`` con ``load_default=False`` (L40): sin
    el campo, una petición de siempre no cambia de comportamiento, y con él,
    el valor llega íntegro al manager — la mitad de la doble puerta que
    depende del usuario."""
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 1

    monkeypatch.setattr(LybraEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"target": "8.8.8.8", "aggressive": True})
    assert resp.status_code == 201
    assert captured["aggressive"] is True


def test_lybra_endpoint_defaults_to_non_aggressive(client, admin_user, auth_headers, monkeypatch):
    captured = {}

    def fake_run_scan(self, **kwargs):
        captured.update(kwargs)
        return 1

    monkeypatch.setattr(LybraEngineManager, "run_scan", fake_run_scan)

    resp = client.post("/themis/lybra", headers=auth_headers(admin_user),
                       json={"target": "8.8.8.8"})
    assert resp.status_code == 201
    assert captured["aggressive"] is False


def test_lybra_self_discovery_produces_open_port_findings(app, admin_user, monkeypatch):
    # Stub reachability (no real socket) and the connect scan; the rest of the
    # self-discovery pipeline runs for real.
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: _sweep([80, 22]))
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
                        lambda self, target, ports, **_kwargs: _sweep([161]))
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
                        lambda self, target, ports, **_kwargs: None)

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
                        lambda self, target, ports, **_kwargs: _sweep([80, 443]))

    with app.app_context():
        mgr = LybraEngineManager()
        first = mgr._create_scan_record(target="10.0.0.31", user_id=admin_user.id)
        mgr._run_lybra(first.id)

    # Segundo escaneo: el objetivo bloquea el barrido — el transporte lo
    # reconoce y devuelve None en vez de una lista vacía.
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: None)
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
                        lambda self, target, ports, **_kwargs: _sweep([80]))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()
        # First scan: port 80 open.
        e1 = mgr._create_scan_record(target="10.0.0.7", user_id=admin_user.id)
        mgr._run_lybra(e1.id)

    # Second scan: discovery ran cleanly and genuinely found nothing open.
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: _sweep([]))
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


class _FrozenClock:
    """Un reloj que sólo avanza cuando el test lo dice.

    ``_run_lybra`` mide su plazo con ``time.monotonic``; sustituir el módulo
    entero dentro del motor —y no el ``time`` global— deja intacto el reloj que
    usan SQLAlchemy, Redis y todo lo demás mientras corre el test.
    """

    def __init__(self, start: float = 1000.0):
        self.now = start

    def monotonic(self) -> float:
        return self.now


def test_a_scan_that_runs_out_of_clock_stops_probing_and_finishes_partial(app, admin_user, monkeypatch):
    """El plazo del panel acota el escaneo entero, no sólo su primera fase.

    El descubrimiento de puertos tenía presupuesto de reloj desde #395, pero las
    fases siguientes no tenían ninguno: un «plazo por operación» limita lo que
    tarda cada sonda, no cuántas sondas se hacen, y cuántas se hacen lo decide
    cuántos puertos abiertos tenga el objetivo. Con un rango ancho el
    fingerprinting corría durante horas y su único límite acababa siendo la
    sentencia de muerte de la cola, que mataba el escaneo dejando su fila en
    `running` para siempre (el incidente del 2026-09-05).

    Aquí el descubrimiento se come el plazo entero. Lo que se comprueba es que
    el fingerprinting ni siquiera empieza, y que el escaneo **termina bien**
    marcado como parcial — que es lo que impide, además, que cierre por
    omisión hallazgos que esta vez no llegó a comprobar (L48-c).
    """
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.managers.lybra import engine as engine_module

    clock = _FrozenClock()
    monkeypatch.setattr(engine_module, "time", clock)
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))

    def clock_eating_discovery(self, target, ports, **_kwargs):
        clock.now += 999  # el plazo eran 60 segundos
        return _sweep([80], truncated=True)

    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports", clock_eating_discovery)
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    def _boom(*args, **kwargs):
        raise AssertionError("un escaneo sin reloj no debe empezar a hacer fingerprinting")
    monkeypatch.setattr(LybraEngineManager, "_fingerprint_services", _boom)
    monkeypatch.setattr(LybraEngineManager, "_run_active_checks", _boom)

    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, discover_ports=[80], timeout=60)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)
            assert escan.status == ScanStatus.FINISHED.value
            assert escan.is_partial is True


def test_a_scan_with_clock_to_spare_still_fingerprints(app, admin_user, monkeypatch):
    """La otra mitad del contrato: el corte lo dispara el reloj agotado, no el
    mero hecho de haber pedido un plazo. Sin esto, la parada podría estar
    siempre activa y el test de arriba pasaría por el motivo equivocado."""
    import src.modules.system.config_reading as CR
    from src.modules.features.themis.managers.lybra import engine as engine_module

    monkeypatch.setattr(engine_module, "time", _FrozenClock())
    monkeypatch.setattr(CR, "lybra_config", lambda: CR.LybraConfig(fingerprinting_enabled=True))

    fingerprinted = []
    monkeypatch.setattr(
        LybraEngineManager, "_fingerprint_services",
        lambda self, target, services, cancel_check=None: (fingerprinted.append(target), (services, []))[1],
    )

    _stub_self_discovery(monkeypatch, [80])
    _authorize_target(app, admin_user.id)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, discover_ports=[80], timeout=60)

        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)
            assert escan.status == ScanStatus.FINISHED.value
            assert escan.is_partial is False

    assert fingerprinted == ["10.0.0.5"]


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
    # L18: el qod refleja de dónde salió la versión. Una cabecera `Server` con
    # versión explícita es la fuente más fuerte de la cascada.
    assert fingerprints[0].qod == 90
    assert fingerprints[0].confirmed is False
    assert fingerprints[0].title == "Fingerprint propio (HTTP): Apache 2.4.49"
    assert "Nmap" not in fingerprints[0].title


def test_lybra_identifies_a_service_on_a_non_canonical_port(app, admin_user, monkeypatch):
    """L10: el punto ciego que multiplicaba a todos los demás.

    Los predicados de aplicabilidad deciden por nombre o por número de puerto,
    y en el autodescubrimiento el nombre sale a su vez de una tabla de puertos.
    Un SSH en el 2222 no recibía dissector, así que producía un `open_port` con
    `qod=30` y nada más: sin producto no hay CPE, y sin CPE no hay ni un CVE.

    Aquí el motor no sabe qué hay en el 2222 — pero lo pregunta, y el servicio
    se lo dice.
    """
    from src.modules.features.themis.lybra.fingerprinting import cascade

    class _GreetingSocket:
        def settimeout(self, _timeout):
            pass

        def recv(self, _size):
            return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

        def close(self):
            pass

    monkeypatch.setattr(cascade, "socket",
                        type("_S", (), {"create_connection": staticmethod(
                            lambda address, timeout: _GreetingSocket())}))

    _stub_self_discovery(monkeypatch, [2222])
    _authorize_target(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1
    assert fingerprints[0].title == "Fingerprint propio (SSH): OpenSSH 8.9p1"


def test_lybra_leaves_a_mute_unknown_port_exactly_as_it_was(app, admin_user, monkeypatch):
    """La otra mitad: un puerto que acepta la conexión y no contesta a nada
    sigue siendo un `open_port` informativo. La cascada añade identificaciones,
    no las inventa."""
    from src.modules.features.themis.lybra.fingerprinting import cascade

    def _refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    monkeypatch.setattr(cascade, "socket",
                        type("_S", (), {"create_connection": staticmethod(_refuse)}))

    _stub_self_discovery(monkeypatch, [45678])
    _authorize_target(app, admin_user.id)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert [f.category for f in findings] == ["open_port"]


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
                        lambda self, target, ports, **_kwargs: _sweep([80]))
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
    monkeypatch.setattr(LybraEngineManager, "_discover_ports", lambda self, target, ports, **_kwargs: _sweep([21]))
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
    monkeypatch.setattr(LybraEngineManager, "_discover_ports", lambda self, target, ports, **_kwargs: _sweep([3306]))
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


# ───────────────────────────── hallazgos agrupados por unidad remediable
#
# El listado devolvía todos los hallazgos de todos los escaneos de la página, y
# la interfaz los pintaba como una lista plana ordenada por prioridad. Pero un
# host con dos productos desactualizados no da 150 trabajos: da dos —subir dos
# productos— más las cosas de configuración que no pertenecen a ningún producto
# y se arreglan de otra manera.


def _seed_kb_apache_cve_with_a_fix(app):
    """Como ``_seed_kb_apache_cve`` pero con la cota "corregido en" que la NVD
    declara: es lo que permite recomendar una versión de destino concreta."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
                 "description": "Path traversal", "cwe_ids": ["CWE-22"], "source": "nvd"},
                [{"vendor": "apache", "product": "http_server", "exact_version": None,
                  "version_start_including": "2.4.0", "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": "2.4.51"}],
            )


def _run_payload_scan(app, user_id: int, target: str = "10.9.9.9") -> int:
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target=target, user_id=user_id)
        mgr._run_lybra(escan.id, services_payload=_network_services())
        return escan.id


def test_grouped_findings_require_authentication(client):
    assert client.get("/themis/lybra/scans/1/findings").status_code == 401


def test_grouped_findings_of_another_users_scan_are_not_found(
        client, app, admin_user, regular_user, auth_headers):
    """La propiedad se verifica sobre el escaneo, y un escaneo ajeno se reporta
    como inexistente en vez de como prohibido: responder 403 confirmaría que
    ese id existe."""
    scan_id = _run_payload_scan(app, admin_user.id)
    resp = client.get(f"/themis/lybra/scans/{scan_id}/findings",
                      headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_findings_of_one_product_arrive_as_a_single_group(client, app, admin_user, auth_headers):
    _seed_kb_apache_cve_with_a_fix(app)
    scan_id = _run_payload_scan(app, admin_user.id)

    resp = client.get(f"/themis/lybra/scans/{scan_id}/findings", headers=auth_headers(admin_user))
    assert resp.status_code == 200
    body = resp.get_json()

    # Ningún hallazgo se pierde por el camino: agrupar es reordenar, no filtrar.
    assert body["totalFindings"] == sum(g["totalFindings"] for g in body["groups"])
    assert body["totalFindings"] > 0

    apache = next(g for g in body["groups"] if "http server" in g["label"])
    assert apache["isProduct"] is True
    assert apache["port"] == 80
    assert "CVE-2021-41773" in apache["cveIds"]
    assert len(apache["findings"]) == apache["totalFindings"]

    # La versión de destino, que hasta ahora sólo veía el PDF.
    assert apache["fixedVersion"] == "2.4.51"


def test_groups_come_ordered_by_severity_and_carry_their_worst_priority(
        client, app, admin_user, auth_headers):
    """Un grupo se atiende por su peor hallazgo, no por su media: doce avisos
    informativos junto a un CRITICAL siguen siendo un CRITICAL."""
    _seed_kb_apache_cve_with_a_fix(app)
    scan_id = _run_payload_scan(app, admin_user.id)

    body = client.get(f"/themis/lybra/scans/{scan_id}/findings",
                      headers=auth_headers(admin_user)).get_json()
    groups = body["groups"]

    scores = [g["maxCvss"] or 0 for g in groups]
    assert scores == sorted(scores, reverse=True)

    ladder = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for group in groups:
        present = [level for level in group["byPriority"] if group["byPriority"][level]]
        assert group["priority"] == max(present, key=ladder.index)


def test_the_open_port_findings_form_their_own_non_product_group(
        client, app, admin_user, auth_headers):
    """Lo que no tiene producto no se cuela en el inventario de productos: se
    remedia de otra manera y se presenta aparte."""
    scan_id = _run_payload_scan(app, admin_user.id)

    body = client.get(f"/themis/lybra/scans/{scan_id}/findings",
                      headers=auth_headers(admin_user)).get_json()

    non_products = [g for g in body["groups"] if not g["isProduct"]]
    assert non_products, "todo acabó en grupos de producto"
    for group in non_products:
        assert group["fixedVersion"] is None   # no hay versión que recomendar
        assert "(" in group["label"]           # "categoría (servicio)"


def test_the_listing_ships_counters_instead_of_every_finding(
        client, app, admin_user, auth_headers):
    """Una página de diez escaneos con 150 hallazgos cada uno eran 1.500 objetos
    por respuesta, y la interfaz no usaba ninguno hasta desplegar una tarjeta.

    Lo que sí necesita la cabecera colapsada —el desglose por prioridad y el
    aviso de cobertura de inventario— lo derivaba en el cliente recorriendo esa
    misma lista, que era justo la razón de tener que mandarla. Ahora llega
    hecho, y el detalle se pide aparte.
    """
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.7")

    result = client.get("/themis/results?type=lybra&page=1&per_page=10",
                        headers=auth_headers(admin_user)).get_json()["results"][0]

    assert "findings" not in result
    assert result["totalFindings"] > 0
    assert sum(result["byPriority"].values()) == result["totalFindings"]
    assert "installedPackages" in result
    assert "unresolvedPackages" in result

    # El detalle sigue completo por su propia ruta.
    detail = client.get(f"/themis/lybra/scans/{scan_id}/findings",
                        headers=auth_headers(admin_user)).get_json()
    assert detail["totalFindings"] == result["totalFindings"]


# ───────────────────────── descubrimiento parcial (presupuesto agotado)
#
# Un barrido que se queda sin reloj encuentra puertos ciertos y deja otros sin
# mirar. La primera versión de esto hacía fallar el escaneo entero, para no
# arriesgarse a que el ciclo de vida cerrara hallazgos que esta vez no se
# comprobaron. Era tirar información verificada para protegerse de una
# inferencia que se puede desactivar: ahora el escaneo termina, se marca
# incompleto, y no cierra nada.


def test_a_truncated_discovery_reports_what_it_found(monkeypatch, app, admin_user):
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: _sweep([80, 443], truncated=True))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            escan = repo.get_by_id(escan.id)
            findings = repo.get_findings_by_scan(escan.id)

    # Termina, no falla: los dos puertos son un hecho verificado.
    assert escan.status == ScanStatus.FINISHED.value
    assert escan.is_partial is True
    open_ports = sorted(f.port for f in findings if f.category == "open_port")
    assert open_ports == [80, 443]


def test_a_truncated_discovery_does_not_mark_anything_fixed(monkeypatch, app, admin_user):
    """El motivo de existir de la marca.

    Primer escaneo completo: 80 y 22 abiertos. Segundo escaneo truncado: sólo
    da tiempo a ver el 80. El 22 no ha desaparecido — no se ha mirado. Cerrarlo
    sería decirle al usuario que se arregló solo.
    """
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()

        monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                            lambda self, target, ports, **_kwargs: _sweep([80, 22]))
        first = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(first.id)

        monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                            lambda self, target, ports, **_kwargs: _sweep([80], truncated=True))
        second = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(second.id)

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(second.id)

    assert [f.state for f in findings if f.state == "fixed"] == []
    assert 22 not in [f.port for f in findings]   # no se inventa lo que no vio


def test_a_complete_scan_still_closes_what_disappeared(monkeypatch, app, admin_user):
    """La contraprueba: sin truncar, el cierre por ausencia sigue funcionando.
    Si no, la defensa habría desactivado el ciclo de vida entero."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])

    with app.app_context():
        mgr = LybraEngineManager()

        monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                            lambda self, target, ports, **_kwargs: _sweep([80, 22]))
        first = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(first.id)

        monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                            lambda self, target, ports, **_kwargs: _sweep([80]))
        second = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(second.id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(second.id)
            second_row = repo.get_by_id(second.id)

    assert second_row.is_partial is False
    fixed = [f for f in findings if f.state == "fixed"]
    assert [f.port for f in fixed] == [22]


def test_a_blocked_discovery_still_fails_the_scan(monkeypatch, app, admin_user):
    """Truncado y bloqueado siguen siendo cosas distintas. Un barrido en el que
    *nada* contestó no aporta ni un puerto cierto, así que no hay resultado
    parcial que reportar: eso sigue siendo un fallo."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: None)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            escan = ScanRepository(uow).get_by_id(escan.id)

    assert escan.status == ScanStatus.FAILED.value


def test_the_partial_flag_reaches_the_api(client, monkeypatch, app, admin_user, auth_headers):
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    monkeypatch.setattr(LybraEngineManager, "_discover_udp_ports", lambda self, target: [])
    monkeypatch.setattr(LybraEngineManager, "_discover_ports",
                        lambda self, target, ports, **_kwargs: _sweep([80], truncated=True))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

    result = client.get("/themis/results?type=lybra&page=1&per_page=10",
                        headers=auth_headers(admin_user)).get_json()["results"][0]
    assert result["isPartial"] is True


# ============================================ progreso y cancelación (L41)


def test_a_scan_reports_progress_by_phase(monkeypatch, app, admin_user):
    """El escaneo publica progreso por fase con pesos honestos: descubrimiento
    40, fingerprint 70, checks 90, persistencia 100 (§3 del issue)."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])

    reported = []

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, progress=reported.append)

    # Monótono, empieza por debajo de 100 y llega a 100.
    assert reported == sorted(reported)
    assert reported[-1] == 100
    assert 40 in reported


def test_a_cancelled_scan_stops_persists_and_is_marked_partial(monkeypatch, app, admin_user):
    """Cancelado tras el descubrimiento: no corre fingerprint ni checks, pero
    persiste lo hallado y queda marcado como parcial — nunca tira lo verificado."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80, 443])

    fingerprinted = []
    original_fp = LybraEngineManager._fingerprint_services
    monkeypatch.setattr(
        LybraEngineManager, "_fingerprint_services",
        lambda self, target, services, **kw: (fingerprinted.append(True)
                                              or original_fp(self, target, services, **kw)))

    # Cancelado desde el primer chequeo: el descubrimiento ya devolvió, pero
    # fingerprint y checks no deben arrancar.
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, cancel_check=lambda: True)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            escan = repo.get_by_id(escan.id)
            findings = repo.get_findings_by_scan(escan.id)

    assert escan.status == ScanStatus.FINISHED.value
    assert escan.is_partial is True
    assert fingerprinted == []          # no se llegó a fingerprintear
    # Lo descubierto se persiste: los puertos son un hecho verificado.
    assert sorted(f.port for f in findings if f.category == "open_port") == [80, 443]


def test_a_cancelled_scan_does_not_close_findings_by_omission(monkeypatch, app, admin_user):
    """La interacción crítica con el ciclo de vida: un escaneo cancelado a mitad
    no vio todo el objetivo, así que la ausencia de un hallazgo anterior no es
    evidencia de que se haya corregido (el fallo de L48-c por otra puerta)."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))

    # Primer escaneo completo: 80 y 443 abiertos.
    _stub_self_discovery(monkeypatch, [80, 443])
    with app.app_context():
        mgr = LybraEngineManager()
        first = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id)
        mgr._run_lybra(first.id)

    # Segundo escaneo cancelado a mitad: sólo llega a ver el 80.
    _stub_self_discovery(monkeypatch, [80])
    with app.app_context():
        mgr = LybraEngineManager()
        second = mgr._create_scan_record(target="10.0.0.9", user_id=admin_user.id)
        mgr._run_lybra(second.id, cancel_check=lambda: True)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(second.id)

    # El 443, que no se llegó a recorrer, no se cierra como corregido.
    fixed = [f for f in findings if f.state == "fixed"]
    assert fixed == []


# ================================================= evidencia cruda (L44)


def test_a_confirmed_http_finding_stores_its_redacted_evidence(monkeypatch, app, admin_user):
    """Un hallazgo http confirmado guarda la respuesta que lo provocó, con las
    cabeceras sensibles redactadas y su hash."""
    from src.modules.features.themis.lybra.checks import Response
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    # El objetivo expone /.git/config y manda una cookie de sesión.
    monkeypatch.setattr(
        "src.modules.features.themis.lybra.checks.HttpProbe.fetch",
        lambda self, host, port, method, path:
            Response(200, "[core]\n\trepositoryformatversion = 0\n",
                     {"Server": "nginx", "Set-Cookie": "PHPSESSID=secret; HttpOnly"})
            if path == "/.git/config" else Response(404, "", {}))
    # Sin fingerprint ni TLS que enturbien.
    monkeypatch.setattr(LybraEngineManager, "_fingerprint_services",
                        lambda self, target, services, **kw: (services, []))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            findings = repo.get_findings_by_scan(escan.id)
            git = next(f for f in findings if f.check_id == "lybra:git-config-exposure@1")
            evidence = repo.get_evidence_for_finding(git.id)

    assert len(evidence) == 1
    row = evidence[0]
    assert row.kind == "http_response"
    assert row.payload["status"] == 200
    assert "[core]" in row.payload["body"]
    # El secreto no está: la cookie se redactó antes de persistir.
    assert row.payload["headers"]["Set-Cookie"] == "[redacted]"
    assert row.payload["headers"]["Server"] == "nginx"
    assert len(row.content_hash) == 64


def test_the_evidence_endpoint_returns_own_findings_and_404s_for_others(
        client, monkeypatch, app, admin_user, regular_user, auth_headers):
    from src.modules.features.themis.lybra.checks import Response
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    monkeypatch.setattr(
        "src.modules.features.themis.lybra.checks.HttpProbe.fetch",
        lambda self, host, port, method, path:
            Response(200, "[core]\n\trepositoryformatversion = 0\n", {"Server": "nginx"})
            if path == "/.git/config" else Response(404, "", {}))
    monkeypatch.setattr(LybraEngineManager, "_fingerprint_services",
                        lambda self, target, services, **kw: (services, []))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            git = next(f for f in repo.get_findings_by_scan(escan.id)
                       if f.check_id == "lybra:git-config-exposure@1")
            finding_id = git.id

    # El dueño ve su evidencia.
    ok = client.get(f"/themis/findings/{finding_id}/evidence",
                    headers=auth_headers(admin_user))
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["evidence"][0]["kind"] == "http_response"
    assert body["evidence"][0]["contentHash"]

    # Otro usuario recibe 404 (mismo criterio de propiedad que set_finding_state).
    forbidden = client.get(f"/themis/findings/{finding_id}/evidence",
                           headers=auth_headers(regular_user))
    assert forbidden.status_code == 404


# =============================================== confirmadores (L29)


def test_a_confirmer_promotes_a_hypothesis_end_to_end(monkeypatch, app, admin_user):
    """El encadenamiento versión→confirmador en el flujo real: el motor propone
    una CVE por versión (hipótesis) y el confirmador la asciende a hecho, dando
    un único hallazgo confirmado en vez de dos sueltos."""
    from src.modules.features.themis.lybra.checks import Response
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    # Fingerprint: el servicio es un Apache 2.4.49 (identificado).
    monkeypatch.setattr(
        LybraEngineManager, "_fingerprint_services",
        lambda self, target, services, **kw: (
            [Service(s.port, s.protocol, s.name, "apache", "2.4.49", None)
             for s in services], []))
    # El motor propone CVE-2021-41773 como hipótesis (confirmed=false, qod=70).
    cve = "CVE-2021-41773"
    monkeypatch.setattr(
        "src.modules.features.themis.lybra.engine.LybraEngine.analyze",
        lambda self, services: [
            {"host_id": None, "port": 80, "service": "http", "protocol": "tcp",
             "cve_ids": [cve], "confirmed": False, "qod": 70, "source": "lybra",
             "check_id": "lybra:outdated@1", "category": "outdated_software",
             "title": "Apache 2.4.49 con CVE conocida", "state": "open"}])
    # El objetivo es de verdad vulnerable: sirve /etc/passwd por la ruta.
    traversal = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    monkeypatch.setattr(
        "src.modules.features.themis.lybra.checks.HttpProbe.fetch",
        lambda self, host, port, method, path:
            Response(200, "root:x:0:0:root:/root:/bin/bash\n", {})
            if path == traversal else Response(404, "", {}))

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    # Un solo hallazgo para esa CVE, ascendido a confirmado con qod 99.
    for_cve = [f for f in findings if f.cve_ids and cve in f.cve_ids]
    assert len(for_cve) == 1
    assert for_cve[0].confirmed is True
    assert for_cve[0].qod == 99


# =============================================== modo agresivo + credenciales (L40/L31)


def _stub_tomcat_manager(monkeypatch) -> None:
    """Un panel de Tomcat Manager con la tercera credencial de fábrica del feed
    (``tomcat/s3cret``) — deliberadamente no la primera que se prueba, para
    que el runtime tenga que agotar un intento fallido antes de acertar, y
    con usuario y contraseña distintos, para poder afirmar sin ambigüedad que
    la contraseña que funcionó no aparece en ningún sitio.

    Sirve tanto a los checks activos declarativos como al motor de
    credenciales: cualquier ruta que no sea ``/manager/html`` con la cabecera
    correcta responde 404/401, así que el resto del feed no dispara ruido.
    """
    from src.modules.features.themis.lybra.checks import Response
    import base64
    valid_auth = "Basic " + base64.b64encode(b"tomcat:s3cret").decode("ascii")

    def fetch(self, host, port, method, path, body=None, headers=None):
        if path == "/manager/html" and (headers or {}).get("Authorization") == valid_auth:
            return Response(200, "Tomcat Web Application Manager", {})
        if path == "/manager/html":
            return Response(401, "", {})
        return Response(404, "", {})

    monkeypatch.setattr("src.modules.features.themis.lybra.checks.HttpProbe.fetch", fetch)
    monkeypatch.setattr(LybraEngineManager, "_fingerprint_services",
                        lambda self, target, services, **kw: (services, []))


def test_aggressive_checks_do_not_run_without_an_explicit_request(monkeypatch, app, admin_user):
    """Objetivo autorizado, pero nadie pidió el modo agresivo: la mitad de la
    puerta que falta. Ni un check ``aggressive`` ni el motor de credenciales
    corren, así que un panel con credenciales de fábrica de verdad expuestas
    no produce ningún hallazgo de ``default_credentials``."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    _stub_tomcat_manager(monkeypatch)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id)  # aggressive=False por defecto
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert not [f for f in findings if f.category == "default_credentials"]


def test_aggressive_checks_do_not_run_on_an_unauthorized_target(monkeypatch, app, admin_user):
    """Petición explícita de modo agresivo, pero el objetivo NO está en el
    registro de autorización: la otra mitad de la puerta. Autorizar un
    objetivo para el escaneo pasivo no autoriza escribir en él."""
    # Deliberadamente sin `_authorize_target`: el objetivo no está autorizado.
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    _stub_tomcat_manager(monkeypatch)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, aggressive=True)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert not [f for f in findings if f.category == "default_credentials"]


def test_an_authorized_and_explicit_aggressive_scan_finds_default_credentials(
        monkeypatch, app, admin_user):
    """Las dos mitades de la puerta juntas: objetivo autorizado y modo
    agresivo pedido explícitamente. El motor de credenciales prueba el panel
    de Tomcat Manager, encuentra la credencial de fábrica que funciona y
    produce un hallazgo confirmado — sin que la contraseña aparezca en
    ningún campo."""
    _authorize_target(app, admin_user.id)
    monkeypatch.setattr(ScanManager, "is_host_reachable", staticmethod(lambda *a, **k: True))
    _stub_self_discovery(monkeypatch, [80])
    _stub_tomcat_manager(monkeypatch)

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.5", user_id=admin_user.id)
        mgr._run_lybra(escan.id, aggressive=True)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    credential_findings = [f for f in findings if f.category == "default_credentials"]
    assert len(credential_findings) == 1
    finding = credential_findings[0]
    assert finding.confirmed is True
    assert finding.qod == 99
    assert finding.check_id == "lybra-credentials:tomcat-manager-default@1"

    assert "s3cret" not in str(finding.title)

    with UnitOfWork() as uow:
        evidence = ScanRepository(uow).get_evidence_for_finding(finding.id)
    # La contraseña que funcionó no aparece en el hallazgo ni en su evidencia
    # — es justo lo que el motor de credenciales existe para garantizar. El
    # usuario ("tomcat") sí puede aparecer; es información útil y no secreta.
    assert len(evidence) == 1
    assert "s3cret" not in str(evidence[0].payload)


# ─────────────── desmentir un hallazgo no es aceptar un riesgo (L35)
#
# Hasta ahora el esquema sólo admitía `accepted` y `open`, así que un usuario
# que sabía que un hallazgo era falso —Debian parcheó por backport y la versión
# no subió— sólo podía marcarlo como "riesgo aceptado". Un informe que dice
# "3 riesgos aceptados" cuando son 3 errores del escáner miente sobre la
# postura de seguridad, y de paso tira la única muestra etiquetada gratis que
# hay para calibrar el motor.


def _first_finding_id(app, scan_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            return ScanRepository(uow).get_findings_by_scan(scan_id)[0].id


def test_a_finding_can_be_refuted_without_accepting_the_risk(
        client, app, admin_user, auth_headers):
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.21")
    finding_id = _first_finding_id(app, scan_id)

    resp = client.patch(f"/themis/findings/{finding_id}",
                        headers=auth_headers(admin_user),
                        json={"state": "false_positive",
                              "reason": "backport de Debian, la versión no sube"})
    assert resp.status_code == 200
    assert resp.get_json()["state"] == "false_positive"

    with app.app_context():
        with UnitOfWork() as uow:
            finding = ScanRepository(uow).get_finding(finding_id)
            assert finding.state == "false_positive"
            assert finding.state_reason.startswith("backport de Debian")
            assert finding.state_set_by == admin_user.id
            assert finding.state_set_at is not None
            # Un desmentido no caduca: el motor no se equivoca más por ser
            # más tarde.
            assert finding.state_expires_at is None


def test_accepting_a_risk_sets_an_expiry(client, app, admin_user, auth_headers):
    """La diferencia con el desmentido, en una línea: un riesgo asumido vuelve
    a revisión, uno desmentido no."""
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.22")
    finding_id = _first_finding_id(app, scan_id)

    client.patch(f"/themis/findings/{finding_id}", headers=auth_headers(admin_user),
                 json={"state": "accepted", "reason": "mitigado por el WAF"})

    with app.app_context():
        with UnitOfWork() as uow:
            finding = ScanRepository(uow).get_finding(finding_id)
            assert finding.state == "accepted"
            assert finding.state_expires_at is not None
            assert finding.state_expires_at > finding.state_set_at


def test_reopening_a_finding_clears_the_previous_decision(
        client, app, admin_user, auth_headers):
    """Volver a `open` no es una decisión nueva: es retirar la anterior, así que
    su motivo y su autor dejan de tener sentido."""
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.23")
    finding_id = _first_finding_id(app, scan_id)
    headers = auth_headers(admin_user)

    client.patch(f"/themis/findings/{finding_id}", headers=headers,
                 json={"state": "false_positive", "reason": "no aplica"})
    client.patch(f"/themis/findings/{finding_id}", headers=headers,
                 json={"state": "open"})

    with app.app_context():
        with UnitOfWork() as uow:
            finding = ScanRepository(uow).get_finding(finding_id)
            assert finding.state == "open"
            assert finding.state_reason is None
            assert finding.state_set_by is None
            assert finding.state_expires_at is None


def test_a_state_the_lifecycle_owns_cannot_be_set_by_hand(
        client, app, admin_user, auth_headers):
    """`fixed` y `regressed` los pone el ciclo de vida al comparar escaneos.
    Dejarlos escribir desde fuera permitiría falsear el historial."""
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.24")
    finding_id = _first_finding_id(app, scan_id)

    resp = client.patch(f"/themis/findings/{finding_id}",
                        headers=auth_headers(admin_user), json={"state": "fixed"})
    assert resp.status_code == 422


def test_the_manager_validates_the_state_on_its_own(app, admin_user):
    """La validación del schema protege el endpoint; el manager es la frontera
    de verdad, y hasta L35 aceptaba cualquier cadena."""
    from src.modules.shared._exceptions import ValidationError

    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.25")
    finding_id = _first_finding_id(app, scan_id)

    with app.app_context():
        with pytest.raises(ValidationError):
            LybraEngineManager().set_finding_state(finding_id, admin_user.id, "inventado")


def test_a_refuted_finding_stops_counting_as_a_risk(
        client, app, admin_user, auth_headers):
    """El coste de producto de confundir los dos estados: el recuento."""
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.26")
    headers = auth_headers(admin_user)

    before = client.get("/themis/results?type=lybra&page=1&per_page=10",
                        headers=headers).get_json()["results"][0]
    assert before["falsePositiveFindings"] == 0
    priorities_before = sum(before["byPriority"].values())

    finding_id = _first_finding_id(app, scan_id)
    client.patch(f"/themis/findings/{finding_id}", headers=headers,
                 json={"state": "false_positive", "reason": "no aplica"})

    after = client.get("/themis/results?type=lybra&page=1&per_page=10",
                       headers=headers).get_json()["results"][0]
    assert after["falsePositiveFindings"] == 1
    assert sum(after["byPriority"].values()) == priorities_before - 1
    assert after["totalFindings"] == before["totalFindings"]   # sigue estando, no se borra


def test_refuted_findings_are_available_as_labelled_samples(
        client, app, admin_user, auth_headers):
    """Lo que convierte esto de una casilla de interfaz en un bucle de mejora:
    cada desmentido dice contra qué check y contra qué producto se equivoca el
    motor."""
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.27")
    finding_id = _first_finding_id(app, scan_id)
    headers = auth_headers(admin_user)

    client.patch(f"/themis/findings/{finding_id}", headers=headers,
                 json={"state": "false_positive", "reason": "backport"})

    body = client.get("/themis/findings/false-positives", headers=headers).get_json()
    assert body["count"] == 1
    sample = body["falsePositives"][0]
    assert sample["findingId"] == finding_id
    assert sample["reason"] == "backport"
    assert "feedVersion" in sample and "checkId" in sample and "cpe" in sample


def test_false_positives_are_scoped_to_their_owner(
        client, app, admin_user, regular_user, auth_headers):
    scan_id = _run_payload_scan(app, admin_user.id, target="10.0.0.28")
    finding_id = _first_finding_id(app, scan_id)
    client.patch(f"/themis/findings/{finding_id}", headers=auth_headers(admin_user),
                 json={"state": "false_positive", "reason": "mío"})

    body = client.get("/themis/findings/false-positives",
                      headers=auth_headers(regular_user)).get_json()
    assert body["count"] == 0


def test_a_finding_carries_its_exploit_maturity(app, admin_user):
    """`exploit_maturity` se declaraba en el modelo desde el principio,
    documentada como "rellenada desde la Fase 1", y estaba NULL en todas las
    filas. Ahora dice algo en cada hallazgo con CVE."""
    _seed_kb_apache_cve(app)   # siembra también KEV para esta CVE

    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.31", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    # En KEV: la evidencia más fuerte que hay, y gana a cualquier otra.
    assert vuln.exploit_maturity == "in_the_wild"


def test_a_cve_outside_kev_with_an_exploit_reference_reads_as_poc(app, admin_user):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
                 "description": "Path traversal", "cwe_ids": ["CWE-22"],
                 "has_exploit_reference": True, "source": "nvd"},
                [{"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )

        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.32", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.exploit_maturity == "poc"


def test_a_cve_with_nothing_public_says_none_not_null(app, admin_user):
    """`none` es una afirmación —no consta nada público—; `NULL` era la
    ausencia de afirmación, que es lo que hacía inútil la columna."""
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(
                {"cve_id": "CVE-2021-41773", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
                 "description": "Path traversal", "cwe_ids": ["CWE-22"], "source": "nvd"},
                [{"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )

        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.33", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_network_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.exploit_maturity == "none"


# ─────────────── verificación de backports de extremo a extremo (Fase O)


def _debian_services() -> list:
    """Apache empaquetado por Debian 11: la versión trae su revisión, que es lo
    que nombra al proveedor sin necesidad de entrar en el host."""
    from src.modules.features.themis.lybra import Service
    return [Service(port=80, protocol="tcp", name="http", product="apache2",
                    version="2.4.49-1~deb11u1",
                    cpe="cpe:/a:apache:http_server:2.4.49", origin="inventory")]


def test_a_backported_finding_is_closed_without_touching_the_host(app, admin_user):
    """El corazón de la Fase O: Debian ya lo parcheó sin subir el número
    visible, así que el hallazgo por versión nunca fue real."""
    _seed_kb_apache_cve(app)
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_distro_pkg_status({
                "vendor": "debian", "release": "11", "package": "apache2",
                "cve_id": "CVE-2021-41773", "fixed_in": "2.4.49-1~deb11u1",
                "status": "fixed",
            })

        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.41", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_debian_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.state == "fixed"
    assert vuln.confirmed is False
    assert vuln.check_id == "lybra:oval-backport@1"


def test_a_vendor_confirming_the_flaw_raises_the_confidence(app, admin_user):
    _seed_kb_apache_cve(app)
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_distro_pkg_status({
                "vendor": "debian", "release": "11", "package": "apache2",
                "cve_id": "CVE-2021-41773", "fixed_in": None, "status": "vulnerable",
            })

        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.42", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_debian_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.confirmed is True
    assert vuln.qod == 90


def test_without_a_distro_advisory_the_finding_stays_a_hypothesis(app, admin_user):
    """El comportamiento de antes de la Fase O, que es el correcto cuando no
    hay a quién preguntar."""
    _seed_kb_apache_cve(app)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.43", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_debian_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    vuln = next(f for f in findings if f.category == "outdated_software")
    assert vuln.state == "open"
    assert vuln.check_id == "lybra:version-match@1"


def test_the_working_keys_never_reach_the_database(app, admin_user):
    """`_installed_version` y `_package_name` son datos de trabajo entre etapas
    de la tubería, no columnas."""
    _seed_kb_apache_cve(app)
    with app.app_context():
        mgr = LybraEngineManager()
        escan = mgr._create_scan_record(target="10.0.0.44", user_id=admin_user.id)
        mgr._run_lybra(escan.id, services_payload=_debian_services())

        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(escan.id)

    assert findings, "el escaneo no llegó a persistir nada"
    for finding in findings:
        assert not hasattr(finding, "_installed_version")
