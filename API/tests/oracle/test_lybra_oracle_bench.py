"""Banco de pruebas con oráculo diferencial para Lybra (roadmap §7).

A diferencia del resto de la suite de Lybra (``tests/integration/test_lybra.py``),
que mockea toda la red a propósito, este módulo hace lo contrario: levanta
contenedores Docker reales con software conocido y deja que Lybra los descubra,
identifique y correlacione con la BC **de verdad**, por la red real. Es la pieza
que el apartado 7 del roadmap pide y que hasta ahora no existía como artefacto
ejecutable — solo como aspiración documentada.

Nmap hace de oráculo cuando aplica (concordancia de puertos/fingerprint, igual
que ``scripts/lybra_concordance_bench.py``); para el resto, la aserción es
directamente "el motor debe encontrar la CVE/hallazgo tal en el contenedor
cual", tal y como describe el apartado 9 ("por dónde empezar esta misma
semana").

Requiere Docker. Se salta entero si no está disponible — no forma parte del
run por defecto de CI (ver ``tests.yml``, marcador ``oracle``), porque el
propio roadmap trata "correr esta medición" como un paso operativo del
usuario, no como una puerta de cada commit.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.lybra import scan_ports_sync, port_concordance
from src.modules.features.themis.managers import LybraEngineManager, AuthorizedTargetManager
from src.modules.features.themis.repositories import ScanRepository, KbRepository

from ._docker_helpers import resolve_docker, docker_run, docker_rm, wait_for_port, port_is_free

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
_NMAP = shutil.which("nmap")

pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))


def _docker(*args: str) -> subprocess.CompletedProcess:
    return docker_run(_DOCKER, *args)


_wait_for_port = wait_for_port


# is_http_service() (checks.py) only recognises a fixed port set for HTTP
# fingerprinting/active checks — a container published on a fully random
# ephemeral port would be discovered (open_port) but never actually probed.
# Picking a free port *from that set* keeps both true: recognised as HTTP,
# and not hard-coded onto a port something else on the host might be using.
# 8443 is deliberately excluded: it is the only port besides 443 that
# is_tls_service() (checks.py) recognises, and it is reserved below for the
# TLS fixtures — a plain HTTP fixture claiming it first would starve them.
_CANDIDATE_HTTP_PORTS = (8080, 8000, 8888, 8008)
_claimed_ports: set = set()

# Reserved exclusively for the TLS family fixtures (only one candidate exists,
# so these fixtures are function-scoped and tear down their container before
# the next one binds it — no persistent claim needed).
_TLS_PORT = 8443


def _free_http_port() -> int:
    for port in _CANDIDATE_HTTP_PORTS:
        if port in _claimed_ports:
            continue
        if port_is_free("127.0.0.1", port):
            _claimed_ports.add(port)
            return port
    raise RuntimeError(f"Ninguno de los puertos HTTP candidatos está libre: {_CANDIDATE_HTTP_PORTS}")


def _free_tls_port() -> int:
    if not port_is_free("127.0.0.1", _TLS_PORT):
        raise RuntimeError(f"Puerto TLS {_TLS_PORT} no está libre")
    return _TLS_PORT


def _tls_container_cmd(days: int, expired: bool) -> str:
    """Shell command that generates a self-signed cert *inside* the container
    at startup (no bind mount, same philosophy as ``git_exposed_port``) and
    serves it over TLS with vanilla nginx.

    When ``expired`` is set, cert generation runs under ``libfaketime`` with
    the clock wound back to 2020 — the container's real clock is never
    touched (no ``CAP_SYS_TIME``, which Docker does not grant by default),
    only the ``openssl`` process sees a fake "now" while computing
    ``notBefore``/``notAfter``. nginx serving the resulting cert later, under
    the container's real clock, does not care that the file is "from the
    past": TLS handshakes don't validate the server's own clock.
    """
    pkgs = "openssl libfaketime" if expired else "openssl"
    prefix = "faketime '2020-01-01 00:00:00' " if expired else ""
    return (
        f"apk add --no-cache {pkgs} >/dev/null 2>&1 && "
        + prefix +
        "openssl req -x509 -nodes -days " + str(days) + " -newkey rsa:2048 "
        "-keyout /etc/nginx/tls.key -out /etc/nginx/tls.crt -subj /CN=lybra-oracle-tls >/dev/null 2>&1 && "
        "printf '%s' 'server { listen 443 ssl; ssl_certificate /etc/nginx/tls.crt; "
        "ssl_certificate_key /etc/nginx/tls.key; location / { return 200; } }' "
        "> /etc/nginx/conf.d/default.conf && nginx -g \"daemon off;\""
    )


@pytest.fixture(scope="module")
def httpd_2449_port():
    """Un ``httpd:2.4.49`` real — el mismo ejemplo que usa el propio roadmap
    (CVE-2021-41773) en el apartado 9."""
    port = _free_http_port()
    name = f"lybra-oracle-httpd-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "httpd:2.4.49")
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def git_exposed_port():
    """Un nginx con ``.git/config`` expuesto — el segundo ejemplo del apartado 9.

    El fichero se escribe dentro del propio contenedor al arrancar (sin bind
    mount): evita depender de traducción de rutas WSL↔Docker Desktop, que es
    justo el tipo de fricción de entorno que este banco no debería añadir.
    """
    port = _free_http_port()
    name = f"lybra-oracle-git-{port}"
    write_config = (
        "mkdir -p /usr/share/nginx/html/.git && "
        "printf '[core]\\n\\trepositoryformatversion = 0\\n\\tfilemode = true\\n' "
        "> /usr/share/nginx/html/.git/config && nginx -g 'daemon off;'"
    )
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "nginx:alpine", "sh", "-c", write_config)
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def tls_healthy_port():
    """A self-signed cert that is otherwise healthy — valid for a year, modern
    protocol. Closes the roadmap's Fase R gap ("la familia tls se quedó fuera
    del banco automatizado"): a local container with a self-signed cert
    generated at startup, avoiding both the bind-mount friction the
    ``.git/config`` fixture already sidesteps and the SNI/IP mismatch a real
    ``badssl.com``-style target would hit through ``AuthorizedTargetManager``
    (IP/CIDR only, no hostnames).

    Also a negative control: it must NOT trip ``tls-expired-cert`` or
    ``tls-deprecated-protocol``, the other two checks in the same family.
    """
    port = _free_tls_port()
    name = f"lybra-oracle-tls-healthy-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:443", "nginx:alpine",
            "sh", "-c", _tls_container_cmd(days=365, expired=False))
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def tls_expired_port():
    """Same container, but the cert is generated under ``libfaketime`` with
    the clock wound back to 2020, so it is already expired against any real
    clock. Also self-signed, like every cert this fixture family produces."""
    port = _free_tls_port()
    name = f"lybra-oracle-tls-expired-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:443", "nginx:alpine",
            "sh", "-c", _tls_container_cmd(days=30, expired=True))
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


def _run_self_discovery(app, admin_user, target: str, port: int, monkeypatch):
    """Lanza un escaneo Lybra de autodescubrimiento real contra ``target:port``."""
    monkeypatch.setattr(CR, "is_host_reachability_check_enabled", lambda: False)
    with app.app_context():
        AuthorizedTargetManager().add(admin_user.id, target)
        mgr = LybraEngineManager()
        scan = mgr._create_scan_record(target=target, user_id=admin_user.id, source_scan_id=None)
        mgr._run_lybra(scan.id, None, [port], False)
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(scan.id)
    return findings


def test_apache_2449_self_discovery_finds_version_and_cve(app, admin_user, httpd_2449_port, monkeypatch):
    """El motor debe encontrar CVE-2021-41773 en un httpd:2.4.49 real (roadmap §9)."""
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

    findings = _run_self_discovery(app, admin_user, "127.0.0.1", httpd_2449_port, monkeypatch)

    fingerprints = [f for f in findings if f.category == "fingerprint"]
    assert len(fingerprints) == 1, f"hallazgos: {[(f.category, f.title) for f in findings]}"
    assert "Apache 2.4.49" in fingerprints[0].title

    vulns = [f for f in findings if f.category == "outdated_software"]
    assert any("CVE-2021-41773" in (v.cve_ids or []) for v in vulns)


def test_git_config_exposure_detected_against_real_container(app, admin_user, git_exposed_port, monkeypatch):
    """El check activo debe confirmar el .git/config expuesto (roadmap §9)."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", git_exposed_port, monkeypatch)

    exposed = [f for f in findings if f.category == "exposed_path"]
    assert len(exposed) == 1, f"hallazgos: {[(f.category, f.title) for f in findings]}"
    assert exposed[0].confirmed is True
    assert exposed[0].qod == 99
    assert exposed[0].check_id == "lybra:git-config-exposure@1"


def test_missing_security_headers_detected_against_real_container(app, admin_user, git_exposed_port, monkeypatch):
    """La familia security_header (Fase R) debe confirmarse contra un nginx real
    que no manda ninguna de las tres cabeceras — vanilla nginx:alpine, sin nada
    de configuración de seguridad."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", git_exposed_port, monkeypatch)

    headers = {f.check_id for f in findings if f.category == "security_header"}
    assert headers == {
        "lybra:missing-hsts-header@1",
        "lybra:missing-x-frame-options-header@1",
        "lybra:missing-x-content-type-options-header@1",
    }
    assert all(f.confirmed and f.qod == 99 for f in findings if f.category == "security_header")


def test_tls_self_signed_cert_detected_against_real_container(app, admin_user, tls_healthy_port, monkeypatch):
    """La familia tls (Fase R) debe confirmar el autofirmado contra un
    contenedor real, y no disparar en falso los otros dos checks de la misma
    familia (caducidad, protocolo obsoleto) — el control negativo que hace
    del número de precisión algo medido y no solo aspiracional."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", tls_healthy_port, monkeypatch)

    tls_findings = {f.check_id for f in findings if f.category == "tls"}
    assert tls_findings == {"lybra:tls-self-signed-cert@1"}
    assert all(f.confirmed and f.qod == 99 for f in findings if f.category == "tls")


def test_tls_expired_cert_detected_against_real_container(app, admin_user, tls_expired_port, monkeypatch):
    """Certificado generado con el reloj adelantado a 2020 (``libfaketime``):
    debe confirmar tanto el autofirmado como la caducidad contra un handshake
    TLS real, sin mockear nada."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", tls_expired_port, monkeypatch)

    tls_findings = {f.check_id for f in findings if f.category == "tls"}
    assert tls_findings == {"lybra:tls-self-signed-cert@1", "lybra:tls-expired-cert@1"}
    assert all(f.confirmed and f.qod == 99 for f in findings if f.category == "tls")


@pytest.mark.skipif(_NMAP is None, reason="nmap no disponible")
def test_port_discovery_agrees_with_nmap_oracle(httpd_2449_port):
    """Concordancia de puertos (Fase T) contra Nmap para un objetivo real, no mockeado."""
    own_ports = scan_ports_sync("127.0.0.1", [httpd_2449_port])

    result = subprocess.run(
        ["nmap", "-p", str(httpd_2449_port), "-oG", "-", "127.0.0.1"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    nmap_ports = [httpd_2449_port] if f"{httpd_2449_port}/open" in result.stdout else []

    assert port_concordance(own_ports, nmap_ports) == 1.0
