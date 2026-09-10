"""Banco de pruebas con oráculo diferencial para Lybra.

A diferencia del resto de la suite de Lybra (``tests/integration/test_lybra.py``),
que mockea toda la red a propósito, este módulo hace lo contrario: levanta
contenedores Docker reales con software conocido y deja que Lybra los descubra,
identifique y correlacione con la BC **de verdad**, por la red real. Es la
medición ejecutable que antes sólo existía como aspiración documentada.

Nmap hace de oráculo cuando aplica (concordancia de puertos/fingerprint, igual
que ``scripts/lybra_concordance_bench.py``); para el resto, la aserción es
directamente "el motor debe encontrar la CVE/hallazgo tal en el contenedor
cual".

Requiere Docker. Se salta entero si no está disponible — no forma parte del
run por defecto de CI (ver ``tests.yml``, marcador ``oracle``), porque correr
esta medición es un paso operativo del usuario, no una puerta de cada commit.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.lybra import scan_ports_sync
from src.modules.features.themis.exceptions import DuplicateAuthorizedTargetError
from src.modules.features.themis.managers import LybraEngineManager, AuthorizedTargetManager
from src.modules.features.themis.repositories import ScanRepository, KbRepository

from ._concordance import port_concordance
from ._security_headers import always_missing_header_checks
from ._docker_helpers import (resolve_docker, docker_run, docker_rm, wait_for_port,
                              port_is_free, container_died, diagnose_port,
                              remember_container)

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
_NMAP = shutil.which("nmap")

pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))


def _docker(*args: str) -> subprocess.CompletedProcess:
    return docker_run(_DOCKER, *args)


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    """``wait_for_port`` con el cliente Docker ya puesto.

    Sin él, un contenedor que muere al arrancar se comunica como un puerto
    que no contestó, que es el síntoma y nunca la causa.
    """
    wait_for_port(host, port, timeout, docker_path=_DOCKER)


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


# Los checks ``network`` se seleccionan por nombre de servicio o por puerto
# (``is_ftp_service`` / ``is_redis_service`` en checks.py), y el
# autodescubrimiento sólo aporta el puerto. Así que estos contenedores tienen
# que publicarse en el puerto canónico de su protocolo o el check ni se
# consideraría. Son puertos fijos, no elegibles: si algo del host ya los ocupa
# —un Redis de desarrollo en el 6379, por ejemplo— el caso se salta con un
# motivo legible en vez de fallar por una colisión que no es del motor.
_FTP_PORT = 21
_REDIS_PORT = 6379


def _require_free_port(port: int, label: str) -> None:
    if not port_is_free("127.0.0.1", port):
        pytest.skip(f"El puerto {port} ({label}) está ocupado en el host")


def _wait_until_answering(port: int, expect: bytes, send: bytes = None, timeout: float = 120.0) -> None:
    """Espera a que el servicio conteste lo que se espera de él, no sólo a que el puerto acepte.

    ``wait_for_port`` no vale para estos dos contenedores. Docker publica el
    puerto en el host en cuanto arranca el contenedor, así que el TCP acepta a
    los 0,0 s — medido — mientras dentro todavía se está instalando el
    servidor. Un escaneo lanzado en ese hueco encuentra una conexión que se
    cierra sin decir nada, el check se abandona, y el test falla por una
    carrera de arranque que no tiene nada que ver con el motor. Es exactamente
    lo que pasó la primera vez que se ejecutaron estas pruebas.

    Exigir además el saludo correcto (``220`` en FTP, ``+PONG`` o ``-NOAUTH``
    en Redis) hace de paso de comprobación de que el contenedor quedó
    configurado como el caso pide: un control negativo mal montado falla aquí,
    en voz alta, en vez de pasar el test sin demostrar nada.

    Args:
        port: El puerto publicado en 127.0.0.1.
        expect: El prefijo con el que debe empezar la respuesta.
        send: Lo que hay que escribir para provocarla, o ``None`` si el
            protocolo saluda solo.
        timeout: Cuánto esperar antes de rendirse — generoso, porque la
            primera ejecución instala paquetes dentro del contenedor.
    """
    deadline = time.monotonic() + timeout
    seen = b""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                if send is not None:
                    sock.sendall(send)
                seen = sock.recv(128)
                if seen.startswith(expect):
                    return
        except OSError:
            pass
        if container_died(_DOCKER, port):
            raise TimeoutError(
                f"127.0.0.1:{port} no contestó {expect!r}: su contenedor no sigue "
                f"en marcha (última respuesta: {seen!r})."
                f"{diagnose_port(_DOCKER, port)}"
            )
        time.sleep(0.3)
    raise TimeoutError(
        f"127.0.0.1:{port} no contestó {expect!r} en {timeout}s (última respuesta: {seen!r})"
        f"{diagnose_port(_DOCKER, port)}"
    )


def _vsftpd_container_cmd(anonymous: bool) -> str:
    """Comando que instala y configura un vsftpd dentro del contenedor.

    Se genera la configuración al arrancar, sin bind mount, por la misma razón
    que el resto de fixtures de este módulo: evitar la traducción de rutas
    WSL↔Docker Desktop.

    ``no_anon_password=NO`` es deliberado y no un detalle: con ``YES`` el
    servidor concede el acceso ya en el ``USER`` (responde 230 directamente) y
    la secuencia USER→331→PASS→230 que el check espera no llega a existir. El
    caso negativo mantiene ``local_enable=YES`` para que vsftpd tenga algún
    modo de acceso habilitado y arranque, aunque no haya ninguna cuenta usable.
    """
    anonymous_enable = "YES" if anonymous else "NO"
    local_enable = "NO" if anonymous else "YES"
    settings = " ".join([
        "'listen=YES'", "'listen_ipv6=NO'",
        f"'anonymous_enable={anonymous_enable}'", f"'local_enable={local_enable}'",
        "'no_anon_password=NO'", "'seccomp_sandbox=NO'", "'anon_root=/var/lib/ftp'",
    ])
    return (
        "apk add --no-cache vsftpd >/dev/null 2>&1 && "
        "mkdir -p /var/lib/ftp && chmod 555 /var/lib/ftp && "
        f"printf '%s\\n' {settings} > /etc/vsftpd/vsftpd.conf && "
        "vsftpd /etc/vsftpd/vsftpd.conf"
    )


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
    """Un ``httpd:2.4.49`` real, vulnerable a CVE-2021-41773."""
    port = _free_http_port()
    name = f"lybra-oracle-httpd-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "httpd:2.4.49")
    remember_container(port, name)
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def git_exposed_port():
    """Un nginx con ``.git/config`` expuesto.

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
    remember_container(port, name)
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def tls_healthy_port():
    """A self-signed cert that is otherwise healthy — valid for a year, modern
    protocol. Covers the tls family in the automated bench: a local container
    with a self-signed cert generated at startup, avoiding both the
    bind-mount friction the
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
    remember_container(port, name)
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
    remember_container(port, name)
    try:
        _wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def ftp_anonymous_port():
    """Un vsftpd real con el acceso anónimo **abierto**: el caso positivo."""
    _require_free_port(_FTP_PORT, "FTP")
    name = f"lybra-oracle-ftp-anon-{_FTP_PORT}"
    _docker("run", "-d", "--name", name, "-p", f"{_FTP_PORT}:21", "alpine:3.19",
            "sh", "-c", _vsftpd_container_cmd(anonymous=True))
    remember_container(_FTP_PORT, name)
    try:
        _wait_until_answering(_FTP_PORT, expect=b"220")
        yield _FTP_PORT
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def ftp_no_anonymous_port():
    """El mismo vsftpd con el acceso anónimo **cerrado**: el control negativo.

    Sin él, el caso positivo no demuestra gran cosa — un check que disparase
    siempre también pasaría el positivo.
    """
    _require_free_port(_FTP_PORT, "FTP")
    name = f"lybra-oracle-ftp-noanon-{_FTP_PORT}"
    _docker("run", "-d", "--name", name, "-p", f"{_FTP_PORT}:21", "alpine:3.19",
            "sh", "-c", _vsftpd_container_cmd(anonymous=False))
    remember_container(_FTP_PORT, name)
    try:
        _wait_until_answering(_FTP_PORT, expect=b"220")
        yield _FTP_PORT
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def redis_open_port():
    """Un ``redis:7`` sin contraseña: cualquiera puede pedirle un INFO."""
    _require_free_port(_REDIS_PORT, "Redis")
    name = f"lybra-oracle-redis-open-{_REDIS_PORT}"
    _docker("run", "-d", "--name", name, "-p", f"{_REDIS_PORT}:6379", "redis:7")
    remember_container(_REDIS_PORT, name)
    try:
        _wait_until_answering(_REDIS_PORT, expect=b"+PONG", send=b"PING\r\n")
        yield _REDIS_PORT
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture
def redis_password_port():
    """El mismo ``redis:7`` con ``requirepass``: contesta ``-NOAUTH`` al INFO."""
    _require_free_port(_REDIS_PORT, "Redis")
    name = f"lybra-oracle-redis-auth-{_REDIS_PORT}"
    _docker("run", "-d", "--name", name, "-p", f"{_REDIS_PORT}:6379", "redis:7",
            "redis-server", "--requirepass", "lybra-oracle")
    remember_container(_REDIS_PORT, name)
    try:
        _wait_until_answering(_REDIS_PORT, expect=b"-NOAUTH", send=b"PING\r\n")
        yield _REDIS_PORT
    finally:
        docker_rm(_DOCKER, name)


def _run_self_discovery(app, admin_user, target: str, port: int, monkeypatch):
    """Lanza un escaneo Lybra de autodescubrimiento real contra ``target:port``.

    La autorización del objetivo es idempotente a propósito: un test que barre
    varios contenedores en un solo caso —el banco de precisión de familias—
    llama aquí una vez por objetivo con la misma IP y la misma BD, y el registro
    rechaza duplicados. Lo que este helper necesita es "que esté autorizado", no
    "que se acabe de añadir".
    """
    monkeypatch.setattr(CR, "host_reachability_check", lambda: CR.HostReachabilityCheck(enabled=False))
    with app.app_context():
        try:
            AuthorizedTargetManager().add(admin_user.id, target)
        except DuplicateAuthorizedTargetError:
            pass
        mgr = LybraEngineManager()
        scan = mgr._create_scan_record(target=target, user_id=admin_user.id)
        mgr._run_lybra(scan.id, discover_ports=[port])
        with UnitOfWork() as uow:
            findings = ScanRepository(uow).get_findings_by_scan(scan.id)
    return findings


def test_apache_2449_self_discovery_finds_version_and_cve(app, admin_user, httpd_2449_port, monkeypatch):
    """El motor debe encontrar CVE-2021-41773 en un httpd:2.4.49 real."""
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
    """El check activo debe confirmar el .git/config expuesto."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", git_exposed_port, monkeypatch)

    exposed = [f for f in findings if f.category == "exposed_path"]
    assert len(exposed) == 1, f"hallazgos: {[(f.category, f.title) for f in findings]}"
    assert exposed[0].confirmed is True
    assert exposed[0].qod == 99
    assert exposed[0].check_id == "lybra:git-config-exposure@1"


def test_missing_security_headers_detected_against_real_container(app, admin_user, git_exposed_port, monkeypatch):
    """La familia security_header debe confirmarse contra un nginx real
    que no manda ninguna de las tres cabeceras — vanilla nginx:alpine, sin nada
    de configuración de seguridad."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", git_exposed_port, monkeypatch)

    headers = {f.check_id for f in findings if f.category == "security_header"}
    # La familia esperada sale del feed, no de una lista escrita aquí. La lista
    # estuvo escrita, con tres identificadores, y se quedó atrás en cuanto el
    # feed creció.
    assert headers == always_missing_header_checks()
    assert all(f.confirmed and f.qod == 99 for f in findings if f.category == "security_header")


def test_tls_self_signed_cert_detected_against_real_container(app, admin_user, tls_healthy_port, monkeypatch):
    """La familia tls debe confirmar el autofirmado contra un
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


# ------------------------------------------- familia network contra servidores reales
#
# Por qué existen estos cuatro casos: hasta aquí, los dos únicos checks no-web
# del motor sólo se habían ejercitado contra dobles, y por eso nadie vio que el
# transporte leía una forma de respuesta que ni FTP ni Redis producen: el
# escaneo terminaba en verde y el FTP anónimo seguía ahí. Un positivo y un
# negativo por protocolo, contra el servidor de verdad.

def test_ftp_anonymous_login_detected_against_real_vsftpd(app, admin_user, ftp_anonymous_port, monkeypatch):
    """Con el acceso anónimo abierto, el check tiene que confirmarlo.

    Es la prueba de que el saludo (``220 ...``) se consume antes de escribir
    ``USER`` y de que la respuesta se lee como bloque de estado: sin las dos
    cosas, el check evalúa el saludo contra el matcher del ``331`` y calla.
    """
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", ftp_anonymous_port, monkeypatch)

    ftp = [f for f in findings if f.check_id == "lybra:ftp-anonymous-login@2"]
    assert len(ftp) == 1, f"hallazgos: {[(f.category, f.title) for f in findings]}"
    assert ftp[0].confirmed is True and ftp[0].qod == 99
    assert ftp[0].category == "default_credentials"
    assert ftp[0].port == 21


def test_ftp_anonymous_login_absent_against_a_locked_down_vsftpd(app, admin_user, ftp_no_anonymous_port, monkeypatch):
    """Con el acceso anónimo cerrado, el mismo check no debe producir nada."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", ftp_no_anonymous_port, monkeypatch)
    assert not any(f.check_id.startswith("lybra:ftp-anonymous-login") for f in findings)


def test_redis_unauthenticated_access_detected_against_real_redis(app, admin_user, redis_open_port, monkeypatch):
    """Un Redis sin contraseña contesta al INFO, y eso es el hallazgo.

    Prueba de que la respuesta se lee como *bulk string*: el contenido va
    detrás de una línea que sólo trae su longitud, así que leyendo una línea
    suelta nunca se llegaba a ver ``redis_version``.
    """
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", redis_open_port, monkeypatch)

    redis_findings = [f for f in findings if f.check_id == "lybra:redis-unauthenticated-access@2"]
    assert len(redis_findings) == 1, f"hallazgos: {[(f.category, f.title) for f in findings]}"
    assert redis_findings[0].confirmed is True and redis_findings[0].qod == 99
    assert redis_findings[0].category == "default_credentials"


def test_redis_unauthenticated_access_absent_when_requirepass_is_set(app, admin_user, redis_password_port, monkeypatch):
    """Con ``requirepass``, el INFO recibe ``-NOAUTH`` y no hay hallazgo."""
    findings = _run_self_discovery(app, admin_user, "127.0.0.1", redis_password_port, monkeypatch)
    assert not any(f.check_id.startswith("lybra:redis-unauthenticated-access") for f in findings)


@pytest.mark.skipif(_NMAP is None, reason="nmap no disponible")
def test_port_discovery_agrees_with_nmap_oracle(httpd_2449_port):
    """Concordancia de puertos contra Nmap para un objetivo real, no mockeado."""
    own_ports = scan_ports_sync("127.0.0.1", [httpd_2449_port])

    result = subprocess.run(
        ["nmap", "-p", str(httpd_2449_port), "-oG", "-", "127.0.0.1"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    nmap_ports = [httpd_2449_port] if f"{httpd_2449_port}/open" in result.stdout else []

    assert port_concordance(own_ports, nmap_ports) == 1.0
