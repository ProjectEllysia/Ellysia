"""Banco de concordancia F/T contra un catálogo de laboratorio (roadmap §7, §6).

``scripts/lybra_concordance_bench.py`` mide cuánto coincide el transporte y el
fingerprinting propios de Lybra con Nmap, pero es una herramienta manual: el
operador le pasa objetivos a mano, y hasta ahora esos objetivos eran solo
``N=4`` (un host de laboratorio, ``scanme.nmap.org`` y dos reales) medidos una
vez y anotados en el roadmap. Este módulo automatiza el lado de laboratorio de
esa medición — un catálogo de contenedores Docker reales, deliberadamente
variados (vendor, con/sin versión en cabecera, con/sin cabecera ``Server``,
TLS, SSH) — y lo convierte en aserciones repetibles, reutilizando exactamente
las mismas funciones puras que ya usa el script manual (importado directamente
de él, sin duplicar el parseo de ``nmap -sV``).

El lado "real" de la paridad laboratorio/real que pide el apartado 6 —
objetivos de Internet ya autorizados, con CDN/WAF por delante— sigue siendo un
paso operativo del usuario: requiere un registro de objetivos que solo el
propio usuario puede autorizar (``AuthorizedTargetManager``), y no es algo que
se pueda fabricar de forma responsable en un banco de pruebas automatizado.

Requiere Docker y Nmap. Se salta entero si cualquiera de los dos falta — no
forma parte del run por defecto de CI (marcador ``oracle``, ver
``test_lybra_oracle_bench.py`` y ``tests.yml``).
"""

from __future__ import annotations

import shutil
import socket
import sys
import time
from pathlib import Path

import pytest

from src.modules.themis.lybra import scan_ports_sync, port_concordance, concordance_rate

from ._docker_helpers import resolve_docker, docker_run, docker_rm, wait_for_port, port_is_free

# Reused as-is from the manual bench script rather than reimplemented here —
# same ``nmap -sV`` XML parsing, same ``fingerprint_own`` dissector wiring.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from lybra_concordance_bench import run_nmap_sv, fingerprint_own  # noqa: E402

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
_NMAP = shutil.which("nmap")

pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))
pytestmark.append(pytest.mark.skipif(_NMAP is None, reason="nmap no disponible"))


def _docker(*args: str) -> None:
    docker_run(_DOCKER, *args)


# fingerprint_own() (scripts/lybra_concordance_bench.py) only dissects a port
# whose *number* is in this fixed whitelist, or port 22 for SSH — a leftover
# from how the manual script recognises "this looks like HTTP" without a
# Service object to check is_http_service() against. Each lab target below is
# pinned to one of these exact ports for that reason, not chosen freely.
_APACHE_PORT = 8080
_NGINX_PLAIN_PORT = 8000
_NGINX_NO_VERSION_PORT = 8888
_NO_SERVER_HEADER_PORT = 8008
_TLS_PORT = 8443
_SSH_PORT = 22


def _wait_for_ssh_banner(host: str, port: int, timeout: float = 30.0) -> None:
    """Wait for an actual ``SSH-...`` banner, not just an accepted connection.

    A plain TCP connect (``wait_for_port``) is not a reliable readiness signal
    here: Docker Desktop's port-forwarding on Windows accepts the connection
    on the host side as soon as the container's network namespace exists,
    before ``sshd`` inside has actually bound the port — the accept-then-
    immediately-close response nmap itself labels ``tcpwrapped``. Waiting for
    the protocol's own greeting line is what actually proves the server is up.
    """
    deadline = time.monotonic() + timeout
    last_reason = "sin intentos"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0) as s:
                s.settimeout(2.0)
                banner = s.recv(64)
            if banner.startswith(b"SSH-"):
                return
            last_reason = f"respuesta no-SSH: {banner!r}"
        except OSError as exc:
            last_reason = str(exc)
        time.sleep(0.3)
    raise TimeoutError(f"{host}:{port} no sirvió un banner SSH en {timeout}s ({last_reason})")


def _require_port(port: int) -> int:
    if not port_is_free("127.0.0.1", port):
        raise RuntimeError(f"Puerto {port} no está libre para el catálogo de concordancia")
    return port


@pytest.fixture(scope="module")
def apache_target():
    """Apache con versión en la cabecera ``Server`` — el caso fácil."""
    port = _require_port(_APACHE_PORT)
    name = f"lybra-concordance-apache-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "httpd:2.4.49")
    try:
        wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def nginx_plain_target():
    """nginx sin tocar — Server header con producto y versión, otro vendor."""
    port = _require_port(_NGINX_PLAIN_PORT)
    name = f"lybra-concordance-nginx-plain-{port}"
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "nginx:alpine")
    try:
        wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def nginx_no_version_target():
    """nginx con ``server_tokens off`` — Server: nginx, sin número de versión.

    Nmap tampoco ve la versión aquí (verificado contra este mismo contenedor);
    ``agrees_with_nmap`` solo exige coincidencia de versión cuando *ambos*
    lados la reportan, así que esto sigue siendo un acuerdo válido por
    producto, no un caso roto.
    """
    port = _require_port(_NGINX_NO_VERSION_PORT)
    name = f"lybra-concordance-nginx-notoken-{port}"
    setup = (
        "printf '%s' 'server { listen 80; server_tokens off; location / { return 200; } }' "
        "> /etc/nginx/conf.d/default.conf && nginx -g \"daemon off;\""
    )
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "nginx:alpine", "sh", "-c", setup)
    try:
        wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def no_server_header_target():
    """busybox httpd — no manda cabecera ``Server`` en absoluto.

    El caso límite que el roadmap nombra explícitamente (apartado 6: "ausencia
    de fallback de fingerprint cuando no hay cabecera Server"). Verificado
    también contra Nmap: con esta respuesta tan genérica, Nmap tampoco
    resuelve un producto — así que esto no mide "Lybra pierde contra Nmap",
    mide "¿coinciden en no saber?", y se trata aparte del resto del catálogo
    (ver ``test_no_server_header_is_a_symmetric_blind_spot``).
    """
    port = _require_port(_NO_SERVER_HEADER_PORT)
    name = f"lybra-concordance-noserver-{port}"
    setup = "mkdir -p /www && echo hi > /www/index.html && httpd -f -p 80 -h /www"
    _docker("run", "-d", "--name", name, "-p", f"{port}:80", "busybox:latest", "sh", "-c", setup)
    try:
        wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def tls_target():
    """HTTPS con certificado autofirmado — mismo patrón que las fixtures TLS
    de ``test_lybra_oracle_bench.py``, aquí para ejercitar el dissector HTTP
    (producto/versión) sobre un handshake TLS real, no la higiene del cert."""
    port = _require_port(_TLS_PORT)
    name = f"lybra-concordance-tls-{port}"
    setup = (
        "apk add --no-cache openssl >/dev/null 2>&1 && "
        "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        "-keyout /etc/nginx/tls.key -out /etc/nginx/tls.crt -subj /CN=lybra-concordance-tls >/dev/null 2>&1 && "
        "printf '%s' 'server { listen 443 ssl; ssl_certificate /etc/nginx/tls.crt; "
        "ssl_certificate_key /etc/nginx/tls.key; location / { return 200; } }' "
        "> /etc/nginx/conf.d/default.conf && nginx -g \"daemon off;\""
    )
    _docker("run", "-d", "--name", name, "-p", f"{port}:443", "nginx:alpine", "sh", "-c", setup)
    try:
        wait_for_port("127.0.0.1", port)
        yield port
    finally:
        docker_rm(_DOCKER, name)


@pytest.fixture(scope="module")
def ssh_target():
    """OpenSSH auto-provisionado en el arranque — banner + KEXINIT reales.

    Publica el puerto 22 del host, así que se salta (no falla) si algo más ya
    lo tiene ocupado — nunca asumimos que el 22 esté libre en toda máquina.
    """
    if not port_is_free("127.0.0.1", _SSH_PORT):
        pytest.skip(f"Puerto {_SSH_PORT} no está libre para la fixture SSH")
    name = f"lybra-concordance-ssh-{_SSH_PORT}"
    setup = "apk add --no-cache openssh >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1 && /usr/sbin/sshd -D"
    _docker("run", "-d", "--name", name, "-p", f"{_SSH_PORT}:22", "alpine:latest", "sh", "-c", setup)
    try:
        _wait_for_ssh_banner("127.0.0.1", _SSH_PORT, timeout=30.0)
        yield _SSH_PORT
    finally:
        docker_rm(_DOCKER, name)


def _measure(port: int) -> tuple:
    """Run the port-discovery + fingerprint pipeline against one target,
    returning ``(port_score, fingerprint_pair_or_None)``."""
    own_ports = scan_ports_sync("127.0.0.1", [port])
    nmap_services = run_nmap_sv("127.0.0.1", [port])
    port_score = port_concordance(own_ports, list(nmap_services))

    own_fp = fingerprint_own("127.0.0.1", own_ports)
    product, version = own_fp.get(port, (None, None))
    nmap_svc = nmap_services.get(port)
    nmap_product = nmap_svc.product if nmap_svc else None
    nmap_version = nmap_svc.version if nmap_svc else None
    return port_score, (product, version, nmap_product, nmap_version)


def test_port_and_fingerprint_concordance_across_lab_catalog(
    apache_target, nginx_plain_target, nginx_no_version_target, tls_target,
):
    """Escala el N=4 ad-hoc del roadmap a un catálogo automatizado y variado:
    dos vendors (Apache, nginx), con y sin versión en la cabecera, y HTTP vs.
    HTTPS. Cada objetivo es un contenedor real, Nmap real como oráculo — nada
    mockeado, igual que el resto de ``tests/oracle/``.

    ``no_server_header_target`` se mide aparte (ver el test dedicado más
    abajo): ahí ni Lybra ni Nmap tienen señal, así que forzarlo en este
    cociente mediría "¿tenemos ambos la misma laguna?", no "¿coincidimos con
    el oráculo?" — son preguntas distintas y este test solo hace la segunda.
    """
    targets = [apache_target, nginx_plain_target, nginx_no_version_target, tls_target]
    port_scores = []
    fp_pairs = []
    details = []
    for port in targets:
        port_score, pair = _measure(port)
        port_scores.append(port_score)
        fp_pairs.append(pair)
        details.append((port, port_score, pair))

    port_score = sum(port_scores) / len(port_scores)
    fp_score = concordance_rate(fp_pairs)

    assert port_score >= 0.95, f"concordancia de puertos {port_score:.2f} — detalle: {details}"
    assert fp_score >= 0.90, f"concordancia de fingerprint {fp_score:.2f} — detalle: {details}"


def test_no_server_header_is_a_symmetric_blind_spot(no_server_header_target):
    """Documenta, en vez de ocultar, el hueco que el roadmap nombra (apartado
    6): sin cabecera ``Server`` ni ningún otro marcador reconocible, ni Lybra
    ni Nmap resuelven un producto para este objetivo. No es que Lybra pierda
    frente al oráculo — es que aquí el oráculo tampoco sabe. Sigue siendo un
    hueco real de la Fase F (falta un fallback cuando no hay ``Server``), solo
    que medirlo como "desacuerdo con Nmap" mediría la pregunta equivocada."""
    _, (product, _version, nmap_product, _nmap_version) = _measure(no_server_header_target)
    assert product is None, f"Lybra identificó '{product}' sin cabecera Server — actualizar este test"
    assert nmap_product is None, f"Nmap identificó '{nmap_product}' — el objetivo ya no es un blind spot compartido"


@pytest.mark.skipif(not port_is_free("127.0.0.1", _SSH_PORT), reason=f"puerto {_SSH_PORT} ocupado")
def test_ssh_fingerprint_concordance(ssh_target):
    """HASSH/banner (Fase F) contra un ``sshd`` real, no mockeado."""
    port_score, pair = _measure(ssh_target)
    assert port_score == 1.0
    assert concordance_rate([pair]) == 1.0, f"par (propio vs. nmap): {pair}"
