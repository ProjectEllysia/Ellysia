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

import os
import shutil
import socket
import subprocess
import time
from typing import Optional

import pytest

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.themis.lybra import scan_ports_sync, port_concordance
from src.modules.themis.managers import LybraEngineManager, AuthorizedTargetManager
from src.modules.themis.repositories import ScanRepository, KbRepository

pytestmark = [pytest.mark.oracle, pytest.mark.integration]


def _working_docker(path: str) -> bool:
    try:
        return subprocess.run(
            [path, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=10,
        ).returncode == 0
    except OSError:
        return False


def _resolve_docker() -> Optional[str]:
    """Find a *working* ``docker`` client, including the WSL⇄Windows interop path.

    ``shutil.which("docker")`` alone is not enough here: Docker Desktop installs
    a thin shim at the front of ``PATH`` in every WSL distro (even ones without
    its "WSL integration" enabled) that just prints a "not found, enable WSL
    integration" message and exits 1 — a real, executable, on-PATH file that is
    still not a working docker client. In this repo's dev setup that shim wins
    over the real Windows-side binary, reachable via the ``/mnt/c/...`` interop
    mount, unless it's actually invoked and checked. On a native Linux CI
    runner none of this applies and the first candidate just works.
    """
    for candidate in (
        shutil.which("docker"),
        "/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe",
    ):
        if candidate and os.path.exists(candidate) and _working_docker(candidate):
            return candidate
    return None


_DOCKER = _resolve_docker()
_NMAP = shutil.which("nmap")

pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([_DOCKER, *args], capture_output=True, text=True, timeout=60, check=True)


# is_http_service() (checks.py) only recognises a fixed port set for HTTP
# fingerprinting/active checks — a container published on a fully random
# ephemeral port would be discovered (open_port) but never actually probed.
# Picking a free port *from that set* keeps both true: recognised as HTTP,
# and not hard-coded onto a port something else on the host might be using.
_CANDIDATE_HTTP_PORTS = (8080, 8000, 8888, 8008, 8443)
_claimed_ports: set = set()


def _free_http_port() -> int:
    for port in _CANDIDATE_HTTP_PORTS:
        if port in _claimed_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
        _claimed_ports.add(port)
        return port
    raise RuntimeError(f"Ninguno de los puertos HTTP candidatos está libre: {_CANDIDATE_HTTP_PORTS}")


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(f"{host}:{port} no respondió en {timeout}s")


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
        subprocess.run([_DOCKER, "rm", "-f", name], capture_output=True, timeout=30)


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
        subprocess.run([_DOCKER, "rm", "-f", name], capture_output=True, timeout=30)


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
