"""Shared Docker plumbing for the Lybra oracle test suite (roadmap §7).

Both modules in this package — the check-runtime oracle
(``test_lybra_oracle_bench.py``) and the F/T concordance bench
(``test_lybra_concordance_bench.py``) — need the same thing: a *working*
Docker client (not just one on PATH) and a way to wait for a published
container port to come up. Factored out once a second module needed it, so
the WSL-specific subtlety in :func:`resolve_docker` is fixed in one place.

Not a test module itself (no ``test_`` prefix) — pytest does not collect it.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from typing import Optional


def _working_docker(path: str) -> bool:
    """¿Es ``path`` un cliente Docker que además tiene demonio detrás?

    Se capturan **dos** formas de no estarlo, y la segunda costó una tarde:

    - ``OSError``: el binario no existe o no se puede ejecutar.
    - ``subprocess.TimeoutExpired``: el binario responde pero el demonio está
      **colgado**, no ausente. Es lo que hace Docker Desktop cuando su distro
      WSL no llega a arrancar: ``docker version`` se queda esperando al pipe
      hasta que alguien lo mata.

    Sin capturar la segunda, la excepción sube por ``resolve_docker()`` —que se
    llama al **importar** cada módulo del banco— y revienta la recolección de
    pytest. Y como los marcadores se filtran *después* de importar, eso tumba
    la suite entera, incluso corriendo con ``-m "not oracle"``: cinco errores de
    colección en tests que ni siquiera se iban a ejecutar. Un Docker roto tiene
    que traducirse en "los bancos se saltan", nunca en "no hay suite".
    """
    try:
        return subprocess.run(
            [path, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=10,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def resolve_docker() -> Optional[str]:
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


def docker_run(docker_path: str, *args: str) -> subprocess.CompletedProcess:
    """Run ``docker <args>``, raising on failure."""
    return subprocess.run([docker_path, *args], capture_output=True, text=True, timeout=60, check=True)


def docker_rm(docker_path: str, name: str) -> None:
    """Force-remove a container by name, best-effort (used in fixture teardown)."""
    subprocess.run([docker_path, "rm", "-f", name], capture_output=True, timeout=30)


def wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    """Block until ``host:port`` accepts a TCP connection, or raise on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(f"{host}:{port} no respondió en {timeout}s")


def port_is_free(host: str, port: int) -> bool:
    """Return whether nothing is currently listening on ``host:port``.

    A connect probe, not a bind test: binding a privileged port (<1024, e.g.
    443 or 22) needs root, which the test runner may not have even though
    Docker's own daemon can publish it just fine — a bind-based check would
    misreport those as "busy" unconditionally. Connecting answers the actual
    question ("is something already listening here") without that privilege,
    and also sidesteps a just-closed container's TIME_WAIT socket on the same
    port, which a fresh connect attempt sees as a plain refused connection.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0
