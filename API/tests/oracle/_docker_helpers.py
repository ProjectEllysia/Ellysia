"""Shared Docker plumbing for the Lybra oracle test suite.

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
from typing import Dict, Optional


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


# Qué contenedor del banco publica cada puerto. Lo rellena remember_container()
# al arrancar cada objetivo y sólo se lee para diagnosticar: es lo que permite
# que un "no respondió en 240s" diga además *por qué* no había nadie al otro
# lado. Ver diagnose_port().
_CONTAINERS_BY_PORT: Dict[int, str] = {}


def remember_container(port: int, name: str) -> None:
    """Apuntar que ``name`` es el contenedor que publica ``port``.

    Sin este apunte, los esperadores de este módulo sólo pueden informar de que
    un puerto no contestó, que es el síntoma y nunca la causa. Con él pueden
    mirar si el contenedor sigue vivo y adjuntar su log. Ya pasó: el objetivo
    de ProFTPD moría al arrancar y el banco lo comunicaba como un timeout de
    cuatro minutos contra un puerto, sin una sola línea sobre el contenedor.
    """
    _CONTAINERS_BY_PORT[port] = name


def container_is_running(docker_path: str, name: str) -> bool:
    """¿Sigue en marcha el contenedor ``name``?

    Un contenedor que no existe cuenta como no arrancado, no como error: las
    fixtures borran los suyos al terminar, y preguntar por uno ya retirado es
    normal.
    """
    completed = subprocess.run(
        [docker_path, "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True, timeout=30,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def container_diagnosis(docker_path: str, name: str) -> str:
    """Por qué murió el contenedor ``name``, en una cadena para un mensaje de error.

    Devuelve el estado con el que terminó y el final de su salida, que es donde
    están las cosas que de verdad explican un arranque fallido: un paquete que
    no existe en el índice de la distribución, un usuario que la configuración
    nombra y el sistema no tiene, un fichero de configuración que no parsea.
    """
    state = subprocess.run(
        [docker_path, "inspect", "-f", "{{.State.Status}} (código {{.State.ExitCode}})", name],
        capture_output=True, text=True, timeout=30,
    )
    if state.returncode != 0:
        return f"el contenedor {name} ya no existe"

    logs = subprocess.run(
        [docker_path, "logs", "--tail", "40", name],
        capture_output=True, text=True, timeout=30,
    )
    output = (logs.stdout + logs.stderr).strip() or "(sin salida)"
    return f"contenedor {name}: {state.stdout.strip()}\n--- docker logs --tail 40 ---\n{output}"


def diagnose_port(docker_path: Optional[str], port: int) -> str:
    """El diagnóstico del contenedor que publica ``port``, si se sabe cuál es.

    Cadena vacía cuando no hay nada que añadir, para poder concatenarla sin
    condicionales en el sitio donde se construye el mensaje de error.
    """
    name = _CONTAINERS_BY_PORT.get(port)
    if not name or not docker_path:
        return ""
    return "\n" + container_diagnosis(docker_path, name)


def container_died(docker_path: Optional[str], port: int) -> bool:
    """¿Ha muerto ya el contenedor que publica ``port``?

    Sirve para rendirse pronto. Los esperadores del banco dan plazos largos a
    propósito —un objetivo se instala sus paquetes dentro del contenedor y eso
    tarda—, pero esperar el plazo entero a un contenedor que ya no existe sólo
    retrasa el diagnóstico: cuatro minutos por objetivo caído, multiplicados por
    la veintena que levanta el banco nocturno.

    Un puerto del que no se sabe nada nunca se da por muerto: la respuesta por
    defecto tiene que ser «sigue esperando», que es el comportamiento de antes.
    """
    name = _CONTAINERS_BY_PORT.get(port)
    if not name or not docker_path:
        return False
    return not container_is_running(docker_path, name)


def wait_for_port(host: str, port: int, timeout: float = 30.0,
                  docker_path: Optional[str] = None) -> None:
    """Block until ``host:port`` accepts a TCP connection, or raise on timeout.

    Args:
        host: El anfitrión donde el contenedor publica el puerto.
        port: El puerto publicado.
        timeout: Cuánto esperar antes de rendirse.
        docker_path: Cliente Docker con el que diagnosticar el contenedor si
            no llega a contestar. Opcional: sin él el fallo sigue siendo un
            timeout a secas, como antes.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            if container_died(docker_path, port):
                raise TimeoutError(
                    f"{host}:{port} no respondió: su contenedor no sigue en "
                    f"marcha.{diagnose_port(docker_path, port)}"
                ) from None
            time.sleep(0.3)
    raise TimeoutError(f"{host}:{port} no respondió en {timeout}s{diagnose_port(docker_path, port)}")


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
