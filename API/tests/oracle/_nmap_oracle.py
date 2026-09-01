"""El oráculo: ``nmap -sV`` contra un objetivo, parseado a algo comparable.

Un banco de concordancia necesita una referencia externa contra la que medirse,
y esa referencia es Nmap: la herramienta de identificación de servicios que
todo el mundo usa, con veinte años de firmas detrás. Medirse contra ella no es
depender de ella —el motor no la invoca nunca en producción, ver L52— es la
única forma de convertir «nuestro fingerprinting es bueno» en un número.

**Nmap se ejecuta en un contenedor cuando no está en el sistema.** El banco
anterior exigía un ``nmap`` instalado en la máquina y se saltaba entero cuando
faltaba, que en la práctica significaba saltarse entero casi siempre: en un
portátil de desarrollo con Docker pero sin Nmap —el caso normal— no había
medición, y por tanto tampoco número. Como todo lo demás en ``tests/oracle/``
ya necesita Docker, el oráculo pasa a ser un contenedor más
(``instrumentisto/nmap``) y el banco deja de depender de lo que cada uno tenga
instalado. Si hay un ``nmap`` en el PATH se usa ése, que es más rápido y evita
el rodeo por la red del contenedor.

Not a test module itself (no ``test_`` prefix) — pytest does not collect it.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

# La imagen del oráculo. Se fija por nombre y no por digest a propósito: lo que
# se mide es la concordancia con *Nmap*, no con una versión congelada suya, y
# una firma nueva que cambie el resultado es información, no una regresión del
# banco.
NMAP_IMAGE = "instrumentisto/nmap"

# Cómo alcanza el contenedor de Nmap los puertos que los contenedores del
# catálogo publican en el host. Docker Desktop resuelve este nombre; en un
# runner Linux hace falta ``--add-host``, que es lo que añade _docker_args().
_HOST_FROM_CONTAINER = "host.docker.internal"


def _target_from_container(host: str) -> str:
    """El nombre con el que el contenedor de Nmap alcanza ``host``.

    Un objetivo publicado en el propio host —los contenedores del banco de
    laboratorio, siempre en 127.0.0.1— no es alcanzable por su IP de loopback
    desde dentro de otro contenedor: hay que rebotar por ``host.docker.internal``.

    Un objetivo **externo** (el banco de paridad real, L48) se alcanza por su
    nombre o IP tal cual: sustituirlo por ``host.docker.internal`` haría que el
    oráculo escaneara la máquina Docker en vez del objetivo, midiendo algo que
    no tiene nada que ver. Sólo se reescribe loopback.
    """
    try:
        if ipaddress.ip_address(host).is_loopback:
            return _HOST_FROM_CONTAINER
    except ValueError:
        if host in ("localhost", ""):
            return _HOST_FROM_CONTAINER
    return host


@dataclass(frozen=True)
class NmapService:
    """Lo que Nmap dice de un puerto: nombre de servicio, producto y versión."""
    name: Optional[str]
    product: Optional[str]
    version: Optional[str]


def run_nmap_sv(
    docker_path: Optional[str],
    ports: Iterable[int],
    host: str = "127.0.0.1",
    protocol: str = "tcp",
    timeout: float = 300.0,
) -> Dict[int, NmapService]:
    """Ejecutar ``nmap -sV`` sobre unos puertos y devolver lo que identificó.

    Args:
        docker_path: Cliente Docker con el que lanzar el oráculo en contenedor.
            Se ignora si hay un ``nmap`` instalado en el sistema.
        ports: Los puertos a examinar.
        host: El objetivo, desde el punto de vista del host.
        protocol: ``"tcp"`` o ``"udp"``. El escaneo UDP necesita privilegios,
            que el contenedor sí tiene y una sesión de usuario normal no.
        timeout: Tope para el proceso entero.

    Returns:
        Un mapa ``puerto -> NmapService`` con los puertos que respondieron.
        Un puerto cerrado o filtrado simplemente no aparece.
    """
    port_list = ",".join(str(port) for port in sorted(set(ports)))
    scan_flag = "-sU" if protocol == "udp" else "-sV"
    flags = ["-sV", "-Pn", "-p", port_list] if protocol == "tcp" else ["-sU", "-sV", "-Pn", "-p", port_list]

    local_nmap = shutil.which("nmap")
    if local_nmap:
        command = [local_nmap, *flags, "-oX", "-", host]
    else:
        if not docker_path:
            raise RuntimeError("Ni nmap instalado ni Docker disponible para el oráculo")
        command = [docker_path, "run", "--rm", NMAP_IMAGE, *flags, "-oX", "-", _target_from_container(host)]

    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
    return parse_nmap_xml(completed.stdout)


def parse_nmap_xml(document: str) -> Dict[int, NmapService]:
    """Extraer ``puerto -> NmapService`` del XML de Nmap.

    Sólo se recogen los puertos en estado ``open``: un ``filtered`` no es una
    identificación fallida, es que Nmap no llegó a hablar con nadie, y contarlo
    como desacuerdo mediría la red y no el fingerprinting.
    """
    services: Dict[int, NmapService] = {}
    root = ET.fromstring(document)
    for port_element in root.iter("port"):
        state = port_element.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_element.find("service")
        services[int(port_element.get("portid"))] = NmapService(
            name=service.get("name") if service is not None else None,
            product=service.get("product") if service is not None else None,
            version=service.get("version") if service is not None else None,
        )
    return services
