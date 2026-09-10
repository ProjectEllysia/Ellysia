"""El oráculo: ``nmap -sV`` contra un objetivo, parseado a algo comparable.

Un banco de concordancia necesita una referencia externa contra la que medirse,
y esa referencia es Nmap: la herramienta de identificación de servicios que
todo el mundo usa, con veinte años de firmas detrás. Medirse contra ella no es
depender de ella —el motor no la invoca nunca en producción, ver la nota sobre
objetivos externos en ``_target_from_container``— es la única forma de
convertir «nuestro fingerprinting es bueno» en un número.

**Nmap se ejecuta en un contenedor cuando no está en el sistema.** Como todo
lo demás en ``tests/oracle/`` ya necesita Docker, el oráculo es un contenedor
más (``instrumentisto/nmap``) y el banco no depende de lo que cada uno tenga
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
from typing import Dict, Iterable, List, Optional

# La imagen del oráculo. Se fija por nombre y no por digest a propósito: lo que
# se mide es la concordancia con *Nmap*, no con una versión congelada suya, y
# una firma nueva que cambie el resultado es información, no una regresión del
# banco.
NMAP_IMAGE = "instrumentisto/nmap"

# Cómo alcanza el contenedor de Nmap los puertos que los contenedores del
# catálogo publican en el host. Docker Desktop resuelve este nombre por su
# cuenta; Docker sobre Linux no, y hay que pedirlo con ``--add-host``. Lo añade
# _docker_args(), que existe justamente para eso.
_HOST_FROM_CONTAINER = "host.docker.internal"


def _target_from_container(host: str) -> str:
    """El nombre con el que el contenedor de Nmap alcanza ``host``.

    Un objetivo publicado en el propio host —los contenedores del banco de
    laboratorio, siempre en 127.0.0.1— no es alcanzable por su IP de loopback
    desde dentro de otro contenedor: hay que rebotar por ``host.docker.internal``.

    Un objetivo **externo** (el banco de paridad contra un objetivo real) se
    alcanza por su nombre o IP tal cual: sustituirlo por
    ``host.docker.internal`` haría que el oráculo escaneara la máquina Docker
    en vez del objetivo, midiendo algo que no tiene nada que ver. Sólo se
    reescribe loopback.
    """
    try:
        if ipaddress.ip_address(host).is_loopback:
            return _HOST_FROM_CONTAINER
    except ValueError:
        if host in ("localhost", ""):
            return _HOST_FROM_CONTAINER
    return host


def _docker_args(docker_path: str) -> List[str]:
    """El ``docker run`` con el que se lanza el oráculo, hasta la imagen.

    Todo lo interesante está en ``--add-host``. Un contenedor no alcanza por
    ``127.0.0.1`` los puertos que otro publica en la máquina anfitriona —ese
    loopback es el suyo propio—, así que hay que rebotar por el nombre
    ``host.docker.internal``. Docker Desktop lo inyecta él solo en todos los
    contenedores; **Docker sobre Linux no**, y ahí el nombre simplemente no
    resuelve salvo que se mapee a mano contra la puerta de enlace del host,
    que es lo que significa el valor mágico ``host-gateway``.

    Sin esta bandera, en un runner Linux el oráculo se quedaba sin objetivo, y
    el modo de fallo era el peor posible: Nmap, ante un nombre que no resuelve,
    avisa por la salida de error, escribe un XML perfectamente válido sin ni un
    host dentro y **termina con código 0**. Nada lanzaba, el banco leía «Nmap
    no identificó nada» y lo apuntaba como desacuerdo de fingerprint. Tres
    tests de concordancia fallaban cada noche por una discrepancia que no
    existía.

    En Docker Desktop la bandera es redundante pero inocua: mapea a la misma
    puerta de enlace que ya estaba puesta.
    """
    return [
        docker_path, "run", "--rm",
        "--add-host", f"{_HOST_FROM_CONTAINER}:host-gateway",
        NMAP_IMAGE,
    ]


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
    flags = ["-sV", "-Pn", "-p", port_list] if protocol == "tcp" else ["-sU", "-sV", "-Pn", "-p", port_list]

    local_nmap = shutil.which("nmap")
    if local_nmap:
        command = [local_nmap, *flags, "-oX", "-", host]
        target = host
    else:
        if not docker_path:
            raise RuntimeError("Ni nmap instalado ni Docker disponible para el oráculo")
        target = _target_from_container(host)
        command = [*_docker_args(docker_path), *flags, "-oX", "-", target]

    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
    assert_target_was_scanned(completed.stdout, completed.stderr, target)
    return parse_nmap_xml(completed.stdout)


def assert_target_was_scanned(document: str, error_output: str, target: str) -> None:
    """Comprobar que el oráculo llegó a mirar el objetivo, y no a otra cosa.

    Hay dos formas muy distintas de que ``run_nmap_sv`` devuelva un mapa vacío,
    y confundirlas es lo que tuvo el banco nocturno en rojo tres noches:

    - **El puerto no está abierto.** Es un resultado legítimo, y el que la
      documentación de :func:`parse_nmap_xml` describe: Nmap habló con el
      objetivo y no encontró nada escuchando.
    - **Nmap no llegó al objetivo.** El nombre no resolvió, o la red del
      contenedor no alcanza al host. Aquí no hay medición ninguna, pero el
      resultado es indistinguible del anterior si sólo se miran los puertos: un
      diccionario vacío que el banco interpreta como «Nmap no supo identificar
      el servicio» y anota como desacuerdo con el motor.

    Lo que separa un caso del otro es el elemento ``<host>``. Como el oráculo
    escanea siempre con ``-Pn``, Nmap da el objetivo por vivo sin comprobarlo y
    emite su ``<host>`` incluso cuando todos los puertos salen cerrados o
    filtrados; que **no haya ni uno** sólo puede significar que no hubo objetivo
    que escanear. Esto se convierte en una excepción a propósito: un oráculo que
    no midió tiene que interrumpir el banco, nunca aportar un cero a la cifra.

    Args:
        document: El XML que escribió Nmap.
        error_output: Su salida de error, que es donde explica por qué no
            resolvió el nombre. Se adjunta al mensaje porque sin ella el fallo
            obliga a reproducirlo a mano.
        target: El objetivo tal y como se le pasó a Nmap.

    Raises:
        RuntimeError: Si Nmap no escaneó ningún host.
    """
    if next(ET.fromstring(document).iter("host"), None) is not None:
        return
    raise RuntimeError(
        f"El oráculo de Nmap no escaneó ningún host para {target!r}: no llegó a "
        f"medir nada, así que su silencio no es un desacuerdo de fingerprint. "
        f"Salida de error de Nmap: {error_output.strip() or '(vacía)'}"
    )


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
