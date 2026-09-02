"""APIs de administración sin autenticar — el mejor valor por coste del backlog.

Hay una familia de servicios que reúne las tres propiedades que la deja en
cabeza de cualquier lista de coste/valor: **son HTTP** (el transporte ya existe
y funciona), **anuncian su versión en un JSON sin autenticar** (identificación
gratis) y **su exposición es en sí misma el hallazgo más grave que un escáner
puede dar**.

- **Docker en 2375** sin TLS ni autenticación es ejecución remota de código
  como root, sin exploit ninguno: un ``POST /containers/create`` con el sistema
  de ficheros del host montado y ya está. Es de las cosas más graves que se
  pueden encontrar en una red interna.
- **Elasticsearch en 9200** sin autenticación expone —y permite borrar— todos
  los índices. Su ``GET /`` devuelve la versión exacta.
- **Kubernetes en 6443**, **etcd en 2379**, **Consul en 8500** y **Kibana en
  5601** siguen el mismo patrón.

Hasta L17 el motor veía ``2375/tcp abierto — docker`` (el nombre salía de
``WELL_KNOWN_PORTS``, así que hasta lo llamaba por su nombre) y emitía un
informativo con ``qod=30``. La información para dar un CRITICAL confirmado
estaba a un ``GET`` de distancia y no se pedía, porque ``is_http_service``
rechazaba esos puertos y ni el dissector HTTP ni los checks los tocaban.

**Todo lo que hay aquí son lecturas puras** (``GET``), así que caben en modo
``safe`` sin discusión. Y la versión extraída entra en la maquinaria de
detección por versión que ya funciona, y produce sus CVEs sola: escribir
*ojos*, no checks, que es el apalancamiento que el roadmap describe.

**Una respuesta 401 o 403 no es un hallazgo, es lo contrario.** Significa que
el servicio está ahí y que exige credenciales, que es exactamente como debe
estar. Este módulo no identifica producto en ese caso y no emite exposición
ninguna; los checks del feed exigen un 200 con contenido reconocible.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..checks import HttpProbe, Response, is_admin_api_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AdminApi:
    """Una API de administración: dónde escucha, qué se le pide y qué se lee.

    Attributes:
        product: El nombre del producto tal y como debe llegar al hallazgo.
        path: La ruta que se pide, siempre un ``GET`` sin efectos.
        version_path: La ruta dentro del JSON de respuesta donde vive la
            versión, como secuencia de claves. ``("version", "number")``
            significa ``respuesta["version"]["number"]``.
    """
    product: str
    path: str
    version_path: Tuple[str, ...]


# Puerto → API que se espera encontrar ahí. Una fila por producto, y **una sola
# petición por puerto**: el mapa evita probar las seis rutas contra los seis
# puertos, que sería multiplicar por seis el coste para no aprender nada nuevo.
#
# El 8080 de Kubernetes (su puerto "inseguro" histórico) queda fuera a
# propósito: es también el puerto HTTP alternativo más común que existe, y
# reclamarlo aquí le quitaría a la sonda HTTP genérica un puerto que casi
# siempre es un servidor web corriente.
ADMIN_APIS: Dict[int, AdminApi] = {
    2375: AdminApi("Docker", "/version", ("Version",)),
    2376: AdminApi("Docker", "/version", ("Version",)),
    9200: AdminApi("Elasticsearch", "/", ("version", "number")),
    5601: AdminApi("Kibana", "/api/status", ("version", "number")),
    6443: AdminApi("Kubernetes", "/version", ("gitVersion",)),
    2379: AdminApi("etcd", "/version", ("etcdserver",)),
    8500: AdminApi("Consul", "/v1/agent/self", ("Config", "Version")),
}


def _value_at(payload: Any, path: Tuple[str, ...]) -> Optional[str]:
    """Lee un valor anidado de un JSON ya parseado, sin reventar por el camino.

    Args:
        payload: El JSON decodificado.
        path: Las claves a recorrer, en orden.

    Returns:
        El valor como texto, o ``None`` si la ruta no existe o no es texto.
    """
    for key in path:
        if not isinstance(payload, dict):
            return None
        payload = payload.get(key)
    if isinstance(payload, (str, int, float)):
        return str(payload)
    return None


def _clean_version(version: Optional[str]) -> Optional[str]:
    """Normaliza la versión que estas APIs publican.

    Kubernetes la da como ``"v1.28.4"`` y etcd como ``"3.5.9"``; la ``v`` de
    delante sobra para buscar un CPE, y dejarla haría que ``1.28.4`` y
    ``v1.28.4`` fueran dos versiones distintas para el matcher.
    """
    if not version:
        return None
    version = version.strip()
    if version[:1].lower() == "v" and version[1:2].isdigit():
        version = version[1:]
    return version or None


def fingerprint_admin_api(port: int, response: Optional[Response]) -> Optional[DissectorResult]:
    """Identifica una API de administración a partir de su respuesta JSON.

    Args:
        port: El puerto sondado, que decide qué API se esperaba.
        response: La respuesta HTTP, o ``None`` si la petición falló.

    Returns:
        La identificación, o ``None`` cuando el puerto no está en el mapa, la
        petición falló, el servicio exigió credenciales (401/403) o el cuerpo
        no es el JSON que ese producto publica.
    """
    api = ADMIN_APIS.get(port)
    if api is None or response is None:
        return None
    if response.status != 200:
        # 401/403 significa "existe y pide credenciales", que es como debe
        # estar. No es un hallazgo, y tampoco una identificación: sin cuerpo
        # legible no se ha observado ninguna versión.
        logger.debug("API de administración en %s contestó %s", port, response.status)
        return None
    try:
        payload = json.loads(response.body or "")
    except (ValueError, TypeError):
        return None
    version = _clean_version(_value_at(payload, api.version_path))
    if version is None:
        return None
    return DissectorResult(api.product, version, f"{api.product} API")


@register_dissector
class AdminApiDissector(Dissector):
    """Un ``GET`` sin autenticar contra la API de administración de su puerto.

    Se registra **antes** que :class:`~.http.HttpDissector` a propósito: los
    puertos de esta familia también entran ahora en ``is_http_service`` —para
    que los checks de exposición y de higiene TLS los alcancen— y el motor se
    queda con el primer dissector que reclame el servicio. Sin esa precedencia,
    la sonda HTTP genérica se llevaría el 2375 y leería una cabecera ``Server``
    en vez de la versión que el JSON publica.
    """

    label = "Admin API"

    def __init__(self, probe: Optional[HttpProbe] = None) -> None:
        self._probe = probe or HttpProbe()

    def applies(self, service) -> bool:
        return is_admin_api_service(service)

    def probe(self, target, service, rate_limiter):
        api = ADMIN_APIS.get(service.port)
        if api is None:
            return None
        rate_limiter.acquire(target)
        response = self._probe.fetch(target, service.port, "GET", api.path)
        if response is None:
            return None
        return fingerprint_admin_api(service.port, response)
