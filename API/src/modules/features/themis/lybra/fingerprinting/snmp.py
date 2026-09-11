"""El dissector SNMP — sobre la sonda UDP mínima de ``transport.py``.

Lee la respuesta de un GetRequest SNMP v2c para el OID
``1.3.6.1.2.1.1.1.0`` (``sysDescr.0``) — el codificador del mensaje vive en
``transport.py`` (:func:`~.transport.build_snmp_get_request`), no aquí: la
tabla de sondas UDP (``UDP_PROBES``) necesita ese payload para el descubrimiento
de puertos, y ``transport.py`` es la capa base de la que ``fingerprinting/``
ya depende — meter el payload aquí e importarlo desde `transport.py` crearía
un ciclo (`transport -> snmp -> transport`). El formato es BER/ASN.1, público
y estable, así que esto es un parser de bytes en el mismo espíritu que el
dissector SMB (MS-SMB2 a mano) o el de SSH (``SSH_MSG_KEXINIT`` a mano): sin
librería de protocolo de por medio. No se añade ``pysnmp`` ni ninguna
dependencia nueva.

**Una sola sonda sirve al dissector y al check de comunidad por defecto**
(``script_checks.py``): que ``sysDescr`` conteste a la comunidad ``public`` ES
las dos cosas a la vez —la identificación y la prueba de que la comunidad por
defecto funciona—. Dos sondas mandarían el mismo datagrama y una tiraría la
respuesta a la basura.

Qué NO soporta, deliberadamente:

- **SNMPv3** — usa USM (autenticación/cifrado) con una estructura de mensaje
  completamente distinta a v1/v2c.
- **SNMPv1** (``version=0``) — solo se construye v2c; un agente que hable
  únicamente v1 no contestará.
- **GETNEXT/GETBULK** (paseos de MIB), tablas, varbinds múltiples.
- Cualquier OID que no sea ``sysDescr.0``, e inspección de ``error-status``.

Lee un escalar y nada más.

**La versión se interpreta con un feed de patrones por fabricante, nunca con
una regex genérica.** El mayor argumento de valor de SNMP es que su
``sysDescr`` trae producto y versión enteros en una sola lectura; extraer esa
versión con una regex genérica sobre texto libre envenenaría el matcher de
CPE, así que el dissector solo la reconoce cuando un patrón concreto de
fabricante la confirma.

``feeds/sysdescr_patterns.json`` resuelve las dos cosas a la vez: patrones
**por fabricante**, no un extractor general. Un formato concreto de un
fabricante concreto es estable aunque el texto libre en general no lo sea. Y
SNMP es donde vive la superficie que más se le escapa a un escaneo por banner
—switches, routers, impresoras, SAIs, cámaras—, justo los activos que un
cliente no sabe que tiene.

Las tres reglas del feed, que son las que evitan el envenenamiento del
matcher de CPE, están escritas en el propio fichero. La tercera es la que
sostiene a las otras dos: cada patrón entra con una muestra, y el test
comprueba que casa con la suya y que **no** casa con la de ningún otro.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Pattern

from ..checks import is_snmp_service
from ..transport import build_snmp_get_request, udp_send_recv
from .dispatch import Dissector, DissectorResult, QOD_FINGERPRINT
from .registry import register_dissector

logger = logging.getLogger(__name__)

# El mismo TLV que transport.py codifica dentro del GetRequest — se reutiliza
# aquí como ancla para localizar el varbind de respuesta sin parsear BER
# completo (ver parse_snmp_sysdescr).
_SYSDESCR_OID_TLV = bytes.fromhex("06082b06010201010100")

# El feed de patrones, junto al resto de feeds de Lybra. Dos directorios
# arriba: fingerprinting/snmp.py -> lybra/feeds/.
_BUNDLED_SYSDESCR_PATTERNS = Path(__file__).parent.parent / "feeds" / "sysdescr_patterns.json"

# El ``qod`` de una versión extraída por un patrón específico del producto: 80,
# por encima del 70 de un CPE genérico y por debajo de una evidencia
# confirmada activamente.
QOD_VENDOR_PATTERN = 80


@dataclass(frozen=True)
class SysDescrPattern:
    """Un patrón de ``sysDescr`` para un fabricante.

    Attributes:
        vendor: El fabricante, en minúsculas.
        product: El nombre canónico del producto que este patrón identifica.
        pattern: La expresión regular, ya compilada. Puede tener un grupo
            llamado ``version``; si no lo tiene, el patrón aporta sólo el
            producto — que ya es mucho más que el texto crudo.
        sample: Un ``sysDescr`` con la forma documentada de ese fabricante.
            **Obligatorio**: sin muestra no hay patrón, porque sin muestra no
            hay forma de comprobar ni que casa ni que no casa de más.
    """
    vendor: str
    product: str
    pattern: Pattern
    sample: str


@dataclass(frozen=True)
class SysDescrMatch:
    """Lo que un patrón aporta cuando reconoce un ``sysDescr``."""
    vendor: str
    product: str
    version: Optional[str]


def load_sysdescr_patterns(path: Optional[str] = None) -> List[SysDescrPattern]:
    """Carga el feed de patrones de ``sysDescr``.

    Args:
        path: Ruta a un fichero de feed. Por defecto, el empaquetado.

    Returns:
        Los patrones, en el orden del fichero — que es el orden en que se
        prueban.
    """
    feed_path = Path(path) if path else _BUNDLED_SYSDESCR_PATTERNS
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    return [
        SysDescrPattern(
            vendor=entry["vendor"],
            product=entry["product"],
            pattern=re.compile(entry["pattern"], re.DOTALL),
            sample=entry.get("sample", ""),
        )
        for entry in data.get("patterns", [])
    ]


def validate_sysdescr_patterns(patterns: List[SysDescrPattern]) -> List[str]:
    """Comprueba que cada patrón esté completo y case con su propia muestra.

    Mismo criterio que los demás feeds de Lybra: su modo de fallo es el
    silencio. Un patrón que no casa con nada no identifica nada, el escaneo
    termina en verde y nadie se entera.

    La comprobación de la muestra es la que da sentido a la regla del feed:
    un patrón que no reconoce ni el ejemplo que lo acompaña no va a reconocer
    un aparato de verdad.

    Args:
        patterns: Los patrones cargados.

    Returns:
        Una lista de problemas legibles, vacía si el feed está bien formado.
    """
    problems: List[str] = []
    for entry in patterns:
        name = entry.product or entry.pattern.pattern
        if not entry.product:
            problems.append(f"Patrón sin producto: {entry.pattern.pattern}")
        if not entry.vendor:
            problems.append(f"{name}: sin fabricante declarado")
        if not entry.sample:
            problems.append(f"{name}: sin muestra de sysDescr — sin muestra no hay patrón")
            continue
        if not entry.pattern.search(entry.sample):
            problems.append(f"{name}: el patrón no casa con su propia muestra")
    return problems


_SYSDESCR_PATTERNS: List[SysDescrPattern] = load_sysdescr_patterns()


def match_sysdescr(sysdescr: str) -> Optional[SysDescrMatch]:
    """Reconoce un ``sysDescr`` con el primer patrón del feed que case.

    Args:
        sysdescr: El texto tal cual lo devolvió el agente.

    Returns:
        La identificación, o ``None`` si ningún patrón lo reconoce — que es el
        caso importante: entonces no hay producto de catálogo y, sobre todo,
        no hay versión.
    """
    for entry in _SYSDESCR_PATTERNS:
        found = entry.pattern.search(sysdescr or "")
        if not found:
            continue
        version = found.groupdict().get("version") if found.groupdict() else None
        return SysDescrMatch(vendor=entry.vendor, product=entry.product, version=version)
    return None


def _read_length(data: bytes, offset: int) -> Optional[tuple]:
    """Lee una longitud BER (forma corta o larga) empezando en ``offset``.

    Returns:
        ``(longitud, offset_tras_el_campo_de_longitud)``, o ``None`` si
        ``data`` no alcanza para leerla.
    """
    if offset >= len(data):
        return None
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        return None
    length = int.from_bytes(data[offset + 1: offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def parse_snmp_sysdescr(reply: bytes) -> Optional[str]:
    """Extrae el ``sysDescr`` de bytes crudos de respuesta SNMP.

    No es un parser BER general: localiza el TLV del OID que la propia
    petición envió (el agente lo repite en el varbind de respuesta) y lee la
    etiqueta que le sigue directamente, en vez de recorrer la estructura
    completa del mensaje.

    Args:
        reply: Los bytes crudos recibidos del agente.

    Returns:
        El valor de ``sysDescr`` decodificado, o ``None`` si la respuesta no
        trae el OID, o si el valor es una etiqueta que no es OCTET STRING
        (``NULL`` sin valor, ``noSuchObject``/``noSuchInstance``/
        ``endOfMibView``), o si está truncada.
    """
    index = reply.find(_SYSDESCR_OID_TLV)
    if index == -1:
        return None
    value_tag_offset = index + len(_SYSDESCR_OID_TLV)
    if value_tag_offset >= len(reply):
        return None
    tag = reply[value_tag_offset]
    if tag != 0x04:  # no es OCTET STRING: NULL (0x05) o un error de contexto (0x80/0x81/0x82)
        return None
    parsed = _read_length(reply, value_tag_offset + 1)
    if parsed is None:
        return None
    length, value_offset = parsed
    if value_offset + length > len(reply):
        return None
    return reply[value_offset: value_offset + length].decode("utf-8", "ignore") or None


@dataclass(frozen=True)
class SnmpFingerprint:
    """El resultado de fingerprintear un servicio SNMP.

    Attributes:
        product: El nombre canónico del producto cuando un patrón del feed
            reconoce el ``sysDescr``; el texto crudo cuando no, porque un
            ``sysDescr`` sin reconocer sigue siendo el dato más informativo que
            hay sobre ese aparato. ``None`` si no se pudo leer nada.
        version: La versión que el patrón capturó, o ``None``. **Nunca sale de
            una regex genérica**: ver :func:`match_sysdescr`.
        confidence: Confianza 0.0-1.0 autoevaluada.
        vendor: El fabricante que el patrón identificó, o ``None``.
        matched_pattern: Si un patrón del feed reconoció el texto. Es lo que
            decide el ``qod`` del hallazgo, y no puede deducirse de los demás
            campos: un patrón puede casar y no capturar versión.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float
    vendor: Optional[str] = None
    matched_pattern: bool = False


def fingerprint_snmp(sysdescr: Optional[str]) -> SnmpFingerprint:
    """Fingerprintea un servicio SNMP a partir de su ``sysDescr``.

    La versión sale **sólo** de un patrón por fabricante del feed
    (``feeds/sysdescr_patterns.json``). Si ningún patrón casa, el producto es
    el texto crudo y la versión es ``None`` — nunca un ``split()`` esperanzado.
    Ésa es la regla que mantiene en pie la cautela original: ``sysDescr`` es
    texto libre, y una versión inventada de ahí alimentaría al matcher CPE→CVE
    con datos falsos, que es justo el falso positivo que este motor existe para
    no producir.

    Args:
        sysdescr: El texto que devolvió el agente, o ``None``.

    Returns:
        El :class:`SnmpFingerprint`.
    """
    if not sysdescr:
        return SnmpFingerprint(product=None, version=None, confidence=0.0)
    matched = match_sysdescr(sysdescr)
    if matched is None:
        return SnmpFingerprint(product=sysdescr, version=None, confidence=0.9)
    return SnmpFingerprint(
        product=matched.product,
        version=matched.version,
        confidence=0.9,
        vendor=matched.vendor,
        matched_pattern=True,
    )


# =========================================================================
# SONDA (el borde de red: socket UDP crudo, sin librería SNMP)
# =========================================================================

class SnmpProbe:  # pylint: disable=too-few-public-methods
    """Envía un GetRequest de ``sysDescr.0`` y lee la respuesta por UDP.

    Args:
        timeout: Timeout de la operación, en segundos.
        sender: Callable inyectable ``(host, port, payload, timeout) ->
            Optional[bytes]``. Por defecto, ``transport.udp_send_recv``.
    """

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 161, community: str = "public") -> Optional[str]:
        """Consulta ``sysDescr.0`` con la comunidad dada.

        Returns:
            El ``sysDescr`` decodificado, o ``None`` si el agente no
            contestó o la respuesta no se pudo interpretar.
        """
        reply = self._sender(host, port, build_snmp_get_request(community), self._timeout)
        if reply is None:
            return None
        return parse_snmp_sysdescr(reply)


@register_dissector
class SnmpDissector(Dissector):
    label = "SNMP"

    def __init__(self, probe: Optional[SnmpProbe] = None) -> None:
        self._probe = probe or SnmpProbe()

    def applies(self, service) -> bool:
        return is_snmp_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        sysdescr = self._probe.fetch(target, service.port or 161)
        if sysdescr is None:
            return None
        fingerprint = fingerprint_snmp(sysdescr)
        if fingerprint.product is None:
            return None
        return DissectorResult(
            fingerprint.product,
            fingerprint.version,
            self.label,
            # Un patrón específico del producto vale más que la constante de
            # fingerprint; un sysDescr sin reconocer, no.
            qod=QOD_VENDOR_PATTERN if fingerprint.matched_pattern else QOD_FINGERPRINT,
        )
