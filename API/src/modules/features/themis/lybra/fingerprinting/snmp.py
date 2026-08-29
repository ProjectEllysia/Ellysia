"""El dissector SNMP — Fase N/Ronda 1 (roadmap §6.3), sobre la sonda UDP de la
Fase T mínima que este mismo cambio añade a ``transport.py``.

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
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from ..checks import is_snmp_service
from ..transport import build_snmp_get_request, udp_send_recv
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# El mismo TLV que transport.py codifica dentro del GetRequest — se reutiliza
# aquí como ancla para localizar el varbind de respuesta sin parsear BER
# completo (ver parse_snmp_sysdescr).
_SYSDESCR_OID_TLV = bytes.fromhex("06082b06010201010100")


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
        product: El ``sysDescr`` crudo, o ``None`` si no se pudo leer.
        version: Siempre ``None`` — ver el docstring del módulo y
            :func:`fingerprint_snmp` sobre por qué no se intenta extraer una
            versión de un texto libre.
        confidence: Confianza 0.0-1.0 autoevaluada.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def fingerprint_snmp(sysdescr: Optional[str]) -> SnmpFingerprint:
    """Fingerprintea un servicio SNMP a partir de su ``sysDescr``.

    ``version`` es siempre ``None``, a propósito. ``sysDescr`` es texto libre
    del fabricante (``"Linux host 5.15.0-84-generic #93-Ubuntu SMP ..."``,
    ``"Hardware: Intel64 ... Windows Version 6.3"``) y cualquier expresión
    regular sobre él alimentaría al matcher CPE→CVE con una versión inventada
    — el tipo de falso positivo que este motor existe para no producir. Con
    ``version=None``, ``_fingerprint_services`` no rellena el servicio y el
    aporte queda en un hallazgo informativo honesto.

    ponytail: extraer versión de sysDescr necesitaría un feed de firmas por
    fabricante (al estilo de tech_signatures.json), no una regex genérica;
    súbelo el día que haga falta identificación de SO vía SNMP.
    """
    if not sysdescr:
        return SnmpFingerprint(product=None, version=None, confidence=0.0)
    return SnmpFingerprint(product=sysdescr, version=None, confidence=0.9)


# =========================================================================
# SONDA (el borde de red: socket UDP crudo, sin librería SNMP)
# =========================================================================

class SnmpProbe:
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
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
