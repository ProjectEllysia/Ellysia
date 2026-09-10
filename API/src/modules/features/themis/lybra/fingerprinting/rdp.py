"""El dissector de RDP — el hallazgo que puede acabar en una llamada de teléfono.

Implementar RDP tiene un coste medio-alto, pero por impacto real merece
prioridad alta: es el vector de entrada de la mayoría de los incidentes de
ransomware que empiezan por acceso remoto, y **BlueKeep** (CVE-2019-0708)
sigue apareciendo en redes reales siete años después.

**RDP sin NLA es el hallazgo.** NLA (*Network Level Authentication*) obliga a
autenticarse **antes** de que se cree la sesión gráfica. Sin él, cualquiera que
alcance el puerto llega a la pantalla de login, lo que habilita fuerza bruta y
toda la familia de vulnerabilidades pre-autenticación de la que BlueKeep es el
ejemplo canónico. Un RDP expuesto a internet sin NLA es, por sí solo, un
hallazgo que justifica un informe entero.

**Cómo se observa.** Un ``X.224 Connection Request`` con un ``RDP_NEG_REQ``
anuncia qué protocolos de seguridad soporta el cliente, y el servidor contesta
**cuál ha elegido** — o por qué no elige ninguno. Es la sonda más compleja de
este paquete (``TPKT`` + ``X.224`` + negociación), pero su resultado
es binario y sin ambigüedad, que es justo lo contrario de un banner de texto
libre: no hay nada que interpretar, el servidor dice un número.

============================== ==========================================
Protocolo elegido              Qué significa
============================== ==========================================
``HYBRID`` / ``HYBRID_EX``     NLA exigido. Es la postura correcta.
``SSL``                        TLS, pero **sin** NLA.
``RDP``                        Seguridad RDP estándar, sin TLS siquiera.
============================== ==========================================

Un ``RDP_NEG_FAILURE`` tampoco es un callejón sin salida: sus códigos
(:data:`FAILURE_CODES`) dicen igual de bien qué exige el servidor —
``HYBRID_REQUIRED_BY_SERVER`` es, de hecho, la mejor noticia posible.

**Sobre la versión: este intercambio no la da, y no se inventa.** La
negociación de X.224 ocurre antes de cualquier intercambio de capacidades, así
que el dissector reporta producto sin versión. Cuando el servidor negocia TLS,
el certificado que presenta suele traer el nombre del equipo — pero eso es un
handshake TLS aparte, y se deja fuera de esta sonda a propósito.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from ..checks import is_rdp_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# TPKT (RFC 1006): versión 3, un byte reservado y la longitud total en 16 bits
# big-endian. Es el sobre que lleva un TPDU de X.224 sobre TCP.
TPKT_VERSION = 0x03
TPKT_HEADER_SIZE = 4

# Códigos de TPDU de X.224 que aparecen aquí, en el nibble alto del byte.
TPDU_CONNECTION_REQUEST = 0xE0
TPDU_CONNECTION_CONFIRM = 0xD0

# Tipos de mensaje de la negociación de RDP (MS-RDPBCGR §2.2.1.1.1 y §2.2.1.2.1).
NEG_REQUEST = 0x01
NEG_RESPONSE = 0x02
NEG_FAILURE = 0x03

# Protocolos de seguridad, como máscara de bits. Se anuncian todos los que el
# motor sabe reconocer para que el servidor elija el que de verdad prefiere:
# pedir sólo uno mediría la petición, no la política del servidor.
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008
REQUESTED_PROTOCOLS = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX

# Nombre legible de cada protocolo elegido.
PROTOCOL_NAMES: Dict[int, str] = {
    PROTOCOL_RDP: "rdp",
    PROTOCOL_SSL: "ssl",
    PROTOCOL_HYBRID: "hybrid",
    PROTOCOL_HYBRID_EX: "hybrid-ex",
}

# Los dos que implican NLA: la autenticación ocurre antes de que exista la
# sesión gráfica.
PROTOCOLS_WITH_NLA = {PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX}

# Códigos de fallo de la negociación (MS-RDPBCGR §2.2.1.2.2). Un fallo informa
# tanto como un éxito: dice qué exige el servidor.
FAILURE_CODES: Dict[int, str] = {
    0x00000001: "ssl-required-by-server",
    0x00000002: "ssl-not-allowed-by-server",
    0x00000003: "ssl-cert-not-on-server",
    0x00000004: "inconsistent-flags",
    0x00000005: "hybrid-required-by-server",
    0x00000006: "ssl-with-user-auth-required-by-server",
}

# El fallo que significa que el servidor exige NLA — es decir, la postura
# correcta expresada como rechazo.
FAILURE_MEANING_NLA_REQUIRED = "hybrid-required-by-server"

_PRODUCT = "Microsoft Terminal Services"


@dataclass(frozen=True)
class RdpFingerprint:
    """Lo que la negociación de X.224 cuenta de un servicio RDP.

    Attributes:
        product: El producto, o ``None`` si la respuesta no era RDP.
        version: Siempre ``None``. La negociación ocurre antes de cualquier
            intercambio de capacidades, así que este intercambio no da versión
            — y no se inventa una.
        selected_protocol: El nombre del protocolo que el servidor eligió
            (:data:`PROTOCOL_NAMES`), o ``None`` si la negociación falló.
        failure: El código de fallo legible (:data:`FAILURE_CODES`), cuando el
            servidor rechazó la negociación.
    """
    product: Optional[str]
    version: Optional[str] = None
    selected_protocol: Optional[str] = None
    failure: Optional[str] = None

    @property
    def requires_network_level_authentication(self) -> Optional[bool]:
        """Si el servidor exige NLA.

        ``None`` cuando la respuesta no permite decidirlo — y eso es distinto
        de ``False``. Un servidor cuyo modo no se ha podido leer **no** debe
        producir el hallazgo: sería afirmar una configuración insegura sin
        haberla observado.
        """
        if self.failure == FAILURE_MEANING_NLA_REQUIRED:
            return True
        if self.selected_protocol is None:
            return None
        return self.selected_protocol in {"hybrid", "hybrid-ex"}


def build_connection_request(protocols: int = REQUESTED_PROTOCOLS) -> bytes:
    """Construye el ``X.224 Connection Request`` con su ``RDP_NEG_REQ``.

    Args:
        protocols: La máscara de protocolos de seguridad que el cliente
            anuncia soportar.

    Returns:
        El paquete completo, con su sobre TPKT.

    Nota sobre el endianness, que es donde esto se rompe si se transcribe mal:
    la longitud de TPKT va en **big-endian** (viene de OSI) y los campos de
    ``RDP_NEG_REQ`` en **little-endian** (vienen de Windows). Conviven en el
    mismo paquete.
    """
    negotiation = struct.pack("<BBHI", NEG_REQUEST, 0x00, 8, protocols)
    # LI cuenta los bytes del TPDU que van *después* del propio LI.
    tpdu = struct.pack(
        "!BBHHB",
        6 + len(negotiation),          # length indicator
        TPDU_CONNECTION_REQUEST,
        0,                             # dst-ref
        0,                             # src-ref
        0,                             # class option
    ) + negotiation
    return struct.pack("!BBH", TPKT_VERSION, 0, TPKT_HEADER_SIZE + len(tpdu)) + tpdu


def parse_connection_confirm(data: bytes) -> RdpFingerprint:
    """Interpreta la respuesta del servidor a la petición de conexión.

    Args:
        data: El paquete completo recibido.

    Returns:
        El :class:`RdpFingerprint`. Sin producto cuando la respuesta no es un
        ``Connection Confirm`` sobre TPKT: un puerto que contesta cualquier
        cosa no es un RDP.
    """
    empty = RdpFingerprint(None)
    if len(data) < TPKT_HEADER_SIZE + 7 or data[0] != TPKT_VERSION:
        return empty
    if data[TPKT_HEADER_SIZE + 1] & 0xF0 != TPDU_CONNECTION_CONFIRM:
        return empty

    # El servidor ha hablado RDP: eso ya identifica el servicio, incluso si no
    # adjunta bloque de negociación (los servidores muy antiguos no lo hacen,
    # y esa ausencia significa seguridad RDP estándar).
    negotiation = data[TPKT_HEADER_SIZE + 7:]
    if len(negotiation) < 8:
        return RdpFingerprint(_PRODUCT, selected_protocol=PROTOCOL_NAMES[PROTOCOL_RDP])

    kind, _flags, _length, value = struct.unpack("<BBHI", negotiation[:8])
    if kind == NEG_RESPONSE:
        return RdpFingerprint(_PRODUCT, selected_protocol=PROTOCOL_NAMES.get(value))
    if kind == NEG_FAILURE:
        return RdpFingerprint(_PRODUCT, failure=FAILURE_CODES.get(value))
    return RdpFingerprint(_PRODUCT)


def fingerprint_rdp(data: bytes) -> RdpFingerprint:
    """Fingerprint de un servicio RDP desde su respuesta de negociación."""
    return parse_connection_confirm(data)


# =========================================================================
# SONDA (el borde de red: socket crudo, sin cliente RDP)
# =========================================================================

class RdpProbe:  # pylint: disable=too-few-public-methods
    """Manda la petición de conexión y devuelve la respuesta cruda.

    Un solo intercambio: la negociación de seguridad es lo primero que ocurre
    en una sesión RDP, y es todo lo que hace falta observar. **La sesión no se
    llega a establecer** — la conexión se cierra en cuanto el servidor dice qué
    protocolo prefiere, así que no se abre ninguna sesión gráfica ni se toca la
    pantalla de login.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 3389) -> Optional[bytes]:
        """Hace el intercambio contra ``host:port``.

        Args:
            host: El objetivo.
            port: El puerto de RDP.

        Returns:
            El paquete de respuesta, o ``None`` si la conexión o la lectura
            fallan.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("RDP: conexión fallida a %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            sock.sendall(build_connection_request())
            return sock.recv(4096) or None
        except OSError as err:
            logger.debug("RDP: intercambio fallido con %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class RdpDissector(Dissector):
    """Una negociación de X.224 y ya: qué seguridad exige el servidor."""

    label = "RDP"

    def __init__(self, probe: Optional[RdpProbe] = None) -> None:
        self._probe = probe or RdpProbe()

    def applies(self, service) -> bool:
        return is_rdp_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        response = self._probe.fetch(target, service.port or 3389)
        if response is None:
            return None
        fingerprint = fingerprint_rdp(response)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
