"""El dissector de SQL Server — el más generoso de los tres pendientes.

De las tres bases de datos que la Fase N dejó fuera, SQL Server es la que más
se identifica sola: el paquete ``PRELOGIN`` del protocolo TDS devuelve la
versión del servidor —major, minor y build— en un campo binario de tamaño
fijo, **sin autenticar y sin negociar nada más**.

Esa versión mapea directo a un producto de NVD (``microsoft:sql_server``) con
historial de CVEs abundante, así que es el caso limpio del apalancamiento que
el roadmap describe: se escriben *ojos*, no checks, y la correlación de
vulnerabilidades sale sola de la base de conocimiento local.

El ``PRELOGIN`` dice además si el servidor **exige cifrado**, en cuatro estados
(:data:`ENCRYPTION_MODES`), lo que es un hecho de configuración por sí mismo en
cuanto el puerto está expuesto.

**Formato del intercambio** (MS-TDS §2.2.6.5). Un paquete TDS son ocho bytes de
cabecera y un cuerpo. El cuerpo de un ``PRELOGIN`` es una tabla de opciones:
cada fila son cinco bytes —un identificador, y el desplazamiento y la longitud
de su dato dentro del mismo cuerpo—, un ``0xFF`` cierra la tabla, y detrás
vienen los datos a los que las filas apuntan. Los desplazamientos son
**relativos al principio del cuerpo**, no del paquete; equivocarse en eso es el
error clásico al parsear esto a mano, y de ahí que el módulo lo diga aquí.

Todo se construye y se parsea a mano, sin librería de TDS, por el mismo
criterio que llevó a hacer SNMP sin ``pysnmp``: dos mensajes no justifican una
dependencia.

Comparte diseño con :mod:`postgres` y :mod:`mongo`.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from ..checks import is_mssql_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# Tipo de paquete TDS para PRELOGIN, y el estado "este es el último paquete
# del mensaje" (MS-TDS §2.2.3.1.2).
PACKET_TYPE_PRELOGIN = 0x12
STATUS_END_OF_MESSAGE = 0x01
TDS_HEADER_SIZE = 8

# Identificadores de opción dentro del cuerpo del PRELOGIN. Sólo se piden y se
# leen los dos que aportan algo sin autenticar.
OPTION_VERSION = 0x00
OPTION_ENCRYPTION = 0x01
OPTION_TERMINATOR = 0xFF

# Qué dice el servidor sobre el cifrado del canal. ``REQ`` y ``ON`` son la
# postura correcta; ``NOT_SUP`` significa que las credenciales de cualquier
# cliente van a viajar en claro.
ENCRYPTION_MODES: Dict[int, str] = {
    0x00: "off",
    0x01: "on",
    0x02: "not-supported",
    0x03: "required",
}

_PRODUCT = "Microsoft SQL Server"

# Familia comercial por versión mayor, para que el hallazgo diga algo legible
# además del número. No sustituye a la versión —el CPE se resuelve con
# ``major.minor.build``, que es lo que NVD indexa— sino que la acompaña.
RELEASE_NAMES: Dict[int, str] = {
    8: "2000", 9: "2005", 10: "2008", 11: "2012", 12: "2014",
    13: "2016", 14: "2017", 15: "2019", 16: "2022",
}


@dataclass(frozen=True)
class MssqlFingerprint:
    """Lo que el ``PRELOGIN`` cuenta de un SQL Server.

    Attributes:
        product: ``"Microsoft SQL Server"``, o ``None`` si la respuesta no era
            un ``PRELOGIN``.
        version: ``"major.minor.build"``, la forma en que NVD indexa este
            producto.
        release_name: La familia comercial (``"2019"``), cuando la versión
            mayor es conocida. Acompaña a la versión, no la sustituye.
        encryption: El modo de cifrado anunciado
            (:data:`ENCRYPTION_MODES`), o ``None``.
    """
    product: Optional[str]
    version: Optional[str]
    release_name: Optional[str]
    encryption: Optional[str]

    @property
    def is_encryption_unsupported(self) -> bool:
        """Si el servidor declara que no admite cifrar el canal."""
        return self.encryption == "not-supported"


def build_prelogin_request() -> bytes:
    """Construye un paquete ``PRELOGIN`` mínimo con las dos opciones que se leen.

    Se declara ``ENCRYPTION = off`` como postura del *cliente*: es lo que dice
    "yo no voy a cifrar", y sirve para que el servidor conteste con su propia
    postura sin que haya que negociar TLS aquí. No cambia nada de lo que el
    servidor exija.

    Returns:
        El paquete completo, cabecera incluida.
    """
    # Tabla de opciones: dos filas de cinco bytes más el terminador.
    table_size = 5 * 2 + 1
    version_data = b"\x00" * 6
    encryption_data = b"\x00"
    body = (
        struct.pack("!BHH", OPTION_VERSION, table_size, len(version_data))
        + struct.pack("!BHH", OPTION_ENCRYPTION,
                      table_size + len(version_data), len(encryption_data))
        + bytes((OPTION_TERMINATOR,))
        + version_data
        + encryption_data
    )
    header = struct.pack(
        "!BBHHBB",
        PACKET_TYPE_PRELOGIN, STATUS_END_OF_MESSAGE,
        TDS_HEADER_SIZE + len(body),
        0,      # SPID
        0,      # PacketID
        0,      # Window
    )
    return header + body


def _option_table(body: bytes) -> Dict[int, Tuple[int, int]]:
    """Lee la tabla de opciones del cuerpo de un ``PRELOGIN``.

    Args:
        body: El cuerpo del paquete, ya sin la cabecera TDS.

    Returns:
        Un mapa ``identificador -> (desplazamiento, longitud)``. Los
        desplazamientos son relativos al principio de ``body``.
    """
    options: Dict[int, Tuple[int, int]] = {}
    offset = 0
    while offset < len(body) and body[offset] != OPTION_TERMINATOR:
        if offset + 5 > len(body):
            break
        token = body[offset]
        data_offset, data_length = struct.unpack("!HH", body[offset + 1:offset + 5])
        options[token] = (data_offset, data_length)
        offset += 5
    return options


def parse_prelogin_response(data: bytes) -> MssqlFingerprint:
    """Interpreta la respuesta ``PRELOGIN`` de un SQL Server.

    Args:
        data: El paquete completo recibido, con su cabecera.

    Returns:
        El :class:`MssqlFingerprint`. Sin producto cuando el paquete está
        truncado, no es TDS o no trae la opción de versión: un puerto que
        contesta cualquier cosa no es un SQL Server.
    """
    empty = MssqlFingerprint(None, None, None, None)
    if len(data) <= TDS_HEADER_SIZE:
        return empty

    body = data[TDS_HEADER_SIZE:]
    options = _option_table(body)

    version_offset, version_length = options.get(OPTION_VERSION, (0, 0))
    if version_length < 6 or version_offset + 6 > len(body):
        return empty
    major, minor, build = struct.unpack("!BBH", body[version_offset:version_offset + 4])

    encryption = None
    encryption_offset, encryption_length = options.get(OPTION_ENCRYPTION, (0, 0))
    if encryption_length >= 1 and encryption_offset < len(body):
        encryption = ENCRYPTION_MODES.get(body[encryption_offset])

    return MssqlFingerprint(
        product=_PRODUCT,
        version=f"{major}.{minor}.{build}",
        release_name=RELEASE_NAMES.get(major),
        encryption=encryption,
    )


def fingerprint_mssql(data: bytes) -> MssqlFingerprint:
    """Fingerprint de un SQL Server desde su respuesta ``PRELOGIN``."""
    return parse_prelogin_response(data)


# =========================================================================
# SONDA (el borde de red: socket crudo, sin librería de TDS)
# =========================================================================

class MssqlProbe:  # pylint: disable=too-few-public-methods
    """Manda un ``PRELOGIN`` y devuelve la respuesta cruda.

    Un solo intercambio, a diferencia de :class:`~.postgres.PostgresProbe`: el
    ``PRELOGIN`` trae la versión y el modo de cifrado en la misma respuesta.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 1433) -> Optional[bytes]:
        """Hace el intercambio contra ``host:port``.

        Args:
            host: El objetivo.
            port: El puerto de SQL Server.

        Returns:
            El paquete de respuesta, o ``None`` si la conexión o la lectura
            fallan.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("MSSQL: conexión fallida a %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            sock.sendall(build_prelogin_request())
            return sock.recv(4096) or None
        except OSError as err:
            logger.debug("MSSQL: intercambio fallido con %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class MssqlDissector(Dissector):
    """Un ``PRELOGIN`` y ya: versión exacta y modo de cifrado, sin autenticar."""

    label = "MSSQL"

    def __init__(self, probe: Optional[MssqlProbe] = None) -> None:
        self._probe = probe or MssqlProbe()

    def applies(self, service) -> bool:
        return is_mssql_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        response = self._probe.fetch(target, service.port or 1433)
        if response is None:
            return None
        fingerprint = fingerprint_mssql(response)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
