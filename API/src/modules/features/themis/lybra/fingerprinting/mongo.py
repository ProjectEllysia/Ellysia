"""El dissector de MongoDB — y el hallazgo más famoso de la lista.

MongoDB cierra el trío de bases de datos que la Fase N dejó fuera, y es el que
tiene asociado el incidente más conocido: durante años, las instalaciones por
defecto escuchaban en todas las interfaces **sin autenticación**, y eso produjo
una de las mayores oleadas de fuga de datos y de ransomware de bases de datos
que se recuerdan. Sigue apareciendo.

**Una corrección al planteamiento original, porque cambia el diseño.** El issue
daba por hecho que un ``hello`` sin autenticar sólo contesta si el servidor no
exige credenciales, y que por tanto su respuesta *es* la evidencia de la
exposición. No es así: ``hello`` (antes ``isMaster``) es el comando de
*handshake* del protocolo y **siempre** contesta, con ``--auth`` y sin él —
tiene que hacerlo, porque el cliente necesita saber con quién habla antes de
poder autenticarse. Un check construido sobre esa premisa habría marcado como
expuesto **todo** MongoDB alcanzable, incluidos los correctamente cerrados.

Así que el módulo separa las dos preguntas, que resultan ser distintas:

- ``hello`` responde *"¿qué versión eres?"* — y contesta siempre, así que
  sirve para el fingerprint y para nada más.
- ``listDatabases`` responde *"¿me dejas entrar?"* — sin credenciales
  devuelve la lista de bases de datos; con ``--auth`` devuelve
  ``ok: 0`` y el código 13 (*Unauthorized*). **Ahí** está la evidencia.

El parseo de BSON necesario es mínimo —leer un documento y sacar unos pocos
campos—, así que no hace falta traer ``pymongo`` sólo para esto: mismo criterio
que llevó a construir SNMP sin ``pysnmp`` y el ``PRELOGIN`` de TDS a mano.

Comparte diseño con :mod:`postgres` y :mod:`mssql`.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..checks import is_mongodb_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# El opcode del único mensaje que este módulo habla. OP_MSG sustituyó en
# MongoDB 3.6 a la familia de opcodes antiguos, y es el que entiende cualquier
# servidor que siga en soporte.
OP_MSG = 2013
MESSAGE_HEADER_SIZE = 16

# El código de error que MongoDB devuelve cuando un comando exige credenciales
# y no se han dado. Es el que distingue un servidor cerrado de uno abierto.
UNAUTHORIZED_CODE = 13

_PRODUCT = "MongoDB"


# =========================================================================
# BSON — lo justo para leer un documento de respuesta
# =========================================================================

def _read_cstring(data: bytes, offset: int) -> Tuple[str, int]:
    """Lee una cadena terminada en NUL y devuelve dónde sigue el documento."""
    end = data.find(b"\x00", offset)
    if end == -1:
        raise ValueError("cadena BSON sin terminador")
    return data[offset:end].decode("utf-8", "ignore"), end + 1


def _read_value(  # pylint: disable=too-many-return-statements
    data: bytes, offset: int, element_type: int,
) -> Tuple[Any, int]:
    """Lee un valor BSON del tipo indicado.

    Un ``return`` por tipo, y a propósito: la alternativa —una tabla de
    tamaños— tendría que llevar además, para la mitad de los tipos, la regla
    de cómo se calcula ese tamaño a partir del propio dato. Diez ramas
    explícitas de dos líneas se leen mejor que una tabla con excepciones.

    Sólo se implementan los tipos que aparecen en las respuestas que este
    módulo consume. Un tipo no soportado corta la lectura en vez de avanzar a
    ciegas: seguir adelante con un desplazamiento equivocado produce basura que
    *parece* datos, que es peor que no leer nada.

    Args:
        data: El documento completo.
        offset: Dónde empieza el valor.
        element_type: El byte de tipo BSON.

    Returns:
        Un par ``(valor, siguiente desplazamiento)``.

    Raises:
        ValueError: Si el tipo no está soportado o el documento está truncado.
    """
    if element_type == 0x01:                                   # double
        return struct.unpack_from("<d", data, offset)[0], offset + 8
    if element_type == 0x02:                                   # string
        length = struct.unpack_from("<i", data, offset)[0]
        text = data[offset + 4:offset + 4 + length - 1].decode("utf-8", "ignore")
        return text, offset + 4 + length
    if element_type in (0x03, 0x04):                           # documento / array
        length = struct.unpack_from("<i", data, offset)[0]
        return parse_bson_document(data[offset:offset + length]), offset + length
    if element_type == 0x05:                                   # binario
        length = struct.unpack_from("<i", data, offset)[0]
        return data[offset + 5:offset + 5 + length], offset + 5 + length
    if element_type == 0x07:                                   # ObjectId
        return data[offset:offset + 12], offset + 12
    if element_type == 0x08:                                   # booleano
        return bool(data[offset]), offset + 1
    if element_type == 0x0A:                                   # null
        return None, offset
    if element_type == 0x10:                                   # int32
        return struct.unpack_from("<i", data, offset)[0], offset + 4
    if element_type in (0x09, 0x11, 0x12):                     # datetime, ts, int64
        return struct.unpack_from("<q", data, offset)[0], offset + 8
    raise ValueError(f"tipo BSON no soportado: {element_type:#04x}")


def parse_bson_document(data: bytes) -> Dict[str, Any]:
    """Descompone un documento BSON en un diccionario.

    Args:
        data: El documento completo, empezando por su longitud de cuatro bytes.

    Returns:
        El documento como diccionario. Vacío si está truncado o trae un tipo
        que este lector no conoce — se prefiere no devolver nada a devolver una
        lectura parcial que nadie distinguiría de una completa.
    """
    if len(data) < 5:
        return {}
    document: Dict[str, Any] = {}
    offset = 4
    try:
        while offset < len(data) and data[offset] != 0x00:
            element_type = data[offset]
            name, offset = _read_cstring(data, offset + 1)
            document[name], offset = _read_value(data, offset, element_type)
    except (ValueError, struct.error, IndexError):
        return {}
    return document


def build_bson_document(fields: List[Tuple[str, Any]]) -> bytes:
    """Serializa los pocos tipos que hacen falta para pedir un comando.

    Args:
        fields: Los campos, en orden. MongoDB exige que el nombre del comando
            sea **el primero** del documento, de ahí que sea una lista de pares
            y no un diccionario.

    Returns:
        El documento BSON completo.
    """
    body = b""
    for name, value in fields:
        key = name.encode("utf-8") + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + key + bytes((1 if value else 0,))
        elif isinstance(value, int):
            body += b"\x10" + key + struct.pack("<i", value)
        else:
            encoded = str(value).encode("utf-8") + b"\x00"
            body += b"\x02" + key + struct.pack("<i", len(encoded)) + encoded
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


# =========================================================================
# OP_MSG
# =========================================================================

def build_op_msg(command: List[Tuple[str, Any]], request_id: int = 1) -> bytes:
    """Envuelve un comando en un ``OP_MSG`` mínimo.

    Args:
        command: Los campos del comando, con su nombre el primero.
        request_id: El identificador de la petición.

    Returns:
        El mensaje completo, con su cabecera de dieciséis bytes.
    """
    # flagBits = 0, y una sola sección de tipo 0 (el documento del comando).
    body = struct.pack("<I", 0) + b"\x00" + build_bson_document(command)
    header = struct.pack("<iiii", MESSAGE_HEADER_SIZE + len(body), request_id, 0, OP_MSG)
    return header + body


def parse_op_msg(data: bytes) -> Dict[str, Any]:
    """Extrae el documento de respuesta de un ``OP_MSG``.

    Args:
        data: El mensaje recibido, con su cabecera.

    Returns:
        El documento, o un diccionario vacío si la respuesta no es un
        ``OP_MSG`` reconocible.
    """
    if len(data) < MESSAGE_HEADER_SIZE + 5:
        return {}
    opcode = struct.unpack_from("<i", data, 12)[0]
    if opcode != OP_MSG:
        return {}
    # flagBits (4) + tipo de sección (1) por delante del documento.
    return parse_bson_document(data[MESSAGE_HEADER_SIZE + 5:])


HELLO_COMMAND: List[Tuple[str, Any]] = [("hello", 1), ("$db", "admin")]
LIST_DATABASES_COMMAND: List[Tuple[str, Any]] = [("listDatabases", 1), ("$db", "admin")]


@dataclass(frozen=True)
class MongoFingerprint:
    """Lo que MongoDB cuenta de sí mismo, y si deja entrar sin credenciales.

    Attributes:
        product: ``"MongoDB"``, o ``None`` si no contestó el protocolo.
        version: La versión exacta que ``hello`` publica.
        max_wire_version: La versión del protocolo de cable, que acota la
            familia del servidor incluso si ``version`` no viniera.
        allows_unauthenticated_access: Si un comando que exige permisos
            funcionó **sin credenciales**. Es el hallazgo, y es un hecho
            observado: el servidor devolvió los datos.
    """
    product: Optional[str]
    version: Optional[str]
    max_wire_version: Optional[int]
    allows_unauthenticated_access: bool = False


def fingerprint_mongo(hello_reply: bytes, list_reply: bytes = b"") -> MongoFingerprint:
    """Construye el fingerprint a partir de las dos respuestas.

    Args:
        hello_reply: La respuesta a ``hello``, que contesta siempre.
        list_reply: La respuesta a ``listDatabases``, que sólo trae datos
            cuando el servidor no exige credenciales.

    Returns:
        El :class:`MongoFingerprint`.
    """
    hello = parse_op_msg(hello_reply)
    if not hello or "maxWireVersion" not in hello:
        return MongoFingerprint(None, None, None)

    listing = parse_op_msg(list_reply) if list_reply else {}
    # `ok: 1` **y** la lista presente: un servidor con --auth contesta `ok: 0`
    # con el código 13, y uno que no entiende el comando no trae `databases`.
    is_open = bool(listing.get("ok")) and "databases" in listing

    version = hello.get("version")
    return MongoFingerprint(
        product=_PRODUCT,
        version=str(version) if version else None,
        max_wire_version=hello.get("maxWireVersion"),
        allows_unauthenticated_access=is_open,
    )


# =========================================================================
# SONDA (el borde de red: socket crudo, sin pymongo)
# =========================================================================

class MongoProbe:  # pylint: disable=too-few-public-methods
    """Manda ``hello`` y ``listDatabases`` sobre la misma conexión.

    Las dos preguntas van juntas porque son dos secciones del mismo diálogo y
    el servidor no cierra entre una y otra: a diferencia de PostgreSQL, aquí no
    hay ninguna negociación de transporte en medio que obligue a reconectar.

    **Ninguno de los dos comandos escribe nada.** ``listDatabases`` es una
    lectura de catálogo; se manda sin credenciales y su fracaso es tan
    informativo como su éxito.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 27017) -> Optional[Tuple[bytes, bytes]]:
        """Hace los dos intercambios contra ``host:port``.

        Args:
            host: El objetivo.
            port: El puerto de MongoDB.

        Returns:
            Un par ``(respuesta a hello, respuesta a listDatabases)``, o
            ``None`` si ni siquiera el primero llegó a completarse.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("MongoDB: conexión fallida a %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            sock.sendall(build_op_msg(HELLO_COMMAND, request_id=1))
            hello_reply = sock.recv(8192)
            if not hello_reply:
                return None
            sock.sendall(build_op_msg(LIST_DATABASES_COMMAND, request_id=2))
            try:
                list_reply = sock.recv(8192)
            except OSError:
                list_reply = b""
            return hello_reply, list_reply
        except OSError as err:
            logger.debug("MongoDB: intercambio fallido con %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class MongoDissector(Dissector):
    """``hello`` para la versión, ``listDatabases`` para saber si hay puerta."""

    label = "MongoDB"

    def __init__(self, probe: Optional[MongoProbe] = None) -> None:
        self._probe = probe or MongoProbe()

    def applies(self, service) -> bool:
        return is_mongodb_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        replies = self._probe.fetch(target, service.port or 27017)
        if replies is None:
            return None
        fingerprint = fingerprint_mongo(*replies)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
