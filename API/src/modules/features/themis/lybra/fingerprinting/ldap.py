"""El dissector de LDAP — el servicio que más cuenta sobre una organización.

LDAP es bajo coste y capacidades básicas, pero no de poca frecuencia: en una
red corporativa con Active Directory, el 389 está abierto **siempre**.

Y a diferencia de casi todo lo demás, LDAP tiene una consulta estándar y
anónima diseñada precisamente para esto: el **rootDSE**, la entrada raíz que
todo servidor publica para que un cliente sepa con qué está hablando antes de
autenticarse. Devuelve ``vendorName``, ``vendorVersion``, los
``namingContexts`` (los dominios que sirve) y los ``supportedSASLMechanisms``.

Dos hallazgos vienen de regalo con la misma sonda:

- **Bind anónimo permitido.** Si el rootDSE contesta sin credenciales, la
  información del directorio es pública. Es un hallazgo de configuración
  clásico, de los que OpenVAS detectaba y este motor no.
- **LDAP en claro conviviendo con LDAPS.** Un 389 abierto en un host que
  también publica el 636 significa que hay credenciales de directorio
  viajando sin cifrar por decisión de cada cliente.

El ``namingContexts`` merece mención aparte: da el nombre de dominio de la
organización, que es el mejor identificador de activo que puede aparecer en un
informe. Una IP no dice de quién es una máquina; ``DC=empresa,DC=local`` sí.

**La codificación es BER**, la misma familia que el SNMP que ya se construyó a
mano en ``transport.py``, así que hay precedente y experiencia en casa. La
diferencia práctica es que aquí hay que **leer** longitudes en forma larga
—una lista de atributos pasa de 127 bytes con facilidad—, no sólo escribirlas
en forma corta.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..checks import is_ldap_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# Etiquetas BER de los mensajes LDAP que este módulo construye o lee
# (RFC 4511 §4.1.1 y siguientes). Las de aplicación llevan el bit 0x60 porque
# son constructed + application class.
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_ENUMERATED = 0x0A
TAG_OCTET_STRING = 0x04
TAG_BOOLEAN = 0x01
TAG_BIND_REQUEST = 0x60
TAG_BIND_RESPONSE = 0x61
TAG_SEARCH_REQUEST = 0x63
TAG_SEARCH_ENTRY = 0x64
TAG_SEARCH_DONE = 0x65
TAG_SIMPLE_AUTH = 0x80          # [0] contexto: contraseña simple
TAG_FILTER_PRESENT = 0x87       # [7] contexto: filtro "el atributo existe"

# Códigos de resultado que importan (RFC 4511 §4.1.9).
RESULT_SUCCESS = 0
RESULT_INAPPROPRIATE_AUTHENTICATION = 48
RESULT_STRONGER_AUTH_REQUIRED = 8

# Los atributos del rootDSE que se piden. Ni uno más: cada uno tiene un
# consumidor concreto abajo, y pedir el directorio entero sería una consulta
# muy distinta en coste y en intención.
ROOTDSE_ATTRIBUTES: Tuple[str, ...] = (
    "vendorName",
    "vendorVersion",
    "namingContexts",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
)

_PRODUCT_FALLBACK = "LDAP"


# =========================================================================
# BER — escribir y, sobre todo, leer
# =========================================================================

def encode_length(length: int) -> bytes:
    """Codifica una longitud BER, en forma corta o larga según haga falta.

    Args:
        length: La longitud a codificar.

    Returns:
        Los bytes de longitud. Hasta 127 es un solo byte; a partir de ahí, un
        byte con el bit alto y el número de bytes que siguen.
    """
    if length < 0x80:
        return bytes((length,))
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def ber(tag: int, value: bytes) -> bytes:
    """Envuelve ``value`` en un TLV BER con la etiqueta dada."""
    return bytes((tag,)) + encode_length(len(value)) + value


def read_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Lee una longitud BER, en cualquiera de sus dos formas.

    Ésta es la mitad que ``transport.py`` no necesitaba: al escribir, ningún
    campo del GetRequest de SNMP se acerca a 128 bytes, pero al leer una
    respuesta LDAP con varios atributos la forma larga es la norma.

    Args:
        data: Los bytes del mensaje.
        offset: Dónde empieza la longitud (justo tras la etiqueta).

    Returns:
        Un par ``(longitud, siguiente desplazamiento)``.

    Raises:
        ValueError: Si el mensaje está truncado.
    """
    if offset >= len(data):
        raise ValueError("longitud BER truncada")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or offset + 1 + count > len(data):
        raise ValueError("longitud BER indefinida o truncada")
    return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), offset + 1 + count


def read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Lee un TLV completo.

    Args:
        data: Los bytes del mensaje.
        offset: Dónde empieza la etiqueta.

    Returns:
        Una tupla ``(etiqueta, valor, siguiente desplazamiento)``.

    Raises:
        ValueError: Si el mensaje está truncado.
    """
    if offset >= len(data):
        raise ValueError("TLV truncado")
    tag = data[offset]
    length, value_offset = read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("valor BER truncado")
    return tag, data[value_offset:end], end


# =========================================================================
# Los mensajes que se envían
# =========================================================================

def build_anonymous_bind(message_id: int = 1) -> bytes:
    """Construye un ``BindRequest`` anónimo: LDAPv3, sin nombre y sin contraseña.

    Un bind anónimo no es un intento de adivinar credenciales: es la forma que
    el propio protocolo define para preguntar sin identificarse, y lo que se
    observa es **si el servidor la acepta**. No se prueba ninguna contraseña.

    Args:
        message_id: El identificador del mensaje.

    Returns:
        El mensaje LDAP completo.
    """
    request = ber(TAG_BIND_REQUEST, (
        ber(TAG_INTEGER, bytes((3,)))       # versión 3
        + ber(TAG_OCTET_STRING, b"")        # nombre vacío
        + ber(TAG_SIMPLE_AUTH, b"")         # contraseña vacía
    ))
    return ber(TAG_SEQUENCE, ber(TAG_INTEGER, bytes((message_id,))) + request)


def build_rootdse_search(message_id: int = 2) -> bytes:
    """Construye el ``SearchRequest`` del rootDSE.

    Base vacía, ámbito ``baseObject`` y filtro ``(objectClass=*)``: la consulta
    exacta que la RFC 4512 §5.1 define para preguntarle a un servidor qué es,
    sin recorrer ni una entrada del directorio.

    Args:
        message_id: El identificador del mensaje.

    Returns:
        El mensaje LDAP completo.
    """
    attributes = b"".join(
        ber(TAG_OCTET_STRING, name.encode("ascii")) for name in ROOTDSE_ATTRIBUTES
    )
    request = ber(TAG_SEARCH_REQUEST, (
        ber(TAG_OCTET_STRING, b"")               # baseObject: la raíz
        + ber(TAG_ENUMERATED, bytes((0,)))       # scope: baseObject
        + ber(TAG_ENUMERATED, bytes((0,)))       # derefAliases: never
        + ber(TAG_INTEGER, bytes((0,)))          # sizeLimit: sin límite
        + ber(TAG_INTEGER, bytes((0,)))          # timeLimit: sin límite
        + ber(TAG_BOOLEAN, bytes((0,)))          # typesOnly: falso
        + ber(TAG_FILTER_PRESENT, b"objectClass")
        + ber(TAG_SEQUENCE, attributes)
    ))
    return ber(TAG_SEQUENCE, ber(TAG_INTEGER, bytes((message_id,))) + request)


# =========================================================================
# Lo que se recibe
# =========================================================================

def _protocol_ops(data: bytes) -> List[Tuple[int, bytes]]:
    """Extrae los ``protocolOp`` de todos los ``LDAPMessage`` de un buffer.

    Un servidor contesta a un ``SearchRequest`` con varios mensajes seguidos
    —una o más entradas y un ``SearchResultDone``— y pueden llegar en la misma
    lectura del socket.

    Args:
        data: Los bytes recibidos.

    Returns:
        Los pares ``(etiqueta, cuerpo)`` que se hayan podido leer enteros. Un
        mensaje truncado al final corta el recorrido sin perder los anteriores.
    """
    operations: List[Tuple[int, bytes]] = []
    offset = 0
    try:
        while offset < len(data):
            tag, body, offset = read_tlv(data, offset)
            if tag != TAG_SEQUENCE:
                break
            _id_tag, _id_value, inner = read_tlv(body, 0)
            operation_tag, operation_body, _end = read_tlv(body, inner)
            operations.append((operation_tag, operation_body))
    except ValueError:
        pass
    return operations


def parse_bind_response(data: bytes) -> Optional[int]:
    """Lee el código de resultado de un ``BindResponse``.

    Args:
        data: Los bytes recibidos.

    Returns:
        El código, o ``None`` si no hay ningún ``BindResponse`` legible.
    """
    for tag, body in _protocol_ops(data):
        if tag != TAG_BIND_RESPONSE:
            continue
        try:
            _tag, value, _end = read_tlv(body, 0)
        except ValueError:
            return None
        return int.from_bytes(value, "big") if value else None
    return None


def parse_search_entry(data: bytes) -> Dict[str, List[str]]:  # pylint: disable=too-many-locals
    """Lee los atributos de un ``SearchResultEntry``.

    Muchas variables locales porque BER se lee así: cada nivel de anidamiento
    —la entrada, la lista de atributos, cada atributo, cada valor— produce su
    etiqueta, su contenido y su desplazamiento, y nombrarlos es lo que hace
    legible un recorrido que si no sería aritmética de índices.

    Args:
        data: Los bytes recibidos.

    Returns:
        Un mapa atributo → valores. Vacío si no hay ninguna entrada legible.
    """
    attributes: Dict[str, List[str]] = {}
    for tag, body in _protocol_ops(data):
        if tag != TAG_SEARCH_ENTRY:
            continue
        try:
            _name_tag, _object_name, offset = read_tlv(body, 0)
            _list_tag, attribute_list, _end = read_tlv(body, offset)
            inner = 0
            while inner < len(attribute_list):
                _attr_tag, attribute, inner = read_tlv(attribute_list, inner)
                _type_tag, attribute_type, values_offset = read_tlv(attribute, 0)
                _values_tag, values, _values_end = read_tlv(attribute, values_offset)
                name = attribute_type.decode("utf-8", "ignore")
                collected: List[str] = []
                value_offset = 0
                while value_offset < len(values):
                    _value_tag, value, value_offset = read_tlv(values, value_offset)
                    collected.append(value.decode("utf-8", "ignore"))
                attributes[name] = collected
        except ValueError:
            continue
    return attributes


@dataclass(frozen=True)
class LdapFingerprint:
    """Lo que el rootDSE cuenta de un servidor de directorio.

    Attributes:
        product: El ``vendorName`` publicado, o ``"LDAP"`` cuando el servidor
            contesta pero no se nombra — que es el caso de Active Directory,
            que no publica ``vendorName``.
        version: El ``vendorVersion``, cuando lo hay.
        naming_contexts: Los dominios que el servidor sirve. El mejor
            identificador de activo que puede aparecer en un informe.
        sasl_mechanisms: Los mecanismos SASL ofrecidos.
        allows_anonymous_bind: Si el servidor aceptó el bind anónimo.
    """
    product: Optional[str]
    version: Optional[str]
    naming_contexts: Tuple[str, ...] = ()
    sasl_mechanisms: Tuple[str, ...] = ()
    allows_anonymous_bind: bool = False


def fingerprint_ldap(bind_reply: bytes, search_reply: bytes) -> LdapFingerprint:
    """Construye el fingerprint a partir de las dos respuestas.

    Args:
        bind_reply: La respuesta al ``BindRequest`` anónimo.
        search_reply: La respuesta al ``SearchRequest`` del rootDSE.

    Returns:
        El :class:`LdapFingerprint`. Sin producto cuando ninguna de las dos
        respuestas es LDAP legible.
    """
    result_code = parse_bind_response(bind_reply)
    attributes = parse_search_entry(search_reply)
    allows_anonymous = result_code == RESULT_SUCCESS

    if result_code is None and not attributes:
        return LdapFingerprint(None, None)

    vendor = attributes.get("vendorName") or []
    version = attributes.get("vendorVersion") or []
    return LdapFingerprint(
        product=vendor[0] if vendor else _PRODUCT_FALLBACK,
        version=version[0] if version else None,
        naming_contexts=tuple(attributes.get("namingContexts") or ()),
        sasl_mechanisms=tuple(attributes.get("supportedSASLMechanisms") or ()),
        allows_anonymous_bind=allows_anonymous,
    )


# =========================================================================
# SONDA (el borde de red: socket crudo, sin cliente LDAP)
# =========================================================================

class LdapProbe:  # pylint: disable=too-few-public-methods
    """Hace el bind anónimo y la consulta del rootDSE sobre una conexión.

    Las dos van juntas porque el protocolo lo pide: un ``SearchRequest`` sólo
    tiene sentido sobre una sesión ya vinculada, aunque sea anónimamente.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 389) -> Optional[Tuple[bytes, bytes]]:
        """Hace los dos intercambios contra ``host:port``.

        Args:
            host: El objetivo.
            port: El puerto de LDAP.

        Returns:
            Un par ``(respuesta al bind, respuesta a la búsqueda)``, o ``None``
            si ni siquiera el bind llegó a contestarse.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("LDAP: conexión fallida a %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            sock.sendall(build_anonymous_bind())
            bind_reply = sock.recv(8192)
            if not bind_reply:
                return None
            sock.sendall(build_rootdse_search())
            try:
                search_reply = sock.recv(16384)
            except OSError:
                search_reply = b""
            return bind_reply, search_reply
        except OSError as err:
            logger.debug("LDAP: intercambio fallido con %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class LdapDissector(Dissector):
    """Bind anónimo y rootDSE: vendor, versión y los dominios que sirve."""

    label = "LDAP"

    def __init__(self, probe: Optional[LdapProbe] = None) -> None:
        self._probe = probe or LdapProbe()

    def applies(self, service) -> bool:
        return is_ldap_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        replies = self._probe.fetch(target, service.port or 389)
        if replies is None:
            return None
        fingerprint = fingerprint_ldap(*replies)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
