"""Los payloads de la tabla de sondas UDP — una fila por protocolo consumido.

En UDP no existe el «connect scan»: un socket de datagrama no negocia nada, así
que la única señal disponible sin privilegios de raw socket es **mandar algo
que ese protocolo entienda y ver si contesta**. De ahí que la tabla de sondas
sea payload por puerto y no una lista de números.

La regla de crecimiento es explícita: *"crece una fila por protocolo que un
check o dissector realmente consuma, no antes de necesitarlo"*. Cada payload
de aquí llega junto con el consumidor que lo lee
(:mod:`~.fingerprinting.udp_services`).

**Por qué la superficie UDP importa.** Ahí viven servicios que no aparecen en
ningún escaneo TCP y que se usan a diario en ataques de amplificación — es
decir, servicios que convierten al host del cliente en **arma contra
terceros**. Ésa es una conversación distinta, y más incómoda, que "tienes un
puerto abierto".

Los payloads viven aquí y no en ``transport.py`` por la misma razón que el
codificador de SNMP vive allí: ``transport.py`` necesita la tabla para el
descubrimiento y ``fingerprinting/`` necesita los parsers, así que el payload
tiene que estar en un sitio del que los dos puedan tirar sin crear un ciclo.
Este módulo no importa nada del paquete de fingerprinting.
"""

from __future__ import annotations

import struct
from typing import Iterable, Tuple

# =========================================================================
# DNS (53) y mDNS (5353) — misma codificación, preguntas distintas
# =========================================================================

# Clases y tipos de registro que se usan aquí (RFC 1035 §3.2.2 y §3.2.4).
DNS_CLASS_IN = 1
DNS_CLASS_CHAOS = 3
DNS_TYPE_TXT = 16
DNS_TYPE_PTR = 12

# La bandera de recursión deseada, en el segundo byte de las banderas de
# cabecera. Se pide para que el servidor conteste diciendo si la ofrece.
DNS_FLAG_RECURSION_DESIRED = 0x0100
# La bandera que el **servidor** enciende en su respuesta cuando acepta
# resolver nombres de terceros. Es el bit que delata un resolutor abierto.
DNS_FLAG_RECURSION_AVAILABLE = 0x0080


def encode_dns_name(name: str) -> bytes:
    """Codifica un nombre de dominio en el formato de etiquetas de DNS.

    Cada etiqueta va precedida de su longitud y un cero cierra el nombre —
    ``"version.bind"`` se convierte en ``\\x07version\\x04bind\\x00``.

    Args:
        name: El nombre, con las etiquetas separadas por puntos.

    Returns:
        El nombre codificado.
    """
    encoded = b""
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("ascii")
        encoded += bytes((len(raw),)) + raw
    return encoded + b"\x00"


def build_dns_query(name: str, record_type: int, record_class: int,
                    transaction_id: int = 0x1337,
                    flags: int = DNS_FLAG_RECURSION_DESIRED) -> bytes:
    """Construye una consulta DNS de una sola pregunta.

    Args:
        name: El nombre a consultar.
        record_type: El tipo de registro (``DNS_TYPE_*``).
        record_class: La clase (``DNS_CLASS_*``).
        transaction_id: El identificador de la consulta.
        flags: Las banderas de cabecera.

    Returns:
        El datagrama completo.
    """
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", record_type, record_class)
    return header + question


def build_dns_version_query() -> bytes:
    """Construye la consulta ``version.bind`` de clase CHAOS.

    Es la pregunta estándar «¿qué versión de servidor eres?» que BIND y sus
    compatibles contestan en un registro TXT. La respuesta trae **además** la
    bandera de recursión disponible, así que este único datagrama sirve para
    el fingerprint y para el check de resolutor abierto.

    Ese detalle no es una casualidad aprovechada, es la razón de que este sea
    el payload elegido: la alternativa —lanzar una consulta recursiva de
    verdad por un nombre externo— haría que el objetivo mandase tráfico a un
    tercero para responderla, que es justo el comportamiento que se está
    midiendo. Leer el bit que el servidor enciende él solo no molesta a nadie.

    Returns:
        El datagrama completo.
    """
    return build_dns_query("version.bind", DNS_TYPE_TXT, DNS_CLASS_CHAOS)


def build_mdns_services_query() -> bytes:
    """Construye la consulta mDNS que pide el catálogo de servicios de la red.

    ``_services._dns-sd._udp.local`` es el meta-servicio que define el
    descubrimiento de servicios de DNS-SD: quien lo contesta enumera qué tipos
    de servicio anuncia. Es inventario de la red local, gratis y sin
    autenticar.

    Returns:
        El datagrama completo.
    """
    return build_dns_query("_services._dns-sd._udp.local", DNS_TYPE_PTR,
                           DNS_CLASS_IN, transaction_id=0, flags=0)


# =========================================================================
# NTP (123) — dos mensajes, dos preguntas distintas
# =========================================================================

# Modo 6: mensajes de control. Modo 7: mensajes privados del implementador,
# que es donde vive `monlist`.
_NTP_CONTROL_HEADER = 0x16          # versión 2, modo 6
_NTP_PRIVATE_HEADER = 0x17          # versión 2, modo 7
_NTP_OPCODE_READVAR = 2
_NTP_IMPLEMENTATION_XNTPD = 3
NTP_REQUEST_MONLIST = 42


def build_ntp_readvar() -> bytes:
    """Construye un ``READVAR`` de control (modo 6), que pide las variables del sistema.

    La respuesta es texto plano con ``version=``, ``processor=``, ``system=``
    y demás: la identificación completa del demonio en una sola lectura.

    Returns:
        Los doce bytes del mensaje.
    """
    return struct.pack(
        "!BBHHHHH",
        _NTP_CONTROL_HEADER, _NTP_OPCODE_READVAR,
        0,      # sequence
        0,      # status
        0,      # association id
        0,      # offset
        0,      # count
    )


def build_ntp_monlist() -> bytes:
    """Construye la petición ``monlist`` (modo 7, código 42).

    ``monlist`` devuelve los últimos seiscientos clientes que han hablado con
    el servidor. Es a la vez un problema de privacidad —el inventario de quién
    usa ese NTP— y **el vector de amplificación x500** que llenó internet de
    ataques en 2014: una petición de ocho bytes provoca una respuesta de varios
    kilobytes.

    Que se pueda pedir es el hallazgo. La respuesta viene **a nosotros**, no a
    un tercero, así que preguntarlo no amplifica nada contra nadie; lo que
    demuestra es que ese servidor serviría para hacerlo.

    Returns:
        Los ocho bytes del mensaje.
    """
    return struct.pack(
        "!BBBB", _NTP_PRIVATE_HEADER, 0,
        _NTP_IMPLEMENTATION_XNTPD, NTP_REQUEST_MONLIST,
    ) + b"\x00" * 4


# =========================================================================
# NetBIOS-NS (137) — nombre, dominio y MAC de un Windows sin tocar SMB
# =========================================================================

NETBIOS_TYPE_NBSTAT = 0x0021
_NETBIOS_WILDCARD = "*"


def encode_netbios_name(name: str) -> bytes:
    """Codifica un nombre NetBIOS en su forma de primer nivel (RFC 1001 §4.1).

    El nombre se rellena con espacios hasta dieciséis caracteres y cada byte se
    parte en dos mitades de cuatro bits, cada una sumada a la letra ``A``. Es
    una codificación peculiar y muy antigua, pero completamente determinista.

    El comodín ``"*"`` es la excepción: se rellena con ceros y no con espacios,
    porque así lo define la especificación para la consulta de estado de
    adaptador.

    Args:
        name: El nombre NetBIOS.

    Returns:
        El nombre codificado, con su byte de longitud y su terminador.
    """
    padding = b"\x00" if name == _NETBIOS_WILDCARD else b" "
    raw = name.encode("ascii")[:16].ljust(16, padding)
    encoded = b""
    for byte in raw:
        encoded += bytes((ord("A") + (byte >> 4), ord("A") + (byte & 0x0F)))
    return bytes((len(encoded),)) + encoded + b"\x00"


def build_netbios_name_query() -> bytes:
    """Construye una consulta de estado de adaptador (``NBSTAT``) al comodín.

    Un Windows contesta con su tabla de nombres —equipo, dominio, servicios— y
    con la **dirección MAC** de la interfaz, todo sin tocar SMB y sin
    autenticarse.

    Returns:
        El datagrama completo.
    """
    header = struct.pack("!HHHHHH", 0x1337, 0, 1, 0, 0, 0)
    question = encode_netbios_name(_NETBIOS_WILDCARD) + struct.pack(
        "!HH", NETBIOS_TYPE_NBSTAT, DNS_CLASS_IN)
    return header + question


# =========================================================================
# IKE / ISAKMP (500) — identificar el gateway VPN y lo que acepta
# =========================================================================

ISAKMP_HEADER_SIZE = 28
ISAKMP_PAYLOAD_SA = 1
ISAKMP_PAYLOAD_PROPOSAL = 2
ISAKMP_PAYLOAD_TRANSFORM = 3
ISAKMP_EXCHANGE_MAIN_MODE = 2
ISAKMP_VERSION = 0x10               # 1.0
_ISAKMP_DOI_IPSEC = 1
_ISAKMP_SITUATION_IDENTITY = 1
_ISAKMP_PROTOCOL_ISAKMP = 1
_ISAKMP_TRANSFORM_KEY_IKE = 1

# Atributos de una transformada, en formato tipo-valor de dos bytes cada uno
# (el bit alto del tipo indica «el valor cabe aquí mismo»). Los cuatro que
# definen una propuesta de fase 1: cifrado, hash, autenticación y grupo DH.
_ATTRIBUTE_ENCRYPTION = 0x8001
_ATTRIBUTE_HASH = 0x8002
_ATTRIBUTE_AUTH = 0x8003
_ATTRIBUTE_GROUP = 0x8004

# Las transformadas que se ofrecen. Se manda un abanico deliberadamente amplio
# —de 3DES/SHA1 a AES-256/SHA2— porque lo interesante **no es que la
# negociación prospere, sino cuál elige el servidor**: un gateway que acepta
# DES o MD5 lo está diciendo él mismo.
IKE_TRANSFORMS: Tuple[Tuple[int, int, int, int], ...] = (
    (7, 2, 1, 14),      # AES, SHA1, clave precompartida, grupo 14
    (7, 4, 1, 14),      # AES, SHA2-256
    (5, 2, 1, 2),       # 3DES, SHA1, grupo 2
    (5, 1, 1, 2),       # 3DES, MD5
    (1, 1, 1, 1),       # DES, MD5, grupo 1 — el que nadie debería aceptar
)


def _ike_transform(number: int, transform: Tuple[int, int, int, int],
                   is_last: bool) -> bytes:
    """Serializa una transformada de fase 1 con sus cuatro atributos."""
    encryption, hash_algorithm, authentication, group = transform
    attributes = b"".join(
        struct.pack("!HH", attribute, value) for attribute, value in (
            (_ATTRIBUTE_ENCRYPTION, encryption),
            (_ATTRIBUTE_HASH, hash_algorithm),
            (_ATTRIBUTE_AUTH, authentication),
            (_ATTRIBUTE_GROUP, group),
        )
    )
    body = struct.pack("!BBH", number, _ISAKMP_TRANSFORM_KEY_IKE, 0) + attributes
    next_payload = 0 if is_last else ISAKMP_PAYLOAD_TRANSFORM
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def build_ike_main_mode(initiator_cookie: bytes = b"Lybra\x00\x00\x01",
                        transforms: Iterable[Tuple[int, int, int, int]] = IKE_TRANSFORMS,
                        ) -> bytes:
    """Construye una petición de modo principal de IKEv1 con varias transformadas.

    La estructura es de muñecas rusas —cabecera, payload SA, dentro una
    propuesta, dentro las transformadas— y **cada nivel declara su propia
    longitud incluyéndose a sí mismo**. Se serializa de dentro hacia fuera por
    eso: no se puede escribir la longitud de un nivel hasta tener el de abajo.

    Args:
        initiator_cookie: La cookie del iniciador, ocho bytes.
        transforms: Las transformadas a ofrecer, como tuplas
            ``(cifrado, hash, autenticación, grupo)``.

    Returns:
        El datagrama completo.
    """
    transform_list = list(transforms)
    serialized = b"".join(
        _ike_transform(number + 1, transform, number == len(transform_list) - 1)
        for number, transform in enumerate(transform_list)
    )

    proposal_body = struct.pack(
        "!BBBB", 1, _ISAKMP_PROTOCOL_ISAKMP, 0, len(transform_list),
    ) + serialized
    proposal = struct.pack("!BBH", 0, 0, 4 + len(proposal_body)) + proposal_body

    sa_body = struct.pack("!II", _ISAKMP_DOI_IPSEC, _ISAKMP_SITUATION_IDENTITY) + proposal
    security_association = struct.pack(
        "!BBH", ISAKMP_PAYLOAD_PROPOSAL, 0, 4 + len(sa_body)) + sa_body

    header = struct.pack(
        "!8s8sBBBBII",
        initiator_cookie[:8].ljust(8, b"\x00"),
        b"\x00" * 8,                                  # cookie del respondedor
        ISAKMP_PAYLOAD_SA,                            # siguiente payload
        ISAKMP_VERSION,
        ISAKMP_EXCHANGE_MAIN_MODE,
        0,                                            # banderas
        0,                                            # identificador de mensaje
        ISAKMP_HEADER_SIZE + len(security_association),
    )
    return header + security_association


# =========================================================================
# SQL Server Browser (1434) — más barato aún que el PRELOGIN de TDS
# =========================================================================

def build_mssql_browser_query() -> bytes:
    """Construye la petición del servicio SQL Server Browser: un solo byte.

    Devuelve, en texto plano y sin autenticar, el nombre del servidor, el de
    cada instancia y su versión. Es la vía más barata que existe para
    identificar un SQL Server — más aún que el ``PRELOGIN`` de TDS del puerto
    1433, y funciona incluso cuando las instancias escuchan en puertos
    dinámicos que ningún barrido encontraría.

    Returns:
        El único byte del mensaje.
    """
    return b"\x02"
