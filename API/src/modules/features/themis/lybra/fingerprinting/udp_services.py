"""Los consumidores de la superficie UDP — un dissector por sonda (L22).

La tabla de sondas UDP creció de una fila a siete, y la regla que la gobierna
desde la Ronda 1 es que **cada fila llega con su consumidor**, nunca la sonda
sola: un payload sin nadie que lea la respuesta sólo produce un ``open_port``
informativo a cambio de construir y validar una consulta más.

Este módulo es esa mitad. Los payloads viven en :mod:`~..udp_payloads`, por la
misma razón de siempre — ``transport.py`` los necesita para la tabla de
descubrimiento y no puede importar de aquí sin crear un ciclo.

Los cinco protocolos, y qué aporta cada uno:

``domain`` (53)
    La versión de BIND por ``version.bind``, y —en la misma respuesta— si el
    servidor ofrece recursión a cualquiera, que es un **resolutor abierto**.

``ntp`` (123)
    Versión e implementación del demonio por ``readvar``, y si acepta
    ``monlist``, el vector de amplificación x500.

``netbios-ns`` (137)
    Nombre de equipo, dominio y **dirección MAC** de un Windows, sin tocar SMB
    y sin autenticarse.

``mdns`` (5353)
    El inventario de servicios que la red local anuncia sola.

``isakmp`` (500)
    El gateway VPN y —lo que de verdad importa— **qué cifrado acepta**: un
    gateway que negocia DES o MD5 lo está diciendo él mismo.

``ms-sql-m`` (1434)
    Nombre de servidor, de instancia y versión de un SQL Server, en texto
    plano. Más barato que el ``PRELOGIN`` de TDS del 1433, y encuentra
    instancias en puertos dinámicos que ningún barrido vería.

**Todos hablan UDP y sólo UDP.** Cada predicado de aplicabilidad lo comprueba,
igual que el de SNMP: varios de estos puertos existen también como TCP, y
mandarle un datagrama a un servicio TCP es tiempo perdido y un hallazgo
duplicado con la misma ``dedup_key``.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..checks import (
    is_dns_service,
    is_ike_service,
    is_mdns_service,
    is_mssql_browser_service,
    is_netbios_service,
    is_ntp_service,
)
from ..transport import udp_send_recv
from ..udp_payloads import (
    DNS_FLAG_RECURSION_AVAILABLE,
    ISAKMP_HEADER_SIZE,
    ISAKMP_PAYLOAD_SA,
    build_dns_version_query,
    build_ike_main_mode,
    build_mdns_services_query,
    build_mssql_browser_query,
    build_netbios_name_query,
    build_ntp_monlist,
    build_ntp_readvar,
)
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

_DNS_HEADER_SIZE = 12


# =========================================================================
# Utilidades compartidas por los que hablan el formato de DNS
# =========================================================================

def skip_dns_name(data: bytes, offset: int) -> int:
    """Salta un nombre codificado, siguiendo la compresión de punteros.

    Un nombre puede terminar en un puntero de dos bytes que apunta a otro
    lugar del mensaje (RFC 1035 §4.1.4). Aquí no hace falta resolverlo —sólo
    saber dónde sigue el mensaje—, así que un puntero se salta entero.

    Args:
        data: El datagrama.
        offset: Dónde empieza el nombre.

    Returns:
        El desplazamiento del primer byte posterior al nombre.

    Raises:
        ValueError: Si el mensaje está truncado.
    """
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:          # puntero de compresión
            return offset + 2
        offset += 1 + length
    raise ValueError("nombre DNS truncado")


def _first_answer(data: bytes) -> Optional[Tuple[int, bytes]]:
    """Devuelve el ``(tipo, rdata)`` de la primera respuesta del mensaje.

    Args:
        data: El datagrama.

    Returns:
        El par, o ``None`` si el mensaje no trae ninguna respuesta legible.
    """
    if len(data) < _DNS_HEADER_SIZE:
        return None
    question_count, answer_count = struct.unpack_from("!HH", data, 4)
    if not answer_count:
        return None
    try:
        offset = _DNS_HEADER_SIZE
        for _ in range(question_count):
            offset = skip_dns_name(data, offset) + 4
        offset = skip_dns_name(data, offset)
        record_type, _record_class, _ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset + rdlength]
        return (record_type, rdata) if len(rdata) == rdlength else None
    except (ValueError, struct.error):
        return None


# =========================================================================
# DNS (53)
# =========================================================================

@dataclass(frozen=True)
class DnsFingerprint:
    """Lo que una consulta ``version.bind`` cuenta de un servidor DNS.

    Attributes:
        product: El producto, o ``None`` si la respuesta no era DNS.
        version: La versión que el servidor publica, cuando la publica —
            suprimirla es lo primero que recomienda cualquier guía, así que lo
            normal es ``None``.
        offers_recursion: Si el servidor enciende la bandera de recursión
            disponible. Un servidor autoritativo público la deja apagada; uno
            que la enciende para cualquiera es un **resolutor abierto**, y por
            tanto un amplificador a disposición de quien lo quiera usar.
    """
    product: Optional[str]
    version: Optional[str]
    offers_recursion: bool = False


# "9.16.1-Ubuntu", "9.11.3-1ubuntu1.17-Ubuntu": la versión va delante y el
# resto es el empaquetado de la distribución.
_BIND_VERSION_RE = re.compile(r"^(?P<version>\d+\.\d+[\w.\-]*)")

_DNS_PRODUCT = "BIND"
_DNS_GENERIC_PRODUCT = "DNS"


def parse_dns_version_response(data: bytes) -> DnsFingerprint:
    """Interpreta la respuesta a ``version.bind``.

    Args:
        data: El datagrama recibido.

    Returns:
        El :class:`DnsFingerprint`. Sin producto cuando el datagrama no es una
        respuesta DNS: un puerto que contesta cualquier cosa no es un DNS.
    """
    if len(data) < _DNS_HEADER_SIZE:
        return DnsFingerprint(None, None)
    flags = struct.unpack_from("!H", data, 2)[0]
    if not flags & 0x8000:                       # el bit de "esto es respuesta"
        return DnsFingerprint(None, None)

    offers_recursion = bool(flags & DNS_FLAG_RECURSION_AVAILABLE)
    answer = _first_answer(data)
    if answer is None or not answer[1]:
        # Contestó DNS pero no publica su versión, que es lo normal en un
        # servidor bien administrado.
        return DnsFingerprint(_DNS_GENERIC_PRODUCT, None, offers_recursion)

    # Un TXT es una secuencia de cadenas, cada una con su byte de longitud.
    rdata = answer[1]
    text = rdata[1:1 + rdata[0]].decode("utf-8", "ignore")
    found = _BIND_VERSION_RE.match(text.strip())
    if not found:
        return DnsFingerprint(_DNS_GENERIC_PRODUCT, None, offers_recursion)
    return DnsFingerprint(_DNS_PRODUCT, found.group("version"), offers_recursion)


class DnsProbe:  # pylint: disable=too-few-public-methods
    """Manda la consulta ``version.bind`` y devuelve la respuesta cruda.

    Args:
        timeout: El plazo de la operación, en segundos.
        sender: Callable inyectable ``(host, port, payload, timeout)``, mismo
            patrón que :class:`~.snmp.SnmpProbe`.
    """

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 53) -> Optional[bytes]:
        """Consulta ``version.bind`` y devuelve el datagrama de respuesta."""
        return self._sender(host, port, build_dns_version_query(), self._timeout)


@register_dissector
class DnsDissector(Dissector):
    """``version.bind``: versión del servidor y si resuelve para cualquiera."""

    label = "DNS"

    def __init__(self, probe: Optional[DnsProbe] = None) -> None:
        self._probe = probe or DnsProbe()

    def applies(self, service) -> bool:
        return is_dns_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 53)
        if reply is None:
            return None
        fingerprint = parse_dns_version_response(reply)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)


# =========================================================================
# NTP (123)
# =========================================================================

@dataclass(frozen=True)
class NtpFingerprint:
    """Lo que ``readvar`` cuenta de un servidor de hora.

    Attributes:
        product: El demonio identificado, o ``None``.
        version: Su versión, cuando la publica.
        system: El sistema operativo que declara, cuando lo declara.
    """
    product: Optional[str]
    version: Optional[str]
    system: Optional[str] = None


# La respuesta de readvar es texto plano de pares clave=valor separados por
# comas: `version="ntpd 4.2.8p15@1.3728-o", processor="x86_64", system="Linux/5.4"`.
_NTP_VARIABLE_RE = re.compile(r'(\w+)="?([^",]*)"?')
_NTPD_VERSION_RE = re.compile(r"ntpd\s+(?P<version>[\w.]+)", re.IGNORECASE)

_NTP_PRODUCT = "ntpd"
_NTP_GENERIC_PRODUCT = "NTP"
# Modo 6 en la respuesta: los tres bits bajos del primer byte.
_NTP_MODE_CONTROL = 6
_NTP_MODE_PRIVATE = 7


def parse_ntp_readvar_response(data: bytes) -> NtpFingerprint:
    """Interpreta la respuesta a un ``READVAR`` de control.

    Args:
        data: El datagrama recibido.

    Returns:
        El :class:`NtpFingerprint`.
    """
    if len(data) < 12 or data[0] & 0x07 != _NTP_MODE_CONTROL:
        return NtpFingerprint(None, None)
    variables: Dict[str, str] = dict(_NTP_VARIABLE_RE.findall(
        data[12:].decode("utf-8", "ignore")))
    raw_version = variables.get("version", "")
    found = _NTPD_VERSION_RE.search(raw_version)
    if not found:
        return NtpFingerprint(_NTP_GENERIC_PRODUCT, None, variables.get("system") or None)
    return NtpFingerprint(_NTP_PRODUCT, found.group("version"),
                          variables.get("system") or None)


def monlist_is_answered(data: Optional[bytes]) -> bool:
    """Decide si una respuesta demuestra que ``monlist`` sigue disponible.

    Args:
        data: El datagrama recibido, o ``None``.

    Returns:
        ``True`` sólo cuando el servidor contesta un mensaje privado (modo 7)
        **sin marcar error**. Un ``ntpd`` moderno responde con el bit de error
        encendido o directamente calla; las dos cosas son un no.
    """
    if not data or len(data) < 8:
        return False
    if data[0] & 0x07 != _NTP_MODE_PRIVATE:
        return False
    # Bit 6 del segundo byte: "esta respuesta es un error".
    return not data[1] & 0x40


class NtpProbe:
    """Manda los dos mensajes de NTP: ``readvar`` y ``monlist``.

    Args:
        timeout: El plazo de cada operación, en segundos.
        sender: Callable inyectable ``(host, port, payload, timeout)``.
    """

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 123) -> Optional[bytes]:
        """Pide las variables del sistema con un ``READVAR``."""
        return self._sender(host, port, build_ntp_readvar(), self._timeout)

    def fetch_monlist(self, host: str, port: int = 123) -> Optional[bytes]:
        """Pide ``monlist``, el vector de amplificación."""
        return self._sender(host, port, build_ntp_monlist(), self._timeout)


@register_dissector
class NtpDissector(Dissector):
    """``readvar``: versión e implementación del demonio de hora."""

    label = "NTP"

    def __init__(self, probe: Optional[NtpProbe] = None) -> None:
        self._probe = probe or NtpProbe()

    def applies(self, service) -> bool:
        return is_ntp_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 123)
        if reply is None:
            return None
        fingerprint = parse_ntp_readvar_response(reply)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)


# =========================================================================
# NetBIOS-NS (137)
# =========================================================================

@dataclass(frozen=True)
class NetbiosFingerprint:
    """La tabla de nombres que un Windows publica en el 137.

    Attributes:
        hostname: El nombre del equipo.
        domain: El grupo de trabajo o dominio.
        mac_address: La dirección MAC de la interfaz, en formato legible.
        names: Todos los nombres declarados, por si hacen falta.
    """
    hostname: Optional[str]
    domain: Optional[str]
    mac_address: Optional[str] = None
    names: Tuple[str, ...] = ()


# Bit alto de las banderas de un nombre: es un nombre de grupo (el dominio)
# y no de una máquina concreta.
_NETBIOS_GROUP_FLAG = 0x8000
_NETBIOS_NAME_ENTRY_SIZE = 18


def parse_netbios_response(data: bytes) -> NetbiosFingerprint:
    """Interpreta la respuesta ``NBSTAT`` de un equipo Windows.

    Args:
        data: El datagrama recibido.

    Returns:
        El :class:`NetbiosFingerprint`. Sin nombre de equipo cuando la
        respuesta no es legible.
    """
    empty = NetbiosFingerprint(None, None)
    if len(data) < _DNS_HEADER_SIZE:
        return empty
    try:
        offset = skip_dns_name(data, _DNS_HEADER_SIZE) + 10
    except ValueError:
        return empty
    if offset >= len(data):
        return empty

    count = data[offset]
    offset += 1
    hostname: Optional[str] = None
    domain: Optional[str] = None
    names: List[str] = []
    for _ in range(count):
        if offset + _NETBIOS_NAME_ENTRY_SIZE > len(data):
            break
        name = data[offset:offset + 15].decode("ascii", "ignore").strip()
        flags = struct.unpack_from("!H", data, offset + 16)[0]
        offset += _NETBIOS_NAME_ENTRY_SIZE
        if not name:
            continue
        names.append(name)
        if flags & _NETBIOS_GROUP_FLAG:
            domain = domain or name
        else:
            hostname = hostname or name

    mac_address = None
    if offset + 6 <= len(data):
        raw = data[offset:offset + 6]
        if any(raw):
            mac_address = ":".join(f"{byte:02x}" for byte in raw)

    return NetbiosFingerprint(hostname, domain, mac_address, tuple(names))


class NetbiosProbe:  # pylint: disable=too-few-public-methods
    """Manda la consulta de estado de adaptador al comodín."""

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 137) -> Optional[bytes]:
        """Devuelve el datagrama de respuesta, o ``None``."""
        return self._sender(host, port, build_netbios_name_query(), self._timeout)


@register_dissector
class NetbiosDissector(Dissector):
    """Nombre de equipo, dominio y MAC sin tocar SMB ni autenticarse."""

    label = "NetBIOS"

    def __init__(self, probe: Optional[NetbiosProbe] = None) -> None:
        self._probe = probe or NetbiosProbe()

    def applies(self, service) -> bool:
        return is_netbios_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 137)
        if reply is None:
            return None
        fingerprint = parse_netbios_response(reply)
        if not fingerprint.hostname and not fingerprint.domain:
            return None
        # El nombre del equipo no es un producto y no debe resolver un CPE: va
        # en la etiqueta, que es lo que llega al título del hallazgo.
        identity = fingerprint.hostname or ""
        if fingerprint.domain:
            identity = f"{identity} ({fingerprint.domain})".strip()
        return DissectorResult("NetBIOS", None, f"{self.label} en {identity}")


# =========================================================================
# mDNS (5353)
# =========================================================================

class MdnsProbe:  # pylint: disable=too-few-public-methods
    """Pregunta por el catálogo de servicios que anuncia la red local."""

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 5353) -> Optional[bytes]:
        """Devuelve el datagrama de respuesta, o ``None``."""
        return self._sender(host, port, build_mdns_services_query(), self._timeout)


def parse_mdns_response(data: bytes) -> Tuple[str, ...]:
    """Extrae los tipos de servicio anunciados de una respuesta mDNS.

    Args:
        data: El datagrama recibido.

    Returns:
        Los nombres de servicio, sin repetir y en el orden en que aparecen.
        Vacío si la respuesta no es legible.
    """
    if len(data) < _DNS_HEADER_SIZE or not struct.unpack_from("!H", data, 2)[0] & 0x8000:
        return ()
    # Las respuestas de DNS-SD nombran servicios como "_http._tcp.local". Se
    # extraen del datagrama entero en vez de recorrer los registros uno a uno:
    # una respuesta mDNS trae los nombres repartidos entre respuestas y
    # registros adicionales, con compresión, y lo que aporta valor aquí es el
    # inventario, no la estructura.
    services = []
    for found in re.finditer(rb"(_[\w\-]+)\x04_(tcp|udp)", data):
        name = f"{found.group(1).decode('ascii', 'ignore')}._{found.group(2).decode()}"
        if name not in services:
            services.append(name)
    return tuple(services)


@register_dissector
class MdnsDissector(Dissector):
    """El inventario de servicios que la red local anuncia sola."""

    label = "mDNS"

    def __init__(self, probe: Optional[MdnsProbe] = None) -> None:
        self._probe = probe or MdnsProbe()

    def applies(self, service) -> bool:
        return is_mdns_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 5353)
        if reply is None:
            return None
        services = parse_mdns_response(reply)
        if not services:
            return None
        return DissectorResult("mDNS", None, f"{self.label}: {', '.join(services)}")


# =========================================================================
# IKE / ISAKMP (500)
# =========================================================================

# Nombres de los valores que puede elegir el gateway, para que el hallazgo diga
# algo legible. Los marcados como débiles son los que ya no deberían aceptarse.
IKE_ENCRYPTION: Dict[int, str] = {
    1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES",
}
IKE_HASH: Dict[int, str] = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
IKE_AUTH: Dict[int, str] = {1: "clave precompartida", 3: "RSA", 5: "firma RSA"}

# Los algoritmos cuyo uso es, hoy, un hallazgo por sí mismo.
WEAK_ENCRYPTION = {"DES", "3DES"}
WEAK_HASH = {"MD5", "SHA1"}


@dataclass(frozen=True)
class IkeFingerprint:
    """La transformada que un gateway VPN elige de las que se le ofrecen.

    Attributes:
        product: ``"IKE"`` si contestó ISAKMP, ``None`` si no.
        encryption: El cifrado elegido, con nombre.
        hash_algorithm: El hash elegido.
        authentication: El método de autenticación elegido.
    """
    product: Optional[str]
    encryption: Optional[str] = None
    hash_algorithm: Optional[str] = None
    authentication: Optional[str] = None

    @property
    def accepts_weak_cryptography(self) -> bool:
        """Si lo que el gateway ha elegido está retirado por débil."""
        return (self.encryption in WEAK_ENCRYPTION) or (self.hash_algorithm in WEAK_HASH)


def parse_ike_response(data: bytes) -> IkeFingerprint:
    """Interpreta la respuesta de un gateway a una petición de modo principal.

    Sólo se busca la transformada elegida, que está anidada dentro del payload
    de asociación de seguridad. Si el gateway contesta otra cosa —una
    notificación de error, por ejemplo— se reconoce el servicio pero no la
    configuración.

    Args:
        data: El datagrama recibido.

    Returns:
        El :class:`IkeFingerprint`.
    """
    if len(data) < ISAKMP_HEADER_SIZE:
        return IkeFingerprint(None)
    # La cookie del respondedor viene rellena: es lo que distingue una
    # respuesta de un eco de nuestra propia petición.
    if not any(data[8:16]):
        return IkeFingerprint(None)
    if data[16] != ISAKMP_PAYLOAD_SA:
        return IkeFingerprint("IKE")

    attributes: Dict[int, int] = {}
    # SA (4 de cabecera + 8 de DOI y situación) → propuesta (8) → transformada (8).
    offset = ISAKMP_HEADER_SIZE + 4 + 8 + 8 + 8
    while offset + 4 <= len(data):
        attribute, value = struct.unpack_from("!HH", data, offset)
        if not attribute & 0x8000:          # sólo se leen los de valor corto
            break
        attributes[attribute & 0x7FFF] = value
        offset += 4

    return IkeFingerprint(
        product="IKE",
        encryption=IKE_ENCRYPTION.get(attributes.get(1, -1)),
        hash_algorithm=IKE_HASH.get(attributes.get(2, -1)),
        authentication=IKE_AUTH.get(attributes.get(3, -1)),
    )


class IkeProbe:  # pylint: disable=too-few-public-methods
    """Ofrece un abanico de transformadas y mira cuál elige el gateway."""

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 500) -> Optional[bytes]:
        """Devuelve el datagrama de respuesta, o ``None``."""
        return self._sender(host, port, build_ike_main_mode(), self._timeout)


@register_dissector
class IkeDissector(Dissector):
    """El gateway VPN y qué criptografía acepta."""

    label = "IKE"

    def __init__(self, probe: Optional[IkeProbe] = None) -> None:
        self._probe = probe or IkeProbe()

    def applies(self, service) -> bool:
        return is_ike_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 500)
        if reply is None:
            return None
        fingerprint = parse_ike_response(reply)
        if not fingerprint.product:
            return None
        chosen = " / ".join(part for part in (
            fingerprint.encryption, fingerprint.hash_algorithm) if part)
        label = f"{self.label} ({chosen})" if chosen else self.label
        return DissectorResult(fingerprint.product, None, label)


# =========================================================================
# SQL Server Browser (1434)
# =========================================================================

_BROWSER_RESPONSE_HEADER = 3


def parse_mssql_browser_response(data: bytes) -> Dict[str, str]:
    """Interpreta la respuesta en texto plano del SQL Server Browser.

    El formato son pares clave-valor separados por punto y coma:
    ``ServerName;SRV01;InstanceName;MSSQLSERVER;Version;15.0.2000.5;;``.

    Args:
        data: El datagrama recibido.

    Returns:
        Los pares de la **primera** instancia anunciada, o un mapa vacío. Sólo
        la primera: un servidor con varias instancias las separa con ``;;``, y
        un fingerprint reporta un servicio, no una lista.
    """
    if len(data) <= _BROWSER_RESPONSE_HEADER:
        return {}
    text = data[_BROWSER_RESPONSE_HEADER:].decode("utf-8", "ignore")
    first = text.split(";;")[0]
    parts = [part for part in first.split(";") if part]
    if len(parts) < 2:
        return {}
    return dict(zip(parts[0::2], parts[1::2]))


class MssqlBrowserProbe:  # pylint: disable=too-few-public-methods
    """Manda el único byte que el SQL Server Browser espera."""

    def __init__(self, timeout: float = 2.0, sender: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._sender = sender or udp_send_recv

    def fetch(self, host: str, port: int = 1434) -> Optional[bytes]:
        """Devuelve el datagrama de respuesta, o ``None``."""
        return self._sender(host, port, build_mssql_browser_query(), self._timeout)


@register_dissector
class MssqlBrowserDissector(Dissector):
    """Nombre de instancia y versión de un SQL Server, en texto plano."""

    label = "MSSQL Browser"

    def __init__(self, probe: Optional[MssqlBrowserProbe] = None) -> None:
        self._probe = probe or MssqlBrowserProbe()

    def applies(self, service) -> bool:
        return is_mssql_browser_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 1434)
        if reply is None:
            return None
        fields = parse_mssql_browser_response(reply)
        version = fields.get("Version")
        if not version:
            return None
        instance = fields.get("InstanceName")
        label = f"{self.label} ({instance})" if instance else self.label
        return DissectorResult("Microsoft SQL Server", version, label)
