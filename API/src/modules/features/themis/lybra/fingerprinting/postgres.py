"""El dissector de PostgreSQL — el primero que negocia en vez de escuchar.

PostgreSQL es una de las bases de datos que, a diferencia de MySQL/Redis,
exige un handshake negociado en vez de ofrecer un banner por su cuenta: el
coste de identificarla es mayor, pero el valor también lo es, porque un
PostgreSQL expuesto es un hallazgo de primer orden y sin este dissector no
pasaría de un ``open_port`` informativo y nada más.

**Conviene ser honesto sobre el techo: PostgreSQL no regala su versión antes de
autenticar.** Ningún truco cambia eso. Lo que sí se puede observar sin
credenciales, y ya es bastante, son tres cosas:

- Si el servidor **exige o admite TLS**, preguntándoselo con un ``SSLRequest``
  de ocho bytes al que contesta con una sola letra: ``S`` o ``N``.
- Qué **método de autenticación** anuncia. Y aquí está el hallazgo: un
  servidor en modo ``trust`` accesible por red es acceso total **sin
  contraseña** — no una configuración débil, la ausencia completa de
  autenticación.
- El **mensaje de error** ante un usuario inexistente, que en algunas
  configuraciones nombra la versión.

Los dos intercambios son lecturas del protocolo de conexión: **no se intenta
autenticar en ningún momento**, no se manda contraseña ninguna y no se prueba
credencial alguna. Por eso caben en modo ``safe``. Un intento de login sería
otra cosa, y no está aquí.

El formato de los mensajes viene de la documentación de PostgreSQL, "Frontend/
Backend Protocol" §55.2.1 y §55.7. Todo se construye y se parsea a mano: traer
``psycopg`` para leer dos respuestas sería la misma desproporción que traer
``pysnmp`` para un solo GetRequest.

Este módulo paga el diseño que :mod:`mssql` y :mod:`mongo` reutilizan.
"""

from __future__ import annotations

import logging
import re
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from ..checks import is_postgres_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# El código mágico que convierte los ocho bytes en una petición de TLS
# (documentación de PostgreSQL §55.2.1). No es un número de versión de
# protocolo: es un valor reservado que el servidor reconoce como "¿hablas
# TLS?".
SSL_REQUEST_CODE = 80877103

# Versión 3.0 del protocolo, empaquetada como major<<16 | minor. Es la que
# habla todo servidor desde PostgreSQL 7.4 (2003).
PROTOCOL_VERSION_3 = 196608

# Los métodos de autenticación que un ``AuthenticationRequest`` puede anunciar,
# por su código. El 0 es el que importa: significa que el servidor ha dado la
# conexión por buena **sin pedir nada**.
AUTH_METHODS: Dict[int, str] = {
    0: "trust",
    2: "gss",
    3: "password",
    5: "md5",
    6: "scm-credential",
    7: "gss-continue",
    9: "sspi",
    10: "sasl",
    12: "sasl-final",
}

# El método que es, por sí solo, un hallazgo crítico.
NO_AUTHENTICATION = "trust"

# "PostgreSQL 16.1 on x86_64-pc-linux-gnu" — la forma en que el servidor se
# nombra a sí mismo cuando aparece en un mensaje de error.
_VERSION_RE = re.compile(r"PostgreSQL\s+(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE)

_PRODUCT = "PostgreSQL"


@dataclass(frozen=True)
class PostgresFingerprint:
    """Lo que se puede saber de un PostgreSQL sin autenticarse.

    Attributes:
        product: ``"PostgreSQL"`` si el servidor habló el protocolo, ``None``
            si no se reconoció nada.
        version: La versión, sólo cuando el servidor la nombró. Suele ser
            ``None``, y eso es correcto: no se inventa lo que no se observó.
        accepts_tls: ``True`` si el servidor acepta TLS, ``False`` si contestó
            que no, ``None`` si no llegó a preguntarse.
        auth_method: El método anunciado (:data:`AUTH_METHODS`), o ``None``.
        sasl_mechanisms: Los mecanismos SASL ofrecidos, cuando el método es
            ``sasl`` — es donde aparece ``SCRAM-SHA-256``.
    """
    product: Optional[str]
    version: Optional[str]
    accepts_tls: Optional[bool]
    auth_method: Optional[str]
    sasl_mechanisms: Tuple[str, ...] = ()

    @property
    def is_unauthenticated(self) -> bool:
        """Si el servidor deja entrar sin credencial ninguna (modo ``trust``)."""
        return self.auth_method == NO_AUTHENTICATION


def build_ssl_request() -> bytes:
    """Construye el ``SSLRequest``: ocho bytes, longitud y código mágico.

    Returns:
        El mensaje completo, listo para enviar nada más conectar.
    """
    return struct.pack("!ii", 8, SSL_REQUEST_CODE)


def build_startup_message(user: str, database: Optional[str] = None) -> bytes:
    """Construye un ``StartupMessage`` para el usuario indicado.

    Se manda con un usuario que no existe **a propósito**: la respuesta dice
    qué método de autenticación anuncia el servidor sin que haga falta acertar
    con ningún nombre real, y sin intentar autenticarse.

    Args:
        user: El nombre de usuario a declarar.
        database: La base de datos, si se quiere declarar una.

    Returns:
        El mensaje completo, con su longitud por delante.
    """
    parameters = b"user\x00" + user.encode("utf-8") + b"\x00"
    if database:
        parameters += b"database\x00" + database.encode("utf-8") + b"\x00"
    body = struct.pack("!i", PROTOCOL_VERSION_3) + parameters + b"\x00"
    return struct.pack("!i", len(body) + 4) + body


def parse_ssl_response(data: bytes) -> Optional[bool]:
    """Interpreta la respuesta de una sola letra al ``SSLRequest``.

    Args:
        data: Los bytes recibidos.

    Returns:
        ``True`` si el servidor acepta TLS (``S``), ``False`` si lo rechaza
        (``N``), ``None`` si la respuesta no es ninguna de las dos — lo que
        significa que al otro lado no hay un PostgreSQL.
    """
    if not data:
        return None
    if data[:1] == b"S":
        return True
    if data[:1] == b"N":
        return False
    return None


def _parse_error_fields(body: bytes) -> Dict[str, str]:
    """Descompone un ``ErrorResponse`` en sus campos etiquetados.

    Cada campo es un byte de tipo (``S`` severidad, ``C`` código, ``M``
    mensaje...) seguido de una cadena terminada en NUL; un byte cero suelto
    cierra la lista.

    Args:
        body: El cuerpo del mensaje, sin el byte de tipo ni la longitud.

    Returns:
        Un mapa etiqueta → valor.
    """
    fields: Dict[str, str] = {}
    offset = 0
    while offset < len(body) and body[offset] != 0:
        label = chr(body[offset])
        end = body.find(b"\x00", offset + 1)
        if end == -1:
            break
        fields[label] = body[offset + 1:end].decode("utf-8", "ignore")
        offset = end + 1
    return fields


def parse_startup_response(data: bytes) -> Tuple[Optional[str], Optional[str], Tuple[str, ...]]:
    """Interpreta la respuesta al ``StartupMessage``.

    El servidor contesta con un ``AuthenticationRequest`` (``R``), que dice qué
    método exige, o con un ``ErrorResponse`` (``E``), que a veces nombra la
    versión.

    Args:
        data: Los bytes recibidos.

    Returns:
        Una tupla ``(método, versión, mecanismos SASL)``. El método es ``None``
        cuando la respuesta es un error o no se reconoce; la versión, cuando el
        servidor no la nombró.
    """
    if len(data) < 5:
        return None, None, ()
    kind = data[:1]
    length = struct.unpack("!i", data[1:5])[0]
    body = data[5:4 + length]

    if kind == b"R":
        if len(body) < 4:
            return None, None, ()
        code = struct.unpack("!i", body[:4])[0]
        method = AUTH_METHODS.get(code)
        mechanisms: Tuple[str, ...] = ()
        if method == "sasl":
            mechanisms = tuple(
                name.decode("utf-8", "ignore")
                for name in body[4:].split(b"\x00") if name
            )
        return method, None, mechanisms

    if kind == b"E":
        fields = _parse_error_fields(body)
        text = " ".join(fields.values())
        found = _VERSION_RE.search(text)
        return None, (found.group("version") if found else None), ()

    return None, None, ()


def fingerprint_postgres(
    ssl_reply: bytes,
    startup_reply: bytes,
) -> PostgresFingerprint:
    """Construye el fingerprint a partir de las dos respuestas.

    Args:
        ssl_reply: La respuesta al ``SSLRequest``.
        startup_reply: La respuesta al ``StartupMessage``.

    Returns:
        El :class:`PostgresFingerprint`. Sin producto cuando ninguna de las dos
        respuestas es reconocible: un puerto que acepta la conexión y contesta
        cualquier cosa no es un PostgreSQL.
    """
    accepts_tls = parse_ssl_response(ssl_reply)
    method, version, mechanisms = parse_startup_response(startup_reply)
    spoke_the_protocol = accepts_tls is not None or method is not None or version is not None
    return PostgresFingerprint(
        product=_PRODUCT if spoke_the_protocol else None,
        version=version,
        accepts_tls=accepts_tls,
        auth_method=method,
        sasl_mechanisms=mechanisms,
    )


# =========================================================================
# SONDA (el borde de red: socket crudo, sin cliente de PostgreSQL)
# =========================================================================

# El usuario que se declara en el StartupMessage. Deliberadamente inexistente:
# lo que se busca es la respuesta del servidor sobre su política, no entrar.
PROBE_USER = "lybra-probe-nonexistent"


class PostgresProbe:  # pylint: disable=too-few-public-methods
    """Hace los dos intercambios y devuelve las dos respuestas crudas.

    Son **dos conexiones y no una**: tras responder ``S`` o ``N`` al
    ``SSLRequest``, el servidor espera o bien un handshake TLS o bien el
    ``StartupMessage`` sobre la misma conexión, y encadenarlos obligaría a
    negociar TLS aquí para el primer caso. Dos conexiones cortas cuestan menos
    que meter una pila TLS en esta sonda, y cada una pide su turno al
    limitador.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable, para que
            un test use un socket falso.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def _exchange(self, host: str, port: int, payload: bytes) -> Optional[bytes]:
        """Abre una conexión, manda ``payload`` y devuelve lo que llegue."""
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("PostgreSQL: conexión fallida a %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            sock.sendall(payload)
            return sock.recv(4096)
        except OSError as err:
            logger.debug("PostgreSQL: intercambio fallido con %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def fetch(self, host: str, port: int = 5432) -> Optional[Tuple[bytes, bytes]]:
        """Hace los dos intercambios contra ``host:port``.

        Args:
            host: El objetivo.
            port: El puerto de PostgreSQL.

        Returns:
            Un par ``(respuesta al SSLRequest, respuesta al StartupMessage)``,
            o ``None`` si el primer intercambio ni siquiera llegó a completarse.
        """
        ssl_reply = self._exchange(host, port, build_ssl_request())
        if ssl_reply is None:
            return None
        startup_reply = self._exchange(host, port, build_startup_message(PROBE_USER)) or b""
        return ssl_reply, startup_reply


@register_dissector
class PostgresDissector(Dissector):
    """Dos lecturas del protocolo de conexión, ningún intento de login."""

    label = "PostgreSQL"

    def __init__(self, probe: Optional[PostgresProbe] = None) -> None:
        self._probe = probe or PostgresProbe()

    def applies(self, service) -> bool:
        return is_postgres_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        replies = self._probe.fetch(target, service.port or 5432)
        if replies is None:
            return None
        rate_limiter.acquire(target)
        fingerprint = fingerprint_postgres(*replies)
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
