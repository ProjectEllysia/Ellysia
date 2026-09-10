"""The MySQL/MariaDB dissector.

MySQL's wire protocol volunteers its identity unprompted, same spirit as FTP:
the server's very first packet after a bare TCP connect is the "Initial
Handshake Packet" (protocol version 10), which carries a NUL-terminated
server-version string in cleartext before any authentication happens. No
query, no login attempt — just reading what the server already sent.

MariaDB famously prefixes that string with ``"5.5.5-"`` for historical
client-compatibility reasons (mysql clients older than the MariaDB fork used
to refuse to talk to a server reporting a bare 10.x version) — recognised and
stripped here so MariaDB is correctly reported as MariaDB, not "MySQL 5.5.5".
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..checks import is_mysql_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# The MariaDB compatibility prefix (see module docstring).
_MARIADB_PREFIX = "5.5.5-"


@dataclass(frozen=True)
class MysqlFingerprint:
    """The result of fingerprinting a MySQL/MariaDB service.

    Attributes:
        product: ``"MySQL"`` or ``"MariaDB"``, or ``None`` if the handshake
            packet was not recognisable.
        version: The server version string, or ``None``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def parse_mysql_handshake(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Extract product and version from a MySQL Initial Handshake Packet's payload.

    Args:
        payload: The packet payload — the bytes *after* the 4-byte
            length+sequence header (see :meth:`MysqlProbe.fetch`).

    Returns:
        A ``(product, version)`` tuple, both ``None`` when the payload is too
        short or is not protocol version 10 (``HandshakeV10``, what every
        server in practice speaks today).
    """
    if len(payload) < 2 or payload[0] != 0x0A:
        return None, None
    end = payload.find(b"\x00", 1)
    if end == -1:
        return None, None
    version = payload[1:end].decode("utf-8", "ignore")
    if not version:
        return None, None
    if version.startswith(_MARIADB_PREFIX) and "mariadb" in version.lower():
        return "MariaDB", version[len(_MARIADB_PREFIX):]
    return "MySQL", version


def fingerprint_mysql(payload: bytes) -> MysqlFingerprint:
    """Fingerprint a MySQL/MariaDB service from its handshake packet payload."""
    product, version = parse_mysql_handshake(payload)
    confidence = 0.9 if product and version else 0.0
    return MysqlFingerprint(product=product, version=version, confidence=confidence)


# =========================================================================
# PROBE (the network edge: raw socket, no MySQL client library)
# =========================================================================

def _read_exact(sock, n: int) -> bytes:
    """Read up to ``n`` bytes, returning fewer if the connection closes early
    (no exception — the caller checks the returned length)."""
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            break
        buffer += chunk
    return buffer


class MysqlProbe:
    """Connects to a MySQL port and reads its Initial Handshake Packet.

    The connection function is injectable, same pattern as every other probe
    in this package.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 3306) -> Optional[bytes]:
        """Connect and return the handshake packet's payload.

        Returns:
            The payload bytes (after the 4-byte length+sequence header), or
            ``None`` on connection failure or a truncated/malformed packet.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("MySQL probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            header = _read_exact(sock, 4)
            if len(header) < 4:
                return None
            payload_length = header[0] | (header[1] << 8) | (header[2] << 16)
            payload = _read_exact(sock, payload_length)
            if len(payload) < payload_length:
                return None
            return payload
        except OSError as err:
            logger.debug("MySQL probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class MysqlDissector(Dissector):
    label = "MySQL"

    def __init__(self, probe: Optional[MysqlProbe] = None) -> None:
        self._probe = probe or MysqlProbe()

    def applies(self, service) -> bool:
        return is_mysql_service(service)

    def identify_from_banner(self, banner):
        # El paquete inicial de MySQL/MariaDB no es texto: son cuatro bytes de
        # cabecera (longitud + secuencia) y después la versión de protocolo,
        # que en todo servidor real es 10 (``HandshakeV10``). Ese 0x0A en la
        # quinta posición es el marcador.
        if len(banner) < 6 or banner[4] != 0x0A:
            return None
        fingerprint = fingerprint_mysql(banner[4:])
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        payload = self._probe.fetch(target, service.port or 3306)
        if payload is None:
            return None
        fingerprint = fingerprint_mysql(payload)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
