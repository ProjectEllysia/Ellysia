"""The FTP dissector — Fase N's opening move into non-HTTP protocols.

FTP is the cheapest possible entry into the roadmap's brecha G1 (protocols
Lybra cannot yet identify at all): the server volunteers its whole identity
unprompted, in the first line it sends after a bare TCP connect — no protocol
negotiation, no framing, just a banner ending in ``\\r\\n``. The well-known
``vsftpd 2.3.4`` backdoor (CVE-2021-... no — CVE-2011-2523) is also one of the
most recognisable "verified by an intentionally-vulnerable lab image" targets
that exists, which makes this dissector unusually easy to validate.

Two banner shapes carry a version outright:

- ``220 (vsFTPd 2.3.4)`` — product and version in parentheses (vsftpd).
- ``220 ProFTPD 1.3.5 Server (Debian) [...]`` — bare ``Product Version``
  tokens before any parenthetical comment (ProFTPD, and similar daemons).

**Y muchos despliegues reales no llevan ninguna de las dos** (L48-a). El
saludo por defecto de ProFTPD en Debian es ``220 ProFTPD Server (Debian)
[::ffff:...]``: nombra el producto y calla la versión, que es justo lo que
recomienda cualquier guía de fortificación. Pure-FTPd hace lo mismo. Contra
esos servidores el dissector no devolvía nada mientras Nmap leía el producto
del mismo saludo — medido en dos hosts reales, concordancia 0,00 para la
familia FTP frente al 1,00 de laboratorio, donde el único contenedor del
banco era un vsftpd cuyo formato el parser sí conocía.

De ahí :data:`KNOWN_DAEMONS`: una tabla de nombres de demonio conocidos que se
buscan en el saludo cuando ningún patrón con versión ha casado. **Reconocer un
producto nombrado no es inventarlo** — el nombre está literalmente en el
banner—; lo que sigue prohibido es fabricar la versión que no se observó, y
por eso este camino devuelve siempre ``(producto, None)``.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..checks import is_ftp_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# "220 (vsFTPd 2.3.4)" — a parenthesised "Product Version" pair.
_PAREN_RE = re.compile(r"\(([A-Za-z][\w.\-]*)\s+([0-9][\w.\-]*)\)")
# "220 ProFTPD 1.3.5 Server (Debian) [...]" / "220-FileZilla Server 0.9.60beta"
# — a bare product (optionally two words, e.g. "FileZilla Server") followed by
# a version token, before any parenthetical comment.
_BARE_RE = re.compile(r"^220[- ]+([A-Za-z][A-Za-z0-9_\-]*(?:\s[A-Za-z]+)?)\s+([0-9][\w.\-]*)")

# Demonios FTP cuyo nombre basta para identificar el producto cuando el saludo
# no trae versión. La clave es la aguja que se busca en el banner (en
# minúsculas); el valor, el nombre canónico del producto tal y como debe
# aparecer en el hallazgo y en la consulta de CPE.
#
# Es una tabla y no una heurística a propósito: un `split()` esperanzado sobre
# la primera palabra del saludo convertiría cualquier mensaje de bienvenida
# personalizado en un producto inventado. Aquí, si el nombre no está escrito,
# no hay identificación.
#
# El orden importa donde un nombre contiene a otro: "Microsoft FTP Service" se
# comprueba antes que "FTP", y "FileZilla Server" antes que "FileZilla".
KNOWN_DAEMONS: Tuple[Tuple[str, str], ...] = (
    ("microsoft ftp service", "Microsoft FTP Service"),
    ("filezilla server", "FileZilla Server"),
    ("pure-ftpd", "Pure-FTPd"),
    ("proftpd", "ProFTPD"),
    ("vsftpd", "vsFTPd"),
    ("wu-ftpd", "WU-FTPD"),
    ("serv-u", "Serv-U"),
    ("crushftp", "CrushFTP"),
    ("glftpd", "glFTPd"),
    ("bftpd", "bftpd"),
    ("titan ftp", "Titan FTP Server"),
)


def _named_daemon(banner: str) -> Optional[str]:
    """Devuelve el producto nombrado en ``banner``, si es uno conocido.

    Args:
        banner: La línea de saludo completa.

    Returns:
        El nombre canónico del demonio, o ``None`` si el saludo no nombra
        ninguno de los conocidos.
    """
    lowered = banner.lower()
    for needle, product in KNOWN_DAEMONS:
        if needle in lowered:
            return product
    return None


@dataclass(frozen=True)
class FtpFingerprint:
    """The result of fingerprinting an FTP service.

    Attributes:
        product: The identified product name (e.g. ``"vsFTPd"``), or ``None``.
        version: The identified version (e.g. ``"2.3.4"``), or ``None``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def parse_ftp_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract product and version from an FTP welcome banner.

    Args:
        banner: The banner line, e.g. ``"220 (vsFTPd 2.3.4)"``.

    Returns:
        A ``(product, version)`` tuple. La versión es ``None`` cuando el saludo
        nombra un demonio conocido pero suprime su versión —el caso por defecto
        de ProFTPD y de Pure-FTPd—; ambos son ``None`` cuando no se reconoce
        nada. Nunca se fabrica una versión que no se leyó: sin ella no hay CPE,
        y un CPE inventado buscaría CVEs de un producto que no está ahí.
    """
    banner = (banner or "").strip()
    if not banner.startswith("220"):
        return None, None
    match = _PAREN_RE.search(banner)
    if match:
        return match.group(1), match.group(2)
    match = _BARE_RE.match(banner)
    if match:
        return match.group(1), match.group(2)
    return _named_daemon(banner), None


def fingerprint_ftp(banner: str) -> FtpFingerprint:
    """Fingerprint an FTP service from its welcome banner.

    Args:
        banner: The server's welcome banner line.

    Returns:
        An :class:`FtpFingerprint`.
    """
    product, version = parse_ftp_banner(banner)
    if product and version:
        confidence = 0.9
    elif product:
        # El producto se leyó del saludo; sólo falta la versión. Mismo escalón
        # que usa fingerprint_http para un `Server` sin versión.
        confidence = 0.6
    else:
        confidence = 0.0
    return FtpFingerprint(product=product, version=version, confidence=confidence)


# =========================================================================
# FTP PROBE (the network edge: raw socket, no FTP library)
# =========================================================================

def _read_line(sock) -> str:
    """Read one newline-terminated line from a socket (the FTP banner).

    Args:
        sock: The socket to read from.

    Returns:
        The line, decoded and stripped of trailing whitespace.
    """
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "ignore").strip()


class FtpProbe:
    """Connects to an FTP port and reads the welcome banner it volunteers.

    The connection function is injectable — it defaults to
    ``socket.create_connection`` but a test can pass a fake — mirroring the
    same pattern used by :class:`~.ssh.SshProbe` and :class:`~.tls.TlsProbe`.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 21) -> Optional[str]:
        """Connect and return the banner FTP sends unprompted.

        Args:
            host: The target host.
            port: The FTP port (default 21).

        Returns:
            The banner line, or ``None`` if the connection fails or the server
            closes without sending anything. The socket is always closed
            afterwards.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("FTP connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            banner = _read_line(sock)
            return banner or None
        except OSError as err:
            logger.debug("FTP probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class FtpDissector(Dissector):
    """Reads the unprompted welcome banner — see the module docstring."""

    label = "FTP"

    def __init__(self, probe: Optional[FtpProbe] = None) -> None:
        self._probe = probe or FtpProbe()

    def applies(self, service) -> bool:
        return is_ftp_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 21)
        if banner is None:
            return None
        fingerprint = fingerprint_ftp(banner)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
