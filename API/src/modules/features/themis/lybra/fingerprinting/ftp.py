"""The FTP dissector — Fase N's opening move into non-HTTP protocols.

FTP is the cheapest possible entry into the roadmap's brecha G1 (protocols
Lybra cannot yet identify at all): the server volunteers its whole identity
unprompted, in the first line it sends after a bare TCP connect — no protocol
negotiation, no framing, just a banner ending in ``\\r\\n``. The well-known
``vsftpd 2.3.4`` backdoor (CVE-2021-... no — CVE-2011-2523) is also one of the
most recognisable "verified by an intentionally-vulnerable lab image" targets
that exists, which makes this dissector unusually easy to validate.

Two banner shapes cover the common daemons:

- ``220 (vsFTPd 2.3.4)`` — product and version in parentheses (vsftpd).
- ``220 ProFTPD 1.3.5 Server (Debian) [...]`` — bare ``Product Version``
  tokens before any parenthetical comment (ProFTPD, and similar daemons).

A banner that carries no version at all — Pure-FTPd's default is the classic
example, which suppresses its version for exactly the reason this dissector
exists — yields no identification rather than a guess. That mirrors the
project's rule everywhere else: no CPE that was not actually observed.
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
        A ``(product, version)`` tuple. Both are ``None`` when the banner does
        not carry a recognisable product/version pair — deliberately not a
        guess, since a fabricated identification would go on to look up a
        CPE that does not exist.
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
    return None, None


def fingerprint_ftp(banner: str) -> FtpFingerprint:
    """Fingerprint an FTP service from its welcome banner.

    Args:
        banner: The server's welcome banner line.

    Returns:
        An :class:`FtpFingerprint`.
    """
    product, version = parse_ftp_banner(banner)
    confidence = 0.9 if product and version else 0.0
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
