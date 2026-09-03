"""The VNC dissector — Fase N.

The RFB protocol (RFC 6143 §7.1.1) opens with the server sending its supported
protocol version unprompted, as a fixed 12-byte ASCII line: ``"RFB 003.008\\n"``.
No negotiation needed just to read it — the same "volunteers its identity"
shape as FTP. RFB has no notion of a product/vendor version beyond the
protocol version itself, so that is what gets reported; it is still a useful
signal (a legacy ``003.003``/``003.007`` responder is a materially different
security posture than a modern ``003.008`` one).
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from ..checks import is_vnc_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

_RFB_RE = re.compile(rb"^RFB (\d{3})\.(\d{3})")


# RFB has no separate product/vendor name to report — the protocol version
# itself is the whole identification, so this stands in as the "product" for
# the fingerprint finding's title (see fingerprint_vnc).
_PRODUCT = "VNC (RFB)"


@dataclass(frozen=True)
class VncFingerprint:
    """The result of fingerprinting a VNC service.

    Attributes:
        product: :data:`_PRODUCT`, or ``None`` if the banner did not look
            like RFB at all.
        version: The negotiated RFB protocol version, e.g. ``"3.8"``, or
            ``None``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def parse_rfb_version(banner: bytes) -> Optional[str]:
    """Extract the protocol version from an RFB version banner.

    Args:
        banner: The raw 12-byte banner, e.g. ``b"RFB 003.008\\n"``.

    Returns:
        A ``"major.minor"`` string (leading zeros stripped, e.g. ``"3.8"``),
        or ``None`` if the banner is not RFB-shaped.
    """
    match = _RFB_RE.match(banner or b"")
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    return f"{major}.{minor}"


def fingerprint_vnc(banner: bytes) -> VncFingerprint:
    """Fingerprint a VNC service from its RFB version banner."""
    version = parse_rfb_version(banner)
    return VncFingerprint(
        product=_PRODUCT if version else None,
        version=version,
        confidence=0.9 if version else 0.0,
    )


# =========================================================================
# PROBE (the network edge: raw socket, no RFB library)
# =========================================================================

class VncProbe:
    """Connects to a VNC port and reads the 12-byte RFB version banner.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 5900) -> Optional[bytes]:
        """Connect and return the raw RFB version banner.

        Returns:
            Up to 12 raw bytes, or ``None`` on connection failure or an empty read.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("VNC probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            data = b""
            while not data.endswith(b"\n") and len(data) < 12:
                chunk = sock.recv(1)
                if not chunk:
                    break
                data += chunk
            return data or None
        except OSError as err:
            logger.debug("VNC probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def security_types(self, host: str, port: int = 5900) -> Optional[list]:
        """Completa el handshake RFB y devuelve los tipos de seguridad ofrecidos.

        Tras enviar su versión, el servidor RFB (3.7/3.8) responde con un byte
        de recuento y esa lista de tipos de seguridad. El tipo **1 es ``None``**
        (RFC 6143 §7.1.2): acceso sin autenticación, que es el hallazgo. Un
        recuento 0 significa que el servidor rechazó, y sigue un motivo de error.

        No se avanza más allá de leer la lista: **no se intenta autenticar** ni
        se envía ninguna respuesta de seguridad, así que no se establece sesión.

        Args:
            host: El objetivo.
            port: El puerto.

        Returns:
            La lista de tipos como enteros, ``[]`` si el servidor rechazó con
            recuento 0, o ``None`` si al otro lado no había un RFB legible.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("VNC security probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            sock.settimeout(self._timeout)
            banner = b""
            while not banner.endswith(b"\n") and len(banner) < 12:
                chunk = sock.recv(1)
                if not chunk:
                    break
                banner += chunk
            if not _RFB_RE.match(banner):
                return None
            sock.sendall(b"RFB 003.008\n")
            count_byte = sock.recv(1)
            if not count_byte:
                return None
            count = count_byte[0]
            if count == 0:
                return []
            types = b""
            while len(types) < count:
                chunk = sock.recv(count - len(types))
                if not chunk:
                    break
                types += chunk
            return list(types)
        except OSError as err:
            logger.debug("VNC security probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class VncDissector(Dissector):
    label = "VNC"

    def __init__(self, probe: Optional[VncProbe] = None) -> None:
        self._probe = probe or VncProbe()

    def applies(self, service) -> bool:
        return is_vnc_service(service)

    def identify_from_banner(self, banner):
        # La RFC 6143 §7.1.1 fija el saludo en doce bytes exactos con la forma
        # "RFB 003.008\n": marcador y versión en la misma línea.
        fingerprint = fingerprint_vnc(banner[:12])
        if not fingerprint.product:
            return None
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 5900)
        if banner is None:
            return None
        fingerprint = fingerprint_vnc(banner)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
