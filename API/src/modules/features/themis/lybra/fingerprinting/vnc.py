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


@register_dissector
class VncDissector(Dissector):
    label = "VNC"

    def __init__(self, probe: Optional[VncProbe] = None) -> None:
        self._probe = probe or VncProbe()

    def applies(self, service) -> bool:
        return is_vnc_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 5900)
        if banner is None:
            return None
        fp = fingerprint_vnc(banner)
        return DissectorResult(fp.product, fp.version, self.label)
