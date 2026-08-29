"""The SMB dissector — Fase N's highest-value protocol by port frequency.

Sends a minimal SMB2 NEGOTIATE request and reads the response's negotiated
dialect and security mode — the wire format is fixed and publicly documented
(MS-SMB2 §2.2.3 "SMB2 NEGOTIATE Request", §2.2.4 "SMB2 NEGOTIATE Response"),
so this is a byte-offset parser in the same spirit as the SSH dissector's raw
``SSH_MSG_KEXINIT`` parsing — no SMB client library involved.

Deliberate simplifications, both documented rather than discovered by
surprise:

- Only SMB2 dialects are offered (``0x0202``/``0x0210``/``0x0300``/``0x0302``),
  never ``0x0311`` (SMB 3.1.1). Offering 3.1.1 requires the request to also
  carry SMB2 "negotiate contexts" (preauth integrity + encryption
  capabilities) — a second layer of variable-length, offset-addressed
  structure this dissector does not build. Consequence: a modern
  Windows/Samba server that would negotiate 3.1.1 instead reports the
  highest dialect actually offered here, 3.0.2 — still correct and useful
  identification, just not the exact ceiling the server supports.
- SMB1 is not spoken at all: a server that has SMB1 fully disabled (the
  now-common hardened configuration) and does not also answer a direct SMB2
  negotiate simply yields no identification here, same as any other
  unrecognised response.

**Unverified against a live server** — this codebase's test environment has
no Docker-backed SMB target (see the concordance bench's own honesty note for
FTP's equivalent gap). The parser is exercised only against a hand-built byte
fixture matching the spec's documented offsets; validate against a real
Samba/Windows target before relying on this in a real scan.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..checks import is_smb_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

# SMB2 dialect revisions this dissector offers, and their human labels — see
# the module docstring for why 0x0311 (SMB 3.1.1) is deliberately excluded.
_DIALECTS: Tuple[int, ...] = (0x0202, 0x0210, 0x0300, 0x0302)
_DIALECT_LABELS = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}

# SMB2_NEGOTIATE_SIGNING_REQUIRED (MS-SMB2 §2.2.4, SecurityMode bit 0x0002).
_SIGNING_REQUIRED_BIT = 0x0002

_SMB2_HEADER_LEN = 64
_PROTOCOL_ID = b"\xfeSMB"


@dataclass(frozen=True)
class SmbFingerprint:
    """The result of fingerprinting an SMB service.

    Attributes:
        product: ``"SMB2"``, or ``"SMB2 (firma no requerida)"`` when the
            server's negotiated security mode does not require message
            signing — a real, directly-observed configuration fact (not a
            guess), folded into the product string since it is the single
            most actionable thing this dissector can report. ``None`` if the
            response was not recognisable.
        version: The negotiated dialect's label, e.g. ``"3.0.2"``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def _smb2_header(command: int, message_id: int = 0) -> bytes:
    """Build a 64-byte SMB2 "SYNC" header (MS-SMB2 §2.2.1.1).

    Every field this dissector does not need (CreditCharge, Flags, SessionId,
    Signature...) is left at its zero default, valid for an unauthenticated
    NEGOTIATE — the very first request on a connection, which is required to
    carry ``MessageId = 0``.
    """
    return b"".join([
        _PROTOCOL_ID,                    # ProtocolId (4)
        struct.pack("<H", 64),           # StructureSize (2)
        struct.pack("<H", 0),            # CreditCharge (2)
        struct.pack("<I", 0),            # Status / ChannelSequence+Reserved (4)
        struct.pack("<H", command),      # Command (2)
        struct.pack("<H", 1),            # CreditRequest (2)
        struct.pack("<I", 0),            # Flags (4)
        struct.pack("<I", 0),            # NextCommand (4)
        struct.pack("<Q", message_id),   # MessageId (8)
        struct.pack("<I", 0),            # Reserved (4)
        struct.pack("<I", 0),            # TreeId (4)
        struct.pack("<Q", 0),            # SessionId (8)
        b"\x00" * 16,                    # Signature (16)
    ])


def build_negotiate_request() -> bytes:
    """Build a full NetBIOS-wrapped SMB2 NEGOTIATE request (MS-SMB2 §2.2.3).

    Returns:
        The wire bytes: the 4-byte NetBIOS Session Service header (RFC 1002)
        followed by the SMB2 header and NEGOTIATE request body.
    """
    body = b"".join([
        struct.pack("<H", 36),                # StructureSize (fixed part only)
        struct.pack("<H", len(_DIALECTS)),    # DialectCount
        struct.pack("<H", 0x0001),            # SecurityMode: SIGNING_ENABLED
        struct.pack("<H", 0),                 # Reserved
        struct.pack("<I", 0),                 # Capabilities
        b"\x00" * 16,                          # ClientGuid
        struct.pack("<Q", 0),                  # ClientStartTime (reserved pre-3.1.1)
    ]) + b"".join(struct.pack("<H", dialect) for dialect in _DIALECTS)

    message = _smb2_header(command=0x0000) + body
    length = len(message)
    netbios_header = bytes([0x00]) + length.to_bytes(3, "big")
    return netbios_header + message


def parse_negotiate_response(message: bytes) -> Optional[Tuple[int, int]]:
    """Parse an SMB2 NEGOTIATE response (MS-SMB2 §2.2.4).

    Args:
        message: The SMB2 message *without* its 4-byte NetBIOS wrapper (see
            :meth:`SmbProbe.fetch`).

    Returns:
        A ``(dialect_revision, security_mode)`` tuple, or ``None`` if the
        message is too short, does not carry the SMB2 protocol id, or is not
        a NEGOTIATE response.
    """
    if len(message) < _SMB2_HEADER_LEN + 6:
        return None
    if message[0:4] != _PROTOCOL_ID:
        return None
    command = struct.unpack_from("<H", message, 12)[0]
    if command != 0x0000:
        return None
    security_mode = struct.unpack_from("<H", message, _SMB2_HEADER_LEN + 2)[0]
    dialect_revision = struct.unpack_from("<H", message, _SMB2_HEADER_LEN + 4)[0]
    return dialect_revision, security_mode


def fingerprint_smb(dialect_revision: int, security_mode: int) -> SmbFingerprint:
    """Fingerprint an SMB service from its negotiated dialect and security mode."""
    version = _DIALECT_LABELS.get(dialect_revision)
    if version is None:
        return SmbFingerprint(product=None, version=None, confidence=0.0)
    signing_required = bool(security_mode & _SIGNING_REQUIRED_BIT)
    product = "SMB2" if signing_required else "SMB2 (firma no requerida)"
    return SmbFingerprint(product=product, version=version, confidence=0.9)


# =========================================================================
# PROBE (the network edge: raw socket, no SMB client library)
# =========================================================================

def _read_exact(sock, n: int) -> bytes:
    """Read up to ``n`` bytes, returning fewer if the connection closes early."""
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            break
        buffer += chunk
    return buffer


class SmbProbe:
    """Sends a NEGOTIATE request and reads the response over a raw socket.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 445) -> Optional[Tuple[int, int]]:
        """Negotiate with an SMB service and return its dialect and security mode.

        Returns:
            A ``(dialect_revision, security_mode)`` tuple, or ``None`` on
            connection failure or an unparseable response.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("SMB probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            sock.sendall(build_negotiate_request())
            nb_header = _read_exact(sock, 4)
            if len(nb_header) < 4:
                return None
            length = int.from_bytes(nb_header[1:4], "big")
            message = _read_exact(sock, length)
            if len(message) < length:
                return None
            return parse_negotiate_response(message)
        except OSError as err:
            logger.debug("SMB probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class SmbDissector(Dissector):
    label = "SMB"

    def __init__(self, probe: Optional[SmbProbe] = None) -> None:
        self._probe = probe or SmbProbe()

    def applies(self, service) -> bool:
        return is_smb_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        result = self._probe.fetch(target, service.port or 445)
        if result is None:
            return None
        dialect_revision, security_mode = result
        fingerprint = fingerprint_smb(dialect_revision, security_mode)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
