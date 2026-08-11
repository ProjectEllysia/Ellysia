"""SMTP/IMAP/POP3 dissectors — Fase N, priority-1 non-HTTP protocols.

All three volunteer an identifying line unprompted, right after a bare TCP
connect — the same shape FTP already exploits (Fase N's opening move): no
negotiation, no framing, just a banner. A stopword list keeps the parser from
mistaking a protocol's own name ("POP3", "IMAP4", "server") for a product,
mirroring the FTP dissector's rule of never inventing an identification that
was not actually observed.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..checks import is_smtp_service, is_imap_service, is_pop3_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

_STOPWORDS = {"pop3", "imap4", "imap4rev1", "server", "mail", "service", "ready", "esmtp"}

# "220 smtp.example.com ESMTP Exim 4.94.2 Debian" — SMTP's EHLO-less banner.
# Postfix's default banner ("... ESMTP Postfix (Debian/GNU)") deliberately
# omits a version, so this correctly yields no match for it.
_SMTP_VERSION_RE = re.compile(r"ESMTP\s+([A-Za-z][\w.\-]*)\s+([0-9][\w.\-/]*)")
# "Dovecot ready." / "Courier-IMAP ready." — IMAP/POP3's "<Product> ready" shape.
_READY_RE = re.compile(r"([A-Za-z][\w\-]*)\s+ready\b", re.IGNORECASE)


@dataclass(frozen=True)
class MailFingerprint:
    """The result of fingerprinting an SMTP/IMAP/POP3 service.

    Attributes:
        product: The identified product name, or ``None``.
        version: The identified version — SMTP only; IMAP/POP3 banners do not
            conventionally carry one — or ``None``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def parse_smtp_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract product and version from an SMTP greeting.

    Args:
        banner: The greeting line, e.g. ``"220 mail.example.com ESMTP Exim 4.94.2"``.

    Returns:
        A ``(product, version)`` tuple, both ``None`` when the banner carries
        no recognisable product/version.
    """
    match = _SMTP_VERSION_RE.search(banner or "")
    if not match:
        return None, None
    return match.group(1), match.group(2)


def _parse_ready_banner(banner: str) -> Optional[str]:
    """Extract a bare product name from an IMAP/POP3 "<Product> ready" banner."""
    match = _READY_RE.search(banner or "")
    if not match:
        return None
    product = match.group(1)
    return None if product.lower() in _STOPWORDS else product


def fingerprint_smtp(banner: str) -> MailFingerprint:
    """Fingerprint an SMTP service from its greeting banner."""
    product, version = parse_smtp_banner(banner)
    confidence = 0.9 if product and version else 0.0
    return MailFingerprint(product=product, version=version, confidence=confidence)


def fingerprint_imap(banner: str) -> MailFingerprint:
    """Fingerprint an IMAP service from its greeting banner (product only)."""
    product = _parse_ready_banner(banner)
    return MailFingerprint(product=product, version=None, confidence=0.6 if product else 0.0)


def fingerprint_pop3(banner: str) -> MailFingerprint:
    """Fingerprint a POP3 service from its greeting banner (product only)."""
    product = _parse_ready_banner(banner)
    return MailFingerprint(product=product, version=None, confidence=0.6 if product else 0.0)


# =========================================================================
# PROBE (the network edge: raw socket, one line, no library)
# =========================================================================

def _read_line(sock) -> str:
    """Read one newline-terminated line from a socket (the greeting)."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "ignore").strip()


class MailProbe:
    """Connects to an SMTP/IMAP/POP3 port and reads the banner it volunteers.

    Same shape as :class:`~.ftp.FtpProbe`: shared across all three protocols
    since they all hand over their identifying line unprompted, right after
    the TCP handshake — only the default port differs per caller.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int) -> Optional[str]:
        """Connect and return the banner the server sends unprompted.

        Returns:
            The banner line, or ``None`` on connection failure or an empty banner.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("Mail probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            banner = _read_line(sock)
            return banner or None
        except OSError as err:
            logger.debug("Mail probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class SmtpDissector(Dissector):
    label = "SMTP"

    def __init__(self, probe: Optional[MailProbe] = None) -> None:
        self._probe = probe or MailProbe()

    def applies(self, service) -> bool:
        return is_smtp_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 25)
        if banner is None:
            return None
        fingerprint = fingerprint_smtp(banner)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)


@register_dissector
class ImapDissector(Dissector):
    label = "IMAP"

    def __init__(self, probe: Optional[MailProbe] = None) -> None:
        self._probe = probe or MailProbe()

    def applies(self, service) -> bool:
        return is_imap_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 143)
        if banner is None:
            return None
        fingerprint = fingerprint_imap(banner)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)


@register_dissector
class Pop3Dissector(Dissector):
    label = "POP3"

    def __init__(self, probe: Optional[MailProbe] = None) -> None:
        self._probe = probe or MailProbe()

    def applies(self, service) -> bool:
        return is_pop3_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        banner = self._probe.fetch(target, service.port or 110)
        if banner is None:
            return None
        fingerprint = fingerprint_pop3(banner)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
