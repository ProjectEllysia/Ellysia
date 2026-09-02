"""The TLS dissector: a single-handshake hygiene check, not identification.

Reads the negotiated protocol version and the self-signed/expiry status of the
certificate.

**JARM: archivado, no pendiente** (L24, 2026-09-02). Este módulo hace **un**
handshake, y de ahí salen la versión de protocolo, el autofirmado y la
caducidad. JARM haría diez saludos deliberadamente distintos y hashearía el
conjunto para identificar la *pila* TLS, no el producto.

No se va a construir, y la razón de fondo cabe en una frase: **el valor de JARM
es comparativo**. Un hash que no coincida bit a bit con el de la implementación
de referencia no es una identificación peor, es ninguna — un número que no se
puede buscar en ningún catálogo. Y comprobar esa coincidencia exige un
laboratorio con varias pilas TLS distintas (OpenSSL, BoringSSL, Schannel,
JSSE), que no existe aquí.

A eso se suma que no es requisito de ninguna definición de hecho —la Fase F se
cierra con la concordancia frente a Nmap, no con JARM—, que su prioridad medida
es la más baja del backlog, y que diez saludos por servicio TLS es la sonda más
cara del catálogo a cambio de un dato que nadie consultaría.

La decisión está escrita, con qué haría falta para reabrirla, en la sección
Fase F de ``plans/feature/themis/lybra-engine-roadmap.md``. No es un "todavía
no": es un "no, y por esto".
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TlsInfo:
    """The result of a single TLS handshake, read for hygiene, not identity.

    Attributes:
        protocol: The negotiated protocol version, e.g. ``"TLSv1.2"``.
        cipher: The negotiated cipher suite name.
        subject_cn: The certificate's subject common name, or ``None``.
        issuer_cn: The certificate's issuer common name, or ``None``.
        self_signed: Whether the certificate's issuer equals its subject.
        expired: Whether the certificate's ``notAfter`` is in the past.
        days_until_expiry: Days remaining before expiry (negative if expired),
            or ``None`` if the certificate could not be parsed.
    """
    protocol: Optional[str]
    cipher: Optional[str]
    subject_cn: Optional[str]
    issuer_cn: Optional[str]
    self_signed: bool
    expired: bool
    days_until_expiry: Optional[int]


def _common_name(name: "x509.Name") -> Optional[str]:
    """Extract the common name from an X.509 ``Name``, best-effort."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


class TlsProbe:
    """Performs a single, unverified TLS handshake to read protocol and cert.

    We are scanning arbitrary hosts whose certificates we do not control, so
    verification is deliberately disabled — a self-signed or expired cert is
    exactly the kind of thing this probe exists to report, not reject.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable, same
            pattern as :class:`~.ssh.SshProbe`.
    """

    def __init__(self, timeout: float = 8.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int) -> Optional[TlsInfo]:
        """Handshake with ``host:port`` and return the certificate's hygiene facts.

        Args:
            host: The target host.
            port: The target port.

        Returns:
            A :class:`TlsInfo`, or ``None`` on any connection/handshake failure.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("TLS connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                protocol = tls_sock.version()
                cipher = tls_sock.cipher()
        except (OSError, ssl.SSLError) as err:
            logger.debug("TLS handshake failed for %s:%s: %s", host, port, err)
            return None
        if der is None:
            return None
        return self._parse_cert(der, protocol, cipher[0] if cipher else None)

    @staticmethod
    def _parse_cert(der: bytes, protocol: Optional[str], cipher: Optional[str]) -> Optional[TlsInfo]:
        """Parse a DER certificate into a :class:`TlsInfo`, best-effort."""
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as err:
            logger.debug("TLS certificate parse failed: %s", err)
            return None
        # not_valid_after_utc (tz-aware) landed in cryptography 42; requirements.txt
        # only pins >=41.0.4, so fall back to the naive attribute on older installs.
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_until_expiry = (not_after - datetime.now(timezone.utc)).days
        return TlsInfo(
            protocol=protocol,
            cipher=cipher,
            subject_cn=_common_name(cert.subject),
            issuer_cn=_common_name(cert.issuer),
            self_signed=cert.issuer == cert.subject,
            expired=days_until_expiry < 0,
            days_until_expiry=days_until_expiry,
        )
