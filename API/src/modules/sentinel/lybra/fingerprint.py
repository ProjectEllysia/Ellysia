"""Lybra's own service fingerprinting — the identification layer.

Instead of trusting ``nmap -sV`` blindly, this module identifies a service's
product and version on its own terms. It ships two dissectors, chosen for the
best value-for-effort in the roadmap:

HTTP
    Reads the ``Server`` / ``X-Powered-By`` headers, the page ``<title>``, a hash
    of the favicon, and a small curated table of technology signatures
    (WordPress, Drupal, and so on).

SSH
    Reads the banner (which gives product and version) and computes **HASSH** —
    a fingerprint of the algorithm lists a server advertises in its
    ``SSH_MSG_KEXINIT`` packet. The packet is parsed straight from the raw
    protocol bytes off a socket, with no SSH library involved.

The governing principle is that **Nmap stays the oracle**: when a service
already carries a Nmap-sourced product/version, this module's own reading
never overrides it. :func:`agrees_with_nmap` and :func:`concordance_rate` turn
"does our fingerprint match Nmap's?" into a measurable number — the roadmap's
Definition of Done requires agreement to reach 0.90 before Nmap could be
demoted to a *fallback*. Actually running that measurement against a lab of
real targets is an operational step for the user, much like the knowledge
base's initial full download.

That said, a service found by Lybra's own transport (Fase T, no Nmap
involved) never had a Nmap reading to defer to in the first place — it carries
no product/version at all. For that case, and only that case,
``LybraEngineManager._fingerprint_services`` uses this module's output to
fill the gap: without it, the version matcher (Fase 1) would have nothing to
look up and a self-discovery-only scan would never find a single CVE. The
result still goes in at the same low-confidence, unconfirmed tier a Nmap CPE
match would (``qod=70``) — this closes a blind spot, it does not raise
confidence beyond what the matcher already assigns any version-based guess.

Two techniques are deliberately left for later: TLS/JARM fingerprinting (a
bit-exact ten-probe handshake that is too large and risky to ship without a live
TLS lab to validate it against) and OS fingerprinting (which the roadmap itself
rates low value). Both stay oracle-only — handled by Nmap — until picked up.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .checks import Response

logger = logging.getLogger(__name__)

# Quality of Detection for a fingerprint finding: informational only. It exists
# to gather calibration evidence and never contributes to a vulnerability's
# confidence.
QOD_FINGERPRINT = 20


# =========================================================================
# HTTP DISSECTOR
# =========================================================================

@dataclass(frozen=True)
class HttpFingerprint:
    """The result of fingerprinting an HTTP service.

    Attributes:
        product: The identified product name, or ``None``.
        version: The identified version, or ``None``.
        title: The page ``<title>``, or ``None``.
        favicon_hash: A SHA-256 hex digest of the favicon, or ``None``. This is
            deliberately *not* the Shodan-compatible mmh3 hash — see the module
            docstring.
        technologies: A tuple of technology names matched by signature.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    title: Optional[str]
    favicon_hash: Optional[str]
    technologies: tuple
    confidence: float


# A small, hand-curated table of technology signatures, Wappalyzer-style. It
# grows as evidence accumulates and never claims a version — only a technology
# name.
_TECH_SIGNATURES: List[Tuple[str, Callable[[Response], bool]]] = [
    ("WordPress", lambda r: "wp-content" in r.body or "wp-includes" in r.body),
    ("Drupal", lambda r: "drupal.settings" in r.body.lower() or "x-generator" in r.headers and "drupal" in r.headers.get("x-generator", "").lower()),
    ("Joomla", lambda r: "joomla" in r.body.lower()),
    ("Apache Tomcat", lambda r: "coyote" in r.headers.get("server", "").lower() or "apache tomcat" in r.body.lower()),
    ("phpMyAdmin", lambda r: "phpmyadmin" in (_extract_title(r.body) or "").lower()),
]


def _extract_title(body: str) -> Optional[str]:
    """Extract the ``<title>`` text from an HTML body, best-effort.

    Args:
        body: The HTML response body.

    Returns:
        The title text, or ``None`` if there is no well-formed title tag.
    """
    lower = body.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    start = lower.find(">", start)
    if start == -1:
        return None
    end = lower.find("</title>", start)
    if end == -1:
        return None
    return body[start + 1:end].strip() or None


def _parse_server_header(server: str) -> Tuple[Optional[str], Optional[str]]:
    """Split an HTTP ``Server`` header into product and version.

    Drops any trailing comment such as ``(Unix)`` or ``(Ubuntu)``.

    Args:
        server: The raw ``Server`` header value, e.g. ``"Apache/2.4.49 (Unix)"``.

    Returns:
        A ``(product, version)`` tuple. The version is ``None`` when the header
        carries only a bare product name (e.g. ``"nginx"``).
    """
    server = (server or "").strip()
    if not server:
        return None, None
    token = server.split()[0]  # drop trailing "(Unix)" / "(Ubuntu)" comments
    if "/" in token:
        product, version = token.split("/", 1)
        return product or None, version or None
    return token, None


def fingerprint_http(resp: Response, favicon: Optional[bytes] = None) -> HttpFingerprint:
    """Fingerprint an HTTP service from a response and, optionally, its favicon.

    The confidence follows a simple three-tier scheme: a versioned ``Server``
    header is the strongest signal (0.9), a bare product name is weaker (0.6),
    and a technology matched only from the body or title contributes a name but
    no confidence on its own. These stay below what Nmap's own direct CPE would
    earn, because this layer has not yet been calibrated against the oracle.

    Args:
        resp: The HTTP response to analyse.
        favicon: The raw bytes of the site's favicon, if fetched.

    Returns:
        An :class:`HttpFingerprint`.
    """
    server = resp.headers.get("server", "")
    product, version = _parse_server_header(server)
    technologies = tuple(name for name, matcher in _TECH_SIGNATURES if matcher(resp))
    title = _extract_title(resp.body)
    favicon_hash = hashlib.sha256(favicon).hexdigest() if favicon else None

    if not product and technologies:
        product = technologies[0]

    if product and version:
        confidence = 0.9
    elif product:
        confidence = 0.6
    else:
        confidence = 0.0

    return HttpFingerprint(
        product=product, version=version, title=title,
        favicon_hash=favicon_hash, technologies=technologies, confidence=confidence,
    )


# =========================================================================
# SSH DISSECTOR (banner + HASSH)
# =========================================================================

# The SSH message code for a key-exchange-init packet (RFC 4253).
SSH_MSG_KEXINIT = 20

# The ten algorithm name-lists a KEXINIT packet carries, in wire order.
_KEXINIT_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


@dataclass(frozen=True)
class SshFingerprint:
    """The result of fingerprinting an SSH service.

    Attributes:
        product: The identified product name (e.g. ``"OpenSSH"``), or ``None``.
        version: The identified version (e.g. ``"7.4"``), or ``None``.
        hassh_server: The HASSH hash of the *server's* advertised algorithm
            lists, or ``None``.
        kex_algorithms: The server's key-exchange algorithm list, as a tuple.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    hassh_server: Optional[str]
    kex_algorithms: tuple
    confidence: float


def parse_ssh_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Split an SSH identification banner into product and version.

    Drops any trailing free-text comment the server appends.

    Args:
        banner: The banner line, e.g. ``"SSH-2.0-OpenSSH_7.4"``.

    Returns:
        A ``(product, version)`` tuple, e.g. ``("OpenSSH", "7.4")``. Both are
        ``None`` if the banner is not a recognisable SSH identification string.
    """
    banner = banner.strip()
    if not banner.startswith("SSH-"):
        return None, None
    parts = banner.split("-", 2)
    if len(parts) < 3 or not parts[2]:
        return None, None
    software = parts[2].split(" ", 1)[0]
    if "_" in software:
        product, version = software.split("_", 1)
        return product or None, version or None
    return software or None, None


def _read_namelist(data: bytes, offset: int) -> Tuple[List[str], int]:
    """Read one SSH name-list from a byte buffer.

    An SSH name-list is a 4-byte big-endian length followed by that many bytes of
    comma-separated ASCII names (RFC 4253 §5).

    Args:
        data: The buffer to read from.
        offset: The byte offset to start at.

    Returns:
        A ``(names, new_offset)`` tuple: the parsed names and the offset just
        past the name-list.
    """
    (length,) = struct.unpack_from(">I", data, offset)
    offset += 4
    raw = data[offset:offset + length].decode("ascii", "ignore")
    offset += length
    return (raw.split(",") if raw else []), offset


def parse_kexinit(payload: bytes) -> Dict[str, List[str]]:
    """Parse an SSH_MSG_KEXINIT payload into its ten algorithm lists.

    The payload layout is defined in RFC 4253 §7.1: the message code, a 16-byte
    random cookie, then the ten name-lists. The caller is expected to have
    already stripped the outer packet framing (see :func:`_read_kexinit_payload`),
    so ``payload`` begins at the message code.

    Args:
        payload: The KEXINIT payload bytes, starting at the message code.

    Returns:
        A dict mapping each field name in :data:`_KEXINIT_FIELDS` to its list of
        algorithm names.

    Raises:
        ValueError: If the payload is empty or does not start with the KEXINIT
            message code.
    """
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("not an SSH_MSG_KEXINIT payload")
    offset = 1 + 16  # message code + 16-byte random cookie
    result: Dict[str, List[str]] = {}
    for field in _KEXINIT_FIELDS:
        result[field], offset = _read_namelist(payload, offset)
    return result


def compute_hassh_server(kexinit: Dict[str, List[str]]) -> str:
    """Compute the server-variant HASSH fingerprint from a parsed KEXINIT.

    Following the HASSH specification (salesforce/hassh), the server hash is the
    MD5 of four of the server's advertised lists joined with semicolons: the
    key-exchange algorithms, the server-to-client encryption, MAC and compression
    lists, each as its raw comma-separated string.

    Args:
        kexinit: A parsed KEXINIT, as returned by :func:`parse_kexinit`.

    Returns:
        The HASSH hash as a hex-encoded MD5 digest.
    """
    material = ";".join(
        ",".join(kexinit.get(field, []))
        for field in (
            "kex_algorithms",
            "encryption_algorithms_server_to_client",
            "mac_algorithms_server_to_client",
            "compression_algorithms_server_to_client",
        )
    )
    return hashlib.md5(material.encode("ascii")).hexdigest()


def fingerprint_ssh(banner: str, kexinit_payload: bytes) -> SshFingerprint:
    """Fingerprint an SSH service from its banner and raw KEXINIT payload.

    Args:
        banner: The server's identification banner line.
        kexinit_payload: The raw KEXINIT payload bytes (framing already stripped).

    Returns:
        An :class:`SshFingerprint`.

    Raises:
        ValueError: If the KEXINIT payload cannot be parsed.
    """
    product, version = parse_ssh_banner(banner)
    kexinit = parse_kexinit(kexinit_payload)
    hassh_server = compute_hassh_server(kexinit)
    confidence = 0.9 if product and version else (0.6 if product else 0.3)
    return SshFingerprint(
        product=product, version=version, hassh_server=hassh_server,
        kex_algorithms=tuple(kexinit.get("kex_algorithms", [])), confidence=confidence,
    )


# =========================================================================
# SSH PROBE (the network edge: raw socket, no SSH library)
# =========================================================================

def _read_exact(sock, n: int) -> bytes:
    """Read exactly ``n`` bytes from a socket, or raise if it closes first.

    Args:
        sock: The socket to read from.
        n: The exact number of bytes required.

    Returns:
        The ``n`` bytes read.

    Raises:
        ValueError: If the connection closes before ``n`` bytes arrive.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ValueError("connection closed while reading SSH data")
        buf += chunk
    return buf


def _read_line(sock) -> str:
    """Read one newline-terminated line from a socket (the SSH banner).

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


def _read_kexinit_payload(sock) -> bytes:
    """Read one SSH binary packet off the wire and return its KEXINIT payload.

    Strips the outer framing defined in RFC 4253 §6 — the 4-byte packet length,
    the padding-length byte and the trailing padding. No MAC is present, because
    key exchange has not started yet.

    Args:
        sock: The socket to read from, positioned just after the banner exchange.

    Returns:
        The KEXINIT payload bytes, starting at the message code.

    Raises:
        ValueError: If the packet does not contain a KEXINIT message.
    """
    (packet_length,) = struct.unpack(">I", _read_exact(sock, 4))
    body = _read_exact(sock, packet_length)
    padding_length = body[0]
    payload = body[1: len(body) - padding_length]
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("expected SSH_MSG_KEXINIT")
    return payload


class SshProbe:
    """Connects to an SSH port and reads the banner and the server's KEXINIT.

    The connection function is injectable — it defaults to
    ``socket.create_connection`` but a test can pass a fake — so the byte-parsing
    logic can be exercised without a real socket. This mirrors the injectable
    ``fetch`` callable used by :class:`~.checks.CheckRuntime`.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 22) -> Optional[Tuple[str, bytes]]:
        """Probe an SSH service and return its banner and raw KEXINIT payload.

        Args:
            host: The target host.
            port: The SSH port (default 22).

        Returns:
            A ``(banner, kexinit_payload)`` tuple, or ``None`` if the connection
            fails or the exchange does not complete. The socket is always closed
            afterwards.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("SSH connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            banner = _read_line(sock)
            if not banner:
                return None
            # RFC 4253 §4.2 requires us to send our own identification banner
            # before the server sends its KEXINIT, even though we only ever read
            # from here on (we never actually perform the key exchange).
            sock.sendall(b"SSH-2.0-Lybra_1.0\r\n")
            payload = _read_kexinit_payload(sock)
            return banner, payload
        except (OSError, ValueError) as err:
            logger.debug("SSH probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


# =========================================================================
# ORACLE / CONCORDANCE (measuring agreement with Nmap)
# =========================================================================

def agrees_with_nmap(
    product: Optional[str], version: Optional[str],
    nmap_product: Optional[str], nmap_version: Optional[str],
) -> bool:
    """Decide whether our fingerprint agrees with Nmap's for one service.

    Product names are compared by case-insensitive substring overlap, because the
    two tools name things differently ("Apache" versus "Apache httpd"). Versions
    must match exactly, but only when both sides actually report one. This is the
    per-service judgement that :func:`concordance_rate` aggregates.

    Args:
        product: Our identified product.
        version: Our identified version.
        nmap_product: Nmap's product for the same service.
        nmap_version: Nmap's version for the same service.

    Returns:
        ``True`` if the two identifications agree, ``False`` otherwise (including
        when either side has no product to compare).
    """
    if not product or not nmap_product:
        return False
    p, np = product.lower(), nmap_product.lower()
    if p not in np and np not in p:
        return False
    if version and nmap_version and version != nmap_version:
        return False
    return True


def concordance_rate(pairs: Iterable[Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]]) -> float:
    """Compute the fraction of fingerprints that agree with Nmap.

    This is the metric the roadmap's Definition of Done thresholds at 0.90 before
    Nmap could become a fallback for a service family. Collecting real
    ``(product, version, nmap_product, nmap_version)`` pairs from a lab of known
    targets is an operational step for the user; this function only does the
    arithmetic once the pairs exist.

    Args:
        pairs: An iterable of ``(product, version, nmap_product, nmap_version)``
            tuples, one per compared service.

    Returns:
        The fraction that agree, in ``[0.0, 1.0]``. Empty input returns 0.0 (no
        evidence yet, not perfect agreement).
    """
    pairs = list(pairs)
    if not pairs:
        return 0.0
    hits = sum(1 for p in pairs if agrees_with_nmap(*p))
    return hits / len(pairs)
