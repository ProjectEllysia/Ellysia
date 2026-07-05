"""Ellysia's own service fingerprinting (Fase F, the L1 layer).

Identifies a service's product/version with independent criteria, instead of
trusting ``nmap -sV`` blindly. Two dissectors, chosen for the best value/cost
ratio in the roadmap:

* **HTTP** — ``Server``/``X-Powered-By`` headers, page ``<title>``, a favicon
  hash, and a small curated technology-signature table.
* **SSH** — the banner (product/version) plus **HASSH** (the server variant):
  a fingerprint of the algorithm lists the server advertises in its
  ``SSH_MSG_KEXINIT`` packet, computed by parsing the raw protocol bytes off a
  socket — no SSH library involved.

Governing principle (roadmap §9): **Nmap `-sV` stays the oracle.** Nothing here
feeds a Finding's confidence yet; ``agrees_with_nmap`` / ``concordance_rate``
operationalize the *measurement* the roadmap's Fase F Definition of Done
requires (agreement ≥ 0.90 before Nmap can become a fallback) — actually running
that measurement against a live lab of targets is an operational step for the
user, the same way the KB's initial full backfill was (see ``kb.py``).

Deliberately deferred within this phase: TLS/JARM fingerprinting (a bit-exact
10-probe ClientHello implementation is too large and too risky to ship without
a live TLS lab to validate against) and OS fingerprinting (the roadmap itself
rates it low ROI). Both remain oracle-only (Nmap) indefinitely, until picked up.
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

QOD_FINGERPRINT = 20  # informational, calibration-only — never feeds vuln confidence


# =========================================================================
# HTTP DISSECTOR
# =========================================================================

@dataclass(frozen=True)
class HttpFingerprint:
    product: Optional[str]
    version: Optional[str]
    title: Optional[str]
    favicon_hash: Optional[str]   # sha256 hex; NOT Shodan-compatible mmh3 (see module docstring)
    technologies: tuple
    confidence: float


# Tiny curated signature table (Wappalyzer-style), grows with evidence, never
# invents a version — just a technology name.
_TECH_SIGNATURES: List[Tuple[str, Callable[[Response], bool]]] = [
    ("WordPress", lambda r: "wp-content" in r.body or "wp-includes" in r.body),
    ("Drupal", lambda r: "drupal.settings" in r.body.lower() or "x-generator" in r.headers and "drupal" in r.headers.get("x-generator", "").lower()),
    ("Joomla", lambda r: "joomla" in r.body.lower()),
    ("Apache Tomcat", lambda r: "coyote" in r.headers.get("server", "").lower() or "apache tomcat" in r.body.lower()),
    ("phpMyAdmin", lambda r: "phpmyadmin" in (_extract_title(r.body) or "").lower()),
]


def _extract_title(body: str) -> Optional[str]:
    """Best-effort ``<title>`` extraction; None if absent or malformed."""
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
    """"Apache/2.4.49 (Unix)" -> ("Apache", "2.4.49"); "nginx" -> ("nginx", None)."""
    server = (server or "").strip()
    if not server:
        return None, None
    token = server.split()[0]  # drop trailing "(Unix)" / "(Ubuntu)" comments
    if "/" in token:
        product, version = token.split("/", 1)
        return product or None, version or None
    return token, None


def fingerprint_http(resp: Response, favicon: Optional[bytes] = None) -> HttpFingerprint:
    """Fingerprint an HTTP service from one response (and optionally its favicon).

    Confidence follows the roadmap's three-tier idea: a versioned ``Server``
    header is the strongest signal (0.9), a bare product name is weaker (0.6),
    and a body/title technology match alone is weakest (0.5) — never higher than
    what Nmap's own direct CPE would earn (0.95 override / 0.7 direct-CPE, per
    §2.1), since this layer has not yet been calibrated against the oracle.
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

SSH_MSG_KEXINIT = 20

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
    product: Optional[str]
    version: Optional[str]
    hassh_server: Optional[str]     # HASSH of the *server's* algorithm lists
    kex_algorithms: tuple
    confidence: float


def parse_ssh_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """"SSH-2.0-OpenSSH_7.4" -> ("OpenSSH", "7.4"); trailing comments are dropped."""
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
    (length,) = struct.unpack_from(">I", data, offset)
    offset += 4
    raw = data[offset:offset + length].decode("ascii", "ignore")
    offset += length
    return (raw.split(",") if raw else []), offset


def parse_kexinit(payload: bytes) -> Dict[str, List[str]]:
    """Parse an SSH_MSG_KEXINIT payload (RFC 4253 §7.1) into its algorithm lists.

    ``payload`` starts at the message code (20); the caller strips packet
    framing first (see :func:`_read_kexinit_payload`).
    """
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("not an SSH_MSG_KEXINIT payload")
    offset = 1 + 16  # message code + 16-byte random cookie
    result: Dict[str, List[str]] = {}
    for field in _KEXINIT_FIELDS:
        result[field], offset = _read_namelist(payload, offset)
    return result


def compute_hassh_server(kexinit: Dict[str, List[str]]) -> str:
    """HASSH (server variant): md5 of "kex;enc_s2c;mac_s2c;cmp_s2c", each field
    the raw comma-joined algorithm list, per the HASSH spec (salesforce/hassh)."""
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
    """Fingerprint an SSH service from its banner and raw KEXINIT payload."""
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
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ValueError("connection closed while reading SSH data")
        buf += chunk
    return buf


def _read_line(sock) -> str:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "ignore").strip()


def _read_kexinit_payload(sock) -> bytes:
    """Strip SSH binary-packet framing (RFC 4253 §6) off the wire and return the
    KEXINIT payload. No MAC is present yet — key exchange has not started."""
    (packet_length,) = struct.unpack(">I", _read_exact(sock, 4))
    body = _read_exact(sock, packet_length)
    padding_length = body[0]
    payload = body[1: len(body) - padding_length]
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("expected SSH_MSG_KEXINIT")
    return payload


class SshProbe:
    """Connects to an SSH port and reads the banner + the server's KEXINIT.

    ``connect`` is injectable (defaults to ``socket.create_connection``) so the
    parsing logic is testable without a real socket, the same pattern
    :class:`~.checks.CheckRuntime` uses for its ``fetch`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 22) -> Optional[Tuple[str, bytes]]:
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("SSH connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            banner = _read_line(sock)
            if not banner:
                return None
            # RFC 4253 §4.2: we must send our own banner before the server's
            # KEXINIT follows, even though we only read (never key-exchange).
            sock.sendall(b"SSH-2.0-Ellysia_1.0\r\n")
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
# ORACLE / CONCORDANCE (§9, §12 measurement)
# =========================================================================

def agrees_with_nmap(
    product: Optional[str], version: Optional[str],
    nmap_product: Optional[str], nmap_version: Optional[str],
) -> bool:
    """Whether our fingerprint agrees with Nmap's for the same service.

    Product agreement is substring overlap (case-insensitive) since naming
    varies ("Apache" vs "Apache httpd"); version agreement requires an exact
    match when both sides report one. This is the per-service judgment that
    :func:`concordance_rate` aggregates.
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
    """Fraction of (product, version, nmap_product, nmap_version) tuples that
    agree — the number the roadmap's Fase F Definition of Done thresholds at
    0.90 before Nmap `-sV` can become a fallback for a service family.

    Empty input returns 0.0 (no evidence yet, not "perfect"). Gathering real
    pairs from a lab of known targets is an operational step for the user, not
    something this function does on its own.
    """
    pairs = list(pairs)
    if not pairs:
        return 0.0
    hits = sum(1 for p in pairs if agrees_with_nmap(*p))
    return hits / len(pairs)
