"""Ellysia's own vulnerability engine.

This is the L2 "detection runtime" seam described in the vuln-engine roadmap.
In Fase 0 it does no detection yet: given the services discovered for a host it
emits one informational "open port" :class:`Finding` per service, so the whole
persistence/correlation plumbing works end to end. Version matching (Fase 1) and
active checks (Fase R) plug into :meth:`EllysiaEngine.analyze` later without the
manager or the persistence layer changing.

The engine is deliberately ORM-free: it takes plain :class:`Service` values and
returns plain dicts ready to build ``Finding`` rows. ``services_from_open_ports``
is the only place that touches the (duck-typed) ``OpenPort`` rows, so the mapping
from Nmap's data model into the engine's lives here, in the ellysia package,
rather than leaking into the manager.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .kb import normalize_cpe_to_23, parse_cpe23


# Quality of Detection for a bare "the port is open" observation: low, because it
# asserts nothing about vulnerability. Detection checks raise this in later phases.
QOD_OPEN_PORT = 30

# Version-based detection (matched a known-vulnerable version by banner/CPE):
# reliable but not actively confirmed — a hypothesis, not a fact (backports).
QOD_VERSION_MATCH = 70


# Nmap product string (lowercased) -> (cpe vendor, cpe product). Seed of the
# override table from the roadmap (§2.1); grows one line per false negative seen
# in production. Consulted only when Nmap did not emit a usable <cpe> itself.
CPE_PRODUCT_OVERRIDES: dict[str, tuple[str, str]] = {
    "apache httpd":        ("apache", "http_server"),
    "openssh":             ("openbsd", "openssh"),
    "nginx":               ("nginx", "nginx"),
    "microsoft iis httpd": ("microsoft", "internet_information_services"),
    "mysql":               ("mysql", "mysql"),
    "mariadb":             ("mariadb", "mariadb"),
    "vsftpd":              ("vsftpd_project", "vsftpd"),
    "proftpd":             ("proftpd", "proftpd"),
    "postfix smtpd":       ("postfix", "postfix"),
    "dovecot imapd":       ("dovecot", "dovecot"),
    "pure-ftpd":           ("pureftpd", "pure-ftpd"),
    "exim smtpd":          ("exim", "exim"),
}


@dataclass(frozen=True)
class Service:
    """A single discovered service, the engine's unit of input.

    Attributes:
        port: TCP/UDP port number, or None if it could not be parsed.
        protocol: Transport protocol ("tcp" / "udp").
        name: Service name as identified (e.g. "http", "ssh"). May be empty.
        product: Product name (e.g. "Apache httpd"). May be empty.
        version: Product version (e.g. "2.4.49"). May be empty.
        cpe: CPE string if known, else None.
    """
    port: Optional[int]
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    cpe: Optional[str] = None

    @property
    def label(self) -> str:
        """Best human-readable name for the service ("Apache httpd 2.4.49")."""
        product_version = " ".join(p for p in (self.product, self.version) if p)
        return product_version or self.name or "servicio desconocido"


class EllysiaEngine:
    """Turns discovered services into normalized findings.

    Emits one informational "open port" finding per service, plus — when a CVE
    lookup is wired (Fase 1) — one version-match finding per known CVE affecting
    the service's product/version. The lookups are injected so the engine stays
    free of the ORM and is trivially testable; the manager passes the KB
    repository's methods.

    Args:
        cve_lookup: ``(vendor, product, version) -> iterable`` of CVE rows (each
            with ``cve_id``/``cvss_score``/``cvss_vector``/``severity``). None
            disables version detection (informational-only, as in Fase 0).
        kev_lookup: ``(cve_id) -> bool``, whether the CVE is in CISA KEV.
        epss_lookup: ``(cve_id) -> float | None``, the EPSS score.
    """

    FEED_VERSION = "ellysia-0"

    def __init__(
        self,
        cve_lookup: Optional[Callable[[str, str, str], Iterable]] = None,
        kev_lookup: Optional[Callable[[str], bool]] = None,
        epss_lookup: Optional[Callable[[str], Optional[float]]] = None,
    ) -> None:
        self._cve_lookup = cve_lookup
        self._kev_lookup = kev_lookup
        self._epss_lookup = epss_lookup

    def analyze(self, services: Iterable[Service]) -> List[dict]:
        """Return Finding-data dicts for the given services.

        Args:
            services: The services discovered for the host.

        Returns:
            A list of dicts with ``Finding`` column values (no scan_id; the
            repository sets it when persisting).
        """
        findings: List[dict] = []
        for service in services:
            findings.append(self._informational_finding(service))
            if self._cve_lookup is not None:
                findings.extend(self._version_findings(service))
        return findings

    def _version_findings(self, service: Service) -> List[dict]:
        """Version-based detection: emit a finding per CVE affecting the service."""
        resolved = _resolve_cpe(service)
        if resolved is None:
            return []
        vendor, product, version, cpe23 = resolved

        findings: List[dict] = []
        for cve in self._cve_lookup(vendor, product, version):  # type: ignore[misc]
            findings.append(self._version_finding(service, cve, cpe23))
        return findings

    def _version_finding(self, service: Service, cve, cpe23: str) -> dict:
        cve_id = cve.cve_id
        return {
            "title":        f"{service.label} — {cve_id}",
            "category":     "outdated_software",
            "port":         service.port,
            "service":      service.name or None,
            "cpe":          cpe23,
            "cve_ids":      [cve_id],
            "cvss_score":   cve.cvss_score,
            "cvss_vector":  cve.cvss_vector,
            "epss_score":   self._epss_lookup(cve_id) if self._epss_lookup else None,
            "in_kev":       self._kev_lookup(cve_id) if self._kev_lookup else False,
            "source":       "ellysia",
            "check_id":     "ellysia:version-match@1",
            "feed_version": self.FEED_VERSION,
            "qod":          QOD_VERSION_MATCH,
            "confirmed":    False,   # version match is a hypothesis; Fase R confirms actively
            "state":        "open",
        }

    def _informational_finding(self, service: Service) -> dict:
        """Build the "open port" informational finding for one service."""
        where = f"{service.port}/{service.protocol}" if service.port else service.protocol
        return {
            "title":        f"Puerto {where} abierto — {service.label}",
            "category":     "open_port",
            "port":         service.port,
            "service":      service.name or None,
            # Normalized to 2.3 (like the version-match finding's cpe) so a
            # consumer grouping findings by cpe sees one consistent format
            # instead of Nmap's raw 2.2 URI here and 2.3 elsewhere.
            "cpe":          normalize_cpe_to_23(service.cpe) if service.cpe else None,
            "source":       "ellysia",
            "check_id":     "ellysia:open-port@1",
            "feed_version": self.FEED_VERSION,
            "qod":          QOD_OPEN_PORT,
            "confirmed":    False,
            "state":        "open",
        }


def services_from_open_ports(open_ports: Iterable) -> List[Service]:
    """Map Nmap ``OpenPort`` rows into engine :class:`Service` values.

    Duck-typed on purpose (reads ``op.port.protocol``, ``op.product`` ...) so the
    engine package does not depend on the ORM model. ``op.port.protocol`` is the
    Nmap "80/tcp" form; anything malformed degrades to ``port=None`` rather than
    raising, so one odd row never sinks a whole scan.
    """
    services: List[Service] = []
    for op in open_ports:
        port, protocol = _split_protocol(getattr(getattr(op, "port", None), "protocol", ""))
        services.append(Service(
            port=port,
            protocol=protocol,
            name=(op.given_use or "").strip(),
            product=(op.product or "").strip(),
            version=(op.version or "").strip(),
            cpe=(op.cpe or None),
        ))
    return services


def _split_protocol(protocol: str) -> tuple[Optional[int], str]:
    """Parse Nmap's "80/tcp" into (80, "tcp"); tolerate malformed input."""
    if not protocol:
        return None, "tcp"
    port_str, _, proto = protocol.partition("/")
    try:
        return int(port_str), (proto or "tcp")
    except ValueError:
        return None, (proto or "tcp")


def _concrete_version(version: str) -> Optional[str]:
    """Return a usable version string, or None for wildcard/empty placeholders."""
    version = (version or "").strip()
    return version if version and version not in ("*", "-") else None


def _resolve_cpe(service: Service) -> Optional[tuple[str, str, str, str]]:
    """Resolve a service to (vendor, product, version, cpe_2_3) for KB matching.

    Two layers, highest confidence first: the CPE Nmap emitted, then the manual
    override table keyed on the product string. Returns None when neither yields
    a concrete vendor/product/version — we never invent a CPE (§2.1). The CPE
    Dictionary token index (roadmap layer 2) is deferred until it is mirrored.
    """
    # 1) Nmap gave a CPE — trust it, falling back to the banner version if the
    #    CPE itself left the version as a wildcard.
    if service.cpe:
        parsed = parse_cpe23(service.cpe)
        if parsed and parsed["vendor"] and parsed["product"]:
            version = _concrete_version(parsed["version"]) or _concrete_version(service.version)
            if version:
                return parsed["vendor"], parsed["product"], version, normalize_cpe_to_23(service.cpe)

    # 2) Override table keyed on the Nmap product string.
    key = (service.product or "").strip().lower()
    version = _concrete_version(service.version)
    if key in CPE_PRODUCT_OVERRIDES and version:
        vendor, product = CPE_PRODUCT_OVERRIDES[key]
        cpe23 = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return vendor, product, version, cpe23

    return None
