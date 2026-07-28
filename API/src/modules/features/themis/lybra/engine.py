"""The detection core — turns discovered services into normalized findings.

This is the L2 "detection runtime" of the roadmap. Given the services found on a
host, the engine produces :class:`Finding`-shaped dicts: always an informational
"this port is open" finding, and — when a CVE lookup is wired in — one finding
per known vulnerability that affects the service's product and version.

Two design choices keep this module easy to reason about and to test:

* It is **ORM-free**. The engine works with plain :class:`Service` values and
  returns plain dicts; it never touches the database. The lookups it needs
  (CVE / KEV / EPSS) are passed in as callables, so a test can hand it fakes and
  a caller can hand it the real repository methods.
* The mapping from Nmap's data model into the engine's lives *here*, in
  :func:`services_from_open_ports`, rather than leaking into the manager.

The persistence, correlation and network phases all happen around the engine, in
the manager; the engine itself is a pure transformation from services to
findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .kb import normalize_cpe_to_23, parse_cpe23


# Quality of Detection for a bare "the port is open" observation. It is low
# because it asserts nothing about vulnerability; the real detection checks in
# later phases earn a much higher score.
QOD_OPEN_PORT = 30

# Quality of Detection for a version-based match: we recognised a known-vulnerable
# version from the banner or CPE. Reliable, but not actively confirmed — it stays
# a hypothesis rather than a fact, because a distro may have back-ported the fix
# without changing the version number.
QOD_VERSION_MATCH = 70

# Quality of Detection for a version-based match built from a Service whose
# origin is "inventory" (Fase 0.9) — a package an agent read directly off the
# host, not a guess from a network banner. There is no back-port ambiguity to
# hedge against here: the installed version *is* the version, so the match is
# both confirmed and scored close to an actively-confirmed check (QOD_CONFIRMED
# in checks.py), without claiming the exploit was actually reproduced.
QOD_INVENTORY_MATCH = 95


# Maps a product string (lowercased) to the (vendor, product) pair CPE uses.
# Consulted whenever a service has no usable CPE of its own — whether the
# product/version came from Nmap's own naming ("Apache httpd") or from
# Lybra's own HTTP/SSH fingerprint reading the Server header or SSH banner
# directly ("Apache", "OpenSSH" — see lybra.fingerprinting). Both spellings for
# the same product are kept as separate keys rather than normalized, since
# that keeps this table a flat, auditable list. This is a small, hand-curated
# seed; it grows by one line each time a real scan turns up a product we do
# not yet map. The alternative — guessing a CPE — is worse, because a CPE that
# does not exist in NVD silently matches nothing.
CPE_PRODUCT_OVERRIDES: dict[str, tuple[str, str]] = {
    "apache httpd":        ("apache", "http_server"),
    "apache":               ("apache", "http_server"),  # Server header says "Apache", Nmap says "Apache httpd"
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
    """One discovered network service — the engine's unit of input.

    Attributes:
        port: The TCP/UDP port number, or ``None`` if it could not be parsed.
            Commonly ``None`` for an ``origin="inventory"`` service — an
            installed library is not listening anywhere.
        protocol: The transport protocol, ``"tcp"`` or ``"udp"``. May be empty
            for an ``origin="inventory"`` service, which has no transport.
        name: The service name as identified, e.g. ``"http"`` or ``"ssh"``. May
            be empty when unknown.
        product: The product name, e.g. ``"Apache httpd"``. May be empty.
        version: The product version, e.g. ``"2.4.49"``. May be empty.
        cpe: A CPE string for the service if one is known, else ``None``.
        origin: Where this reading came from — ``"network"`` (the only value
            that existed before Fase 0.9): inferred from a banner, a CPE Nmap
            emitted, or Lybra's own fingerprint. Or ``"inventory"``: a fact
            read directly off the host (e.g. a package manager), not a guess.
            The engine uses this to decide how much to trust a version match
            (see :data:`QOD_INVENTORY_MATCH`) — it is not network vs. local in
            the transport sense, it is inferred vs. verified.
    """
    port: Optional[int]
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    cpe: Optional[str] = None
    origin: str = "network"

    @property
    def label(self) -> str:
        """A human-readable name for the service.

        Prefers "product version" (e.g. "Apache httpd 2.4.49"), falls back to the
        service name, and finally to a generic placeholder.
        """
        product_version = " ".join(p for p in (self.product, self.version) if p)
        return product_version or self.name or "servicio desconocido"


class LybraEngine:
    """Produces normalized findings from a host's discovered services.

    For every service the engine emits one informational "open port" finding.
    When a CVE lookup has been supplied, it also emits one finding per known CVE
    affecting the service's product and version.

    The lookups are injected rather than imported so the engine stays free of the
    ORM and is trivially testable — the manager passes the knowledge-base
    repository's methods, while a test passes stubs.

    Args:
        cve_lookup: A callable ``(vendor, product, version) -> iterable`` of CVE
            rows, each exposing ``cve_id`` / ``cvss_score`` / ``cvss_vector``.
            Passing ``None`` disables version detection, leaving only the
            informational findings.
        kev_lookup: A callable ``(cve_id) -> bool`` telling whether the CVE is in
            CISA's Known Exploited Vulnerabilities catalogue.
        epss_lookup: A callable ``(cve_id) -> float | None`` returning the CVE's
            EPSS exploitation-probability score.
    """

    FEED_VERSION = "lybra-0"

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
        """Produce the findings for a set of services.

        Args:
            services: The services discovered on the host.

        Returns:
            A list of dicts holding ``Finding`` column values. The ``scan_id`` is
            not set here — the repository fills it in at persist time.
        """
        findings: List[dict] = []
        for service in services:
            findings.append(self._informational_finding(service))
            if self._cve_lookup is not None:
                findings.extend(self._version_findings(service))
        return findings

    def _version_findings(self, service: Service) -> List[dict]:
        """Emit a finding for each known CVE affecting one service.

        Resolves the service to a CPE, queries the CVE lookup, and builds a
        finding per hit. Returns an empty list when the service cannot be
        resolved to a concrete vendor/product/version.
        """
        resolved = _resolve_cpe(service)
        if resolved is None:
            return []
        vendor, product, version, cpe23 = resolved

        findings: List[dict] = []
        for cve in self._cve_lookup(vendor, product, version):  # type: ignore[misc]
            findings.append(self._version_finding(service, cve, cpe23))
        return findings

    def _version_finding(self, service: Service, cve, cpe23: str) -> dict:
        """Build a single version-match finding for a service and one CVE.

        An ``origin="inventory"`` service (Fase 0.9) is a verified fact, not a
        banner guess, so it earns a higher ``qod`` and is born ``confirmed`` —
        there is no back-port ambiguity to hedge against when the version came
        straight from the package manager.
        """
        cve_id = cve.cve_id
        verified = service.origin == "inventory"
        return {
            "title":        f"{service.label} — {cve_id}",
            "category":     "outdated_software",
            "port":         service.port,
            "service":      service.name or service.product or None,
            "cpe":          cpe23,
            "cve_ids":      [cve_id],
            "cvss_score":   cve.cvss_score,
            "cvss_vector":  cve.cvss_vector,
            "epss_score":   self._epss_lookup(cve_id) if self._epss_lookup else None,
            "in_kev":       self._kev_lookup(cve_id) if self._kev_lookup else False,
            "source":       "lybra",
            "check_id":     "lybra:version-match@1",
            "feed_version": self.FEED_VERSION,
            "qod":          QOD_INVENTORY_MATCH if verified else QOD_VERSION_MATCH,
            "confirmed":    verified,   # a network-inferred match stays a hypothesis; Fase R confirms it actively
            "state":        "open",
        }

    def _informational_finding(self, service: Service) -> dict:
        """Build the baseline informational finding for one service.

        A network-origin service is described as an open port, as before. An
        inventory-origin service commonly has no port at all (a library is not
        listening anywhere), so that case gets its own phrasing and category
        instead of a nonsensical "Puerto None abierto".
        """
        if service.origin == "inventory" and service.port is None:
            title = f"Paquete instalado — {service.label}"
            category = "installed_package"
        else:
            where = f"{service.port}/{service.protocol}" if service.port else service.protocol
            title = f"Puerto {where} abierto — {service.label}"
            category = "open_port"
        return {
            "title":        title,
            "category":     category,
            "port":         service.port,
            "service":      service.name or service.product or None,
            "cpe":          normalize_cpe_to_23(service.cpe) if service.cpe else None,
            "source":       "lybra",
            "check_id":     "lybra:open-port@1",
            "feed_version": self.FEED_VERSION,
            "qod":          QOD_OPEN_PORT,
            "confirmed":    False,
            "state":        "open",
        }


def services_from_open_ports(open_ports: Iterable) -> List[Service]:
    """Map Nmap ``OpenPort`` rows into engine :class:`Service` values.

    Reads the rows by duck typing (``op.port.protocol``, ``op.product`` and so
    on) so the engine package does not depend on the ORM model. Anything
    malformed — a bad protocol string, say — degrades gracefully to ``port=None``
    instead of raising, so a single odd row never sinks a whole scan.

    Args:
        open_ports: An iterable of ``OpenPort`` rows (or anything exposing the
            same attributes).

    Returns:
        The corresponding list of :class:`Service` values.
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


def services_from_payload(raw: Iterable[dict]) -> List[Service]:
    """Build engine :class:`Service` values from an externally-supplied dataset.

    Fase 0.9's third input mode: a convenience for a producer whose data
    arrives as plain dicts rather than already-built ``Service`` instances —
    the shape a future Hygeia inventory adapter, or any other in-process
    caller, is likely to have. A caller that already builds ``Service``
    directly does not need this at all; ``LybraEngineManager.run_scan``
    accepts either.

    Unlike :func:`services_from_open_ports` and
    :func:`services_from_discovered_ports`, this trusts an explicit
    ``"origin"`` key if the payload sets one, defaulting to ``"network"`` so a
    producer that predates Fase 0.9 (there are none yet) would behave exactly
    as those two functions do.

    Args:
        raw: An iterable of dicts with the same keys as :class:`Service`'s
            fields (all optional except none are required — missing keys
            fall back to the same defaults ``Service`` itself uses).

    Returns:
        The corresponding list of :class:`Service` values.
    """
    services: List[Service] = []
    for item in raw:
        services.append(Service(
            port=item.get("port"),
            protocol=item.get("protocol") or "",
            name=(item.get("name") or "").strip(),
            product=(item.get("product") or "").strip(),
            version=(item.get("version") or "").strip(),
            cpe=item.get("cpe") or None,
            origin=item.get("origin") or "network",
        ))
    return services


def _split_protocol(protocol: str) -> tuple[Optional[int], str]:
    """Split Nmap's "80/tcp" form into a ``(port, protocol)`` pair.

    Tolerates malformed input by returning ``port=None`` rather than raising.

    Args:
        protocol: A protocol string such as ``"80/tcp"``.

    Returns:
        A ``(port_number_or_None, protocol_string)`` tuple, defaulting the
        protocol to ``"tcp"``.
    """
    if not protocol:
        return None, "tcp"
    port_str, _, proto = protocol.partition("/")
    try:
        return int(port_str), (proto or "tcp")
    except ValueError:
        return None, (proto or "tcp")


def _concrete_version(version: str) -> Optional[str]:
    """Return a usable version string, or ``None`` for wildcard/empty placeholders.

    Args:
        version: A raw version string, possibly ``"*"``, ``"-"`` or empty.

    Returns:
        The stripped version, or ``None`` if it is a wildcard or blank.
    """
    version = (version or "").strip()
    return version if version and version not in ("*", "-") else None


def _resolve_cpe(service: Service) -> Optional[tuple[str, str, str, str]]:
    """Resolve a service to a ``(vendor, product, version, cpe_2_3)`` for matching.

    Two strategies are tried, highest confidence first:

    1. Trust the CPE Nmap emitted, if any — falling back to the banner version
       when the CPE itself left the version as a wildcard.
    2. Look the product name up in :data:`CPE_PRODUCT_OVERRIDES`.

    If neither yields a concrete vendor, product and version, this returns
    ``None`` rather than inventing a CPE — a fabricated CPE that NVD does not know
    would silently match nothing. (The token-based CPE Dictionary lookup, the
    roadmap's third strategy, is deferred until that dictionary is mirrored.)

    Args:
        service: The service to resolve.

    Returns:
        A ``(vendor, product, version, cpe_2_3)`` tuple, or ``None`` if the
        service cannot be resolved with confidence.
    """
    # 1) Nmap gave a CPE — trust it, falling back to the banner version if the
    #    CPE itself left the version as a wildcard.
    if service.cpe:
        parsed = parse_cpe23(service.cpe)
        if parsed and parsed["vendor"] and parsed["product"]:
            version = _concrete_version(parsed["version"]) or _concrete_version(service.version)
            if version:
                return parsed["vendor"], parsed["product"], version, normalize_cpe_to_23(service.cpe)

    # 2) Fall back to the override table, keyed on the Nmap product string.
    key = (service.product or "").strip().lower()
    version = _concrete_version(service.version)
    if key in CPE_PRODUCT_OVERRIDES and version:
        vendor, product = CPE_PRODUCT_OVERRIDES[key]
        cpe23 = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return vendor, product, version, cpe23

    return None
