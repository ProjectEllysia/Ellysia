"""Lybra's own vulnerability engine — the code that makes it a scanner.

This package holds everything that makes Lybra a scanner in its own right,
rather than an orchestrator that just runs Nmap, Nikto and OpenVAS. By project
convention the managers live in ``themis/managers.py`` and the repositories in
``themis/repositories.py``; the detection logic lives here.

A scan flows down through the engine's layers, and each module here owns one of
them:

``transport``
    Discovers which ports are open (the L0 layer) — an unprivileged asyncio
    connect scan.

``fingerprint``
    Identifies what is running on a port (L1) — HTTP and SSH dissectors,
    calibrated against Nmap.

``engine``
    The detection core (L2): turns discovered services into findings, including
    version-based CVE matches.

``checks``
    The active-detection runtime (also L2): runs declarative checks to *confirm*
    a vulnerability rather than merely infer it.

``kb``
    The local knowledge base (L3): a mirror of NVD/KEV/EPSS plus the version and
    CPE logic the matcher relies on.

``correlation``
    Deduplication, lifecycle and contextual scoring (L3): turns per-scan findings
    into vulnerability state on an asset over time.

``adapters``
    Bridges Nikto and OpenVAS results into the shared ``Finding`` model, so every
    scanner can be correlated together.

Everything here is deliberately free of the ORM and of network side effects
where it can be: pure functions take plain values and return plain dicts, and the
few pieces that must touch the network (the probes and fetchers) take injectable
callables so they can be tested without it.
"""

from __future__ import annotations

from .engine import (
    LybraEngine,
    Service,
    services_from_open_ports,
    QOD_OPEN_PORT,
)
from .kb import (
    version_compare,
    version_in_range,
    normalize_cpe_to_23,
    parse_cpe23,
    ingest_nvd_cve,
    ingest_kev,
    parse_epss_rows,
    fetch_kev,
    fetch_epss,
    iter_nvd_pages,
)
from .checks import (
    load_checks,
    CheckRuntime,
    HttpProbe,
    HostRateLimiter,
    Response,
    is_http_service,
    is_tls_service,
    CHECKS_FEED_VERSION,
    QOD_CONFIRMED,
)
from .correlation import (
    classify_exposure,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    score_finding,
    PRIORITY_LADDER,
)
from .fingerprint import (
    fingerprint_http,
    fingerprint_ssh,
    parse_ssh_banner,
    parse_kexinit,
    compute_hassh_server,
    load_tech_signatures,
    SshProbe,
    TlsProbe,
    HttpFingerprint,
    SshFingerprint,
    TlsInfo,
    TechSignature,
    TechMatcher,
    agrees_with_nmap,
    concordance_rate,
    QOD_FINGERPRINT,
)
from .adapters import (
    nikto_incident_to_finding,
    openvas_result_to_finding,
)
from .transport import (
    AsyncConnectScanner,
    scan_ports_sync,
    services_from_discovered_ports,
    port_concordance,
    DEFAULT_PORTS,
    WELL_KNOWN_PORTS,
)

__all__ = [
    "LybraEngine",
    "Service",
    "services_from_open_ports",
    "QOD_OPEN_PORT",
    "version_compare",
    "version_in_range",
    "normalize_cpe_to_23",
    "parse_cpe23",
    "ingest_nvd_cve",
    "ingest_kev",
    "parse_epss_rows",
    "fetch_kev",
    "fetch_epss",
    "iter_nvd_pages",
    "load_checks",
    "CheckRuntime",
    "HttpProbe",
    "HostRateLimiter",
    "Response",
    "is_http_service",
    "is_tls_service",
    "CHECKS_FEED_VERSION",
    "QOD_CONFIRMED",
    "classify_exposure",
    "compute_dedup_key",
    "merge_findings",
    "apply_lifecycle",
    "score_finding",
    "PRIORITY_LADDER",
    "fingerprint_http",
    "fingerprint_ssh",
    "parse_ssh_banner",
    "parse_kexinit",
    "compute_hassh_server",
    "load_tech_signatures",
    "SshProbe",
    "TlsProbe",
    "HttpFingerprint",
    "SshFingerprint",
    "TlsInfo",
    "TechSignature",
    "TechMatcher",
    "agrees_with_nmap",
    "concordance_rate",
    "QOD_FINGERPRINT",
    "nikto_incident_to_finding",
    "openvas_result_to_finding",
    "AsyncConnectScanner",
    "scan_ports_sync",
    "services_from_discovered_ports",
    "port_concordance",
    "DEFAULT_PORTS",
    "WELL_KNOWN_PORTS",
]
