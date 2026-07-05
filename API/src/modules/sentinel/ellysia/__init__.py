"""Ellysia's own vulnerability engine (native detection).

Home for everything that makes Ellysia a scanner in its own right rather than an
orchestrator of Nmap/Nikto/OpenVAS. Managers live in ``sentinel/managers.py`` and
repositories in ``sentinel/repositories.py`` by project convention; the detection
logic (the engine, and in later phases the dissectors, checks and transport)
lives here.
"""

from __future__ import annotations

from .engine import (
    EllysiaEngine,
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
    SshProbe,
    HttpFingerprint,
    SshFingerprint,
    agrees_with_nmap,
    concordance_rate,
    QOD_FINGERPRINT,
)

__all__ = [
    "EllysiaEngine",
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
    "SshProbe",
    "HttpFingerprint",
    "SshFingerprint",
    "agrees_with_nmap",
    "concordance_rate",
    "QOD_FINGERPRINT",
]
