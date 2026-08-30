"""Lybra's own vulnerability engine — the code that makes it a scanner.

This package holds everything that makes Lybra a scanner in its own right,
rather than an orchestrator that just runs Nmap and Nikto. By project
convention the managers live in ``themis/managers.py`` and the repositories in
``themis/repositories.py``; the detection logic lives here.

A scan flows down through the engine's layers, and each module here owns one of
them:

``transport``
    Discovers which ports are open (the L0 layer) — an unprivileged asyncio
    connect scan.

``fingerprinting``
    Identifies what is running on a port (L1) — one dissector module per
    protocol (HTTP, SSH, TLS, FTP, SMTP/IMAP/POP3, SMB, MySQL, Redis, VNC...),
    calibrated against Nmap where an oracle bench exists.

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
    Bridges Nikto and Nuclei results into the shared ``Finding`` model, so every
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
    services_from_payload,
    QOD_OPEN_PORT,
    QOD_INVENTORY_MATCH,
    CPE_PRODUCT_OVERRIDES,
)
from .kb import (
    version_compare,
    split_distro_version,
    kb_feed_version,
    version_in_range,
    normalize_cpe_to_23,
    normalize_product_name,
    extract_trailing_version,
    load_product_aliases,
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
    NetworkProbe,
    NetworkSession,
    Response,
    is_http_service,
    is_tls_service,
    is_ftp_service,
    is_smtp_service,
    is_imap_service,
    is_pop3_service,
    is_smb_service,
    is_mysql_service,
    is_redis_service,
    is_vnc_service,
    CHECKS_FEED_VERSION,
    QOD_CONFIRMED,
    ScriptContext,
    ScriptPlugin,
)
from .script_checks import (
    SmbSigningNotRequiredPlugin,
    SnmpDefaultCommunityPlugin,
    default_script_plugins,
)
from .correlation import (
    classify_exposure,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    score_finding,
    PRIORITY_LADDER,
)
from .fingerprinting import (
    Dissector,
    DissectorResult,
    default_dissectors,
    fingerprint_http,
    fingerprint_ssh,
    parse_ssh_banner,
    parse_kexinit,
    compute_hassh_server,
    load_tech_signatures,
    SshProbe,
    SshDissector,
    HttpDissector,
    TlsProbe,
    HttpFingerprint,
    SshFingerprint,
    TlsInfo,
    TechSignature,
    TechMatcher,
    FtpFingerprint,
    parse_ftp_banner,
    fingerprint_ftp,
    FtpProbe,
    FtpDissector,
    MailFingerprint,
    parse_smtp_banner,
    fingerprint_smtp,
    fingerprint_imap,
    fingerprint_pop3,
    MailProbe,
    SmtpDissector,
    ImapDissector,
    Pop3Dissector,
    SmbFingerprint,
    parse_negotiate_response,
    fingerprint_smb,
    SmbProbe,
    SmbDissector,
    MysqlFingerprint,
    parse_mysql_handshake,
    fingerprint_mysql,
    MysqlProbe,
    MysqlDissector,
    RedisFingerprint,
    parse_redis_info,
    fingerprint_redis,
    RedisProbe,
    RedisDissector,
    VncFingerprint,
    parse_rfb_version,
    fingerprint_vnc,
    VncProbe,
    VncDissector,
    SnmpFingerprint,
    parse_snmp_sysdescr,
    fingerprint_snmp,
    SnmpProbe,
    SnmpDissector,
    QOD_FINGERPRINT,
)
from .adapters import (
    nikto_incident_to_finding,
    nuclei_result_to_finding,
    finding_to_json,
    QOD_NUCLEI_MATCH,
)
from .transport import (
    AsyncConnectScanner,
    scan_ports_sync,
    scan_udp_ports_sync,
    services_from_discovered_ports,
    DEFAULT_PORTS,
    UDP_PROBES,
    WELL_KNOWN_PORTS,
)

__all__ = [
    "LybraEngine",
    "Service",
    "services_from_payload",
    "QOD_OPEN_PORT",
    "QOD_INVENTORY_MATCH",
    "version_compare",
    "split_distro_version",
    "kb_feed_version",
    "version_in_range",
    "normalize_cpe_to_23",
    "normalize_product_name",
    "extract_trailing_version",
    "load_product_aliases",
    "parse_cpe23",
    "CPE_PRODUCT_OVERRIDES",
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
    "NetworkProbe",
    "NetworkSession",
    "Response",
    "is_http_service",
    "is_tls_service",
    "is_ftp_service",
    "is_smtp_service",
    "is_imap_service",
    "is_pop3_service",
    "is_smb_service",
    "is_mysql_service",
    "is_redis_service",
    "is_vnc_service",
    "CHECKS_FEED_VERSION",
    "QOD_CONFIRMED",
    "ScriptContext",
    "ScriptPlugin",
    "SmbSigningNotRequiredPlugin",
    "SnmpDefaultCommunityPlugin",
    "default_script_plugins",
    "classify_exposure",
    "compute_dedup_key",
    "merge_findings",
    "apply_lifecycle",
    "score_finding",
    "PRIORITY_LADDER",
    "Dissector",
    "DissectorResult",
    "default_dissectors",
    "fingerprint_http",
    "fingerprint_ssh",
    "parse_ssh_banner",
    "parse_kexinit",
    "compute_hassh_server",
    "load_tech_signatures",
    "SshProbe",
    "SshDissector",
    "HttpDissector",
    "TlsProbe",
    "HttpFingerprint",
    "SshFingerprint",
    "TlsInfo",
    "TechSignature",
    "TechMatcher",
    "FtpFingerprint",
    "parse_ftp_banner",
    "fingerprint_ftp",
    "FtpProbe",
    "FtpDissector",
    "MailFingerprint",
    "parse_smtp_banner",
    "fingerprint_smtp",
    "fingerprint_imap",
    "fingerprint_pop3",
    "MailProbe",
    "SmtpDissector",
    "ImapDissector",
    "Pop3Dissector",
    "SmbFingerprint",
    "parse_negotiate_response",
    "fingerprint_smb",
    "SmbProbe",
    "SmbDissector",
    "MysqlFingerprint",
    "parse_mysql_handshake",
    "fingerprint_mysql",
    "MysqlProbe",
    "MysqlDissector",
    "RedisFingerprint",
    "parse_redis_info",
    "fingerprint_redis",
    "RedisProbe",
    "RedisDissector",
    "VncFingerprint",
    "parse_rfb_version",
    "fingerprint_vnc",
    "VncProbe",
    "VncDissector",
    "SnmpFingerprint",
    "parse_snmp_sysdescr",
    "fingerprint_snmp",
    "SnmpProbe",
    "SnmpDissector",
    "QOD_FINGERPRINT",
    "nikto_incident_to_finding",
    "nuclei_result_to_finding",
    "finding_to_json",
    "QOD_NUCLEI_MATCH",
    "AsyncConnectScanner",
    "scan_ports_sync",
    "scan_udp_ports_sync",
    "services_from_discovered_ports",
    "DEFAULT_PORTS",
    "UDP_PROBES",
    "WELL_KNOWN_PORTS",
]
