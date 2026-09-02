"""Lybra's own service fingerprinting — the identification layer (Fase F).

Instead of trusting ``nmap -sV`` blindly, this package identifies a service's
product and version on its own terms. One module per protocol, chosen for the
best value-for-effort in the roadmap:

``http``
    The ``Server``/``X-Powered-By`` headers, the page ``<title>``, a favicon
    hash, and a data-driven, Wappalyzer-style technology signature feed.

``ssh``
    The identification banner plus **HASSH** — a fingerprint of the algorithm
    lists a server advertises in its ``SSH_MSG_KEXINIT`` packet, parsed
    straight off a raw socket, no SSH library involved.

``tls``
    A single-handshake hygiene check — negotiated protocol version, self-signed
    and expiry status of the certificate. Not JARM (full bit-exact
    *identification*, a separate and larger effort left for later).

``ftp``, ``mail`` (SMTP/IMAP/POP3), ``mysql``, ``redis_probe``, ``vnc``
    Fase N's non-HTTP protocols — each volunteers its identity unprompted
    right after a bare TCP connect, no negotiation needed to read it.

``smb``
    Fase N's one negotiated (not volunteered) protocol: a minimal SMB2
    NEGOTIATE exchange. See its own module docstring for the documented
    simplifications and the "unverified against a live server" caveat.

``snmp``
    Fase N/Ronda 1's first UDP protocol — a ``sysDescr.0`` GetRequest (the
    encoder lives in ``transport.py``, imported back here; see the module's
    own docstring for why). Deliberately never yields a version, only a
    product string — see ``fingerprint_snmp``.

``dispatch``
    The :class:`Dissector` base every protocol module above implements.

``registry``
    :func:`register_dissector`, the class decorator each protocol module uses
    to subscribe its dissector, and :func:`default_dissectors`, which
    instantiates every subscribed one. Together they replace what used to be
    an if/elif chain in ``LybraEngineManager._fingerprint_services`` — adding
    protocol N+1 means decorating its class, not editing a list here or in
    the manager.


That said, a service found by Lybra's own transport (Fase T, no Nmap
involved) never had a Nmap reading to defer to in the first place — it carries
no product/version at all. For that case, and only that case,
``LybraEngineManager._fingerprint_services`` uses a dissector's output to
fill the gap: without it, the version matcher (Fase 1) would have nothing to
look up and a self-discovery-only scan would never find a single CVE. The
result still goes in at the same low-confidence, unconfirmed tier a Nmap CPE
match would (``qod=70``) — this closes a blind spot, it does not raise
confidence beyond what the matcher already assigns any version-based guess.

Two techniques are deliberately left for later: full JARM fingerprinting (too
large and risky to ship without a live TLS lab to validate it against) and OS
fingerprinting (which the roadmap itself rates low value). Both stay
oracle-only — handled by Nmap — until picked up. RDP, LDAP, VNC's full
protocol beyond its version banner, and RPC stay oracle-only too, per the
roadmap's own priority-3 rating for that group; PostgreSQL/MSSQL/MongoDB
(unlike MySQL/Redis) need a negotiated handshake rather than a volunteered
banner and are deferred alongside them.
"""

from __future__ import annotations

from .dispatch import Dissector, DissectorResult, QOD_FINGERPRINT
from .registry import register_dissector, default_dissectors
from .http import (
    HttpFingerprint,
    SignatureHit,
    TechMatcher,
    TechSignature,
    load_tech_signatures,
    validate_tech_signatures,
    fingerprint_http,
    HttpDissector,
)
from .ssh import (
    SSH_MSG_KEXINIT,
    SshFingerprint,
    parse_ssh_banner,
    parse_kexinit,
    compute_hassh_server,
    fingerprint_ssh,
    SshProbe,
    SshDissector,
)
from .tls import (
    TlsInfo,
    TlsProbe,
)
from .ftp import (
    FtpFingerprint,
    parse_ftp_banner,
    fingerprint_ftp,
    FtpProbe,
    FtpDissector,
)
from .mail import (
    MailFingerprint,
    parse_smtp_banner,
    fingerprint_smtp,
    fingerprint_imap,
    fingerprint_pop3,
    MailProbe,
    SmtpDissector,
    ImapDissector,
    Pop3Dissector,
)
from .smb import (
    SmbFingerprint,
    parse_negotiate_response,
    fingerprint_smb,
    SmbProbe,
    SmbDissector,
)
from .mysql import (
    MysqlFingerprint,
    parse_mysql_handshake,
    fingerprint_mysql,
    MysqlProbe,
    MysqlDissector,
)
from .redis_probe import (
    RedisFingerprint,
    parse_redis_info,
    fingerprint_redis,
    RedisProbe,
    RedisDissector,
)
from .vnc import (
    VncFingerprint,
    parse_rfb_version,
    fingerprint_vnc,
    VncProbe,
    VncDissector,
)
from .snmp import (
    SnmpFingerprint,
    parse_snmp_sysdescr,
    fingerprint_snmp,
    SnmpProbe,
    SnmpDissector,
)

__all__ = [
    "Dissector",
    "DissectorResult",
    "register_dissector",
    "default_dissectors",
    "HttpFingerprint",
    "SignatureHit",
    "TechMatcher",
    "TechSignature",
    "validate_tech_signatures",
    "load_tech_signatures",
    "fingerprint_http",
    "HttpDissector",
    "SSH_MSG_KEXINIT",
    "SshFingerprint",
    "parse_ssh_banner",
    "parse_kexinit",
    "compute_hassh_server",
    "fingerprint_ssh",
    "SshProbe",
    "SshDissector",
    "TlsInfo",
    "TlsProbe",
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
]
