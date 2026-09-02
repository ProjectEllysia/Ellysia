"""Lybra's own service fingerprinting — the identification layer (Fase F).

Instead of trusting ``nmap -sV`` blindly, this package identifies a service's
product and version on its own terms. One module per protocol, chosen for the
best value-for-effort in the roadmap:

``http_apis``
    Las APIs de administración que hablan HTTP y publican su versión en un
    JSON sin autenticar: Docker, Elasticsearch, Kibana, Kubernetes, etcd y
    Consul. Se importa **antes** que ``http`` porque sus puertos entran ahora
    en la familia HTTP y el motor se queda con el primer dissector que
    reclame el servicio (ver ``registry``).

``http``
    Una cascada de seis fuentes para producto y versión —cabecera ``Server``,
    cabeceras ``X-Powered-By``/``X-AspNet-Version``, ``<meta generator>``,
    firmas del feed con patrón de versión, página de error por defecto y
    versión repetida en rutas de assets—, más el ``<title>``, un hash del
    favicon y el feed de firmas de tecnología al estilo Wappalyzer. Cada
    lectura registra de qué nivel salió, y ese nivel decide el ``qod`` del
    hallazgo. Hasta L18 la única fuente era ``Server``, que es justo la que
    cualquier despliegue fortificado suprime.

``ssh``
    The identification banner plus **HASSH** — a fingerprint of the algorithm
    lists a server advertises in its ``SSH_MSG_KEXINIT`` packet, parsed
    straight off a raw socket, no SSH library involved.

``tls``
    A single-handshake hygiene check — negotiated protocol version, self-signed
    and expiry status of the certificate. Not JARM (full bit-exact
    *identification*, a separate and larger effort left for later).

``postgres``
    La primera base de datos que **negocia** en vez de ofrecer un banner: un
    ``SSLRequest`` de ocho bytes y un ``StartupMessage`` con un usuario que no
    existe, para leer si el servidor exige TLS y qué autenticación anuncia.
    Ningún intento de login. PostgreSQL no regala su versión antes de
    autenticar, y el módulo no la inventa.

``mssql``
    El más generoso de los tres: un ``PRELOGIN`` de TDS devuelve major, minor
    y build en un campo binario de tamaño fijo, sin autenticar, más el modo de
    cifrado que el servidor exige.

``mongo``
    ``hello`` para la versión —que contesta siempre, con autenticación y sin
    ella— y ``listDatabases`` para saber si el servidor deja entrar sin
    credenciales. Parseo de BSON mínimo, sin ``pymongo``.

``ldap``
    El rootDSE, la consulta anónima que la RFC 4512 define para que un cliente
    sepa con quién habla: vendor, versión y los dominios que el servidor sirve.
    BER a mano, con lectura de longitudes en forma larga — la mitad que el
    codificador de SNMP no necesitaba.

``rdp``
    La negociación de ``X.224``: qué protocolo de seguridad elige el servidor
    y, con ello, si exige NLA. Resultado binario y sin ambigüedad, que es lo
    contrario de un banner de texto libre. No da versión, y no se inventa una.

``ftp``, ``mail`` (SMTP/IMAP/POP3), ``mysql``, ``redis_probe``, ``vnc``
    Fase N's non-HTTP protocols — each volunteers its identity unprompted
    right after a bare TCP connect, no negotiation needed to read it.

``smb``
    Tres intercambios sin credenciales: el ``NEGOTIATE`` de SMB2 (dialecto y
    si exige firma), un ``SESSION_SETUP`` anónimo que se corta en el primer
    paso de NTLM y del que salen nombre de equipo, dominio y versión de
    sistema, y una negociación de **SMB1** aparte — el único modo de saber si
    ese protocolo sigue habilitado, porque el saludo de SMB2 no lo ve. Ver su
    docstring para las simplificaciones documentadas.

``snmp``
    Fase N/Ronda 1's first UDP protocol — a ``sysDescr.0`` GetRequest (the
    encoder lives in ``transport.py``, imported back here; see the module's
    own docstring for why). La versión sale de un feed de patrones **por
    fabricante** (``feeds/sysdescr_patterns.json``) y nunca de una regex
    genérica sobre texto libre; un ``sysDescr`` que ningún patrón reconoce
    aporta el texto crudo como producto y ninguna versión.

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
oracle-only — handled by Nmap — until picked up. VNC's full protocol beyond its
version banner, and RPC, stay oracle-only too, per the roadmap's own
priority-3 rating for that group.
"""

from __future__ import annotations

from .dispatch import Dissector, DissectorResult, QOD_FINGERPRINT
from .registry import register_dissector, default_dissectors
from .cascade import (
    banner_readers,
    blind_probers,
    identify_unknown_service,
    read_volunteered_banner,
)
from .favicon import (
    FaviconCatalog,
    FaviconEntry,
    favicon_hash,
    load_favicon_hashes,
    murmurhash3_x86_32,
    validate_favicon_hashes,
)
from .http_apis import (
    ADMIN_APIS,
    AdminApi,
    AdminApiDissector,
    fingerprint_admin_api,
)
from .http import (
    HttpFingerprint,
    SignatureHit,
    VersionReading,
    VERSION_SOURCES,
    VERSION_SOURCE_QOD,
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
    AV_PAIR_NAMES,
    SMB1_DIALECT,
    SIGNING_REQUIRED_BIT,
    SmbDissector,
    SmbFingerprint,
    SmbProbe,
    build_negotiate_request,
    build_ntlm_negotiate,
    build_session_setup_request,
    build_smb1_negotiate,
    fingerprint_smb,
    parse_negotiate_response,
    parse_ntlm_challenge,
    parse_smb1_negotiate_response,
)
from .rdp import (
    FAILURE_CODES,
    PROTOCOL_NAMES,
    RdpDissector,
    RdpFingerprint,
    RdpProbe,
    build_connection_request,
    fingerprint_rdp,
    parse_connection_confirm,
)
from .ldap import (
    ROOTDSE_ATTRIBUTES,
    LdapDissector,
    LdapFingerprint,
    LdapProbe,
    build_anonymous_bind,
    build_rootdse_search,
    fingerprint_ldap,
    parse_bind_response,
    parse_search_entry,
)
from .mongo import (
    HELLO_COMMAND,
    LIST_DATABASES_COMMAND,
    MongoDissector,
    MongoFingerprint,
    MongoProbe,
    build_op_msg,
    fingerprint_mongo,
    parse_bson_document,
    parse_op_msg,
)
from .mssql import (
    ENCRYPTION_MODES,
    MssqlDissector,
    MssqlFingerprint,
    MssqlProbe,
    build_prelogin_request,
    fingerprint_mssql,
    parse_prelogin_response,
)
from .postgres import (
    AUTH_METHODS,
    PostgresDissector,
    PostgresFingerprint,
    PostgresProbe,
    build_ssl_request,
    build_startup_message,
    fingerprint_postgres,
    parse_ssl_response,
    parse_startup_response,
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
    QOD_VENDOR_PATTERN,
    SnmpDissector,
    SnmpFingerprint,
    SnmpProbe,
    SysDescrMatch,
    SysDescrPattern,
    fingerprint_snmp,
    load_sysdescr_patterns,
    match_sysdescr,
    parse_snmp_sysdescr,
    validate_sysdescr_patterns,
)

__all__ = [
    "Dissector",
    "DissectorResult",
    "register_dissector",
    "default_dissectors",
    "HttpFingerprint",
    "SignatureHit",
    "QOD_VENDOR_PATTERN",
    "SysDescrMatch",
    "SysDescrPattern",
    "load_sysdescr_patterns",
    "match_sysdescr",
    "validate_sysdescr_patterns",
    "AV_PAIR_NAMES",
    "SMB1_DIALECT",
    "build_ntlm_negotiate",
    "build_session_setup_request",
    "build_smb1_negotiate",
    "parse_ntlm_challenge",
    "parse_smb1_negotiate_response",
    "FAILURE_CODES",
    "PROTOCOL_NAMES",
    "RdpDissector",
    "RdpFingerprint",
    "RdpProbe",
    "build_connection_request",
    "fingerprint_rdp",
    "parse_connection_confirm",
    "ROOTDSE_ATTRIBUTES",
    "LdapDissector",
    "LdapFingerprint",
    "LdapProbe",
    "build_anonymous_bind",
    "build_rootdse_search",
    "fingerprint_ldap",
    "parse_bind_response",
    "parse_search_entry",
    "HELLO_COMMAND",
    "LIST_DATABASES_COMMAND",
    "MongoDissector",
    "MongoFingerprint",
    "MongoProbe",
    "build_op_msg",
    "fingerprint_mongo",
    "parse_bson_document",
    "parse_op_msg",
    "ENCRYPTION_MODES",
    "MssqlDissector",
    "MssqlFingerprint",
    "MssqlProbe",
    "build_prelogin_request",
    "fingerprint_mssql",
    "parse_prelogin_response",
    "AUTH_METHODS",
    "PostgresDissector",
    "PostgresFingerprint",
    "PostgresProbe",
    "build_ssl_request",
    "build_startup_message",
    "fingerprint_postgres",
    "parse_ssl_response",
    "parse_startup_response",
    "ADMIN_APIS",
    "AdminApi",
    "AdminApiDissector",
    "fingerprint_admin_api",
    "banner_readers",
    "blind_probers",
    "identify_unknown_service",
    "read_volunteered_banner",
    "FaviconCatalog",
    "FaviconEntry",
    "favicon_hash",
    "load_favicon_hashes",
    "murmurhash3_x86_32",
    "validate_favicon_hashes",
    "VersionReading",
    "VERSION_SOURCES",
    "VERSION_SOURCE_QOD",
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
