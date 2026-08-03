"""Unit tests for Fase N's remaining dissectors: SMTP/IMAP/POP3, SMB, MySQL,
Redis, VNC — plus the dissector registry that replaced the manager's
if/elif chain.

Pure logic + a fake socket, same pattern as ``test_lybra_fingerprint.py``:
no real network anywhere.
"""

import struct

import pytest

from src.modules.features.themis.lybra import (
    parse_smtp_banner,
    fingerprint_smtp,
    fingerprint_imap,
    fingerprint_pop3,
    MailProbe,
    parse_mysql_handshake,
    fingerprint_mysql,
    MysqlProbe,
    parse_redis_info,
    fingerprint_redis,
    RedisProbe,
    parse_rfb_version,
    fingerprint_vnc,
    VncProbe,
    parse_negotiate_response,
    fingerprint_smb,
    SmbProbe,
    default_dissectors,
    is_smtp_service,
    is_imap_service,
    is_pop3_service,
    is_smb_service,
    is_mysql_service,
    is_redis_service,
    is_vnc_service,
)
from src.modules.features.themis.lybra.fingerprinting.smb import (
    build_negotiate_request,
    _DIALECTS,
)
from src.modules.features.themis.lybra.engine import Service

pytestmark = pytest.mark.unit


class _FakeSocket:
    """A byte-stream-backed stand-in for a real socket (shared shape across
    the whole test suite: fixed buffer, ``recv`` drains it, ``sendall``
    records what was written)."""

    def __init__(self, data: bytes):
        self._buf = data
        self.sent = b""
        self.closed = False

    def recv(self, n: int) -> bytes:
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


# ============================================================ SMTP/IMAP/POP3

@pytest.mark.parametrize("banner,product,version", [
    ("220 smtp.example.com ESMTP Exim 4.94.2 Debian", "Exim", "4.94.2"),
    ("220 mail.example.com ESMTP Postfix (Debian/GNU)", None, None),
    ("220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2; Tue, 1 Jan 2030",
     "Sendmail", "8.15.2/8.15.2;".rstrip(";")),
])
def test_parse_smtp_banner(banner, product, version):
    assert parse_smtp_banner(banner) == (product, version)


def test_fingerprint_smtp_versioned_banner_is_high_confidence():
    fp = fingerprint_smtp("220 smtp.example.com ESMTP Exim 4.94.2 Debian")
    assert fp.product == "Exim" and fp.version == "4.94.2"
    assert fp.confidence == 0.9


def test_fingerprint_smtp_postfix_default_banner_yields_nothing():
    # Postfix deliberately omits its version — no CPE should be invented.
    fp = fingerprint_smtp("220 mail.example.com ESMTP Postfix (Debian/GNU)")
    assert fp.product is None and fp.confidence == 0.0


def test_fingerprint_imap_ready_banner_names_product_no_version():
    fp = fingerprint_imap(
        "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR ID ENABLE IDLE] Dovecot ready."
    )
    assert fp.product == "Dovecot" and fp.version is None
    assert fp.confidence == 0.6


def test_fingerprint_pop3_generic_banner_yields_nothing():
    # "server" is the protocol's own generic wording, not a product name.
    fp = fingerprint_pop3("+OK POP3 server ready")
    assert fp.product is None and fp.confidence == 0.0


def test_fingerprint_pop3_product_banner_is_recognised():
    fp = fingerprint_pop3("+OK Dovecot ready.")
    assert fp.product == "Dovecot" and fp.confidence == 0.6


def test_mail_probe_reads_banner_over_fake_socket():
    fake_sock = _FakeSocket(b"220 smtp.example.com ESMTP Exim 4.94.2 Debian\r\n")
    probe = MailProbe(connect=lambda addr, timeout: fake_sock)
    assert probe.fetch("10.0.0.5", 25) == "220 smtp.example.com ESMTP Exim 4.94.2 Debian"
    assert fake_sock.closed is True


def test_mail_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert MailProbe(connect=failing_connect).fetch("10.0.0.5", 25) is None


@pytest.mark.parametrize("service,expected", [
    (Service(25, "tcp", "smtp"), True),
    (Service(587, "tcp", ""), True),
    (Service(80, "tcp", "http"), False),
])
def test_is_smtp_service(service, expected):
    assert is_smtp_service(service) is expected


@pytest.mark.parametrize("service,expected", [
    (Service(143, "tcp", "imap"), True),
    (Service(993, "tcp", ""), True),
    (Service(110, "tcp", "pop3"), False),
])
def test_is_imap_service(service, expected):
    assert is_imap_service(service) is expected


@pytest.mark.parametrize("service,expected", [
    (Service(110, "tcp", "pop3"), True),
    (Service(995, "tcp", ""), True),
    (Service(143, "tcp", "imap"), False),
])
def test_is_pop3_service(service, expected):
    assert is_pop3_service(service) is expected


# ============================================================= MySQL/MariaDB

def _mysql_wire(version_string: bytes) -> bytes:
    """Build a full wire-format MySQL Initial Handshake Packet."""
    payload = bytes([0x0A]) + version_string + b"\x00" + b"\x00" * 13
    header = len(payload).to_bytes(3, "little") + bytes([0])  # length + sequence id
    return header + payload


def test_parse_mysql_handshake_extracts_mysql_version():
    payload = bytes([0x0A]) + b"8.0.34-0ubuntu0.22.04.1\x00" + b"\x00" * 13
    assert parse_mysql_handshake(payload) == ("MySQL", "8.0.34-0ubuntu0.22.04.1")


def test_parse_mysql_handshake_recognises_mariadb_compat_prefix():
    version = b"5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004\x00"
    payload = bytes([0x0A]) + version + b"\x00" * 13
    product, real_version = parse_mysql_handshake(payload)
    assert product == "MariaDB"
    assert real_version == "10.6.12-MariaDB-1:10.6.12+maria~ubu2004"


def test_parse_mysql_handshake_rejects_non_v10_protocol():
    assert parse_mysql_handshake(bytes([0x09]) + b"whatever\x00") == (None, None)


def test_fingerprint_mysql_confidence_reflects_recognition():
    hit = fingerprint_mysql(bytes([0x0A]) + b"8.0.34\x00")
    assert hit.product == "MySQL" and hit.confidence == 0.9

    miss = fingerprint_mysql(b"\x00")
    assert miss.product is None and miss.confidence == 0.0


def test_mysql_probe_reads_handshake_over_fake_socket():
    wire = _mysql_wire(b"8.0.34-0ubuntu0.22.04.1")
    fake_sock = _FakeSocket(wire)
    probe = MysqlProbe(connect=lambda addr, timeout: fake_sock)

    payload = probe.fetch("10.0.0.5", 3306)

    product, version = parse_mysql_handshake(payload)
    assert (product, version) == ("MySQL", "8.0.34-0ubuntu0.22.04.1")
    assert fake_sock.closed is True


def test_mysql_probe_returns_none_on_truncated_payload():
    # Header claims more bytes than actually follow.
    fake_sock = _FakeSocket((100).to_bytes(3, "little") + bytes([0]) + b"short")
    probe = MysqlProbe(connect=lambda addr, timeout: fake_sock)
    assert probe.fetch("10.0.0.5", 3306) is None


@pytest.mark.parametrize("service,expected", [
    (Service(3306, "tcp", "mysql"), True),
    (Service(3307, "tcp", "mysql"), True),
    (Service(5432, "tcp", "postgresql"), False),
])
def test_is_mysql_service(service, expected):
    assert is_mysql_service(service) is expected


# ==================================================================== Redis

def test_parse_redis_info_extracts_version():
    reply = "$120\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n"
    assert parse_redis_info(reply) == "7.0.11"


def test_parse_redis_info_no_auth_response_yields_nothing():
    assert parse_redis_info("-NOAUTH Authentication required.\r\n") is None


def test_fingerprint_redis_confidence_reflects_recognition():
    hit = fingerprint_redis("redis_version:7.0.11\r\n")
    assert hit.product == "Redis" and hit.version == "7.0.11" and hit.confidence == 0.9

    miss = fingerprint_redis("-NOAUTH Authentication required.\r\n")
    assert miss.product is None and miss.confidence == 0.0


def test_redis_probe_sends_info_and_reads_reply():
    fake_sock = _FakeSocket(b"$40\r\n# Server\r\nredis_version:7.0.11\r\n")
    probe = RedisProbe(connect=lambda addr, timeout: fake_sock)

    reply = probe.fetch("10.0.0.5", 6379)

    assert fake_sock.sent == b"INFO\r\n"
    assert "redis_version:7.0.11" in reply
    assert fake_sock.closed is True


def test_redis_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert RedisProbe(connect=failing_connect).fetch("10.0.0.5", 6379) is None


@pytest.mark.parametrize("service,expected", [
    (Service(6379, "tcp", "redis"), True),
    (Service(6380, "tcp", "redis"), True),
    (Service(27017, "tcp", "mongodb"), False),
])
def test_is_redis_service(service, expected):
    assert is_redis_service(service) is expected


# ======================================================================= VNC

@pytest.mark.parametrize("banner,version", [
    (b"RFB 003.008\n", "3.8"),
    (b"RFB 003.003\n", "3.3"),
    (b"SSH-2.0-OpenSSH_7.4\r\n", None),
    (b"", None),
])
def test_parse_rfb_version(banner, version):
    assert parse_rfb_version(banner) == version


def test_fingerprint_vnc_recognised_banner():
    fp = fingerprint_vnc(b"RFB 003.008\n")
    assert fp.version == "3.8" and fp.confidence == 0.9
    assert "VNC" in fp.product


def test_vnc_probe_reads_banner_over_fake_socket():
    fake_sock = _FakeSocket(b"RFB 003.008\n")
    probe = VncProbe(connect=lambda addr, timeout: fake_sock)
    assert probe.fetch("10.0.0.5", 5900) == b"RFB 003.008\n"
    assert fake_sock.closed is True


@pytest.mark.parametrize("service,expected", [
    (Service(5900, "tcp", "vnc"), True),
    (Service(5901, "tcp", "vnc"), True),
    (Service(3389, "tcp", "ms-wbt-server"), False),
])
def test_is_vnc_service(service, expected):
    assert is_vnc_service(service) is expected


# ======================================================================= SMB

def _smb2_response_wire(dialect_revision: int, security_mode: int) -> bytes:
    """Build a full NetBIOS-wrapped SMB2 NEGOTIATE response, independent of
    the production request builder — see MS-SMB2 §2.2.1.1 / §2.2.4 for the
    offsets this hand-transcribes."""
    header = b"".join([
        b"\xfeSMB",                       # ProtocolId
        struct.pack("<H", 64),            # StructureSize
        struct.pack("<H", 0),             # CreditCharge
        struct.pack("<I", 0),             # Status
        struct.pack("<H", 0x0000),        # Command = NEGOTIATE
        struct.pack("<H", 1),             # CreditResponse
        struct.pack("<I", 0x00000001),    # Flags (SERVER_TO_REDIR set on responses)
        struct.pack("<I", 0),             # NextCommand
        struct.pack("<Q", 0),             # MessageId
        struct.pack("<I", 0),             # Reserved
        struct.pack("<I", 0),             # TreeId
        struct.pack("<Q", 0),             # SessionId
        b"\x00" * 16,                     # Signature
    ])
    body = b"".join([
        struct.pack("<H", 65),                    # StructureSize
        struct.pack("<H", security_mode),          # SecurityMode
        struct.pack("<H", dialect_revision),       # DialectRevision
    ])
    message = header + body
    netbios_header = bytes([0x00]) + len(message).to_bytes(3, "big")
    return netbios_header + message


def test_build_negotiate_request_wire_length_matches_dialect_count():
    wire = build_negotiate_request()
    # 4-byte NetBIOS header + 64-byte SMB2 header + 36-byte fixed body + 2 bytes/dialect.
    assert len(wire) == 4 + 64 + 36 + 2 * len(_DIALECTS)
    assert wire[4:8] == b"\xfeSMB"


def test_parse_negotiate_response_extracts_dialect_and_security_mode():
    wire = _smb2_response_wire(0x0302, 0x0003)
    message = wire[4:]  # strip the NetBIOS wrapper, same as SmbProbe.fetch does
    assert parse_negotiate_response(message) == (0x0302, 0x0003)


def test_parse_negotiate_response_rejects_wrong_protocol_id():
    assert parse_negotiate_response(b"\x00" * 80) is None


def test_parse_negotiate_response_rejects_too_short_message():
    assert parse_negotiate_response(b"\xfeSMB" + b"\x00" * 10) is None


def test_fingerprint_smb_flags_signing_not_required():
    fp = fingerprint_smb(0x0302, 0x0001)  # SIGNING_ENABLED only, not REQUIRED
    assert fp.version == "3.0.2"
    assert "firma no requerida" in fp.product


def test_fingerprint_smb_signing_required_is_plain_label():
    fp = fingerprint_smb(0x0210, 0x0003)  # ENABLED + REQUIRED
    assert fp.version == "2.1"
    assert fp.product == "SMB2"


def test_fingerprint_smb_unrecognised_dialect_yields_nothing():
    fp = fingerprint_smb(0x02FF, 0x0000)  # the SMB2 wildcard, never a real dialect
    assert fp.product is None and fp.confidence == 0.0


def test_smb_probe_negotiates_and_parses_response_over_fake_socket():
    wire = _smb2_response_wire(0x0302, 0x0001)
    fake_sock = _FakeSocket(wire)
    probe = SmbProbe(connect=lambda addr, timeout: fake_sock)

    result = probe.fetch("10.0.0.5", 445)

    assert result == (0x0302, 0x0001)
    assert fake_sock.sent[4:8] == b"\xfeSMB"   # the request itself was sent
    assert fake_sock.closed is True


def test_smb_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert SmbProbe(connect=failing_connect).fetch("10.0.0.5", 445) is None


@pytest.mark.parametrize("service,expected", [
    (Service(445, "tcp", "microsoft-ds"), True),
    (Service(139, "tcp", ""), True),
    (Service(3389, "tcp", "ms-wbt-server"), False),
])
def test_is_smb_service(service, expected):
    assert is_smb_service(service) is expected


# ============================================================== the registry

def test_default_dissectors_each_service_selects_exactly_one():
    """The refactor's whole point: for a batch of mixed services, exactly one
    dissector should claim each one — proving the registry replaced the
    if/elif chain without losing (or duplicating) any protocol's selectivity."""
    dissectors = default_dissectors()
    labels_by_service = {
        Service(80, "tcp", "http"): "HTTP",
        Service(22, "tcp", "ssh"): "SSH",
        Service(21, "tcp", "ftp"): "FTP",
        Service(25, "tcp", "smtp"): "SMTP",
        Service(143, "tcp", "imap"): "IMAP",
        Service(110, "tcp", "pop3"): "POP3",
        Service(445, "tcp", "microsoft-ds"): "SMB",
        Service(3306, "tcp", "mysql"): "MySQL",
        Service(6379, "tcp", "redis"): "Redis",
        Service(5900, "tcp", "vnc"): "VNC",
    }
    for service, expected_label in labels_by_service.items():
        matches = [d for d in dissectors if d.applies(service)]
        assert len(matches) == 1, f"{service} matched {[m.label for m in matches]}, expected exactly [{expected_label}]"
        assert matches[0].label == expected_label


def test_default_dissectors_unrecognised_service_matches_nothing():
    unknown = Service(31337, "tcp", "some-unknown-thing")
    assert not [d for d in default_dissectors() if d.applies(unknown)]
