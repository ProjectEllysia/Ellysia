"""Unit tests for Lybra's own fingerprinting (Fase F): HTTP/SSH dissectors,
raw SSH_MSG_KEXINIT parsing, the HASSH formula, and oracle concordance.

Pure logic + a fake socket for SshProbe — no real network anywhere.
"""

import hashlib
import struct

import pytest

from src.modules.features.themis.lybra import (
    fingerprint_http,
    fingerprint_ssh,
    parse_ssh_banner,
    parse_kexinit,
    compute_hassh_server,
    SshProbe,
    agrees_with_nmap,
    concordance_rate,
)
from src.modules.features.themis.lybra.checks import Response
from src.modules.features.themis.lybra.fingerprint import SSH_MSG_KEXINIT
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.managers import LybraEngineManager

pytestmark = pytest.mark.unit


# ============================================================== HTTP dissector

def test_fingerprint_http_versioned_server_header():
    resp = Response(200, "<html><head><title>Welcome</title></head></html>",
                    {"server": "Apache/2.4.49 (Unix)"})
    fp = fingerprint_http(resp)
    assert fp.product == "Apache"
    assert fp.version == "2.4.49"
    assert fp.title == "Welcome"
    assert fp.confidence == 0.9


def test_fingerprint_http_bare_product_lower_confidence():
    fp = fingerprint_http(Response(200, "<html></html>", {"server": "nginx"}))
    assert fp.product == "nginx" and fp.version is None
    assert fp.confidence == 0.6


def test_fingerprint_http_no_server_header_falls_back_to_signature():
    body = "<html><body>Powered by <script src='/wp-includes/js/x.js'></script></body></html>"
    fp = fingerprint_http(Response(200, body, {}))
    assert "WordPress" in fp.technologies
    assert fp.product == "WordPress"


def test_fingerprint_http_no_signal_zero_confidence():
    fp = fingerprint_http(Response(200, "<html></html>", {}))
    assert fp.product is None and fp.confidence == 0.0


def test_fingerprint_http_favicon_hash_is_sha256_of_bytes():
    favicon = b"\x00\x01\x02fake-icon-bytes"
    fp = fingerprint_http(Response(200, "<html></html>", {}), favicon=favicon)
    assert fp.favicon_hash == hashlib.sha256(favicon).hexdigest()


def test_fingerprint_http_no_favicon_means_no_hash():
    fp = fingerprint_http(Response(200, "<html></html>", {}))
    assert fp.favicon_hash is None


def test_fingerprint_http_vendor_signature_only_on_error_page():
    """The real case that motivated error_body: a SonicWall's homepage says
    only "Server: Web Server", but its 404 page names the vendor."""
    home = Response(302, "<HTML>Page Redirecting</HTML>", {"server": "Web Server"})
    error_404 = Response(404, "<p><span class='server'>SonicWall Server</span></p>", {"server": "Web Server"})

    fp_without_error_page = fingerprint_http(home)
    assert "SonicWall" not in fp_without_error_page.technologies

    fp = fingerprint_http(home, error_resp=error_404)
    assert "SonicWall" in fp.technologies
    # product stays the (unhelpfully generic) header value, not the far more
    # useful signature match — an explicit Server header always wins over an
    # inferred technology name, vague or not. Known, accepted limitation.
    assert fp.product == "Web"


def test_fingerprint_http_vendor_signature_from_body():
    fp = fingerprint_http(Response(200, "<html>MikroTik RouterOS</html>", {}))
    assert "MikroTik RouterOS" in fp.technologies


def test_load_tech_signatures_covers_known_vendors():
    from src.modules.features.themis.lybra import load_tech_signatures
    names = {s.name for s in load_tech_signatures()}
    assert {"WordPress", "SonicWall", "pfSense", "Fortinet FortiGate", "Cisco IOS/ASA"} <= names


# ================================================================ SSH banner

@pytest.mark.parametrize("banner,product,version", [
    ("SSH-2.0-OpenSSH_7.4", "OpenSSH", "7.4"),
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "OpenSSH", "8.9p1"),
    ("SSH-2.0-dropbear_2020.81", "dropbear", "2020.81"),
    ("SSH-2.0-libssh", "libssh", None),
    ("not-an-ssh-banner", None, None),
])
def test_parse_ssh_banner(banner, product, version):
    assert parse_ssh_banner(banner) == (product, version)


# ============================================================== KEXINIT parse

def _namelist(names: list[str]) -> bytes:
    raw = ",".join(names).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def _build_kexinit(**lists: list[str]) -> bytes:
    """Assemble a valid SSH_MSG_KEXINIT payload (RFC 4253 §7.1) from algorithm
    lists, keyed by field name; missing fields default to []."""
    fields = [
        "kex_algorithms", "server_host_key_algorithms",
        "encryption_algorithms_client_to_server", "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server", "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server", "compression_algorithms_server_to_client",
        "languages_client_to_server", "languages_server_to_client",
    ]
    parts = [bytes([SSH_MSG_KEXINIT]), bytes(16)]  # msg code + zeroed cookie
    for field in fields:
        parts.append(_namelist(lists.get(field, [])))
    parts.append(b"\x00")                    # first_kex_packet_follows = false
    parts.append(struct.pack(">I", 0))       # reserved
    return b"".join(parts)


_SAMPLE_KEXINIT = _build_kexinit(
    kex_algorithms=["curve25519-sha256", "diffie-hellman-group14-sha256"],
    server_host_key_algorithms=["ssh-ed25519"],
    encryption_algorithms_client_to_server=["aes128-ctr"],
    encryption_algorithms_server_to_client=["aes128-ctr", "aes256-gcm@openssh.com"],
    mac_algorithms_client_to_server=["hmac-sha2-256"],
    mac_algorithms_server_to_client=["hmac-sha2-256"],
    compression_algorithms_client_to_server=["none"],
    compression_algorithms_server_to_client=["none", "zlib@openssh.com"],
)


def test_parse_kexinit_extracts_all_algorithm_lists():
    parsed = parse_kexinit(_SAMPLE_KEXINIT)
    assert parsed["kex_algorithms"] == ["curve25519-sha256", "diffie-hellman-group14-sha256"]
    assert parsed["server_host_key_algorithms"] == ["ssh-ed25519"]
    assert parsed["encryption_algorithms_server_to_client"] == ["aes128-ctr", "aes256-gcm@openssh.com"]
    assert parsed["compression_algorithms_server_to_client"] == ["none", "zlib@openssh.com"]


def test_parse_kexinit_rejects_wrong_message_code():
    with pytest.raises(ValueError):
        parse_kexinit(bytes([99]) + bytes(16))


def test_parse_kexinit_rejects_empty_payload():
    with pytest.raises(ValueError):
        parse_kexinit(b"")


# ---------------------------------------------------------------- HASSH

def test_compute_hassh_server_matches_the_documented_formula():
    parsed = parse_kexinit(_SAMPLE_KEXINIT)
    expected_material = ";".join([
        "curve25519-sha256,diffie-hellman-group14-sha256",
        "aes128-ctr,aes256-gcm@openssh.com",
        "hmac-sha2-256",
        "none,zlib@openssh.com",
    ])
    expected = hashlib.md5(expected_material.encode()).hexdigest()
    assert compute_hassh_server(parsed) == expected


def test_hassh_differs_when_server_algorithms_differ():
    other = _build_kexinit(
        kex_algorithms=["curve25519-sha256"],
        encryption_algorithms_server_to_client=["chacha20-poly1305@openssh.com"],
        mac_algorithms_server_to_client=["hmac-sha2-256"],
        compression_algorithms_server_to_client=["none"],
    )
    assert compute_hassh_server(parse_kexinit(_SAMPLE_KEXINIT)) != compute_hassh_server(parse_kexinit(other))


def test_fingerprint_ssh_combines_banner_and_hassh():
    fp = fingerprint_ssh("SSH-2.0-OpenSSH_7.4", _SAMPLE_KEXINIT)
    assert fp.product == "OpenSSH" and fp.version == "7.4"
    assert fp.confidence == 0.9
    assert fp.hassh_server == compute_hassh_server(parse_kexinit(_SAMPLE_KEXINIT))
    assert fp.kex_algorithms == ("curve25519-sha256", "diffie-hellman-group14-sha256")


# ============================================================= SshProbe (fake socket)

class _FakeSocket:
    """A byte-stream-backed stand-in for a real SSH socket."""

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


def _frame_ssh_packet(payload: bytes, block_size: int = 8) -> bytes:
    """RFC 4253 §6 binary packet framing (no MAC — pre key-exchange)."""
    unpadded = 1 + len(payload)  # padding_length byte + payload
    padding_length = block_size - (unpadded % block_size)
    if padding_length < 4:
        padding_length += block_size
    body = bytes([padding_length]) + payload + bytes(padding_length)
    return struct.pack(">I", len(body)) + body


def test_ssh_probe_reads_banner_and_kexinit_over_fake_socket():
    stream = b"SSH-2.0-OpenSSH_7.4\r\n" + _frame_ssh_packet(_SAMPLE_KEXINIT)
    fake_sock = _FakeSocket(stream)
    probe = SshProbe(connect=lambda addr, timeout: fake_sock)

    result = probe.fetch("10.0.0.5", 22)

    assert result is not None
    banner, payload = result
    assert banner == "SSH-2.0-OpenSSH_7.4"
    assert payload == _SAMPLE_KEXINIT
    assert fake_sock.sent.startswith(b"SSH-2.0-Lybra_")
    assert fake_sock.closed is True


def test_ssh_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert SshProbe(connect=failing_connect).fetch("10.0.0.5", 22) is None


def test_ssh_probe_returns_none_on_empty_banner():
    probe = SshProbe(connect=lambda addr, timeout: _FakeSocket(b""))
    assert probe.fetch("10.0.0.5", 22) is None


# ================================================================== oracle

def test_agrees_with_nmap_token_overlap_and_version():
    assert agrees_with_nmap("Apache", "2.4.49", "Apache httpd", "2.4.49") is True
    assert agrees_with_nmap("OpenSSH", "7.4", "OpenSSH", "7.4") is True
    assert agrees_with_nmap("nginx", None, "nginx", "1.18") is True   # no version to contradict
    assert agrees_with_nmap("Apache", "2.4.49", "Apache httpd", "2.4.50") is False
    assert agrees_with_nmap("nginx", None, "Apache", None) is False
    assert agrees_with_nmap(None, None, "Apache", "2.4.49") is False


def test_concordance_rate():
    pairs = [
        ("Apache", "2.4.49", "Apache httpd", "2.4.49"),   # agree
        ("nginx", "1.18", "nginx", "1.19"),                # disagree (version)
        ("OpenSSH", "7.4", "OpenSSH", "7.4"),               # agree
    ]
    assert concordance_rate(pairs) == pytest.approx(2 / 3)


def test_concordance_rate_empty_is_zero_not_perfect():
    assert concordance_rate([]) == 0.0


# ================================= _fingerprint_finding title honesty (manager)

def test_fingerprint_finding_reports_agreement_when_nmap_baseline_exists():
    service = Service(port=80, protocol="tcp", name="http", product="Apache httpd", version="2.4.49")
    finding = LybraEngineManager._fingerprint_finding(service, "Apache", "2.4.49", "HTTP")
    assert "concuerda con Nmap" in finding["title"]
    assert "no concuerda" not in finding["title"]


def test_fingerprint_finding_reports_disagreement_when_nmap_baseline_differs():
    service = Service(port=80, protocol="tcp", name="http", product="nginx", version="1.18")
    finding = LybraEngineManager._fingerprint_finding(service, "Apache", "2.4.49", "HTTP")
    assert "no concuerda con Nmap" in finding["title"]


def test_fingerprint_finding_no_nmap_baseline_is_honest_not_a_false_disagreement():
    """Self-discovered services carry no Nmap product/version at all — the
    title must not claim disagreement when there is nothing to compare against."""
    service = Service(port=80, protocol="tcp", name="http", product="", version="")
    finding = LybraEngineManager._fingerprint_finding(service, "Apache", "2.4.49", "HTTP")
    assert "no concuerda" not in finding["title"]
    assert "concuerda con Nmap" not in finding["title"]
    assert "sin datos de Nmap para comparar" in finding["title"]
