"""Unit tests for Lybra's own fingerprinting (Fase F): HTTP/SSH/FTP dissectors,
raw SSH_MSG_KEXINIT parsing y la fórmula HASSH.

La aritmética de la concordancia con Nmap ya no se prueba aquí: se fue al arnés
de medición (``tests/oracle/test_concordance_metrics.py``) con el código que
ejercita, en L52.

Pure logic + a fake socket for SshProbe/FtpProbe — no real network anywhere.
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
    parse_ftp_banner,
    fingerprint_ftp,
    FtpProbe,
)
from src.modules.features.themis.lybra.fingerprinting.dispatch import (
    DissectorResult,
    QOD_FINGERPRINT,
)
from src.modules.features.themis.lybra.checks import Response
from src.modules.features.themis.lybra.fingerprinting.ssh import SSH_MSG_KEXINIT
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


# =============================================== versión capturada por firma
#
# L19: una firma identificaba **nombres** y ahí se paraba. Sin versión no hay
# CPE, y sin CPE no hay ni un CVE — así que un WordPress reconocido sin
# versión era un dato de inventario, no una detección.


def test_a_signature_captures_the_version_from_the_generator_meta():
    body = (
        '<html><head><meta name="generator" content="WordPress 6.4.2" />'
        "<title>Blog</title></head><body>wp-content</body></html>"
    )
    fp = fingerprint_http(Response(200, body, {}))
    assert fp.product == "WordPress"
    assert fp.version == "6.4.2"
    # La confianza es la del nivel del que salió (L18): un `<meta generator>`
    # es evidencia explícita pero la pone la aplicación, no el servidor, así
    # que va un escalón por debajo de una cabecera `Server` completa.
    assert fp.confidence == 0.8
    assert fp.version_source == "meta-generator"


def test_a_signature_without_a_captured_version_still_names_the_product():
    # La regla que separa esto de inventar CPEs: reconocer el producto no
    # autoriza a fabricar una versión.
    fp = fingerprint_http(Response(200, "<html>MikroTik RouterOS</html>", {}))
    assert fp.product == "MikroTik RouterOS"
    assert fp.version is None
    assert fp.confidence == 0.6


def test_a_signature_version_never_lands_on_another_products_name():
    """El error que este mecanismo podría introducir, y que no introduce.

    Un WordPress servido detrás de un nginx tiene dos identidades: la cabecera
    `Server` habla del proxy, el `<meta generator>` habla de la aplicación.
    Pegar la versión de uno al nombre del otro produciría `nginx 6.4.2` — un
    CPE que no existe, y una búsqueda de CVEs de un producto que no está ahí.
    """
    body = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head>'            "<body>wp-content</body></html>"
    fp = fingerprint_http(Response(200, body, {"server": "nginx/1.24.0"}))
    assert (fp.product, fp.version) == ("nginx", "1.24.0")
    assert "WordPress" in fp.technologies


def test_a_signature_captures_the_version_from_a_header():
    fp = fingerprint_http(Response(200, "<html>Dashboard [Jenkins]</html>",
                                   {"x-jenkins": "2.426.3"}))
    assert fp.product == "Jenkins"
    assert fp.version == "2.426.3"


def test_a_version_pattern_that_does_not_capture_leaves_the_version_alone():
    # La firma casa por su matcher de palabras, pero el patrón de versión no
    # encuentra nada en esa parte: producto sí, versión no.
    body = "<html><head><title>Blog</title></head><body>wp-content</body></html>"
    fp = fingerprint_http(Response(200, body, {}))
    assert fp.product == "WordPress"
    assert fp.version is None


def test_the_bundled_signature_feed_is_well_formed():
    """Mismo criterio que ``test_lybra_feed_shape`` aplica al feed de checks: el
    modo de fallo de un feed de datos es el silencio. Una firma sin matchers no
    casa nunca y un ``versionPattern`` sin grupo ``version`` casa sin aportar
    nada; en los dos casos el escaneo termina en verde con un producto menos."""
    from src.modules.features.themis.lybra import (
        load_tech_signatures, validate_tech_signatures,
    )
    signatures = load_tech_signatures()
    assert validate_tech_signatures(signatures) == []
    # El criterio de cierre del issue: al menos 30 productos cubiertos.
    assert len(signatures) >= 30


def test_the_signature_validator_finds_each_kind_of_breakage():
    """Sin este bloque, un validador que devolviera siempre `[]` dejaría el
    test de arriba en verde para siempre."""
    import re

    from src.modules.features.themis.lybra import (
        TechMatcher, TechSignature, validate_tech_signatures,
    )

    no_matchers = TechSignature(name="Vacía", matchers=())
    no_name = TechSignature(name="", matchers=(TechMatcher("body", ("x",)),))
    bad_group = TechSignature(
        name="SinGrupo",
        matchers=(TechMatcher("body", ("x",), re.compile(r"v([\d.]+)")),),
    )
    no_words = TechSignature(name="SinPalabras", matchers=(TechMatcher("body", ()),))
    duplicated = [TechSignature(name="Doble", matchers=(TechMatcher("body", ("x",)),))] * 2

    assert len(validate_tech_signatures([no_matchers])) == 1
    assert len(validate_tech_signatures([no_name])) == 1
    assert len(validate_tech_signatures([bad_group])) == 1
    assert len(validate_tech_signatures([no_words])) == 1
    assert len(validate_tech_signatures(duplicated)) == 1


# ================================================ cascada de versión (L18)
#
# La versión salía de una sola fuente, la cabecera `Server`. Y `server_tokens
# off` en nginx, `ServerTokens Prod` en Apache y cualquier CDN o WAF la
# suprimen, así que el caso más común en producción era justo el que dejaba al
# motor sin versión — luego sin CPE, luego sin un solo CVE.
#
# Un test por nivel de la cascada, más los dos que la protegen: que el orden de
# preferencia se respeta, y que sin ninguna señal no se inventa nada.


def test_version_cascade_level_1_server_header():
    fp = fingerprint_http(Response(200, "<html></html>", {"server": "Apache/2.4.49 (Unix)"}))
    assert (fp.product, fp.version) == ("Apache", "2.4.49")
    assert fp.version_source == "server-header"
    assert fp.confidence == 0.9


def test_version_cascade_level_2_powered_by_headers():
    """El docstring del paquete prometía leer `X-Powered-By` desde el principio;
    el código sólo miraba `Server`."""
    php = fingerprint_http(Response(200, "<html></html>", {"x-powered-by": "PHP/8.1.2"}))
    assert (php.product, php.version) == ("PHP", "8.1.2")
    assert php.version_source == "powered-by-header"
    assert php.confidence == 0.85

    # X-AspNet-Version es el caso raro: su valor es la versión desnuda, sin
    # nombre, así que el producto lo pone la cabecera misma.
    aspnet = fingerprint_http(Response(200, "<html></html>",
                                       {"x-aspnet-version": "4.0.30319"}))
    assert (aspnet.product, aspnet.version) == ("ASP.NET", "4.0.30319")


def test_version_cascade_level_3_meta_generator():
    body = '<html><head><meta content="Joomla! 4.3.1" name="generator" /></head></html>'
    fp = fingerprint_http(Response(200, body, {}))
    # El "!" de "Joomla!" se queda fuera: el nombre del producto se recorta a
    # caracteres de identificador, que es la forma en la que hay que buscarlo
    # en NVD (`joomla`), no la de su logotipo.
    assert (fp.product, fp.version) == ("Joomla", "4.3.1")
    assert fp.version_source == "meta-generator"
    assert fp.confidence == 0.8


def test_version_cascade_level_4_feed_signature_pattern():
    fp = fingerprint_http(Response(200, "<html>Dashboard [Jenkins]</html>",
                                   {"x-jenkins": "2.426.3"}))
    assert (fp.product, fp.version) == ("Jenkins", "2.426.3")
    assert fp.version_source == "tech-signature"
    assert fp.confidence == 0.75


def test_version_cascade_level_5_default_error_page():
    """El motor ya se descarga la página de error para las firmas de fabricante
    y no la miraba para versión. Es la respuesta al punto ciego del banco: un
    nginx con `server_tokens off` sigue firmando su 404."""
    home = Response(200, "<html>Bienvenido</html>", {})
    error = Response(404, "<hr><center>nginx/1.24.0</center></body></html>", {})
    fp = fingerprint_http(home, error_resp=error)
    assert (fp.product, fp.version) == ("nginx", "1.24.0")
    assert fp.version_source == "error-page"
    assert fp.confidence == 0.6


def test_version_cascade_level_6_repeated_asset_version():
    """El último nivel, y el único que exige una condición extra: la misma
    versión repetida en varios assets. Sólo completa un producto ya
    identificado por otra vía — aquí, por la firma de WordPress."""
    body = (
        "<html><body>wp-content"
        "<script src='/wp-includes/js/a.js?ver=6.4.2'></script>"
        "<script src='/wp-includes/js/b.js?ver=6.4.2'></script>"
        "</body></html>"
    )
    fp = fingerprint_http(Response(200, body, {}))
    assert (fp.product, fp.version) == ("WordPress", "6.4.2")
    assert fp.version_source == "asset-path"


def test_a_single_asset_version_is_not_taken_for_the_products_version():
    """La condición que hace utilizable el último nivel.

    Un `?ver=` suelto es casi siempre la versión de *ese* fichero —una librería
    de terceros, un plugin— y no la de la aplicación. Tomarlo por bueno daría
    un CPE de WordPress con la versión de jQuery: peor que no dar versión.
    """
    body = (
        "<html><body>wp-content"
        "<script src='/wp-includes/js/jquery.min.js?ver=3.7.1'></script>"
        "</body></html>"
    )
    fp = fingerprint_http(Response(200, body, {}))
    assert fp.product == "WordPress"
    assert fp.version is None
    assert fp.version_source is None


def test_two_different_repeated_asset_versions_are_ambiguous_so_nothing_is_claimed():
    body = (
        "<html><body>wp-content"
        "<script src='/a.js?ver=6.4.2'></script><script src='/b.js?ver=6.4.2'></script>"
        "<script src='/c.js?ver=3.7.1'></script><script src='/d.js?ver=3.7.1'></script>"
        "</body></html>"
    )
    fp = fingerprint_http(Response(200, body, {}))
    assert fp.version is None


def test_the_cascade_respects_its_order_of_preference():
    """Con varias señales a la vez gana la más explícita, no la última leída."""
    body = (
        '<html><head><meta name="generator" content="WordPress 6.4.2" /></head>'
        "<body>wp-content</body></html>"
    )
    error = Response(404, "<center>nginx/1.24.0</center>", {})
    fp = fingerprint_http(
        Response(200, body, {"server": "Apache/2.4.49", "x-powered-by": "PHP/8.1.2"}),
        error_resp=error,
    )
    assert (fp.product, fp.version) == ("Apache", "2.4.49")
    assert fp.version_source == "server-header"


def test_the_cascade_never_invents_a_version_when_no_source_has_one():
    fp = fingerprint_http(Response(200, "<html>MikroTik RouterOS</html>", {}))
    assert fp.product == "MikroTik RouterOS"
    assert fp.version is None
    assert fp.version_source is None


def test_every_declared_version_source_has_a_confidence_and_a_qod():
    """Añadir un nivel a la cascada obliga a decidir las dos cosas que un nivel
    significa: cuánta confianza da y qué `qod` produce. Sin este test, un nivel
    nuevo se colaría con `qod` por defecto y confianza cero."""
    from src.modules.features.themis.lybra.fingerprinting.http import (
        VERSION_SOURCES, VERSION_SOURCE_QOD, _SOURCE_CONFIDENCE,
    )
    assert set(VERSION_SOURCES) == set(_SOURCE_CONFIDENCE)
    assert set(VERSION_SOURCES) == set(VERSION_SOURCE_QOD)


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


# ============================================================== FTP dissector

def test_parse_ftp_banner_vsftpd_parenthesised_form():
    product, version = parse_ftp_banner("220 (vsFTPd 2.3.4)")
    assert (product, version) == ("vsFTPd", "2.3.4")


def test_parse_ftp_banner_proftpd_bare_form():
    product, version = parse_ftp_banner(
        "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]"
    )
    assert (product, version) == ("ProFTPD", "1.3.5")


def test_parse_ftp_banner_filezilla_two_word_product():
    product, version = parse_ftp_banner("220-FileZilla Server 0.9.60beta")
    assert (product, version) == ("FileZilla Server", "0.9.60beta")


def test_parse_ftp_banner_debian_proftpd_without_version():
    """L48-a: el saludo por defecto de ProFTPD en Debian nombra el producto y
    calla la versión. Es el caso que se midió en real y que daba `None`
    mientras Nmap leía `ProFTPD` del mismo saludo."""
    banner = "220 ProFTPD Server (Debian) [::ffff:203.0.113.10]"
    assert parse_ftp_banner(banner) == ("ProFTPD", None)


def test_parse_ftp_banner_versionless_pureftpd_names_the_product():
    # Pure-FTPd suprime su versión por defecto. El producto sí está escrito en
    # el saludo, así que reconocerlo no es inventarlo; la versión sigue sin
    # fabricarse, que es lo que la regla del proyecto prohíbe.
    banner = "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------"
    assert parse_ftp_banner(banner) == ("Pure-FTPd", None)


def test_parse_ftp_banner_versionless_iis_names_the_product():
    assert parse_ftp_banner("220 Microsoft FTP Service") == ("Microsoft FTP Service", None)


def test_parse_ftp_banner_a_version_always_wins_over_the_name_table():
    # El saludo nombra ProFTPD y además trae la versión: gana el patrón con
    # versión, no la tabla de nombres.
    banner = "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]"
    assert parse_ftp_banner(banner) == ("ProFTPD", "1.3.5")


def test_parse_ftp_banner_unknown_daemon_is_not_guessed():
    # El caso importante de la tabla: un saludo personalizado que no nombra
    # ningún demonio conocido no produce producto. Sin esto, la tabla sería
    # una heurística disfrazada.
    banner = "220 Bienvenido al servidor de ficheros de la empresa."
    assert parse_ftp_banner(banner) == (None, None)


def test_parse_ftp_banner_rejects_non_220_lines():
    assert parse_ftp_banner("530 Login incorrect.") == (None, None)
    assert parse_ftp_banner("") == (None, None)


def test_fingerprint_ftp_confidence_reflects_whether_a_version_was_found():
    hit = fingerprint_ftp("220 (vsFTPd 2.3.4)")
    assert hit.product == "vsFTPd" and hit.version == "2.3.4" and hit.confidence == 0.9

    named_only = fingerprint_ftp("220 ProFTPD Server (Debian) [::ffff:10.0.0.1]")
    assert named_only.product == "ProFTPD"
    assert named_only.version is None and named_only.confidence == 0.6

    miss = fingerprint_ftp("220 Service ready.")
    assert miss.product is None and miss.confidence == 0.0


# =============================================================== FTP probe

def test_ftp_probe_reads_banner_over_fake_socket():
    fake_sock = _FakeSocket(b"220 (vsFTPd 2.3.4)\r\n")
    probe = FtpProbe(connect=lambda addr, timeout: fake_sock)

    banner = probe.fetch("10.0.0.5", 21)

    assert banner == "220 (vsFTPd 2.3.4)"
    assert fake_sock.closed is True


def test_ftp_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert FtpProbe(connect=failing_connect).fetch("10.0.0.5", 21) is None


def test_ftp_probe_returns_none_on_empty_banner():
    probe = FtpProbe(connect=lambda addr, timeout: _FakeSocket(b""))
    assert probe.fetch("10.0.0.5", 21) is None


# ============================== _fingerprint_finding: qué vio Lybra (manager)

def test_fingerprint_finding_states_what_lybra_read():
    """El título es una constatación, no un veredicto sobre otra herramienta.

    Hasta L52 decía "concuerda / no concuerda con Nmap": convertía un dato
    propio en una nota al pie sobre el escáner al que el motor estaba
    subordinado. Ese modo de arranque ya no existe.
    """
    service = Service(port=80, protocol="tcp", name="http", product="", version="")
    result = DissectorResult("Apache", "2.4.49", "HTTP")
    finding = LybraEngineManager._fingerprint_finding(service, result)
    assert finding["title"] == "Fingerprint propio (HTTP): Apache 2.4.49"
    assert "Nmap" not in finding["title"]


def test_fingerprint_finding_carries_the_qod_the_dissector_assigned():
    """L18: el `qod` era una constante para todos los fingerprints, así que una
    versión leída de un `Server` explícito y otra deducida de una página de
    error valían exactamente lo mismo. Ahora cada lectura dice cuánto se fía de
    sí misma; un dissector que no distinga sigue con la constante de siempre."""
    service = Service(port=80, protocol="tcp", name="http", product="", version="")
    from_header = LybraEngineManager._fingerprint_finding(
        service, DissectorResult("Apache", "2.4.49", "HTTP", qod=90))
    from_error_page = LybraEngineManager._fingerprint_finding(
        service, DissectorResult("Apache", "2.4.49", "HTTP", qod=60))
    plain = LybraEngineManager._fingerprint_finding(
        service, DissectorResult("vsFTPd", "3.0.5", "FTP"))
    assert from_header["qod"] == 90
    assert from_error_page["qod"] == 60
    assert plain["qod"] == QOD_FINGERPRINT


def test_fingerprint_finding_never_mentions_nmap_even_with_a_prior_reading():
    """Un servicio puede llegar con producto ya puesto (payload externo de
    Hygeia, por ejemplo). Ni siquiera entonces el título compara con nada."""
    service = Service(port=80, protocol="tcp", name="http", product="nginx", version="1.18")
    finding = LybraEngineManager._fingerprint_finding(
        service, DissectorResult("Apache", "2.4.49", "HTTP"))
    assert finding["title"] == "Fingerprint propio (HTTP): Apache 2.4.49"
