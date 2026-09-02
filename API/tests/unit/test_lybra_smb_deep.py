"""SMB más allá del NEGOTIATE: SMBv1, identidad del activo y versión (L11).

El dissector de SMB leía dialecto y modo de firma, y ahí se acababa. Faltaban
tres datos que el propio protocolo ofrece **sin autenticar**, y cada uno tiene
aquí su bloque:

- si **SMBv1** sigue habilitado, que el saludo de SMB2 no puede ver;
- el **nombre de equipo y el dominio**, que llegan en el ``SESSION_SETUP``;
- la **versión de sistema**, cuando el servidor la declara.
"""

import struct

import pytest

from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.smb import (
    AV_PAIR_NAMES,
    NTLM_CHALLENGE,
    NTLM_NEGOTIATE,
    NTLM_SIGNATURE,
    SMB1_DIALECT,
    SmbDissector,
    SmbProbe,
    _label_with_identity,
    build_negotiate_request,
    build_ntlm_negotiate,
    build_session_setup_request,
    build_smb1_negotiate,
    fingerprint_smb,
    parse_ntlm_challenge,
    parse_smb1_negotiate_response,
)

pytestmark = pytest.mark.unit

_SMB1_HEADER_LEN = 32


def _smb1_header(command=0x72, status=0):
    return b"".join([
        b"\xffSMB", bytes((command,)), struct.pack("<I", status),
        bytes((0x98,)), struct.pack("<H", 0xC853), struct.pack("<H", 0),
        b"\x00" * 8, struct.pack("<H", 0), struct.pack("<H", 0),
        struct.pack("<H", 0xFEFF), struct.pack("<H", 0), struct.pack("<H", 0),
    ])


def _smb1_negotiate_reply(dialect_index=0, status=0, command=0x72, word_count=17):
    body = bytes((word_count,)) + struct.pack("<H", dialect_index) + b"\x00" * 30
    return _smb1_header(command, status) + body


def _av_pairs(pairs):
    block = b""
    for av_id, value in pairs:
        encoded = value.encode("utf-16-le")
        block += struct.pack("<HH", av_id, len(encoded)) + encoded
    return block + struct.pack("<HH", 0, 0)


def _ntlm_challenge(pairs=(), major=10, minor=0, build=19041, prefix=b""):
    """Un NTLM CHALLENGE con su bloque de información de destino."""
    target_info = _av_pairs(pairs)
    header_size = 56
    head = b"".join([
        NTLM_SIGNATURE,
        struct.pack("<I", NTLM_CHALLENGE),
        struct.pack("<HHI", 0, 0, header_size),          # TargetNameFields
        struct.pack("<I", 0x00080205),                    # NegotiateFlags
        b"\x00" * 8,                                      # ServerChallenge
        b"\x00" * 8,                                      # Reserved
        struct.pack("<HHI", len(target_info), len(target_info), header_size),
        struct.pack("<BBH", major, minor, build) + b"\x00\x00\x00\x0f",
    ])
    return prefix + head + target_info


# ================================================== SMBv1: el otro protocolo


def test_the_smb1_negotiate_starts_with_the_other_protocol_id():
    """Un solo bit de diferencia entre las dos cabeceras —0xFF frente a
    0xFE— y toda una década de vulnerabilidades."""
    request = build_smb1_negotiate()
    assert request[4:8] == b"\xffSMB"
    assert build_negotiate_request()[4:8] == b"\xfeSMB"


def test_the_smb1_negotiate_declares_its_length_and_offers_the_legacy_dialect():
    request = build_smb1_negotiate()
    assert int.from_bytes(request[1:4], "big") == len(request) - 4
    assert SMB1_DIALECT in request


def test_a_server_that_picks_a_dialect_proves_smb1_is_enabled():
    assert parse_smb1_negotiate_response(_smb1_negotiate_reply(dialect_index=0)) is True


@pytest.mark.parametrize("reply, why", [
    (b"", "silencio"),
    (b"\xfeSMB" + b"\x00" * 60, "una respuesta de SMB2"),
    (_smb1_negotiate_reply(status=0xC0000022), "un error"),
    (_smb1_negotiate_reply(dialect_index=0xFFFF), "ningun dialecto aceptado"),
    (_smb1_negotiate_reply(word_count=0), "una respuesta sin cuerpo"),
    (_smb1_negotiate_reply(command=0x73), "otro comando"),
])
def test_only_an_explicit_acceptance_counts_as_smb1_enabled(reply, why):
    """La garantía que evita el falso positivo: un servidor que **no** habla
    SMB1 no tiene por qué contestar de ninguna forma concreta, así que
    cualquier cosa que no sea una aceptación explícita es un no."""
    assert parse_smb1_negotiate_response(reply) is False, why


# ======================================= identidad: nombre de equipo y dominio


def test_the_ntlm_negotiate_carries_no_credentials():
    """Es el mensaje de tipo 1: declara qué sabe hacer el cliente y pide el
    bloque de destino. El usuario y la contraseña irían en el de tipo 3, que
    este módulo nunca construye."""
    message = build_ntlm_negotiate()
    assert message.startswith(NTLM_SIGNATURE)
    assert struct.unpack_from("<I", message, 8)[0] == NTLM_NEGOTIATE
    assert len(message) == 40
    # Los campos de dominio y estación de trabajo van vacíos.
    assert message[16:32] == b"\x00" * 16


def test_the_session_setup_points_its_security_buffer_at_the_token():
    token = build_ntlm_negotiate()
    request = build_session_setup_request(token)
    # StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) +
    # Channel(4) deja el par offset/length en el byte 12 del cuerpo.
    offset, length = struct.unpack_from("<HH", request, 4 + 64 + 12)
    assert length == len(token)
    # El desplazamiento es relativo al principio del mensaje SMB2, no del
    # paquete: hay que sumarle los cuatro bytes de NetBIOS para indexar aquí.
    assert request[4 + offset:4 + offset + length] == token


def test_the_challenge_yields_the_hostname_and_the_domain():
    challenge = _ntlm_challenge([(1, "WIN-SRV01"), (2, "CORP")])
    identity = parse_ntlm_challenge(challenge)
    assert identity["netbios_computer_name"] == "WIN-SRV01"
    assert identity["netbios_domain_name"] == "CORP"


def test_the_challenge_yields_the_dns_names_too():
    challenge = _ntlm_challenge([
        (3, "win-srv01.corp.empresa.com"), (4, "corp.empresa.com"),
    ])
    identity = parse_ntlm_challenge(challenge)
    assert identity["dns_computer_name"] == "win-srv01.corp.empresa.com"
    assert identity["dns_domain_name"] == "corp.empresa.com"


def test_the_challenge_is_found_wherever_it_sits_in_the_response():
    """El lector busca la firma NTLMSSP dentro del buffer en vez de fiarse de
    un desplazamiento fijo, así que da igual cuánta cabecera SMB2 haya delante
    y da igual que el token venga envuelto en SPNEGO."""
    wrapped = _ntlm_challenge([(1, "WIN-SRV01")], prefix=b"\xfeSMB" + b"\x00" * 120)
    assert parse_ntlm_challenge(wrapped)["netbios_computer_name"] == "WIN-SRV01"


def test_an_unknown_av_pair_id_is_skipped_without_losing_the_rest():
    challenge = _ntlm_challenge([(1, "WIN-SRV01"), (7, "algo raro"), (2, "CORP")])
    identity = parse_ntlm_challenge(challenge)
    assert identity["netbios_computer_name"] == "WIN-SRV01"
    assert identity["netbios_domain_name"] == "CORP"


@pytest.mark.parametrize("data", [
    b"",
    b"sin firma ninguna",
    NTLM_SIGNATURE + struct.pack("<I", NTLM_NEGOTIATE) + b"\x00" * 60,   # tipo 1
    NTLM_SIGNATURE + b"\x00" * 8,                                         # truncado
])
def test_a_response_without_a_readable_challenge_yields_nothing(data):
    assert parse_ntlm_challenge(data) == {}


def test_a_truncated_av_pair_block_keeps_what_was_read_before_it():
    challenge = _ntlm_challenge([(1, "WIN-SRV01")])
    identity = parse_ntlm_challenge(challenge[:-4])
    assert identity.get("netbios_computer_name") in (None, "WIN-SRV01")


# =============================================== la versión que el servidor da


def test_the_os_version_is_read_when_the_server_declares_one():
    identity = parse_ntlm_challenge(_ntlm_challenge(major=10, minor=0, build=19041))
    assert identity["os_version"] == "10.0.19041"


def test_a_build_of_zero_means_the_server_did_not_fill_the_field():
    """Un `build` a cero no es la versión 6.1.0: es el campo sin rellenar. Se
    calla en vez de reportar un número que nadie declaró."""
    assert "os_version" not in parse_ntlm_challenge(_ntlm_challenge(build=0))


def test_the_os_version_never_becomes_a_product():
    """Samba rellena ese campo emulando una versión de Windows, así que deducir
    el fabricante de ahí sería inventarlo. Se reporta como hecho observado y no
    toca `product`."""
    identity = parse_ntlm_challenge(_ntlm_challenge(major=6, minor=1, build=7601))
    fingerprint = fingerprint_smb(0x0302, 0x0003, identity)
    assert fingerprint.os_version == "6.1.7601"
    assert fingerprint.product == "SMB2"
    assert "Windows" not in (fingerprint.product or "")


# ================================================ el fingerprint y la etiqueta


def test_the_fingerprint_carries_the_identity_it_read():
    identity = parse_ntlm_challenge(_ntlm_challenge([
        (1, "WIN-SRV01"), (2, "CORP"), (3, "win-srv01.corp.local"),
    ]))
    fingerprint = fingerprint_smb(0x0302, 0x0003, identity, speaks_smb1=True)
    assert fingerprint.hostname == "WIN-SRV01"
    assert fingerprint.domain == "CORP"
    assert fingerprint.dns_name == "win-srv01.corp.local"
    assert fingerprint.speaks_smb1 is True
    assert fingerprint.version == "3.0.2"


def test_an_unrecognised_dialect_still_yields_nothing():
    """La garantía de antes no se pierde: una respuesta que no se entiende no
    es prueba de nada, y en particular no lo es de que la firma no se exija."""
    assert fingerprint_smb(0x02FF, 0x0000, {"netbios_computer_name": "X"}).product is None


@pytest.mark.parametrize("hostname, domain, expected", [
    ("WIN-SRV01", "CORP", "SMB en WIN-SRV01 (CORP)"),
    ("WIN-SRV01", None, "SMB en WIN-SRV01"),
    (None, "CORP", "SMB en CORP"),
    (None, None, "SMB"),
])
def test_the_label_carries_the_asset_identity_to_the_finding_title(hostname, domain, expected):
    """Nombre de equipo y dominio no caben en product/version —esos dos campos
    alimentan la resolución de un CPE— pero sí merecen llegar al título del
    hallazgo, que es lo que alguien lee en el informe."""
    fingerprint = fingerprint_smb(0x0302, 0x0003, {
        "netbios_computer_name": hostname, "netbios_domain_name": domain,
    })
    assert _label_with_identity(fingerprint) == expected


# ================================================================== la sonda


class _ScriptedSocket:
    """Socket que devuelve mensajes SMB ya envueltos en su cabecera NetBIOS."""

    def __init__(self, messages, sent):
        self._buffer = b"".join(
            bytes((0,)) + len(message).to_bytes(3, "big") + message
            for message in messages
        )
        self._sent = sent

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self._sent.append(payload)

    def recv(self, size):
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk

    def close(self):
        pass


def _probe_with(messages):
    sent = []
    return SmbProbe(connect=lambda _a, _t: _ScriptedSocket(messages, sent)), sent


def _negotiate_reply(dialect=0x0302, security_mode=0x0003):
    return b"\xfeSMB" + b"\x00" * 8 + struct.pack("<H", 0) + b"\x00" * 50 + \
        struct.pack("<HHH", 65, security_mode, dialect) + b"\x00" * 40


def test_the_identity_probe_negotiates_before_asking_who_you_are():
    probe, sent = _probe_with([
        _negotiate_reply(), _ntlm_challenge([(1, "WIN-SRV01"), (2, "CORP")]),
    ])
    identity = probe.fetch_identity("10.0.0.5")
    assert identity["netbios_computer_name"] == "WIN-SRV01"
    assert sent[0] == build_negotiate_request()
    assert sent[1] == build_session_setup_request(build_ntlm_negotiate())


def test_the_identity_probe_yields_nothing_if_the_negotiate_is_all_it_gets():
    probe, _sent = _probe_with([_negotiate_reply()])
    assert probe.fetch_identity("10.0.0.5") == {}


def test_the_smb1_probe_uses_a_connection_of_its_own():
    """No es un descuido: son dos protocolos distintos, y un servidor que ya ha
    negociado SMB2 sobre una conexión no va a aceptar un saludo de SMB1 sobre
    la misma."""
    probe, sent = _probe_with([_smb1_negotiate_reply()])
    assert probe.speaks_smb1("10.0.0.5") is True
    assert sent == [build_smb1_negotiate()]


def test_a_refused_connection_yields_no_identity_and_no_smb1():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    probe = SmbProbe(connect=refuse)
    assert probe.fetch_identity("10.0.0.5") == {}
    assert probe.speaks_smb1("10.0.0.5") is False


# =========================================================== el dissector


class _NullLimiter:
    def acquire(self, _host):
        pass


def test_the_dissector_folds_the_identity_into_its_label():
    probe, _sent = _probe_with([
        _negotiate_reply(), _ntlm_challenge([(1, "WIN-SRV01"), (2, "CORP")]),
        _negotiate_reply(), _ntlm_challenge([(1, "WIN-SRV01"), (2, "CORP")]),
    ])
    result = SmbDissector(probe=probe).probe(
        "10.0.0.5", Service(445, "tcp", "microsoft-ds"), _NullLimiter())
    assert result.label == "SMB en WIN-SRV01 (CORP)"
    assert (result.product, result.version) == ("SMB2", "3.0.2")


# ================================================================== el check


class _Context:
    def __init__(self, port=445):
        self.target = "10.0.0.5"
        self.service = Service(port, "tcp", "microsoft-ds")
        self.sibling_services = ()

    def acquire(self):
        pass


def _plugin(messages):
    from src.modules.features.themis.lybra.script_checks import SmbV1EnabledPlugin
    probe, _sent = _probe_with(messages)
    return SmbV1EnabledPlugin(probe=probe)


def test_the_smbv1_check_fires_on_an_explicit_acceptance():
    assert _plugin([_smb1_negotiate_reply()]).run(_Context()) is True


def test_the_smbv1_check_stays_quiet_for_a_hardened_server():
    assert _plugin([_smb1_negotiate_reply(dialect_index=0xFFFF)]).run(_Context()) is False
    assert _plugin([]).run(_Context()) is False


def test_the_smbv1_check_is_registered_and_wired_to_its_feed_entry():
    from src.modules.features.themis.lybra.checks import load_checks
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    check = next(c for c in load_checks() if c.id == "smbv1-enabled")
    assert check.severity == "HIGH" and check.mode == "safe"
    assert check.service == "smb"
    assert check.script in default_script_plugins()


def test_every_av_pair_the_table_declares_is_read():
    """Añadir un identificador a la tabla es todo lo que hace falta para que su
    valor llegue al fingerprint: sin este test, una entrada nueva podría no
    tener consumidor y nadie se enteraría."""
    pairs = [(av_id, f"valor-{av_id}") for av_id in AV_PAIR_NAMES]
    identity = parse_ntlm_challenge(_ntlm_challenge(pairs))
    for av_id, name in AV_PAIR_NAMES.items():
        assert identity[name] == f"valor-{av_id}"
