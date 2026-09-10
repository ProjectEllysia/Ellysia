"""El dissector de PostgreSQL.

La primera base de datos del motor que **negocia** en vez de escuchar un banner
ofrecido. Todo con socket falso: la sonda recibe su conector inyectado, igual
que el resto del paquete.

El techo del protocolo está asumido en los tests, no disimulado: PostgreSQL no
regala su versión antes de autenticar, así que la mayoría de los casos
comprueban producto sin versión — y comprueban que no se inventa ninguna.
"""

import struct

import pytest

from src.modules.features.themis.lybra.checks import is_postgres_service
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.postgres import (
    PROTOCOL_VERSION_3,
    SSL_REQUEST_CODE,
    PostgresDissector,
    PostgresProbe,
    build_ssl_request,
    build_startup_message,
    fingerprint_postgres,
    parse_ssl_response,
    parse_startup_response,
)

pytestmark = pytest.mark.unit


def _auth_response(code: int, extra: bytes = b"") -> bytes:
    """Un AuthenticationRequest con el código dado."""
    body = struct.pack("!i", code) + extra
    return b"R" + struct.pack("!i", len(body) + 4) + body


def _error_response(**fields) -> bytes:
    """Un ErrorResponse con los campos etiquetados dados."""
    body = b""
    for label, value in fields.items():
        body += label.encode("ascii") + value.encode("utf-8") + b"\x00"
    body += b"\x00"
    return b"E" + struct.pack("!i", len(body) + 4) + body


# ============================================= los mensajes que se construyen


def test_the_ssl_request_is_the_eight_bytes_the_protocol_fixes():
    """El único artefacto de este módulo verificable a ojo contra la
    documentación: longitud 8 y el código mágico, nada más."""
    request = build_ssl_request()
    assert len(request) == 8
    assert struct.unpack("!ii", request) == (8, SSL_REQUEST_CODE)


def test_the_startup_message_declares_its_length_and_protocol():
    message = build_startup_message("alguien")
    length, version = struct.unpack("!ii", message[:8])
    assert length == len(message)
    assert version == PROTOCOL_VERSION_3
    assert b"user\x00alguien\x00" in message
    assert message.endswith(b"\x00")


def test_the_startup_message_can_declare_a_database():
    message = build_startup_message("alguien", "produccion")
    assert b"database\x00produccion\x00" in message
    assert struct.unpack("!i", message[:4])[0] == len(message)


# ================================================== la respuesta al SSLRequest


@pytest.mark.parametrize("reply, expected", [
    (b"S", True),
    (b"N", False),
    (b"X", None),
    (b"", None),
])
def test_the_ssl_reply_is_a_single_letter(reply, expected):
    assert parse_ssl_response(reply) is expected


# ============================================ la respuesta al StartupMessage


@pytest.mark.parametrize("code, method", [
    (0, "trust"),
    (3, "password"),
    (5, "md5"),
    (10, "sasl"),
])
def test_each_authentication_code_names_its_method(code, method):
    assert parse_startup_response(_auth_response(code))[0] == method


def test_the_sasl_mechanisms_are_read_from_the_body():
    """Es donde aparece SCRAM-SHA-256, que es lo que distingue un servidor
    moderno de uno que sigue con md5."""
    reply = _auth_response(10, b"SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00")
    method, _version, mechanisms = parse_startup_response(reply)
    assert method == "sasl"
    assert mechanisms == ("SCRAM-SHA-256", "SCRAM-SHA-256-PLUS")


def test_an_unknown_authentication_code_names_no_method():
    assert parse_startup_response(_auth_response(99))[0] is None


def test_an_error_response_can_carry_the_version():
    reply = _error_response(S="FATAL", C="28000",
                            M='role "lybra-probe" does not exist on PostgreSQL 16.1')
    method, version, _mechanisms = parse_startup_response(reply)
    assert method is None
    assert version == "16.1"


def test_an_error_response_without_a_version_invents_none():
    """El caso normal, y el que importa: PostgreSQL casi nunca se nombra en sus
    errores. Producto sí, versión no."""
    reply = _error_response(S="FATAL", C="28000", M='role "lybra-probe" does not exist')
    assert parse_startup_response(reply)[1] is None


@pytest.mark.parametrize("reply", [b"", b"R", b"R\x00\x00", b"Z\x00\x00\x00\x05I"])
def test_a_truncated_or_unrelated_reply_yields_nothing(reply):
    assert parse_startup_response(reply) == (None, None, ())


# ======================================================== el fingerprint


def test_a_server_requiring_scram_is_identified_without_a_version():
    fingerprint = fingerprint_postgres(
        b"S", _auth_response(10, b"SCRAM-SHA-256\x00\x00"))
    assert fingerprint.product == "PostgreSQL"
    assert fingerprint.version is None
    assert fingerprint.accepts_tls is True
    assert fingerprint.auth_method == "sasl"
    assert not fingerprint.is_unauthenticated


def test_a_server_in_trust_mode_is_flagged_as_unauthenticated():
    """El hallazgo del issue. `trust` no es autenticación débil: es la ausencia
    completa de autenticación, y el servidor lo dice él mismo contestando
    AuthenticationOk a un usuario que no existe."""
    fingerprint = fingerprint_postgres(b"N", _auth_response(0))
    assert fingerprint.is_unauthenticated
    assert fingerprint.auth_method == "trust"
    assert fingerprint.accepts_tls is False


def test_a_server_that_only_answers_the_ssl_request_is_still_identified():
    fingerprint = fingerprint_postgres(b"S", b"")
    assert fingerprint.product == "PostgreSQL"
    assert fingerprint.accepts_tls is True
    assert fingerprint.auth_method is None


def test_something_that_is_not_postgres_is_not_identified():
    """Un puerto que acepta la conexión y contesta cualquier cosa no es un
    PostgreSQL, y no se va a etiquetar como tal."""
    fingerprint = fingerprint_postgres(b"HTTP/1.1 400 Bad Request", b"<html>")
    assert fingerprint.product is None


# ============================================================ la sonda


class _ScriptedSocket:
    def __init__(self, reply, sent):
        self._reply = reply
        self._sent = sent

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self._sent.append(payload)

    def recv(self, _size):
        return self._reply

    def close(self):
        pass


def _probe_with(replies):
    sent = []
    pending = list(replies)

    def connect(_address, _timeout):
        return _ScriptedSocket(pending.pop(0), sent)

    return PostgresProbe(connect=connect), sent


def test_the_probe_makes_the_two_exchanges_in_order():
    probe, sent = _probe_with([b"S", _auth_response(0)])
    ssl_reply, startup_reply = probe.fetch("10.0.0.5")
    assert ssl_reply == b"S"
    assert startup_reply == _auth_response(0)
    assert sent[0] == build_ssl_request()
    assert sent[1].startswith(struct.pack("!i", len(sent[1])))


def test_the_probe_never_sends_a_password():
    """La garantía que permite que esto viva en modo `safe`: se leen las dos
    respuestas del protocolo de conexión y no se intenta autenticar."""
    probe, sent = _probe_with([b"S", _auth_response(5)])
    probe.fetch("10.0.0.5")
    assert len(sent) == 2                      # SSLRequest y StartupMessage
    assert b"password" not in b"".join(sent).lower()


def test_a_refused_connection_yields_nothing():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    assert PostgresProbe(connect=refuse).fetch("10.0.0.5") is None


# ======================================================== el dissector


def test_the_dissector_claims_its_port_and_its_name():
    dissector = PostgresDissector()
    assert dissector.applies(Service(5432, "tcp", "postgresql"))
    assert dissector.applies(Service(5433, "tcp", "postgres"))
    assert not dissector.applies(Service(3306, "tcp", "mysql"))
    assert is_postgres_service(Service(5432, "tcp", ""))


class _NullLimiter:
    def acquire(self, _host):
        pass


def test_the_dissector_reports_the_product_it_observed():
    probe, _sent = _probe_with([b"S", _auth_response(10, b"SCRAM-SHA-256\x00\x00")])
    result = PostgresDissector(probe=probe).probe(
        "10.0.0.5", Service(5432, "tcp", "postgresql"), _NullLimiter())
    assert (result.product, result.version, result.label) == (
        "PostgreSQL", None, "PostgreSQL")


def test_the_dissector_stays_quiet_when_nothing_answered():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    result = PostgresDissector(probe=PostgresProbe(connect=refuse)).probe(
        "10.0.0.5", Service(5432, "tcp", "postgresql"), _NullLimiter())
    assert result is None


# ================================== el check de trust (plugin de tipo script)


def _trust_plugin(replies):
    from src.modules.features.themis.lybra.script_checks import (
        PostgresTrustAuthenticationPlugin,
    )
    probe, _sent = _probe_with(replies)
    return PostgresTrustAuthenticationPlugin(probe=probe)


class _Context:
    def __init__(self, port=5432):
        self.target = "10.0.0.5"
        self.service = Service(port, "tcp", "postgresql")

    def acquire(self):
        pass


def test_the_trust_check_fires_only_when_the_server_asks_for_nothing():
    assert _trust_plugin([b"N", _auth_response(0)]).run(_Context()) is True


@pytest.mark.parametrize("code", [3, 5, 10])
def test_the_trust_check_stays_quiet_for_a_server_that_authenticates(code):
    assert _trust_plugin([b"S", _auth_response(code)]).run(_Context()) is False


def test_the_trust_check_stays_quiet_without_evidence():
    """Sin intercambio no hay evidencia, y sin evidencia no hay hallazgo — el
    mismo criterio que los otros dos plugins de primera parte."""
    from src.modules.features.themis.lybra.script_checks import (
        PostgresTrustAuthenticationPlugin,
    )

    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    plugin = PostgresTrustAuthenticationPlugin(probe=PostgresProbe(connect=refuse))
    assert plugin.run(_Context()) is False


def test_the_trust_check_is_registered_and_wired_to_its_feed_entry():
    from src.modules.features.themis.lybra.checks import load_checks
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    check = next(c for c in load_checks() if c.id == "postgres-trust-authentication")
    assert check.severity == "CRITICAL" and check.mode == "safe"
    assert check.service == "postgres"
    assert check.script in default_script_plugins()
