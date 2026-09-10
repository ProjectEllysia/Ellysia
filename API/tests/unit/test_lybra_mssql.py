"""El dissector de SQL Server.

El más generoso de los dissectors de bases de datos: el ``PRELOGIN`` de TDS
devuelve major, minor y build en un campo binario de tamaño fijo, sin
autenticar y sin negociar nada más.

Los desplazamientos de la tabla de opciones son **relativos al principio del
cuerpo**, no del paquete. Es el error clásico al parsear esto a mano, y varios
tests de aquí existen para que no vuelva.
"""

import struct

import pytest

from src.modules.features.themis.lybra.checks import is_mssql_service
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.mssql import (
    OPTION_ENCRYPTION,
    OPTION_TERMINATOR,
    OPTION_VERSION,
    PACKET_TYPE_PRELOGIN,
    TDS_HEADER_SIZE,
    MssqlDissector,
    MssqlProbe,
    build_prelogin_request,
    fingerprint_mssql,
    parse_prelogin_response,
)

pytestmark = pytest.mark.unit


def _prelogin_response(major=15, minor=0, build=2000, encryption=0x03,
                       with_encryption=True):
    """Construye una respuesta PRELOGIN como la que manda un servidor real."""
    table_size = 5 * (2 if with_encryption else 1) + 1
    version_data = struct.pack("!BBHH", major, minor, build, 0)
    body = struct.pack("!BHH", OPTION_VERSION, table_size, len(version_data))
    if with_encryption:
        body += struct.pack("!BHH", OPTION_ENCRYPTION,
                            table_size + len(version_data), 1)
    body += bytes((OPTION_TERMINATOR,)) + version_data
    if with_encryption:
        body += bytes((encryption,))
    header = struct.pack("!BBHHBB", 0x04, 0x01, TDS_HEADER_SIZE + len(body), 0, 0, 0)
    return header + body


# ================================================= el paquete que se construye


def test_the_prelogin_request_declares_its_own_length():
    """La cabecera TDS lleva la longitud total del paquete. Un servidor real
    espera exactamente esos bytes, así que si la longitud miente la conexión se
    queda colgada en vez de fallar."""
    request = build_prelogin_request()
    kind, _status, length = struct.unpack("!BBH", request[:4])
    assert kind == PACKET_TYPE_PRELOGIN
    assert length == len(request)


def test_the_prelogin_request_offsets_point_inside_its_own_body():
    """El error clásico: los desplazamientos son relativos al cuerpo, no al
    paquete. Si se contara desde la cabecera, apuntarían ocho bytes más allá."""
    body = build_prelogin_request()[TDS_HEADER_SIZE:]
    version_offset, version_length = struct.unpack("!HH", body[1:5])
    assert version_offset + version_length <= len(body)
    assert body[version_offset - 1] == OPTION_TERMINATOR


# ============================================================ el parseo


def test_a_real_shaped_response_yields_version_and_encryption():
    fingerprint = fingerprint_mssql(_prelogin_response(15, 0, 2000, 0x03))
    assert fingerprint.product == "Microsoft SQL Server"
    assert fingerprint.version == "15.0.2000"
    assert fingerprint.release_name == "2019"
    assert fingerprint.encryption == "required"


@pytest.mark.parametrize("code, mode", [
    (0x00, "off"),
    (0x01, "on"),
    (0x02, "not-supported"),
    (0x03, "required"),
])
def test_every_encryption_mode_is_named(code, mode):
    assert fingerprint_mssql(_prelogin_response(encryption=code)).encryption == mode


def test_a_server_that_cannot_encrypt_is_flagged():
    """Un `not-supported` significa que las credenciales de cualquier cliente
    van a viajar en claro: es un hecho de configuración por sí mismo en cuanto
    el puerto está expuesto."""
    assert fingerprint_mssql(_prelogin_response(encryption=0x02)).is_encryption_unsupported
    assert not fingerprint_mssql(_prelogin_response(encryption=0x03)).is_encryption_unsupported


@pytest.mark.parametrize("major, release", [
    (8, "2000"), (10, "2008"), (13, "2016"), (16, "2022"),
])
def test_the_major_version_names_its_commercial_release(major, release):
    assert fingerprint_mssql(_prelogin_response(major=major)).release_name == release


def test_an_unknown_major_version_still_reports_the_number():
    """La familia comercial acompaña a la versión, no la sustituye: el CPE se
    resuelve con `major.minor.build`, que es lo que NVD indexa."""
    fingerprint = fingerprint_mssql(_prelogin_response(major=99, minor=1, build=7))
    assert fingerprint.version == "99.1.7"
    assert fingerprint.release_name is None
    assert fingerprint.product == "Microsoft SQL Server"


def test_a_response_without_the_encryption_option_still_gives_the_version():
    fingerprint = fingerprint_mssql(_prelogin_response(with_encryption=False))
    assert fingerprint.version == "15.0.2000"
    assert fingerprint.encryption is None


# ==================================================== lo que no identifica


@pytest.mark.parametrize("data", [
    b"",
    b"\x04\x01\x00\x08\x00\x00\x00\x00",                 # cabecera sin cuerpo
    b"HTTP/1.1 400 Bad Request\r\n\r\n",                 # otro protocolo
    b"+OK POP3 ready\r\n",                               # un banner de texto
])
def test_something_that_is_not_a_prelogin_is_not_identified(data):
    assert fingerprint_mssql(data).product is None


def test_a_truncated_version_field_is_not_guessed():
    """Un desplazamiento que apunta fuera del cuerpo no se lee "hasta donde
    llegue": no hay versión, y sin versión no hay producto."""
    body = struct.pack("!BHH", OPTION_VERSION, 200, 6) + bytes((OPTION_TERMINATOR,))
    packet = struct.pack("!BBHHBB", 0x04, 0x01, TDS_HEADER_SIZE + len(body), 0, 0, 0) + body
    assert parse_prelogin_response(packet).product is None


def test_an_option_table_without_a_terminator_does_not_loop():
    body = struct.pack("!BHH", OPTION_VERSION, 11, 6) * 3
    packet = struct.pack("!BBHHBB", 0x04, 0x01, TDS_HEADER_SIZE + len(body), 0, 0, 0) + body
    parse_prelogin_response(packet)          # no cuelga ni revienta


# ============================================================== la sonda


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


def _probe_with(reply):
    sent = []
    return MssqlProbe(connect=lambda _a, _t: _ScriptedSocket(reply, sent)), sent


def test_the_probe_sends_one_prelogin_and_returns_the_answer():
    """Un solo intercambio, a diferencia de PostgreSQL: el PRELOGIN trae la
    versión y el cifrado en la misma respuesta."""
    reply = _prelogin_response()
    probe, sent = _probe_with(reply)
    assert probe.fetch("10.0.0.5") == reply
    assert sent == [build_prelogin_request()]


def test_a_refused_connection_yields_nothing():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    assert MssqlProbe(connect=refuse).fetch("10.0.0.5") is None


# =========================================================== el dissector


class _NullLimiter:
    def acquire(self, _host):
        pass


def test_the_dissector_claims_its_port_and_its_names():
    dissector = MssqlDissector()
    assert dissector.applies(Service(1433, "tcp", "ms-sql-s"))
    assert dissector.applies(Service(14330, "tcp", "mssql"))
    assert not dissector.applies(Service(5432, "tcp", "postgresql"))
    assert is_mssql_service(Service(1433, "tcp", ""))


def test_the_dissector_reports_product_and_version():
    probe, _sent = _probe_with(_prelogin_response(15, 0, 2000))
    result = MssqlDissector(probe=probe).probe(
        "10.0.0.5", Service(1433, "tcp", "ms-sql-s"), _NullLimiter())
    assert (result.product, result.version, result.label) == (
        "Microsoft SQL Server", "15.0.2000", "MSSQL")


def test_the_dissector_stays_quiet_for_a_port_that_is_not_sql_server():
    probe, _sent = _probe_with(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    result = MssqlDissector(probe=probe).probe(
        "10.0.0.5", Service(1433, "tcp", "ms-sql-s"), _NullLimiter())
    assert result is None


def test_the_product_name_has_an_alias_to_its_nvd_identity():
    """Sin el alias, `Microsoft SQL Server` no encontraría nada en la base de
    conocimiento: NVD lo indexa como `microsoft:sql_server`."""
    import json
    from pathlib import Path

    feed = Path(__file__).resolve().parents[2] / (
        "src/modules/features/themis/lybra/feeds/product_aliases.json")
    aliases = json.loads(feed.read_text(encoding="utf-8"))["aliases"]
    entry = next(a for a in aliases if a["match"] == "microsoft sql server")
    assert (entry["vendor"], entry["product"]) == ("microsoft", "sql_server")
