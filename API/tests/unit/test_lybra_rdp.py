"""El dissector de RDP.

RDP es el vector de entrada de la mayoría de los incidentes de ransomware que
empiezan por acceso remoto, y BlueKeep (CVE-2019-0708) sigue apareciendo en
redes reales. El hallazgo es **RDP sin NLA**: sin autenticación a nivel de red,
cualquiera que alcance el puerto llega a la pantalla de login.

La sonda es la más compleja del backlog en construcción, pero su resultado es
binario: el servidor dice un número. Lo que estos tests protegen es el paso de
ese número al veredicto — y, sobre todo, el caso en el que **no hay número**.
"""

import struct

import pytest

from src.modules.features.themis.lybra.checks import is_rdp_service
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.rdp import (
    NEG_FAILURE,
    NEG_RESPONSE,
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_RDP,
    PROTOCOL_SSL,
    REQUESTED_PROTOCOLS,
    TPDU_CONNECTION_REQUEST,
    TPKT_HEADER_SIZE,
    TPKT_VERSION,
    RdpDissector,
    RdpProbe,
    build_connection_request,
    fingerprint_rdp,
    parse_connection_confirm,
)

pytestmark = pytest.mark.unit


def _confirm(negotiation=b""):
    """Un Connection Confirm con el bloque de negociación dado."""
    tpdu = struct.pack("!BBHHB", 6 + len(negotiation), 0xD0, 0, 0, 0) + negotiation
    return struct.pack("!BBH", TPKT_VERSION, 0, TPKT_HEADER_SIZE + len(tpdu)) + tpdu


def _selected(protocol):
    return _confirm(struct.pack("<BBHI", NEG_RESPONSE, 0, 8, protocol))


def _failed(code):
    return _confirm(struct.pack("<BBHI", NEG_FAILURE, 0, 8, code))


# =============================================== el paquete que se construye


def test_the_connection_request_is_nineteen_bytes_with_a_matching_tpkt_length():
    """TPKT lleva la longitud total del paquete; si miente, el servidor se
    queda esperando bytes que no llegan en vez de contestar."""
    request = build_connection_request()
    version, _reserved, length = struct.unpack("!BBH", request[:4])
    assert version == TPKT_VERSION
    assert length == len(request) == 19


def test_the_length_indicator_counts_the_bytes_after_itself():
    """El LI de X.224 no cuenta el propio LI, que es la trampa de este campo."""
    request = build_connection_request()
    length_indicator = request[TPKT_HEADER_SIZE]
    assert length_indicator == len(request) - TPKT_HEADER_SIZE - 1
    assert request[TPKT_HEADER_SIZE + 1] == TPDU_CONNECTION_REQUEST


def test_the_two_endiannesses_coexist_in_the_same_packet():
    """TPKT viene de OSI y va en big-endian; RDP_NEG_REQ viene de Windows y va
    en little-endian. Conviven en el mismo paquete, y transcribir uno con el
    orden del otro es donde esto se rompe."""
    request = build_connection_request()
    assert struct.unpack("!H", request[2:4])[0] == 19            # TPKT: big-endian
    kind, _flags, length, protocols = struct.unpack("<BBHI", request[11:19])
    assert (kind, length, protocols) == (0x01, 8, REQUESTED_PROTOCOLS)


def test_all_supported_protocols_are_announced():
    """Pedir sólo uno mediría la petición, no la política del servidor: hay que
    dejarle elegir entre todos los que sabemos reconocer."""
    assert REQUESTED_PROTOCOLS & PROTOCOL_SSL
    assert REQUESTED_PROTOCOLS & PROTOCOL_HYBRID
    assert REQUESTED_PROTOCOLS & PROTOCOL_HYBRID_EX


# ================================================== el protocolo negociado


@pytest.mark.parametrize("protocol, name, has_nla", [
    (PROTOCOL_HYBRID, "hybrid", True),
    (PROTOCOL_HYBRID_EX, "hybrid-ex", True),
    (PROTOCOL_SSL, "ssl", False),
    (PROTOCOL_RDP, "rdp", False),
])
def test_each_selected_protocol_decides_whether_nla_is_required(protocol, name, has_nla):
    fingerprint = fingerprint_rdp(_selected(protocol))
    assert fingerprint.product == "Microsoft Terminal Services"
    assert fingerprint.selected_protocol == name
    assert fingerprint.requires_network_level_authentication is has_nla


def test_the_dissector_never_claims_a_version():
    """La negociación de X.224 ocurre antes de cualquier intercambio de
    capacidades. Este intercambio no da versión, y no se inventa una."""
    assert fingerprint_rdp(_selected(PROTOCOL_HYBRID)).version is None


def test_a_server_without_a_negotiation_block_means_plain_rdp_security():
    """Los servidores muy antiguos no adjuntan bloque de negociación, y esa
    ausencia significa seguridad RDP estándar — sin TLS siquiera."""
    fingerprint = fingerprint_rdp(_confirm())
    assert fingerprint.selected_protocol == "rdp"
    assert fingerprint.requires_network_level_authentication is False


# ==================================================== la negociación fallida


def test_a_failure_that_demands_nla_counts_as_nla_required():
    """Un rechazo informa tanto como un éxito: `hybrid-required-by-server` es,
    de hecho, la mejor noticia posible."""
    fingerprint = fingerprint_rdp(_failed(0x00000005))
    assert fingerprint.failure == "hybrid-required-by-server"
    assert fingerprint.requires_network_level_authentication is True


@pytest.mark.parametrize("code, name", [
    (0x00000001, "ssl-required-by-server"),
    (0x00000002, "ssl-not-allowed-by-server"),
    (0x00000004, "inconsistent-flags"),
])
def test_other_failures_are_named_but_decide_nothing_about_nla(code, name):
    """**El caso que hay que no equivocar.** Un fallo que no habla de NLA deja
    la pregunta sin respuesta, y eso es `None`, no `False`: afirmar que un
    servidor no exige NLA sin haberlo observado sería inventarlo."""
    fingerprint = fingerprint_rdp(_failed(code))
    assert fingerprint.failure == name
    assert fingerprint.requires_network_level_authentication is None


def test_an_unknown_failure_code_still_identifies_the_service():
    fingerprint = fingerprint_rdp(_failed(0x000000FF))
    assert fingerprint.product == "Microsoft Terminal Services"
    assert fingerprint.failure is None
    assert fingerprint.requires_network_level_authentication is None


# ==================================================== lo que no identifica


@pytest.mark.parametrize("data", [
    b"",
    b"\x03\x00\x00\x04",                             # TPKT sin TPDU
    b"HTTP/1.1 400 Bad Request\r\n\r\n",
    b"SSH-2.0-OpenSSH_8.9p1\r\n",
])
def test_something_that_is_not_rdp_is_not_identified(data):
    assert parse_connection_confirm(data).product is None


def test_a_tpdu_that_is_not_a_connection_confirm_is_not_identified():
    tpdu = struct.pack("!BBHHB", 6, 0x80, 0, 0, 0)   # Disconnect Request
    packet = struct.pack("!BBH", TPKT_VERSION, 0, TPKT_HEADER_SIZE + len(tpdu)) + tpdu
    assert parse_connection_confirm(packet).product is None


# ================================================================ la sonda


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
    return RdpProbe(connect=lambda _a, _t: _ScriptedSocket(reply, sent)), sent


def test_the_probe_sends_one_request_and_stops_there():
    """La sesión no se llega a establecer: la conexión se cierra en cuanto el
    servidor dice qué protocolo prefiere, así que no se abre ninguna sesión
    gráfica ni se toca la pantalla de login."""
    probe, sent = _probe_with(_selected(PROTOCOL_HYBRID))
    probe.fetch("10.0.0.5")
    assert sent == [build_connection_request()]


def test_a_refused_connection_yields_nothing():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    assert RdpProbe(connect=refuse).fetch("10.0.0.5") is None


# =========================================================== el dissector


class _NullLimiter:
    def acquire(self, _host):
        pass


def test_the_dissector_claims_its_port_and_its_names():
    dissector = RdpDissector()
    assert dissector.applies(Service(3389, "tcp", "ms-wbt-server"))
    assert dissector.applies(Service(33890, "tcp", "rdp"))
    assert not dissector.applies(Service(22, "tcp", "ssh"))
    assert is_rdp_service(Service(3389, "tcp", ""))


def test_the_dissector_reports_the_product_without_a_version():
    probe, _sent = _probe_with(_selected(PROTOCOL_HYBRID))
    result = RdpDissector(probe=probe).probe(
        "10.0.0.5", Service(3389, "tcp", "ms-wbt-server"), _NullLimiter())
    assert (result.product, result.version, result.label) == (
        "Microsoft Terminal Services", None, "RDP")


# ================================================================ el check


class _Context:
    def __init__(self, port=3389):
        self.target = "10.0.0.5"
        self.service = Service(port, "tcp", "ms-wbt-server")
        self.sibling_services = ()

    def acquire(self):
        pass


def _plugin(reply):
    from src.modules.features.themis.lybra.script_checks import RdpNlaNotRequiredPlugin
    probe, _sent = _probe_with(reply)
    return RdpNlaNotRequiredPlugin(probe=probe)


@pytest.mark.parametrize("reply, fires", [
    (_selected(PROTOCOL_SSL), True),        # TLS pero sin NLA
    (_selected(PROTOCOL_RDP), True),        # ni TLS
    (_selected(PROTOCOL_HYBRID), False),    # NLA exigido
    (_selected(PROTOCOL_HYBRID_EX), False),
    (_failed(0x00000005), False),           # NLA exigido, dicho como rechazo
])
def test_the_check_follows_the_protocol_the_server_chose(reply, fires):
    assert _plugin(reply).run(_Context()) is fires


def test_the_check_stays_quiet_when_the_mode_could_not_be_read():
    """`None` no es `False`. Un servidor cuyo modo no se ha podido leer no
    produce el hallazgo: sería afirmar una configuración insegura sin haberla
    observado."""
    assert _plugin(_failed(0x00000004)).run(_Context()) is False
    assert _plugin(b"HTTP/1.1 400 Bad Request").run(_Context()) is False


def test_the_check_stays_quiet_without_evidence():
    from src.modules.features.themis.lybra.script_checks import RdpNlaNotRequiredPlugin

    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    plugin = RdpNlaNotRequiredPlugin(probe=RdpProbe(connect=refuse))
    assert plugin.run(_Context()) is False


def test_the_check_is_registered_and_wired_to_its_feed_entry():
    from src.modules.features.themis.lybra.checks import load_checks
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    check = next(c for c in load_checks() if c.id == "rdp-nla-not-required")
    assert check.severity == "HIGH" and check.mode == "safe"
    assert check.service == "rdp"
    assert check.script in default_script_plugins()
