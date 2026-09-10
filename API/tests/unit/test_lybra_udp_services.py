"""La superficie UDP: seis protocolos, cada uno con su consumidor.

La tabla de sondas UDP nació con una fila y una regla —crece una fila por
protocolo que un check o un dissector consuma de verdad, no antes—. Este
fichero es la mitad que comprueba que la regla se cumple: cada payload que
``udp_payloads`` construye tiene aquí quien lo lea.

Todo con emisor inyectado: ni un datagrama sale a la red.
"""

import struct

import pytest

from src.modules.features.themis.lybra.checks import (
    is_dns_service,
    is_ike_service,
    is_mdns_service,
    is_mssql_browser_service,
    is_netbios_service,
    is_ntp_service,
)
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.transport import UDP_PROBES, scan_udp_ports_sync
from src.modules.features.themis.lybra.udp_payloads import (
    DNS_CLASS_CHAOS,
    DNS_FLAG_RECURSION_AVAILABLE,
    DNS_TYPE_TXT,
    ISAKMP_HEADER_SIZE,
    ISAKMP_PAYLOAD_SA,
    build_dns_version_query,
    build_ike_main_mode,
    build_mdns_services_query,
    build_mssql_browser_query,
    build_netbios_name_query,
    build_ntp_monlist,
    build_ntp_readvar,
    encode_dns_name,
    encode_netbios_name,
)
from src.modules.features.themis.lybra.fingerprinting.udp_services import (
    DnsDissector,
    DnsProbe,
    IkeDissector,
    IkeProbe,
    MssqlBrowserDissector,
    MssqlBrowserProbe,
    NetbiosDissector,
    NetbiosProbe,
    NtpDissector,
    NtpProbe,
    monlist_is_answered,
    parse_dns_version_response,
    parse_ike_response,
    parse_mdns_response,
    parse_mssql_browser_response,
    parse_netbios_response,
    parse_ntp_readvar_response,
)

pytestmark = pytest.mark.unit


class _NullLimiter:
    def acquire(self, _host):
        pass


def _sender(reply):
    return lambda _host, _port, _payload, _timeout: reply


# ============================================ la regla que gobierna la tabla


def test_every_udp_probe_row_has_a_consumer():
    """La regla con la que la tabla nació: una fila por protocolo que alguien
    consuma de verdad, nunca la sonda sola. Un payload sin lector sólo produce
    un `open_port` informativo a cambio de construir y validar una consulta
    más."""
    from src.modules.features.themis.lybra import default_dissectors

    dissectors = default_dissectors()
    for port in UDP_PROBES:
        service = Service(port, "udp", "")
        assert any(dissector.applies(service) for dissector in dissectors), (
            f"el puerto {port} tiene payload y nadie que lea la respuesta")


@pytest.mark.parametrize("predicate, port", [
    (is_dns_service, 53),
    (is_ntp_service, 123),
    (is_netbios_service, 137),
    (is_ike_service, 500),
    (is_mssql_browser_service, 1434),
    (is_mdns_service, 5353),
])
def test_every_udp_predicate_refuses_the_same_port_over_tcp(predicate, port):
    """Todos comparten con SNMP la guarda de protocolo: varios de estos
    puertos existen también como TCP, y mandarle un datagrama a un servicio TCP
    es tiempo perdido y un hallazgo duplicado con la misma `dedup_key`."""
    assert predicate(Service(port, "udp", "")) is True
    assert predicate(Service(port, "tcp", "")) is False
    assert predicate(Service(port, "", "")) is False


# ============================================================ DNS y mDNS


def test_the_dns_name_encoding_puts_a_length_before_each_label():
    assert encode_dns_name("version.bind") == b"\x07version\x04bind\x00"
    assert encode_dns_name("") == b"\x00"


def test_the_version_query_asks_for_a_chaos_txt_record():
    query = build_dns_version_query()
    assert b"\x07version\x04bind\x00" in query
    record_type, record_class = struct.unpack("!HH", query[-4:])
    assert (record_type, record_class) == (DNS_TYPE_TXT, DNS_CLASS_CHAOS)


def _dns_reply(text=b"9.16.1-Ubuntu", flags=0x8180, answers=1):
    header = struct.pack("!HHHHHH", 0x1337, flags, 1, answers, 0, 0)
    question = encode_dns_name("version.bind") + struct.pack(
        "!HH", DNS_TYPE_TXT, DNS_CLASS_CHAOS)
    if not answers:
        return header + question
    rdata = bytes((len(text),)) + text
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", DNS_TYPE_TXT, DNS_CLASS_CHAOS, 0,
                                        len(rdata)) + rdata)
    return header + question + answer


def test_a_bind_server_that_publishes_its_version_is_identified():
    fingerprint = parse_dns_version_response(_dns_reply())
    assert (fingerprint.product, fingerprint.version) == ("BIND", "9.16.1-Ubuntu")


def test_a_dns_server_that_hides_its_version_is_still_a_dns_server():
    """Suprimir `version.bind` es lo primero que recomienda cualquier guía, así
    que lo normal es no obtener versión — y eso no es un fallo."""
    fingerprint = parse_dns_version_response(_dns_reply(answers=0))
    assert fingerprint.product == "DNS"
    assert fingerprint.version is None


def test_the_recursion_flag_comes_from_the_same_answer():
    """El bit que delata un resolutor abierto lo enciende el servidor él solo
    en la respuesta a version.bind. Leerlo no hace que el objetivo mande
    tráfico a ningún tercero, que es justo el comportamiento medido."""
    assert parse_dns_version_response(
        _dns_reply(flags=0x8180 | DNS_FLAG_RECURSION_AVAILABLE)).offers_recursion
    assert not parse_dns_version_response(_dns_reply(flags=0x8100)).offers_recursion


@pytest.mark.parametrize("data", [b"", b"\x13\x37", b"no es un datagrama DNS"])
def test_something_that_is_not_dns_is_not_identified(data):
    assert parse_dns_version_response(data).product is None


def test_a_query_that_is_not_a_response_is_not_identified():
    """El bit de "esto es una respuesta" apagado significa que lo que ha
    llegado es una pregunta, probablemente la nuestra rebotada."""
    assert parse_dns_version_response(_dns_reply(flags=0x0100)).product is None


def test_the_mdns_query_asks_for_the_service_catalogue():
    query = build_mdns_services_query()
    assert b"\x09_services\x07_dns-sd\x04_udp\x05local\x00" in query


def test_the_mdns_response_lists_the_services_it_announces():
    body = (b"\x0c_googlecast\x04_tcp\x05local\x00"
            b"\x05_http\x04_tcp\x05local\x00"
            b"\x05_http\x04_tcp\x05local\x00")
    reply = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0) + body
    assert parse_mdns_response(reply) == ("_googlecast._tcp", "_http._tcp")


def test_an_mdns_query_echoed_back_lists_nothing():
    assert parse_mdns_response(build_mdns_services_query()) == ()


# ==================================================================== NTP


def test_the_readvar_message_is_a_mode_six_control_request():
    message = build_ntp_readvar()
    assert len(message) == 12
    assert message[0] & 0x07 == 6          # modo 6: control
    assert message[1] == 2                 # opcode READVAR


def test_the_monlist_message_is_the_mode_seven_private_request():
    message = build_ntp_monlist()
    assert len(message) == 8
    assert message[0] & 0x07 == 7          # modo 7: privado
    assert message[3] == 42                # código de petición monlist


def _ntp_readvar_reply(payload):
    return struct.pack("!BBHHHHH", 0x1E, 0x82, 1, 0, 0, 0, len(payload)) + payload


def test_the_readvar_reply_names_the_daemon_and_its_version():
    payload = b'version="ntpd 4.2.8p15@1.3728-o", processor="x86_64", system="Linux/5.4.0"'
    fingerprint = parse_ntp_readvar_response(_ntp_readvar_reply(payload))
    assert (fingerprint.product, fingerprint.version) == ("ntpd", "4.2.8p15")
    assert fingerprint.system == "Linux/5.4.0"


def test_a_readvar_reply_without_a_version_is_still_ntp():
    fingerprint = parse_ntp_readvar_response(_ntp_readvar_reply(b'processor="x86_64"'))
    assert fingerprint.product == "NTP"
    assert fingerprint.version is None


def test_something_that_is_not_a_control_reply_is_not_ntp():
    assert parse_ntp_readvar_response(b"\x00" * 20).product is None
    assert parse_ntp_readvar_response(b"").product is None


def test_monlist_counts_only_a_private_reply_without_the_error_bit():
    """Un ntpd moderno responde con el bit de error encendido o directamente
    calla; las dos cosas son un no."""
    answered = struct.pack("!BB", 0x17, 0x80) + b"\x00" * 10
    errored = struct.pack("!BB", 0x17, 0xC0) + b"\x00" * 10
    assert monlist_is_answered(answered) is True
    assert monlist_is_answered(errored) is False
    assert monlist_is_answered(None) is False
    assert monlist_is_answered(b"\x1e\x82" + b"\x00" * 10) is False   # modo 6


# =============================================================== NetBIOS


def test_the_netbios_name_encoding_splits_each_byte_into_two_letters():
    """La codificación de primer nivel de la RFC 1001: peculiar, muy antigua y
    completamente determinista."""
    encoded = encode_netbios_name("*")
    assert encoded[0] == 32                       # longitud del nombre codificado
    assert encoded[1:3] == b"CK"                  # '*' = 0x2A -> 'C','K'
    assert encoded[3:5] == b"AA"                  # el relleno del comodín es NUL
    assert encoded.endswith(b"\x00")


def test_the_netbios_query_asks_for_the_adapter_status():
    query = build_netbios_name_query()
    record_type, record_class = struct.unpack("!HH", query[-4:])
    assert (record_type, record_class) == (0x0021, 1)


def _netbios_reply(names, mac=b"\x00\x0c\x29\x1a\x2b\x3c"):
    body = bytes((len(names),))
    for name, flags in names:
        body += name.ljust(15).encode("ascii")[:15] + b"\x20" + struct.pack("!H", flags)
    body += mac
    header = struct.pack("!HHHHHH", 0x1337, 0x8500, 0, 1, 0, 0)
    answer = (encode_netbios_name("*") + struct.pack("!HHIH", 0x0021, 1, 0, len(body))
              + body)
    return header + answer


def test_the_netbios_reply_yields_hostname_domain_and_mac():
    reply = _netbios_reply([("WIN-SRV01", 0x0400), ("CORP", 0x8400)])
    fingerprint = parse_netbios_response(reply)
    assert fingerprint.hostname == "WIN-SRV01"
    assert fingerprint.domain == "CORP"
    assert fingerprint.mac_address == "00:0c:29:1a:2b:3c"


def test_the_group_flag_is_what_tells_a_domain_from_a_hostname():
    """Sin ese bit, el primer nombre de la tabla sería el equipo y el segundo
    el dominio por orden de llegada — que es sólo cierto a veces."""
    reply = _netbios_reply([("CORP", 0x8400), ("WIN-SRV01", 0x0400)])
    fingerprint = parse_netbios_response(reply)
    assert (fingerprint.hostname, fingerprint.domain) == ("WIN-SRV01", "CORP")


def test_a_reply_with_no_mac_reports_none():
    reply = _netbios_reply([("WIN-SRV01", 0x0400)], mac=b"\x00" * 6)
    assert parse_netbios_response(reply).mac_address is None


@pytest.mark.parametrize("data", [b"", b"\x00" * 8, b"esto no es NetBIOS"])
def test_an_unreadable_netbios_reply_yields_nothing(data):
    fingerprint = parse_netbios_response(data)
    assert fingerprint.hostname is None and fingerprint.domain is None


# =================================================================== IKE


def test_the_ike_request_declares_a_consistent_length_at_every_level():
    """La estructura es de muñecas rusas y cada nivel declara su propia
    longitud incluyéndose a sí mismo. Es el sitio donde una transcripción a
    mano se rompe, y el servidor no diría por qué: simplemente callaría."""
    request = build_ike_main_mode()
    declared = struct.unpack_from("!I", request, 24)[0]
    assert declared == len(request)

    next_payload, _reserved, sa_length = struct.unpack_from("!BBH", request,
                                                            ISAKMP_HEADER_SIZE)
    assert sa_length == len(request) - ISAKMP_HEADER_SIZE
    assert request[16] == ISAKMP_PAYLOAD_SA
    assert next_payload == 2                      # dentro del SA viene la propuesta


def test_the_ike_request_offers_a_wide_range_on_purpose():
    """Lo interesante no es que la negociación prospere, sino cuál elige el
    servidor: un gateway que acepta DES o MD5 lo está diciendo él mismo."""
    from src.modules.features.themis.lybra.udp_payloads import IKE_TRANSFORMS

    # Cabecera (28) + cabecera del SA (4) + DOI y situación (8) + cabecera de
    # la propuesta (4) deja el recuento de transformadas en el cuarto byte del
    # cuerpo de la propuesta.
    request = build_ike_main_mode()
    transform_count = request[ISAKMP_HEADER_SIZE + 4 + 8 + 4 + 3]
    assert transform_count == len(IKE_TRANSFORMS)
    assert transform_count >= 4


def _ike_reply(encryption=7, hash_algorithm=2, authentication=1, group=14):
    attributes = b"".join(struct.pack("!HH", attribute, value) for attribute, value in (
        (0x8001, encryption), (0x8002, hash_algorithm),
        (0x8003, authentication), (0x8004, group),
    ))
    transform = struct.pack("!BBH", 0, 0, 8 + len(attributes)) + \
        struct.pack("!BBH", 1, 1, 0) + attributes
    proposal = struct.pack("!BBH", 0, 0, 8 + len(transform)) + \
        struct.pack("!BBBB", 1, 1, 0, 1) + transform
    sa_body = struct.pack("!II", 1, 1) + proposal
    security_association = struct.pack("!BBH", 2, 0, 4 + len(sa_body)) + sa_body
    header = struct.pack("!8s8sBBBBII", b"Lybra\x00\x00\x01", b"respondr",
                         ISAKMP_PAYLOAD_SA, 0x10, 2, 0, 0,
                         ISAKMP_HEADER_SIZE + len(security_association))
    return header + security_association


def test_the_gateway_choice_is_read_with_readable_names():
    fingerprint = parse_ike_response(_ike_reply())
    assert fingerprint.product == "IKE"
    assert (fingerprint.encryption, fingerprint.hash_algorithm) == ("AES", "SHA1")
    assert fingerprint.authentication == "clave precompartida"


def test_a_gateway_that_picks_retired_cryptography_is_flagged():
    assert parse_ike_response(_ike_reply(encryption=1)).accepts_weak_cryptography
    assert parse_ike_response(_ike_reply(hash_algorithm=1)).accepts_weak_cryptography
    assert not parse_ike_response(
        _ike_reply(encryption=7, hash_algorithm=4)).accepts_weak_cryptography


def test_our_own_request_echoed_back_is_not_taken_for_an_answer():
    """La cookie del respondedor viene a cero en la petición y rellena en la
    respuesta: es lo que distingue una de otra."""
    assert parse_ike_response(build_ike_main_mode()).product is None


@pytest.mark.parametrize("data", [b"", b"\x00" * 10, b"no es ISAKMP"])
def test_an_unreadable_ike_reply_yields_nothing(data):
    assert parse_ike_response(data).product is None


# ==================================================== SQL Server Browser


def test_the_browser_query_is_a_single_byte():
    assert build_mssql_browser_query() == b"\x02"


def test_the_browser_reply_is_parsed_into_its_fields():
    payload = b"ServerName;SRV01;InstanceName;MSSQLSERVER;Version;15.0.2000.5;;"
    reply = b"\x05" + struct.pack("<H", len(payload)) + payload
    fields = parse_mssql_browser_response(reply)
    assert fields["ServerName"] == "SRV01"
    assert fields["InstanceName"] == "MSSQLSERVER"
    assert fields["Version"] == "15.0.2000.5"


def test_only_the_first_instance_is_reported():
    """Un servidor con varias instancias las separa con ';;'. Un fingerprint
    reporta un servicio, no una lista."""
    payload = (b"ServerName;SRV01;InstanceName;UNO;Version;15.0.2000.5;;"
               b"ServerName;SRV01;InstanceName;DOS;Version;13.0.5026.0;;")
    reply = b"\x05" + struct.pack("<H", len(payload)) + payload
    assert parse_mssql_browser_response(reply)["InstanceName"] == "UNO"


@pytest.mark.parametrize("data", [b"", b"\x05\x00\x00", b"\x05\x00\x00solo-una-clave"])
def test_an_unreadable_browser_reply_yields_nothing(data):
    assert parse_mssql_browser_response(data) == {}


# =========================================================== los dissectors


@pytest.mark.parametrize("dissector, probe_class, port, reply, product", [
    (DnsDissector, DnsProbe, 53, _dns_reply(), "BIND"),
    (NtpDissector, NtpProbe, 123,
     _ntp_readvar_reply(b'version="ntpd 4.2.8p15@1.3728-o"'), "ntpd"),
    (IkeDissector, IkeProbe, 500, _ike_reply(), "IKE"),
])
def test_each_dissector_reports_what_its_probe_read(dissector, probe_class, port,
                                                    reply, product):
    result = dissector(probe=probe_class(sender=_sender(reply))).probe(
        "10.0.0.5", Service(port, "udp", ""), _NullLimiter())
    assert result.product == product


def test_the_netbios_dissector_puts_the_asset_identity_in_its_label():
    reply = _netbios_reply([("WIN-SRV01", 0x0400), ("CORP", 0x8400)])
    result = NetbiosDissector(probe=NetbiosProbe(sender=_sender(reply))).probe(
        "10.0.0.5", Service(137, "udp", ""), _NullLimiter())
    assert result.label == "NetBIOS en WIN-SRV01 (CORP)"


def test_the_browser_dissector_reports_the_product_and_its_instance():
    payload = b"ServerName;SRV01;InstanceName;MSSQLSERVER;Version;15.0.2000.5;;"
    reply = b"\x05" + struct.pack("<H", len(payload)) + payload
    result = MssqlBrowserDissector(
        probe=MssqlBrowserProbe(sender=_sender(reply))).probe(
            "10.0.0.5", Service(1434, "udp", ""), _NullLimiter())
    assert (result.product, result.version) == ("Microsoft SQL Server", "15.0.2000.5")
    assert result.label == "MSSQL Browser (MSSQLSERVER)"


@pytest.mark.parametrize("dissector, probe_class, port", [
    (DnsDissector, DnsProbe, 53),
    (NtpDissector, NtpProbe, 123),
    (NetbiosDissector, NetbiosProbe, 137),
    (IkeDissector, IkeProbe, 500),
    (MssqlBrowserDissector, MssqlBrowserProbe, 1434),
])
def test_a_silent_service_produces_no_identification(dissector, probe_class, port):
    result = dissector(probe=probe_class(sender=_sender(None))).probe(
        "10.0.0.5", Service(port, "udp", ""), _NullLimiter())
    assert result is None


# ================================================ el barrido, ahora concurrente


def test_the_sweep_reports_only_the_ports_that_answered():
    answered = scan_udp_ports_sync(
        "10.0.0.5", sender=lambda _h, port, _p, _t: b"x" if port in (53, 161) else None)
    assert answered == [53, 161]


def test_a_port_without_a_row_in_the_table_is_ignored():
    """No hay payload que enviarle: preguntarle algo sería mandar ruido."""
    assert scan_udp_ports_sync("10.0.0.5", ports=[9999],
                               sender=lambda *_args: b"x") == []


def test_the_sweep_probes_the_ports_concurrently():
    """Con siete filas, un reintento y dos segundos de plazo, el peor caso
    secuencial son veintiocho segundos contra un host que probablemente no
    tenga ninguno de esos servicios."""
    import threading

    seen = set()
    barrier = threading.Barrier(len(UDP_PROBES), timeout=5.0)

    def send(_host, port, _payload, _timeout):
        seen.add(port)
        barrier.wait()          # cuelga si las sondas no van a la vez
        return None

    scan_udp_ports_sync("10.0.0.5", sender=send, retries=0)
    assert seen == set(UDP_PROBES)


def test_the_time_budget_stops_the_sweep_without_calling_anything_closed():
    """Agotar el presupuesto no marca nada como cerrado —en UDP nunca lo es—:
    los puertos que no llegaron a contestar se quedan como no observados, que
    es lo que ya eran."""
    ticks = iter([0.0] + [99.0] * 100)
    probed = []

    def send(_host, port, _payload, _timeout):
        probed.append(port)
        return b"x"

    answered = scan_udp_ports_sync("10.0.0.5", sender=send, budget_seconds=1.0,
                                   clock=lambda: next(ticks))
    assert answered == []
    assert probed == []


def test_a_budget_of_zero_means_no_limit():
    answered = scan_udp_ports_sync("10.0.0.5", budget_seconds=0,
                                   sender=lambda *_args: b"x")
    assert answered == sorted(UDP_PROBES)


# ================================================================ los checks


class _Context:
    def __init__(self, port):
        self.target = "10.0.0.5"
        self.service = Service(port, "udp", "")
        self.sibling_services = ()

    def acquire(self):
        pass


def test_the_open_resolver_check_follows_the_flag_the_server_sets():
    from src.modules.features.themis.lybra.script_checks import DnsOpenResolverPlugin

    def plugin(reply):
        return DnsOpenResolverPlugin(probe=DnsProbe(sender=_sender(reply)))

    open_resolver = _dns_reply(flags=0x8180 | DNS_FLAG_RECURSION_AVAILABLE)
    authoritative = _dns_reply(flags=0x8100)
    assert plugin(open_resolver).run(_Context(53)) is True
    assert plugin(authoritative).run(_Context(53)) is False
    assert plugin(None).run(_Context(53)) is False


def test_the_monlist_check_follows_the_servers_answer():
    from src.modules.features.themis.lybra.script_checks import NtpMonlistPlugin

    def plugin(reply):
        return NtpMonlistPlugin(probe=NtpProbe(sender=_sender(reply)))

    answered = struct.pack("!BB", 0x17, 0x80) + b"\x00" * 10
    errored = struct.pack("!BB", 0x17, 0xC0) + b"\x00" * 10
    assert plugin(answered).run(_Context(123)) is True
    assert plugin(errored).run(_Context(123)) is False
    assert plugin(None).run(_Context(123)) is False


@pytest.mark.parametrize("check_id, service, severity", [
    ("dns-open-resolver", "dns", "MEDIUM"),
    ("ntp-monlist-enabled", "ntp", "HIGH"),
])
def test_the_amplification_checks_are_registered(check_id, service, severity):
    from src.modules.features.themis.lybra.checks import load_checks
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    check = next(c for c in load_checks() if c.id == check_id)
    assert (check.service, check.severity, check.mode) == (service, severity, "safe")
    assert check.script in default_script_plugins()
