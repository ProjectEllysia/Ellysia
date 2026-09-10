"""El dissector de LDAP.

En una red corporativa con Active Directory el 389 está abierto siempre, y
LDAP tiene una consulta estándar y anónima diseñada para esto: el rootDSE.

La codificación es BER, la misma familia que el GetRequest de SNMP que ya se
construyó a mano. La diferencia práctica —y la que más tests tiene aquí— es
que hay que **leer** longitudes en forma larga, no sólo escribirlas en forma
corta: una lista de atributos pasa de 127 bytes con facilidad.
"""

import pytest

from src.modules.features.themis.lybra.checks import LDAPS_PORTS, is_ldap_service
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.ldap import (
    RESULT_INAPPROPRIATE_AUTHENTICATION,
    RESULT_SUCCESS,
    ROOTDSE_ATTRIBUTES,
    TAG_BIND_RESPONSE,
    TAG_SEARCH_ENTRY,
    LdapDissector,
    LdapProbe,
    ber,
    build_anonymous_bind,
    build_rootdse_search,
    encode_length,
    fingerprint_ldap,
    parse_bind_response,
    parse_search_entry,
    read_length,
    read_tlv,
)

pytestmark = pytest.mark.unit


def _message(message_id, operation_tag, operation_body):
    return ber(0x30, ber(0x02, bytes((message_id,))) + ber(operation_tag, operation_body))


def _bind_reply(result_code):
    body = ber(0x0A, bytes((result_code,))) + ber(0x04, b"") + ber(0x04, b"")
    return _message(1, TAG_BIND_RESPONSE, body)


def _attribute(name, values):
    return ber(0x30, ber(0x04, name.encode()) + ber(
        0x31, b"".join(ber(0x04, value.encode()) for value in values)))


def _search_reply(attributes):
    body = ber(0x04, b"") + ber(0x30, b"".join(
        _attribute(name, values) for name, values in attributes.items()))
    return _message(2, TAG_SEARCH_ENTRY, body)


OPENLDAP_ROOTDSE = _search_reply({
    "vendorName": ["Apache Software Foundation"],
    "vendorVersion": ["2.0.0"],
    "namingContexts": ["DC=empresa,DC=local"],
    "supportedSASLMechanisms": ["GSSAPI", "DIGEST-MD5"],
})

# Active Directory no publica vendorName ni vendorVersion: se identifica por
# sus contextos de nombres y por sus mecanismos.
ACTIVE_DIRECTORY_ROOTDSE = _search_reply({
    "namingContexts": ["DC=corp,DC=empresa,DC=com",
                       "CN=Configuration,DC=corp,DC=empresa,DC=com"],
    "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
    "supportedLDAPVersion": ["3", "2"],
})


# ====================================================================== BER


@pytest.mark.parametrize("length, encoded", [
    (0, b"\x00"),
    (127, b"\x7f"),
    (128, b"\x81\x80"),
    (255, b"\x81\xff"),
    (256, b"\x82\x01\x00"),
])
def test_lengths_use_the_short_form_up_to_127_and_the_long_form_after(length, encoded):
    assert encode_length(length) == encoded


@pytest.mark.parametrize("length", [0, 1, 127, 128, 300, 70000])
def test_a_written_length_reads_back_the_same(length):
    encoded = encode_length(length)
    assert read_length(encoded, 0) == (length, len(encoded))


def test_a_long_form_value_survives_the_round_trip():
    """El caso que obliga a implementar la forma larga: un valor de más de 127
    bytes, que es lo normal en una respuesta de rootDSE."""
    payload = b"x" * 500
    tag, value, end = read_tlv(ber(0x04, payload), 0)
    assert (tag, value) == (0x04, payload)
    assert end == len(ber(0x04, payload))


@pytest.mark.parametrize("data", [
    b"",
    b"\x04",                       # etiqueta sin longitud
    b"\x04\x05ab",                 # valor truncado
    b"\x04\x82\x01",               # forma larga truncada
    b"\x04\x80",                   # longitud indefinida, no permitida en LDAP
])
def test_a_truncated_tlv_raises_instead_of_returning_garbage(data):
    with pytest.raises(ValueError):
        read_tlv(data, 0)


# ================================================ los mensajes que se envían


def test_the_anonymous_bind_is_the_exact_message_the_rfc_fixes():
    """El artefacto verificable a ojo de este módulo: un bind LDAPv3 anónimo
    son catorce bytes y no admite variantes."""
    assert build_anonymous_bind().hex() == "300c020101600702010304008000"


def test_the_anonymous_bind_carries_no_password():
    """No es un intento de adivinar credenciales: es la forma que el protocolo
    define para preguntar sin identificarse (RFC 4511 §4.2), y lo que se
    observa es si el servidor la acepta."""
    request = build_anonymous_bind()
    assert request.endswith(b"\x04\x00\x80\x00")     # nombre vacío, clave vacía


def test_the_rootdse_search_asks_only_for_the_attributes_it_consumes():
    request = build_rootdse_search()
    for name in ROOTDSE_ATTRIBUTES:
        assert name.encode() in request
    # Base vacía y ámbito baseObject: no se recorre ni una entrada del
    # directorio, sólo se pregunta por la raíz.
    assert b"objectClass" in request


def test_the_rootdse_search_needs_the_long_form_and_declares_it_right():
    """Con cinco atributos el mensaje pasa de 127 bytes, así que este mensaje
    es el que ejercita la forma larga al escribir."""
    request = build_rootdse_search()
    assert len(request) > 127
    tag, value, end = read_tlv(request, 0)
    assert tag == 0x30 and end == len(request) and value


# ========================================================== las respuestas


def test_a_successful_bind_is_read_as_success():
    assert parse_bind_response(_bind_reply(RESULT_SUCCESS)) == RESULT_SUCCESS


def test_a_rejected_bind_is_read_as_its_own_code():
    reply = _bind_reply(RESULT_INAPPROPRIATE_AUTHENTICATION)
    assert parse_bind_response(reply) == RESULT_INAPPROPRIATE_AUTHENTICATION


@pytest.mark.parametrize("data", [b"", b"\x30\x00", b"no es LDAP"])
def test_an_unreadable_bind_reply_yields_nothing(data):
    assert parse_bind_response(data) is None


def test_the_rootdse_attributes_are_read_with_all_their_values():
    attributes = parse_search_entry(ACTIVE_DIRECTORY_ROOTDSE)
    assert attributes["namingContexts"] == [
        "DC=corp,DC=empresa,DC=com", "CN=Configuration,DC=corp,DC=empresa,DC=com"]
    assert "GSSAPI" in attributes["supportedSASLMechanisms"]


def test_a_search_reply_that_is_not_ldap_yields_no_attributes():
    assert parse_search_entry(b"HTTP/1.1 400 Bad Request") == {}


# ========================================================== el fingerprint


def test_an_openldap_style_server_names_itself():
    fingerprint = fingerprint_ldap(_bind_reply(RESULT_SUCCESS), OPENLDAP_ROOTDSE)
    assert fingerprint.product == "Apache Software Foundation"
    assert fingerprint.version == "2.0.0"
    assert fingerprint.naming_contexts == ("DC=empresa,DC=local",)
    assert fingerprint.allows_anonymous_bind


def test_active_directory_is_identified_even_without_a_vendor_name():
    """AD no publica `vendorName` ni `vendorVersion`. Se le reconoce igual como
    servicio LDAP, y lo que aporta —el nombre de dominio— es el mejor
    identificador de activo que puede llegar a un informe."""
    fingerprint = fingerprint_ldap(_bind_reply(RESULT_SUCCESS), ACTIVE_DIRECTORY_ROOTDSE)
    assert fingerprint.product == "LDAP"
    assert fingerprint.version is None
    assert fingerprint.naming_contexts[0] == "DC=corp,DC=empresa,DC=com"


def test_a_server_that_rejects_the_anonymous_bind_is_not_flagged():
    reply = _bind_reply(RESULT_INAPPROPRIATE_AUTHENTICATION)
    fingerprint = fingerprint_ldap(reply, b"")
    assert fingerprint.product == "LDAP"          # contestó LDAP, se identifica
    assert not fingerprint.allows_anonymous_bind  # pero no deja mirar


def test_something_that_is_not_ldap_is_not_identified():
    assert fingerprint_ldap(b"+OK POP3 ready\r\n", b"<html>").product is None


# ================================================================ la sonda


class _ScriptedSocket:
    def __init__(self, replies, sent):
        self._replies = list(replies)
        self._sent = sent

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self._sent.append(payload)

    def recv(self, _size):
        return self._replies.pop(0) if self._replies else b""

    def close(self):
        pass


def _probe_with(replies):
    sent = []
    return LdapProbe(connect=lambda _a, _t: _ScriptedSocket(replies, sent)), sent


def test_the_probe_binds_before_searching():
    """Un SearchRequest sólo tiene sentido sobre una sesión ya vinculada,
    aunque sea anónimamente: el orden lo pide el protocolo."""
    probe, sent = _probe_with([_bind_reply(RESULT_SUCCESS), OPENLDAP_ROOTDSE])
    probe.fetch("10.0.0.5")
    assert sent == [build_anonymous_bind(), build_rootdse_search()]


def test_a_server_that_says_nothing_yields_nothing():
    probe, _sent = _probe_with([b""])
    assert probe.fetch("10.0.0.5") is None


def test_a_refused_connection_yields_nothing():
    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    assert LdapProbe(connect=refuse).fetch("10.0.0.5") is None


# ============================================================ el dissector


class _NullLimiter:
    def acquire(self, _host):
        pass


def test_the_dissector_claims_the_directory_ports():
    dissector = LdapDissector()
    for port in (389, 636, 3268, 3269):
        assert dissector.applies(Service(port, "tcp", ""))
    assert dissector.applies(Service(1389, "tcp", "ldap"))
    assert not dissector.applies(Service(80, "tcp", "http"))
    assert is_ldap_service(Service(389, "tcp", ""))


def test_the_dissector_reports_what_the_rootdse_published():
    probe, _sent = _probe_with([_bind_reply(RESULT_SUCCESS), OPENLDAP_ROOTDSE])
    result = LdapDissector(probe=probe).probe(
        "10.0.0.5", Service(389, "tcp", "ldap"), _NullLimiter())
    assert (result.product, result.version, result.label) == (
        "Apache Software Foundation", "2.0.0", "LDAP")


# ================================================================ los checks


class _Context:
    def __init__(self, port=389, siblings=()):
        self.target = "10.0.0.5"
        self.service = Service(port, "tcp", "ldap")
        self.sibling_services = siblings

    def acquire(self):
        pass


def _anonymous_plugin(replies):
    from src.modules.features.themis.lybra.script_checks import LdapAnonymousBindPlugin
    probe, _sent = _probe_with(replies)
    return LdapAnonymousBindPlugin(probe=probe)


def test_the_anonymous_bind_check_follows_the_servers_answer():
    accepted = [_bind_reply(RESULT_SUCCESS), OPENLDAP_ROOTDSE]
    rejected = [_bind_reply(RESULT_INAPPROPRIATE_AUTHENTICATION), b""]
    assert _anonymous_plugin(accepted).run(_Context()) is True
    assert _anonymous_plugin(rejected).run(_Context()) is False


def test_the_anonymous_bind_check_stays_quiet_without_evidence():
    from src.modules.features.themis.lybra.script_checks import LdapAnonymousBindPlugin

    def refuse(_address, _timeout):
        raise ConnectionRefusedError("cerrado")

    plugin = LdapAnonymousBindPlugin(probe=LdapProbe(connect=refuse))
    assert plugin.run(_Context()) is False


def _cleartext_plugin():
    from src.modules.features.themis.lybra.script_checks import (
        LdapCleartextWithLdapsPlugin,
    )
    return LdapCleartextWithLdapsPlugin()


def test_the_cleartext_check_needs_an_ldaps_sibling_to_fire():
    """El primer check del motor que no es propiedad de un servicio sino de la
    relación entre dos. Un 389 solo no dice gran cosa; un 389 junto a un 636
    dice que la versión cifrada existe y que la de claro sigue abierta."""
    plugin = _cleartext_plugin()
    alone = _Context(389, siblings=(Service(389, "tcp", "ldap"),))
    with_ldaps = _Context(389, siblings=(Service(389, "tcp", "ldap"),
                                         Service(636, "tcp", "ldaps")))
    assert plugin.run(alone) is False
    assert plugin.run(with_ldaps) is True


def test_the_cleartext_check_never_applies_to_the_encrypted_port_itself():
    plugin = _cleartext_plugin()
    for port in LDAPS_PORTS:
        assert not plugin.applies(Service(port, "tcp", "ldaps"))
    assert plugin.applies(Service(389, "tcp", "ldap"))


def test_the_cleartext_check_makes_no_network_request():
    """La evidencia son dos puertos que el descubrimiento ya encontró: no hay
    ninguna petición que hacer, y por eso el plugin no recibe sonda."""
    plugin = _cleartext_plugin()
    assert not hasattr(plugin, "_probe")


def test_both_ldap_checks_are_registered_and_wired_to_their_feed_entries():
    from src.modules.features.themis.lybra.checks import load_checks
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    plugins = default_script_plugins()
    for check_id in ("ldap-anonymous-bind", "ldap-cleartext-with-ldaps"):
        check = next(c for c in load_checks() if c.id == check_id)
        assert check.service == "ldap" and check.mode == "safe"
        assert check.script in plugins
