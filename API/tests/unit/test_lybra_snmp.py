"""Tests unitarios del dissector SNMP y de su codificador/parser (Fase N/Ronda 1,
roadmap §6.3): sin red real, sin base de datos.

El codificador vive en ``transport.py`` (ver el docstring de
``fingerprinting/snmp.py`` sobre por qué) y el parser + dissector viven en
``fingerprinting/snmp.py``; este fichero cubre ambos.
"""

import pytest

from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.transport import build_snmp_get_request
from src.modules.features.themis.lybra.fingerprinting.snmp import (
    SnmpDissector,
    SnmpFingerprint,
    SnmpProbe,
    fingerprint_snmp,
    parse_snmp_sysdescr,
)

pytestmark = pytest.mark.unit


# =========================================================== build_snmp_get_request

def test_get_request_is_exact_ber():
    """El caso dorado: 40 bytes exactos, verificados a mano contra RFC 3416."""
    assert build_snmp_get_request().hex() == (
        "302602010104067075626c6963a019020101020100020100300e300c"
        "06082b060102010101000500"
    )


def test_get_request_community_changes_lengths():
    request = build_snmp_get_request("private")
    assert len(request) == 41  # "private" es un byte más largo que "public"
    # Las tres longitudes que envuelven la comunidad tienen que moverse en bloque.
    assert request[1] == len(request) - 2          # longitud del mensaje completo
    assert b"private" in request


def test_get_request_default_community_is_public():
    assert b"public" in build_snmp_get_request()


# ============================================================= parse_snmp_sysdescr

def _wrap_octet_string(value: bytes) -> bytes:
    """Construye el TLV del OID de sysDescr seguido de un valor OCTET STRING,
    con forma corta o larga de longitud según haga falta — lo mínimo que
    parse_snmp_sysdescr necesita para localizarlo."""
    oid = bytes.fromhex("06082b06010201010100")
    if len(value) < 128:
        length = bytes([len(value)])
    else:
        length_bytes = len(value).to_bytes(2, "big")
        length = bytes([0x80 | len(length_bytes)]) + length_bytes
    return oid + bytes([0x04]) + length + value


def test_parse_sysdescr_short_form():
    value = b"Linux host 5.15.0-84-generic"
    reply = _wrap_octet_string(value)
    assert parse_snmp_sysdescr(reply) == value.decode()


def test_parse_sysdescr_long_form():
    value = b"A" * 300  # supera 127 bytes: fuerza la forma larga de longitud
    reply = _wrap_octet_string(value)
    assert parse_snmp_sysdescr(reply) == value.decode()


def test_parse_returns_none_for_null_value():
    oid = bytes.fromhex("06082b06010201010100")
    reply = oid + bytes.fromhex("0500")  # NULL: sin valor
    assert parse_snmp_sysdescr(reply) is None


def test_parse_returns_none_for_nosuchobject_tag():
    oid = bytes.fromhex("06082b06010201010100")
    reply = oid + bytes([0x80, 0x00])  # noSuchObject, contexto 0x80
    assert parse_snmp_sysdescr(reply) is None


def test_parse_returns_none_for_truncated_reply():
    oid = bytes.fromhex("06082b06010201010100")
    reply = oid + bytes([0x04, 0x10]) + b"short"  # dice 16 bytes, trae menos
    assert parse_snmp_sysdescr(reply) is None


def test_parse_returns_none_for_garbage():
    assert parse_snmp_sysdescr(b"\x00\x01\x02not snmp at all") is None


def test_parse_returns_none_when_oid_missing():
    assert parse_snmp_sysdescr(b"") is None


# ================================================================ fingerprint_snmp

def test_fingerprint_snmp_never_yields_a_version():
    """El test que impide que alguien 'mejore' esto con una regex: sysDescr es
    texto libre del fabricante y una versión inventada de ahí alimentaría al
    matcher CPE->CVE con datos falsos."""
    fp = fingerprint_snmp("Linux host 5.15.0-84-generic #93-Ubuntu SMP x86_64")
    assert fp.version is None
    assert fp.product == "Linux host 5.15.0-84-generic #93-Ubuntu SMP x86_64"
    assert fp.confidence == pytest.approx(0.9)


def test_fingerprint_snmp_empty_sysdescr_is_no_result():
    assert fingerprint_snmp(None) == SnmpFingerprint(product=None, version=None, confidence=0.0)
    assert fingerprint_snmp("") == SnmpFingerprint(product=None, version=None, confidence=0.0)


# =================================================================== SnmpProbe

def test_probe_fetch_with_injected_sender():
    value = b"Cisco IOS Software"
    reply = _wrap_octet_string(value)
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: reply)
    assert probe.fetch("10.0.0.5") == value.decode()


def test_probe_fetch_returns_none_when_sender_returns_none():
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: None)
    assert probe.fetch("10.0.0.5") is None


def test_probe_fetch_sends_the_requested_community():
    captured = {}

    def sender(host, port, payload, timeout):
        captured["payload"] = payload
        return None

    SnmpProbe(sender=sender).fetch("10.0.0.5", community="private")
    assert captured["payload"] == build_snmp_get_request("private")


# ================================================================ SnmpDissector

class _FakeRateLimiter:
    def __init__(self):
        self.calls = []

    def acquire(self, host):
        self.calls.append(host)


@pytest.mark.parametrize("protocol,port,expected", [
    ("udp", 161, True),
    ("tcp", 161, False),   # el mismo puerto por TCP nunca contestará al datagrama
    ("", 161, False),      # servicio de inventario (protocolo vacío)
    ("udp", 9999, False),  # UDP pero puerto sin relación con SNMP
])
def test_snmp_dissector_applies_only_to_snmp_over_udp(protocol, port, expected):
    dissector = SnmpDissector()
    assert dissector.applies(Service(port=port, protocol=protocol)) is expected


def test_snmp_dissector_probe_returns_result():
    value = b"Linux router 5.4.0"
    reply = _wrap_octet_string(value)
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: reply)
    dissector = SnmpDissector(probe=probe)
    limiter = _FakeRateLimiter()

    result = dissector.probe("10.0.0.5", Service(port=161, protocol="udp"), limiter)

    assert result is not None
    assert result.product == value.decode()
    assert result.version is None
    assert result.label == "SNMP"
    assert limiter.calls == ["10.0.0.5"]


def test_snmp_dissector_probe_returns_none_without_reply():
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: None)
    dissector = SnmpDissector(probe=probe)
    result = dissector.probe("10.0.0.5", Service(port=161, protocol="udp"), _FakeRateLimiter())
    assert result is None
