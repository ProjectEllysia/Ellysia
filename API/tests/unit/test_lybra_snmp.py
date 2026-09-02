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

def test_fingerprint_snmp_never_invents_a_version_from_free_text():
    """El test que impide que alguien 'mejore' esto con una regex genérica.

    Sigue siendo cierto lo que decía cuando la versión no se extraía nunca:
    sysDescr es texto libre del fabricante, y una versión adivinada de ahí
    alimentaría al matcher CPE→CVE con datos falsos. Lo que L21 cambia es de
    dónde puede salir una versión —de un patrón por fabricante, con su
    muestra— no que pueda salir de cualquier sitio.
    """
    fp = fingerprint_snmp("Aparato de fabricante desconocido, revisión interna 7")
    assert fp.version is None
    assert fp.vendor is None
    assert fp.matched_pattern is False
    # El texto crudo se conserva como producto: un sysDescr sin reconocer sigue
    # siendo el dato más informativo que hay sobre ese aparato.
    assert fp.product == "Aparato de fabricante desconocido, revisión interna 7"
    assert fp.confidence == pytest.approx(0.9)


# ======================================== patrones de sysDescr por fabricante


def _patterns():
    from src.modules.features.themis.lybra.fingerprinting.snmp import (
        load_sysdescr_patterns,
    )
    return load_sysdescr_patterns()


def test_the_bundled_pattern_feed_is_well_formed():
    from src.modules.features.themis.lybra.fingerprinting.snmp import (
        validate_sysdescr_patterns,
    )
    patterns = _patterns()
    assert validate_sysdescr_patterns(patterns) == []
    # El criterio de cierre del issue: al menos cinco familias de sysDescr.
    assert len({entry.product for entry in patterns}) >= 5


def test_every_pattern_recognises_its_own_sample():
    """La regla del feed —sin muestra no hay patrón— comprobada de verdad. Un
    patrón que no reconoce ni el ejemplo que lo acompaña no va a reconocer un
    aparato real."""
    from src.modules.features.themis.lybra.fingerprinting.snmp import match_sysdescr

    for entry in _patterns():
        matched = match_sysdescr(entry.sample)
        assert matched is not None, f"{entry.product} no casa con su muestra"
        assert matched.product == entry.product
        assert matched.vendor == entry.vendor


def test_no_pattern_matches_another_vendors_sample():
    """**El test que de verdad protege el feed.**

    Que un patrón case con lo suyo es fácil; lo peligroso es que case de más.
    Un patrón goloso se lleva el sysDescr de otro fabricante y produce un
    producto equivocado con una versión equivocada — un falso positivo que
    parece perfectamente creíble. Esta matriz cruzada lo delata en cuanto
    alguien añade una entrada demasiado laxa.
    """
    from src.modules.features.themis.lybra.fingerprinting.snmp import match_sysdescr

    patterns = _patterns()
    for entry in patterns:
        for other in patterns:
            if other.product == entry.product:
                continue
            matched = match_sysdescr(other.sample)
            assert matched is not None
            assert matched.product != entry.product or entry.pattern.search(other.sample) is None, (
                f"el patrón de {entry.product} se lleva la muestra de {other.product}")


def test_a_pattern_may_identify_a_product_without_any_version():
    """La impresora HP anuncia su modelo y no su firmware. Producto sí, versión
    no: sigue siendo mucho más que el texto crudo, y no se fabrica nada."""
    from src.modules.features.themis.lybra.fingerprinting.snmp import match_sysdescr

    printer = ("HP ETHERNET MULTI-ENVIRONMENT,SN:CNB1234567,FN:JW123AB,"
               "SVCID:25086,PID:HP LaserJet M402dn")
    matched = match_sysdescr(printer)
    assert matched.product == "HP LaserJet"
    assert matched.version is None
    assert fingerprint_snmp(printer).version is None


@pytest.mark.parametrize("sysdescr, product, version", [
    ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, "
     "RELEASE SOFTWARE (fc3)", "Cisco IOS", "15.0(2)SE11"),
    ("Linux servidor01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64",
     "Linux Kernel", "5.15.0"),
    ("ProCurve J9085A Switch 2610-24, revision R.11.25, ROM R.10.06",
     "HP ProCurve", "R.11.25"),
    ("MikroTik RouterOS 6.48.6 (long-term) RB750Gr3", "MikroTik RouterOS", "6.48.6"),
    ("FortiGate-60E v6.4.5,build1828,210217 (GA)", "Fortinet FortiGate", "6.4.5"),
])
def test_each_vendor_family_yields_product_and_version(sysdescr, product, version):
    fp = fingerprint_snmp(sysdescr)
    assert (fp.product, fp.version) == (product, version)
    assert fp.matched_pattern is True


def test_a_matched_pattern_raises_the_qod_of_the_finding():
    """La tabla del §10 del roadmap: 'banner que coincide con un patrón
    específico del producto: qod 80'. Un sysDescr sin reconocer se queda con la
    constante informativa de siempre."""
    from src.modules.features.themis.lybra.engine import Service
    from src.modules.features.themis.lybra.fingerprinting.dispatch import (
        QOD_FINGERPRINT,
    )
    from src.modules.features.themis.lybra.fingerprinting.snmp import (
        QOD_VENDOR_PATTERN,
        SnmpDissector,
    )

    class _NullLimiter:
        def acquire(self, _host):
            pass

    class _Probe:
        def __init__(self, sysdescr):
            self._sysdescr = sysdescr

        def fetch(self, host, port=161, community="public"):
            return self._sysdescr

    service = Service(161, "udp", "snmp")
    known = SnmpDissector(probe=_Probe(
        "MikroTik RouterOS 6.48.6 (long-term) RB750Gr3")).probe(
            "10.0.0.5", service, _NullLimiter())
    unknown = SnmpDissector(probe=_Probe("Aparato raro")).probe(
        "10.0.0.5", service, _NullLimiter())

    assert known.qod == QOD_VENDOR_PATTERN
    assert unknown.qod == QOD_FINGERPRINT


def test_the_pattern_validator_finds_each_kind_of_breakage():
    """Sin este bloque, un validador que devolviera siempre `[]` dejaría el
    feed en verde para siempre."""
    import re

    from src.modules.features.themis.lybra.fingerprinting.snmp import (
        SysDescrPattern,
        validate_sysdescr_patterns,
    )

    sin_muestra = SysDescrPattern("acme", "Acme", re.compile("Acme"), "")
    sin_producto = SysDescrPattern("acme", "", re.compile("Acme"), "Acme 1.0")
    sin_fabricante = SysDescrPattern("", "Acme", re.compile("Acme"), "Acme 1.0")
    no_casa = SysDescrPattern("acme", "Acme", re.compile("Otra cosa"), "Acme 1.0")

    assert len(validate_sysdescr_patterns(sin_muestra and [sin_muestra])) == 1
    assert len(validate_sysdescr_patterns([sin_producto])) == 1
    assert len(validate_sysdescr_patterns([sin_fabricante])) == 1
    assert len(validate_sysdescr_patterns([no_casa])) == 1


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
    """Un sysDescr que ningún patrón reconoce: el texto crudo pasa tal cual
    como producto y no hay versión. Es el camino que L21 deja intacto."""
    value = b"Conmutador de fabricante desconocido, unidad 3"
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


def test_snmp_dissector_probe_uses_the_pattern_feed_when_it_recognises_the_text():
    """Y el que L21 añade: un sysDescr de una familia conocida sale con el
    nombre canónico del producto y con su versión."""
    value = "Linux servidor01 5.15.0-88-generic #98-Ubuntu SMP x86_64".encode()
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: _wrap_octet_string(value))
    result = SnmpDissector(probe=probe).probe(
        "10.0.0.5", Service(port=161, protocol="udp"), _FakeRateLimiter())

    assert (result.product, result.version) == ("Linux Kernel", "5.15.0")


def test_snmp_dissector_probe_returns_none_without_reply():
    probe = SnmpProbe(sender=lambda host, port, payload, timeout: None)
    dissector = SnmpDissector(probe=probe)
    result = dissector.probe("10.0.0.5", Service(port=161, protocol="udp"), _FakeRateLimiter())
    assert result is None
