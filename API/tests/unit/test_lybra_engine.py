"""Unit tests for the Lybra engine (Fase 0) and the Nmap CPE capture refactor.

Pure logic: no DB, no network. Verifies the two things Fase 0 introduces below
the manager — the engine turning services into informational findings, and Nmap's
``<cpe>`` surviving the parser all the way into ``ports_data``.
"""

import types

import pytest

from src.modules.features.themis.lybra import (
    LybraEngine,
    Service,
    services_from_open_ports,
    services_from_payload,
    QOD_OPEN_PORT,
    QOD_INVENTORY_MATCH,
    version_in_range,
)
from src.modules.features.themis.services.processors import NmapResultProcessor

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------ engine core

def test_analyze_emits_one_informational_finding_per_service():
    services = [
        Service(port=80, protocol="tcp", name="http", product="Apache httpd",
                version="2.4.49", cpe="cpe:/a:apache:http_server:2.4.49"),
        Service(port=22, protocol="tcp", name="ssh", product="OpenSSH", version="7.4"),
    ]

    findings = LybraEngine().analyze(services)

    assert len(findings) == 2
    http = findings[0]
    assert http["category"] == "open_port"
    assert http["qod"] == QOD_OPEN_PORT == 30
    assert http["source"] == "lybra"
    assert http["confirmed"] is False
    assert http["state"] == "open"
    assert http["feed_version"] == "lybra-0"
    assert http["check_id"] == "lybra:open-port@1"
    # Title carries where + what, and the CPE is preserved for later phases.
    assert "80/tcp" in http["title"]
    assert "Apache httpd 2.4.49" in http["title"]
    # Normalized to 2.3, consistent with the version-match finding's cpe (a
    # consumer grouping by cpe should see one format, not Nmap's raw 2.2 here).
    assert http["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    # A service without a CPE stores None, not "".
    assert findings[1]["cpe"] is None


def test_analyze_no_services_returns_empty():
    assert LybraEngine().analyze([]) == []


def test_service_label_falls_back_when_product_missing():
    assert Service(port=53, protocol="udp", name="domain").label == "domain"
    assert Service(port=1, protocol="tcp").label == "servicio desconocido"


# ------------------------------------------------- OpenPort -> Service mapping

def _open_port(protocol, product="", version="", given_use="", cpe=None):
    """A duck-typed OpenPort row (only the attributes the mapper reads)."""
    return types.SimpleNamespace(
        port=types.SimpleNamespace(protocol=protocol),
        product=product, version=version, given_use=given_use, cpe=cpe,
    )


def test_services_from_open_ports_parses_protocol_and_fields():
    rows = [_open_port("80/tcp", "Apache httpd", "2.4.49", "http",
                        "cpe:/a:apache:http_server:2.4.49")]

    services = services_from_open_ports(rows)

    assert services == [Service(
        port=80, protocol="tcp", name="http", product="Apache httpd",
        version="2.4.49", cpe="cpe:/a:apache:http_server:2.4.49",
    )]


def test_services_from_open_ports_tolerates_malformed_protocol():
    # A blank or non-numeric protocol must degrade to port=None, never raise.
    assert services_from_open_ports([_open_port("")])[0].port is None
    assert services_from_open_ports([_open_port("abc/tcp")])[0].port is None
    assert services_from_open_ports([_open_port("")])[0].protocol == "tcp"


# ------------------------------------------------------- Nmap CPE capture (§2.1)

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV 10.0.0.5" version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_processor_keeps_cpe_in_ports_data():
    _host, ports = NmapResultProcessor().process(_NMAP_XML, "10.0.0.5")

    by_proto = {p["protocol"]: p for p in ports}
    assert by_proto["80/tcp"]["cpe"] == "cpe:/a:apache:http_server:2.4.49"
    assert by_proto["80/tcp"]["product"] == "Apache httpd"
    assert by_proto["80/tcp"]["version"] == "2.4.49"
    # No <cpe> element -> empty string (persistence coerces to NULL).
    assert by_proto["22/tcp"]["cpe"] == ""


# ------------------------------------------------ version matcher (Fase 1)

def _fake_cve(cve_id="CVE-2021-41773", required_os=None):
    return types.SimpleNamespace(
        cve_id=cve_id, cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N", severity="HIGH",
        required_os=required_os,
    )


def _lookup_for(expected_vendor_product, calls=None):
    """A cve_lookup that returns one CVE only for the expected (vendor, product)."""
    def lookup(vendor, product, version):
        if calls is not None:
            calls.append((vendor, product, version))
        return [_fake_cve()] if (vendor, product) == expected_vendor_product else []
    return lookup


def test_no_cve_lookup_means_informational_only():
    # Fase 0 behaviour preserved when no lookup is wired.
    engine = LybraEngine()
    findings = engine.analyze([Service(80, "tcp", "http", "Apache httpd", "2.4.49",
                                       "cpe:/a:apache:http_server:2.4.49")])
    assert [f["category"] for f in findings] == ["open_port"]


def test_version_finding_from_nmap_cpe():
    calls = []
    engine = LybraEngine(
        cve_lookup=_lookup_for(("apache", "http_server"), calls),
        kev_lookup=lambda cid: True,
        epss_lookup=lambda cid: 0.97,
    )
    service = Service(80, "tcp", "http", "Apache httpd", "2.4.49",
                      "cpe:/a:apache:http_server:2.4.49")

    findings = engine.analyze([service])

    # The CPE resolved to (vendor, product, version) for the lookup.
    assert calls == [("apache", "http_server", "2.4.49")]
    categories = [f["category"] for f in findings]
    assert categories == ["open_port", "outdated_software"]

    vuln = findings[1]
    assert vuln["cve_ids"] == ["CVE-2021-41773"]
    assert vuln["cvss_score"] == 7.5
    assert vuln["qod"] == 70
    assert vuln["confirmed"] is False
    assert vuln["in_kev"] is True
    assert vuln["epss_score"] == 0.97
    assert vuln["check_id"] == "lybra:version-match@1"
    assert vuln["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_version_finding_carries_required_os_from_the_cve_lookup():
    """#118: a cve_lookup result flagged with a platform gate (KbRepository's
    transient CveEntry.required_os) must reach the finding dict, so
    score_finding can avoid crowning an unverifiable platform hypothesis as
    CRITICAL."""
    engine = LybraEngine(cve_lookup=lambda *a: [_fake_cve(required_os="windows_10")])
    service = Service(80, "tcp", "http", "Apache httpd", "2.4.59",
                      "cpe:/a:apache:http_server:2.4.59")

    findings = engine.analyze([service])

    vuln = findings[1]
    assert vuln["required_os"] == "windows_10"


def test_version_finding_required_os_defaults_to_none():
    """A cve_lookup result with no required_os attribute at all (a stub, or a
    genuinely unconditional match) must not blow up — getattr defaults it."""
    engine = LybraEngine(cve_lookup=_lookup_for(("apache", "http_server")))
    service = Service(80, "tcp", "http", "Apache httpd", "2.4.49",
                      "cpe:/a:apache:http_server:2.4.49")

    findings = engine.analyze([service])

    assert findings[1]["required_os"] is None


def test_version_finding_via_override_when_no_cpe():
    # No CPE from Nmap; product string resolves through the override table.
    calls = []
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh"), calls))
    findings = engine.analyze([Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)])

    assert calls == [("openbsd", "openssh", "7.4")]
    assert findings[1]["cpe"] == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"


def test_no_version_finding_without_a_concrete_version():
    calls = []
    engine = LybraEngine(cve_lookup=_lookup_for(("apache", "http_server"), calls))
    # Unknown product + wildcard version -> nothing to match, lookup not called.
    findings = engine.analyze([Service(80, "tcp", "http", "weird-server", "*", None)])

    assert calls == []
    assert [f["category"] for f in findings] == ["open_port"]


# --------------------------------- Fase I-b: the automated CPE index (paso 2)

def test_version_finding_via_product_alias_lookup_when_override_misses():
    """The third strategy: a product the curated table has never heard of,
    resolved through the injected KB-backed index instead."""
    calls = []

    def alias_lookup(normalized_name):
        assert normalized_name == "docker desktop"  # already normalized before the call
        return ("docker", "docker_desktop")

    engine = LybraEngine(
        cve_lookup=_lookup_for(("docker", "docker_desktop"), calls),
        product_alias_lookup=alias_lookup,
    )
    findings = engine.analyze([
        Service(port=None, protocol="", product="Docker Desktop", version="4.80.0", origin="inventory"),
    ])

    assert calls == [("docker", "docker_desktop", "4.80.0")]
    assert findings[1]["cpe"] == "cpe:2.3:a:docker:docker_desktop:4.80.0:*:*:*:*:*:*:*"


def test_product_alias_lookup_never_called_when_curated_override_already_hit():
    """Strategy 2 (curated feed) wins over strategy 3 — the index is the
    fallback, not consulted when the hand-verified table already resolved it."""
    calls = []

    def alias_lookup(_normalized_name):
        calls.append(_normalized_name)
        return ("wrong", "vendor")  # would prove the index was consulted if it were

    engine = LybraEngine(
        cve_lookup=lambda vendor, product, version: [],
        product_alias_lookup=alias_lookup,
    )
    engine.analyze([Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)])  # in the curated feed

    assert calls == []


def test_product_alias_lookup_not_consulted_without_a_concrete_version():
    calls = []

    def alias_lookup(_normalized_name):
        calls.append(_normalized_name)
        return None

    engine = LybraEngine(cve_lookup=lambda *a: [], product_alias_lookup=alias_lookup)
    engine.analyze([Service(port=None, protocol="", product="Some App", version="*", origin="inventory")])

    assert calls == []


def test_embedded_version_in_the_product_name_still_resolves():
    """The real bug this session found: a Windows inventory entry that bakes
    the version straight into the name ("7-Zip 25.01 (x64)") must still
    normalize down to something the KB's clean "7-zip" product can match."""
    calls = []

    def alias_lookup(normalized_name):
        assert normalized_name == "7 zip"
        return ("7-zip", "7-zip")

    engine = LybraEngine(
        cve_lookup=_lookup_for(("7-zip", "7-zip"), calls),
        product_alias_lookup=alias_lookup,
    )
    findings = engine.analyze([
        Service(port=None, protocol="", product="7-Zip 25.01 (x64)", version="25.01", origin="inventory"),
    ])

    assert calls == [("7-zip", "7-zip", "25.01")]
    assert findings[1]["category"] == "outdated_software"


# ----------------------------------------------- Fase 0.9: external payload

def test_version_finding_from_inventory_origin_is_confirmed_with_high_qod():
    # A service read straight off a package manager (Service.origin=="inventory")
    # is a verified fact, not a banner guess: it should be born confirmed at a
    # higher qod than the default network-inferred hypothesis.
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh")))
    service = Service(port=None, protocol="", name="", product="OpenSSH",
                      version="7.4", cpe=None, origin="inventory")

    findings = engine.analyze([service])

    vuln = findings[1]
    assert vuln["category"] == "outdated_software"
    assert vuln["qod"] == QOD_INVENTORY_MATCH == 95
    assert vuln["confirmed"] is True


def test_an_inventory_package_resolves_the_same_cves_as_its_upstream_version():
    """El criterio de cierre de #267, extremo a extremo dentro del motor.

    El inventario de un agente entrega versiones de paquete de distribución
    (`1:7.4-1ubuntu1`), y NVD sólo publica rangos sobre versiones de
    fabricante (`7.4`). Si el paquete no cae en los mismos rangos que su
    versión upstream, la Fase I entera —el sustituto del escaneo autenticado—
    mide otra cosa.

    La búsqueda que se inyecta aquí usa `version_in_range` de verdad, no una
    tabla de respuestas: lo que se comprueba es el camino completo, no que el
    doble diga que sí.
    """
    afectado = {"version_start_including": "7.0", "version_end_including": "7.4"}

    def lookup(vendor, product, version):
        return [_fake_cve()] if version_in_range(version, afectado) else []

    engine = LybraEngine(cve_lookup=lookup)
    upstream = Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)
    paquete = Service(port=None, protocol="", name="", product="OpenSSH",
                      version="1:7.4-1ubuntu1", cpe=None, origin="inventory")

    del_banner = [f for f in engine.analyze([upstream]) if f["category"] == "outdated_software"]
    del_paquete = [f for f in engine.analyze([paquete]) if f["category"] == "outdated_software"]

    assert len(del_banner) == 1
    assert [f["cve_ids"] for f in del_paquete] == [f["cve_ids"] for f in del_banner]


def test_a_normalized_version_says_so_in_the_finding():
    # Sin esto, el hallazgo es inexplicable de puertas afuera: nada en él da
    # cuenta de por qué un host con 1:7.4-1ubuntu1 sale contra un CVE cuyo
    # rango termina en 7.4.
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh")))
    paquete = Service(port=None, protocol="", name="", product="OpenSSH",
                      version="1:7.4-1ubuntu1", cpe=None, origin="inventory")

    vuln = [f for f in engine.analyze([paquete]) if f["category"] == "outdated_software"][0]

    assert "1:7.4-1ubuntu1" in vuln["title"]      # lo que se descubrió, tal cual
    assert "(upstream 7.4)" in vuln["title"]      # y contra qué se comparó


def test_a_plain_vendor_version_gets_no_normalization_note():
    # La nota sólo aparece donde hay algo que explicar.
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh")))
    findings = engine.analyze([Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)])

    assert "upstream" not in findings[1]["title"]


def test_version_finding_from_network_origin_stays_a_hypothesis():
    # Default origin ("network") behaviour is unchanged by Fase 0.9.
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh")))
    findings = engine.analyze([Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)])

    vuln = findings[1]
    assert vuln["qod"] == 70
    assert vuln["confirmed"] is False


def test_informational_finding_for_portless_inventory_service():
    # A library with no listening port must not read as "Puerto None abierto".
    service = Service(port=None, protocol="", name="", product="openssl",
                      version="1.1.1", cpe=None, origin="inventory")

    finding = LybraEngine().analyze([service])[0]

    assert finding["category"] == "installed_package"
    assert finding["title"] == "Paquete instalado — openssl 1.1.1"
    assert finding["port"] is None


def test_informational_finding_for_inventory_service_with_a_port_is_unaffected():
    # A daemon read from inventory that *does* have a port (rare, but the
    # dataclass allows it) keeps the ordinary "open port" phrasing — the
    # special case is specifically "no port to report", not "origin=inventory".
    service = Service(port=22, protocol="tcp", name="ssh", product="OpenSSH",
                      version="7.4", cpe=None, origin="inventory")

    finding = LybraEngine().analyze([service])[0]

    assert finding["category"] == "open_port"
    assert "22/tcp" in finding["title"]


# --------------------------------------- cpe_resolved observability (Fase I-b)

def test_informational_finding_flags_unresolved_cpe():
    # No override, no alias index wired: cannot resolve -> the informational
    # finding must say so explicitly instead of reading like a clean scan.
    service = Service(port=None, protocol="", product="Some Unknown App",
                       version="1.0", origin="inventory")

    finding = LybraEngine().analyze([service])[0]

    assert finding["category"] == "installed_package"
    assert finding["cpe_resolved"] is False


def test_informational_finding_flags_resolved_cpe():
    # In the curated feed (OpenSSH) -> resolvable even without a CVE hit.
    service = Service(port=None, protocol="", product="OpenSSH", version="7.4",
                       origin="inventory")

    finding = LybraEngine().analyze([service])[0]

    assert finding["cpe_resolved"] is True


def test_version_finding_carries_cpe_resolved_true():
    calls = []
    engine = LybraEngine(cve_lookup=_lookup_for(("openbsd", "openssh"), calls))

    findings = engine.analyze([Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)])

    version_finding = next(f for f in findings if f["category"] == "outdated_software")
    assert version_finding["cpe_resolved"] is True


def test_services_from_payload_builds_services_and_defaults_origin():
    services = services_from_payload([
        {"port": 21, "protocol": "tcp", "name": "ftp", "product": "vsftpd", "version": "2.3.4"},
    ])

    assert services == [Service(port=21, protocol="tcp", name="ftp",
                                product="vsftpd", version="2.3.4", cpe=None, origin="network")]


def test_services_from_payload_respects_explicit_origin_and_missing_port():
    services = services_from_payload([
        {"product": "openssl", "version": "1.1.1", "origin": "inventory"},
    ])

    assert services == [Service(port=None, protocol="", name="", product="openssl",
                                version="1.1.1", cpe=None, origin="inventory")]


def test_services_from_payload_empty_returns_empty():
    assert services_from_payload([]) == []
