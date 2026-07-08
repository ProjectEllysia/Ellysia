"""Unit tests for the Lybra engine (Fase 0) and the Nmap CPE capture refactor.

Pure logic: no DB, no network. Verifies the two things Fase 0 introduces below
the manager — the engine turning services into informational findings, and Nmap's
``<cpe>`` surviving the parser all the way into ``ports_data``.
"""

import types

import pytest

from src.modules.sentinel.lybra import (
    LybraEngine,
    Service,
    services_from_open_ports,
    QOD_OPEN_PORT,
)
from src.modules.sentinel.services.processors import NmapResultProcessor

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

def _fake_cve(cve_id="CVE-2021-41773"):
    return types.SimpleNamespace(
        cve_id=cve_id, cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N", severity="HIGH",
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
