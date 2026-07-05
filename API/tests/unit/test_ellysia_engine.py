"""Unit tests for the Ellysia engine (Fase 0) and the Nmap CPE capture refactor.

Pure logic: no DB, no network. Verifies the two things Fase 0 introduces below
the manager — the engine turning services into informational findings, and Nmap's
``<cpe>`` surviving the parser all the way into ``ports_data``.
"""

import types

import pytest

from src.modules.sentinel.ellysia import (
    EllysiaEngine,
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

    findings = EllysiaEngine().analyze(services)

    assert len(findings) == 2
    http = findings[0]
    assert http["category"] == "open_port"
    assert http["qod"] == QOD_OPEN_PORT == 30
    assert http["source"] == "ellysia"
    assert http["confirmed"] is False
    assert http["state"] == "open"
    assert http["feed_version"] == "ellysia-0"
    assert http["check_id"] == "ellysia:open-port@1"
    # Title carries where + what, and the CPE is preserved for later phases.
    assert "80/tcp" in http["title"]
    assert "Apache httpd 2.4.49" in http["title"]
    assert http["cpe"] == "cpe:/a:apache:http_server:2.4.49"
    # A service without a CPE stores None, not "".
    assert findings[1]["cpe"] is None


def test_analyze_no_services_returns_empty():
    assert EllysiaEngine().analyze([]) == []


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
