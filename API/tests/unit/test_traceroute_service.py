"""Tests unitarios del parser de TracerouteService (sin red ni BD).

Se ejercita ``_parse`` con salida real de ``traceroute`` (Linux, el servidor
Ellysia) y ``tracert`` (Windows, máquinas de desarrollo), incluyendo saltos sin
respuesta, resolución de nombres e IPv6.
"""

import pytest

from src.modules.sentinel.services.traceroute import TracerouteService

pytestmark = pytest.mark.unit


@pytest.fixture()
def svc():
    return TracerouteService()


def test_parse_linux_with_hostnames_and_timeout(svc):
    output = (
        "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n"
        " 1  router.local (192.168.1.1)  1.234 ms\n"
        " 2  10.0.0.1  5.678 ms\n"
        " 3  * * *\n"
        " 4  core1.isp.net (203.0.113.1)  10.250 ms\n"
    )
    hops = svc._parse(output)

    assert [h["ttl"] for h in hops] == [1, 2, 3, 4]

    # Salto con nombre + IP entre paréntesis.
    assert hops[0] == {"ttl": 1, "ip": "192.168.1.1", "hostname": "router.local", "rtt_ms": 1.234}
    # Salto solo-IP: sin hostname.
    assert hops[1] == {"ttl": 2, "ip": "10.0.0.1", "hostname": None, "rtt_ms": 5.678}
    # Salto sin respuesta ("* * *").
    assert hops[2] == {"ttl": 3, "ip": None, "hostname": None, "rtt_ms": None}
    assert hops[3]["hostname"] == "core1.isp.net"


def test_parse_windows_tracert(svc):
    output = (
        "Tracing route to example.com [93.184.216.34]\n"
        "over a maximum of 30 hops:\n"
        "\n"
        "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
        "  2     *        *        *     Request timed out.\n"
        "  3    10 ms     9 ms    11 ms  93.184.216.34\n"
        "\n"
        "Trace complete.\n"
    )
    hops = svc._parse(output)

    assert [h["ttl"] for h in hops] == [1, 2, 3]
    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[0]["rtt_ms"] == 1.0
    assert hops[1]["ip"] is None  # "Request timed out."
    assert hops[2]["ip"] == "93.184.216.34"


def test_parse_windows_bracket_hostname(svc):
    # tracert sin -d resuelve nombres como "host [ip]".
    output = "  5    12 ms    11 ms    13 ms  edge.example.net [203.0.113.9]\n"
    hops = svc._parse(output)

    assert len(hops) == 1
    assert hops[0]["hostname"] == "edge.example.net"
    assert hops[0]["ip"] == "203.0.113.9"


def test_parse_ipv6_hop(svc):
    output = " 1  2001:db8::1  0.842 ms\n"
    hops = svc._parse(output)

    assert len(hops) == 1
    assert hops[0]["ip"] == "2001:db8::1"
    assert hops[0]["rtt_ms"] == 0.842


def test_hostname_equal_to_ip_is_dropped(svc):
    # Cuando traceroute no resuelve nombre, repite la IP: no debe duplicarse.
    output = " 1  192.168.1.1 (192.168.1.1)  1.000 ms\n"
    hops = svc._parse(output)

    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[0]["hostname"] is None


def test_parse_empty_or_headers_only_returns_empty(svc):
    assert svc._parse("") == []
    assert svc._parse("traceroute to example.com (1.2.3.4), 30 hops max\n") == []
