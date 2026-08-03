"""Unit tests for Lybra's own port discovery (Fase T).

The connect scanner runs on a real (test-thread) event loop but against an
injected ``opener``, so no real sockets or privileges are involved.
"""

import pytest

from src.modules.features.themis.lybra import (
    scan_ports_sync,
    scan_udp_ports_sync,
    services_from_discovered_ports,
    port_concordance,
    DEFAULT_PORTS,
    UDP_PROBES,
)
from src.modules.features.themis.lybra.transport import build_snmp_get_request

pytestmark = pytest.mark.unit


class _FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def _opener_for(open_ports):
    """Async opener that 'connects' only to the given ports."""
    async def opener(host, port):
        if port in open_ports:
            return None, _FakeWriter()
        raise ConnectionRefusedError(f"port {port} closed")
    return opener


# ------------------------------------------------------------- connect scan

def test_scan_returns_only_open_ports_sorted():
    opener = _opener_for({22, 80, 443})
    result = scan_ports_sync("10.0.0.5", [443, 22, 81, 80, 8080], opener=opener)
    assert result == [22, 80, 443]


def test_scan_all_closed_returns_empty():
    result = scan_ports_sync("10.0.0.5", [1, 2, 3], opener=_opener_for(set()))
    assert result == []


def test_scan_opener_oserror_is_treated_as_closed():
    async def failing(host, port):
        raise OSError("network unreachable")
    assert scan_ports_sync("10.0.0.5", [80, 443], opener=failing) == []


def test_scan_respects_cancel_check():
    opener = _opener_for({22, 80, 443})
    result = scan_ports_sync("10.0.0.5", [22, 80, 443], opener=opener,
                             cancel_check=lambda: True)
    assert result == []          # cancelled before any probe registered a port


def test_scan_defaults_to_curated_port_set():
    # No explicit port list -> DEFAULT_PORTS is swept.
    opener = _opener_for({80})
    assert scan_ports_sync("10.0.0.5", opener=opener) == [80]
    assert {22, 80, 443} <= set(DEFAULT_PORTS)


# ------------------------------------------------------- services + oracle

def test_services_from_discovered_ports_names_well_known():
    services = services_from_discovered_ports([80, 22, 12345])
    by_port = {s.port: s for s in services}
    assert by_port[80].name == "http"
    assert by_port[22].name == "ssh"
    assert by_port[12345].name == ""          # unknown port -> no guessed name
    # No product/version yet — fingerprinting (Fase F) fills those when enabled.
    assert by_port[80].product == "" and by_port[80].version == ""


def test_services_from_discovered_ports_defaults_to_tcp():
    services = services_from_discovered_ports([80])
    assert services[0].protocol == "tcp"


def test_services_from_discovered_ports_udp_protocol():
    services = services_from_discovered_ports([161], protocol="udp")
    assert services[0].protocol == "udp"
    assert services[0].name == "snmp"


@pytest.mark.parametrize("own,nmap,expected", [
    ({80, 443}, {80, 443}, 1.0),
    ({80, 443}, {80, 443, 22}, 2 / 3),
    (set(), set(), 1.0),                        # nothing to disagree on
    ({80}, set(), 0.0),
])
def test_port_concordance(own, nmap, expected):
    assert port_concordance(own, nmap) == pytest.approx(expected)


# ----------------------------------------------------------------- UDP scan
# Fase N/Ronda 1 (roadmap §6.3): a diferencia del connect scan, aquí no hay
# "abierto/cerrado" que decidir con un solo intento — el sender devuelve
# bytes (contestó) o None (silencio), y el escáner solo reporta lo primero.

def test_udp_probes_table_covers_snmp():
    assert 161 in UDP_PROBES
    assert UDP_PROBES[161] == build_snmp_get_request()


def test_udp_scan_reports_only_answering_ports():
    def sender(host, port, payload, timeout):
        return b"reply" if port == 161 else None
    result = scan_udp_ports_sync("10.0.0.5", [161, 999], sender=sender)
    assert result == [161]           # 999 no tiene fila en UDP_PROBES: se ignora


def test_udp_scan_retries_once_before_giving_up():
    calls = []

    def sender(host, port, payload, timeout):
        calls.append(port)
        return None if len(calls) == 1 else b"reply"

    result = scan_udp_ports_sync("10.0.0.5", [161], retries=1, sender=sender)
    assert result == [161]
    assert calls == [161, 161]       # primer intento en silencio, el reintento contesta


def test_udp_scan_gives_up_after_retries_exhausted():
    result = scan_udp_ports_sync("10.0.0.5", [161], retries=1,
                                  sender=lambda h, p, pl, t: None)
    assert result == []


def test_udp_scan_propagates_a_raising_injected_sender():
    # Simetría deliberada con el escáner TCP: scan_ports_sync tampoco captura
    # los fallos del opener que se le inyecta — es _discover_ports, en el
    # manager, quien hace de red de seguridad (ver _discover_udp_ports, su
    # equivalente UDP). Un sender inyectado que lance es cosa de quien lo
    # inyectó, no de scan_udp_ports_sync.
    def raising_sender(host, port, payload, timeout):
        raise OSError("network unreachable")
    with pytest.raises(OSError):
        scan_udp_ports_sync("10.0.0.5", [161], sender=raising_sender)


def test_udp_send_recv_swallows_oserror(monkeypatch):
    """El sender por defecto sí traga el fallo de red: es la costura que
    hace posible que scan_udp_ports_sync, en su forma de uso normal (sin
    sender inyectado), nunca lance por un puerto cerrado o inalcanzable."""
    import src.modules.features.themis.lybra.transport as transport_module

    class _RefusingSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, timeout):
            pass

        def connect(self, addr):
            pass

        def send(self, payload):
            pass

        def recv(self, size):
            raise ConnectionRefusedError("port closed")

    monkeypatch.setattr(
        transport_module.socket, "socket", lambda *a, **kw: _RefusingSocket()
    )
    assert transport_module.udp_send_recv("10.0.0.5", 161, b"\x00", 1.0) is None


def test_udp_scan_defaults_to_udp_probes_table():
    calls = []

    def sender(host, port, payload, timeout):
        calls.append(port)
        return None

    scan_udp_ports_sync("10.0.0.5", sender=sender)
    # retries=1 por defecto -> cada puerto de la tabla se intenta dos veces.
    assert calls == list(UDP_PROBES) * 2
