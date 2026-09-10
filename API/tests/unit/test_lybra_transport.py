"""Unit tests for Lybra's own port discovery.

The connect scanner runs on a real (test-thread) event loop but against an
injected ``opener``, so no real sockets or privileges are involved.
"""

import asyncio

import pytest

from src.modules.features.themis.lybra import (
    PortSweep,
    sweep_with_retries,
    scan_ports_sync,
    sweep_ports_sync,
    scan_udp_ports_sync,
    services_from_discovered_ports,
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


# --------------------------------------------- barrido bloqueado vs vacío
#
# Un objetivo que bloquea el barrido a mitad de camino devolvía una
# lista vacía, indistinguible de un host limpio — y el ciclo de vida marcaba
# entonces como corregidos hallazgos que seguían abiertos.


def _timing_out_opener():
    """Abridor que nunca completa: toda sonda agota su plazo."""
    async def opener(host, port):
        await asyncio.sleep(3600)
    return opener


def test_sweep_classifies_each_outcome_apart():
    async def opener(host, port):
        if port == 80:
            return None, _FakeWriter()
        if port == 22:
            raise ConnectionRefusedError("closed")
        raise OSError("network unreachable")

    sweep = sweep_ports_sync("10.0.0.5", [80, 22, 443], opener=opener)
    assert sweep.open_ports == (80,)
    assert sweep.refused_ports == (22,)
    assert sweep.unreachable_ports == (443,)
    assert sweep.timed_out_ports == ()
    assert not sweep.is_blocked


def test_sweep_where_every_port_times_out_is_blocked():
    ports = list(range(1000, 1000 + 16))
    sweep = sweep_ports_sync("10.0.0.5", ports, timeout=0.01,
                             opener=_timing_out_opener())
    assert sweep.timed_out_ports == tuple(ports)
    assert sweep.is_blocked


def test_scan_returns_none_when_the_sweep_looks_blocked():
    # La distinción entera del issue: esto NO puede ser [], porque [] significa
    # "objetivo limpio" y el ciclo de vida actuaría en consecuencia.
    ports = list(range(1000, 1000 + 16))
    waits = []
    result = scan_ports_sync("10.0.0.5", ports, timeout=0.01,
                             opener=_timing_out_opener(),
                             retry_delay=0.5, sleeper=waits.append)
    assert result is None
    assert waits == [0.5]          # se reintentó una vez antes de rendirse


def test_scan_recovers_when_the_retry_answers():
    ports = list(range(1000, 1000 + 16))
    attempts = {"count": 0}

    async def opener(host, port):
        if attempts["count"] == 0:
            await asyncio.sleep(3600)
        if port == 1000:
            return None, _FakeWriter()
        raise ConnectionRefusedError("closed")

    def sleeper(_seconds):
        attempts["count"] += 1

    result = scan_ports_sync("10.0.0.5", ports, timeout=0.01, opener=opener,
                             retry_delay=0.1, sleeper=sleeper)
    assert result == [1000]


def test_a_short_muted_sweep_is_not_called_blocked():
    # Con tres puertos, que los tres expiren es plausible en una red lenta:
    # preferimos callar antes que inventar un fallo que no está.
    result = scan_ports_sync("10.0.0.5", [1, 2, 3], timeout=0.01,
                             opener=_timing_out_opener(), retry_delay=0)
    assert result == []


def test_a_cancelled_sweep_is_never_blocked():
    sweep = PortSweep(open_ports=(), refused_ports=(),
                      timed_out_ports=tuple(range(20)), unreachable_ports=(),
                      was_cancelled=True)
    assert not sweep.is_blocked


# ------------------------------------------------------- services + oracle

def test_services_from_discovered_ports_names_well_known():
    services = services_from_discovered_ports([80, 22, 12345])
    by_port = {s.port: s for s in services}
    assert by_port[80].name == "http"
    assert by_port[22].name == "ssh"
    assert by_port[12345].name == ""          # unknown port -> no guessed name
    # No product/version yet — fingerprinting fills those when enabled.
    assert by_port[80].product == "" and by_port[80].version == ""


def test_services_from_discovered_ports_defaults_to_tcp():
    services = services_from_discovered_ports([80])
    assert services[0].protocol == "tcp"


def test_services_from_discovered_ports_udp_protocol():
    services = services_from_discovered_ports([161], protocol="udp")
    assert services[0].protocol == "udp"
    assert services[0].name == "snmp"


# ----------------------------------------------------------------- UDP scan
# A diferencia del connect scan, aquí no hay
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
    # retries=1 por defecto -> cada puerto de la tabla se intenta dos veces. Se
    # compara el recuento y no la secuencia: el barrido es
    # concurrente, así que el orden en que llegan los intentos es cosa del
    # planificador y no del escáner.
    assert sorted(calls) == sorted(list(UDP_PROBES) * 2)


# ─────────────────────────────────────────────────── presupuesto de reloj
#
# El plazo que la cola de tareas le pone a un job no puede acotar el barrido:
# se inyecta con ``PyThreadState_SetAsyncExc``, que sólo se materializa cuando
# el hilo vuelve a ejecutar bytecode, y un hilo parado en la llamada al sistema
# que espera a los sockets lo rebasa sin enterarse (en producción, un plazo de
# 60 s apareció a los 159). Estas pruebas fijan el presupuesto que sí evalúa el
# propio barrido.


def _slow_opener(seconds):
    """Abridor que tarda ``seconds`` y luego acepta la conexión."""
    async def opener(host, port):
        await asyncio.sleep(seconds)
        return None, _FakeWriter()
    return opener


def test_the_sweep_stops_starting_probes_once_the_budget_is_spent():
    # Concurrencia 1 para que las sondas vayan en fila y el reloj avance de
    # forma predecible: con 0,05 s cada una, en 0,15 s no caben veinte.
    ports = list(range(1000, 1020))
    sweep = sweep_ports_sync("10.0.0.5", ports, concurrency=1,
                             opener=_slow_opener(0.05), budget_seconds=0.15)

    assert sweep.was_truncated
    probed = (len(sweep.open_ports) + len(sweep.refused_ports)
              + len(sweep.timed_out_ports) + len(sweep.unreachable_ports))
    assert 0 < probed < len(ports), f"se probaron {probed} de {len(ports)}"


def test_a_truncated_sweep_is_neither_blocked_nor_clean():
    """Un barrido truncado no es evidencia de nada sobre lo que no se miró.

    Y en particular no puede llegar al motor como lista de puertos: el ciclo de
    vida marcaría como corregido todo lo que estaba abierto y esta vez no dio
    tiempo a comprobar, el mismo riesgo que un descubrimiento intermitente
    puede producir por otra puerta.
    """
    ports = list(range(1000, 1020))
    sweep = sweep_ports_sync("10.0.0.5", ports, concurrency=1,
                             opener=_slow_opener(0.05), budget_seconds=0.15)
    assert not sweep.is_blocked

    result = scan_ports_sync("10.0.0.5", ports, concurrency=1,
                             opener=_slow_opener(0.05), budget_seconds=0.15)
    assert result is None


def test_a_sweep_that_fits_its_budget_is_unaffected():
    opener = _opener_for({22, 80, 443})
    result = scan_ports_sync("10.0.0.5", [443, 22, 81, 80, 8080],
                             opener=opener, budget_seconds=30)
    assert result == [22, 80, 443]


def test_the_retry_does_not_outlive_the_budget():
    """Reintentar un barrido bloqueado cuesta ``retry_delay`` más otro barrido
    entero. Si no queda presupuesto para eso, no se intenta."""
    ports = list(range(1000, 1000 + 16))
    waits = []
    result = scan_ports_sync("10.0.0.5", ports, timeout=0.01,
                             opener=_timing_out_opener(),
                             retry_delay=0.5, sleeper=waits.append,
                             budget_seconds=0.05)
    assert result is None
    assert waits == [], "se durmió un reintento que no cabía en el presupuesto"


def test_the_two_views_of_a_truncated_sweep_differ():
    """`scan_ports_sync` y `sweep_with_retries` responden a preguntas distintas.

    La primera es la vista de sólo-la-lista: devuelve `None` si el barrido no
    sirve, sin distinguir por qué. La segunda devuelve el barrido entero, que
    es lo que permite al motor reportar los puertos ciertos de un barrido
    truncado y marcar el escaneo como incompleto en vez de tirar el trabajo.
    """
    ports = list(range(1000, 1020))
    args = dict(concurrency=1, opener=_slow_opener(0.05), budget_seconds=0.15)

    assert scan_ports_sync("10.0.0.5", ports, **args) is None

    sweep = sweep_with_retries("10.0.0.5", ports, **args)
    assert sweep.was_truncated
    assert not sweep.is_blocked
    assert len(sweep.open_ports) > 0, "no encontró ni un puerto antes de truncarse"
