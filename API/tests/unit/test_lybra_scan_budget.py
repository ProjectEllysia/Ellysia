"""El ``timeout`` del panel de lanzamiento llega hasta el barrido de puertos.

Antes se quedaba a mitad de camino. `run_scan` lo usaba en un único sitio —el
plazo que se le pone al job en la cola— y nunca lo pasaba al descubrimiento,
que no tenía presupuesto de reloj de ninguna clase. Como además ese plazo no se
puede hacer cumplir con puntualidad (se inyecta con
``PyThreadState_SetAsyncExc`` y un hilo parado en una llamada al sistema lo
rebasa sin enterarse), el número que el usuario escribía no participaba de
hecho en ninguna decisión: era un campo decorativo.

Estos tests fijan el recorrido completo del valor.
"""

from __future__ import annotations

import time

import pytest

from src.modules.features.themis.lybra import PortSweep
from src.modules.features.themis.managers.lybra import engine as engine_module
from src.modules.features.themis.managers.lybra.engine import LybraEngineManager

pytestmark = pytest.mark.unit


def _clean_sweep(open_ports=(80,), truncated=False) -> PortSweep:
    return PortSweep(open_ports=tuple(open_ports), refused_ports=(), timed_out_ports=(),
                     unreachable_ports=(), was_truncated=truncated)


def test_the_budget_reaches_the_sweep(monkeypatch):
    captured = {}

    def fake_sweep(target, ports, budget_seconds=None):
        captured["target"] = target
        captured["ports"] = ports
        captured["budget"] = budget_seconds
        return _clean_sweep()

    monkeypatch.setattr(engine_module, "sweep_with_retries", fake_sweep)

    sweep = LybraEngineManager()._discover_ports(  # pylint: disable=protected-access
        "10.0.0.5", [80, 443], budget_seconds=42.0)

    assert sweep.open_ports == (80,)
    assert captured["budget"] == 42.0


def test_a_scan_without_budget_keeps_the_old_behaviour(monkeypatch):
    """Los caminos que no pasan ``timeout`` —un escaneo programado, o un job
    encolado antes de este cambio— siguen barriendo sin límite de reloj."""
    captured = {}

    def fake_sweep(target, ports, budget_seconds=None):
        captured["budget"] = budget_seconds
        return _clean_sweep(open_ports=())

    monkeypatch.setattr(engine_module, "sweep_with_retries", fake_sweep)
    LybraEngineManager()._discover_ports("10.0.0.5", None)  # pylint: disable=protected-access

    assert captured["budget"] is None


def test_remaining_budget_shrinks_and_never_goes_negative():
    remaining = LybraEngineManager._remaining_budget  # pylint: disable=protected-access

    assert remaining(None) is None

    deadline = time.monotonic() + 10
    first = remaining(deadline)
    second = remaining(deadline)
    assert 0 < second <= first <= 10

    # Un plazo ya vencido da cero, no un número negativo: el barrido lo
    # traduce en "no empieces nada", que es lo que se quiere, y no en un
    # presupuesto enorme por desbordamiento de signo.
    assert remaining(time.monotonic() - 5) == 0.0


def test_the_worker_entry_point_carries_the_timeout(monkeypatch):
    """La tupla de argumentos que viaja a la cola.

    ``timeout`` es el cuarto y es opcional a propósito: un job encolado antes
    de este cambio viaja con tres argumentos y tiene que seguir ejecutándose
    tras el despliegue en vez de fallar al deserializarse.
    """
    seen = []

    class _NullContext:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(engine_module, "job_context", lambda: _NullContext())
    monkeypatch.setattr(
        LybraEngineManager, "_run_lybra",
        lambda self, *args: seen.append(args),
    )

    LybraEngineManager.execute_lybra_scan(7, [80], None, 90)
    LybraEngineManager.execute_lybra_scan(8, [80])

    assert seen == [(7, [80], None, 90), (8, [80], None, None)]
