"""El pool acotado por host: fingerprinting y checks dejan la fila india (L23).

``_fingerprint_services`` recorría los servicios en un ``for`` y sondaba cada
uno hasta terminar antes de pasar al siguiente. Sobre un host con veinte
puertos abiertos, y con dissectors que hacen varias peticiones cada uno, eso es
una fila india de decenas de intercambios con sus plazos — y **un servicio mudo
retrasa a todos los que vienen detrás**. La fase más lenta de un escaneo Lybra
acababa siendo la que menos trabajo hace.

Lo que estos tests protegen no es la velocidad, que es difícil de afirmar en un
test: son las **cuatro garantías** que hacen aceptable el pool. Que las sondas
van de verdad a la vez, que el tope se respeta, que el orden del resultado no
depende de quién conteste antes, y que un dissector que revienta sigue costando
sólo su servicio.
"""

import threading

import pytest

from src.modules.features.themis.lybra.checks import Response
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting.dispatch import (
    Dissector,
    DissectorResult,
)
from src.modules.features.themis.managers import LybraEngineManager

pytestmark = pytest.mark.unit


def _services(count, first_port=8000):
    return [Service(first_port + index, "tcp", "http") for index in range(count)]


class _RecordingDissector(Dissector):
    """Dissector falso que apunta cuándo entra y cuándo sale de cada sonda."""

    label = "FALSO"

    def __init__(self, on_probe=None):
        self.ports = []
        self._on_probe = on_probe

    def applies(self, service):
        return True

    def probe(self, target, service, rate_limiter):
        self.ports.append(service.port)
        if self._on_probe is not None:
            self._on_probe(service)
        return DissectorResult("Falso", "1.0", self.label)


def _run_fingerprint(monkeypatch, dissector, services, pool_size=8):
    """Ejecuta ``_fingerprint_services`` con un dissector y un tope inyectados."""
    from src.modules.features.themis.managers.lybra import engine as engine_module

    monkeypatch.setattr(engine_module, "default_dissectors", lambda: [dissector])
    monkeypatch.setattr(
        engine_module.CR, "lybra_config",
        lambda: type("_Config", (), {
            "host_pool_size": pool_size, "banner_timeout": 0.1, "max_blind_probes": 0,
        })(),
    )
    return LybraEngineManager()._fingerprint_services("10.0.0.5", services)


# ============================================== las sondas van de verdad a la vez


def test_the_services_are_probed_concurrently(monkeypatch):
    """Una barrera que sólo se abre cuando han llegado todos: si las sondas
    fueran en fila india, la primera se quedaría esperando a las demás y el
    test agotaría su plazo."""
    services = _services(6)
    barrier = threading.Barrier(len(services), timeout=5.0)
    dissector = _RecordingDissector(on_probe=lambda _service: barrier.wait())

    updated, findings = _run_fingerprint(monkeypatch, dissector, services)

    assert len(updated) == len(services)
    assert len(findings) == len(services)


def test_the_pool_never_exceeds_its_bound(monkeypatch):
    """El tope no es una sugerencia: el límite no es la máquina que escanea,
    es la cortesía con el objetivo."""
    services = _services(12)
    in_flight = 0
    peak = 0
    lock = threading.Lock()
    release = threading.Event()

    def on_probe(_service):
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        release.wait(timeout=0.05)
        with lock:
            in_flight -= 1

    _run_fingerprint(monkeypatch, _RecordingDissector(on_probe), services, pool_size=4)
    assert peak <= 4


def test_a_pool_of_one_still_works(monkeypatch):
    """El tope a uno vuelve al comportamiento de antes, sin montar hilos: es la
    salida de emergencia si el paralelismo diera problemas contra algún
    objetivo."""
    services = _services(3)
    dissector = _RecordingDissector()
    updated, _findings = _run_fingerprint(monkeypatch, dissector, services, pool_size=1)
    assert dissector.ports == [8000, 8001, 8002]
    assert len(updated) == 3


# ================================================ el orden no depende de la carrera


def test_the_result_keeps_the_order_of_the_input(monkeypatch):
    """Un escáner cuyos hallazgos cambian de orden entre ejecuciones hace ruido
    en cualquier comparación posterior, empezando por el ciclo de vida. El
    orden lo fija la lista de entrada, no quién conteste antes."""
    import time

    services = _services(8)

    def on_probe(service):
        # Los puertos altos contestan antes: si el resultado siguiera el orden
        # de terminación, saldría del revés.
        time.sleep((8100 - service.port) / 1000)

    updated, findings = _run_fingerprint(monkeypatch, _RecordingDissector(on_probe),
                                         services)
    assert [service.port for service in updated] == [service.port for service in services]
    assert [finding["port"] for finding in findings] == [
        service.port for service in services]


# ============================================ el aislamiento de fallos se mantiene


def test_a_dissector_that_raises_costs_only_its_own_service(monkeypatch):
    """La garantía que ya existía antes del pool y que no se pierde con él."""
    services = _services(5)

    class _Exploding(_RecordingDissector):
        def probe(self, target, service, rate_limiter):
            if service.port == 8002:
                raise RuntimeError("boom")
            return super().probe(target, service, rate_limiter)

    updated, findings = _run_fingerprint(monkeypatch, _Exploding(), services)

    assert len(updated) == 5                       # ningún servicio se pierde
    assert len(findings) == 4                      # el que reventó no aporta
    assert 8002 not in [finding["port"] for finding in findings]


# ================================================= el runtime de checks, igual


def test_the_check_runtime_walks_services_with_the_injected_mapper():
    """``CheckRuntime`` no monta hilos por su cuenta ni conoce la
    configuración: recibe el recorrido igual que ya recibe las sondas."""
    from src.modules.features.themis.lybra.checks import CheckRuntime, load_checks

    calls = []

    def mapper(work, items):
        calls.append(len(list(items)))
        return [work(item) for item in items]

    runtime = CheckRuntime(
        load_checks(),
        lambda *_args: Response(404, "", {}),
        mode="safe",
        mapper=mapper,
    )
    runtime.run("10.0.0.5", _services(3))
    assert calls == [3]


def test_the_check_runtime_defaults_to_walking_them_one_by_one():
    """Sin mapper inyectado se comporta como siempre. El paralelismo es una
    decisión del manager, no del runtime."""
    from src.modules.features.themis.lybra.checks import CheckRuntime, load_checks

    runtime = CheckRuntime(load_checks(), lambda *_args: Response(404, "", {}))
    assert runtime.run("10.0.0.5", _services(2)) == []


def test_the_response_cache_is_keyed_per_service_so_threads_never_collide():
    """La razón de que el pool sea seguro sin candados.

    Las cachés de respuesta y de handshake se indexan por ``(host, puerto,
    ...)``, así que cada hilo toca sólo las claves de su propio servicio. Dos
    checks del mismo servicio siguen compartiendo una petición —que es para lo
    que la caché existe— y dos servicios distintos no compiten por ninguna
    entrada.
    """
    from src.modules.features.themis.lybra.checks import CheckRuntime, load_checks

    requested = []

    def fetch(_host, port, method, path):
        requested.append((port, method, path))
        return Response(404, "", {})

    runtime = CheckRuntime(load_checks(), fetch, mode="safe")
    runtime.run("10.0.0.5", _services(2))

    ports = {port for port, _method, _path in requested}
    assert ports == {8000, 8001}
    # Ninguna combinación (puerto, método, ruta) se pide dos veces: la caché
    # sigue haciendo su trabajo dentro de cada servicio.
    assert len(requested) == len(set(requested))
