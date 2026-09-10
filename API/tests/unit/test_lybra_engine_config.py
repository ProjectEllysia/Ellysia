"""El bloque de configuración del motor.

Cada timeout, cada nivel de concurrencia y cada intervalo de ritmo tiene que
venir del bloque de configuración, no de un literal en la firma de un
constructor. Este fichero comprueba las dos mitades: que el bloque existe y
está atado, y —lo que de verdad importa— que el manager **usa** los valores
configurados en vez de los defectos del constructor.
"""

import pytest

from src.modules.system import config_reading as CR

pytestmark = pytest.mark.unit


def test_the_engine_block_keeps_the_old_values_as_defaults():
    """El cambio es invisible hasta que alguien mueve un dial: los defaults son
    exactamente los que estaban a fuego."""
    engine = CR.lybra_engine_config()
    assert engine.tcp_concurrency == 200
    assert engine.tcp_timeout == 2.0
    assert engine.rate_limit_interval == 0.2
    assert engine.http_timeout == 8
    assert engine.http_max_body_bytes == 131072
    assert engine.http_user_agent == "Lybra/1.0"
    assert engine.network_timeout == 5.0


def test_the_operator_switches_stay_out_of_the_engine_block():
    """Un interruptor de despliegue y un dial de afinado son cosas distintas:
    `LybraConfig` se queda con los dos booleanos y nada más."""
    assert set(CR.LybraConfig.__dataclass_fields__) == {
        "active_checks", "fingerprinting_enabled"}


def test_the_http_probe_presents_the_configured_user_agent():
    from src.modules.features.themis.lybra.checks import HttpProbe

    seen = {}

    class _Opener:
        def open(self, request, timeout=None):
            seen["ua"] = request.get_header("User-agent")
            raise OSError("no real network")

    probe = HttpProbe(user_agent="Escaner-Auditoria/2.0")
    probe._opener = _Opener()                      # pylint: disable=protected-access
    probe._scheme_for = lambda host, port: "http"  # pylint: disable=protected-access
    probe._request("10.0.0.5", 80, "GET", "/")     # pylint: disable=protected-access
    assert seen["ua"] == "Escaner-Auditoria/2.0"


def test_the_discovery_scan_receives_the_configured_dials(monkeypatch):
    """El dial llega a la sonda: sin esto, el bloque sería config muerta."""
    from src.modules.features.themis.managers.lybra import engine as engine_module
    from src.modules.features.themis.lybra.transport import PortSweep

    captured = {}

    def fake_sweep(target, ports, **kwargs):
        captured.update(kwargs)
        return PortSweep(open_ports=(80,), refused_ports=(), timed_out_ports=(),
                         unreachable_ports=())

    monkeypatch.setattr(engine_module, "sweep_with_retries", fake_sweep)
    monkeypatch.setattr(
        engine_module.CR, "lybra_engine_config",
        lambda: type("_Cfg", (), {
            "tcp_concurrency": 50, "tcp_timeout": 0.5, "udp_retries": 3,
        })())

    engine_module.LybraEngineManager()._discover_ports(  # pylint: disable=protected-access
        "10.0.0.5", [80])

    assert captured["concurrency"] == 50
    assert captured["timeout"] == 0.5
