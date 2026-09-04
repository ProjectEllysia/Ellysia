"""Lo que ``scribe`` lee de ``SecOpsConfig.json`` en vez de tenerlo a fuego.

Antes, el modelo de cada proveedor solo se podía cambiar por el ``.env`` (que
es parte del despliegue: cambiarlo obliga a redesplegar) y los cuatro
parámetros de resiliencia del generador estaban escritos en la firma de
``AIGenerator.__init__``, sin ninguna ruta de configuración. Estos tests atan
las tres costuras que hacen que ahora se puedan cambiar desde el panel:

- ``ScribeConfig.timeout_for`` resuelve el timeout de cliente por proveedor.
- ``build_generator`` le pasa al generador la resiliencia configurada, en vez
  de dejarle usar los defaults de su propia firma.
- La estrategia de un módulo sale de ``tools.scribe.modules``, incluido Iris,
  que usa IA desde ``iris/services/ai_writer.py`` y no estaba declarado.
"""

import pytest

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import factory

pytestmark = pytest.mark.unit


class _FakeStrategy:
    """Estrategia de mentira: evita construir un cliente real de proveedor."""

    name = "fake"

    def complete(self, ai_input, tool_executor=None):  # pragma: no cover - no se llama
        return "ok"


# ------------------------------------------------------- ScribeConfig.timeout_for

def test_timeout_for_prefers_the_configured_value():
    config = CR.ScribeConfig(strategies={"openai": {"timeout": 45}})
    assert config.timeout_for("openai", 120) == 45


def test_timeout_for_falls_back_when_the_strategy_declares_nothing():
    """Cada backend tiene un default razonable distinto —un modelo local tarda
    mucho más que una API en la nube—, así que el fallback lo pone quien
    pregunta, no el bloque de configuración."""
    config = CR.ScribeConfig(strategies={"openai": {"model": "gpt-4o-mini"}})
    assert config.timeout_for("openai", 120) == 120
    assert config.timeout_for("ollama", 300) == 300


def test_timeout_for_ignores_a_zero_because_it_would_mean_no_wait_at_all():
    config = CR.ScribeConfig(strategies={"ollama": {"timeout": 0}})
    assert config.timeout_for("ollama", 300) == 300


# ------------------------------------------------------------- build_generator

def test_build_generator_uses_the_configured_resilience(monkeypatch):
    """Sin esto, la factory construía el generador con los defaults de la
    firma y los valores del fichero no llegaban a ninguna parte."""
    monkeypatch.setattr(factory, "_build_strategy", lambda name: _FakeStrategy())
    monkeypatch.setattr(CR, "scribe_config", lambda: CR.ScribeConfig(default_strategy="fake"))
    monkeypatch.setattr(
        CR, "scribe_resilience_config",
        lambda: CR.ScribeResilienceConfig(
            max_retries=7,
            retry_base_seconds=2.5,
            breaker_threshold=9,
            breaker_timeout_seconds=11,
        ),
    )

    generator = factory.build_generator("aegis")

    assert generator._max_retries == 7
    assert generator._retry_base == 2.5
    assert generator._breaker_threshold == 9
    assert generator._breaker_timeout == 11


def test_build_generator_picks_the_strategy_declared_for_the_module(monkeypatch):
    requested: list[str] = []
    monkeypatch.setattr(
        factory, "_build_strategy",
        lambda name: requested.append(name) or _FakeStrategy(),
    )
    monkeypatch.setattr(
        CR, "scribe_config",
        lambda: CR.ScribeConfig(default_strategy="openai", modules={"iris": "ollama"}),
    )
    monkeypatch.setattr(CR, "scribe_resilience_config", CR.ScribeResilienceConfig)

    factory.build_generator("iris")
    factory.build_generator("aegis")

    assert requested == ["ollama", "openai"]


# ------------------------------------------------------ el fichero que se despliega

def test_the_shipped_config_declares_a_strategy_for_every_ai_module():
    """Los tres módulos que llaman a ``build_generator`` tienen que estar en
    ``tools.scribe.modules``, o su estrategia queda implícita en el default y
    el panel no tiene qué pintar para ellos."""
    modules = CR.scribe_config().modules
    assert set(modules) >= {"themis", "aegis", "iris"}, (
        f"faltan módulos en tools.scribe.modules: {sorted({'themis', 'aegis', 'iris'} - set(modules))}"
    )


def test_the_shipped_config_declares_a_block_for_every_registered_strategy():
    """Un proveedor sin bloque propio en ``strategies`` no tiene dónde guardar
    su modelo, así que el panel no puede ofrecerlo — que es exactamente lo que
    le pasaba a Ollama."""
    from src.modules.tools.scribe.strategies import ModelStrategy

    declared = set(CR.scribe_config().strategies)
    registered = set(ModelStrategy.registered_names())
    assert registered <= declared, (
        f"estrategias registradas sin bloque en SecOpsConfig.json: {sorted(registered - declared)}"
    )
