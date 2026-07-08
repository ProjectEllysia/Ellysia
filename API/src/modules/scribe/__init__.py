"""
src.modules.scribe — Generación de contenido con IA.

Módulo transversal que unifica todo el "digest" de la plataforma: cualquier
módulo (Aegis, Themis, …) construye un ``AIInput`` y se lo pasa a un
``AIGenerator``, que delega en una estrategia de *model calling* inyectada
(Ollama en local o OpenAI en la nube). La estrategia se decide por módulo desde
``SecOpsConfig.json`` mediante ``build_generator``.

Uso típico:
    >>> from src.modules.scribe import build_generator, AIInput
    >>> generator = build_generator("aegis")
    >>> result = generator.digest(AIInput(system_prompt=..., user_prompt=...))
    >>> data = result.parse_json()
"""

from .inputs import AIInput, AIResult, Example
from .strategies import ModelStrategy, OllamaStrategy, OpenAIStrategy, ToolExecutor
from .generator import AIGenerator
from .factory import build_generator
from .tools import web_search, WEB_SEARCH_TOOL
from .exceptions import (
    AIConnectionError,
    AIResponseError,
    AIFallbackExhaustedError,
    CircuitBreakerOpenError,
    AIStrategyConfigurationError,
)

__all__ = [
    "AIInput",
    "AIResult",
    "Example",
    "ModelStrategy",
    "OllamaStrategy",
    "OpenAIStrategy",
    "ToolExecutor",
    "AIGenerator",
    "build_generator",
    "web_search",
    "WEB_SEARCH_TOOL",
    "AIConnectionError",
    "AIResponseError",
    "AIFallbackExhaustedError",
    "CircuitBreakerOpenError",
    "AIStrategyConfigurationError",
]
