"""
scribe.strategies
─────────────────
Estrategias de "model calling" inyectables en ``AIGenerator``.

Cada estrategia traduce un ``AIInput`` a la API nativa de un backend y ejecuta
una completación completa (incluido un turno de tool-calling con ``web_search``),
devolviendo el texto crudo del modelo. Así el resto de la plataforma es
agnóstica a si detrás hay un modelo local (Ollama), en la nube (OpenAI) o en
Google Gemini, lo que habilita el despliegue en un VPS sin GPU.

    — ModelStrategy: contrato abstracto.
    — OllamaStrategy: modelo local servido por Ollama.
    — OpenAIStrategy: modelos de OpenAI (p.ej. gpt-4o-mini).
    — GoogleStrategy: modelos de Google Gemini (p.ej. gemini-2.0-flash).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from .exceptions import AIConnectionError, AIStrategyConfigurationError
from .inputs import AIInput

logger = logging.getLogger(__name__)

# Ejecutor de herramientas: recibe (nombre, argumentos) y devuelve texto.
ToolExecutor = Callable[[str, dict], str]


class ModelStrategy(ABC):
    """Contrato de una estrategia de llamada al modelo.

    ``register``/``resolve`` (B4) centralizan lo que ``scribe.factory``
    hacía con una cadena ``if/elif`` por nombre: cada estrategia se da de
    alta junto a su propia clase, así que añadir un proveedor nuevo (una
    API transaccional, etc.) no exige volver a editar la factory.
    """

    #: Nombre legible de la estrategia (para logs y circuit breaker).
    name: str = "model"

    _registry: dict[str, type["ModelStrategy"]] = {}

    @classmethod
    def register(cls, name: str):
        def decorator(subclass: type["ModelStrategy"]) -> type["ModelStrategy"]:
            cls._registry[name] = subclass
            return subclass
        return decorator

    @classmethod
    def resolve(cls, name: str, overrides: dict) -> "ModelStrategy":
        """Instancia la estrategia ``name`` con credenciales de entorno/config."""
        strategy_cls = cls._registry.get(name)
        if strategy_cls is None:
            raise AIStrategyConfigurationError(f"estrategia desconocida: '{name}'")
        return strategy_cls.from_config(overrides)

    @classmethod
    def from_config(cls, overrides: dict) -> "ModelStrategy":
        """Construye esta estrategia a partir de las credenciales de entorno
        (``.env``) y las ``overrides`` de ``SecOpsConfig.json``
        (``tools.scribe.modules.<módulo>``, p.ej. un ``model`` distinto).

        No es ``@abstractmethod``: un doble de test que construye la
        estrategia directamente (sin pasar por ``resolve``/config real) no
        tiene por qué implementarlo — solo lo necesitan las estrategias
        registradas de verdad."""
        raise NotImplementedError

    @abstractmethod
    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        """
        Ejecuta una completación y devuelve el texto crudo del modelo.

        Implementa internamente el bucle de tool-calling (un turno) usando
        ``tool_executor`` cuando el modelo solicita herramientas.

        Raises:
            AIConnectionError: Si falla la comunicación con el backend.
        """


@ModelStrategy.register("ollama")
class OllamaStrategy(ModelStrategy):
    """Estrategia que llama a un modelo local servido por Ollama."""

    name = "ollama"

    @classmethod
    def from_config(cls, overrides: dict) -> "OllamaStrategy":
        import src.modules.system.config_reading as CR
        host, model = CR.get_ollama_environment()
        return cls(host=host, model=overrides.get("model") or model)

    def __init__(self, host: str, model: str, timeout: int = 300) -> None:
        import ollama

        self.host = host
        self.model = model
        logger.info("[scribe/ollama] cliente host=%s model=%s", host, model)
        self._client = ollama.Client(host=host, timeout=timeout)

    def _options(self, ai_input: AIInput) -> dict:
        return {
            "num_predict": ai_input.num_predict,
            "temperature": ai_input.temperature,
            "top_p": ai_input.top_p,
            "repeat_penalty": ai_input.repeat_penalty,
        }

    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        messages = ai_input.to_messages()
        options = self._options(ai_input)
        fmt = "json" if ai_input.json_mode else None

        try:
            resp = self._client.chat(
                model=self.model,
                messages=messages,
                tools=ai_input.tools,
                format=fmt,
                options=options,
            )

            tool_calls = getattr(resp.message, "tool_calls", None)
            if tool_calls and tool_executor:
                logger.info("[scribe/ollama] tool_calls: %d", len(tool_calls))
                messages.append({
                    "role": "assistant",
                    "content": resp.message.content or "",
                    "tool_calls": tool_calls,
                })
                for tc in tool_calls:
                    args = tc.function.arguments or {}
                    result = tool_executor(tc.function.name, dict(args))
                    messages.append({"role": "tool", "content": result})

                resp = self._client.chat(
                    model=self.model,
                    messages=messages,
                    format=fmt,
                    options=options,
                )

            return (resp.message.content or "").strip()

        except Exception as exc:
            logger.error("[scribe/ollama] error en %s: %s", self.host, exc, exc_info=True)
            raise AIConnectionError(str(exc), model=self.model) from exc


@ModelStrategy.register("openai")
class OpenAIStrategy(ModelStrategy):
    """Estrategia que llama a la API de OpenAI (p.ej. gpt-4o-mini)."""

    name = "openai"

    @classmethod
    def from_config(cls, overrides: dict) -> "OpenAIStrategy":
        import src.modules.system.config_reading as CR
        env = CR.get_openai_environment()
        return cls(
            api_key=env["api_key"],
            model=overrides.get("model") or env["model"],
            base_url=env.get("base_url"),
        )

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        timeout: int = 120,
    ) -> None:
        from openai import OpenAI

        self.model = model
        logger.info("[scribe/openai] cliente model=%s base_url=%s", model, base_url or "default")
        self._client = OpenAI(api_key=api_key, base_url=base_url or None, timeout=timeout)

    def _create(self, messages: list[dict], ai_input: AIInput, with_tools: bool):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": ai_input.temperature,
            "max_tokens": ai_input.num_predict,
            "top_p": ai_input.top_p,
        }
        if ai_input.json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if with_tools and ai_input.tools:
            kwargs["tools"] = ai_input.tools
        return self._client.chat.completions.create(**kwargs)

    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        messages = ai_input.to_messages()

        try:
            resp = self._create(messages, ai_input, with_tools=True)
            message = resp.choices[0].message

            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls and tool_executor:
                logger.info("[scribe/openai] tool_calls: %d", len(tool_calls))
                messages.append({
                    "role": "assistant",
                    "content": message.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                })
                for tc in tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    result = tool_executor(tc.function.name, args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    })

                resp = self._create(messages, ai_input, with_tools=False)
                message = resp.choices[0].message

            return (message.content or "").strip()

        except Exception as exc:
            logger.error("[scribe/openai] error: %s", exc, exc_info=True)
            raise AIConnectionError(str(exc), model=self.model) from exc


@ModelStrategy.register("google")
class GoogleStrategy(ModelStrategy):
    """Estrategia que llama a la API de Google Gemini."""

    name = "google"

    @classmethod
    def from_config(cls, overrides: dict) -> "GoogleStrategy":
        import src.modules.system.config_reading as CR
        env = CR.get_google_environment()
        return cls(
            api_key=env["api_key"],
            model=overrides.get("model") or env["model"],
        )

    def __init__(self, api_key: str, model: str, timeout: int = 120) -> None:
        import google.generativeai as genai

        self.model = model
        logger.info("[scribe/google] cliente model=%s", model)
        genai.configure(api_key=api_key)
        self._genai = genai

    @staticmethod
    def _build_tool_declarations(tools: list[dict]) -> list[dict]:
        """Convierte herramientas de formato OpenAI a function_declarations de Gemini."""
        declarations = []
        for tool in tools:
            if tool.get("type") == "function":
                func = tool["function"]
                declarations.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "parameters": func.get("parameters"),
                })
        return declarations or None

    def _contents_from_messages(
        self, messages: list[dict], system_prompt: str
    ) -> tuple[list[dict], str]:
        """Convierte la lista de mensajes estándar al formato content de Gemini.

        Gemini usa system_instruction aparte de contents, y los roles
        'assistant' → 'model', 'tool' → 'user' (como functionResponse).
        """
        contents = []
        for msg in messages:
            if msg["role"] == "system":
                continue
            elif msg["role"] == "assistant":
                role = "model"
            elif msg["role"] == "tool":
                role = "user"
            else:
                role = msg["role"]

            parts = []
            content = msg.get("content", "")
            if content:
                parts.append({"text": content})

            tc = msg.get("tool_calls")
            if tc:
                for t in tc:
                    fn = t.get("function", t)
                    parts.append({
                        "functionCall": {
                            "name": fn["name"],
                            "args": fn.get("arguments", {}),
                        }
                    })

            if parts:
                contents.append({"role": role, "parts": parts})

        return contents, system_prompt

    def complete(
        self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None
    ) -> str:
        genai = self._genai
        messages = ai_input.to_messages()

        try:
            contents, system_instruction = self._contents_from_messages(
                messages, ai_input.system_prompt
            )

            generation_config = {
                "temperature": ai_input.temperature,
                "top_p": ai_input.top_p,
                "max_output_tokens": ai_input.num_predict,
            }
            if ai_input.json_mode:
                generation_config["response_mime_type"] = "application/json"

            tools = [
                {
                    "function_declarations": self._build_tool_declarations(ai_input.tools)
                }
            ]

            model = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system_instruction or None,
            )

            response = model.generate_content(
                contents=contents,
                generation_config=generation_config,
                tools=tools,
            )

            if tool_executor and tools:
                candidate = response.candidates[0] if response.candidates else None
                part = candidate.content.parts[0] if candidate and candidate.content.parts else None
                fc = getattr(part, "function_call", None) if part else None

                if fc:
                    logger.info("[scribe/google] tool_call: %s", fc.name)
                    result = tool_executor(fc.name, dict(fc.args))

                    contents.append({
                        "role": "user",
                        "parts": [{
                            "functionResponse": {
                                "name": fc.name,
                                "response": {"result": result},
                            }
                        }],
                    })

                    response = model.generate_content(
                        contents=contents,
                        generation_config=generation_config,
                        tools=tools,
                    )

            try:
                return (response.text or "").strip()
            except (ValueError, AttributeError):
                return ""

        except Exception as exc:
            logger.error("[scribe/google] error: %s", exc, exc_info=True)
            raise AIConnectionError(str(exc), model=self.model) from exc
