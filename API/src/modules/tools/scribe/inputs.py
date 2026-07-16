"""
scribe.inputs
─────────────
Dataclasses de tránsito del proceso de "digest".

    — Example: par (usuario, asistente) para few-shot prompting.
    — AIInput: contrato de entrada que recibe ``AIGenerator.digest``. Reúne
      todo lo necesario para una generación con independencia del backend.
    — AIResult: contrato de salida. Envuelve el texto crudo del modelo y ofrece
      un parseo JSON robusto reutilizable por todos los consumidores.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .exceptions import AIResponseError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Example:
    """Ejemplo de few-shot: lo que diría el usuario y la respuesta esperada."""

    user: str
    assistant: str


@dataclass(frozen=True)
class AIInput:
    """
    Datos a "digerir" por el generador.

    Es agnóstico al backend: cada estrategia traduce estos campos a su API
    nativa (Ollama, OpenAI, …). Las opciones de muestreo se exponen aquí para
    que cada consumidor las ajuste sin tocar la estrategia.

    Attributes:
        system_prompt: Instrucciones de sistema (persona, reglas, formato).
        user_prompt: Petición concreta a resolver.
        examples: Ejemplos few-shot inyectados entre system y user.
        tools: Definiciones de herramientas (function calling). None = sin tools.
        json_mode: Si True, fuerza salida JSON en los backends que lo soporten.
        temperature: Temperatura de muestreo.
        num_predict: Máximo de tokens a generar.
        top_p: Núcleo de muestreo.
        repeat_penalty: Penalización por repetición (Ollama). Ignorado por OpenAI.
    """

    system_prompt: str
    user_prompt: str
    examples: list[Example] = field(default_factory=list)
    tools: list[dict] | None = None
    json_mode: bool = True
    temperature: float = 0.4
    num_predict: int = 4096
    top_p: float = 0.9
    repeat_penalty: float = 1.1

    def to_messages(self) -> list[dict]:
        """Construye la lista de mensajes en formato chat (rol/contenido)."""
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]
        for ex in self.examples:
            messages.append({"role": "user", "content": ex.user})
            messages.append({"role": "assistant", "content": ex.assistant})
        messages.append({"role": "user", "content": self.user_prompt})
        return messages


@dataclass
class AIResult:
    """
    Resultado crudo de una generación.

    ``text`` es la respuesta textual del modelo. ``raw`` conserva el objeto
    nativo de la estrategia por si el consumidor necesita metadatos.
    """

    text: str
    raw: Any = None

    def parse_json(self, *, detect_truncation: bool = True) -> dict:
        """
        Parseo JSON robusto con varias estrategias de recuperación.

        Centraliza la lógica que antes duplicaban los writers de dominio:
            1. Detección temprana de truncado (la llave raíz no cierra).
            2. Intento directo.
            3. Extracción por patrones (bloques markdown, ``{...}``).
            4. Limpieza de texto sobrante antes/después del objeto.

        Args:
            detect_truncation: Si True, lanza error cuando el JSON no cierra
                su llave raíz (respuesta cortada por límite de tokens).

        Returns:
            El diccionario parseado.

        Raises:
            AIResponseError: Si la respuesta es vacía, truncada o no parseable.
        """
        raw = self.text
        if not raw:
            raise AIResponseError("Respuesta vacía del modelo")

        stripped = raw.rstrip()
        if detect_truncation and stripped and stripped[-1] != "}":
            logger.warning(
                "Respuesta truncada detectada (num_predict alcanzado). "
                "Últimos 80 chars: %r",
                stripped[-80:],
            )
            raise AIResponseError(
                "Respuesta truncada por límite de tokens: el JSON no está completo. "
                "Aumenta num_predict o reduce el tamaño del prompt."
            )

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        for pattern in (
            r"```(?:json)?\s*([\s\S]*?)\s*```",
            r"JSON:\s*(\{[\s\S]*\})",
            r"\{[\s\S]*\}",
        ):
            match = re.search(pattern, raw)
            if match:
                try:
                    return json.loads(match.group(1) if match.groups() else match.group())
                except json.JSONDecodeError:
                    continue

        cleaned = re.sub(r"^[^{]*", "", raw)
        cleaned = re.sub(r"[^}]*$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.error("No se pudo parsear respuesta: %s", raw[:500])
            raise AIResponseError(f"JSON inválido tras limpieza: {exc}")
