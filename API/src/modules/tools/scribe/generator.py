"""
scribe.generator
────────────────
``AIGenerator``: la entidad central del módulo.

Se construye con una estrategia de *model calling* (inyección de dependencias)
y expone un único método público, ``digest``, que recibe un ``AIInput`` y lo
"digiere" invocando la estrategia. Alrededor de la llamada añade las garantías
transversales comunes a todos los backends:

    — Reintentos con backoff exponencial.
    — Circuit breaker por instancia (protege el backend ante fallos en cadena).
    — Ejecutor de herramientas por defecto (``web_search``).

El generador no sabe nada del dominio: devuelve un ``AIResult`` con el texto
crudo y deja el parseo/validación a quien lo consume (Aegis, Themis, …).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .exceptions import AIFallbackExhaustedError, CircuitBreakerOpenError
from .inputs import AIInput, AIResult
from .strategies import ModelStrategy, ToolExecutor
from .tools import web_search

logger = logging.getLogger(__name__)


def _default_tool_executor(name: str, arguments: dict) -> str:
    """Ejecutor por defecto: resuelve la herramienta ``web_search``."""
    if name == "web_search":
        return web_search(arguments.get("query", ""))
    logger.warning("[scribe] herramienta no soportada solicitada: %s", name)
    return f"[ERROR] Herramienta no soportada: {name}"


class AIGenerator:
    """
    Orquestador de generación con IA agnóstico al backend.

    Attributes:
        strategy: La estrategia de model calling inyectada.
    """

    def __init__(
        self,
        strategy: ModelStrategy,
        *,
        max_retries: int = 3,
        retry_base: float = 1.5,
        breaker_threshold: int = 3,
        breaker_timeout: int = 60,
    ) -> None:
        self.strategy = strategy
        self._max_retries = max_retries
        self._retry_base = retry_base
        self._breaker_threshold = breaker_threshold
        self._breaker_timeout = breaker_timeout

        self._failures = 0
        self._last_failure_time: float | None = None
        self._lock = threading.Lock()

    # ── Circuit breaker ────────────────────────────────────────────────────

    def _check_breaker(self) -> None:
        with self._lock:
            if self._failures >= self._breaker_threshold:
                elapsed = time.time() - (self._last_failure_time or 0)
                if elapsed < self._breaker_timeout:
                    raise CircuitBreakerOpenError(self.strategy.name)
                self._failures = 0

    def _record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def _record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._last_failure_time = time.time()

    # ── API pública ──────────────────────────────────────────────────────────

    def digest(
        self,
        ai_input: AIInput,
        *,
        tool_executor: Optional[ToolExecutor] = None,
    ) -> AIResult:
        """
        Genera contenido a partir de ``ai_input`` usando la estrategia inyectada.

        Args:
            ai_input: Datos a digerir (prompts, ejemplos, tools, opciones).
            tool_executor: Ejecutor de herramientas alternativo. Por defecto
                resuelve ``web_search``.

        Returns:
            AIResult con el texto crudo del modelo.

        Raises:
            CircuitBreakerOpenError: Si el breaker del backend está abierto.
            AIFallbackExhaustedError: Si se agotan los reintentos.
        """
        self._check_breaker()
        executor = tool_executor or _default_tool_executor

        last_error: str = ""
        for attempt in range(self._max_retries):
            try:
                text = self.strategy.complete(ai_input, executor)
                if text:
                    self._record_success()
                    return AIResult(text=text)
                last_error = "respuesta vacía"
            except Exception as exc:  # noqa: BLE001 — se reintenta y se envuelve
                last_error = str(exc)
                logger.error("[scribe] intento %d fallido: %s", attempt + 1, exc)
                self._record_failure()
                if attempt == self._max_retries - 1:
                    raise AIFallbackExhaustedError(self._max_retries, last_error) from exc
                time.sleep(self._retry_base ** attempt)

        # Solo se alcanza si todos los intentos devolvieron texto vacío.
        self._record_failure()
        raise AIFallbackExhaustedError(self._max_retries, last_error or "sin respuesta")
