"""
herald.mailer
─────────────
``Mailer``: la entidad central del módulo.

Se construye con una estrategia de envío inyectada (inyección de
dependencias) y expone dos métodos públicos:

    — send: envía un único mensaje, propagando el error si falla (igual que
      ``AIGenerator.digest`` para una generación individual).
    — send_bulk: envía una lista de mensajes SIN abortar el lote ante un
      fallo individual — un destinatario inválido no debe tirar abajo una
      campaña completa de N destinatarios.

El mailer no sabe nada del dominio (campañas, píldoras, …); eso vive en el
módulo consumidor (Aegis).
"""

from __future__ import annotations

import logging

from .inputs import EmailMessage, SendResult
from .strategies import EmailStrategy

logger = logging.getLogger(__name__)


class Mailer:
    """Orquestador de envío de correo agnóstico al proveedor."""

    def __init__(self, strategy: EmailStrategy) -> None:
        self.strategy = strategy

    def send(self, message: EmailMessage) -> SendResult:
        """
        Envía ``message`` usando la estrategia inyectada.

        Raises:
            EmailConnectionError: Si falla la comunicación con el proveedor.
            EmailSendError: Si el proveedor rechaza el mensaje.
        """
        return self.strategy.send(message)

    def send_bulk(self, messages: list[EmailMessage]) -> list[SendResult]:
        """
        Envía cada mensaje de ``messages`` sin abortar el lote ante un fallo
        individual. Devuelve un resultado por mensaje, en el mismo orden.
        """
        results: list[SendResult] = []
        for message in messages:
            try:
                results.append(self.send(message))
            except Exception as exc:  # noqa: BLE001 — se aísla por destinatario
                logger.error("[herald] fallo enviando a %s: %s", message.to, exc)
                results.append(SendResult(ok=False, error=str(exc)))
        return results
