"""
IrisPhishingNotifyManager — aviso por correo cuando la ingesta automática
de buzón clasifica un correo como Phishing.

Mismo patrón que ``HygeiaNotifyManager`` (``features/hygeia/managers.py``):
el análisis se persiste, se confirma la transacción y después se encola un
job de categoría ``iris.notify`` en TaskQueue; el envío SMTP corre en el
worker (proceso aislado), nunca en el hilo que finalizó el análisis. Un
fallo de envío se registra y se descarta — el veredicto ya quedó persistido
y visible en el panel, con independencia de si el correo llegó o no.

El correo va al ``User`` dueño del análisis (``IrisAnalysis.user_id``), no
necesariamente a la cuenta de correo conectada: quien conecta un buzón
puede no ser el titular de todas las bandejas que vigila, y la alerta debe
llegar a su panel de usuario.
"""

from __future__ import annotations

import logging

from src.modules.infrastructure.session import build_repository
from src.modules.system.taskqueue import TaskQueue, job_context
from src.modules.tools.herald import EmailMessage, build_mailer, render_email

from ..repositories import IrisAnalysisRepository

logger = logging.getLogger(__name__)


class IrisPhishingNotifyManager:
    """Envía la notificación por correo de un veredicto Phishing de la
    ingesta automática (categoría ``iris.notify``)."""

    TASK_CATEGORY = "iris.notify"
    EXTERNAL_ID_PREFIX = "iris-phishing-notify:"

    @staticmethod
    def enqueue_for(analysis_id: int) -> None:
        """Encola la notificación del análisis ``analysis_id``.

        Debe llamarse **después** de que la transacción que lo marcó como
        ``finished`` sea durable — el worker corre en otro proceso y no vería
        una fila todavía sin confirmar (mismo contrato que
        ``HygeiaNotifyManager.enqueue_for``).
        """
        TaskQueue.get_instance().submit(
            func=IrisPhishingNotifyManager.execute_notify_phishing,
            args=(analysis_id,),
            name=f"IrisPhishingNotify-{analysis_id}",
            category=IrisPhishingNotifyManager.TASK_CATEGORY,
            external_id=f"{IrisPhishingNotifyManager.EXTERNAL_ID_PREFIX}{analysis_id}",
        )

    @staticmethod
    def execute_notify_phishing(analysis_id: int) -> None:
        """Entry point submitted to the TaskQueue for background email sending."""
        with job_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    @staticmethod
    def _run_notify(analysis_id: int) -> None:
        """Envía el correo de aviso al dueño del análisis.

        Re-comprueba veredicto y origen aquí dentro (un job encolado por
        error, o re-enviado tras un fallo de cola, no debe mandar un correo
        que ya no corresponde): solo los análisis de buzón (``connection_id``
        no nulo) con veredicto final ``Phishing`` notifican. Un fallo SMTP
        se registra y se descarta; nunca revierte un análisis ya finalizado.
        """
        from src.modules.users.managers import UserManager

        analysis = build_repository(IrisAnalysisRepository).get_by_id(analysis_id)
        if analysis is None:
            logger.error(f"Análisis {analysis_id} no encontrado para notificar")
            return
        if analysis.verdict != "Phishing" or analysis.connection_id is None:
            logger.info(
                f"Notificación de phishing descartada para el análisis {analysis_id} "
                f"(verdict={analysis.verdict}, "
                f"origen={'buzón' if analysis.connection_id else 'manual'})"
            )
            return

        user = UserManager().get_user_by_id(analysis.user_id)
        if user is None:
            logger.error(f"Usuario {analysis.user_id} no encontrado para notificar el análisis {analysis_id}")
            return

        subject = analysis.title or "Correo sin asunto"
        html_body, text_body = render_email(
            "iris_phishing",
            subject=subject,
            analysis_id=analysis_id,
            score=analysis.total_score,
            recipient_name=user.first_name,
        )
        message = EmailMessage(
            to=user.email,
            to_name=user.first_name,
            subject=f"[Iris] Ten cuidado con el correo: {subject}",
            html_body=html_body,
            text_body=text_body,
        )
        try:
            build_mailer("iris").send(message)
            logger.info(f"Notificación de phishing enviada para el análisis {analysis_id}")
        except Exception as exc:
            logger.error(
                f"Fallo enviando la notificación de phishing del análisis {analysis_id}: {exc}",
                exc_info=True,
            )
