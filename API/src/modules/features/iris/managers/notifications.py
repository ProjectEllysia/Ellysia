"""
Notificaciones de Iris: aviso por correo de un veredicto Phishing en la
ingesta automática de buzón (``IrisPhishingNotifyManager``), del digest
diario que agrupa los que no eran de alta confianza (``IrisDigestNotifyManager``),
y de los dos avisos operativos de M08 -- conexión que necesita
reautorización (``IrisReauthNotifyManager``) y conexión activa atascada sin
un sync limpio (``IrisStuckSyncNotifyManager``).

Mismo patrón que ``HygeiaNotifyManager`` (``features/hygeia/managers.py``)
en los cuatro: el estado relevante se persiste, se confirma la transacción y
después se encola un job de categoría ``iris.notify`` en TaskQueue; el envío
SMTP corre en el worker (proceso aislado), nunca en el hilo que disparó el
evento. Un fallo de envío se registra y se descarta -- el estado ya quedó
persistido y visible en el panel, con independencia de si el correo llegó o
no.

El correo va siempre al ``User`` dueño del recurso (análisis o conexión), no
necesariamente a la cuenta de correo conectada: quien conecta un buzón puede
no ser el titular de todas las bandejas que vigila, y la alerta debe llegar
a su panel de usuario.

``IrisNotificationPreferenceManager`` resuelve las preferencias de ese
usuario (digest, silenciado temporal, qué avisos operativos quiere) --
``IrisPhishingNotifyManager`` es el único de los cuatro que las consulta
para decidir si notifica ahora, las agrupa en el digest, o las descarta por
estar silenciado; los otros tres no tienen un modo "no crítico" que
retrasar.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.system.taskqueue import TaskQueue, job_context
from src.modules.tools.herald import EmailMessage, build_mailer, render_email

import src.modules.system.config_reading as CR

from ..model import IrisNotificationPreference
from ..repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository, IrisNotificationPreferenceRepository,
)

logger = logging.getLogger(__name__)


#: Centinela para distinguir "el llamante no ha tocado este campo" de "el
#: llamante quiere ponerlo a None" -- ``muted_until=None`` es una operación
#: válida (quitar un silenciado activo), así que ``None`` no puede ser
#: también el valor por defecto de "sin cambios".
_UNSET = object()


class IrisNotificationPreferenceManager:
    """Lectura y escritura de las preferencias de notificación de un
    usuario (M08) -- una fila por usuario, creada perezosamente en el
    primer ``update()``."""

    @staticmethod
    def get_or_default(user_id: int) -> IrisNotificationPreference:
        """Preferencias del usuario, o una instancia (sin persistir) con los
        valores por defecto del modelo si nunca las ha tocado.

        No persistir la fila por defecto evita crear preferencias para
        cualquier usuario que solo consulte ``GET /iris/notification-preferences``
        una vez -- se persiste de verdad la primera vez que cambia algo.
        """
        existing = build_repository(IrisNotificationPreferenceRepository).get_by_user_id(user_id)
        if existing is not None:
            return existing
        # Los defaults de las columnas ("default=...") solo se aplican al
        # hacer flush -- una instancia sin persistir se queda con None si no
        # se rellenan aquí a mano.
        return IrisNotificationPreference(
            user_id=user_id, digest_enabled=False,
            notify_reauth_required=True, notify_sync_stuck=True,
        )

    @staticmethod
    def update(
        user_id: int, *,
        digest_enabled: Any = _UNSET,
        muted_for_minutes: Any = _UNSET,
        notify_reauth_required: Any = _UNSET,
        notify_sync_stuck: Any = _UNSET,
    ) -> IrisNotificationPreference:
        """Aplica los cambios recibidos sobre la fila del usuario,
        creándola si es la primera vez que la toca.

        Args:
            user_id: Dueño de las preferencias.
            digest_enabled: Nuevo valor, o ``_UNSET`` (el valor por defecto)
                para no tocarlo.
            muted_for_minutes: Cuántos minutos silenciar a partir de ahora
                (``muted_until = utcnow_naive() + timedelta(minutes=...)``),
                ``0`` para quitar un silenciado activo, o ``_UNSET`` para no
                tocarlo. En minutos relativos y no en una fecha absoluta
                porque el cliente conoce "cuánto tiempo" (una hora, un día,
                una semana), no un instante en UTC -- resolverlo aquí evita
                aceptar una fecha con zona horaria ambigua desde fuera.
            notify_reauth_required: Nuevo valor, o ``_UNSET`` para no tocarlo.
            notify_sync_stuck: Nuevo valor, o ``_UNSET`` para no tocarlo.

        Returns:
            IrisNotificationPreference: La fila ya persistida con los
                cambios aplicados.
        """
        with UnitOfWork() as uow:
            repo = IrisNotificationPreferenceRepository(uow)
            preference = repo.get_by_user_id(user_id)
            if preference is None:
                preference = IrisNotificationPreference(user_id=user_id)
            if digest_enabled is not _UNSET:
                preference.digest_enabled = digest_enabled
            if muted_for_minutes is not _UNSET:
                preference.muted_until = (
                    utcnow_naive() + timedelta(minutes=muted_for_minutes)
                    if muted_for_minutes > 0 else None
                )
            if notify_reauth_required is not _UNSET:
                preference.notify_reauth_required = notify_reauth_required
            if notify_sync_stuck is not _UNSET:
                preference.notify_sync_stuck = notify_sync_stuck
            repo.save(preference)
            return preference


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
        """Envía el correo de aviso al dueño del análisis, salvo que las
        preferencias de M08 digan que debe esperar al digest o que el
        usuario lo tiene silenciado.

        Re-comprueba veredicto y origen aquí dentro (un job encolado por
        error, o re-enviado tras un fallo de cola, no debe mandar un correo
        que ya no corresponde): solo los análisis de buzón (``connection_id``
        no nulo) con veredicto final ``Phishing`` notifican. Un fallo SMTP
        se registra y se descarta; nunca revierte un análisis ya finalizado.

        Un veredicto de alta confianza (``total_score`` en o por debajo de
        ``iris.criticalPhishingScoreThreshold``) ignora tanto el silenciado
        como el digest -- el criterio de cierre de M08 exige que nunca se
        pierda una incidencia crítica.
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

        is_critical = analysis.total_score <= CR.iris_config().critical_phishing_score_threshold
        if not is_critical:
            preference = build_repository(IrisNotificationPreferenceRepository).get_by_user_id(
                analysis.user_id,
            )
            if preference is not None:
                if preference.muted_until is not None and preference.muted_until > utcnow_naive():
                    logger.info(f"Notificación de phishing silenciada para el análisis {analysis_id}")
                    return
                if preference.digest_enabled:
                    logger.info(
                        f"Notificación de phishing del análisis {analysis_id} diferida al digest diario"
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


class IrisDigestNotifyManager:
    """Envía el resumen diario de veredictos Phishing no críticos que
    quedaron diferidos por ``digest_enabled`` (M08, categoría ``iris.notify``)."""

    TASK_CATEGORY = "iris.notify"
    EXTERNAL_ID_PREFIX = "iris-digest-notify:"

    @staticmethod
    def enqueue_for(user_id: int) -> None:
        """Encola el digest de ``user_id``. Llamado por el scheduler de
        notificaciones de Iris (``services/notifications/scheduling.py``),
        nunca directamente por el usuario."""
        TaskQueue.get_instance().submit(
            func=IrisDigestNotifyManager.execute_notify_digest,
            args=(user_id,),
            name=f"IrisDigestNotify-{user_id}",
            category=IrisDigestNotifyManager.TASK_CATEGORY,
            external_id=f"{IrisDigestNotifyManager.EXTERNAL_ID_PREFIX}{user_id}",
        )

    @staticmethod
    def execute_notify_digest(user_id: int) -> None:
        """Entry point submitted to the TaskQueue for background email sending."""
        with job_context():
            IrisDigestNotifyManager._run_notify(user_id)

    @staticmethod
    def _run_notify(user_id: int) -> None:
        """Reúne los veredictos Phishing no críticos desde el último digest
        y envía un único correo resumen, si hay alguno.

        Re-comprueba ``digest_enabled`` aquí dentro por el mismo motivo que
        el resto de managers de este fichero: el usuario pudo desactivarlo
        entre que el scheduler lo encoló y que el worker lo ejecuta.
        ``digest_last_sent_at`` avanza tanto si había algo que resumir como
        si no -- si no avanzara con la bandeja vacía, la ventana se iría
        acumulando sin límite hasta el primer Phishing, y ese correo
        arrastraría semanas de "nada que contar" mezcladas con el aviso real.
        Si el envío SMTP falla, en cambio, no se avanza: mejor reintentar en
        el siguiente ciclo del scheduler que dar por enviado un digest que
        nunca llegó.
        """
        from src.modules.users.managers import UserManager

        preference = build_repository(IrisNotificationPreferenceRepository).get_by_user_id(user_id)
        if preference is None or not preference.digest_enabled:
            return

        since = preference.digest_last_sent_at or preference.created_at
        critical_threshold = CR.iris_config().critical_phishing_score_threshold
        analyses = build_repository(IrisAnalysisRepository).get_non_critical_phishing_since(
            user_id, since, critical_threshold,
        )
        now = utcnow_naive()

        if analyses:
            user = UserManager().get_user_by_id(user_id)
            if user is None:
                logger.error(f"Usuario {user_id} no encontrado para enviar su digest de Iris")
                return
            html_body, text_body = render_email(
                "iris_digest",
                analyses=[
                    {"analysis_id": a.id, "subject": a.title or "Correo sin asunto", "score": a.total_score}
                    for a in analyses
                ],
                recipient_name=user.first_name,
            )
            message = EmailMessage(
                to=user.email,
                to_name=user.first_name,
                subject=f"[Iris] Resumen diario: {len(analyses)} correo(s) sospechoso(s)",
                html_body=html_body,
                text_body=text_body,
            )
            try:
                build_mailer("iris").send(message)
                logger.info(f"Digest de Iris enviado a {user_id} con {len(analyses)} análisis")
            except Exception as exc:
                logger.error(f"Fallo enviando el digest de Iris a {user_id}: {exc}", exc_info=True)
                return

        with UnitOfWork() as uow:
            repo = IrisNotificationPreferenceRepository(uow)
            fresh = repo.get_by_user_id(user_id)
            if fresh is not None:
                fresh.digest_last_sent_at = now
                repo.update(fresh)


class IrisReauthNotifyManager:
    """Avisa por correo cuando una conexión de buzón pasa a necesitar
    reautorización (M08, categoría ``iris.notify``)."""

    TASK_CATEGORY = "iris.notify"
    EXTERNAL_ID_PREFIX = "iris-reauth-notify:"

    @staticmethod
    def enqueue_for(connection_id: int) -> None:
        """Encola el aviso de ``connection_id``. Llamado desde
        ``IrisMailboxManager._mark_reauth_required`` solo en la transición
        hacia ese estado, nunca en cada sondeo mientras sigue en él."""
        TaskQueue.get_instance().submit(
            func=IrisReauthNotifyManager.execute_notify_reauth,
            args=(connection_id,),
            name=f"IrisReauthNotify-{connection_id}",
            category=IrisReauthNotifyManager.TASK_CATEGORY,
            external_id=f"{IrisReauthNotifyManager.EXTERNAL_ID_PREFIX}{connection_id}",
        )

    @staticmethod
    def execute_notify_reauth(connection_id: int) -> None:
        """Entry point submitted to the TaskQueue for background email sending."""
        with job_context():
            IrisReauthNotifyManager._run_notify(connection_id)

    @staticmethod
    def _run_notify(connection_id: int) -> None:
        """Envía el aviso al dueño de la conexión, salvo que ya haya vuelto
        a estar activa o el usuario tenga desactivado este aviso.

        No consulta ``muted_until``: un silenciado temporal es para bajar el
        ruido de veredictos de correo, no para dejar de saber que Iris ha
        dejado de vigilar un buzón por completo -- eso lo controla solo
        ``notify_reauth_required``.
        """
        from src.modules.users.managers import UserManager

        connection = build_repository(IrisMailboxConnectionRepository).get_by_id(connection_id)
        if connection is None or connection.status != "reauth_required":
            logger.info(
                f"Aviso de reautenticación descartado para la conexión {connection_id} "
                f"(status={connection.status if connection else 'borrada'})"
            )
            return

        preference = build_repository(IrisNotificationPreferenceRepository).get_by_user_id(
            connection.user_id,
        )
        if preference is not None and not preference.notify_reauth_required:
            return

        user = UserManager().get_user_by_id(connection.user_id)
        if user is None:
            logger.error(f"Usuario {connection.user_id} no encontrado para avisar de la conexión {connection_id}")
            return

        html_body, text_body = render_email(
            "iris_reauth_required",
            account_email=connection.account_email,
            recipient_name=user.first_name,
        )
        message = EmailMessage(
            to=user.email,
            to_name=user.first_name,
            subject=f"[Iris] Reconecta tu buzón: {connection.account_email}",
            html_body=html_body,
            text_body=text_body,
        )
        try:
            build_mailer("iris").send(message)
            logger.info(f"Aviso de reautenticación enviado para la conexión {connection_id}")
        except Exception as exc:
            logger.error(
                f"Fallo enviando el aviso de reautenticación de la conexión {connection_id}: {exc}",
                exc_info=True,
            )


class IrisStuckSyncNotifyManager:
    """Avisa por correo cuando una conexión activa lleva atascada sin un
    sync limpio (M08, categoría ``iris.notify``)."""

    TASK_CATEGORY = "iris.notify"
    EXTERNAL_ID_PREFIX = "iris-stuck-sync-notify:"

    @staticmethod
    def enqueue_for(connection_id: int) -> None:
        """Encola el aviso de ``connection_id``. Llamado desde el scheduler
        de notificaciones de Iris, que ya ha marcado ``stuck_alert_sent_at``
        antes de encolar -- ver ``services/notifications/scheduling.py``."""
        TaskQueue.get_instance().submit(
            func=IrisStuckSyncNotifyManager.execute_notify_stuck,
            args=(connection_id,),
            name=f"IrisStuckSyncNotify-{connection_id}",
            category=IrisStuckSyncNotifyManager.TASK_CATEGORY,
            external_id=f"{IrisStuckSyncNotifyManager.EXTERNAL_ID_PREFIX}{connection_id}",
        )

    @staticmethod
    def execute_notify_stuck(connection_id: int) -> None:
        """Entry point submitted to the TaskQueue for background email sending."""
        with job_context():
            IrisStuckSyncNotifyManager._run_notify(connection_id)

    @staticmethod
    def _run_notify(connection_id: int) -> None:
        """Envía el aviso al dueño de la conexión, salvo que el usuario
        tenga desactivado este aviso concreto."""
        from src.modules.users.managers import UserManager

        connection = build_repository(IrisMailboxConnectionRepository).get_by_id(connection_id)
        if connection is None:
            logger.error(f"Conexión {connection_id} no encontrada para avisar de atasco")
            return

        preference = build_repository(IrisNotificationPreferenceRepository).get_by_user_id(
            connection.user_id,
        )
        if preference is not None and not preference.notify_sync_stuck:
            return

        user = UserManager().get_user_by_id(connection.user_id)
        if user is None:
            logger.error(f"Usuario {connection.user_id} no encontrado para avisar de la conexión {connection_id}")
            return

        html_body, text_body = render_email(
            "iris_sync_stuck",
            account_email=connection.account_email,
            last_success_at=connection.last_success_at,
            recipient_name=user.first_name,
        )
        message = EmailMessage(
            to=user.email,
            to_name=user.first_name,
            subject=f"[Iris] Tu buzón lleva un tiempo sin sincronizar: {connection.account_email}",
            html_body=html_body,
            text_body=text_body,
        )
        try:
            build_mailer("iris").send(message)
            logger.info(f"Aviso de sync atascado enviado para la conexión {connection_id}")
        except Exception as exc:
            logger.error(
                f"Fallo enviando el aviso de sync atascado de la conexión {connection_id}: {exc}",
                exc_info=True,
            )
