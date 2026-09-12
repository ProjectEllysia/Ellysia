"""
CampaignManager — campañas de concienciación.

CRUD de listas de distribución y sus destinatarios, y el ciclo de vida de
una campaña: creación (draft), lanzamiento (snapshot del quiz + tokens
opacos por destinatario) y envío asíncrono vía TaskQueue. También el
tracking de apertura/finalización del quiz público, consumido por los
endpoints sin autenticación.

El envío de email delega en el módulo transversal ``herald``
(``build_mailer("aegis").send(...)``): este manager no sabe nada de SMTP —
tampoco de cómo se pinta una marca: el white-labeling se resuelve con las
piezas compartidas (``shared.WhiteLabel`` + ``herald.apply_white_label``) y
aquí solo se leen los ajustes del perfil de la organización.
"""

from __future__ import annotations

import logging
import secrets

from sqlalchemy.exc import IntegrityError

from src.modules.features.aegis.exceptions import (
    CampaignAlreadyLaunchedError,
    CampaignEmptyListError,
    CampaignNoQuestionsError,
    CampaignNotFoundError,
    DistributionListNotFoundError,
    DocumentNotFoundError,
    DocumentNotReadyError,
    QuizAlreadyCompletedError,
    QuizTokenInvalidError,
)
import src.modules.system.config_reading as CR
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.tools.herald import (
    EmailMessage,
    Mailer,
    apply_white_label,
    build_mailer,
    default_brand,
    render_email,
)
from src.modules.users import User
from src.modules.system.taskqueue import ITaskQueue, TaskTrackingMixin, job_context
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox import build_dispatch
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import WhiteLabel, WhiteLabelLevel, assert_owned

from .org_profile import AegisOrgProfileManager
from ..model import Campaign, CampaignRecipient, DistributionList
from ..repositories import (
    AegisDocumentRepository,
    AegisOrgProfileRepository,
    CampaignRepository,
    DistributionListRepository,
)


logger = logging.getLogger(__name__)


class CampaignManager(TaskTrackingMixin):
    """
    Gestiona listas de distribución y campañas de concienciación.

    Sigue la convención del proyecto para el acceso a datos: las **lecturas**
    usan ``build_repository(RepoCls)`` (sesión ambiental de la request, sin demarcar
    transacción) y las **escrituras** van dentro de un ``UnitOfWork``. El
    manager nunca crea ni cierra sesiones — de eso se encargan los bordes
    (``teardown_request`` en HTTP, ``job_context`` en el worker).
    """

    EXTERNAL_ID_PREFIX = "aegis-campaign:"
    TASK_CATEGORY = "aegis.campaign"

    def __init__(
        self,
        user: User,
        task_queue: ITaskQueue | None = None,
        mailer: Mailer | None = None,
    ) -> None:
        # A9: mailer inyectable — igual que ai_writer en AegisManager, se
        # guarda tal cual (puede ser None) y el default se construye de
        # forma perezosa en _run_campaign_send, no aquí.
        self.user = user
        super().__init__(task_queue)
        self.mailer = mailer

    # =========================================================================
    # DISTRIBUTION LISTS
    # =========================================================================

    def create_list(self, name: str) -> dict:
        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            distribution_list = repo.create_list(self.user.id, name)
            return distribution_list.to_dict()

    def list_lists(self) -> list[dict]:
        repo = build_repository(DistributionListRepository)
        return [distribution_list.to_dict() for distribution_list in repo.get_lists_by_user(self.user.id)]

    def get_list(self, list_id: int) -> dict:
        distribution_list = self._assert_list_ownership(list_id)
        return distribution_list.to_dict()

    def delete_list(self, list_id: int) -> None:
        with UnitOfWork() as uow:
            distribution_list = assert_owned(
                DistributionListRepository, list_id, self.user.id,
                DistributionListNotFoundError, uow=uow,
            )

            # Campaign.list_id no tiene ON DELETE CASCADE en BD: borrar la
            # lista con campañas colgando de ella violaba la FK, y el fallo
            # saltaba en el commit de teardown_request — fuera ya de
            # handle_exceptions, así que llegaba al cliente como un 500 mudo.
            # Mismo tratamiento que al borrar una píldora (AegisManager):
            # se borran antes las campañas, arrastrando sus destinatarios y
            # respuestas por cascade="all, delete-orphan".
            campaign_repo = CampaignRepository(uow)
            for campaign in campaign_repo.get_campaigns_by_list(list_id):
                campaign_repo.delete(campaign)

            DistributionListRepository(uow).delete(distribution_list)

    def add_recipients(self, list_id: int, recipients: list[dict]) -> list[dict]:
        self._assert_list_ownership(list_id)

        # El tope es de destinatarios totales, no por lista: se cobran todos los
        # del lote de golpe para que no se pueda rebasar metiéndolos de uno en
        # uno. Son existencias, así que borrar destinatarios devuelve el hueco.
        QuotaManager().consume(self.user.id, LimitKey.AEGIS_RECIPIENTS, amount=len(recipients))

        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            created = repo.add_recipients(list_id, recipients)
            return [recipient.to_dict() for recipient in created]

    def get_recipients(self, list_id: int) -> list[dict]:
        self._assert_list_ownership(list_id)
        repo = build_repository(DistributionListRepository)
        return [recipient.to_dict() for recipient in repo.get_recipients(list_id)]

    def remove_recipient(self, list_id: int, recipient_id: int) -> None:
        self._assert_list_ownership(list_id)
        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            repo.remove_recipient(list_id, recipient_id)

    def _assert_list_ownership(self, list_id: int) -> DistributionList:
        return assert_owned(DistributionListRepository, list_id, self.user.id, DistributionListNotFoundError)

    # =========================================================================
    # CAMPAIGNS
    # =========================================================================

    def create_campaign(self, document_id: int, list_id: int, name: str) -> dict:
        document = assert_owned(AegisDocumentRepository, document_id, self.user.id, DocumentNotFoundError)
        if document.status != "done":
            raise DocumentNotReadyError(document_id, document.status)

        self._assert_list_ownership(list_id)

        with UnitOfWork() as uow:
            repo = CampaignRepository(uow)
            campaign = repo.create_campaign(self.user.id, document_id, list_id, name)
            return campaign.to_dict()

    def list_campaigns(self) -> list[dict]:
        """Lista las campañas del usuario, de la más reciente a la más antigua, con su resumen de progreso.

        Cada campaña trae, además de sus datos, cuántos destinatarios tiene y
        cuántos abrieron el enlace, cuántos completaron el test y su nota
        media. Así quien consulta varias campañas a la vez no tiene que pedir
        el detalle de cada una.

        Returns:
            list[dict]: Una entrada por campaña con los campos de
                ``Campaign.to_dict()`` más ``recipientCount``, ``openedCount``,
                ``completedCount`` y ``averageScore``. Un borrador todavía no
                tiene destinatarios: sale con los contadores a cero y
                ``averageScore`` a ``None``.
        """
        repo = build_repository(CampaignRepository)
        campaigns = repo.get_campaigns_by_user(self.user.id)
        summaries = repo.get_recipient_summaries([campaign.id for campaign in campaigns])
        empty_summary = {"recipientCount": 0, "openedCount": 0, "completedCount": 0, "averageScore": None}
        return [
            {**campaign.to_dict(), **summaries.get(campaign.id, empty_summary)}
            for campaign in campaigns
        ]

    def get_campaign(self, campaign_id: int) -> dict:
        campaign = self._assert_campaign_ownership(campaign_id)
        repo = build_repository(CampaignRepository)
        recipients = repo.get_recipients(campaign_id)
        result = campaign.to_dict()
        result["recipients"] = [recipient.to_dict() for recipient in recipients]
        return result

    def launch_campaign(self, campaign_id: int) -> dict:
        """
        Lanza una campaña: congela el quiz (snapshot), genera un token
        opaco por destinatario y encola el envío asíncrono. No envía nada
        de forma síncrona — eso lo hace el worker vía TaskQueue.
        """
        campaign = self._assert_campaign_ownership(campaign_id)
        if campaign.status != "draft":
            raise CampaignAlreadyLaunchedError(campaign_id, campaign.status)

        doc_repo = build_repository(AegisDocumentRepository)
        document = doc_repo.get_by_id(campaign.document_id)
        questions_snapshot = [question.to_dict() for question in document.questions] if document else []
        if not questions_snapshot:
            raise CampaignNoQuestionsError(campaign.document_id)

        list_repo = build_repository(DistributionListRepository)
        recipients = list_repo.get_recipients(campaign.list_id)
        if not recipients:
            raise CampaignEmptyListError(campaign.list_id)

        # Se cobra al lanzar, no al crear el borrador: un borrador no manda
        # correos ni cuesta nada. Y después de las validaciones — una campaña
        # sin preguntas o sin destinatarios no llega a lanzarse, así que
        # tampoco debe gastar.
        QuotaManager().consume(self.user.id, LimitKey.AEGIS_CAMPAIGNS)

        campaign_recipients = [
            CampaignRecipient(
                recipient_email=recipient.email,
                recipient_name=recipient.name,
                token=secrets.token_urlsafe(32),
            )
            for recipient in recipients
        ]

        with UnitOfWork() as uow:
            repo = CampaignRepository(uow)
            repo.launch_campaign(campaign_id, questions_snapshot, campaign_recipients)
            # La intención de encolar va en la MISMA transacción que el
            # lanzamiento. Antes el submit caía fuera, y si Redis fallaba
            # justo ahí la campaña quedaba lanzada —snapshot congelado, tokens
            # acuñados, cuota cobrada— pero sin un solo correo enviado y sin
            # nada que lo reintentase: no hay reconciliación de campañas.
            #
            # Repetir el envío es seguro, que es lo que la outbox exige de todo
            # consumidor suyo: `_run_campaign_send` solo toma los destinatarios
            # con `sent_at is None` y confirma cada `mark_sent()` en su propia
            # transacción, así que un segundo intento alcanza únicamente a quien
            # todavía no recibió el correo.
            dispatch = TaskDispatchRepository(uow).save(build_dispatch(
                func=CampaignManager.execute_campaign_send,
                name=f"CampaignSend-{campaign_id}",
                category=self.TASK_CATEGORY,
                args=(campaign_id, self.user.id),
                external_id=self.external_id_for(campaign_id),
            ))
            dispatch_id = dispatch.id
            # Durable antes de encolar: el worker corre en otro proceso y debe
            # ver el snapshot + los tokens ya persistidos.
            uow.commit_for_handoff()

        # Camino feliz: publicar ya, para no añadir latencia cuando Redis está
        # arriba. Si falla, la fila queda `pending` y la recogen el barrido
        # periódico o la reconciliación de arranque.
        OutboxDispatcher.dispatch(dispatch_id, task_queue=self._task_queue)
        logger.info(f"Campaña {campaign_id} lanzada: {len(campaign_recipients)} destinatarios")

        return self.get_campaign(campaign_id)

    def _assert_campaign_ownership(self, campaign_id: int) -> Campaign:
        return assert_owned(CampaignRepository, campaign_id, self.user.id, CampaignNotFoundError)

    def delete_campaign(self, campaign_id: int) -> None:
        """
        Elimina una campaña y todo su tracking (destinatarios, respuestas).

        Borra las filas CampaignRecipient en cascada (cascade="all,
        delete-orphan" en Campaign.recipients), lo que se lleva por delante
        sus tokens: cualquier enlace de correo ya enviado para esta campaña
        pasa a devolver QuizTokenInvalidError (404) — es la forma en que se
        "invalida" la URL, no hay una lista de revocación aparte.
        """
        campaign = self._assert_campaign_ownership(campaign_id)
        with UnitOfWork() as uow:
            CampaignRepository(uow).delete(campaign)

    # =========================================================================
    # WORKFLOW DE ENVÍO (privado, ejecutado en el worker RQ)
    # =========================================================================

    @staticmethod
    def execute_campaign_send(campaign_id: int, user_id: int) -> None:
        """Entry point submitted to the TaskQueue for background sending."""
        from src.modules.users.managers import UserManager

        user = UserManager().get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        CampaignManager(user)._run_campaign_send(campaign_id)

    def _run_campaign_send(self, campaign_id: int) -> None:
        """Envía el email de la campaña a cada destinatario pendiente."""
        with job_context() as job:
            campaign_repository = build_repository(CampaignRepository)
            campaign = campaign_repository.get_by_id(campaign_id)
            if campaign is None:
                logger.error(f"Campaña {campaign_id} no encontrada para envío")
                return

            document = campaign.document
            recipients = [recipient for recipient in campaign_repository.get_recipients(campaign_id) if recipient.sent_at is None]
            total = len(recipients)
            if total == 0:
                logger.info(f"Campaña {campaign_id}: no hay destinatarios pendientes de envío")
                return

            base_url = CR.general_config().public_url
            mailer = self.mailer or build_mailer("aegis")
            pill_title = document.subtitle or document.title if document else "Formación de concienciación"

            # La píldora se entrega dentro del propio correo (no solo el
            # enlace al test): el destinatario nunca la recibía por ningún
            # otro canal, así que el test evaluaba un contenido que no se le
            # había hecho llegar. Mismos campos que consume HTMLExporter,
            # pero renderizados aquí con la plantilla de correo (tablas +
            # estilos inline) en vez del HTML de exportación — ese usa
            # <style> en <head> y no es válido embebido dentro de un correo.
            pill_intro = document.intro if document else ""
            pill_closing = document.closing if document else ""
            pill_company = document.company if document else ""
            pill_contact_email = document.contact_email if document else ""
            # Mismo tratamiento que los exportadores (services/exporters.py):
            # "seguridad@empresa.com" es el placeholder por defecto de la IA
            # cuando no se indicó un contacto real — no se envía como si fuera
            # un correo válido, se sustituye por una frase.
            pill_contact_is_placeholder = pill_contact_email == "seguridad@empresa.com"
            pill_tips = [tip.to_dict() for tip in (document.tips if document else [])]
            # Los avisos cuelgan del documento ya cargado: ninguna consulta extra.
            pill_alerts = [
                alert.to_dict()
                for alert in sorted(document.alerts, key=lambda a: a.position)
            ] if document else []

            # White-labeling: los ajustes son del perfil de la organización y
            # se leen una vez, no por destinatario — la marca es la misma para
            # toda la campaña. El nombre con el que sustituir la del producto
            # es el que el destinatario ya lee en el cuerpo ("Desde X, te
            # hacemos llegar…"), para que cabecera y texto no se contradigan.
            profile = build_repository(AegisOrgProfileRepository).get_by_user_id(self.user.id)
            white_label = WhiteLabel.from_stored(
                profile.white_label_level if profile else None,
                profile.brand_logo if profile else None,
                profile.brand_color if profile else None,
                pill_company or (profile.company if profile else ""),
            )
            # El tope del plan se vuelve a aplicar aquí: entre que se guardó el
            # ajuste y se envía la campaña la suscripción puede haber bajado.
            white_label = white_label.capped_to(
                AegisOrgProfileManager.max_white_label_level(self.user.id)
            )
            brand, brand_images = apply_white_label(default_brand(), white_label)

            sent_count = 0
            was_cancelled = False
            for i, recipient in enumerate(recipients):
                if job.cancelled():
                    was_cancelled = True
                    break

                # /quiz, no /aegis/quiz: la página del quiz vive en el SPA y
                # todo lo que cuelga de /aegis/ lo captura el proxy hacia Flask
                # (matcher @api del Caddyfile, vite.config.js) — el
                # destinatario vería el JSON.
                link = f"{base_url}/quiz?t={recipient.token}"
                html_body, text_body = render_email(
                    "campaign",
                    brand=brand,
                    pill_title=pill_title,
                    link=link,
                    recipient_name=recipient.recipient_name,
                    company=pill_company,
                    intro=pill_intro,
                    tips=pill_tips,
                    closing=pill_closing,
                    contact_email=pill_contact_email,
                    contact_is_placeholder=pill_contact_is_placeholder,
                    alerts=pill_alerts,
                )
                message = EmailMessage(
                    to=recipient.recipient_email,
                    to_name=recipient.recipient_name,
                    subject=f"Formación de concienciación: {pill_title}",
                    html_body=html_body,
                    text_body=text_body,
                    inline_images=brand_images,
                )
                try:
                    mailer.send(message)
                    with UnitOfWork() as uow:
                        CampaignRepository(uow).mark_sent(recipient.id)
                    sent_count += 1
                except Exception as exc:
                    logger.error(
                        f"Fallo enviando campaña {campaign_id} a "
                        f"{recipient.recipient_email}: {exc}"
                    )

                job.progress(int(100 * (i + 1) / total))

            if not was_cancelled:
                # No mentir sobre el resultado: si ningún envío tuvo éxito la
                # campaña no se "envió". Solo se marca 'sent' cuando al menos un
                # destinatario recibió el correo.
                final_status = "sent" if sent_count > 0 else "failed"
                with UnitOfWork() as uow:
                    CampaignRepository(uow).mark_campaign_status(campaign_id, final_status)

            logger.info(
                f"Campaña {campaign_id} procesada: {sent_count}/{total} enviados"
                f"{' (cancelada)' if was_cancelled else ''}"
            )

    # =========================================================================
    # PÁGINA PÚBLICA DEL QUIZ (sin autenticación — el token ES la identidad)
    # =========================================================================

    @staticmethod
    def get_public_quiz(token: str) -> dict:
        """
        Vista pública del quiz para un token dado — SIN respuestas correctas.

        No requiere autenticación ni instancia de usuario: el token es la
        única identidad. Si el test ya fue completado, devuelve el estado
        final (score) en vez de volver a servir las preguntas.
        """
        repo = build_repository(CampaignRepository)
        recipient = repo.get_recipient_by_token(token)
        if recipient is None:
            raise QuizTokenInvalidError()

        campaign = recipient.campaign
        snapshot = campaign.questions_snapshot or []

        white_label = CampaignManager._public_white_label(campaign)

        if recipient.status == "completed":
            return {
                "status": "completed",
                "score": recipient.score,
                "total": len(snapshot),
                "whiteLabel": white_label,
            }

        if recipient.status == "sent":
            with UnitOfWork() as uow:
                CampaignRepository(uow).mark_opened(recipient.id)

        document = campaign.document
        return {
            "status": "opened",
            "whiteLabel": white_label,
            "pillTitle": (document.subtitle or document.title) if document else "",
            "questions": [
                {"position": question["position"], "prompt": question["prompt"], "options": question["options"]}
                for question in snapshot
            ],
        }

    @staticmethod
    def _public_white_label(campaign: Campaign) -> dict:
        """Marca que ve el destinatario en la página del test.

        La misma que en el correo y resuelta igual (ajustes del perfil, topados
        por el plan): el test es la segunda mitad de la campaña y sería raro
        que la primera llegara sin marca del producto y la segunda con ella.

        Se sirve por un endpoint sin autenticar, así que solo sale lo que ese
        destinatario ya ha recibido en su correo — nombre y logo de su propia
        organización, nada más.
        """
        document = campaign.document
        if document is None:
            return {
                "level": WhiteLabelLevel.NONE.value,
                "brandName": "", "brandLogo": "", "brandColor": "",
            }

        profile = build_repository(AegisOrgProfileRepository).get_by_user_id(document.user_id)
        white_label = WhiteLabel.from_stored(
            profile.white_label_level if profile else None,
            profile.brand_logo if profile else None,
            profile.brand_color if profile else None,
            document.company or (profile.company if profile else ""),
        ).capped_to(AegisOrgProfileManager.max_white_label_level(document.user_id))

        level = white_label.effective_level
        if level is WhiteLabelLevel.NONE:
            return {"level": level.value, "brandName": "", "brandLogo": "", "brandColor": ""}

        return {
            "level": level.value,
            "brandName": white_label.brand_name,
            # El logo solo se pinta desde el escalón que lo introduce; en COLOR
            # el ajuste puede existir y no tocar todavía.
            "brandLogo": white_label.logo if level.rank >= WhiteLabelLevel.LOGO.rank else "",
            "brandColor": white_label.color,
        }

    @staticmethod
    def submit_public_quiz(token: str, answers: list[dict]) -> dict:
        """
        Corrige y persiste las respuestas de un quiz público.

        Regla no-repetir: si el token ya está 'completed', rechaza con
        QuizAlreadyCompletedError (409) sin aceptar respuestas nuevas. La
        comprobación de estado cierra la ventana normal, y la
        UniqueConstraint(campaign_recipient_id, question_position) de
        CampaignAnswer cierra la carrera entre dos envíos concurrentes del
        mismo token (el segundo falla al hacer flush y se traduce al mismo
        409) — el token nunca puede completar el test dos veces.
        """
        repo = build_repository(CampaignRepository)
        recipient = repo.get_recipient_by_token(token)
        if recipient is None:
            raise QuizTokenInvalidError()
        if recipient.status == "completed":
            raise QuizAlreadyCompletedError()

        snapshot = {question["position"]: question for question in (recipient.campaign.questions_snapshot or [])}

        answers_data = []
        for answer in answers:
            position = answer["questionPosition"]
            question = snapshot.get(position)
            if question is None:
                continue
            selected_index = answer["selectedIndex"]
            answers_data.append({
                "question_position": position,
                "selected_index": selected_index,
                "is_correct": selected_index == question.get("correctIndex"),
            })

        score = sum(1 for answer in answers_data if answer["is_correct"])

        try:
            with UnitOfWork() as uow:
                CampaignRepository(uow).mark_completed(recipient.id, score, answers_data)
        except IntegrityError:
            raise QuizAlreadyCompletedError()

        return {"status": "completed", "score": score, "total": len(snapshot)}
