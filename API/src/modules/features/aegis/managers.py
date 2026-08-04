"""
aegis_managers.py
─────────────────
Managers de operaciones Aegis: generación de píldoras, campañas de
concienciación y el perfil de organización. Todos viven en este único
fichero por convención.

Responsabilidades de AegisOrgProfileManager:
    — Devolver el perfil de organización guardado (o defaults si no existe).
    — Crear o actualizar (upsert) el perfil.

Responsabilidades de AegisManager:
    — Crear documentos pendientes y lanzar el workflow de generación en thread
    — Persistir AegisContent (tips directamente en AegisTip con FK a AegisDocument)
    — Persistir AegisAlert en AegisDocumentAlert
    — Exponer get_document, list_user_documents, delete_document, get_document_path y get_topics

Responsabilidades de CampaignManager:
    — CRUD de listas de distribución y sus destinatarios.
    — Ciclo de vida de una campaña: creación (draft), lanzamiento (snapshot
      del quiz + generación de tokens) y envío asíncrono vía TaskQueue.
    — Tracking de apertura/finalización del quiz público (consumido por los
      endpoints sin autenticación de endpoints.py).
    — El envío de email delega en el módulo transversal `herald`
      (`build_mailer("aegis").send(...)`) — este manager no sabe nada de SMTP.
"""

from __future__ import annotations

import json
import logging
import random
import secrets
import threading
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

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
# ---------------------------------------------------------------------------
# Dependencia de Aegis sobre Themis (KbQueryManager).
#
# Segundo import entre módulos de ``features/``, tras el de Hygeia → Themis,
# y por la misma clase de razón: la base de conocimiento (espejo local de
# NVD/KEV/EPSS, ~350k CVEs refrescados cada noche) ya existe en Themis, y
# Aegis la necesita para saber qué ha sido notable en los productos de una
# organización. Antes se lo preguntaba por HTTP a cve.circl.lu — que es otro
# espejo de NVD, más lento, sin KEV ni EPSS y con la red de por medio. Esto
# no añade una dependencia: retira una.
#
# Va en la MISMA dirección que la de Hygeia (``features/* → themis``), así
# que no abre un sentido nuevo, y entra por ``KbQueryManager``, que devuelve
# dataclasses planas: ninguna entidad del ORM de Themis cruza la frontera.
# Los imports son locales, dentro de los métodos que los usan, para no crear
# un ciclo en tiempo de carga entre los paquetes de features.
#
# Themis sigue sin saber que Aegis existe, y así debe seguir.
# ---------------------------------------------------------------------------
from src.modules.tools.herald import EmailMessage, Mailer, build_mailer, render_email
from src.modules.users import User
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, TaskTrackingMixin, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive, isoformat_utc

from .model import AegisDocument, AegisOrgProfile, Campaign, CampaignRecipient, DistributionList, Topic
from .services import AegisAIWriter, AegisAlertFetcher, AlertSource, AegisAlert, AegisContent
from .repositories import (
    AegisDocumentRepository,
    AegisOrgProfileRepository,
    CampaignRepository,
    DistributionListRepository,
)


logger = logging.getLogger(__name__)


class AegisManager(TaskTrackingMixin):
    """
    Gestiona el ciclo de vida completo de los documentos Aegis:
    creación, generación asíncrona, consulta, exportación y eliminación.

    Toda la persistencia se realiza a través de AegisDocumentRepository
    usando UnitOfWork. El manager no gestiona sesiones directamente.
    """

    EXTERNAL_ID_PREFIX = "aegis-doc:"
    TASK_CATEGORY = "aegis.generate"

    _lock = threading.Lock()

    def __init__(
        self,
        user: User,
        task_queue: ITaskQueue | None = None,
        alert_fetcher: AegisAlertFetcher | None = None,
        ai_writer: AegisAIWriter | None = None,
    ) -> None:
        # A9: alert_fetcher/ai_writer inyectables (mismo patrón que task_queue)
        # — los tests pueden sustituirlos por dobles sin monkeypatchear la clase.
        # ai_writer se guarda tal cual (puede ser None) y solo se construye el
        # default de forma perezosa en generate(): instanciarlo aquí resolvería
        # la estrategia de IA (y loguearía) en cada AegisManager(), incluida
        # la mayoría de llamadas (list/delete/get_topics) que nunca generan.
        self.user = user
        self.alert_fetcher = alert_fetcher or AegisAlertFetcher()
        self.ai_writer = ai_writer
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    # =========================================================================
    # API PÚBLICA
    # =========================================================================

    def generate(self, topic_id: int, tweaks: dict | None = None) -> int:
        """
        Lanza la generacion asincrona de una pildora y devuelve el documentId
        inmediatamente. Thread-safe.
        """
        with self._lock:
            tweaks      = tweaks or {}
            document_id = self._create_pending_document(topic_id)

            self._tq.submit(
                func=AegisManager.execute_aegis_generation,
                args=(document_id, topic_id, tweaks, self.user.id),
                name=f"AegisGen-{document_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(document_id),
            )

        return document_id

    def get_document(self, doc_id: int) -> dict:
        repo = build_repository(AegisDocumentRepository)
        doc = repo.get_by_id(doc_id)
        if not doc:
            raise DocumentNotFoundError(doc_id)

        result = {
            "id": doc.id,
            "internalName": doc.title,
            "title": doc.subtitle or "Sin título",
            "userId": doc.user.id,
            "topicId": doc.topic_id,
            "topicTitle": doc.topic.title if doc.topic else "Tema desconocido",
            "status": doc.status,
            "pill": {
                "subtitle": doc.subtitle,
                "intro": doc.intro,
                "closing": doc.closing,
                "company": doc.company,
                "contactEmail": doc.contact_email,
                "tips": [t.to_dict() for t in doc.tips],
            },
            "alerts": [a.to_dict() for a in doc.alerts],
            "generatedAt": isoformat_utc(doc.generated_at), # type: ignore
        }

        if doc.status == "done": # type: ignore
            result["pill"] = doc.pill_to_dict()
            result["alerts"] = [a.to_dict() for a in sorted(doc.alerts, key=lambda a: a.position)]

        return result

    def update_pill(self, doc_id: int, pill: dict) -> dict:
        """
        Reemplaza el contenido editable de una píldora ya generada (upsert).

        Persiste subtitle, intro, closing, contactEmail, company, tips y
        questions (quiz). Las alertas permanecen inmutables. Mantiene
        sincronizado el 'title' interno (etiqueta del historial) con el nuevo
        subtitle y regenera el JSON de archivo en disco para que /download no
        quede desincronizado con /document y /export.

        Editar las preguntas aquí solo afecta a la píldora fuente: una
        campaña ya lanzada usa su propio Campaign.questions_snapshot y no se
        ve afectada por ediciones posteriores.

        Args:
            doc_id: ID del documento a actualizar (debe existir y ser del usuario).
            pill: Diccionario validado con subtitle, intro, closing,
                  contactEmail, company, tips y questions.

        Returns:
            El documento actualizado (mismo formato que get_document).
        """
        subtitle = pill["subtitle"]
        intro = pill.get("intro", "") or None
        closing = pill.get("closing", "") or None
        contact_email = pill.get("contactEmail", "") or None
        company = pill.get("company", "") or None

        tips_data = [
            {
                "headline": tip["headline"],
                "body": tip["body"],
                "links": (
                    [{"text": lk["text"], "url": lk["url"]} for lk in tip.get("links") or []]
                    or None
                ),
            }
            for tip in pill.get("tips", [])
        ]

        questions_data = [
            {
                "prompt": q["prompt"],
                "options": q["options"],
                "correct_index": q["correctIndex"],
            }
            for q in pill.get("questions", [])
        ]

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            doc = repo.update_content_fields(
                doc_id=doc_id,
                subtitle=subtitle,
                intro=intro,
                closing=closing,
                contact_email=contact_email,
                company=company,
            )
            if doc is not None:
                # Mantener sincronizada la etiqueta del historial (title interno).
                doc.title = subtitle[:64]
            repo.save_tips(doc_id, tips_data)
            repo.save_questions(doc_id, questions_data)
            logger.info(
                f"Píldora {doc_id} actualizada: {len(tips_data)} tips, "
                f"{len(questions_data)} preguntas"
            )

        self._rewrite_archive_file(
            doc_id, subtitle, intro, closing, contact_email, tips_data, questions_data
        )

        return self.get_document(doc_id)

    def _rewrite_archive_file(
        self,
        doc_id: int,
        subtitle: str | None,
        intro: str | None,
        closing: str | None,
        contact_email: str | None,
        tips_data: list[dict],
        questions_data: list[dict],
    ) -> None:
        """
        Reescribe el subárbol 'pill' del JSON de archivo en disco conservando
        metadata y alerts. Si el fichero no existe, registra warning y continúa
        (la BD es la fuente de verdad).
        """
        try:
            path = self.get_document_path(doc_id)

            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            data["pill"] = {
                "subtitle": subtitle or "",
                "intro": intro or "",
                "tips": [
                    {
                        "position": i + 1,
                        "headline": t["headline"],
                        "body": t["body"],
                        "links": t["links"] or [],
                    }
                    for i, t in enumerate(tips_data)
                ],
                "closing": closing or "",
                "contactEmail": contact_email or "",
                "questions": [
                    {
                        "position": i + 1,
                        "prompt": q["prompt"],
                        "options": q["options"],
                        "correctIndex": q["correct_index"],
                    }
                    for i, q in enumerate(questions_data)
                ],
            }

            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning(f"Error reescribiendo archivo de doc {doc_id}: {exc}", exc_info=True)

    def get_document_path(self, document_id: int) -> Path:
        """Devuelve la ruta al archivo generado, validando propiedad y existencia."""
        doc = self.assert_document_ownership(document_id)
        if not doc:
            raise ValueError(f"Documento {document_id} no existe")

        if not doc.filename:
            raise ValueError(f"Documento {document_id} no tiene filename")

        cfg = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {doc.filename}")

        return path

    def delete_document(self, document_id: int) -> None:
        """Elimina el documento de BD y el archivo en disco de forma atómica."""

        cfg = self._read_cfg()
        try:
            with UnitOfWork() as uow:
                repo = AegisDocumentRepository(uow)
                doc = repo.get_by_id(document_id)
                if not doc:
                    raise ValueError(f"Documento {document_id} no existe")

                if doc.filename:
                    file_path = cfg["output_dir"] / doc.filename
                    if file_path.exists():
                        import os
                        try:
                            os.remove(str(file_path))
                        except OSError:
                            logger.warning("No se pudo eliminar el archivo %s", file_path, exc_info=True)

                # Campaign.document_id no tiene ON DELETE CASCADE en BD: borrar
                # el documento con campañas colgando de él violaría la FK. Se
                # borran primero (arrastrando destinatarios y respuestas por
                # cascade="all, delete-orphan" en Campaign.recipients).
                campaign_repo = CampaignRepository(uow)
                for campaign in campaign_repo.get_campaigns_by_document(document_id):
                    campaign_repo.delete(campaign)

                repo.delete(doc)
        except Exception as exc:
            raise RuntimeError(f"Error eliminando documento: {exc}")

    def list_user_documents(self) -> list[dict]:
        """Lista todos los documentos del usuario, ordenados por fecha descendente."""
        # A4: antes hacía session.query(Document) directo aquí, duplicando lo
        # que ya resuelve el repositorio (mismo filtro/orden/límite, y evita
        # el lazy-load extra de las columnas de AegisDocument al consultar
        # solo la tabla base Document).
        repo = build_repository(AegisDocumentRepository)
        docs = repo.get_documents_by_user(self.user.id)
        fields_map = {
            "id":          "id",
            "title":       "title",
            "subtitle":    "subtitle",
            "filename":    "filename",
            "format":      "format",
            "status":      "status",
            "generated_at": "generatedAt",
            "topic_id":    "topicId",
        }
        result = []
        for doc in docs:
            item = {}
            for model_field, output_name in fields_map.items():
                value = getattr(doc, model_field, None)
                if value is None:
                    item[output_name] = None
                elif isinstance(value, datetime):
                    item[output_name] = isoformat_utc(value)
                else:
                    item[output_name] = value
            result.append(item)
        return result

    def get_topics(self) -> list[dict]:
        """Devuelve todos los temas disponibles ordenados por título."""
        repo = build_repository(AegisDocumentRepository)

        topics = repo.get_topics()
        return [{"id": t.id, "title": t.title} for t in topics]

    def assert_document_ownership(self, document_id: int) -> AegisDocument:
        """
        Checks whether the document with the given ID is owned by
        the user with the given ID.

        Args:
            document_id: id of the document to check

        Returns:
            The document, if owned by the current user.

        Raises:
            DocumentNotFoundError if the document was not found or belongs
            to another user (same error for both cases to prevent ID
            enumeration).
        """
        return assert_owned(
            AegisDocumentRepository, document_id, self.user.id,
            DocumentNotFoundError,
        )

    # =========================================================================
    # WORKFLOW DE GENERACIÓN (privado)
    # =========================================================================

    @staticmethod
    def execute_aegis_generation(document_id: int, topic_id: int, tweaks: dict, user_id: int) -> None:
        """Entry point submitted to the TaskQueue for background generation."""
        from src.modules.users.managers import UserManager

        user = UserManager().get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        AegisManager(user)._run_generation_workflow(document_id, topic_id, tweaks)

    def _run_generation_workflow(
        self,
        document_id: int,
        topic_id:    int,
        tweaks:      dict[str, Any],
    ) -> None:
        """Orquesta todos los pasos de generación en el thread secundario."""
        with job_context():
            cfg = self._read_cfg()

            if not cfg["enabled"]:
                raise RuntimeError("Aegis deshabilitado en configuración")

            # El campo company es el único requerido en tweaks
            if not tweaks.get("company"):
                raise ValueError("El campo 'company' es obligatorio en tweaks")

            try:
                # 1. Resolución de topic
                topic, was_random = self._get_topic_from_db(topic_id)
                if topic is None:
                    topic_note     = "No hay topics en BD. Contenido genérico."
                    resolved_id    = topic_id or 0
                    resolved_title = tweaks.get("topicFocus", "Ciberseguridad General")
                elif was_random:
                    topic_note     = f"Topic {topic_id} no encontrado. Usado: '{topic.title}'"
                    resolved_id    = topic.id
                    resolved_title = topic.title
                else:
                    topic_note     = ""
                    resolved_id    = topic.id
                    resolved_title = topic.title

                # 2. Carga de referencias de disco
                reference = self._load_reference_stack(cfg["stack_dir"])

                # 3. Avisos vigentes — ANTES de generar, no después.
                #
                # Es el orden el que hace que los avisos importen: son el
                # contexto sobre el que el modelo redacta. Traerlos después,
                # como se hacía, los dejaba en un apéndice decorativo pegado
                # al final del documento que no había influido en una sola
                # frase del contenido.
                products = self._resolve_tracked_products(tweaks)
                alerts = self.alert_fetcher.fetch_alerts(
                    products        = products,
                    max_per_product = 2,
                )

                # 4. Generación de contenido con el modelo
                writer = self.ai_writer or AegisAIWriter()
                content: AegisContent = writer.generate(
                    topic             = topic,
                    resolved_topic_id = resolved_id,
                    topic_title       = resolved_title,
                    topic_note        = topic_note,
                    reference         = reference,
                    tweaks            = tweaks,
                    advisories        = alerts,
                )

                # 5. Persistencia
                self._persist_content_atomic(document_id, content, tweaks.get("mentionContact"))
                self._persist_alerts_atomic(document_id, alerts)

                # 6. Escritura del archivo de archivo
                ts       = utcnow_naive().strftime("%Y%m%d_%H%M%S")
                filename = f"{ts}_{self.user.id}_{resolved_id}.json"
                filepath = cfg["output_dir"] / filename

                with open(filepath, "w", encoding="utf-8") as fh:
                    json.dump(content.to_json_dict(document_id, alerts), fh, ensure_ascii=False, indent=2)

                # 7. Actualización del estado a 'done'
                self._update_document_status(
                    document_id = document_id,
                    status      = "done",
                    title       = content.subtitle,
                    filename    = filename,
                )
                logger.info(f"Documento {document_id} generado: {filename}")

            except Exception as exc:
                logger.error(f"Error en workflow {document_id}: {exc}", exc_info=True)
                self._update_document_status(
                    document_id=document_id,
                    status="error",
                    error=str(exc)[:100],
                )

    def _persist_content_atomic(
        self, document_id: int, content: AegisContent, contact_email_from_tweaks: str | None = None
    ) -> None:
        """Persiste el contenido de la píldora y los tips usando el repositorio."""
        default_email = "seguridad@empresa.com"
        contact_email = (
            contact_email_from_tweaks
            if contact_email_from_tweaks and contact_email_from_tweaks != default_email
            else (content.contact_email or None)
        )

        tips_data = [
            {
                "headline": tip.headline,
                "body": tip.body,
                "links": (
                    [{"text": lk["text"], "url": lk["url"]} for lk in tip.links]
                    if tip.links else None
                ),
            }
            for tip in content.tips
        ]

        questions_data = [
            {
                "prompt": q.prompt,
                "options": q.options,
                "correct_index": q.correct_index,
            }
            for q in content.questions
        ]

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            repo.update_content_fields(
                doc_id=document_id,
                subtitle=content.subtitle,
                intro=content.intro,
                closing=content.closing,
                contact_email=contact_email,
                company=content.company,
            )
            repo.save_tips(document_id, tips_data)
            repo.save_questions(document_id, questions_data)
            logger.info(
                f"Contenido persistido para doc {document_id}: "
                f"{len(content.tips)} tips, {len(content.questions)} preguntas"
            )

    def _persist_alerts_atomic(self, document_id: int, alerts: list[AegisAlert]) -> None:
        """Persiste alertas usando el repositorio."""
        alerts_data = []
        for alert in alerts:
            pub_date: date | None = None
            if alert.published:
                try:
                    pub_date = date.fromisoformat(alert.published[:10])
                except ValueError:
                    pass

            alerts_data.append({
                "source": alert.source.value,
                "source_label": "INCIBE-CERT" if alert.source == AlertSource.INCIBE else "NVD/CVE",
                "title": alert.title[:256],
                "published": pub_date,
                "severity": alert.severity.value if isinstance(alert.severity, Enum) else alert.severity,
                "affected_brands": alert.brands or None,
                "description": alert.description[:500] if alert.description else None,
                "url": alert.url[:512],
            })

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            repo.save_alerts(document_id, alerts_data)
            logger.info(f"Alertas persistidas para doc {document_id}: {len(alerts)}")

    def _read_cfg(self) -> dict:
        stack_dir = Path(CR.get_directory_of(CR.DirectoryType.STACK_AEGIS))
        output_dir = Path(CR.get_directory_of(CR.DirectoryType.OUTPUT_AEGIS))
        output_dir.mkdir(parents=True, exist_ok=True)

        ollama_host, ollama_model = CR.get_ollama_environment()

        return {
            "enabled":          CR.aegis_config().enabled,
            "ollama_host":      ollama_host,
            "ollama_model":     ollama_model,
            "timeout_seconds":  120,
            "stack_dir":        stack_dir,
            "output_dir":       output_dir,
        }

    def _get_topic_from_db(self, topic_id: int | None) -> tuple[Topic | None, bool]:
        """Devuelve (topic, was_random). Si topic_id no existe, elige uno aleatorio."""
        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            if topic_id is not None:
                topic = repo.get_topic_by_id(topic_id)
                if topic:
                    return topic, False
                logger.warning(f"Topic {topic_id} no encontrado, usando aleatorio")

            all_topics = repo.get_topics()
            if not all_topics:
                return None, False

        return random.choice(all_topics), True

    def _resolve_tracked_products(self, tweaks: dict[str, Any]) -> list[dict]:
        """Los productos cuyos avisos alimentan esta píldora.

        Dos orígenes, y se elige uno, no se mezclan:

        1. **El inventario de los agentes de Hygeia**, si el usuario no lo ha
           desactivado y algún activo suyo ha reportado software. Es el mejor
           dato posible: los productos que la organización ejecuta de verdad,
           sin que nadie los teclee ni los mantenga.
        2. **La lista manual** del perfil (``trackedProducts``), que es a lo
           que se cae siempre que lo anterior no dé nada: sin agentes, con el
           interruptor apagado, o cuando ningún nombre del inventario resuelve
           a un CPE conocido (un parque entero de software que NVD no indexa).

        Devuelve pares ``{"vendor", "product"}``.
        """
        manual = [
            entry for entry in (tweaks.get("trackedProducts") or [])
            if entry.get("vendor")
        ]
        if not tweaks.get("useHygeiaInventory", True):
            return manual

        try:
            from src.modules.features.hygeia.managers import HygeiaAssetManager
            from src.modules.features.themis.managers import KbQueryManager

            names = HygeiaAssetManager.inventory_products(self.user.id)
            resolved = KbQueryManager().resolve_products(names)
        except Exception as exc:
            # El inventario es una mejora, no un requisito: si falla, la
            # píldora se genera igual con la lista que el usuario eligió.
            logger.warning(f"No se pudo resolver el inventario de Hygeia: {exc}", exc_info=True)
            return manual

        if not resolved:
            return manual

        logger.info(
            f"Aegis: {len(resolved)} productos deducidos del inventario de "
            f"{len(names)} paquetes del usuario {self.user.id}"
        )
        return [{"vendor": vendor, "product": product} for vendor, product in resolved]

    def _load_reference_stack(self, stack_dir: Path) -> str:
        """Carga los 3 archivos .md más recientes del directorio de referencias."""
        if not stack_dir.exists():
            return ""

        files = sorted(stack_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        contents = []
        for f in files[:3]:
            try:
                content = f.read_text(encoding="utf-8")
                if len(content) > 50_000:
                    content = content[:50_000] + "\n... [truncado]"
                contents.append(content)
            except Exception as exc:
                logger.warning(f"No se pudo leer {f}: {exc}", exc_info=True)

        return "\n\n---\n\n".join(contents)

    def _create_pending_document(self, topic_id: int) -> int:
        """Crea un registro AegisDocument en estado 'pending' y devuelve su ID."""
        ts = utcnow_naive().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{self.user.id}_{topic_id}"

        doc = AegisDocument(
            title=placeholder[:64],
            filename=f"{placeholder}.json"[:128],
            status="pending",
            format="json",
            topic_id=topic_id,
            user_id=self.user.id,
            is_ai_generated=1,
        )

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            saved_doc = repo.save(doc)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()

        return saved_doc.id # type: ignore

    def _update_document_status(
        self,
        document_id: int,
        status: str,
        title: str | None = None,
        filename: str | None = None,
        error: str | None = None,
    ) -> None:
        """Actualiza el estado del documento usando el repositorio."""
        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            repo.update_status(document_id, status, title, filename, error)


# Defaults del perfil de organización cuando el usuario aún no ha guardado
# ninguno — mismos valores por defecto que AegisTweaksSchema para que el
# formulario de generación arranque igual con o sin perfil guardado.
_ORG_PROFILE_DEFAULTS: dict[str, Any] = {
    "company": "",
    "mentionContact": "",
    "tone": "profesional",
    "companySize": "",
    "jurisdiction": "",
    "language": "es",
    "sector": "",
    "workModel": "",
    "employeeCount": None,
    "trackedProducts": [],
    "useHygeiaInventory": True,
}


class AegisOrgProfileManager:
    """
    Gestiona el perfil de organización de Aegis: los valores estables de
    generación (empresa, contacto, tono, tamaño, jurisdicción, productos
    vigilados) que se guardan una vez y se precargan en cada generación,
    en vez de reintroducirse cada vez.
    """

    def __init__(self, user: User) -> None:
        self.user = user

    @staticmethod
    def search_products(term: str, limit: int = 20) -> list[dict]:
        """Busca productos vigilables en el índice CPE del espejo local de NVD.

        Sustituye al catálogo fijo de 19 marcas que vivía en
        ``SecOpsConfig.json``: la lista sale de la base de conocimiento, se
        refresca sola con el sync nocturno y solo ofrece productos que de
        verdad tienen algún CVE registrado.
        """
        from src.modules.features.themis.managers import KbQueryManager

        return [
            {"vendor": p.vendor, "product": p.product, "displayName": p.display_name}
            for p in KbQueryManager().search_products(term, limit=limit)
        ]

    def get_or_default(self) -> dict:
        """Devuelve el perfil guardado, o los defaults si aún no existe.

        Añade ``hygeiaInventoryAvailable``, que no es un campo del perfil sino
        del entorno: le dice al frontend si tiene sentido pintar el
        interruptor de "deducir los productos de mis agentes". Sin agentes que
        hayan reportado inventario, el control no se muestra y la preferencia
        guardada (activada por defecto) queda latente hasta que haya alguno.
        """
        repo = build_repository(AegisOrgProfileRepository)
        profile = repo.get_by_user_id(self.user.id)
        result = dict(_ORG_PROFILE_DEFAULTS) if profile is None else profile.to_dict()
        result["hygeiaInventoryAvailable"] = self._hygeia_inventory_available()
        return result

    def _hygeia_inventory_available(self) -> bool:
        try:
            from src.modules.features.hygeia.managers import HygeiaAssetManager

            return HygeiaAssetManager.has_inventory(self.user.id)
        except Exception as exc:
            logger.warning(f"No se pudo comprobar el inventario de Hygeia: {exc}")
            return False

    def upsert(self, data: dict) -> dict:
        """Crea o actualiza el perfil de organización del usuario actual."""
        with UnitOfWork() as uow:
            repo = AegisOrgProfileRepository(uow)
            profile = repo.get_by_user_id(self.user.id)
            if profile is None:
                profile = AegisOrgProfile(user_id=self.user.id)

            profile.company = data["company"]
            profile.contact_email = data["mentionContact"]
            profile.tone = data["tone"]
            profile.company_size = data["companySize"]
            profile.jurisdiction = data["jurisdiction"]
            profile.language = data["language"]
            profile.sector = data["sector"]
            profile.work_model = data["workModel"]
            profile.employee_count = data["employeeCount"]
            profile.tracked_products = data["trackedProducts"]
            profile.use_hygeia_inventory = data["useHygeiaInventory"]

            saved = repo.save(profile)
            return saved.to_dict()


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
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()
        self.mailer = mailer

    # =========================================================================
    # DISTRIBUTION LISTS
    # =========================================================================

    def create_list(self, name: str) -> dict:
        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            dist_list = repo.create_list(self.user.id, name)
            return dist_list.to_dict()

    def list_lists(self) -> list[dict]:
        repo = build_repository(DistributionListRepository)
        return [d.to_dict() for d in repo.get_lists_by_user(self.user.id)]

    def get_list(self, list_id: int) -> dict:
        dist_list = self._assert_list_ownership(list_id)
        return dist_list.to_dict()

    def delete_list(self, list_id: int) -> None:
        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            dist_list = repo.get_by_id(list_id)
            if dist_list is None or dist_list.user_id != self.user.id:
                raise DistributionListNotFoundError(list_id)
            repo.delete(dist_list)

    def add_recipients(self, list_id: int, recipients: list[dict]) -> list[dict]:
        self._assert_list_ownership(list_id)
        with UnitOfWork() as uow:
            repo = DistributionListRepository(uow)
            created = repo.add_recipients(list_id, recipients)
            return [r.to_dict() for r in created]

    def get_recipients(self, list_id: int) -> list[dict]:
        self._assert_list_ownership(list_id)
        repo = build_repository(DistributionListRepository)
        return [r.to_dict() for r in repo.get_recipients(list_id)]

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
        doc_repo = build_repository(AegisDocumentRepository)
        doc = doc_repo.get_by_id(document_id)
        if doc is None or doc.user_id != self.user.id:
            raise DocumentNotFoundError(document_id)
        if doc.status != "done":
            raise DocumentNotReadyError(document_id, doc.status)

        self._assert_list_ownership(list_id)

        with UnitOfWork() as uow:
            repo = CampaignRepository(uow)
            campaign = repo.create_campaign(self.user.id, document_id, list_id, name)
            return campaign.to_dict()

    def list_campaigns(self) -> list[dict]:
        repo = build_repository(CampaignRepository)
        return [c.to_dict() for c in repo.get_campaigns_by_user(self.user.id)]

    def get_campaign(self, campaign_id: int) -> dict:
        campaign = self._assert_campaign_ownership(campaign_id)
        repo = build_repository(CampaignRepository)
        recipients = repo.get_recipients(campaign_id)
        result = campaign.to_dict()
        result["recipients"] = [r.to_dict() for r in recipients]
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
        doc = doc_repo.get_by_id(campaign.document_id)
        questions_snapshot = [q.to_dict() for q in doc.questions] if doc else []
        if not questions_snapshot:
            raise CampaignNoQuestionsError(campaign.document_id)

        list_repo = build_repository(DistributionListRepository)
        recipients = list_repo.get_recipients(campaign.list_id)
        if not recipients:
            raise CampaignEmptyListError(campaign.list_id)

        campaign_recipients = [
            CampaignRecipient(
                recipient_email=r.email,
                recipient_name=r.name,
                token=secrets.token_urlsafe(32),
            )
            for r in recipients
        ]

        with UnitOfWork() as uow:
            repo = CampaignRepository(uow)
            repo.launch_campaign(campaign_id, questions_snapshot, campaign_recipients)
            # Durable antes de encolar: el worker corre en otro proceso y debe
            # ver el snapshot + los tokens ya persistidos.
            uow.commit_for_handoff()

        self._tq.submit(
            func=CampaignManager.execute_campaign_send,
            args=(campaign_id, self.user.id),
            name=f"CampaignSend-{campaign_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(campaign_id),
        )
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
            camp_repo = build_repository(CampaignRepository)
            campaign = camp_repo.get_by_id(campaign_id)
            if campaign is None:
                logger.error(f"Campaña {campaign_id} no encontrada para envío")
                return

            doc = campaign.document
            recipients = [r for r in camp_repo.get_recipients(campaign_id) if r.sent_at is None]
            total = len(recipients)
            if total == 0:
                logger.info(f"Campaña {campaign_id}: no hay destinatarios pendientes de envío")
                return

            base_url = CR.general_config().public_url
            mailer = self.mailer or build_mailer("aegis")
            pill_title = doc.subtitle or doc.title if doc else "Formación de concienciación"

            # La píldora se entrega dentro del propio correo (no solo el
            # enlace al test): el destinatario nunca la recibía por ningún
            # otro canal, así que el test evaluaba un contenido que no se le
            # había hecho llegar. Mismos campos que consume HTMLExporter,
            # pero renderizados aquí con la plantilla de correo (tablas +
            # estilos inline) en vez del HTML de exportación — ese usa
            # <style> en <head> y no es válido embebido dentro de un correo.
            pill_intro = doc.intro if doc else ""
            pill_closing = doc.closing if doc else ""
            pill_company = doc.company if doc else ""
            pill_contact_email = doc.contact_email if doc else ""
            # Mismo tratamiento que los exportadores (services/exporters.py):
            # "seguridad@empresa.com" es el placeholder por defecto de la IA
            # cuando no se indicó un contacto real — no se envía como si fuera
            # un correo válido, se sustituye por una frase.
            pill_contact_is_placeholder = pill_contact_email == "seguridad@empresa.com"
            pill_tips = [tip.to_dict() for tip in (doc.tips if doc else [])]
            # Los avisos cuelgan del documento ya cargado: ninguna consulta extra.
            pill_alerts = [
                alert.to_dict()
                for alert in sorted(doc.alerts, key=lambda a: a.position)
            ] if doc else []

            sent_count = 0
            cancelled = False
            for i, recipient in enumerate(recipients):
                if job.cancelled():
                    cancelled = True
                    break

                # /quiz, no /aegis/quiz: la página del quiz vive en el SPA y
                # todo lo que cuelga de /aegis/ lo captura el proxy hacia Flask
                # (nginx.conf, vite.config.js) — el destinatario vería el JSON.
                link = f"{base_url}/quiz?t={recipient.token}"
                html_body, text_body = render_email(
                    "campaign",
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

            if not cancelled:
                # No mentir sobre el resultado: si ningún envío tuvo éxito la
                # campaña no se "envió". Solo se marca 'sent' cuando al menos un
                # destinatario recibió el correo.
                final_status = "sent" if sent_count > 0 else "failed"
                with UnitOfWork() as uow:
                    CampaignRepository(uow).mark_campaign_status(campaign_id, final_status)

            logger.info(
                f"Campaña {campaign_id} procesada: {sent_count}/{total} enviados"
                f"{' (cancelada)' if cancelled else ''}"
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

        if recipient.status == "completed":
            return {
                "status": "completed",
                "score": recipient.score,
                "total": len(snapshot),
            }

        if recipient.status == "sent":
            with UnitOfWork() as uow:
                CampaignRepository(uow).mark_opened(recipient.id)

        doc = campaign.document
        return {
            "status": "opened",
            "pillTitle": (doc.subtitle or doc.title) if doc else "",
            "questions": [
                {"position": q["position"], "prompt": q["prompt"], "options": q["options"]}
                for q in snapshot
            ],
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

        snapshot = {q["position"]: q for q in (recipient.campaign.questions_snapshot or [])}

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

        score = sum(1 for a in answers_data if a["is_correct"])

        try:
            with UnitOfWork() as uow:
                CampaignRepository(uow).mark_completed(recipient.id, score, answers_data)
        except IntegrityError:
            raise QuizAlreadyCompletedError()

        return {"status": "completed", "score": score, "total": len(snapshot)}
