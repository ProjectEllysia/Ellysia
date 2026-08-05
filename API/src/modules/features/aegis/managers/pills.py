"""
AegisManager — generación de píldoras de concienciación (D3 en
plans/deuda-tecnica-y-calidad.md).

Crea documentos pendientes y lanza el workflow de generación en la
TaskQueue, persiste el contenido (tips en AegisTip, avisos en
AegisDocumentAlert) y expone el CRUD que consumen los endpoints.
"""

from __future__ import annotations

import json
import logging
import random
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.modules.features.aegis.exceptions import DocumentNotFoundError
import src.modules.system.config_reading as CR
from src.modules.users import User
from src.modules.system.taskqueue import ITaskQueue, TaskTrackingMixin, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive, isoformat_utc

from ..model import AegisDocument, Topic
from ..services import AegisAIWriter, AegisAlertFetcher, AlertSource, AegisAlert, AegisContent
from ..repositories import AegisDocumentRepository, CampaignRepository


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
        super().__init__(task_queue)

    # =========================================================================
    # API PÚBLICA
    # =========================================================================

    def generate(self, topic_id: int, tweaks: dict | None = None) -> int:
        """
        Lanza la generacion asincrona de una pildora y devuelve el documentId
        inmediatamente.

        E6: no necesita lock. ``_create_pending_document`` siempre inserta
        una fila nueva (PK autoincremental) — no hay estado mutuo
        compartido que proteger entre dos llamadas concurrentes, cada una
        obtiene su propio documento. Un ``threading.Lock`` de atributo de
        clase tampoco serviría aunque lo hubiera: bajo gunicorn con varios
        workers (el despliegue real de este proyecto) cada proceso tiene su
        propio lock, así que no coordina nada entre procesos — solo
        serializaba llamadas dentro de un mismo proceso sin necesidad.
        """
        tweaks      = tweaks or {}
        document_id = self._create_pending_document(topic_id)

        self._task_queue.submit(
            func=AegisManager.execute_aegis_generation,
            args=(document_id, topic_id, tweaks, self.user.id),
            name=f"AegisGen-{document_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(document_id),
        )

        return document_id

    def get_document(self, doc_id: int) -> dict:
        repo = build_repository(AegisDocumentRepository)
        document = repo.get_by_id(doc_id)
        if not document:
            raise DocumentNotFoundError(doc_id)

        result = {
            "id": document.id,
            "internalName": document.title,
            "title": document.subtitle or "Sin título",
            "userId": document.user.id,
            "topicId": document.topic_id,
            "topicTitle": document.topic.title if document.topic else "Tema desconocido",
            "status": document.status,
            "pill": {
                "subtitle": document.subtitle,
                "intro": document.intro,
                "closing": document.closing,
                "company": document.company,
                "contactEmail": document.contact_email,
                "tips": [tip.to_dict() for tip in document.tips],
            },
            "alerts": [alert.to_dict() for alert in document.alerts],
            "generatedAt": isoformat_utc(document.generated_at), # type: ignore
        }

        if document.status == "done": # type: ignore
            result["pill"] = document.pill_to_dict()
            result["alerts"] = [a.to_dict() for a in sorted(document.alerts, key=lambda a: a.position)]

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
                    [{"text": link["text"], "url": link["url"]} for link in tip.get("links") or []]
                    or None
                ),
            }
            for tip in pill.get("tips", [])
        ]

        questions_data = [
            {
                "prompt": question["prompt"],
                "options": question["options"],
                "correct_index": question["correctIndex"],
            }
            for question in pill.get("questions", [])
        ]

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            document = repo.update_content_fields(
                doc_id=doc_id,
                subtitle=subtitle,
                intro=intro,
                closing=closing,
                contact_email=contact_email,
                company=company,
            )
            if document is not None:
                # Mantener sincronizada la etiqueta del historial (title interno).
                document.title = subtitle[:64]
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
        document = self.assert_document_ownership(document_id)
        if not document:
            raise ValueError(f"Documento {document_id} no existe")

        if not document.filename:
            raise ValueError(f"Documento {document_id} no tiene filename")

        cfg = self._read_cfg()
        path = cfg["output_dir"] / document.filename
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {document.filename}")

        return path

    def delete_document(self, document_id: int) -> None:
        """Elimina el documento de BD y el archivo en disco de forma atómica."""

        cfg = self._read_cfg()
        try:
            with UnitOfWork() as uow:
                repo = AegisDocumentRepository(uow)
                document = repo.get_by_id(document_id)
                if not document:
                    raise ValueError(f"Documento {document_id} no existe")

                if document.filename:
                    file_path = cfg["output_dir"] / document.filename
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

                repo.delete(document)
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
        for document in docs:
            item = {}
            for model_field, output_name in fields_map.items():
                value = getattr(document, model_field, None)
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
        return [{"id": topic.id, "title": topic.title} for topic in topics]

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
                    [{"text": link["text"], "url": link["url"]} for link in tip.links]
                    if tip.links else None
                ),
            }
            for tip in content.tips
        ]

        questions_data = [
            {
                "prompt": question.prompt,
                "options": question.options,
                "correct_index": question.correct_index,
            }
            for question in content.questions
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

        document = AegisDocument(
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
            saved_doc = repo.save(document)
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


