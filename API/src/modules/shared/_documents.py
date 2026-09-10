"""
Document utilities for AI-generated content.

Pure helpers to manage ``Document`` rows and their on-disk files (status
updates, listing, deletion). The AI generation itself lives in the ``scribe``
module; this file no longer holds any LLM client logic.
"""

import os
import logging

from typing import Callable, List, Optional, Tuple, Type

logger = logging.getLogger(__name__)

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.system.taskqueue import TaskTrackingMixin
from ._ownership import assert_owned
from ._time import utcnow_naive


# =========================================================================
# GENERACIÓN DE INFORMES EN SEGUNDO PLANO (Themis / Iris)
# =========================================================================


def run_report_generation(
    document_id: int,
    repo_cls: Type,
    render: Callable[[], str],
) -> None:
    """Renderiza un informe PDF y sincroniza el estado de su documento.

    Patrón común a Themis e Iris (antes duplicado en ambos managers):

    1. ``render()`` produce el PDF y devuelve su ruta.
    2. El documento se marca ``done`` con esa ruta y ``generated_at``.
    3. Ante **cualquier** fallo el documento se marca ``error`` y se **re-lanza**
       la excepción: así el job de la cola termina como FAILED y el estado de la
       tarea coincide con el del documento (sin esto, el callback de éxito de RQ
       registraría COMPLETED pese al error).

    Se ejecuta dentro del worker (contexto background), por lo que cada
    ``UnitOfWork`` confirma su propia transacción al salir del bloque.

    Args:
        document_id: PK del documento a actualizar.
        repo_cls:    Clase de repositorio del documento (recibe un ``UnitOfWork``).
        render:      Callable sin argumentos que genera el PDF y devuelve su ruta.
    """
    try:
        pdf_path = render()
        with UnitOfWork() as uow:
            document = repo_cls(uow).get_by_id(document_id)
            if document:
                document.filename = pdf_path
                document.status = "done"
                document.generated_at = utcnow_naive()
        logger.info("PDF generado exitosamente para documento %s", document_id)
    except Exception:
        logger.error("Error generando PDF para documento %s", document_id, exc_info=True)
        try:
            with UnitOfWork() as uow:
                document = repo_cls(uow).get_by_id(document_id)
                if document:
                    document.status = "error"
        except Exception:
            logger.exception("Error updating document status for document %s", document_id)
        raise
    

def submit_report_generation(task_queue, document_id: int, repo_cls: Type, **submit_kwargs) -> None:
    """Encola la generación del PDF y revierte el documento si el encolado falla.

    ``_create_document`` deja el documento en ``running`` de forma durable
    antes de llamar aquí (el worker corre en otro proceso). Si ``submit()``
    rechaza el job — p. ej. dos clics rápidos del mismo informe chocan con
    ``_reject_if_still_running`` — nadie más va a procesar ese documento: sin
    este manejo se quedaba en ``running`` para siempre ("Generando..." que
    nunca acaba), aunque el usuario sí viera el error de "ya hay una tarea
    en curso". Se marca ``error`` y se re-lanza para que el caller siga
    devolviendo el mismo error al cliente.

    Este manejo es la razón por la que los informes de Themis e Iris se
    quedaron **fuera** de la outbox transaccional, aunque
    siguen el mismo patrón create-then-enqueue que Themis y Aegis sí migraron:
    un encolado fallido no deja el documento colgado en ``running`` para
    siempre, lo marca ``error``, y el usuario ve el fallo y puede volver a
    pedir el informe -- que es un botón, no una operación que consuma cuota ni
    acuñe estado. Lo que la outbox añadiría aquí es recuperar sola un PDF que
    el usuario ya puede regenerar solo, a cambio de acoplar la creación del
    documento a la tabla de outbox.
    """
    try:
        task_queue.submit(**submit_kwargs)
    except Exception:
        with UnitOfWork() as uow:
            document = repo_cls(uow).get_by_id(document_id)
            if document:
                document.status = "error"
        raise


def delete_document_with_file(
    document_id: int,
    repo_cls: Type,
    not_found_exc: Callable[[int], Exception],
) -> None:
    """Elimina un documento de BD y su archivo asociado en disco.

    Unifica el patrón ``get → exists → remove file → delete row`` que estaba
    duplicado en ``ThemisReportManager.delete_document``,
    ``IrisReportManager.delete_document`` y el bucle interno de
    ``ScanManager.delete_scan``.

    Args:
        document_id:   PK del documento a eliminar.
        repo_cls:      Clase de repositorio del documento (recibe un ``UnitOfWork``).
        not_found_exc: Callable que recibe el ``document_id`` y devuelve la
                       excepción a lanzar si el documento no existe.

    Raises:
        La excepción devuelta por ``not_found_exc`` si el documento no existe.
    """
    
    with UnitOfWork() as uow:
        doc_repo = repo_cls(uow)
        document = doc_repo.get_by_id(document_id)
        if not document:
            raise not_found_exc(document_id)

        if document.filename and os.path.exists(document.filename):
            try:
                os.remove(document.filename)
            except Exception as exc:
                logger.warning(f"No se pudo eliminar el archivo {document.filename}: {exc}", exc_info=True)

        doc_repo.delete(document)


# =========================================================================
# CICLO DE VIDA COMPARTIDO DE DOCUMENTOS (Themis / Iris) — A3
# =========================================================================


class DocumentManager(TaskTrackingMixin):
    """CRUD y ownership compartidos por el ciclo de vida de un documento.

    ``ThemisReportManager`` e ``IrisReportManager`` eran el mismo manager con
    los nombres cambiados: esta
    base concentra lo que de verdad era idéntico. La generación en sí
    (``generate_report``/``_generate_pdf_async``/``execute_report_generation``)
    se queda en cada subclase porque el ``render`` y el disparador difieren
    de verdad — unificarlos no colapsaría duplicación real, solo añadiría
    indirección.

    Subclases deben declarar:
        _REPOSITORY:      Clase de repositorio del documento, que debe
            extender ``infrastructure.DocumentRepository`` (A9) — de ahí
            salen las tres consultas que estos métodos delegan.
        _NOT_FOUND_ERROR: Callable(document_id) -> Exception, lanzada tanto
            si el documento no existe como si pertenece a otro usuario.
        EXTERNAL_ID_PREFIX / TASK_CATEGORY: contrato de ``TaskTrackingMixin``.

    Ya no hace falta sobreescribir ``get_documents_by_parent``: hasta A9 cada
    repositorio nombraba esa consulta a su manera (``get_documents_by_scan``
    vs. ``get_documents_by_analysis``), así que la base no podía tener un
    default; ahora los tres la exponen con el mismo nombre.
    """

    _REPOSITORY: Type
    _NOT_FOUND_ERROR: Callable[[int], Exception]

    def get_document_by_id(self, document_id: int):
        """Retrieve a document by its primary key."""
        document = build_repository(self._REPOSITORY).get_by_id(document_id)
        if not document:
            logger.warning(f"Documento {document_id} no encontrado")
        return document

    def get_latest_document_by_parent(self, parent_id: int):
        """Retrieve the most recently created document for a parent entity
        (a scan or an analysis)."""
        return build_repository(self._REPOSITORY).get_latest_document(parent_id)

    def get_documents_for_user(self, user_id: int) -> List:
        """Retrieve all documents belonging to a user."""
        docs = build_repository(self._REPOSITORY).get_documents_by_user(user_id)
        logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_for_user_paginated(
        self, user_id: int, page: int, per_page: int,
    ) -> Tuple[List, int]:
        """Una página de los documentos de un usuario más el total real
        (B17) -- ``get_documents_for_user`` sigue sin cambios para quien no
        pagina."""
        return build_repository(self._REPOSITORY).get_documents_by_user_paginated(
            user_id, page, per_page,
        )

    def get_documents_by_parent(self, parent_id: int) -> List:
        """Retrieve all documents generated for a specific parent entity."""
        docs = build_repository(self._REPOSITORY).get_documents_by_parent(parent_id)
        logger.info(f"Se obtuvieron {len(docs)} documentos para el padre {parent_id}")
        return docs

    def delete_document(self, document_id: int) -> bool:
        """Delete a document and its associated file on disk.

        Raises:
            The subclass's ``_NOT_FOUND_ERROR`` if the document was not found.
        """
        delete_document_with_file(document_id, self._REPOSITORY, self._NOT_FOUND_ERROR)
        return True

    def assert_document_ownership(self, document_id: int, user_id: int):
        """Verify document ownership and return the document.

        Raises:
            The subclass's ``_NOT_FOUND_ERROR`` if the document was not found
            or is not owned by ``user_id`` (same error for both cases, to
            prevent ID enumeration).
        """
        return assert_owned(self._REPOSITORY, document_id, user_id, self._NOT_FOUND_ERROR)

    def get_document_status(
        self, document_id: Optional[int], parent_id: Optional[int], user_id: int,
        not_found_error: Optional[Callable[[int], Exception]] = None,
    ):
        """Resolve a document for the ``/document-status`` endpoints (E4).

        Looks the document up by ``document_id`` when given, otherwise falls
        back to the parent entity's latest document — the dual-lookup both
        Themis's and Iris's ``get_document_status`` endpoints hand-rolled,
        including the manual ownership check that belonged in the manager,
        not in ``endpoints.py``.

        Args:
            not_found_error: Override for the exception raised (defaults to
                ``self._NOT_FOUND_ERROR``). Themis's endpoint has always
                raised ``ScanNotFoundError`` here specifically — a different,
                404-status exception from the 500-status ``DocumentError``
                its own ``delete_document``/``assert_document_ownership``
                use — so unifying this method must not silently change that.

        Raises:
            ``not_found_error`` (or the subclass's ``_NOT_FOUND_ERROR``) if
            no document resolves, or resolves to one not owned by
            ``user_id``.
        """
        not_found_error = not_found_error or self._NOT_FOUND_ERROR
        document = self.get_document_by_id(document_id) if document_id else (
            self.get_latest_document_by_parent(parent_id) if parent_id else None
        )
        if not document or document.user_id != user_id:
            raise not_found_error(document_id or parent_id)
        return document

