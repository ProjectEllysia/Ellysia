"""
Document utilities for AI-generated content.

Pure helpers to manage ``Document`` rows and their on-disk files (status
updates, listing, deletion). The AI generation itself lives in the ``scribe``
module; this file no longer holds any LLM client logic.
"""

import os
import logging

from typing import Callable, List, Optional, Type

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
            doc = repo_cls(uow).get_by_id(document_id)
            if doc:
                doc.filename = pdf_path
                doc.status = "done"
                doc.generated_at = utcnow_naive()
        logger.info("PDF generado exitosamente para documento %s", document_id)
    except Exception:
        logger.error("Error generando PDF para documento %s", document_id, exc_info=True)
        try:
            with UnitOfWork() as uow:
                doc = repo_cls(uow).get_by_id(document_id)
                if doc:
                    doc.status = "error"
        except Exception:
            logger.exception("Error updating document status for document %s", document_id)
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
        doc = doc_repo.get_by_id(document_id)
        if not doc:
            raise not_found_exc(document_id)

        if doc.filename and os.path.exists(doc.filename):
            try:
                os.remove(doc.filename)
            except Exception as exc:
                logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {exc}", exc_info=True)

        doc_repo.delete(doc)


# =========================================================================
# CICLO DE VIDA COMPARTIDO DE DOCUMENTOS (Themis / Iris) — A3
# =========================================================================


class DocumentManager(TaskTrackingMixin):
    """CRUD y ownership compartidos por el ciclo de vida de un documento.

    ``ThemisReportManager`` e ``IrisReportManager`` eran el mismo manager con
    los nombres cambiados (A3 en ``plans/deuda-tecnica-y-calidad.md``): esta
    base concentra lo que de verdad era idéntico. La generación en sí
    (``generate_report``/``_generate_pdf_async``/``execute_report_generation``)
    se queda en cada subclase porque el ``render`` y el disparador difieren
    de verdad — unificarlos no colapsaría duplicación real, solo añadiría
    indirección.

    Subclases deben declarar:
        _REPOSITORY:      Clase de repositorio del documento.
        _NOT_FOUND_ERROR: Callable(document_id) -> Exception, lanzada tanto
            si el documento no existe como si pertenece a otro usuario.
        EXTERNAL_ID_PREFIX / TASK_CATEGORY: contrato de ``TaskTrackingMixin``.

    Y sobreescribir:
        get_documents_by_parent: el repositorio de cada módulo nombra su
            consulta "por padre" de forma distinta (``get_documents_by_scan``
            vs. ``get_documents_by_analysis``) — ``get_latest_document`` y
            ``get_documents_by_user`` sí comparten nombre en ambos
            repositorios y por eso sí viven aquí sin indirección.
    """

    _REPOSITORY: Type
    _NOT_FOUND_ERROR: Callable[[int], Exception]

    def get_document_by_id(self, document_id: int):
        """Retrieve a document by its primary key."""
        doc = build_repository(self._REPOSITORY).get_by_id(document_id)
        if not doc:
            logger.warning(f"Documento {document_id} no encontrado")
        return doc

    def get_latest_document_by_parent(self, parent_id: int):
        """Retrieve the most recently created document for a parent entity
        (a scan or an analysis)."""
        return build_repository(self._REPOSITORY).get_latest_document(parent_id)

    def get_documents_for_user(self, user_id: int) -> List:
        """Retrieve all documents belonging to a user."""
        docs = build_repository(self._REPOSITORY).get_documents_by_user(user_id)
        logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_parent(self, parent_id: int) -> List:
        """Retrieve all documents generated for a specific parent entity.

        Must be overridden — the underlying repository query is named
        differently per module (``get_documents_by_scan`` vs.
        ``get_documents_by_analysis``), so there is no default here.
        """
        raise NotImplementedError

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
        doc = self.get_document_by_id(document_id) if document_id else (
            self.get_latest_document_by_parent(parent_id) if parent_id else None
        )
        if not doc or doc.user_id != user_id:
            raise not_found_error(document_id or parent_id)
        return doc

