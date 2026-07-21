"""
Document utilities for AI-generated content.

Pure helpers to manage ``Document`` rows and their on-disk files (status
updates, listing, deletion). The AI generation itself lives in the ``scribe``
module; this file no longer holds any LLM client logic.
"""

import os
import logging

from typing import Callable, Type

logger = logging.getLogger(__name__)

from src.modules.infrastructure import UnitOfWork
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

    
