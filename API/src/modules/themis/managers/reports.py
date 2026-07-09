"""ThemisReportManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
import os
from typing import List, Optional
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, job_context
from src.modules.aegis.exceptions import DocumentError
from src.modules.shared import Document, assert_owned, utcnow_naive
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from ..repositories import ThemisReportRepository
from ..model import ThemisDocument
from ..services import PDFCreator

from .scan import ScanManager


logger = logging.getLogger(__name__)


class ThemisReportManager:
    """
    Manager for Themis document lifecycle and PDF report generation.

    Handles document CRUD operations, ownership verification, and async
    PDF generation for security scan reports.

    Attributes:
        user: User performing the operations.
    """

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    @staticmethod
    def _create_document(scan, ai_report: bool) -> int:
        """Create a ThemisDocument for a scan and return its ID."""
        with UnitOfWork() as uow:
            document = ThemisDocument(
                scan_id         = scan.id,
                scan_type       = scan.scan_type,
                document_type   = "themis",
                filename        = "",
                format          = "pdf",
                status          = "running",
                user_id         = scan.user_id,
                is_ai_generated = 1 if ai_report else 0,
            )
            ThemisReportRepository(uow).save(document)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()

        return document.id  # type: ignore

    def get_document_by_id(self, document_id: int) -> Optional[ThemisDocument]:
        """Retrieve a ThemisDocument by its primary key."""
        doc = read_repo(ThemisReportRepository).get_by_id(document_id)

        if not doc:
            logger.warning(f"Documento {document_id} no encontrado")

        return doc

    def get_latest_document_by_scan_id(self, scan_id: int) -> Optional[ThemisDocument]:
        """Retrieve the most recently created document for a scan."""
        doc = read_repo(ThemisReportRepository).get_latest_document(scan_id)

        return doc

    def get_documents_for_user(self, user_id: int) -> List[ThemisDocument]:
        """Retrieve all documents belonging to the active user."""
        docs = read_repo(ThemisReportRepository).get_documents_by_user(user_id)  # type: ignore

        logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_scan_id(self, scan_id: int) -> List[ThemisDocument]:
        """Retrieve all documents associated with a specific scan."""
        docs = read_repo(ThemisReportRepository).get_documents_by_scan(scan_id)

        logger.info(f"Se obtuvieron {len(docs)} documentos para scan {scan_id}")
        return docs

    def delete_document(self, document_id: int) -> bool:
        """
        Delete a document and its associated file on disk.

        Returns:
            True if deleted successfully.

        Raises:
            DocumentError: If the document was not found.
        """
        with UnitOfWork() as uow:
            doc_repo = ThemisReportRepository(uow)
            doc = doc_repo.get_by_id(document_id)

            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")

            if doc.filename and os.path.exists(doc.filename):  # pyright: ignore[reportArgumentType, reportGeneralTypeIssues]
                try:
                    os.remove(doc.filename)  # type: ignore
                except (OSError, IOError) as e:
                    logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}", exc_info=True)

            doc_repo.delete(doc)

        return True

    def assert_document_ownership(self, document_id: int, user_id: int) -> Document:
        """
        Verify document ownership and return the document.

        Args:
            document_id: ID of the document.

        Returns:
            Document instance.

        Raises:
            DocumentError: If document not found or not owned by user.
        """
        return assert_owned(
            ThemisReportRepository, document_id, user_id,
            lambda eid: DocumentError(f"Documento {eid} no encontrado"),
        )

    def generate_report(self, scan_id: int, ai_report: bool = False, strategy_class=None) -> int:
        """
        Create a ThemisDocument and start async PDF generation.

        Args:
            scan_id:        Primary key of the scan.
            ai_report:      Include AI-generated analysis.
            strategy_class: Printing strategy class for the scan type.

        Returns:
            Primary key of the created ThemisDocument.
        """
        scan_manager = ScanManager.resolve_manager(scan_id)
        scan = scan_manager.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        doc_id = self._create_document(scan, ai_report)

        self._tq.submit(
            func=ThemisReportManager.execute_report_generation,
            args=(doc_id, scan.id, ai_report),
            name=f"PDFGeneration-Scan-{scan.id}",
            category="themis.report",
            external_id=f"themis-doc:{doc_id}",
        )
        return doc_id  # type: ignore

    @staticmethod
    def execute_report_generation(doc_id: int, scan_id: int, ai_report: bool) -> None:
        """Entry point submitted to the TaskQueue for background PDF generation."""
        with job_context():
            ThemisReportManager()._generate_pdf_async(doc_id, scan_id, ai_report)

    def _generate_pdf_async(
        self,
        document_id: int,
        scan_id: int,
        ai_report: bool,
    ) -> None:
        """Generate PDF in a background thread and update document status."""

        try:
            pdf_creator = PDFCreator(scan_id)
            pdf_path = pdf_creator.print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc = ThemisReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path  # type: ignore
                    doc.status       = "done"  # type: ignore
                    doc.generated_at = utcnow_naive()  # type: ignore

            logger.info(f"PDF generado exitosamente para documento {document_id}")

        except Exception as e:
            logger.error(
                f"Error generando PDF para documento {document_id}: {e}",
                exc_info=True
            )
            self._update_document_status(document_id, "error")
            # Re-lanzar: sin esto el job termina "con éxito" y el callback de RQ
            # lo registra como COMPLETED pese a que el documento quedó en error.
            # Al propagar, RQ lo marca FAILED y estado de tarea y documento
            # coinciden.
            raise

    def _update_document_status(self, document_id: int, status: str) -> None:
        """Update document status in database."""
        try:
            with UnitOfWork() as uow:
                doc = ThemisReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.status = status  # type: ignore
        except (OSError, RuntimeError) as e:
            logger.exception(f"Error updating document status for document {document_id}")

