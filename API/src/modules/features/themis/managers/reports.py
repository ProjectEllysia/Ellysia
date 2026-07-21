"""ThemisReportManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from typing import List, Optional
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, job_context
from src.modules.shared import Document, assert_owned
from src.modules.shared._exceptions import DocumentError
from src.modules.shared._documents import run_report_generation, delete_document_with_file
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
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
        doc = build_repository(ThemisReportRepository).get_by_id(document_id)

        if not doc:
            logger.warning(f"Documento {document_id} no encontrado")

        return doc

    def get_latest_document_by_scan_id(self, scan_id: int) -> Optional[ThemisDocument]:
        """Retrieve the most recently created document for a scan."""
        doc = build_repository(ThemisReportRepository).get_latest_document(scan_id)

        return doc

    def get_documents_for_user(self, user_id: int) -> List[ThemisDocument]:
        """Retrieve all documents belonging to the active user."""
        docs = build_repository(ThemisReportRepository).get_documents_by_user(user_id)  # type: ignore

        logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_scan_id(self, scan_id: int) -> List[ThemisDocument]:
        """Retrieve all documents associated with a specific scan."""
        docs = build_repository(ThemisReportRepository).get_documents_by_scan(scan_id)

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
        delete_document_with_file(
            document_id,
            ThemisReportRepository,
            lambda eid: DocumentError(f"Documento {eid} no encontrado"),
        )
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

    def generate_report(self, scan_id: int, ai_report: bool = False) -> int:
        """
        Create a ThemisDocument and start async PDF generation.

        Args:
            scan_id:   Primary key of the scan.
            ai_report: Include AI-generated analysis.

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
        """Genera el PDF del informe en el worker y sincroniza el estado del documento.

        Delega en ``run_report_generation`` (helper compartido con Iris) que
        gestiona el marcado ``done``/``error`` y la re-lanzamiento de la
        excepción para que el job de RQ termine como FAILED si algo falla.
        """
        run_report_generation(
            document_id=document_id,
            repo_cls=ThemisReportRepository,
            render=lambda: PDFCreator(scan_id, document_id).print_pdf(ai_report=ai_report),
        )

