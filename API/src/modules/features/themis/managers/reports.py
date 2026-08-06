"""ThemisReportManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.system.taskqueue import job_context
from src.modules.shared._exceptions import DocumentError
from src.modules.shared._documents import run_report_generation, DocumentManager
from src.modules.infrastructure import UnitOfWork
from ..repositories import ThemisReportRepository
from ..model import ThemisDocument
from ..services import PDFCreator

from .scan import ScanManager


logger = logging.getLogger(__name__)


class ThemisReportManager(DocumentManager):
    """
    Manager for Themis document lifecycle and PDF report generation.

    Handles document CRUD operations, ownership verification, and async
    PDF generation for security scan reports. CRUD/ownership are shared with
    Iris via ``DocumentManager`` (A3); this class keeps only what is really
    Themis-specific: creating a ``ThemisDocument`` and rendering its PDF.
    """

    EXTERNAL_ID_PREFIX = "themis-doc:"
    TASK_CATEGORY = "themis.report"

    _REPOSITORY = ThemisReportRepository
    _NOT_FOUND_ERROR = staticmethod(lambda eid: DocumentError(f"Documento {eid} no encontrado"))

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

    # get_documents_by_parent: usa el default de DocumentManager (A9).

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

        # Solo el informe con IA cuesta dinero; el PDF a secas no consume nada.
        # Se cobra al pedirlo y no al terminarlo: el trabajo se encola aquí, y
        # esperar al worker dejaría un hueco para pedir mil informes a la vez.
        if ai_report:
            QuotaManager().consume(scan.user_id, LimitKey.AI_REQUESTS)

        doc_id = self._create_document(scan, ai_report)

        self._task_queue.submit(
            func=ThemisReportManager.execute_report_generation,
            args=(doc_id, scan.id, ai_report),
            name=f"PDFGeneration-Scan-{scan.id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(doc_id),
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

