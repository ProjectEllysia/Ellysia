"""
IrisReportManager — ciclo de vida de IrisDocument y generación asíncrona
del informe PDF.

El CRUD y la comprobación de propiedad los comparte con Themis vía
``DocumentManager``; aquí queda solo lo propio de Iris: crear el
``IrisDocument`` y renderizar su PDF con :class:`IrisPDFCreator`.
"""

from __future__ import annotations

import logging

from src.modules.shared._exceptions import DocumentNotFoundError
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared._documents import run_report_generation, submit_report_generation, DocumentManager
from src.modules.system.taskqueue import job_context

from ..exceptions import IrisAnalysisNotReadyError
from ..model import IrisAnalysis, IrisDocument
from ..repositories import IrisAnalysisRepository, IrisReportRepository
from ..services import parse_raw_message
from ..services.parsers import build_path
from ..services.reports import IrisPDFCreator

from .analysis import IrisManager


logger = logging.getLogger(__name__)


class IrisReportManager(DocumentManager):
    """Manager for IrisDocument lifecycle and async PDF report generation.

    CRUD/ownership are shared with Themis via ``DocumentManager``; this
    class keeps only what is really Iris-specific: creating an
    ``IrisDocument`` and rendering its PDF via :class:`IrisPDFCreator`.
    """

    EXTERNAL_ID_PREFIX = "iris-doc:"
    TASK_CATEGORY = "iris.report"

    _REPOSITORY = IrisReportRepository
    _NOT_FOUND_ERROR = DocumentNotFoundError

    @staticmethod
    def _create_document(analysis: IrisAnalysis) -> int:
        """Create an IrisDocument for a finished analysis and return its ID."""
        with UnitOfWork() as uow:
            document = IrisDocument(
                analysis_id=analysis.id,
                document_type="iris",
                filename="",
                format="pdf",
                status="running",
                user_id=analysis.user_id,
                verdict=analysis.verdict,
                is_ai_generated=0,
            )
            IrisReportRepository(uow).save(document)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return document.id  # type: ignore

    # get_documents_by_parent: usa el default de DocumentManager.

    def generate_report(self, analysis_id: int, user_id: int) -> int:
        """Create an IrisDocument and start async PDF generation.

        Args:
            analysis_id: Primary key of the finished analysis.
            user_id:     Owner of the analysis (ownership is verified here).

        Returns:
            Primary key of the created IrisDocument.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist or
                is not owned by ``user_id``.
            IrisAnalysisNotReadyError: If the analysis is not ``finished``.
        """
        analysis = IrisManager.assert_analysis_ownership(analysis_id, user_id)
        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        doc_id = self._create_document(analysis)

        submit_report_generation(
            self._task_queue, doc_id, self._REPOSITORY,
            func=IrisReportManager.execute_report_generation,
            args=(doc_id, analysis_id),
            name=f"PDFGeneration-Analysis-{analysis_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(doc_id),
        )
        return doc_id  # type: ignore

    @staticmethod
    def execute_report_generation(doc_id: int, analysis_id: int) -> None:
        """Entry point submitted to the TaskQueue for background PDF generation."""
        with job_context():
            IrisReportManager()._generate_pdf_async(doc_id, analysis_id)

    def _generate_pdf_async(self, document_id: int, analysis_id: int) -> None:
        """Genera el PDF del informe en el worker y sincroniza el estado del documento.

        Delega en ``run_report_generation`` (helper compartido con Themis) que
        gestiona el marcado ``done``/``error`` y el re-lanzamiento de la
        excepción para que el job de RQ termine como FAILED si algo falla.
        """
        def _render() -> str:
            report = IrisManager().get_analysis_results(analysis_id)
            analysis = build_repository(IrisAnalysisRepository).get_by_id(analysis_id)
            path = None
            if analysis is not None:
                context = parse_raw_message(analysis.raw_headers or "")
                path = {"analysisId": analysis_id, **build_path(context.received_headers)}
            return IrisPDFCreator(report=report, path=path,
                                  document_id=document_id).print_pdf()

        run_report_generation(
            document_id=document_id,
            repo_cls=IrisReportRepository,
            render=_render,
        )
