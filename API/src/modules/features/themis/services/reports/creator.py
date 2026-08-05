"""
``PDFCreator``: arma el documento PDF a partir de la estrategia del escaneo.

D5 en ``plans/deuda-tecnica-y-calidad.md``.
"""

import os
import logging

from datetime import datetime
from typing import Optional
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from .theme import ColorType, ReportTheme
from .base import PrintingStrategy

logger = logging.getLogger(__name__)


class PDFCreator:
    """PDF document generator for security scan reports.

    Coordinates the creation of PDF reports using printing strategies
    for different scan types. Handles cover page, content, consent page,
    and footer generation.

    Attributes:
        config_reader: Configuration reader for directory paths.
        directory: Output directory for PDF files.
        printing_strategy: Strategy for generating report content.
        scan: Source scan data.
    """

    def __init__(self, scan_id: int, document_id: Optional[int] = None) -> None:
        """
        Args:
            scan_id: Primary key of the scan to report on.
            document_id: Primary key of the ThemisDocument this PDF belongs to,
                if any. Included in the output filename so two documents for
                the same scan (e.g. one plain, one with AI, or a re-generated
                one) never collide on disk — without it, a later generation
                for the same scan silently overwrote the file every earlier
                document row's `filename` still pointed to.
        """
        self.directory = CR.get_directory_of(CR.DirectoryType.OUTPUT_THEMIS)
        self.printing_strategy = PrintingStrategy.resolve_printing_strategy(scan_id)
        self.scan = self.printing_strategy.scan
        self.document_id = document_id

    def _set_pdf_metadata(self, document) -> None:
        """Set PDF document metadata.

        Args:
            doc: SimpleDocTemplate instance.
        """
        scan = self.scan
        started = getattr(scan, "started_at", None)
        date_str = started.strftime("%d/%m/%Y") if started else datetime.now().strftime("%d/%m/%Y")
        document.title = f"Informe de Seguridad - {scan.id}"
        document.author = "Ellysia Security Team"
        document.subject = f"Análisis de seguridad realizado el {date_str}"
        document.creator = "Ellysia PDF Generator v2.0"

    def _on_page(self, canv, document):
        """Callback for rendering page elements (header, footer, sidebar, small logo).

        Args:
            canv: Canvas instance.
            doc: Document instance.
        """
        canv.saveState()
        width, height = A4

        palette = self.printing_strategy.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])

        canv.setFillColor(main)
        canv.rect(20, 20, 6, height - 40, stroke=0, fill=1)

        canv.setFont("Helvetica-Bold", 12)
        canv.setFillColor(dark)
        canv.drawString(40, height - 30, "Ellysia Security Report")

        canv.setStrokeColor(colors.HexColor("#e0e0e0"))
        canv.setLineWidth(0.5)
        canv.line(36, height - 42, width - 36, height - 42)

        # Small logo in top-right corner (skipping cover page)
        page_num = canv.getPageNumber()
        if page_num > 1:
            logo_path = getattr(self, "_header_logo_path", None)
            if logo_path is None:
                directory_type = CR.DirectoryType.RESOURCES_THEMIS
                resource_directory = CR.get_directory_of(directory_type)
                picture_name = self.printing_strategy.get_picture_name()
                logo_path = os.path.join(resource_directory, picture_name)
                self._header_logo_path = logo_path
            if os.path.exists(logo_path):
                canv.drawImage(logo_path, width - 50, height - 36, width=0.3 * inch, height=0.3 * inch, preserveAspectRatio=True)

        canv.setFont("Helvetica", 8)
        canv.setFillColor(colors.HexColor("#999999"))
        canv.drawRightString(width - 40, 28, f"Página {page_num}")

        canv.restoreState()

    def append_cover_page(
        self,
        elements: list,
        theme: ReportTheme,
        title: str,
        subtitle: str = "",
        client_name: Optional[str] = None,
        document_type: str = "Informe de Seguridad",
        date: Optional[datetime] = None,
    ) -> None:
        """Append cover page to the document.

        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
            title: Main title text.
            subtitle: Optional subtitle text.
            client_name: Optional client name.
            document_type: Type of document.
            date: Optional date (defaults to now).
        """
        if date is None:
            date = datetime.now()

        palette = theme.palette
        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        elements.append(Spacer(1, 2.5 * inch))

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=theme.styles["Heading1"],
            fontSize=30,
            leading=34,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        title_paragraph = Paragraph(title, title_style)
        title_table = Table([[title_paragraph]], colWidths=[6 * inch])
        title_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("TOPPADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
            ("LEFTPADDING", (0, 0), (-1, -1), 24),
            ("RIGHTPADDING", (0, 0), (-1, -1), 24),
        ]))
        elements.append(title_table)

        if subtitle:
            elements.append(Spacer(1, 0.3 * inch))
            subtitle_style = ParagraphStyle(
                "CoverSubtitle",
                parent=theme.styles["Normal"],
                fontSize=13,
                leading=16,
                textColor=black,
                alignment=TA_CENTER,
            )
            elements.append(Paragraph(subtitle, subtitle_style))

        elements.append(Spacer(1, 1.3 * inch))

        info_data = []
        if client_name:
            info_data.append(["Cliente:", client_name])
        info_data.append(["Fecha:", date.strftime("%d/%m/%Y")])

        info_table = Table(info_data, colWidths=[1.8 * inch, 3.2 * inch])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("TEXTCOLOR", (0, 0), (0, -1), main),
            ("TEXTCOLOR", (1, 0), (1, -1), black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BOX", (0, 0), (-1, -1), 1, light),
        ]))
        elements.append(info_table)

        elements.append(Spacer(1, 1.0 * inch))
        decoration = Table([[""]], colWidths=[6 * inch], rowHeights=[0.12 * inch])
        decoration.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light),
        ]))
        elements.append(decoration)
        elements.append(PageBreak())

    def append_logo(self, elements: list) -> None:
        """Append the logo as a standalone themed badge (useful for cover pages).

        Args:
            elements: List of flowable elements.
        """
        badge = self._make_logo_badge()
        elements.append(badge)
        elements.append(Spacer(1, 0.2 * inch))

    def _make_logo_badge(self) -> Table:
        """Build a header-band badge: themed square container with the tool logo.

        Returns:
            A Table flowable (full-width, main-colored) with the logo centred inside.
        """
        directory_type = CR.DirectoryType.RESOURCES_THEMIS
        resource_directory = CR.get_directory_of(directory_type)
        picture_name = self.printing_strategy.get_picture_name()
        image_filename = os.path.join(resource_directory, picture_name)

        if not os.path.exists(image_filename):
            logger.error(f"No se ha encontrado la imagen {image_filename}")
            dummy = Table([[""]], colWidths=[0.9 * inch], rowHeights=[0.9 * inch])
            dummy.hAlign = "CENTER"
            return dummy

        palette = self.printing_strategy.color_palette
        main_color = colors.HexColor(palette[ColorType.MAIN])

        logo = Image(image_filename, width=0.9 * inch, height=0.9 * inch)
        container = Table([[logo]], colWidths=[1.3 * inch], rowHeights=[1.3 * inch])
        container.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        container.hAlign = "CENTER"

        doc_type_style = ParagraphStyle(
            "CoverDocType",
            parent=getSampleStyleSheet()["Normal"],
            fontSize=13,
            textColor=colors.HexColor(palette[ColorType.WHITE]),
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        )
        doc_para = Paragraph(self.printing_strategy.get_report_title().upper(), doc_type_style)

        band = Table([[container, doc_para]], colWidths=[1.8 * inch, 4.2 * inch])
        band.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("ALIGN", (1, 0), (1, 0), "LEFT"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        band.hAlign = "CENTER"
        return band

    def append_consent(self, elements: list, theme: ReportTheme) -> None:
        """Append consent declaration page to the document.

        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
        """
        elements.append(PageBreak())

        palette = theme.palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        title_style = ParagraphStyle(
            "ConsentTitle",
            parent=theme.styles["Heading2"],
            fontSize=11,
            textColor=main,
            spaceAfter=10,
            fontName="Helvetica-Bold",
        )
        text_style = ParagraphStyle(
            "ConsentText",
            parent=theme.styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=dark,
            alignment=TA_JUSTIFY,
        )

        title = Paragraph("DECLARACIÓN DE CONFORMIDAD Y CONSENTIMIENTO", title_style)
        elements.append(title)

        consent_text = """
        El usuario declara y confirma que ha otorgado su consentimiento expreso e
        inequívoco para la realización del escaneo de seguridad sobre el sitio web
        y/o sistema informático objeto del presente informe. El usuario acepta y
        reconoce que es el titular legítimo o cuenta con la autorización necesaria
        de los equipos, sistemas y redes escaneados.

        El usuario asume la plena responsabilidad sobre las consecuencias derivadas
        del escaneo realizado, incluyendo cualquier resultado, hallazgo o
        vulnerabilidad identificada en el proceso. Asimismo, el usuario exonera
        de toda responsabilidad a los ejecutores del análisis de seguridad respecto
        al uso que se haga de la información contenida en este documento.

        Este documento contiene información sensible de carácter confidencial y
        debe ser tratado con las medidas de seguridad apropiadas conforme a la
        normativa vigente en materia de protección de datos.
        """
        paragraph = Paragraph(consent_text.strip(), text_style)
        table = Table([[paragraph]], colWidths=[6 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("BOX", (0, 0), (-1, -1), 1.2, main),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    def append_footer(self, elements: list, theme: ReportTheme) -> None:
        """Append footer text to the document.

        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
        """
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        footer_text = f"Informe generado automáticamente | {timestamp}"
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(footer_text, theme.footer))

    def print_pdf(self,
        ai_report: bool = False,
        client_name: Optional[str] = None
    ) -> str:
        """Generate the complete PDF report.

        Args:
            ai_report: Whether to include AI-generated analysis.
            client_name: Optional client name for the cover page.

        Returns:
            Path to the generated PDF file.
        """
        os.makedirs(self.directory, exist_ok=True)

        # Unique per document, not just per scan — two documents for the same
        # scan (plain + AI, or a re-generation) must not share a file path.
        stem = f"{self.scan.id}_{self.document_id}" if self.document_id else str(self.scan.id)
        filename = os.path.join(
            self.directory,
            f"{stem}{self.printing_strategy.get_filename_suffix()}",
        )

        document = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=60,
            bottomMargin=40,
        )

        base_styles = getSampleStyleSheet()
        theme = ReportTheme(base_styles, self.printing_strategy.color_palette)
        elements: list = []

        self.append_cover_page(
            elements=elements,
            theme=theme,
            title=self.printing_strategy.get_report_title(),
            client_name=client_name,
        )

        self.printing_strategy.append_body(theme=theme, elements=elements, ai_report=ai_report)

        self.append_consent(elements, theme)
        self.append_footer(elements, theme)

        self._set_pdf_metadata(document)
        document.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)

        return filename

