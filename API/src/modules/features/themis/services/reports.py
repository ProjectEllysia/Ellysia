"""
Report generation for security scans.

This module provides classes for generating PDF security reports from scan results.
It includes strategies for different scan types (Nmap, OpenVAS, Nikto) with support
for AI-powered analysis using Ollama.

Classes:
    ColorType: Enumeration of color palette types.
    ReportTheme: Theme configuration for PDF styling.
    PrintingStrategy: Abstract base class for printing strategies.
    PDFCreator: Main class for PDF document generation.
    NmapPrintingStrategy: Strategy for Nmap scan reports.
    OpenVASPrintingStrategy: Strategy for OpenVAS scan reports.
    NiktoPrintingStrategy: Strategy for Nikto scan reports.
    NmapAIWriter: AI writer for Nmap scan analysis.
    NiktoAIWriter: AI writer for Nikto scan analysis.
    OpenVASAIWriter: AI writer for OpenVAS scan analysis.
"""

import os

from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    CondPageBreak,
)

import logging

import src.modules.system.config_reading as CR
from src.modules.shared._exceptions import IllegalStateError, ValidationError

logger = logging.getLogger(__name__)

from ..model import NmapScan, NiktoScan, LybraScan, Scan, Host, ScanType
from .analyzers import NmapAIWriter, NiktoAIWriter, OpenVASAIWriter, LybraAIWriter



class ThemisTool(Enum):
    """Enumeración de herramientas disponibles en Themis"""
    NMAP    = "nmap"
    NIKTO   = "nikto"
    OPENVAS = "openvas"
    LYBRA   = "lybra"


class ColorType(Enum):
    """Color palette type identifiers for report theming."""
    BLACK       = "black"
    DARK        = "dark"
    MAIN        = "main"
    SECONDARY   = "secondary"
    LIGHT       = "light"
    WHITE       = "white"


class ReportTheme:
    """PDF report theme configuration.

    Manages styling for PDF reports including paragraph styles, table styles,
    and helper methods for creating report sections like headers, cards, and tables.

    Attributes:
        palette: Dictionary mapping ColorType to hex color values.
        styles: Base styles from ReportLab.
        title: Main section title style.
        subtitle: Subtitle style.
        pill: Pill/badge style.
        info: Information text style.
        body: Body paragraph style.
        label: Label style.
        footer: Footer style.
        kv_table_style: Key-value table style.
    """

    def __init__(self, base_styles, palette):
        self.palette = palette
        self.styles = base_styles

        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        self._accent_color = light

        self.title = ParagraphStyle(
            "ReportTitle",
            parent=base_styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=black,
            alignment=TA_CENTER,
            spaceBefore=6,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        )

        self.subtitle = ParagraphStyle(
            "ReportSubtitle",
            parent=base_styles["Heading2"],
            fontSize=9,
            leading=12,
            textColor=main,
            alignment=TA_CENTER,
            spaceBefore=2,
            spaceAfter=2,
            fontName="Helvetica-Bold",
        )

        self.pill = ParagraphStyle(
            "Pill",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        self.info = ParagraphStyle(
            "Info",
            parent=base_styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=main,
            alignment=TA_LEFT,
        )

        self.body = ParagraphStyle(
            "Body",
            parent=base_styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=black,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        )

        self.label = ParagraphStyle(
            "Label",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=main,
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        )

        self.footer = ParagraphStyle(
            "Footer",
            parent=base_styles["Normal"],
            fontSize=8,
            leading=9,
            textColor=colors.HexColor("#aaaaaa"),
            alignment=TA_CENTER,
        )

        self.kv_table_style = TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), white),
            ("TEXTCOLOR", (0, 0), (0, -1), main),
            ("TEXTCOLOR", (1, 0), (1, -1), black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
        ])

    def kv_table(self, data, col_widths):
        """Create a key-value style table.

        Args:
            data: List of [key, value] pairs.
            col_widths: Column widths for the table.

        Returns:
            Table with applied key-value style.
        """
        t = Table(data, colWidths=col_widths)
        t.setStyle(self.kv_table_style)
        return t

    def section_header(self, title_text: str, tag_text: str) -> list:
        """
        Devuelve [píldora centrada, título centrado, línea de acento].
        """
        main = colors.HexColor(self.palette[ColorType.MAIN])
        accent = self._accent_color

        # Píldora centrada
        pill_para = Paragraph(tag_text.upper(), self.pill)
        pill_table = Table([[pill_para]], colWidths=[1.8 * inch]) # Ancho ajustado para tags largos
        pill_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("BOX", (0, 0), (-1, -1), 0.7, main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        pill_wrapper = Table([[pill_table]], colWidths=[6 * inch])
        pill_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        # Título centrado
        title_para = Paragraph(title_text, self.title)
        title_wrapper = Table([[title_para]], colWidths=[6 * inch])
        title_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        # Línea de acento
        divider = Table([[""]], colWidths=[2.5 * inch], rowHeights=[0.035 * inch])
        divider.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        divider_wrapper = Table([[divider]], colWidths=[6 * inch])
        divider_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        return [pill_wrapper, title_wrapper, divider_wrapper]

    def card(self, inner_flowables, severity_color=None):
        """
        Envuelve un bloque (vuln/incidente) en una 'card' con borde, padding
        y banda de color opcional a la izquierda.
        """
        white = colors.HexColor(self.palette[ColorType.WHITE])
        border = colors.HexColor("#DDDDDD")
        band_color = severity_color or colors.HexColor(self.palette[ColorType.MAIN])

        # banda vertical + contenido
        band = Table([[""]], colWidths=[0.12 * inch])
        band.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), band_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        content_table = Table([[inner_flowables]], colWidths=[5.8 * inch])
        content_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        outer = Table([[band, content_table]], colWidths=[0.12 * inch, 5.88 * inch])
        outer.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.7, border),
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        return outer

    def severity_header_table(self, left_text: str, right_text: str, bg_color) -> Table:
        data = [[left_text, right_text]]
        t = Table(data, colWidths=[3 * inch, 3 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(self.palette[ColorType.BLACK])),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(self.palette[ColorType.LIGHT])),
        ]))
        return t


class PrintingStrategy(ABC):
    """Abstract base class for printing strategies.

    Defines the interface for generating PDF report content from scan data.
    Each subclass implements type-specific report generation.

    Attributes:
        scan: The scan object to generate report from.
        writer: AI writer instance for analysis generation.
        color_palette: Color palette for the report theme.
        logger: Logger instance for the class.
    """

    _registry: Dict[ScanType, type["PrintingStrategy"]] = {}

    def __init__(self, scan: Scan) -> None:
        super().__init__()
        self.scan = scan
        self.writer = None
        self.color_palette: Dict[ColorType, str] = {}

    @classmethod
    def register(cls, scan_type: ScanType):
        def decorator(subclass: type["PrintingStrategy"]):
            cls._registry[scan_type] = subclass
            return subclass
        return decorator

    @classmethod
    def resolve_printing_strategy(cls, scan_id: int) -> "PrintingStrategy":
        """Resolve the appropriate printing strategy for a scan.

        Creates a new session to avoid DetachedInstanceError when accessing
        scan relationships in background threads.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            PrintingStrategy instance configured with the scan.

        Raises:
            ValidationError: If scan type is not registered.
        """

        from ..managers import ScanManager
        raw_type = ScanManager.get_scan_type(scan_id)
        try:
            scan_type = ScanType(raw_type)
        except ValueError:
            raise ValidationError(
                field="scan_type",
                message=f"Tipo de escaneo desconocido: {raw_type}",
                value=raw_type
            )

        strategy_class = cls._registry.get(scan_type)
        if strategy_class is None:
            raise ValidationError(
                field="scan_type",
                message=f"Estrategia de impresión no registrada para: {scan_type.value}",
                value=scan_type.value
            )

        scan = ScanManager.get_scan_rich(scan_id)
        return strategy_class(scan=scan)

    def _append_ai_analysis(self, elements: list, theme: ReportTheme) -> None:
        """Append AI-generated security analysis to the report."""
        scan_type = type(self.scan).__name__
        logger.info(f"[IA] Iniciando para scan {self.scan.id} ({scan_type})")

        prompts = CR.get_prompts_config()
        tool_key = {
            'NmapScan': 'nmap', 'NiktoScan': 'nikto', 'OpenVASScan': 'openvas', 'LybraScan': 'lybra',
        }.get(scan_type, 'nmap')
        tool_prompts = prompts.get(tool_key, {})

        if not tool_prompts.get('system'):
            logger.error(f"[IA] Prompt 'system' no encontrado para {tool_key}")
            elements.append(PageBreak())
            elements.extend(theme.section_header("Análisis de Seguridad IA", "INTELIGENCIA ARTIFICIAL"))
            elements.append(Paragraph("Error: Configuración IA no encontrada", theme.body))
            return

        if not tool_prompts.get('userTemplate'):
            logger.warning(f"[IA] Prompt 'userTemplate' no encontrado para {tool_key}")

        try:
            if self.writer is None:
                raise IllegalStateError("Writer detectado como None")

            ai_analysis = self.writer.generate(self.scan)
        except Exception as e:
            logger.error(f"[IA] Excepción: {e}", exc_info=True)
            ai_analysis = {}

        if not ai_analysis:
            logger.warning(f"[IA] Respuesta vacía para scan {self.scan.id}")
            elements.append(PageBreak())
            elements.extend(theme.section_header("Análisis de Seguridad IA", "INTELIGENCIA ARTIFICIAL"))
            elements.append(Paragraph("No se pudo generar análisis IA", theme.body))
            return

        logger.info(f"[IA] OK - keys: {list(ai_analysis.keys())}")

        elements.append(PageBreak())

        elements.extend(theme.section_header("Análisis de Seguridad IA", "INTELIGENCIA ARTIFICIAL"))
        elements.append(Spacer(1, 0.15 * inch))

        risk = ai_analysis.get("risk_level", "MEDIO")

        risk_colors = {
            "CRÍTICO": colors.HexColor("#b71c1c"),
            "ALTO": colors.HexColor("#d32f2f"),
            "MEDIO": colors.HexColor("#f57c00"),
            "BAJO": colors.HexColor("#388e3c"),
            "INFORMATIVO": colors.HexColor("#1976d2"),
        }

        risk_color = risk_colors.get(risk.upper(), colors.HexColor("#757575"))

        risk_para = Paragraph(f"NIVEL DE RIESGO: {risk.upper()}", theme.pill)
        risk_table = Table([[risk_para]], colWidths=[2 * inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), risk_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.5, risk_color),
        ]))

        risk_wrapper = Table([[risk_table]], colWidths=[6 * inch])
        risk_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(risk_wrapper)
        elements.append(Spacer(1, 0.1 * inch))

        exec_summary = ai_analysis.get("executive_summary", "")
        if exec_summary and isinstance(exec_summary, str):
            elements.append(Paragraph("Resumen Ejecutivo", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(exec_summary, theme.body))
            elements.append(Spacer(1, 0.15 * inch))

        tech_analysis = ai_analysis.get("technical_analysis", "")
        if tech_analysis and isinstance(tech_analysis, str):
            elements.append(Paragraph("Análisis Técnico", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(tech_analysis, theme.body))
            elements.append(Spacer(1, 0.15 * inch))

        recommendations = ai_analysis.get("recommendations", [])
        if recommendations:
            elements.append(Paragraph("Recomendaciones de Seguridad", theme.subtitle))
            elements.append(Spacer(1, 0.1 * inch))

            priority_colors = {
                "ALTA": colors.HexColor("#d32f2f"),
                "MEDIA": colors.HexColor("#f57c00"),
                "BAJA": colors.HexColor("#388e3c"),
                "INFORMATIVA": colors.HexColor("#1976d2"),
            }

            for i, rec in enumerate(recommendations, 1):
                title = rec.get("title", "Recomendación") if isinstance(rec, dict) else "Recomendación"
                desc = rec.get("description", "") if isinstance(rec, dict) else ""
                priority = rec.get("priority", "MEDIA") if isinstance(rec, dict) else "MEDIA"
                remediation = rec.get("remediation", "") if isinstance(rec, dict) else ""

                pri_color = priority_colors.get(priority.upper(), colors.HexColor("#757575"))

                rec_flowables = []
                rec_flowables.append(Paragraph(f"<b>{i}. {title}</b> — Prioridad: {priority}", theme.info))
                if desc:
                    rec_flowables.append(Spacer(1, 0.05 * inch))
                    rec_flowables.append(Paragraph(desc, theme.body))
                if remediation:
                    rec_flowables.append(Spacer(1, 0.05 * inch))
                    rec_flowables.append(Paragraph(f"<b>Acción:</b> {remediation}", theme.body))

                elements.append(theme.card(rec_flowables, severity_color=pri_color))
                elements.append(Spacer(1, 0.1 * inch))

        conclusions = ai_analysis.get("conclusions", "")
        if conclusions and isinstance(conclusions, str):
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("Conclusiones", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(conclusions, theme.body))

        disclaimer_text = """
        <b>Nota:</b> El contenido de esta sección ha sido generado mediante
        inteligencia artificial y se basa en el análisis automático de los datos del escaneo.
        Si bien se ha diseñado para proporcionar una evaluación de seguridad objetiva, los
        resultados deben ser interpretados por un profesional cualificado, pues Themis no cuenta
        con todo el contexto en el que se encuentran los hosts escaneados. Ellysia no garantiza
        la exactitud, completitud o aplicabilidad de las recomendaciones generadas. Este análisis con
        inteligencia artificial no sustituye —sino complementa— una auditoría de seguridad manual o la evaluación
        detallada por parte de un experto en ciberseguridad.
        """
        disclaimer_style = ParagraphStyle(
            "Disclaimer",
            parent=theme.styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#6C757D"),
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        )
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph(disclaimer_text, disclaimer_style))
        elements.append(Spacer(1, 0.15 * inch))

    def _append_history_stats(self, elements: list, theme: ReportTheme) -> None:
        """Append per-host historical statistics (chart + diff) after the AI section.

        Reuses the same ScanHistoryManager/HistoryStatsService that powers the
        web statistics tab, so the report and the web stay in sync. Tolerant to
        failure: if there is no history or anything goes wrong, the section is
        silently skipped and the report is still produced.
        """
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from ..managers import ScanHistoryManager

        tool_map = {
            "NmapScan": ScanType.NMAP,
            "NiktoScan": ScanType.NIKTO,
            "OpenVASScan": ScanType.OPENVAS,
        }
        scan_type = tool_map.get(type(self.scan).__name__)
        if scan_type is None:
            return

        try:
            payload = ScanHistoryManager().get_host_history(
                self.scan.user_id, self.scan.target, scan_type
            )
        except Exception as e:
            logger.error(f"[HIST] Excepción generando estadísticas históricas: {e}", exc_info=True)
            return

        series = payload.get("series") or [{}]
        points = series[0].get("points", [])
        if not points:
            logger.info(f"[HIST] Sin histórico para scan {self.scan.id}, sección omitida")
            return

        elements.append(PageBreak())
        elements.extend(theme.section_header("Estadísticas Históricas", "EVOLUCIÓN DEL HOST"))
        elements.append(Spacer(1, 0.15 * inch))

        metric_label = payload.get("metricLabel", "Hallazgos")
        scan_count = payload.get("scanCount", len(points))
        x_axis = payload.get("axes", {}).get("x", {})
        first_date = points[0]["x"] if points else None
        last_date = points[-1]["x"] if points else None

        intro = (
            f"El siguiente gráfico recoge la evolución de «{metric_label.lower()}» "
            f"observada en los últimos {scan_count} escaneos de tipo "
            f"{scan_type.value.upper()} realizados sobre <b>{self.scan.target}</b> "
            f"por el usuario propietario de este informe. Permite identificar de un "
            f"vistazo si la superficie expuesta del host crece, se mantiene estable "
            f"o se reduce a lo largo del tiempo."
        )
        elements.append(Paragraph(intro, theme.body))
        elements.append(Spacer(1, 0.08 * inch))

        if first_date and last_date and scan_count >= 2:
            range_text = (
                f"Periodo analizado: desde <b>{first_date}</b> hasta <b>{last_date}</b> "
                f"({scan_count} escaneos). El eje horizontal («{x_axis.get('label', 'Escaneo')}») "
                f"representa cada escaneo en orden cronológico, mientras que el eje vertical "
                f"indica el número de «{metric_label.lower()}» detectados en cada uno."
            )
        else:
            range_text = (
                f"Este es el primer escaneo registrado de este host con esta herramienta, "
                f"por lo que todavía no hay un histórico con el que comparar. A partir del "
                f"siguiente escaneo se mostrará también la comparativa de cambios."
            )
        elements.append(Paragraph(range_text, theme.label))
        elements.append(Spacer(1, 0.18 * inch))

        main_color = colors.HexColor(self.color_palette[ColorType.MAIN])
        light_color = colors.HexColor(self.color_palette[ColorType.LIGHT])

        y_axis = payload.get("axes", {}).get("y", {})
        step = y_axis.get("step", 1) or 1
        max_val = y_axis.get("max", 0) or 0

        drawing = Drawing(460, 210)
        drawing.hAlign = "CENTER"
        bc = VerticalBarChart()
        bc.x = 45
        bc.y = 45
        bc.height = 135
        bc.width = 390
        bc.data = [[p["y"] for p in points]]
        bc.categoryAxis.categoryNames = [p["x"] for p in points]
        bc.categoryAxis.labels.boxAnchor = "ne"
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.labels.fontName = "Helvetica"
        bc.categoryAxis.labels.fontSize = 6
        bc.categoryAxis.labels.dy = -2
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = max(max_val + step, step)
        bc.valueAxis.valueStep = step
        bc.valueAxis.labels.fontName = "Helvetica"
        bc.valueAxis.labels.fontSize = 7
        bc.bars[0].fillColor = main_color
        bc.bars[0].strokeColor = light_color
        drawing.add(bc)
        elements.append(drawing)
        elements.append(Spacer(1, 0.18 * inch))

        # Diff legend (only meaningful with at least two scans to compare).
        if scan_count >= 2:
            diff = payload.get("diff", {})
            legend_data = [
                ["Nuevos", "Iguales", "Desaparecidos"],
                [
                    str(diff.get("new", 0)),
                    str(diff.get("unchanged", 0)),
                    str(diff.get("disappeared", 0)),
                ],
            ]
            legend_table = Table(legend_data, colWidths=[2 * inch, 2 * inch, 2 * inch])
            legend_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), main_color),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.4, light_color),
            ]))
            elements.append(legend_table)
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(Paragraph(
                "Comparativa del último escaneo frente al inmediatamente anterior: "
                "<b>Nuevos</b> son los hallazgos que no estaban presentes antes, "
                "<b>Iguales</b> los que se mantienen en ambos escaneos y "
                "<b>Desaparecidos</b> los que ya no se detectan.",
                theme.label,
            ))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(
                "Un número elevado de hallazgos nuevos o desaparecidos puede indicar "
                "cambios recientes en la configuración o exposición del host; conviene "
                "revisar dichos cambios para confirmar que son intencionados.",
                theme.body,
            ))

    @abstractmethod
    def append_body(self, theme: ReportTheme, elements: list, ai_report: bool = False) -> None:
        """Add the report body specific to each scan tool.

        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """

    @abstractmethod
    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix for this scan type.

        Returns:
            Filename suffix string (e.g., "_Nmap.pdf").
        """

    @abstractmethod
    def get_picture_name(self, dark: bool = True) -> str:
        """Get the logo image name for this scan type.

        Args:
            dark: Whether to use dark variant of logo.

        Returns:
            Logo image filename.
        """

    @abstractmethod
    def get_report_title(self) -> str:
        """Get the report title for the cover page.

        Returns:
            Report title string.
        """


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

    def _set_pdf_metadata(self, doc) -> None:
        """Set PDF document metadata.

        Args:
            doc: SimpleDocTemplate instance.
        """
        scan = self.scan
        started = getattr(scan, "started_at", None)
        date_str = started.strftime("%d/%m/%Y") if started else datetime.now().strftime("%d/%m/%Y")
        doc.title = f"Informe de Seguridad - {scan.id}"
        doc.author = "Ellysia Security Team"
        doc.subject = f"Análisis de seguridad realizado el {date_str}"
        doc.creator = "Ellysia PDF Generator v2.0"

    def _on_page(self, canv, doc):
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

        doc = SimpleDocTemplate(
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

        self._set_pdf_metadata(doc)
        doc.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)

        return filename


@PrintingStrategy.register(ScanType.NMAP)
class NmapPrintingStrategy(PrintingStrategy):
    """Printing strategy for Nmap scan reports.

    Generates PDF reports for Nmap network scans including host information,
    open ports table, and optional AI-powered security analysis.

    Color palette: Blue theme for network security reports.

    Attributes:
        writer: NmapAIWriter instance for AI analysis.
        color_palette: Blue color palette for the report.
    """

    def __init__(self, scan: NmapScan) -> None:
        """Initialize Nmap printing strategy.

        Args:
            scan: NmapScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = NmapAIWriter()

        palette_config = CR.get_tool_color_palette(ThemisTool.NMAP)

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", "#121212"),
            ColorType.DARK: palette_config.get("dark", "#01375A"),
            ColorType.MAIN: palette_config.get("main", "#014F86"),
            ColorType.SECONDARY: palette_config.get("secondary", "#555B6E"),
            ColorType.LIGHT: palette_config.get("light", "#4A90E2"),
            ColorType.WHITE: palette_config.get("white", "#E1E8F0"),
        }

    def append_body(self, theme: ReportTheme, elements: list, ai_report: bool = False) -> None:
        """Generate the report body for Nmap scans.

        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])
        light = colors.HexColor(palette[ColorType.LIGHT])

        elements.append(Paragraph("Informe de Escaneo Nmap", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host: Host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
                ["MAC address:", str(getattr(host, "mac_address", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        total_ports = len(getattr(scan, "open_ports_relation", []))

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de puertos abiertos:", str(total_ports)],
        ]
        scan_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(scan_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Puertos abiertos detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        open_ports = getattr(scan, "open_ports_relation", [])
        if not open_ports:
            elements.append(Paragraph("No se detectaron puertos abiertos.", theme.info))
            return

        port_data = [["#", "Puerto", "Servicio", "Versión del software"]]
        for idx, relation in enumerate(open_ports, start=1):
            port = getattr(relation, "port", None)
            port_id = getattr(port, "port", "") if port else ""
            protocol = getattr(port, "protocol", "") if port else ""
            given_use = str(getattr(relation, "given_use", "") or "").upper()
            product_name = str(getattr(relation, "product", "") or "") or "NO ENCONTRADO"
            product_version = str(getattr(relation, "version", "") or "") or "N/A"

            port_str = f"{port_id}"
            proto_str = protocol.split("/")[0] if protocol else ""

            port_data.append([
                str(idx),
                proto_str,
                given_use,
                f"{product_name} {product_version}".strip(),
            ])

        port_table = Table(
            port_data,
            colWidths=[0.5 * inch, 0.8 * inch, 2.0 * inch, 4.0 * inch],
            repeatRows=1,
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, main),
        ]))
        elements.append(port_table)

        if ai_report:
            self._append_ai_analysis(elements, theme)

        self._append_history_stats(elements, theme)

    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix.

        Returns:
            Filename suffix: "_Nmap.pdf"
        """
        return "_Nmap.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        """Get the logo image name for Nmap reports.

        Args:
            dark: Whether to use dark variant.

        Returns:
            Logo filename.
        """
        picture_name = "Themis-Blue-Bg"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        """Get the report title for the cover page.

        Returns:
            Report title: "Análisis de Seguridad de Red"
        """
        return "Análisis de Seguridad de Red"


@PrintingStrategy.register(ScanType.OPENVAS)
class OpenVASPrintingStrategy(PrintingStrategy):
    """Printing strategy for OpenVAS vulnerability scan reports.

    Generates PDF reports for OpenVAS scans including vulnerability summary,
    detailed vulnerability cards with CVSS scores, and optional AI analysis.

    Color palette: Green theme for vulnerability management reports.

    Attributes:
        color_palette: Green color palette for the report.
    """

    def __init__(self, scan) -> None:
        """Initialize OpenVAS printing strategy.

        Args:
            scan: OpenVASScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = OpenVASAIWriter()

        palette_config = CR.get_tool_color_palette(ThemisTool.OPENVAS)

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", "#0D2818"),
            ColorType.DARK: palette_config.get("dark", "#1B5E20"),
            ColorType.MAIN: palette_config.get("main", "#2E7D32"),
            ColorType.SECONDARY: palette_config.get("secondary", "#43A047"),
            ColorType.LIGHT: palette_config.get("light", "#66BB6A"),
            ColorType.WHITE: palette_config.get("white", "#E8F5E9"),
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        """Generate the report body for OpenVAS scans.

        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        results = getattr(self.scan, "results", []) or []

        self._append_ov_header(theme, elements, results)

        # Resumen de severidad
        if results:
            self._append_ov_severity_summary(theme, elements, results)

            # Detalle de vulnerabilidades
            elements.append(PageBreak())
            elements.append(Paragraph("Vulnerabilidades detectadas", theme.subtitle))
            elements.append(Spacer(1, 0.1 * inch))

            if not results:
                elements.append(Paragraph("No se detectaron vulnerabilidades.", theme.info))
                return

            severity_priority = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "LOG": 4,
                "UNKNOWN": 5,
            }

        def sort_key(res):
            vuln = res.vulnerability
            sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
            sev = str(sev_raw).upper()
            score = getattr(vuln, "severity_score", None) or 0.0
            return (severity_priority.get(sev, 5), -float(score))

        sorted_results = sorted(results, key=sort_key)

        # Colores de fondo por severidad
        severity_bg = {
            "CRITICAL": colors.HexColor("#ffcccc"),
            "HIGH": colors.HexColor("#ffe6cc"),
            "MEDIUM": colors.HexColor("#fff4cc"),
            "LOW": colors.HexColor("#e6ffe6"),
            "LOG": colors.HexColor("#e6f7ff"),
            "UNKNOWN": colors.HexColor("#f0f0f0"),
        }

        description_style = ParagraphStyle(
            "OVDescription",
            parent=theme.body,
            fontSize=9,
            leading=12,
        )

        for idx, result in enumerate(sorted_results, start=1):
            self._append_ov_vulnerability_card(theme, elements, result, idx, severity_bg, description_style)

        if ai_report:
            self._append_ai_analysis(elements, theme)

        self._append_history_stats(elements, theme)

    def _append_ov_header(self, theme: "ReportTheme", elements: list, results: list) -> None:
        """Cabecera del informe: título, tabla de host y tabla de resumen del escaneo."""
        scan = self.scan

        elements.append(Paragraph("Informe de Escaneo OpenVAS", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Task ID:", str(getattr(scan, "task_id", ""))],
            ["Report ID:", str(getattr(scan, "report_id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de vulnerabilidades:", str(len(results))],
        ]
        if getattr(scan, "scan_config_name", None):
            scan_info.append(["Configuración:", str(scan.scan_config_name)])
        if getattr(scan, "scanner_name", None):
            scan_info.append(["Scanner:", str(scan.scanner_name)])

        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_ov_severity_summary(self, theme: "ReportTheme", elements: list, results: list) -> None:
        """Tabla resumen: cantidad y score CVSS promedio por severidad."""
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Resumen de severidad", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        severity_counts: Dict[str, int] = {}
        scores_by_severity: Dict[str, list] = {}

        for result in results:
            vuln = result.vulnerability
            sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
            severity = str(sev_raw).upper()

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            score = getattr(vuln, "severity_score", None)
            if score is not None:
                scores_by_severity.setdefault(severity, []).append(float(score))

        header = ["Severidad", "Cantidad", "Score promedio"]
        data = [header]

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOG", "UNKNOWN"]
        for sev in severity_order:
            if sev not in severity_counts:
                continue
            count = severity_counts[sev]
            scores = scores_by_severity.get(sev, [])
            avg = sum(scores) / len(scores) if scores else 0.0
            data.append([sev, str(count), f"{avg:.1f}"])

        table = Table(data, colWidths=[2.5 * inch, 1.3 * inch, 2.2 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.4, dark),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_ov_vulnerability_card(
        self,
        theme: "ReportTheme",
        elements: list,
        result,
        idx: int,
        severity_bg: dict,
        description_style: ParagraphStyle,
    ) -> None:
        """Tarjeta de una vulnerabilidad: cabecera, nombre, detalles técnicos,
        resumen, impacto, solución y referencias (bloques opcionales según datos)."""
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(CondPageBreak(3 * inch))

        vuln = result.vulnerability
        sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
        severity = str(sev_raw).upper()

        bgcolor = severity_bg.get(severity, severity_bg["UNKNOWN"])
        cvss = getattr(vuln, "cvss_base_score", None)
        score_text = f"CVSS: {cvss:.1f}" if cvss is not None else "CVSS: N/A"

        # Cabecera
        header_table = theme.severity_header_table(
            left_text=f"Vulnerabilidad #{idx}",
            right_text=f"Severidad: {severity} | {score_text}",
            bg_color=bgcolor,
        )
        elements.append(header_table)

        # Nombre de la vulnerabilidad en una banda de color principal
        name_para = Paragraph(str(getattr(vuln, "name", "")), ParagraphStyle(
            "OVName",
            parent=theme.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=colors.whitesmoke,
            alignment=TA_LEFT,
        ))
        name_table = Table([[name_para]], colWidths=[6 * inch])
        name_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.6, dark),
        ]))
        elements.append(name_table)

        # Detalles técnicos
        details = [
            ["NVT OID:", str(getattr(vuln, "nvt_oid", ""))],
            ["Host:", str(getattr(result.host, "ip_address", ""))],
        ]
        detected = getattr(result, "detected_at", None)
        if detected:
            details.append(["Detectado:", detected.strftime("%d/%m/%Y %H:%M:%S")])
        if getattr(vuln, "family", None):
            details.append(["Familia:", str(vuln.family)])
        if getattr(vuln, "cvss_vector", None):
            details.append(["Vector CVSS:", str(vuln.cvss_vector)])
        if getattr(vuln, "qod_value", None) is not None:
            qod_type = getattr(vuln, "qod_type", None) or "N/A"
            details.append(["QoD:", f"{vuln.qod_value}% ({qod_type})"])

        details_table = Table(details, colWidths=[1.7 * inch, 4.3 * inch])
        details_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ]))
        elements.append(details_table)

        # Resumen
        summary = getattr(vuln, "summary", None)
        if summary:
            text = summary[:500] + ("..." if len(summary) > 500 else "")
            para = Paragraph(f"Resumen: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        # Impacto
        impact = getattr(vuln, "impact", None)
        if impact:
            text = impact[:400] + ("..." if len(impact) > 400 else "")
            para = Paragraph(f"Impacto: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff0f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        # Solución
        solution = getattr(vuln, "solution", None)
        if solution:
            text = solution[:400] + ("..." if len(solution) > 400 else "")
            stype = getattr(vuln, "solution_type", None)
            stype_txt = f" ({stype})" if stype else ""
            para = Paragraph(f"Solución{stype_txt}: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        # Referencias
        refs_parts = []
        if getattr(vuln, "cve_ids", None):
            refs_parts.append(f"CVE: {vuln.cve_ids}")
        if getattr(vuln, "cert_refs", None):
            refs_parts.append(f"CERT: {vuln.cert_refs}")
        if getattr(vuln, "bugtraq_ids", None):
            refs_parts.append(f"BugTraq: {vuln.bugtraq_ids}")
        if getattr(vuln, "other_refs", None):
            refs_parts.append(f"Otros: {vuln.other_refs}")

        if refs_parts:
            full = " | ".join(refs_parts)
            text = full[:400] + ("..." if len(full) > 400 else "")
            para = Paragraph(f"Referencias: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        elements.append(Spacer(1, 0.2 * inch))

    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix.

        Returns:
            Filename suffix: "_OpenVAS.pdf"
        """
        return "_OpenVAS.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        """Get the logo image name for OpenVAS reports.

        Args:
            dark: Whether to use dark variant.

        Returns:
            Logo filename.
        """
        picture_name = "Themis-Green-Bg"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        """Get the report title for the cover page.

        Returns:
            Report title: "Análisis de Vulnerabilidades OpenVAS"
        """
        return "Análisis de Vulnerabilidades OpenVAS"


@PrintingStrategy.register(ScanType.NIKTO)
class NiktoPrintingStrategy(PrintingStrategy):
    """Printing strategy for Nikto web vulnerability scan reports.

    Generates PDF reports for Nikto scans including incident summary,
    detailed security incident cards, and optional AI analysis.

    Color palette: Orange/Salmon theme for web security reports.

    Attributes:
        writer: NiktoAIWriter instance for AI analysis.
        color_palette: Orange color palette for the report.
    """

    def __init__(self, scan: NiktoScan) -> None:
        """Initialize Nikto printing strategy.

        Args:
            scan: NiktoScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = NiktoAIWriter()

        palette_config = CR.get_tool_color_palette(ThemisTool.NIKTO)

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", "#4B2500"),
            ColorType.DARK: palette_config.get("dark", "#8E3D0A"),
            ColorType.MAIN: palette_config.get("main", "#C75B12"),
            ColorType.SECONDARY: palette_config.get("secondary", "#FA8072"),
            ColorType.LIGHT: palette_config.get("light", "#F9B49A"),
            ColorType.WHITE: palette_config.get("white", "#FFF5F0"),
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        incidents = getattr(self.scan, "incidents", []) or []

        self._append_nikto_header(theme, elements, incidents)

        # Resumen de severidad
        if incidents:
            self._append_nikto_severity_summary(theme, elements, incidents)

        # Detalle de incidentes
        elements.append(Paragraph("Incidentes de seguridad detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        if not incidents:
            elements.append(Paragraph("No se detectaron incidentes de seguridad.", theme.info))
            return

        severity_priority = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
            "UNKNOWN": 5,
        }

        def sort_key(inc):
            sev_raw = getattr(inc, "severity", None) or "UNKNOWN"
            sev = str(sev_raw).upper()
            return severity_priority.get(sev, 5)

        sorted_incidents = sorted(incidents, key=sort_key)

        severity_bg = {
            "CRITICAL": colors.HexColor("#ffcccc"),
            "HIGH": colors.HexColor("#ffe6cc"),
            "MEDIUM": colors.HexColor("#fff4cc"),
            "LOW": colors.HexColor("#e6f7ff"),
            "INFO": colors.HexColor("#e6f7ff"),
            "UNKNOWN": colors.HexColor("#f0f0f0"),
        }

        description_style = ParagraphStyle(
            "NiktoDesc",
            parent=theme.body,
            fontSize=9,
            leading=12,
        )
        url_style = ParagraphStyle(
            "NiktoUrl",
            parent=theme.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=colors.HexColor(self.color_palette[ColorType.BLACK]),
            wordWrap="CJK",
            alignment=TA_LEFT,
        )

        for idx, incident in enumerate(sorted_incidents, start=1):
            self._append_nikto_incident_card(
                theme, elements, incident, idx, severity_bg, description_style, url_style
            )

        if ai_report:
            self._append_ai_analysis(elements, theme)

        self._append_history_stats(elements, theme)

    def _append_nikto_header(self, theme: "ReportTheme", elements: list, incidents: list) -> None:
        """Cabecera del informe: título, tabla de host y tabla de resumen del escaneo."""
        scan = self.scan

        elements.append(Paragraph("Informe de Escaneo Nikto", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de incidentes:", str(len(incidents))],
        ]
        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_nikto_severity_summary(self, theme: "ReportTheme", elements: list, incidents: list) -> None:
        """Tabla resumen: cantidad de incidentes por severidad."""
        palette = self.color_palette
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Resumen de severidad", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        severity_counts: Dict[str, int] = {}
        for inc in incidents:
            sev_raw = getattr(inc, "severity", None) or "UNKNOWN"
            severity = str(sev_raw).upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        header = ["Severidad", "Cantidad"]
        data = [header]

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        for sev in severity_order:
            if sev not in severity_counts:
                continue
            data.append([sev, str(severity_counts[sev])])

        table = Table(data, colWidths=[3 * inch, 2 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(palette[ColorType.SECONDARY])),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.4, dark),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_nikto_incident_card(
        self,
        theme: "ReportTheme",
        elements: list,
        incident,
        idx: int,
        severity_bg: dict,
        description_style: ParagraphStyle,
        url_style: ParagraphStyle,
    ) -> None:
        """Tarjeta de un incidente: cabecera, detalles, descripción y
        referencias (bloques opcionales según datos disponibles)."""
        palette = self.color_palette
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(CondPageBreak(2.5 * inch))

        sev_raw = getattr(incident, "severity", None) or "UNKNOWN"
        severity = str(sev_raw).upper()
        bgcolor = severity_bg.get(severity, severity_bg["UNKNOWN"])

        # Cabecera simple
        header = Table(
            [[f"Incidente #{idx}", f"Severidad: {severity}"]],
            colWidths=[3 * inch, 3 * inch],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bgcolor),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(palette[ColorType.BLACK])),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.8, white),
        ]))
        elements.append(header)

        # Detalles
        details = []
        if getattr(incident, "osvdb_id", None):
            details.append(["OSVDB ID:", str(incident.osvdb_id)])
        if getattr(incident, "method", None):
            details.append(["Método:", str(incident.method)])
        if getattr(incident, "url", None):
            details.append(["URL:", Paragraph(str(incident.url), url_style)])
        if getattr(incident, "port", None):
            details.append(["Puerto:", str(incident.port)])
        if getattr(incident, "discovered_at", None):
            discovered = incident.discovered_at.strftime("%d/%m/%Y %H:%M:%S")
            details.append(["Detectado:", discovered])

        if details:
            details_table = Table(details, colWidths=[1.6 * inch, 4.4 * inch])
            details_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(details_table)

        # Descripción
        desc = getattr(incident, "description", None)
        if desc:
            text = desc[:500] + ("..." if len(desc) > 500 else "")
            para = Paragraph(f"Descripción: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        # Referencias
        refs = getattr(incident, "references", None)
        if refs:
            text = refs[:300] + ("..." if len(refs) > 300 else "")
            para = Paragraph(f"Referencias: {text}", description_style)
            table = Table([[para]], colWidths=[6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(table)

        elements.append(Spacer(1, 0.2 * inch))

    def get_filename_suffix(self) -> str:
        return "_Nikto.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "Themis-Salmon-Bg"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades Web"


@PrintingStrategy.register(ScanType.LYBRA)
class LybraPrintingStrategy(PrintingStrategy):
    """Printing strategy for Lybra engine scan reports.

    Unlike the other three strategies, the source data is the unified
    `Finding` table rather than a tool-specific incident/vulnerability model,
    fetched via the repository since `LybraScan` deliberately carries no ORM
    relationship to it (see `repositories.py`). Cards are sorted by the same
    `priority` ladder the web UI uses, computed the same way
    (`score_finding`), so the PDF and the web view never disagree.

    Color palette: Green theme, matching Lybra's own UI identity.

    Attributes:
        writer: LybraAIWriter instance for AI analysis.
        color_palette: Green color palette for the report.
    """

    _PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    _PRIORITY_LABEL = {"CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MEDIUM": "MEDIA", "LOW": "BAJA", "INFO": "INFO"}
    _STATE_LABEL = {"open": "Abierto", "fixed": "Corregido", "regressed": "Regresado", "accepted": "Aceptado"}

    def __init__(self, scan: LybraScan) -> None:
        """Initialize Lybra printing strategy.

        Args:
            scan: LybraScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = LybraAIWriter()

        palette_config = CR.get_tool_color_palette(ThemisTool.LYBRA)

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", "#1A2410"),
            ColorType.DARK: palette_config.get("dark", "#4A6132"),
            ColorType.MAIN: palette_config.get("main", "#7CA163"),
            ColorType.SECONDARY: palette_config.get("secondary", "#A8C98F"),
            ColorType.LIGHT: palette_config.get("light", "#D4E8C4"),
            ColorType.WHITE: palette_config.get("white", "#F3F8EE"),
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        from src.modules.infrastructure.session import build_repository
        from ..repositories import ScanRepository
        from ..lybra import classify_exposure, score_finding

        rows = build_repository(ScanRepository).get_findings_by_scan(self.scan.id)
        exposure = classify_exposure(self.scan.target)

        findings = [{
            "title": f.title, "category": f.category, "port": f.port, "service": f.service,
            "cpe": f.cpe, "cve_ids": f.cve_ids or [], "cvss_score": f.cvss_score,
            "epss_score": f.epss_score, "in_kev": f.in_kev, "qod": f.qod, "confirmed": f.confirmed,
            "source": f.source, "state": f.state,
        } for f in rows]
        for f in findings:
            f["priority"] = score_finding(f, exposure)
        self._enrich_with_cve_context(findings)

        self._append_lybra_header(theme, elements, findings, exposure)

        if findings:
            self._append_lybra_summary(theme, elements, findings)

        elements.append(Paragraph("Hallazgos", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        if not findings:
            elements.append(Paragraph("El motor no detectó ningún hallazgo para este objetivo.", theme.info))
        else:
            # Priority first (the contextual CVSS+EPSS+KEV+exposure synthesis that is
            # Lybra's whole value proposition — see roadmap §1); raw CVSS only breaks
            # ties *within* the same priority band, confirmed findings before hypotheses.
            sorted_findings = sorted(
                findings,
                key=lambda f: (
                    self._PRIORITY_ORDER.get(f["priority"], 5),
                    not f["confirmed"],
                    -(f["cvss_score"] or 0),
                ),
            )
            for idx, f in enumerate(sorted_findings, start=1):
                self._append_lybra_finding_card(theme, elements, f, idx)

        if ai_report:
            self._append_ai_analysis(elements, theme)

        # ponytail: no per-target history chart for Lybra yet — _append_history_stats'
        # tool_map only knows the Nmap/Nikto/OpenVAS scan classes, since it relies on
        # a MetricExtractor for each; a Finding-based one for Lybra is separate scope
        # from wiring the PDF itself. Add it when that's needed.

    def _enrich_with_cve_context(self, findings: list) -> None:
        """Attach CVE description/CWE/fixed-version context from the local KB.

        One bulk query for every CVE referenced by this scan's findings — never
        one query per finding. Nothing here is invented: `description`/`cwe_ids`
        come straight from the mirrored NVD record, and `fixed_version` is only
        set when NVD's own applicability data (the CpeMatch that matched this
        finding's product) actually states an upper bound.
        """
        from src.modules.infrastructure.session import build_repository
        from ..repositories import KbRepository
        from ..lybra import parse_cpe23

        cve_ids = sorted({cve for f in findings for cve in (f.get("cve_ids") or [])})
        if not cve_ids:
            return

        entries = {e.cve_id: e for e in build_repository(KbRepository).get_cves_with_matches(cve_ids)}

        for f in findings:
            ids = f.get("cve_ids") or []
            if not ids:
                continue
            entry = entries.get(ids[0])
            if entry is None:
                continue
            f["description"] = entry.description
            f["cwe_ids"] = entry.cwe_ids or []
            f["fixed_version"] = self._find_fixed_version(entry, f.get("cpe"), parse_cpe23)

    @staticmethod
    def _find_fixed_version(entry, cpe, parse_cpe23) -> Optional[str]:
        """Read the 'fixed in' version bound off the CpeMatch row for this
        finding's own product, when NVD states one. Returns None rather than
        guessing when no matching row has an upper bound."""
        if not cpe:
            return None
        parsed = parse_cpe23(cpe)
        if not parsed:
            return None
        for m in entry.cpe_matches:
            if m.vendor == parsed["vendor"] and m.product == parsed["product"]:
                if m.version_end_excluding:
                    return m.version_end_excluding
                if m.version_end_including:
                    return m.version_end_including
        return None

    def _append_lybra_header(self, theme: "ReportTheme", elements: list, findings: list, exposure: str) -> None:
        """Cabecera del informe: título y tablas de objetivo/escaneo."""
        scan = self.scan

        elements.append(Paragraph("Informe del Motor Lybra", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        exposure_label = "Pública" if exposure == "public" else "Privada" if exposure == "private" else "Desconocida"
        target_info = [
            ["Objetivo:", str(getattr(scan, "target", ""))],
            ["Exposición:", exposure_label],
        ]
        if getattr(scan, "source_scan_id", None):
            target_info.append(["Analiza escaneo Nmap:", f"#{scan.source_scan_id}"])
        target_table = theme.kv_table(target_info, col_widths=[2 * inch, 4 * inch])
        elements.append(target_table)
        elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        confirmed_count = sum(1 for f in findings if f["confirmed"])

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de hallazgos:", str(len(findings))],
            ["Confirmados activamente:", str(confirmed_count)],
        ]
        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_lybra_summary(self, theme: "ReportTheme", elements: list, findings: list) -> None:
        """Tabla resumen: cantidad de hallazgos por prioridad."""
        palette = self.color_palette
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Resumen por prioridad", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        counts: Dict[str, int] = {}
        for f in findings:
            counts[f["priority"]] = counts.get(f["priority"], 0) + 1

        data = [["Prioridad", "Cantidad"]]
        for prio in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if prio not in counts:
                continue
            data.append([self._PRIORITY_LABEL[prio], str(counts[prio])])

        table = Table(data, colWidths=[3 * inch, 2 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(palette[ColorType.SECONDARY])),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.4, dark),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_lybra_finding_card(self, theme: "ReportTheme", elements: list, finding: dict, idx: int) -> None:
        """Tarjeta de un hallazgo: cabecera de prioridad, nombre, detalles,
        descripción y referencias (mismo lenguaje visual que Nmap/Nikto/OpenVAS:
        cada bloque lleva su propio borde, no solo la cabecera)."""
        severity_bg = {
            "CRITICAL": colors.HexColor("#ffcccc"),
            "HIGH": colors.HexColor("#ffe6cc"),
            "MEDIUM": colors.HexColor("#fff4cc"),
            "LOW": colors.HexColor("#e6f7ff"),
            "INFO": colors.HexColor("#f0f0f0"),
        }
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        border = colors.HexColor("#dddddd")
        prio = finding["priority"]
        bgcolor = severity_bg.get(prio, severity_bg["INFO"])

        elements.append(CondPageBreak(2.5 * inch))

        confirmed_text = "Comprobado" if finding["confirmed"] else "Potencial"
        header = theme.severity_header_table(
            left_text=f"Hallazgo #{idx}: {self._PRIORITY_LABEL.get(prio, prio)}",
            right_text=confirmed_text,
            bg_color=bgcolor,
        )
        elements.append(header)

        # Título en banda de color principal, igual que el nombre de vulnerabilidad de OpenVAS.
        title_para = Paragraph(finding["title"], ParagraphStyle(
            "LybraFindingTitle", parent=theme.styles["Normal"], fontName="Helvetica-Bold",
            fontSize=10, textColor=colors.whitesmoke, alignment=TA_LEFT,
        ))
        title_table = Table([[title_para]], colWidths=[6 * inch])
        title_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.6, dark),
        ]))
        elements.append(title_table)

        details = []
        if finding.get("port"):
            details.append(["Puerto/servicio:", f"{finding.get('service') or '?'}:{finding['port']}"])
        if finding.get("cve_ids"):
            details.append(["CVE:", ", ".join(finding["cve_ids"])])
        if finding.get("cwe_ids"):
            details.append(["CWE:", ", ".join(finding["cwe_ids"])])
        if finding.get("cvss_score") is not None:
            details.append(["CVSS:", str(finding["cvss_score"])])
        if finding.get("epss_score") is not None:
            details.append(["EPSS (30 días):", f"{finding['epss_score'] * 100:.1f}%"])
        if finding.get("in_kev"):
            details.append(["CISA KEV:", "Sí — explotada activamente"])
        if finding.get("fixed_version"):
            details.append(["Corregido en:", f"{finding['fixed_version']} o superior"])
        if finding.get("state") and finding["state"] != "open":
            details.append(["Estado:", self._STATE_LABEL.get(finding["state"], finding["state"])])
        if finding.get("source") and finding["source"] != "lybra":
            details.append(["Corroborado por:", finding["source"]])

        if details:
            detail_table = Table(details, colWidths=[1.7 * inch, 4.3 * inch])
            detail_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(palette[ColorType.BLACK])),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, border),
            ]))
            elements.append(detail_table)

        description = finding.get("description")
        if description:
            text = description[:450] + ("..." if len(description) > 450 else "")
            desc_style = ParagraphStyle(
                "LybraFindingDesc", parent=theme.body, fontSize=8.5, leading=11.5,
            )
            para = Paragraph(f"Qué implica: {text}", desc_style)
            desc_table = Table([[para]], colWidths=[6 * inch])
            desc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, border),
            ]))
            elements.append(desc_table)

        elements.append(Spacer(1, 0.2 * inch))

    def get_filename_suffix(self) -> str:
        return "_Lybra.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "Themis-Green-Bg"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Veredicto del Motor Lybra"