"""
``PrintingStrategy``: contrato y registro de las estrategias de impresión.

Cada tipo de escaneo se da de alta con ``@PrintingStrategy.register(...)``
junto a su propia clase; ``resolve_printing_strategy`` despacha por ese
registro, así que añadir un tipo nuevo no toca este fichero.

D5 en ``plans/deuda-tecnica-y-calidad.md``.
"""

import logging

from abc import ABC, abstractmethod
from typing import Dict
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from src.modules.shared._exceptions import IllegalStateError, ValidationError
from ...model import Scan, ScanType
from .theme import ColorType, ReportTheme

logger = logging.getLogger(__name__)


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

        from src.modules.features.themis import ScanManager
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
        tool_key = self.scan.scan_type
        logger.info(f"[IA] Iniciando para scan {self.scan.id} ({tool_key})")

        prompts = CR.get_prompts_config()
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
        bc.data = [[point["y"] for point in points]]
        bc.categoryAxis.categoryNames = [point["x"] for point in points]
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

