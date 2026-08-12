"""Estrategia de impresión de los informes de Nikto (D5)."""

from typing import Dict
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, Paragraph, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from ...model import NiktoScan, ScanType
from ..analyzers import NiktoAIWriter
from src.modules.shared.report_theme import ColorType
from .base import PrintingStrategy


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

        palette_config = CR.get_tool_color_palette(ScanType.NIKTO)

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

        def sort_key(incident):
            sev_raw = getattr(incident, "severity", None) or "UNKNOWN"
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
        for incident in incidents:
            sev_raw = getattr(incident, "severity", None) or "UNKNOWN"
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

