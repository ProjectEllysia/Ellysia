"""
PDF report generation for Iris email-header analyses.

Renders the same information shown in the web report viewer (verdict,
score, per-rule results, recommendations, Received-chain path and raw
headers) into a downloadable PDF. Mirrors the visual conventions of
``sentinel.services.reports`` (cover page, consent page, footer) but is
self-contained: Iris analyses are not Sentinel scans, so this module
does not depend on the ``PrintingStrategy`` registry.

Classes:
    IrisReportTheme: Theme configuration for PDF styling (Iris palette).
    IrisPDFCreator: Builds the complete PDF from an analysis report dict.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import Any, Dict, Optional

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
    PageBreak,
)

import src.modules.system.config_reading as CR

logger = logging.getLogger(__name__)


# Iris brand palette (violet) — distinct from Sentinel's blue/green tools.
PALETTE = {
    "black":     "#1A1330",
    "dark":      "#3B2768",
    "main":      "#5B3FA8",
    "secondary": "#8A6FD1",
    "light":     "#B89EE8",
    "white":     "#F1ECFB",
}

_VERDICT_COLORS = {
    "Legitimate": colors.HexColor("#388e3c"),
    "Suspicious": colors.HexColor("#f57c00"),
    "Phishing":   colors.HexColor("#d32f2f"),
}

_VERDICT_LABELS = {
    "Legitimate": "Correo verificado",
    "Suspicious": "Posible amenaza",
    "Phishing":   "Phishing detectado",
}


def _esc(value: Any) -> str:
    """Escape text for safe interpolation into a reportlab Paragraph.

    Paragraph interprets a small XML-like markup, so any user/analysis
    controlled text (rule names, domains, recommendations...) must be
    escaped before being embedded — otherwise a stray ``&``/``<``/``>``
    breaks parsing or, worse, lets arbitrary mini-markup through.
    """
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class IrisReportTheme:
    """PDF report theme configuration for Iris reports.

    Provides the paragraph/table styles shared across the document body
    (title, subtitle, body text, key-value tables, section headers).
    """

    def __init__(self, base_styles, palette: Dict[str, str]):
        self.palette = palette
        self.styles = base_styles

        main = colors.HexColor(palette["main"])
        light = colors.HexColor(palette["light"])
        white = colors.HexColor(palette["white"])
        black = colors.HexColor(palette["black"])
        self._accent_color = light

        self.title = ParagraphStyle(
            "IrisTitle", parent=base_styles["Heading1"],
            fontSize=20, leading=24, textColor=black,
            alignment=TA_CENTER, spaceBefore=6, spaceAfter=4,
            fontName="Helvetica-Bold",
        )
        self.subtitle = ParagraphStyle(
            "IrisSubtitle", parent=base_styles["Heading2"],
            fontSize=9, leading=12, textColor=main,
            alignment=TA_CENTER, spaceBefore=2, spaceAfter=2,
            fontName="Helvetica-Bold",
        )
        self.body = ParagraphStyle(
            "IrisBody", parent=base_styles["Normal"],
            fontSize=9, leading=12, textColor=black,
            alignment=TA_JUSTIFY, spaceAfter=5,
        )
        self.label = ParagraphStyle(
            "IrisLabel", parent=base_styles["Normal"],
            fontSize=7, leading=9, textColor=main,
            alignment=TA_LEFT, fontName="Helvetica-Bold",
        )
        self.footer = ParagraphStyle(
            "IrisFooter", parent=base_styles["Normal"],
            fontSize=8, leading=9, textColor=colors.HexColor("#aaaaaa"),
            alignment=TA_CENTER,
        )
        self.mono = ParagraphStyle(
            "IrisMono", parent=base_styles["Normal"],
            fontSize=7.5, leading=10, textColor=black,
            fontName="Courier",
        )

        # Table-cell styles: wrap (and, if a single word is too wide,
        # break it) instead of overflowing past the column's fixed width.
        self.cell_left = ParagraphStyle(
            "IrisCellLeft", parent=base_styles["Normal"],
            fontSize=8, leading=10, textColor=black,
            alignment=TA_LEFT, wordWrap="CJK",
        )
        self.cell_center = ParagraphStyle(
            "IrisCellCenter", parent=self.cell_left, alignment=TA_CENTER,
        )
        self.cell_header = ParagraphStyle(
            "IrisCellHeader", parent=self.cell_left,
            textColor=white, alignment=TA_CENTER, fontName="Helvetica-Bold",
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
        """Create a key-value style table."""
        t = Table(data, colWidths=col_widths)
        t.setStyle(self.kv_table_style)
        return t

    def section_header(self, title_text: str, tag_text: str) -> list:
        """Return [pill, centered title, accent divider] flowables."""
        main = colors.HexColor(self.palette["main"])
        accent = self._accent_color

        pill_style = ParagraphStyle(
            "IrisPill", parent=self.styles["Normal"],
            fontSize=7, leading=9, textColor=colors.HexColor(self.palette["white"]),
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        )
        pill_para = Paragraph(tag_text.upper(), pill_style)
        pill_table = Table([[pill_para]], colWidths=[2.2 * inch])
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

        title_para = Paragraph(title_text, self.title)
        title_wrapper = Table([[title_para]], colWidths=[6 * inch])
        title_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        divider = Table([[""]], colWidths=[2.5 * inch], rowHeights=[0.035 * inch])
        divider.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), accent)]))
        divider_wrapper = Table([[divider]], colWidths=[6 * inch])
        divider_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        return [pill_wrapper, title_wrapper, divider_wrapper]


class IrisPDFCreator:
    """Builds a complete PDF report from an Iris analysis report dict.

    The report dict and path dict are produced by
    ``IrisManager.get_analysis_results`` and ``IrisManager.get_analysis_path``
    respectively, so this class stays a pure rendering layer with no
    direct database access.
    """

    def __init__(self, report: Dict[str, Any], path: Optional[Dict[str, Any]] = None) -> None:
        self.report = report
        self.path = path or {}
        self.directory = CR.get_directory_of(CR.DirectoryType.OUTPUT_IRIS)

    def _set_pdf_metadata(self, doc) -> None:
        analysis_id = self.report.get("analysisId")
        doc.title = f"Informe de Análisis Iris - {analysis_id}"
        doc.author = "Ellysia Security Team"
        doc.subject = "Análisis de cabeceras de correo (anti-phishing)"
        doc.creator = "Ellysia PDF Generator v2.0"

    def _on_page(self, canv, doc):
        canv.saveState()
        width, height = A4

        main = colors.HexColor(PALETTE["main"])
        dark = colors.HexColor(PALETTE["dark"])

        canv.setFillColor(main)
        canv.rect(20, 20, 6, height - 40, stroke=0, fill=1)

        canv.setFont("Helvetica-Bold", 12)
        canv.setFillColor(dark)
        canv.drawString(40, height - 30, "Iris Email Security Report")

        canv.setStrokeColor(colors.HexColor("#e0e0e0"))
        canv.setLineWidth(0.5)
        canv.line(36, height - 42, width - 36, height - 42)

        canv.setFont("Helvetica", 8)
        canv.setFillColor(colors.HexColor("#999999"))
        canv.drawRightString(width - 40, 28, f"Página {canv.getPageNumber()}")

        canv.restoreState()

    def append_cover_page(self, elements: list, theme: IrisReportTheme) -> None:
        palette = theme.palette
        main = colors.HexColor(palette["main"])
        light = colors.HexColor(palette["light"])
        white = colors.HexColor(palette["white"])
        black = colors.HexColor(palette["black"])

        elements.append(Spacer(1, 2.5 * inch))

        title_style = ParagraphStyle(
            "IrisCoverTitle", parent=theme.styles["Heading1"],
            fontSize=28, leading=32, textColor=white,
            alignment=TA_CENTER, fontName="Helvetica-Bold", wordWrap="CJK",
        )
        title = _esc(self.report.get("title") or "Análisis de Correo Electrónico")
        title_table = Table([[Paragraph(title, title_style)]], colWidths=[6 * inch])
        title_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("TOPPADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
            ("LEFTPADDING", (0, 0), (-1, -1), 24),
            ("RIGHTPADDING", (0, 0), (-1, -1), 24),
        ]))
        elements.append(title_table)
        elements.append(Spacer(1, 1.3 * inch))

        started = self.report.get("startedAt")
        date_str = started[:10] if started else datetime.now().strftime("%Y-%m-%d")
        info_data = [
            ["Análisis:", f"#{self.report.get('analysisId')}"],
            ["Fecha:", date_str],
            ["Usuario:", str(self.report.get("user", ""))],
        ]
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
        decoration.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), light)]))
        elements.append(decoration)
        elements.append(PageBreak())

    def append_verdict_hero(self, elements: list, theme: IrisReportTheme) -> None:
        verdict = self.report.get("verdict") or "Suspicious"
        score = self.report.get("totalScore")
        risk_color = _VERDICT_COLORS.get(verdict, colors.HexColor("#757575"))
        label = _VERDICT_LABELS.get(verdict, "")

        score_style = ParagraphStyle(
            "IrisScore", parent=theme.styles["Normal"],
            fontSize=26, leading=30, textColor=risk_color,
            alignment=TA_LEFT, fontName="Helvetica-Bold",
        )
        verdict_style = ParagraphStyle(
            "IrisVerdict", parent=theme.styles["Normal"],
            fontSize=15, leading=18, textColor=risk_color,
            alignment=TA_LEFT, fontName="Helvetica-Bold",
        )
        label_style = ParagraphStyle(
            "IrisVerdictLabel", parent=theme.styles["Normal"],
            fontSize=9.5, leading=12, textColor=colors.HexColor(theme.palette["dark"]),
            alignment=TA_LEFT,
        )

        score_cell = Paragraph(f"{score if score is not None else 'N/A'}", score_style)
        verdict_cell = [Paragraph(verdict, verdict_style)]
        if label:
            verdict_cell.append(Paragraph(label, label_style))

        hero = Table([[score_cell, verdict_cell]], colWidths=[2 * inch, 4 * inch])
        hero.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, risk_color),
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 16),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ]))
        elements.append(hero)
        elements.append(Spacer(1, 0.25 * inch))

    def append_gate_reasons(self, elements: list, theme: IrisReportTheme) -> None:
        """Señales de alta confianza que fijaron el veredicto (S1).

        Solo aparece cuando algún gate se disparó — explica el "por qué"
        del veredicto más allá de la puntuación numérica.
        """
        reasons = self.report.get("gateReasons") or []
        if not reasons:
            return

        verdict = self.report.get("verdict") or "Suspicious"
        risk_color = _VERDICT_COLORS.get(verdict, colors.HexColor("#757575"))

        elements.extend(theme.section_header("Por qué este veredicto", "SEÑALES CLAVE"))
        elements.append(Spacer(1, 0.08 * inch))

        reason_style = ParagraphStyle(
            "IrisGateReason", parent=theme.body,
            textColor=risk_color,
        )
        for reason in reasons:
            elements.append(Paragraph(f"• {_esc(reason)}", reason_style))
        elements.append(Spacer(1, 0.2 * inch))

    def append_rules(self, elements: list, theme: IrisReportTheme) -> None:
        rules = self.report.get("rules") or []
        elements.extend(theme.section_header("Reglas Aplicadas", "VERIFICACIONES"))
        elements.append(Spacer(1, 0.1 * inch))

        if not rules:
            elements.append(Paragraph("No se ejecutaron reglas.", theme.body))
            return

        main = colors.HexColor(theme.palette["main"])
        light = colors.HexColor(theme.palette["light"])
        white = colors.HexColor(theme.palette["white"])
        dark = colors.HexColor(theme.palette["dark"])

        rule_data = [[
            Paragraph("Regla", theme.cell_header),
            Paragraph("Categoría", theme.cell_header),
            Paragraph("Puntuación", theme.cell_header),
            Paragraph("Veredicto", theme.cell_header),
        ]]
        for r in rules:
            score = r.get("score", 0)
            sign = "+" if score > 0 else ""
            rule_data.append([
                Paragraph(_esc(r.get("ruleName", "")), theme.cell_left),
                Paragraph(_esc(r.get("category") or "-"), theme.cell_left),
                Paragraph(f"{sign}{score}", theme.cell_center),
                Paragraph(_esc(r.get("verdict", "")), theme.cell_center),
            ])

        rule_table = Table(
            rule_data,
            colWidths=[2.1 * inch, 1.6 * inch, 1.1 * inch, 1.2 * inch],
            repeatRows=1,
        )
        rule_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, 0), 7),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, main),
        ]))
        elements.append(rule_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Recommendations attached to failing rules.
        flagged = [r for r in rules if r.get("recommendation")]
        if flagged:
            elements.append(Paragraph("Detalle de hallazgos", theme.subtitle))
            elements.append(Spacer(1, 0.08 * inch))
            for r in flagged:
                text = f"<b>{_esc(r.get('ruleName'))}:</b> {_esc(r.get('recommendation'))}"
                elements.append(Paragraph(text, theme.body))
            elements.append(Spacer(1, 0.15 * inch))

    def append_recommendations(self, elements: list, theme: IrisReportTheme) -> None:
        recommendations = self.report.get("recommendations") or []
        if not recommendations:
            return
        elements.append(PageBreak())
        elements.extend(theme.section_header("Recomendaciones", "ACCIONES SUGERIDAS"))
        elements.append(Spacer(1, 0.1 * inch))
        for rec in recommendations:
            elements.append(Paragraph(f"• {_esc(rec)}", theme.body))
        elements.append(Spacer(1, 0.15 * inch))

    def append_path(self, elements: list, theme: IrisReportTheme) -> None:
        if not self.path or not self.path.get("available"):
            return
        hops = self.path.get("hops") or []
        if not hops:
            return

        elements.append(PageBreak())
        elements.extend(theme.section_header("Recorrido del Correo", "CADENA RECEIVED"))
        elements.append(Spacer(1, 0.1 * inch))

        main = colors.HexColor(theme.palette["main"])
        light = colors.HexColor(theme.palette["light"])
        white = colors.HexColor(theme.palette["white"])
        dark = colors.HexColor(theme.palette["dark"])

        hop_data = [[
            Paragraph("#", theme.cell_header),
            Paragraph("Desde", theme.cell_header),
            Paragraph("IP", theme.cell_header),
            Paragraph("TLS", theme.cell_header),
            Paragraph("Fecha", theme.cell_header),
        ]]
        for hop in hops:
            hop_data.append([
                Paragraph(_esc(hop.get("hop", "")), theme.cell_center),
                Paragraph(_esc(hop.get("from") or "-"), theme.cell_left),
                Paragraph(_esc(hop.get("fromIp") or "-"), theme.cell_left),
                Paragraph("Sí" if hop.get("tls") else "No", theme.cell_center),
                Paragraph(_esc(hop.get("timestamp") or "-"), theme.cell_left),
            ])

        hop_table = Table(
            hop_data,
            colWidths=[0.4 * inch, 2.2 * inch, 1.3 * inch, 0.5 * inch, 1.6 * inch],
            repeatRows=1,
        )
        hop_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
        ]))
        elements.append(hop_table)

        transitions = self.path.get("transitions") or []
        suspicious = [t for t in transitions if t.get("suspicious")]
        if suspicious:
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph("Transiciones sospechosas detectadas", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            for t in suspicious:
                reasons = _esc(", ".join(t.get("reasons") or []))
                elements.append(Paragraph(
                    f"Salto {_esc(t.get('from'))} → {_esc(t.get('to'))}: {reasons}", theme.body
                ))

    def append_raw_headers(self, elements: list, theme: IrisReportTheme) -> None:
        raw = self.report.get("rawHeaders")
        if not raw:
            return
        elements.append(PageBreak())
        elements.extend(theme.section_header("Cabeceras Originales", "EVIDENCIA RAW"))
        elements.append(Spacer(1, 0.1 * inch))
        # Escape so reportlab's mini-markup doesn't choke on raw header text.
        escaped = (
            raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        for line in escaped.splitlines():
            elements.append(Paragraph(line if line.strip() else "&nbsp;", theme.mono))

    def append_consent(self, elements: list, theme: IrisReportTheme) -> None:
        elements.append(PageBreak())
        palette = theme.palette
        main = colors.HexColor(palette["main"])
        dark = colors.HexColor(palette["dark"])
        white = colors.HexColor(palette["white"])

        title_style = ParagraphStyle(
            "IrisConsentTitle", parent=theme.styles["Heading2"],
            fontSize=11, textColor=main, spaceAfter=10, fontName="Helvetica-Bold",
        )
        text_style = ParagraphStyle(
            "IrisConsentText", parent=theme.styles["Normal"],
            fontSize=9, leading=12, textColor=dark, alignment=TA_JUSTIFY,
        )

        elements.append(Paragraph("NOTA SOBRE EL ANÁLISIS", title_style))
        consent_text = """
        Este informe se ha generado automáticamente a partir del análisis de
        las cabeceras (y, cuando estaba disponible, el cuerpo) del correo
        electrónico indicado. El veredicto y la puntuación reflejan el resultado
        de las reglas heurísticas aplicadas y deben interpretarse como una ayuda
        a la decisión, no como una determinación legal o definitiva sobre la
        naturaleza del mensaje. Iris no garantiza la exactitud o completitud
        del análisis frente a técnicas de evasión no contempladas por las reglas
        vigentes en el momento de la ejecución.

        Este documento puede contener información sensible extraída del correo
        analizado y debe tratarse con las medidas de seguridad apropiadas.
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

    def append_footer(self, elements: list, theme: IrisReportTheme) -> None:
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(f"Informe generado automáticamente | {timestamp}", theme.footer))

    def print_pdf(self) -> str:
        """Generate the complete PDF report and return its file path."""
        os.makedirs(self.directory, exist_ok=True)

        analysis_id = self.report.get("analysisId")
        filename = os.path.join(self.directory, f"{analysis_id}_Iris.pdf")

        doc = SimpleDocTemplate(
            filename, pagesize=A4,
            rightMargin=36, leftMargin=36, topMargin=60, bottomMargin=40,
        )

        base_styles = getSampleStyleSheet()
        theme = IrisReportTheme(base_styles, PALETTE)
        elements: list = []

        self.append_cover_page(elements, theme)
        self.append_verdict_hero(elements, theme)
        self.append_gate_reasons(elements, theme)
        self.append_rules(elements, theme)
        self.append_recommendations(elements, theme)
        self.append_path(elements, theme)
        self.append_raw_headers(elements, theme)
        self.append_consent(elements, theme)
        self.append_footer(elements, theme)

        self._set_pdf_metadata(doc)
        doc.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)

        return filename
