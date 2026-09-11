"""
PDF report generation for Iris email-header analyses.

Renders the same information shown in the web report viewer (verdict,
score, per-rule results, recommendations, Received-chain path and raw
headers) into a downloadable PDF. Mirrors the visual conventions of
``themis.services.reports`` (cover page, consent page, footer) but is
self-contained: Iris analyses are not Themis scans, so this module
does not depend on the ``PrintingStrategy`` registry.

Classes:
    IrisReportTheme: Theme configuration for PDF styling (Iris palette).
    IrisPDFCreator: Builds the complete PDF from an analysis report dict.
"""

from __future__ import annotations

import os
import logging
import uuid
from datetime import datetime
from email.utils import parseaddr
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
from .parsers import parse_raw_headers, decode_mime_words
from .redaction import redact_pii

logger = logging.getLogger(__name__)


# Iris brand palette (violet) — distinct from Themis's blue/green tools.
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
        table = Table(data, colWidths=col_widths)
        table.setStyle(self.kv_table_style)
        return table

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

    def __init__(self, report: Dict[str, Any], path: Optional[Dict[str, Any]] = None,
                 document_id: Optional[int] = None) -> None:
        self.report = report
        self.path = path or {}
        self.document_id = document_id
        self.directory = CR.get_directory_of(CR.DirectoryType.OUTPUT_IRIS)

    def _set_pdf_metadata(self, document) -> None:
        analysis_id = self.report.get("analysisId")
        document.title = f"Informe de Análisis Iris - {analysis_id}"
        document.author = "Ellysia Security Team"
        document.subject = "Análisis de cabeceras de correo (anti-phishing)"
        document.creator = "Ellysia PDF Generator v2.0"

    def _on_page(self, canv, document):
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

    def append_email_preview(self, elements: list, theme: IrisReportTheme) -> None:
        """Vista previa del correo: De / Para / Responder-a / Asunto / Fecha.

        Va de las primeras secciones del informe (justo tras el veredicto)
        para dar contexto inmediato de "qué correo es este" antes de entrar
        en el detalle de reglas y evidencia. El contraste De vs. Responder-a
        se resalta porque una discrepancia entre ambos es una señal clásica
        de fraude BEC (el atacante quiere que las respuestas vayan a un
        buzón distinto del remitente que se ve a simple vista).

        Las cabeceras salen de ``previewHeaders``, que el manager toma del
        contexto que produjo el veredicto; si el informe no las trae (un
        informe construido a mano), se leen del raw.
        """
        preview = self.report.get("previewHeaders")
        if preview is None:
            raw = self.report.get("rawHeaders")
            if not raw:
                return
            headers = parse_raw_headers(raw)
            preview = {
                key: (decode_mime_words(headers[name]) if headers.get(name) else None)
                for name, key in (("subject", "subject"), ("from", "from"), ("to", "to"),
                                  ("reply-to", "replyTo"), ("return-path", "returnPath"),
                                  ("date", "date"))
            }

        subject = preview.get("subject")
        from_ = preview.get("from")
        to_address = preview.get("to")
        reply_to = preview.get("replyTo")
        return_path = preview.get("returnPath")
        date = preview.get("date")

        if not any([subject, from_, to_address, reply_to, return_path, date]):
            return

        elements.extend(theme.section_header("Vista Previa del Correo", "CONTENIDO"))
        elements.append(Spacer(1, 0.1 * inch))

        main = colors.HexColor(theme.palette["main"])
        dark = colors.HexColor(theme.palette["dark"])
        white = colors.HexColor(theme.palette["white"])
        light = colors.HexColor(theme.palette["light"])
        alert = colors.HexColor("#d32f2f")

        value_style = ParagraphStyle(
            "IrisPreviewValue", parent=theme.styles["Normal"],
            fontSize=9, leading=12, textColor=dark,
            alignment=TA_LEFT, wordWrap="CJK",
        )
        mismatch_style = ParagraphStyle(
            "IrisPreviewMismatch", parent=value_style,
            textColor=alert, fontName="Helvetica-Bold",
        )

        rows: list = []
        if subject:
            rows.append(["Asunto:", Paragraph(_esc(subject), value_style)])
        if from_:
            rows.append(["De:", Paragraph(_esc(from_), value_style)])
        if to_address:
            rows.append(["Para:", Paragraph(_esc(to_address), value_style)])
        if reply_to:
            # Compara solo la dirección (sin el nombre visible) para no
            # marcar como discrepancia un simple cambio de formato.
            mismatch = bool(from_) and parseaddr(reply_to)[1].lower() != parseaddr(from_)[1].lower()
            if mismatch:
                text = f"{_esc(reply_to)}  [!] distinto del remitente (De:)"
                rows.append(["Responder a:", Paragraph(text, mismatch_style)])
            else:
                rows.append(["Responder a:", Paragraph(_esc(reply_to), value_style)])
        if return_path:
            rows.append(["Return-Path:", Paragraph(_esc(return_path), value_style)])
        if date:
            rows.append(["Fecha:", Paragraph(_esc(date), value_style)])

        preview_table = Table(rows, colWidths=[1.3 * inch, 5.1 * inch])
        preview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), white),
            ("BACKGROUND", (1, 0), (1, -1), colors.white),
            ("TEXTCOLOR", (0, 0), (0, -1), main),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
        ]))
        elements.append(preview_table)

        if self.report.get("unwrappedFromForward"):
            elements.append(Spacer(1, 0.1 * inch))
            wrapper_from = self.report.get("wrapperFrom")
            wrapper_subject = self.report.get("wrapperSubject")
            if self.report.get("winningContext") == "wrapper":
                note = "Este análisis corresponde al envoltorio del reenvío"
            else:
                note = "Este análisis corresponde al correo original reenviado"
            if wrapper_from:
                note += f" por {_esc(wrapper_from)}"
            if wrapper_subject:
                note += f" (asunto del reenvío: «{_esc(wrapper_subject)}»)"
            note += "."
            winning_reason = self.report.get("winningReason")
            if winning_reason:
                note += f" {_esc(winning_reason)}"
            secondary = self.report.get("secondaryContext")
            if secondary:
                note += (
                    f" El otro mensaje ({'envoltorio' if secondary.get('contextType') == 'wrapper' else 'original'})"
                    f" obtuvo {_esc(secondary.get('verdict'))} con {_esc(secondary.get('totalScore'))} puntos."
                )
            elements.append(Paragraph(note, theme.body))

        elements.append(Spacer(1, 0.22 * inch))

    _CONFIDENCE_LABELS = {"high": "Alta", "medium": "Media", "low": "Baja"}

    def append_confidence(self, elements: list, theme: IrisReportTheme) -> None:
        """Confianza y cobertura del veredicto, justo debajo de él.

        Usa la misma semántica que la API y la UI: una confianza ordinal
        (alta/media/baja), nunca un porcentaje, con sus motivos, y si se
        inspeccionó el mensaje completo o solo sus cabeceras. No aparece en
        informes de análisis anteriores a que se calculara.

        Args:
            elements: Lista de flowables del documento, a la que se añade.
            theme: Tema del informe (estilos y paleta).
        """
        label = self._CONFIDENCE_LABELS.get(self.report.get("confidence") or "")
        if label is None:
            return

        coverage = self.report.get("coverage") or {}
        if coverage.get("mode") == "headers_only":
            uncovered = coverage.get("uncoveredRules") or []
            coverage_text = (
                "solo cabeceras. Estas reglas no tuvieron cuerpo, enlaces ni "
                f"adjuntos que inspeccionar: {_esc(', '.join(uncovered)) or 'ninguna'}."
            )
        else:
            coverage_text = "mensaje completo."

        text = (
            f"<b>Confianza del análisis: {label}.</b> Es una escala ordinal, no "
            "una probabilidad: el score mide riesgo y no está calibrado "
            f"estadísticamente.<br/><b>Cobertura:</b> {coverage_text}"
        )
        for reason in self.report.get("uncertaintyReasons") or []:
            text += f"<br/>• {_esc(reason)}"

        card = Table([[Paragraph(text, theme.body)]], colWidths=[6.4 * inch])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(theme.palette["white"])),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(theme.palette["light"])),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(card)
        elements.append(Spacer(1, 0.22 * inch))

    def append_quality_warning(self, elements: list, theme: IrisReportTheme) -> None:
        """Aviso de análisis degradado, justo debajo del veredicto.

        Va aquí y no entre las señales de más abajo porque contradice
        parcialmente lo que el lector acaba de leer: el veredicto grande de la
        portada se calculó sin una parte del examen, y quien imprima el
        informe tiene que verlo antes de actuar sobre él.
        """
        failed_rules = self.report.get("failedRules") or []
        if self.report.get("analysisQuality") != "degraded" and not failed_rules:
            return

        names = ", ".join(rule.get("name", "?") for rule in failed_rules) or "desconocidas"
        warning_style = ParagraphStyle(
            "IrisQualityWarning", parent=theme.body,
            textColor=colors.HexColor("#7a4100"),
        )
        text = (
            f"<b>Análisis incompleto.</b> No se pudieron ejecutar estas reglas: "
            f"{_esc(names)}. La parte del mensaje que les correspondía no se ha "
            "inspeccionado, así que este informe describe menos de lo que "
            "describiría un análisis completo."
        )

        card = Table([[Paragraph(text, warning_style)]], colWidths=[6.4 * inch])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF4E5")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#f57c00")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FFD8A8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(card)
        elements.append(Spacer(1, 0.22 * inch))

    def append_gate_reasons(self, elements: list, theme: IrisReportTheme) -> None:
        """Señales de alta confianza que fijaron el veredicto.

        Solo aparece cuando algún gate se disparó — explica el "por qué"
        del veredicto más allá de la puntuación numérica.
        """
        reasons = self.report.get("gateReasons") or []
        if not reasons:
            return

        verdict = self.report.get("verdict") or "Suspicious"
        risk_color = _VERDICT_COLORS.get(verdict, colors.HexColor("#757575"))

        elements.extend(theme.section_header("Por qué este veredicto", "SEÑALES CLAVE"))
        elements.append(Spacer(1, 0.1 * inch))

        reason_style = ParagraphStyle(
            "IrisGateReason", parent=theme.body,
            textColor=colors.HexColor(theme.palette["black"]),
            spaceAfter=4,
        )
        reason_paras = [Paragraph(f"•  {_esc(reason)}", reason_style) for reason in reasons]

        card = Table([[reason_paras]], colWidths=[6.4 * inch])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, risk_color),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E0E0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(card)
        elements.append(Spacer(1, 0.22 * inch))

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
        for rule in rules:
            score = rule.get("score", 0)
            sign = "+" if score > 0 else ""
            rule_data.append([
                Paragraph(_esc(rule.get("ruleName", "")), theme.cell_left),
                Paragraph(_esc(rule.get("category") or "-"), theme.cell_left),
                Paragraph(f"{sign}{score}", theme.cell_center),
                Paragraph(_esc(rule.get("verdict", "")), theme.cell_center),
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
        flagged = [rule for rule in rules if rule.get("recommendation")]
        if flagged:
            elements.append(Paragraph("Detalle de hallazgos", theme.subtitle))
            elements.append(Spacer(1, 0.08 * inch))
            for flagged_rule in flagged:
                text = f"<b>{_esc(flagged_rule.get('ruleName'))}:</b> {_esc(flagged_rule.get('recommendation'))}"
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
        suspicious = [transition for transition in transitions if transition.get("suspicious")]
        if suspicious:
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph("Transiciones sospechosas detectadas", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            for suspicious_transition in suspicious:
                reasons = _esc(", ".join(suspicious_transition.get("reasons") or []))
                elements.append(Paragraph(
                    f"Salto {_esc(suspicious_transition.get('from'))} → "
                    f"{_esc(suspicious_transition.get('to'))}: {reasons}", theme.body
                ))

    def append_raw_headers(self, elements: list, theme: IrisReportTheme) -> None:
        """Vuelca el raw completo del correo -- la única vista de Iris que
        sale del panel autenticado tal cual una vez descargado el PDF, así
        que es la que se redacta (``iris.redactPiiInReports``): no se
        toca el remitente/destinatario/responder-a/return-path, que son la
        evidencia del informe (ya mostrados en "Vista Previa del Correo"),
        pero sí cualquier otra dirección, teléfono o número con forma de
        tarjeta que aparezca en cabeceras de reenvío, listas de distribución
        o el cuerpo (en ``full_message_mode``)."""
        raw = self.report.get("rawHeaders")
        if not raw:
            return
        elements.append(PageBreak())
        elements.extend(theme.section_header("Cabeceras Originales", "EVIDENCIA RAW"))
        elements.append(Spacer(1, 0.1 * inch))

        body = raw
        if CR.iris_config().redact_pii_in_reports:
            headers = parse_raw_headers(raw)
            surfaced_addresses = [
                parseaddr(headers.get(name, ""))[1]
                for name in ("from", "to", "reply-to", "return-path")
            ]
            body = redact_pii(raw, keep_emails=surfaced_addresses)

        # Escape so reportlab's mini-markup doesn't choke on raw header text.
        escaped = (
            body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
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

    def _output_path(self) -> str:
        """Ruta del PDF, única por **documento** y no por análisis.

        El modelo permite N ``IrisDocument`` por análisis, pero el nombre solo
        dependía del ``analysis_id``, así que todos escribían el mismo fichero:
        dos generaciones a la vez se pisaban, y borrar un documento destruía el
        PDF del otro (``delete_document_with_file`` borra por ``filename``, que
        era el mismo para ambos).

        Cuando no hay ``document_id`` —ningún camino de la aplicación llega
        así hoy; queda para que la clase siga siendo usable a pelo— se cae a un
        sufijo aleatorio, que no colisiona aunque tampoco sea reproducible.
        """
        analysis_id = self.report.get("analysisId")
        suffix = self.document_id if self.document_id is not None else uuid.uuid4().hex
        return os.path.join(self.directory, f"{analysis_id}_{suffix}_Iris.pdf")

    def print_pdf(self) -> str:
        """Generate the complete PDF report and return its file path.

        Se escribe en un temporal del mismo directorio y se mueve con
        ``os.replace()``, que es atómico dentro de un mismo sistema de
        ficheros. Sin eso, un lector que descargue el informe mientras se
        regenera recibe un PDF a medio escribir: ``document.status`` pasa a
        ``done`` una sola vez, pero el fichero al que apunta se reescribe en
        sitio en cada regeneración.
        """
        os.makedirs(self.directory, exist_ok=True)

        filename = self._output_path()
        temporary = f"{filename}.{uuid.uuid4().hex}.tmp"

        document = SimpleDocTemplate(
            temporary, pagesize=A4,
            rightMargin=36, leftMargin=36, topMargin=60, bottomMargin=40,
        )

        base_styles = getSampleStyleSheet()
        theme = IrisReportTheme(base_styles, PALETTE)
        elements: list = []

        self.append_cover_page(elements, theme)
        self.append_verdict_hero(elements, theme)
        self.append_confidence(elements, theme)
        self.append_quality_warning(elements, theme)
        self.append_email_preview(elements, theme)
        self.append_gate_reasons(elements, theme)
        self.append_rules(elements, theme)
        self.append_recommendations(elements, theme)
        self.append_path(elements, theme)
        self.append_raw_headers(elements, theme)
        self.append_consent(elements, theme)
        self.append_footer(elements, theme)

        self._set_pdf_metadata(document)
        try:
            document.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)
            os.replace(temporary, filename)
        except Exception:
            # Un temporal huérfano no lo limpia nadie: el nombre lleva un UUID,
            # así que ni siquiera lo pisaría el siguiente intento.
            if os.path.exists(temporary):
                try:
                    os.remove(temporary)
                except OSError:
                    logger.warning("No se pudo borrar el temporal %s", temporary)
            raise

        return filename
