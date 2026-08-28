"""
``FindingsPrintingStrategy``: base compartida por los tipos de escaneo que
viven enteramente en ``Finding`` (Lybra y Nuclei).

D5 en ``plans/deuda-tecnica-y-calidad.md``.
"""

from typing import Dict, Optional
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, Paragraph, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from src.modules.shared.report_theme import ColorType, safe_markup
from .base import PrintingStrategy


class FindingsPrintingStrategy(PrintingStrategy):
    """Shared PDF renderer for scan types whose data lives entirely in the
    unified `Finding` table rather than a tool-specific incident/vulnerability
    model — Lybra originally, and now Nuclei (roadmap Fase U1).

    Extracted from what used to be a single, Lybra-only class: Nuclei's JSONL
    output maps onto `Finding` almost as completely as Lybra's own engine does
    (`cve_ids`, `cvss_score`, `check_id` all populated — see
    `lybra/adapters.py::nuclei_result_to_finding`), so its PDF is "the exact
    same card renderer, a different identity and palette" rather than a fourth
    near-duplicate `PrintingStrategy`. A subclass fixes the small set of class
    attributes below; everything else — fetching findings via the repository
    (neither `LybraScan` nor `NucleiScan` carries an ORM relationship to
    `Finding`), scoring, sorting, the summary table, the CVE-context
    enrichment and the per-finding card — is identical.

    Cards are sorted by the same `priority` ladder the web UI uses, computed
    the same way (`score_finding`), so the PDF and the web view never
    disagree.

    Subclass contract (all required, no defaults — each identity must be a
    deliberate choice, not an inherited accident):
        _TOOL:              ``ScanType`` member, for ``CR.get_tool_color_palette``.
        _WRITER_CLASS:       AI writer class to instantiate (both tools reuse
                             ``LybraAIWriter`` today — its logic only reads
                             already-structured findings, nothing Lybra-specific).
        _WRITER_PROMPT_KEY:  Which ``SecOpsConfig.json`` prompt pair to read
                             (``"lybra"`` / ``"nuclei"``).
        _OWN_SOURCE:         This tool's own ``Finding.source`` value, so a
                             finding corroborated by *another* scanner is
                             correctly flagged ("Corroborado por: ...") instead
                             of always comparing against the literal "lybra".
        _HEADER_TITLE:       In-body report title (``theme.title`` paragraph).
        _REPORT_TITLE:       PDF metadata / cover title (``get_report_title``).
        _FILENAME_SUFFIX:    Download filename suffix (``get_filename_suffix``).
        _PICTURE_BASE:       Background image basename, before ``Light``/``Dark.png``.
        _DEFAULT_PALETTE:    Fallback color dict when ``SecOpsConfig.json``
                             carries no ``colorPalette`` for ``_TOOL``.

    Attributes:
        writer: ``_WRITER_CLASS`` instance for AI analysis.
        color_palette: This tool's color palette for the report.
    """

    _PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    _PRIORITY_LABEL = {"CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MEDIUM": "MEDIA", "LOW": "BAJA", "INFO": "INFO"}
    _STATE_LABEL = {"open": "Abierto", "fixed": "Corregido", "regressed": "Regresado", "accepted": "Aceptado"}

    # Bare annotations, no defaults on purpose (see the "Subclass contract"
    # docstring above): each subclass must set every one of these explicitly,
    # the same way ScanManager._MODEL/_RICH_LOADER declare the contract a
    # concrete subclass fills in. Declaring them here (rather than leaving
    # them only in prose) is what lets static analysis resolve `self._TOOL`
    # etc. inside this class's own methods.
    _TOOL: "ScanType"
    _WRITER_CLASS: type
    _WRITER_PROMPT_KEY: str
    _OWN_SOURCE: str
    _HEADER_TITLE: str
    _REPORT_TITLE: str
    _FILENAME_SUFFIX: str
    _PICTURE_BASE: str
    _DEFAULT_PALETTE: Dict[str, str]

    def __init__(self, scan) -> None:
        """Initialize the printing strategy.

        Args:
            scan: LybraScan or NucleiScan instance to generate the report from.
        """
        super().__init__(scan)
        self.writer = self._WRITER_CLASS(prompt_key=self._WRITER_PROMPT_KEY)

        palette_config = CR.get_tool_color_palette(self._TOOL)
        defaults = self._DEFAULT_PALETTE

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", defaults["black"]),
            ColorType.DARK: palette_config.get("dark", defaults["dark"]),
            ColorType.MAIN: palette_config.get("main", defaults["main"]),
            ColorType.SECONDARY: palette_config.get("secondary", defaults["secondary"]),
            ColorType.LIGHT: palette_config.get("light", defaults["light"]),
            ColorType.WHITE: palette_config.get("white", defaults["white"]),
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        from src.modules.infrastructure.session import build_repository
        from src.modules.features.themis import ScanRepository
        from src.modules.features.themis.lybra import score_finding
        # Diferido como el resto de imports de esta función: `managers` importa
        # `services`, así que a nivel de módulo sería un ciclo.
        from src.modules.features.themis.managers import LybraEngineManager

        rows = build_repository(ScanRepository).get_findings_by_scan(self.scan.id)
        exposure = LybraEngineManager.exposure_for(self.scan)

        findings = [{
            "title": row.title, "category": row.category, "port": row.port, "service": row.service,
            "cpe": row.cpe, "cve_ids": row.cve_ids or [], "cvss_score": row.cvss_score,
            "epss_score": row.epss_score, "in_kev": row.in_kev, "qod": row.qod, "confirmed": row.confirmed,
            "source": row.source, "state": row.state, "cpe_resolved": row.cpe_resolved,
            "required_os": row.required_os,
        } for row in rows]
        for f in findings:
            f["priority"] = score_finding(f, exposure)
        self._enrich_with_cve_context(findings)

        self._append_finding_header(theme, elements, findings, exposure)

        if findings:
            self._append_finding_summary(theme, elements, findings)
        self._append_cpe_coverage_note(theme, elements, findings)

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
                self._append_finding_card(theme, elements, f, idx)

        if ai_report:
            # La misma lista que imprime las fichas: ya priorizada por
            # `score_finding` y ya enriquecida con descripción y versión
            # corregida. Así el análisis puede recomendar la versión destino
            # concreta y no puede contradecir al cuerpo del informe.
            self._append_ai_analysis(elements, theme, findings=findings)

        # ponytail: no per-target history chart yet — _append_history_stats'
        # tool_map only knows the Nmap/Nikto scan classes, since it relies on
        # a MetricExtractor for each; a Finding-based one is separate scope
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
        from src.modules.features.themis.repositories import KbRepository
        from src.modules.features.themis.lybra import parse_cpe23

        cve_ids = sorted({cve for finding in findings for cve in (finding.get("cve_ids") or [])})
        if not cve_ids:
            return

        entries = {cve_entry.cve_id: cve_entry for cve_entry in build_repository(KbRepository).get_cves_with_matches(cve_ids)}

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

    def _append_finding_header(self, theme: "ReportTheme", elements: list, findings: list, exposure: str) -> None:
        """Cabecera del informe: título y tablas de objetivo/escaneo."""
        scan = self.scan

        elements.append(Paragraph(self._HEADER_TITLE, theme.title))
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
        confirmed_count = sum(1 for finding in findings if finding["confirmed"])

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de hallazgos:", str(len(findings))],
            ["Confirmados activamente:", str(confirmed_count)],
        ]
        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

    def _append_finding_summary(self, theme: "ReportTheme", elements: list, findings: list) -> None:
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

    def _append_cpe_coverage_note(self, theme: "ReportTheme", elements: list, findings: list) -> None:
        """Advierte cuando el matcher no pudo identificar parte del inventario.

        Un escaneo por inventario (Fase I) emite un hallazgo
        ``installed_package`` por **cada** paquete, se le haya podido resolver
        un CPE o no. Antes de la observabilidad de la Fase I-b
        (``Finding.cpe_resolved``) esto era indistinguible de "comprobado y
        limpio" salvo por una heurística ("cero ``outdated_software``") que
        mezclaba dos causas sin poder nombrar cuál. Ahora el dato es exacto:
        cuántos de los paquetes inventariados no se pudieron ni identificar
        contra el catálogo CPE — la KB local puede seguir sin tener CVEs para
        los que sí se resolvieron, pero eso ya no es ambiguo, es "comprobado y
        sin hallazgos".
        """
        packages = sum(1 for finding in findings if finding["category"] == "installed_package")
        unresolved = sum(
            1 for finding in findings
            if finding["category"] == "installed_package" and finding.get("cpe_resolved") is False
        )
        if not packages or not unresolved:
            return

        note_style = ParagraphStyle(
            "CpeCoverageNote", parent=theme.body, textColor=colors.HexColor("#8a6d1f"),
            backColor=colors.HexColor("#fff8e1"), borderColor=colors.HexColor("#e0c34a"),
            borderWidth=0.75, borderPadding=6, alignment=TA_LEFT,
        )
        elements.append(Paragraph(
            f"<b>Nota de cobertura:</b> {unresolved} de los {packages} paquetes inventariados no se "
            "pudieron identificar contra el catálogo de vulnerabilidades (nombre de producto sin "
            "resolución conocida), así que no se comprobaron. El resto sí se comprobó — su ausencia "
            "de hallazgos es una verificación real, no una laguna.",
            note_style,
        ))
        elements.append(Spacer(1, 0.25 * inch))

    def _append_finding_card(self, theme: "ReportTheme", elements: list, finding: dict, idx: int) -> None:
        """Tarjeta de un hallazgo: cabecera de prioridad, nombre, detalles,
        descripción y referencias (mismo lenguaje visual que Nmap/Nikto:
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

        # Título en banda de color principal, mismo lenguaje visual que las demás tarjetas.
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
        if finding.get("required_os") and not finding.get("confirmed"):
            details.append(["Requiere SO:", f"{finding['required_os']} (no verificado en este escaneo)"])
        if finding.get("fixed_version"):
            details.append(["Corregido en:", f"{finding['fixed_version']} o superior"])
        if finding.get("state") and finding["state"] != "open":
            details.append(["Estado:", self._STATE_LABEL.get(finding["state"], finding["state"])])
        if finding.get("source") and finding["source"] != self._OWN_SOURCE:
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
            para = Paragraph(f"Qué implica: {safe_markup(text)}", desc_style)
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
        return self._FILENAME_SUFFIX

    def get_picture_name(self, dark: bool = False) -> str:
        return self._PICTURE_BASE + ("Dark.png" if dark else "Light.png")

    def get_report_title(self) -> str:
        return self._REPORT_TITLE

