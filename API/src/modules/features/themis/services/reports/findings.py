"""
``FindingsPrintingStrategy``: base compartida por los tipos de escaneo que
viven enteramente en ``Finding`` (Lybra y Nuclei).
"""

import logging
from typing import Dict, Optional
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, Paragraph, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from src.modules.shared.report_theme import ColorType, safe_markup
from ...lybra.grouping import build_service_rollup
from ..cve_context import enrich_with_cve_context
from .base import PrintingStrategy
from .outline import OutlineEntry

logger = logging.getLogger(__name__)


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
            "exploit_maturity": row.exploit_maturity, "state": row.state,
            "source": row.source, "state": row.state, "cpe_resolved": row.cpe_resolved,
            "required_os": row.required_os,
        } for row in rows]
        for finding in findings:
            finding["priority"] = score_finding(finding, exposure)
        enrich_with_cve_context(findings)

        self._append_finding_header(theme, elements, findings, exposure)

        if findings:
            self._append_finding_summary(theme, elements, findings)
        self._append_cpe_coverage_note(theme, elements, findings)

        self._append_findings_section(theme, elements, findings)

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
        target_table = theme.kv_table(target_info, col_widths=[2 * inch, 4 * inch])
        elements.append(target_table)
        elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        confirmed_count = sum(1 for finding in findings if finding["confirmed"]
                              and finding.get("state") != "false_positive")
        refuted_count = sum(1 for finding in findings
                            if finding.get("state") == "false_positive")

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de hallazgos:", str(len(findings))],
            ["Confirmados activamente:", str(confirmed_count)],
            ["Base de conocimiento:", self._knowledge_base_line()],
        ]
        if refuted_count:
            # Se dice, no se esconde: que el informe no los cuente como riesgo
            # es correcto, pero callar cuántos hay ocultaría que alguien
            # intervino sobre lo que el motor detectó.
            scan_info.append(["Desmentidos por el usuario:", str(refuted_count)])
        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

    @staticmethod
    def _knowledge_base_line() -> str:
        """Contra qué catálogo se resolvieron estos hallazgos, y de cuándo es.

        Un informe que dice "sincronizada el 29/08/2026" es honesto; uno que
        calla hace una afirmación sin fecha, y la detección por versión —que es
        la que produce la mayoría de los hallazgos con CVE— vale exactamente lo
        que valga la frescura de ese espejo.

        Si alguna fuente está vieja, el informe lo dice: es preferible a que el
        lector suponga que el catálogo estaba al día. Best-effort — un fallo
        consultando el estado no puede impedir que se emita el informe.
        """
        from src.modules.features.themis.managers.kb_sync import KbSyncManager

        try:
            status = KbSyncManager().status()
        except Exception:  # noqa: BLE001
            logger.exception("No se pudo leer el estado de la base de conocimiento")
            return "No disponible"

        parts = []
        for entry in status["sources"]:
            when = (entry["lastSuccessAt"] or "")[:10] or "nunca"
            parts.append(f"{entry['source'].upper()} {when}"
                         + (" (desactualizada)" if entry["isStale"] else ""))
        return " · ".join(parts) if parts else "Sin fuentes configuradas"

    #: Cómo se lee cada nivel de ``Finding.exploit_maturity`` en el informe.
    #: ``none`` no aparece: decir "no consta exploit" en cada ficha sería ruido
    #: en la inmensa mayoría de los hallazgos, y su ausencia ya lo dice.
    _EXPLOIT_MATURITY_LABEL = {
        "poc": "Existe una prueba de concepto pública",
        "functional": "Existe un exploit funcional público",
        "weaponized": "Existe un exploit integrado en herramientas de ataque",
        "in_the_wild": "Se explota activamente en el mundo real",
    }

    def _append_finding_summary(self, theme: "ReportTheme", elements: list, findings: list) -> None:
        """Tabla resumen: cantidad de hallazgos por prioridad."""
        palette = self.color_palette
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Resumen por prioridad", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        counts: Dict[str, int] = {}
        for finding in findings:
            if finding.get("state") == "false_positive":
                # El usuario ha desmentido este hallazgo: no es un riesgo, y un
                # resumen que lo cuente afirma una postura de seguridad peor
                # que la real (L35).
                continue
            counts[finding["priority"]] = counts.get(finding["priority"], 0) + 1

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

    # Las dos clases de trabajo en que se parten los grupos, en el orden en
    # que se imprimen. Son los mismos títulos que usa la interfaz web
    # (`LybraResults.vue`), a propósito: quien mira la pantalla y quien lee el
    # PDF tienen que estar hablando del mismo sitio.
    _GROUP_SECTIONS = (
        ("prod", "Productos afectados", True),
        ("conf", "Configuración y exposición", False),
    )

    def _outline_key(self, suffix: str) -> str:
        """Clave de un marcador, única dentro del documento.

        Lleva el escaneo delante porque un mismo informe podría llegar a
        arrastrar bloques de más de un origen; sin eso, dos grupos homónimos
        anclarían al mismo destino y el índice mandaría al sitio equivocado.
        """
        return f"scan{getattr(self.scan, 'id', 0)}-{suffix}"

    def _append_findings_section(self, theme: "ReportTheme", elements: list, findings: list) -> None:
        """El bloque «Hallazgos» completo: su rama del índice, su título y su cuerpo.

        Los tres niveles del árbol de marcadores —«Hallazgos», la sección y el
        grupo— los emite este método y no dos repartidos, porque ReportLab
        rechaza un nivel que salte más de uno respecto al anterior: si la raíz
        la pusiera el llamante, el subárbol sólo sería válido cuando alguien se
        acordara de emitirla antes, y el precio de olvidarlo no es un índice
        raro sino un informe que no se genera.
        """
        elements.append(OutlineEntry("Hallazgos", key=self._outline_key("findings"), level=0))
        elements.append(Paragraph("Hallazgos", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        if not findings:
            elements.append(Paragraph(
                "El motor no detectó ningún hallazgo para este objetivo.", theme.info))
            return

        self._append_grouped_findings(theme, elements, findings)

    def _append_grouped_findings(self, theme: "ReportTheme", elements: list, findings: list) -> None:
        """Imprimir los hallazgos por unidad remediable, no en lista plana.

        Un escaneo contra un host con dos productos desactualizados puede dar
        150 hallazgos, y ciento cincuenta fichas seguidas confunden la cantidad
        de *evidencia* con la cantidad de *trabajo*: son dos acciones —subir
        dos productos de versión— más un puñado de cosas de configuración que
        se arreglan de otra manera.

        La agrupación no se calcula aquí: `build_service_rollup` ya existía en
        la capa pura y la interfaz web ya la pintaba. Lo llamativo es que el
        informe la tenía delante —la usa desde hace tiempo para armar el
        prompt del análisis de IA— y aun así imprimía plano. El resultado era
        un informe donde la IA recomendaba «actualiza Apache y cierras 12
        CVEs» y tres páginas más abajo esos 12 CVEs aparecían como fichas
        inconexas.
        """
        sections = self._split_into_sections(build_service_rollup(findings))

        self._append_group_index(theme, elements, sections)

        position = 0
        for section_key, section_title, groups in sections:
            elements.append(CondPageBreak(2 * inch))
            elements.append(OutlineEntry(
                section_title, key=self._outline_key(f"section-{section_key}"), level=1))
            elements.append(Paragraph(section_title, theme.subtitle))
            elements.append(Spacer(1, 0.12 * inch))

            for group in groups:
                position += 1
                elements.append(OutlineEntry(
                    f"{group.label} ({group.total_findings})",
                    key=self._outline_key(f"group-{position}"),
                    level=2,
                ))
                self._append_group_header(theme, elements, group, position)

                for idx, finding in enumerate(self._sorted_findings(group.findings), start=1):
                    self._append_finding_card(theme, elements, finding, f"{position}.{idx}")

    def _split_into_sections(self, groups: list) -> list:
        """Repartir los grupos entre producto y configuración, sin los vacíos.

        Un objetivo puede no tener ningún producto identificado (o ninguna
        configuración señalada), y en ese caso imprimir el título de una
        sección para no colgarle nada debajo se lee como si faltara algo.

        Returns:
            Tuplas ``(clave, título, grupos)`` de las secciones con contenido.
        """
        sections = []
        for key, title, wants_products in self._GROUP_SECTIONS:
            matching = [group for group in groups if group.is_product is wants_products]
            if matching:
                sections.append((key, title, matching))
        return sections

    def _sorted_findings(self, findings: list) -> list:
        """Priority first (the contextual CVSS+EPSS+KEV+exposure synthesis that
        is Lybra's whole value proposition — see roadmap §1); raw CVSS
        only breaks ties *within* the same priority band, confirmed findings
        before hypotheses. Es el mismo orden de antes, aplicado ahora dentro de
        cada grupo en vez de sobre la lista entera."""
        return sorted(
            findings,
            key=lambda finding: (
                self._PRIORITY_ORDER.get(finding["priority"], 5),
                not finding["confirmed"],
                -(finding["cvss_score"] or 0),
            ),
        )

    def _append_group_index(self, theme: "ReportTheme", elements: list, sections: list) -> None:
        """Tabla-índice: todo el trabajo pendiente junto, antes del detalle.

        Es la mitad de la respuesta a «que se pueda plegar para leer mejor»
        que sí cabe dentro de la página (la otra mitad es el árbol de
        marcadores del visor). Quien recibe el informe ve de un vistazo
        cuántas acciones hay y cuáles son, y sólo baja al detalle de las que
        le interesan.
        """
        palette = self.color_palette
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Índice de grupos", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        cell = ParagraphStyle("GroupIndexCell", parent=theme.body, fontSize=8,
                              leading=10, alignment=TA_LEFT, spaceAfter=0)
        data = [["#", "Unidad a remediar", "Prioridad", "Hallazgos", "CVEs", "Acción"]]
        position = 0
        for _, _, groups in sections:
            for group in groups:
                position += 1
                action = (f"Actualizar a {group.fixed_version} o superior"
                          if group.fixed_version else "Revisar configuración")
                data.append([
                    str(position),
                    Paragraph(safe_markup(group.label), cell),
                    self._PRIORITY_LABEL.get(group.worst_priority, group.worst_priority),
                    str(group.total_findings),
                    str(group.total_cves),
                    Paragraph(safe_markup(action), cell),
                ])

        table = Table(data, colWidths=[0.3 * inch, 2.1 * inch, 0.75 * inch,
                                       0.75 * inch, 0.5 * inch, 1.6 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(palette[ColorType.SECONDARY])),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (4, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.4, dark),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.25 * inch))

    def _append_group_header(self, theme: "ReportTheme", elements: list, group, position: int) -> None:
        """Cabecera de un grupo: qué es, cuánto pesa y qué hay que hacer con él.

        La línea que de verdad importa es `fixed_version`: es la cota más alta
        del grupo, así que actualizar hasta ahí cierra también todas las
        inferiores — un solo movimiento para todos los hallazgos de debajo.
        """
        palette = self.color_palette
        dark = colors.HexColor(palette[ColorType.DARK])
        light = colors.HexColor(palette[ColorType.LIGHT])

        elements.append(CondPageBreak(2.2 * inch))

        where = f"{group.service or 'svc'}:{group.port}" if group.port else "—"
        title = Paragraph(
            f"Grupo #{position} · {safe_markup(group.label)}",
            ParagraphStyle("GroupTitle", parent=theme.styles["Normal"], fontName="Helvetica-Bold",
                           fontSize=9.5, textColor=dark, alignment=TA_LEFT),
        )
        heading = Table([[title, where]], colWidths=[4.6 * inch, 1.4 * inch])
        heading.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (1, 0), (1, -1), 8.5),
            ("TEXTCOLOR", (1, 0), (1, -1), dark),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.6, dark),
        ]))
        elements.append(heading)

        confirmed_plural = "" if group.confirmed_count == 1 else "s"
        rows = [
            ["Prioridad del grupo:",
             self._PRIORITY_LABEL.get(group.worst_priority, group.worst_priority)],
            ["Hallazgos:",
             f"{group.total_findings} ({group.confirmed_count} comprobado{confirmed_plural})"],
        ]
        if group.total_cves:
            rows.append(["CVEs distintos:", str(group.total_cves)])
        if group.kev_cve_ids:
            rows.append(["En CISA KEV:",
                         f"{len(group.kev_cve_ids)} — explotación activa confirmada"])
        if group.max_cvss is not None:
            rows.append(["CVSS máximo:", str(group.max_cvss)])
        if group.max_epss is not None:
            rows.append(["EPSS máximo (30 días):", f"{group.max_epss * 100:.1f}%"])
        if group.fixed_version:
            rows.append(["Cierra el grupo:",
                         f"actualizar a {group.fixed_version} o superior"])

        summary = Table(rows, colWidths=[1.7 * inch, 4.3 * inch])
        summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(palette[ColorType.BLACK])),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ]))
        elements.append(summary)
        elements.append(Spacer(1, 0.12 * inch))

    def _append_finding_card(self, theme: "ReportTheme", elements: list, finding: dict, label: str) -> None:
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
            left_text=f"Hallazgo #{label}: {self._PRIORITY_LABEL.get(prio, prio)}",
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
        # La tercera dimensión de explotabilidad, junto a KEV y EPSS: si existe
        # algo público que demuestre el fallo. Es lo que separa una urgencia de
        # un deber cuando el lector decide qué arregla el lunes.
        maturity_label = self._EXPLOIT_MATURITY_LABEL.get(finding.get("exploit_maturity"))
        if maturity_label:
            details.append(["Explotación:", maturity_label])
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

