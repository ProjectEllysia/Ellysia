"""
aegis_exporters.py
──────────────────
Exportadores de documentos Aegis a Markdown y JSON.

Clases públicas:
    ExportData      — DTO de entrada para todos los exportadores
    ExportResult    — resultado inmutable de una exportación
    MarkdownExporter
    JsonExporter
    get_exporter_for_format  — factory por formato

El protocolo AegisData se conserva para compatibilidad con código externo
que construya objetos ad-hoc, pero ExportData es la forma canónica de
alimentar los exportadores desde managers y endpoints.
"""

from __future__ import annotations

import html
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.modules.shared import utcnow_naive, isoformat_utc
from src.modules.features.aegis.exceptions import (
    ExporterFormatError,
    ExporterConfigurationError,
)


def get_exporter_for_format(format_type: ExportFormat | str) -> AegisExporter:
    """Devuelve el exportador adecuado para el formato solicitado."""
    if isinstance(format_type, str):
        format_type = ExportFormat(format_type.lower())

    exporters: dict[ExportFormat, type[AegisExporter]] = {
        ExportFormat.MARKDOWN: MarkdownExporter,
        ExportFormat.JSON:     JsonExporter,
        ExportFormat.HTML:     HTMLExporter,
    }

    exporter_class = exporters.get(format_type)
    if not exporter_class:
        raise ExporterFormatError(format_type.value if hasattr(format_type, 'value') else format_type)

    return exporter_class()


class ExportFormat(str, Enum):
    JSON     = "json"
    MARKDOWN = "md"
    PDF      = "pdf"
    HTML     = "html"
    DOCX     = "docx"


@dataclass(frozen=True)
class ExportResult:
    """Resultado inmutable de una operación de exportación."""

    content:      bytes | str
    filename:     str
    mimetype:     str
    format:       ExportFormat
    size_bytes:   int
    generated_at: datetime

    def to_response_dict(self) -> dict[str, Any]:
        """Metadatos serializables para respuestas de API."""
        return {
            "filename":    self.filename,
            "format":      self.format.value,
            "mimetype":    self.mimetype,
            "sizeBytes":   self.size_bytes,
            "generatedAt": isoformat_utc(self.generated_at),
        }


@dataclass
class ExportData:
    """
    DTO canónico de entrada para los exportadores.
    """
    topic_id:      int   = 0
    topic_title:   str   = ""
    subtitle:      str   = ""
    company:       str   = "Empresa"
    language:      str   = "es"
    generated_at:  str   = ""
    subtitle:      str   = ""
    intro:         str   = ""
    tips:          list[dict] = field(default_factory=list)
    closing:       str   = ""
    contact_email: str   = ""
    alerts:        list[dict] = field(default_factory=list)
    document_id:   int   = 0

    @classmethod
    def from_document_dict(cls, document: dict, doc_id: int | None = None) -> "ExportData":
        """
        Construye un ExportData a partir del dict devuelto por
        AegisManager.get_document(). Centraliza el mapeo de claves
        para que endpoints y managers no lo repitan.
        """
        pill = document.get("pill") or {}
        return cls(
            topic_id      = document.get("topicId", 0),
            topic_title   = document.get("title", "Sin título"),
            company       = pill.get("company") or document.get("company", "Empresa"),
            language      = pill.get("language", "es"),
            generated_at  = document.get("generatedAt", ""),
            subtitle      = pill.get("subtitle", ""),
            intro         = pill.get("intro", ""),
            tips          = pill.get("tips", []),
            closing       = pill.get("closing", ""),
            contact_email = pill.get("contactEmail", ""),
            alerts        = document.get("alerts", []),
            document_id   = doc_id if doc_id is not None else document.get("id", 0),
        )


@dataclass
class MarkdownTemplate:
    """Configuración de plantilla para el exportador Markdown."""

    include_toc:            bool = False
    include_metadata_block: bool = True
    alert_section_title:    str  = "## 🔴 Alertas de Seguridad Recientes"
    tip_emoji:              str  = "💡"
    severity_emojis:        dict[str, str] = field(default_factory=lambda: {
        "crítica":    "🔴",
        "alta":       "🟠",
        "media":      "🟡",
        "baja":       "🟢",
        "informativa": "🔵",
    })


class AegisExporter(ABC):
    """
    Clase base para exportadores.

    Implementa el patrón Strategy: cada subclase define su formato de salida
    sin cambiar la interfaz que usan managers y endpoints.
    """

    format:             ExportFormat
    extension:          str
    mimetype:           str
    supports_streaming: bool = False

    def __init__(self) -> None:
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        required = ["format", "extension", "mimetype"]
        missing = [required_field for required_field in required if not getattr(self, required_field, None)]
        if missing:
            raise ExporterConfigurationError(missing)

    @abstractmethod
    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        raise NotImplementedError("Subclass must implement export method")

    def generate_filename(self, data: ExportData, suffix: str = "") -> str:
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name   = "".join(character for character in data.company if character.isalnum() or character in "-_").lower()[:20]
        base        = f"aegis_{safe_name}_{data.topic_id}_{timestamp}"
        if suffix:
            base += f"_{suffix}"
        return f"{base}.{self.extension}"

    def _sanitize(self, text: str | None, max_length: int = 10_000) -> str:
        if not text:
            return ""
        text = str(text).strip()
        if len(text) > max_length:
            text = text[:max_length] + "\n\n[Contenido truncado por longitud máxima]"
        return text

    def _format_datetime(self, iso_string: str) -> str:
        try:
            parsed_datetime = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            return parsed_datetime.strftime("%d de %B de %Y, %H:%M")
        except Exception:
            return iso_string


class MarkdownExporter(AegisExporter):

    format             = ExportFormat.MARKDOWN
    extension          = "md"
    mimetype           = "text/markdown; charset=utf-8"
    supports_streaming = True

    def __init__(self, template: MarkdownTemplate | None = None) -> None:
        super().__init__()
        self.template = template or MarkdownTemplate()

    # ── Punto de entrada ──────────────────────────────────────────────────────

    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        content       = self._generate_content(data)
        content_bytes = content.encode("utf-8")
        filename      = output_path.with_suffix(f".{self.extension}").name if output_path else self.generate_filename(data)

        if output_path:
            output_path.with_suffix(f".{self.extension}").write_text(content, encoding="utf-8")

        return ExportResult(
            content      = content_bytes,
            filename     = filename,
            mimetype     = self.mimetype,
            format       = self.format,
            size_bytes   = len(content_bytes),
            generated_at = utcnow_naive(),
        )

    # ── Generación por secciones ──────────────────────────────────────────────

    def _generate_content(self, data: ExportData) -> str:
        sections: list[list[str]] = []

        if self.template.include_metadata_block:
            sections.append(self._frontmatter(data))

        sections.append(self._header(data))

        if data.intro:
            sections.append(self._intro(data))

        sections.append(self._tips(data))

        if data.alerts:
            sections.append(self._alerts(data))

        sections.append(self._closing(data))
        sections.append(self._footer(data))

        return "\n".join(line for section in sections for line in section)

    def _frontmatter(self, data: ExportData) -> list[str]:
        return [
            "---",
            f"title: '{self._sanitize(data.subtitle)}'",
            f"company: '{self._sanitize(data.company)}'",
            f"topic: '{self._sanitize(data.topic_title)}'",
            f"language: {data.language}",
            f"generated: '{data.generated_at}'",
            f"document_id: {data.document_id}",
            "---",
            "",
        ]

    def _header(self, data: ExportData) -> list[str]:
        return [
            f"# {self._sanitize(data.subtitle)}",
            "",
            "> **Píldora de Concienciación en Ciberseguridad**",
            f"> Empresa: *{self._sanitize(data.company)}*",
            f"> Fecha de generación: {self._format_datetime(data.generated_at)}",
            "",
            "---",
            "",
        ]

    def _intro(self, data: ExportData) -> list[str]:
        paragraphs = [paragraph.strip() for paragraph in self._sanitize(data.intro).split("\n\n") if paragraph.strip()]
        lines: list[str] = []
        for paragraph in paragraphs:
            lines.append(paragraph)
            lines.append("")
        return lines

    def _tips(self, data: ExportData) -> list[str]:
        lines = ["## Consejos Prácticos", ""]

        for i, tip in enumerate(data.tips, 1):
            headline = self._sanitize(tip.get("headline", f"Consejo {i}"))
            body     = self._sanitize(tip.get("body", ""))

            lines.append(f"### {self.template.tip_emoji} {headline}")
            lines.append("")

            for paragraph in body.split("\n\n"):
                if paragraph.strip():
                    lines.append(paragraph.strip())
                    lines.append("")

            links = tip.get("links") or []
            if links:
                lines.append("**Recursos relacionados:**")
                for link in links:
                    text = self._sanitize(link.get("text", "Enlace"))
                    url  = link.get("url", "#")
                    lines.append(f"- [{text}]({url})")
                lines.append("")

        return lines

    def _alerts(self, data: ExportData) -> list[str]:
        if not self.template.alert_section_title:
            return []

        lines = [self.template.alert_section_title, ""]

        for alert in data.alerts:
            title       = self._sanitize(alert.get("title", "Alerta"))
            description = self._sanitize(alert.get("description", ""))
            source      = alert.get("sourceLabel", "Fuente desconocida")
            published   = alert.get("published", "Fecha desconocida")
            severity    = alert.get("severity", "")
            brands      = alert.get("affectedBrands", [])
            url         = alert.get("url", "#")

            severity_emoji = self.template.severity_emojis.get(severity.lower(), "⚪")

            lines.append(f"### {severity_emoji} {title}")
            lines.append("")
            lines.append(f"- **Fuente:** {source}")
            lines.append(f"- **Publicado:** {published}")
            if severity:
                lines.append(f"- **Severidad:** {severity.upper()}")
            if brands:
                lines.append(f"- **Tecnologías afectadas:** {', '.join(brands)}")
            lines.append("")

            if description:
                lines.append(description)
                lines.append("")

            lines.append(f"[Ver detalle completo →]({url})")
            lines.append("")
            lines.append("---")
            lines.append("")

        return lines

    def _closing(self, data: ExportData) -> list[str]:
        if not data.closing:
            return []
        return ["## Conclusión", "", self._sanitize(data.closing), ""]

    def _footer(self, data: ExportData) -> list[str]:
        lines = [
            "---",
            "",
            "*Este documento fue generado automáticamente por el sistema Aegis "
            "de concienciación en ciberseguridad.*",
        ]
        contact_email = data.contact_email
        if contact_email:
            contact_info = "el responsable de Ellysia en tu empresa." if (contact_email == "seguridad@empresa.com") else contact_email
            lines.append(f"*Para más información, contacta con {contact_info}*")
        lines.append("")
        lines.append(f"*ID del documento: {data.document_id}*")
        return lines


class HTMLExporter(AegisExporter):
    """Exportador de documentos Aegis a HTML."""

    format             = ExportFormat.HTML
    extension          = "html"
    mimetype           = "text/html; charset=utf-8"
    supports_streaming = False

    def __init__(self) -> None:
        super().__init__()

    def _esc(self, text: str | None) -> str:
        """Sanitiza y escapa texto para inserción segura en HTML.

        ``_sanitize`` (heredado, compartido con MarkdownExporter) solo recorta
        longitud — no protege de HTML/script embebido. Este documento se
        genera con contenido de un LLM y de feeds externos (INCIBE/CIRCL), así
        que todo texto insertado en el HTML pasa por aquí antes de usarse.
        """
        return html.escape(self._sanitize(text))

    def _safe_url(self, url: str | None, fallback: str = "#") -> str:
        """Valida el esquema de una URL (solo http/https) y la escapa para
        un atributo href. Cualquier otro esquema (``javascript:``, ``data:``,
        ``vbscript:``...) cae al fallback en vez de insertarse."""
        if not url:
            return fallback
        url = str(url).strip()
        if urlparse(url).scheme.lower() not in ("http", "https"):
            return fallback
        return html.escape(url, quote=True)

    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        content       = self._generate_content(data)
        content_bytes = content.encode("utf-8")
        filename      = output_path.with_suffix(f".{self.extension}").name if output_path else self.generate_filename(data)

        if output_path:
            output_path.with_suffix(f".{self.extension}").write_text(content, encoding="utf-8")

        return ExportResult(
            content      = content_bytes,
            filename     = filename,
            mimetype     = self.mimetype,
            format       = self.format,
            size_bytes   = len(content_bytes),
            generated_at = utcnow_naive(),
        )

    def _generate_content(self, data: ExportData) -> str:
        return "\n".join([
            self._html_header(data),
            self._html_body(data),
            self._html_footer(data),
        ])

    def _html_header(self, data: ExportData) -> str:
        return f"""<!DOCTYPE html>
        <html lang="{html.escape(data.language, quote=True)}">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{self._esc(data.subtitle)}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #333; }}
                h1 {{ color: #1a365d; border-bottom: 2px solid #38bdf8; padding-bottom: 10px; }}
                h2 {{ color: #2c5282; margin-top: 30px; }}
                h3 {{ color: #2b6cb0; }}
                .meta {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
                .tip {{ background: #f7fafc; padding: 15px; margin: 15px 0; border-left: 4px solid #38bdf8; }}
                .alert {{ background: #fff5f5; padding: 15px; margin: 15px 0; border-left: 4px solid #f56565; }}
                .alert-high {{ border-left-color: #ed8936; }}
                .alert-medium {{ border-left-color: #ecc94b; }}
                .alert-low {{ border-left-color: #48bb78; }}
                .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 0.85em; color: #718096; }}
                a {{ color: #3182ce; }}
            </style>
        </head>
        <body>"""

    def _html_body(self, data: ExportData) -> str:
        parts = [
            f"<h1>{self._esc(data.subtitle)}</h1>",
            f"<div class='meta'>",
            f"<p><strong>Píldora de Concienciación en Ciberseguridad</strong></p>",
            f"<p>Empresa: {self._esc(data.company)}</p>",
            f"<p>Fecha de generación: {self._format_datetime(data.generated_at)}</p>",
            f"</div>",
        ]
        parts.extend(self._html_intro(data))
        parts.extend(self._html_tips(data))
        parts.extend(self._html_alerts(data))
        parts.extend(self._html_closing(data))
        return "\n".join(parts)

    def _html_intro(self, data: ExportData) -> list[str]:
        parts: list[str] = []
        if data.intro:
            for paragraph in data.intro.split("\n\n"):
                if paragraph.strip():
                    parts.append(f"<p>{self._esc(paragraph.strip())}</p>")
        return parts

    def _html_tips(self, data: ExportData) -> list[str]:
        parts: list[str] = []
        if data.tips:
            parts.append("<h2>Consejos Prácticos</h2>")
            for tip in data.tips:
                headline = self._esc(tip.get("headline", ""))
                body = self._esc(tip.get("body", ""))
                parts.append("<div class='tip'>")
                if headline:
                    parts.append(f"<h3>{headline}</h3>")
                if body:
                    for line in body.split("\n"):
                        if line.strip():
                            parts.append(f"<p>{line.strip()}</p>")
                links = tip.get("links") or []
                if links:
                    parts.append("<p><strong>Recursos relacionados:</strong></p>")
                    for link in links:
                        text = self._esc(link.get("text", "Enlace"))
                        url = self._safe_url(link.get("url"))
                        parts.append(f"<p><a href='{url}'>{text}</a></p>")
                parts.append("</div>")
        return parts

    def _html_alerts(self, data: ExportData) -> list[str]:
        parts: list[str] = []
        if data.alerts:
            parts.append("<h2>Alertas de Seguridad Recientes</h2>")
            for alert in data.alerts:
                title = self._esc(alert.get("title", "Alerta"))
                description = self._esc(alert.get("description", ""))
                source = self._esc(alert.get("sourceLabel", "Fuente desconocida"))
                severity = alert.get("severity", "").lower()

                alert_class = "alert"
                if severity in ["alta", "high"]:
                    alert_class += " alert-high"
                elif severity in ["media", "medium"]:
                    alert_class += " alert-medium"
                elif severity in ["baja", "low"]:
                    alert_class += " alert-low"

                parts.append(f"<div class='{alert_class}'>")
                parts.append(f"<h3>{title}</h3>")
                parts.append(f"<p><strong>Fuente:</strong> {source}</p>")
                if severity:
                    parts.append(f"<p><strong>Severidad:</strong> {html.escape(severity.upper())}</p>")
                if description:
                    parts.append(f"<p>{description}</p>")
                url = self._safe_url(alert.get("url"))
                parts.append(f"<p><a href='{url}'>Ver detalle completo</a></p>")
                parts.append("</div>")
        return parts

    def _html_closing(self, data: ExportData) -> list[str]:
        parts: list[str] = []
        if data.closing:
            parts.append("<h2>Conclusión</h2>")
            for paragraph in data.closing.split("\n"):
                if paragraph.strip():
                    parts.append(f"<p>{self._esc(paragraph.strip())}</p>")
        return parts

    def _html_footer(self, data: ExportData) -> str:
        footer = [
            "<div class='footer'>",
            "<p>Este documento fue generado automáticamente por el sistema Aegis de concienciación en ciberseguridad.</p>",
        ]

        contact_email = data.contact_email
        if contact_email:
            if contact_email == "seguridad@empresa.com":
                contact_text = "el responsable de Ellysia en tu empresa."
            else:
                contact_text = self._esc(contact_email)
            footer.append(f"<p>Para más información, contacta con {contact_text}</p>")
        footer.append(f"<p>ID del documento: {data.document_id}</p>")
        footer.append("</div>")
        footer.append("</body>")
        footer.append("</html>")
        return "\n".join(footer)


class JsonExporter(AegisExporter):

    format             = ExportFormat.JSON
    extension          = "json"
    mimetype           = "application/json; charset=utf-8"
    supports_streaming = True

    def __init__(self, indent: int = 2, sort_keys: bool = False) -> None:
        super().__init__()
        self.indent    = indent
        self.sort_keys = sort_keys

    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        content_dict  = self._to_dict(data)
        content       = json.dumps(content_dict, ensure_ascii=False, indent=self.indent,
                                   sort_keys=self.sort_keys, default=str)
        content_bytes = content.encode("utf-8")
        filename      = output_path.with_suffix(f".{self.extension}").name if output_path else self.generate_filename(data)

        if output_path:
            output_path.with_suffix(f".{self.extension}").write_bytes(content_bytes)

        return ExportResult(
            content      = content_bytes,
            filename     = filename,
            mimetype     = self.mimetype,
            format       = self.format,
            size_bytes   = len(content_bytes),
            generated_at = utcnow_naive(),
        )

    def _to_dict(self, data: ExportData) -> dict:
        """
        Estructura corregida:
        - topicTitle: Nombre del tema de la base de datos (categoría)
        - title: Título creativo de la píldora (el subtitle generado por IA)
        """
        return {
            "documentId":   data.document_id,
            "topicId":      data.topic_id,
            "topicTitle":   data.topic_title,
            "title":        data.subtitle,
            "company":      data.company,
            "language":     data.language,
            "generatedAt":  data.generated_at,
            "intro":        data.intro,
            "tips":         data.tips,
            "closing":      data.closing,
            "contactEmail": data.contact_email,
            "alerts":       data.alerts,
        }

