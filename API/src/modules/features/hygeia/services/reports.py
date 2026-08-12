"""
Informe PDF del inventario de activos de Hygeia.

Dibuja, no consulta: recibe los activos ya cargados y devuelve los bytes del
PDF. El manager es quien decide qué activos entran (propios o de toda la
organización) y quien comprueba permisos; aquí solo se pinta lo que llega.

El documento se construye sobre un ``BytesIO``, sin tocar el disco. Es lo que
hace innecesarios un directorio de salida, una entrada en ``DirectoryType`` y
cualquier limpieza posterior: el PDF se genera, se envía y desaparece. Si algún
día hiciera falta archivarlo, ese es el momento de darle una fila en
``Document``, no antes.

Estructura:
    1. Portada — ámbito, autor, fecha y recuento por estado.
    2. Registro de activos — una fila por activo.
    3. Anexo de software — opcional, una tabla por activo, al final.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Dict, Optional, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import src.modules.system.config_reading as CR
from src.modules.shared.report_theme import ColorType, ReportTheme

#: Colores de respaldo, iguales al acento de Hygeia en la SPA
#: (``[data-module="hygeia"]`` en ``shared.css``). Se usan si
#: ``features.hygeia.colorPalette`` no está en la configuración.
_FALLBACK_PALETTE = {
    "black":     "#121212",
    "dark":      "#24402c",
    "main":      "#3e6b4a",
    "secondary": "#555b6e",
    "light":     "#5a8f6d",
    "white":     "#f5f5f5",
}

#: Cómo se lee cada estado de presencia en el informe. Coincide con las
#: etiquetas de la SPA (``AssetList.vue``) a propósito: un mismo activo no
#: puede llamarse "stale" en el PDF y "Inestable" en pantalla.
_STATUS_LABELS = {
    "pending": "Pendiente",
    "online":  "En línea",
    "stale":   "Inestable",
    "offline": "Caído",
}

#: Orden en el que se presenta el recuento de la portada: de mejor a peor, que
#: es como se lee un semáforo.
_STATUS_ORDER = ("online", "stale", "offline", "pending")


def _palette() -> Dict[ColorType, str]:
    """Paleta del informe, de la configuración y con respaldo propio."""
    configured = CR.get_hygeia_color_palette()
    return {
        color_type: configured.get(key, _FALLBACK_PALETTE[key])
        for key, color_type in (
            ("black",     ColorType.BLACK),
            ("dark",      ColorType.DARK),
            ("main",      ColorType.MAIN),
            ("secondary", ColorType.SECONDARY),
            ("light",     ColorType.LIGHT),
            ("white",     ColorType.WHITE),
        )
    }


def _status_label(asset) -> str:
    """El estado tal como debe leerse.

    Un activo que se apaga a propósito no está "caído": es la misma distinción
    que hace la lista de la SPA, y pintarlo como caído en un informe de
    auditoría sería inventarse una incidencia.
    """
    if asset.status == "offline" and asset.is_persistent is False:
        return "Apagado"
    return _STATUS_LABELS.get(asset.status, asset.status or "—")


def _format_datetime(value: Optional[datetime]) -> str:
    """Fecha y hora en formato local legible, o una raya si nunca ocurrió."""
    return value.strftime("%d/%m/%Y %H:%M") if value else "—"


def _cell(text: str, style) -> Paragraph:
    """Celda que sabe partirse en varias líneas.

    Un ``str`` suelto dentro de una ``Table`` de ReportLab no hace *wrap*: se
    sale de la columna. Con ``Paragraph`` sí, y en una tabla de hostnames y
    nombres de software eso pasa constantemente.
    """
    return Paragraph(text or "—", style)


def _data_table_style(theme: ReportTheme) -> TableStyle:
    """Estilo común de las tablas de datos: cabecera en color, filas cebradas."""
    main = colors.HexColor(theme.palette[ColorType.MAIN])
    light = colors.HexColor(theme.palette[ColorType.LIGHT])
    white = colors.HexColor(theme.palette[ColorType.WHITE])

    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), main),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("GRID",          (0, 0), (-1, -1), 0.4, light),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f2")]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])


def _cover(
    theme: ReportTheme, assets: Sequence, scope_label: str, author: str,
    generated_at: datetime,
) -> list:
    """Portada: de qué va el informe, quién lo pidió y qué hay dentro."""
    elements: list = []
    elements.extend(theme.section_header("Inventario de activos", "HYGEIA"))
    elements.append(Spacer(1, 0.25 * inch))

    counts = {status: 0 for status in _STATUS_ORDER}
    for asset in assets:
        counts[asset.status] = counts.get(asset.status, 0) + 1

    summary = [
        ["Ámbito", scope_label],
        ["Generado por", author],
        ["Fecha", _format_datetime(generated_at)],
        ["Activos totales", str(len(assets))],
    ]
    summary.extend(
        [_STATUS_LABELS[status], str(counts.get(status, 0))]
        for status in _STATUS_ORDER
        if counts.get(status)
    )

    elements.append(theme.kv_table(summary, col_widths=[2.2 * inch, 3.8 * inch]))
    return elements


def _asset_register(theme: ReportTheme, assets: Sequence, owner_names: Dict[int, str]) -> list:
    """El registro: una fila por activo.

    ``owner_names`` vacío significa ámbito propio, y entonces la columna de
    dueño no se pinta: en un informe de los activos de uno mismo, repetir el
    propio nombre en cada fila es ruido.
    """
    show_owner = bool(owner_names)

    header = ["Hostname", "SO", "Kernel", "Estado", "Última señal", "Etiquetas"]
    widths = [1.35 * inch, 0.6 * inch, 0.95 * inch, 0.75 * inch, 1.0 * inch, 1.35 * inch]
    if show_owner:
        header.insert(1, "Dueño")
        widths = [1.15 * inch, 0.8 * inch, 0.5 * inch, 0.8 * inch, 0.7 * inch,
                  0.95 * inch, 1.1 * inch]

    rows = [[_cell(text, theme.label) for text in header]]
    for asset in assets:
        values = [
            asset.hostname,
            asset.os or "—",
            asset.kernel or "—",
            _status_label(asset),
            _format_datetime(asset.last_seen_at),
            ", ".join(tag.name for tag in asset.tags) or "—",
        ]
        if show_owner:
            values.insert(1, owner_names.get(asset.user_id, f"#{asset.user_id}"))
        rows.append([_cell(value, theme.body) for value in values])

    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(_data_table_style(theme))

    elements: list = [PageBreak()]
    elements.extend(theme.section_header("Registro de activos", "INVENTARIO"))
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(table)
    return elements


def _software_appendix(theme: ReportTheme, assets: Sequence) -> list:
    """Anexo con el software instalado, una tabla por activo.

    Va al final y en su propia sección a propósito: así el registro se lee
    igual de bien con la opción activada que sin ella. Puede ser largo — el
    agente manda hasta ``features.hygeia.limits.maxInventoryItems`` entradas
    por activo — y por eso no se activa por defecto.
    """
    elements: list = [PageBreak()]
    elements.extend(theme.section_header("Software instalado", "ANEXO"))
    elements.append(Spacer(1, 0.15 * inch))

    with_inventory = [asset for asset in assets if asset.inventory]
    if not with_inventory:
        elements.append(Paragraph(
            "Ningún activo ha reportado todavía su inventario de software.",
            theme.body,
        ))
        return elements

    header = [_cell(text, theme.label) for text in ("Nombre", "Fabricante", "Versión", "Arq.")]
    widths = [2.6 * inch, 1.6 * inch, 1.1 * inch, 0.7 * inch]

    for asset in with_inventory:
        rows = [header]
        for entry in asset.inventory:
            rows.append([
                _cell(entry.get("name") or "—", theme.body),
                _cell(entry.get("vendor") or "—", theme.body),
                _cell(entry.get("version") or "—", theme.body),
                _cell(entry.get("architecture") or "—", theme.body),
            ])

        table = Table(rows, colWidths=widths, repeatRows=1)
        table.setStyle(_data_table_style(theme))

        # El título y el arranque de su tabla no deben quedar separados por un
        # salto de página: un encabezado huérfano al pie hace pensar que el
        # activo no tiene software.
        heading = Paragraph(
            f"<b>{asset.hostname}</b> — {len(asset.inventory)} aplicaciones",
            theme.subtitle,
        )
        elements.append(KeepTogether([heading, Spacer(1, 0.06 * inch), table]))
        elements.append(Spacer(1, 0.2 * inch))

    return elements


def build_inventory_report(
    *,
    assets: Sequence,
    scope_label: str,
    author: str,
    include_software: bool = False,
    owner_names: Optional[Dict[int, str]] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    """
    Dibuja el informe de inventario y devuelve los bytes del PDF.

    Args:
        assets: Activos a incluir, ya cargados y en el orden en que deben salir.
        scope_label: Texto del ámbito para la portada ("Mis activos", el nombre
            de la organización...).
        author: Quién pide el informe, tal como debe figurar en la portada.
        include_software: Añade el anexo con el software instalado.
        owner_names: ``{user_id: nombre}`` para el ámbito de organización.
            Vacío o ``None`` en ámbito propio, y entonces no se pinta la
            columna de dueño.
        generated_at: Instante que figura en la portada. Se inyecta para que
            los tests puedan fijarlo.

    Returns:
        El PDF completo, en memoria.
    """
    generated_at = generated_at or datetime.now()
    theme = ReportTheme(getSampleStyleSheet(), _palette())

    elements = _cover(theme, assets, scope_label, author, generated_at)
    if assets:
        elements.extend(_asset_register(theme, assets, owner_names or {}))
        if include_software:
            elements.extend(_software_appendix(theme, assets))
    else:
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("No hay ningún activo que inventariar.", theme.body))

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Inventario de activos — {scope_label}",
        author=author,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
    )
    document.build(
        elements,
        onFirstPage=lambda canvas, doc: _draw_footer(canvas, doc, theme),
        onLaterPages=lambda canvas, doc: _draw_footer(canvas, doc, theme),
    )

    buffer.seek(0)
    return buffer.read()


def _draw_footer(canvas, document, theme: ReportTheme) -> None:
    """Pie con el número de página, en todas."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor(theme.palette[ColorType.SECONDARY]))
    canvas.drawRightString(
        document.pagesize[0] - 0.6 * inch, 0.45 * inch, f"Página {document.page}",
    )
    canvas.drawString(0.6 * inch, 0.45 * inch, "Ellysia · Hygeia")
    canvas.restoreState()
