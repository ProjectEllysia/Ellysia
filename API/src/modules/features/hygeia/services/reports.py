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
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
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


def _data_table_style(theme: ReportTheme, header_rows: int = 1) -> TableStyle:
    """Estilo común de las tablas de datos: cabecera en color, filas cebradas.

    ``header_rows`` es 2 en el anexo de software, donde la primera fila es el
    nombre del activo abarcando las cuatro columnas y la segunda los títulos.
    """
    main = colors.HexColor(theme.palette[ColorType.MAIN])
    dark = colors.HexColor(theme.palette[ColorType.DARK])
    light = colors.HexColor(theme.palette[ColorType.LIGHT])
    white = colors.HexColor(theme.palette[ColorType.WHITE])
    last_header = header_rows - 1

    commands = [
        ("BACKGROUND",    (0, 0), (-1, last_header), main),
        ("TEXTCOLOR",     (0, 0), (-1, last_header), white),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("GRID",          (0, 0), (-1, -1), 0.4, light),
        ("ROWBACKGROUNDS", (0, header_rows), (-1, -1),
                          [colors.white, colors.HexColor("#f2f5f2")]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]

    if header_rows == 2:
        # La fila del activo, más oscura y a todo lo ancho, para que se lea como
        # un título y no como una fila más de la tabla.
        commands += [
            ("SPAN",          (0, 0), (-1, 0)),
            ("BACKGROUND",    (0, 0), (-1, 0), dark),
            ("TOPPADDING",    (0, 0), (-1, 0), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("LEFTPADDING",   (0, 0), (-1, 0), 8),
        ]

    return TableStyle(commands)


def _cover(
    theme: ReportTheme, assets: Sequence, scope_label: str, author: str,
    generated_at: datetime,
) -> list:
    """Portada del informe.

    Sigue el molde de los informes de Themis (``reports/creator.py``,
    ``append_cover_page``): banda de título en color, subtítulo, ficha
    enmarcada y barra decorativa. Antes esto era una tabla clave-valor y
    parecía un formulario, no la primera página de un documento.
    """
    main = colors.HexColor(theme.palette[ColorType.MAIN])
    light = colors.HexColor(theme.palette[ColorType.LIGHT])
    white = colors.HexColor(theme.palette[ColorType.WHITE])
    black = colors.HexColor(theme.palette[ColorType.BLACK])

    elements: list = [Spacer(1, 1.9 * inch)]

    title_style = ParagraphStyle(
        "CoverTitle", parent=theme.styles["Heading1"],
        fontSize=28, leading=32, textColor=white,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
    )
    title_band = Table([[Paragraph("Inventario de activos", title_style)]], colWidths=[6 * inch])
    title_band.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), main),
        ("TOPPADDING",    (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING",   (0, 0), (-1, -1), 24),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 24),
    ]))
    elements.append(title_band)

    subtitle_style = ParagraphStyle(
        "CoverSubtitle", parent=theme.styles["Normal"],
        fontSize=13, leading=16, textColor=black, alignment=TA_CENTER,
    )
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(scope_label, subtitle_style))

    elements.append(Spacer(1, 0.9 * inch))
    info_table = Table(
        [["Generado por:", author], ["Fecha:", _format_datetime(generated_at)]],
        colWidths=[1.8 * inch, 3.2 * inch],
    )
    info_table.setStyle(TableStyle([
        ("TEXTCOLOR",     (0, 0), (0, -1), main),
        ("TEXTCOLOR",     (1, 0), (1, -1), black),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BOX",           (0, 0), (-1, -1), 1, light),
    ]))
    elements.append(info_table)

    elements.append(Spacer(1, 0.5 * inch))
    elements.append(_status_strip(theme, assets))

    elements.append(Spacer(1, 0.6 * inch))
    decoration = Table([[""]], colWidths=[6 * inch], rowHeights=[0.12 * inch])
    decoration.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), light)]))
    elements.append(decoration)

    elements.append(PageBreak())
    return elements


def _status_strip(theme: ReportTheme, assets: Sequence) -> Table:
    """Cifras de un vistazo: el total y el desglose por estado.

    Es la respuesta a "¿qué hay aquí dentro?" sin pasar de página, y lo que
    convierte la portada en algo que se mira en vez de leerse. Los estados sin
    ningún activo no se pintan: una columna a cero no informa, estorba.
    """
    main = colors.HexColor(theme.palette[ColorType.MAIN])
    light = colors.HexColor(theme.palette[ColorType.LIGHT])
    white = colors.HexColor(theme.palette[ColorType.WHITE])

    counts: Dict[str, int] = {}
    for asset in assets:
        counts[asset.status] = counts.get(asset.status, 0) + 1

    columns = [("Activos", len(assets))]
    columns.extend(
        (_STATUS_LABELS[status], counts[status])
        for status in _STATUS_ORDER
        if counts.get(status)
    )

    number_style = ParagraphStyle(
        "StatNumber", parent=theme.styles["Normal"],
        fontSize=20, leading=23, alignment=TA_CENTER,
        fontName="Helvetica-Bold", textColor=white,
    )
    label_style = ParagraphStyle(
        "StatLabel", parent=theme.styles["Normal"],
        fontSize=7.5, leading=10, alignment=TA_CENTER, textColor=white,
    )

    cells = [
        [Paragraph(str(value), number_style), Paragraph(label.upper(), label_style)]
        for label, value in columns
    ]
    inner = [
        Table([[cell[0]], [cell[1]]], colWidths=[6 * inch / len(columns)])
        for cell in cells
    ]

    strip = Table([inner], colWidths=[6 * inch / len(columns)] * len(columns))
    strip.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), main),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEAFTER",     (0, 0), (-2, -1), 0.6, light),
    ]))
    return strip


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

    # Sin `PageBreak` aquí: la portada ya termina con uno.
    elements: list = list(theme.section_header("Registro de activos", "INVENTARIO"))
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

    widths = [2.6 * inch, 1.6 * inch, 1.1 * inch, 0.7 * inch]

    # El nombre del activo va DENTRO de la tabla, como fila que abarca las
    # cuatro columnas, y no como párrafo suelto encima.
    #
    # Es la única forma de que no quede huérfano: tanto `KeepTogether` como
    # `keepWithNext` obligan al bloque título+tabla a caber entero en una
    # página, y una tabla de cientos de aplicaciones no cabe nunca — así que
    # ReportLab la empujaba a la siguiente y dejaba el encabezado solo, con
    # la página medio en blanco. Como fila de la propia tabla, hay un único
    # flowable, que se parte por donde haga falta.
    #
    # `repeatRows=2` remata la jugada: al continuar en la página siguiente se
    # repiten el nombre del activo y la cabecera de columnas, así que nunca hay
    # una página de aplicaciones sin saber de quién son.
    title_style = ParagraphStyle(
        "SoftwareAssetTitle", parent=theme.styles["Normal"],
        fontSize=10.5, leading=13, fontName="Helvetica-Bold",
        textColor=colors.HexColor(theme.palette[ColorType.WHITE]),
    )

    for asset in with_inventory:
        count = len(asset.inventory)
        caption = f"{asset.hostname} — {count} {'aplicación' if count == 1 else 'aplicaciones'}"

        rows = [
            [Paragraph(caption, title_style), "", "", ""],
            [_cell(text, theme.label) for text in ("Nombre", "Fabricante", "Versión", "Arq.")],
        ]
        for entry in asset.inventory:
            rows.append([
                _cell(entry.get("name") or "—", theme.body),
                _cell(entry.get("vendor") or "—", theme.body),
                _cell(entry.get("version") or "—", theme.body),
                _cell(entry.get("architecture") or "—", theme.body),
            ])

        table = Table(rows, colWidths=widths, repeatRows=2)
        table.setStyle(_data_table_style(theme, header_rows=2))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

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
        onFirstPage=lambda canvas, doc: _draw_page_furniture(canvas, doc, theme),
        onLaterPages=lambda canvas, doc: _draw_page_furniture(canvas, doc, theme),
    )

    buffer.seek(0)
    return buffer.read()


def _draw_page_furniture(canvas, document, theme: ReportTheme) -> None:
    """Barra de acento, cabecera y número de página.

    Mismo aparejo que los informes de Themis (``creator.py::_on_page``), para
    que los dos documentos se reconozcan como del mismo producto.

    La portada se queda limpia: una cabecera y un pie en la página 1 son
    justamente lo que hace que una portada no parezca una portada.
    """
    if canvas.getPageNumber() == 1:
        return

    width, height = document.pagesize
    main = colors.HexColor(theme.palette[ColorType.MAIN])
    dark = colors.HexColor(theme.palette[ColorType.DARK])

    canvas.saveState()

    canvas.setFillColor(main)
    canvas.rect(20, 20, 6, height - 40, stroke=0, fill=1)

    canvas.setFont("Helvetica-Bold", 12)
    canvas.setFillColor(dark)
    canvas.drawString(40, height - 30, "Ellysia · Inventario de activos")

    canvas.setStrokeColor(colors.HexColor("#e0e0e0"))
    canvas.setLineWidth(0.5)
    canvas.line(36, height - 42, width - 36, height - 42)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#999999"))
    canvas.drawRightString(width - 40, 28, f"Página {canvas.getPageNumber()}")

    canvas.restoreState()
