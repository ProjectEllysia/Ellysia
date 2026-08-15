"""
Tema visual de los informes PDF: paleta y estilos.

Nació en Themis (D5 en ``plans/deuda-tecnica-y-calidad.md``, extraído del
``reports.py`` de 85 KB, el fichero más grande del repositorio) y vive aquí
desde que Hygeia también imprime. No sabe nada de escaneos ni de activos: solo
importa ``reportlab``, así que cualquier módulo que genere un PDF puede
heredarlo y salir con la misma cara que el resto del producto.

A propósito **no** se reexporta desde ``src.modules.shared``: ese ``__init__``
lo importa medio backend, y colgar de él la carga de ``reportlab`` haría que
la pagara hasta quien solo quiere ``utcnow_naive``. Quien imprime, lo importa
por su ruta completa.
"""

import re

from enum import Enum
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Table, TableStyle

_MARKDOWN_BOLD = re.compile(r"\*\*(?!\s)(.+?)(?<!\s)\*\*", re.DOTALL)


def safe_markup(text: str) -> str:
    """Convierte texto no confiable en el mini-HTML que entiende ``Paragraph``.

    Todo lo que un informe imprime sin haberlo escrito nosotros pasa por aquí:
    la prosa del modelo, las descripciones de NVD y los hallazgos de Nikto.
    Dos motivos, y el primero no es cosmético:

    1. ``Paragraph`` parsea sus marcas como XML, así que un ``<`` seguido de
       letra aborta el build entero con ValueError — no imprime el texto en
       crudo, tumba el PDF. No es hipotético: unas 4.000 descripciones de NVD
       traen construcciones así ("Listen to !nick <source>"), y una de cada
       diez basta para reventar el informe entero.
    2. Los modelos escriben markdown por costumbre aunque se les pida que no.
       ``**Apache 2.4.7**`` salía literal en el papel, y traducirlo aquí es
       más fiable que confiar en que el prompt se respete siempre.

    Solo se traduce ``**negrita**``. Ni ``__x__`` ni ``*cursiva*``: sobre texto
    arbitrario disparan constantemente — los volcados de kernel de NVD están
    llenos de ``****`` y de ``__mutex_lock_common``, y emparejarlos generaba
    etiquetas cruzadas que rompían justo lo que esta función debía evitar.

    Por eso el resultado se valida antes de devolverlo: si la conversión no ha
    quedado bien formada, se descarta y sale el texto escapado a secas. Feo
    antes que caído — ninguna entrada puede tumbar el PDF.
    """
    if not text:
        return ""

    plain = escape(str(text)).replace("\n", "<br/>")
    markup = _MARKDOWN_BOLD.sub(r"<b>\1</b>", plain)

    if markup != plain:
        try:
            ElementTree.fromstring(f"<p>{markup}</p>")
        except ElementTree.ParseError:
            return plain

    return markup


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

