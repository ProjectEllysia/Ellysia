"""El índice plegable del informe PDF.

Un informe de Lybra puede pasar de las cien páginas y hasta ahora sólo se podía
recorrer bajando. El árbol de marcadores del panel lateral —lo único parecido a
«plegar» que un PDF admite de verdad, porque el contenido de la página ya está
compuesto y no se puede esconder— se emite con un flowable de altura cero que
se intercala entre los elementos del informe.

Lo que hay que fijar es justo eso: que no ocupa espacio (si midiera algo,
añadir marcadores movería la paginación del informe entero) y que emite las dos
llamadas que hacen falta —anclar el destino y darlo de alta en el árbol— con
la clave que las une.
"""

from __future__ import annotations

import pytest

from src.modules.features.themis.services.reports.outline import OutlineEntry

pytestmark = pytest.mark.unit


class _CanvasSpy:
    """Un canvas que sólo apunta lo que le piden.

    El canvas real de ReportLab sólo existe dentro de ``build()``, y montar un
    documento entero para comprobar dos llamadas sería pagar la generación de
    un PDF para verificar algo que no depende de ella.
    """

    def __init__(self) -> None:
        self.bookmarks = []
        self.entries = []

    def bookmarkHorizontal(self, key, relative_x, relative_y, **kwargs):  # pylint: disable=invalid-name
        self.bookmarks.append((key, relative_x, relative_y))

    def addOutlineEntry(self, title, key, level=0, closed=None):  # pylint: disable=invalid-name
        self.entries.append((title, key, level, closed))


def test_the_bookmark_takes_up_no_space_on_the_page():
    """Si midiera algo, añadir marcadores cambiaría dónde parte la página cada
    informe, y el índice pasaría de ser navegación a ser maquetación."""
    entry = OutlineEntry("Apache 2.4.52", key="grupo-1")

    assert entry.wrap(6 * 72, 9 * 72) == (0, 0)


def test_drawing_anchors_the_destination_and_registers_it_in_the_tree():
    """Son dos llamadas distintas y las une la clave: una deja el ancla en la
    posición que el elemento acabó ocupando, la otra pone el título en el
    panel apuntando a esa ancla."""
    entry = OutlineEntry("Apache 2.4.52", key="grupo-1", level=2)
    entry.canv = _CanvasSpy()

    entry.draw()

    assert entry.canv.bookmarks == [("grupo-1", 0, 0)]
    assert entry.canv.entries == [("Apache 2.4.52", "grupo-1", 2, True)]


def test_a_node_is_born_collapsed_unless_asked_otherwise():
    """El valor de un índice de cien grupos está en verlos todos de golpe, no
    en que el árbol se despliegue entero al abrir el documento."""
    collapsed = OutlineEntry("Hallazgos", key="h")
    expanded = OutlineEntry("Hallazgos", key="h2", is_closed=False)

    collapsed.canv = _CanvasSpy()
    expanded.canv = _CanvasSpy()
    collapsed.draw()
    expanded.draw()

    assert collapsed.canv.entries[0][3] is True
    assert expanded.canv.entries[0][3] is False


def test_the_entry_survives_a_real_document_build(tmp_path):
    """La comprobación de que el flowable encaja de verdad en el circuito de
    platypus: que ReportLab lo acepta entre los elementos, le inyecta el canvas
    y termina el PDF con el árbol dentro. Un canvas de mentira no puede decir
    esto."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import Paragraph, SimpleDocTemplate
    from reportlab.lib.styles import getSampleStyleSheet

    target = tmp_path / "outline.pdf"
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(target), pagesize=A4)

    document.build([
        OutlineEntry("Hallazgos", key="findings", level=0),
        Paragraph("Hallazgos", styles["Heading1"]),
        OutlineEntry("Productos afectados", key="section-prod", level=1),
        Paragraph("Productos afectados", styles["Heading2"]),
        OutlineEntry("Apache 2.4.52", key="group-0", level=2),
        Paragraph("Apache 2.4.52", styles["Normal"]),
    ])

    contents = target.read_bytes()
    assert target.stat().st_size > 0
    # /Outlines es la entrada del catálogo PDF que cuelga el árbol del
    # documento: sin marcadores, ReportLab no la escribe.
    assert b"/Outlines" in contents
