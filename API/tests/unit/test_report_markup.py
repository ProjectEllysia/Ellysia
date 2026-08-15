"""Tests de ``safe_markup``: el saneado del texto ajeno que imprimen los PDFs.

El invariante que se protege es duro: NINGUNA entrada puede tumbar el build.
``Paragraph`` parsea sus marcas como XML y aborta con ValueError ante un ``<``
suelto, así que un fallo aquí no imprime texto feo — deja al usuario sin
informe. En el KB local había 462 descripciones de NVD capaces de hacerlo.
"""

from __future__ import annotations

import pytest

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph

from src.modules.shared.report_theme import safe_markup

pytestmark = pytest.mark.unit


def _renderiza(text: str) -> None:
    """Falla si ReportLab no sabe maquetar el resultado."""
    Paragraph(f"Qué implica: {safe_markup(text)}", getSampleStyleSheet()["Normal"]).wrap(400, 400)


def test_traduce_la_negrita_que_escriben_los_modelos():
    assert safe_markup("Actualizar **Apache 2.4.7** ya") == "Actualizar <b>Apache 2.4.7</b> ya"


def test_escapa_lo_que_parece_una_etiqueta():
    # Sin escapar, esto aborta el PDF entero con "unclosed tags".
    assert safe_markup("usa <script> aqui") == "usa &lt;script&gt; aqui"
    _renderiza("usa <script> aqui")


def test_los_saltos_de_linea_se_convierten_en_br():
    assert safe_markup("uno\ndos") == "uno<br/>dos"


def test_el_markdown_mal_emparejado_cae_a_texto_plano():
    # Caso real: los volcados de kernel de NVD traen '****' y '__nombre__',
    # que emparejados generaban <b>/<i> cruzados y rompían el documento.
    kernel = "panic ****\n Call Trace:\n <TASK>\n __mutex_lock_common+0x1fd\n __rtl8152_set_mac+0x80"

    resultado = safe_markup(kernel)

    assert "<b>" not in resultado, "no debe inventar negritas sobre un volcado de kernel"
    assert "&lt;TASK&gt;" in resultado
    _renderiza(kernel)


def test_el_texto_vacio_no_revienta():
    assert safe_markup("") == ""
    assert safe_markup(None) == ""


@pytest.mark.parametrize("entrada", [
    'Listen to !nick <source>" option',
    "compara a<b y b>c sin cerrar",
    "**negrita sin cerrar y <div>",
    "mezcla **a <b> b** c",
    "&amp; ya escapado",
])
def test_ninguna_entrada_tumba_el_build(entrada):
    _renderiza(entrada)
