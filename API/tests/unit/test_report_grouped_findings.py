"""El cuerpo del informe PDF, agrupado por unidad remediable.

Un escaneo contra un host con dos productos desactualizados puede dar 150
hallazgos, y hasta ahora el PDF los imprimía como 150 fichas seguidas. Lo
llamativo era que el propio informe ya tenía la agrupación delante: la usa
desde hace tiempo para armar el prompt del análisis de IA. Así que la IA
recomendaba «actualiza Apache y cierras 12 CVEs» y tres páginas más abajo esos
12 CVEs aparecían como fichas inconexas.

Lo que hay que fijar aquí es lo que un lector del PDF puede comprobar sin
abrirlo en un visor: que los grupos se parten en las dos secciones correctas y
en el orden correcto, que el orden interno de las fichas es el de siempre, y
que el árbol de marcadores sale con los niveles bien anidados (ReportLab
rechaza un nivel que salte más de uno respecto al anterior, así que un error
aquí no es cosmético: no genera el PDF).
"""

from __future__ import annotations

import pytest
from reportlab.lib.styles import getSampleStyleSheet

from src.modules.shared.report_theme import ColorType, ReportTheme
from src.modules.features.themis.lybra.grouping import build_service_rollup
from src.modules.features.themis.services.reports.findings import FindingsPrintingStrategy
from src.modules.features.themis.services.reports.outline import OutlineEntry

pytestmark = pytest.mark.unit

_PALETTE = {
    ColorType.BLACK: "#1A2410", ColorType.DARK: "#4A6132", ColorType.MAIN: "#7CA163",
    ColorType.SECONDARY: "#A8C98F", ColorType.LIGHT: "#D4E8C4", ColorType.WHITE: "#F3F8EE",
}

_APACHE = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
_OPENSSH = "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*"


class _Scan:
    """Lo único que el cuerpo agrupado mira del escaneo es su id, que va en la
    clave de los marcadores."""

    id = 7


def _strategy() -> FindingsPrintingStrategy:
    """La estrategia sin pasar por ``__init__``.

    ``__init__`` construye además el escritor de IA y lee la paleta de
    ``SecOpsConfig.json``, y nada de eso interviene en cómo se reparten los
    grupos: pedirlo obligaría a montar configuración para comprobar un orden.
    """
    strategy = FindingsPrintingStrategy.__new__(FindingsPrintingStrategy)
    strategy.scan = _Scan()
    strategy.color_palette = _PALETTE
    return strategy


def _theme() -> ReportTheme:
    return ReportTheme(getSampleStyleSheet(), _PALETTE)


def _finding(**overrides) -> dict:
    base = {
        "title": "hallazgo", "category": "outdated_software", "port": 80, "service": "http",
        "cpe": None, "cve_ids": [], "cvss_score": None, "epss_score": None, "in_kev": False,
        "confirmed": False, "priority": "INFO", "fixed_version": None,
    }
    base.update(overrides)
    return base


def _outline_entries(elements: list) -> list:
    return [(entry.level, entry.title, entry.key)
            for entry in elements if isinstance(entry, OutlineEntry)]


# ------------------------------------------------------------------ secciones

def test_products_and_configuration_are_two_separate_sections_in_that_order():
    """Son dos clases de trabajo distintas: subir un producto de versión, y
    arreglar una configuración. Mezclarlas hacía que «falta la cabecera HSTS»
    pareciera un producto más del inventario."""
    groups = build_service_rollup([
        _finding(cpe=_APACHE, cvss_score=9.8),
        _finding(category="security_header", cvss_score=2.0),
    ])

    sections = _strategy()._split_into_sections(groups)  # pylint: disable=protected-access

    assert [key for key, _, _ in sections] == ["prod", "conf"]
    assert [title for _, title, _ in sections] == [
        "Productos afectados", "Configuración y exposición"]
    assert [group.label for group in sections[0][2]] == ["http server 2.4.52"]
    assert [group.label for group in sections[1][2]] == ["security_header (http)"]


def test_a_section_with_no_groups_is_not_printed_at_all():
    """Imprimir el título de una sección para no colgarle nada debajo se lee
    como si faltara algo, no como si no hubiera nada que decir."""
    groups = build_service_rollup([_finding(cpe=_APACHE, cvss_score=9.8)])

    sections = _strategy()._split_into_sections(groups)  # pylint: disable=protected-access

    assert [key for key, _, _ in sections] == ["prod"]


def test_findings_inside_a_group_keep_the_priority_ladder_of_the_flat_list():
    """El orden de las fichas no cambia con la agrupación: sigue siendo
    prioridad, luego comprobados antes que hipótesis, luego CVSS. Lo que cambia
    es que ahora se aplica dentro de cada grupo."""
    low = _finding(title="bajo", priority="LOW", confirmed=True)
    critical_guess = _finding(title="crítico deducido", priority="CRITICAL", confirmed=False)
    critical_confirmed = _finding(title="crítico comprobado", priority="CRITICAL", confirmed=True)

    ordered = _strategy()._sorted_findings(  # pylint: disable=protected-access
        [low, critical_guess, critical_confirmed])

    assert [finding["title"] for finding in ordered] == [
        "crítico comprobado", "crítico deducido", "bajo"]


def test_a_scan_with_no_findings_still_says_so_and_prints_no_group_index():
    """El caso vacío no es un informe a medias: es la afirmación de que se
    comprobó y no había nada. Un índice de grupos vacío ahí sobra."""
    elements = []
    strategy = _strategy()
    strategy._append_findings_section(_theme(), elements, [])  # pylint: disable=protected-access

    texts = [element.text for element in elements if hasattr(element, "text")]

    assert "El motor no detectó ningún hallazgo para este objetivo." in texts
    assert "Índice de grupos" not in texts
    assert [level for level, _, _ in _outline_entries(elements)] == [0]


# ---------------------------------------------------------------- marcadores

def test_the_outline_nests_section_under_findings_and_group_under_section():
    """ReportLab rechaza un nivel que salte más de uno respecto al anterior, así
    que este anidamiento no es cosmético: si se rompe, el PDF no se genera."""
    elements = []
    strategy = _strategy()
    strategy._append_findings_section(  # pylint: disable=protected-access
        _theme(), elements, [
            _finding(cpe=_APACHE, cvss_score=9.8, cve_ids=["CVE-2023-1"]),
            _finding(cpe=_OPENSSH, port=22, service="ssh", cvss_score=7.1),
            _finding(category="security_header", cvss_score=2.0),
        ])

    levels = [level for level, _, _ in _outline_entries(elements)]

    assert levels == [0, 1, 2, 2, 1, 2]
    for index, level in enumerate(levels[1:], start=1):
        assert level - levels[index - 1] <= 1


def test_every_bookmark_key_is_unique_and_carries_the_scan():
    """Dos marcadores con la misma clave apuntarían al mismo destino, y el
    índice mandaría al sitio equivocado."""
    elements = []
    strategy = _strategy()
    strategy._append_findings_section(  # pylint: disable=protected-access
        _theme(), elements, [
            _finding(cpe=_APACHE, cvss_score=9.8),
            _finding(cpe=_OPENSSH, port=22, service="ssh", cvss_score=7.1),
            _finding(category="security_header", cvss_score=2.0),
        ])

    keys = [key for _, _, key in _outline_entries(elements)]

    assert len(keys) == len(set(keys))
    assert all(key.startswith("scan7-") for key in keys)


def test_a_group_bookmark_says_how_many_findings_it_hides():
    """El árbol de marcadores es lo más parecido a plegar que un PDF admite, y
    sólo sirve para decidir dónde entrar si dice cuánto hay detrás."""
    elements = []
    strategy = _strategy()
    strategy._append_findings_section(  # pylint: disable=protected-access
        _theme(), elements, [
            _finding(cpe=_APACHE, cvss_score=9.8),
            _finding(cpe=_APACHE, cvss_score=7.5),
        ])

    group_titles = [title for level, title, _ in _outline_entries(elements) if level == 2]

    assert group_titles == ["http server 2.4.52 (2)"]


# ------------------------------------------------------------- el PDF entero

def test_the_grouped_body_builds_a_real_pdf_with_its_outline(tmp_path):
    """La comprobación de que todo esto compone de verdad: tablas, saltos
    condicionales y marcadores pasando juntos por ReportLab. Es lo único que
    puede detectar un ancho de columna imposible o un nivel de outline mal
    anidado, que sólo revientan al construir el documento."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate

    elements = []
    strategy = _strategy()
    strategy._append_findings_section(  # pylint: disable=protected-access
        _theme(), elements, [
            _finding(cpe=_APACHE, cvss_score=9.8, epss_score=0.42, in_kev=True,
                     cve_ids=["CVE-2023-1"], confirmed=True, priority="CRITICAL",
                     fixed_version="2.4.58"),
            _finding(cpe=_APACHE, cvss_score=5.0, cve_ids=["CVE-2023-2"], priority="MEDIUM"),
            _finding(category="security_header", cvss_score=2.0, priority="LOW",
                     title="Falta la cabecera HSTS"),
        ])

    target = tmp_path / "grouped.pdf"
    SimpleDocTemplate(str(target), pagesize=A4).build(elements)

    contents = target.read_bytes()
    assert target.stat().st_size > 0
    assert b"/Outlines" in contents
