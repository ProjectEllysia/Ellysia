"""La agrupación de hallazgos por unidad remediable.

Un escaneo contra un host con dos productos desactualizados puede producir 150
hallazgos, que son dos acciones —subir dos productos de versión— más un puñado
de cosas de configuración que se arreglan de otra manera. Esta agrupación
existía ya, pero vivía dentro del constructor del prompt de IA del informe PDF,
así que el modelo de lenguaje recibía los hallazgos bien organizados y el
usuario los recibía en una lista plana.

Al extraerla a la capa pura hay dos cosas que fijar: que agrupa lo que debe, y
que el prompt del informe sigue recibiendo exactamente la misma forma que antes
—sus claves están descritas una por una en el texto de sistema, así que
cambiarlas rompería el contrato en silencio—.
"""

from __future__ import annotations

import pytest

from src.modules.features.themis.lybra import build_service_rollup, group_label
from src.modules.features.themis.services.analyzers import LybraAIWriter

pytestmark = pytest.mark.unit


def _finding(**overrides) -> dict:
    base = {
        "title": "hallazgo",
        "category": "outdated_software",
        "port": 80,
        "service": "http",
        "cpe": None,
        "cve_ids": [],
        "cvss_score": None,
        "epss_score": None,
        "in_kev": False,
        "confirmed": False,
        "priority": "INFO",
        "fixed_version": None,
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------------ etiquetas

def test_a_resolved_cpe_names_the_product_and_its_version():
    label, is_product = group_label(
        _finding(cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"))
    assert label == "http server 2.4.52"
    assert is_product


def test_a_cpe_without_a_concrete_version_names_just_the_product():
    for wildcard in ("*", "-"):
        label, is_product = group_label(
            _finding(cpe=f"cpe:2.3:a:apache:http_server:{wildcard}:*:*:*:*:*:*:*"))
        assert label == "http server"
        assert is_product


def test_a_finding_without_a_product_groups_by_category_and_service():
    """El caso de las cabeceras ausentes.

    Las tres que faltan en http:80 se arreglan de una sola pasada por la
    configuración del servidor. Agruparlas por título produciría tres
    "productos" de un elemento y desdibujaría el inventario.
    """
    label, is_product = group_label(
        _finding(cpe=None, category="security_header", service="http"))
    assert label == "security_header (http)"
    assert not is_product


# --------------------------------------------------------------------- rollup

def test_findings_of_one_product_collapse_into_a_single_group():
    cpe = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
    groups = build_service_rollup([
        _finding(cpe=cpe, cve_ids=["CVE-2023-1"], cvss_score=7.5, priority="HIGH"),
        _finding(cpe=cpe, cve_ids=["CVE-2023-2"], cvss_score=9.1, priority="CRITICAL",
                 in_kev=True, confirmed=True),
        _finding(cpe=cpe, cve_ids=["CVE-2023-1"], cvss_score=7.5, priority="HIGH"),
    ])

    assert len(groups) == 1
    group = groups[0]
    assert group.total_findings == 3
    assert group.cve_ids == ["CVE-2023-1", "CVE-2023-2"]   # distintos, no repetidos
    assert group.total_cves == 2
    assert group.kev_cve_ids == ["CVE-2023-2"]             # sólo el que va en KEV
    assert group.max_cvss == 9.1
    assert group.confirmed_count == 1
    assert group.by_priority == {"HIGH": 2, "CRITICAL": 1}


def test_the_same_product_on_two_ports_is_two_groups():
    """Se remedia un servicio, no un producto en abstracto: el mismo Apache en
    el 80 y en el 8080 son dos sitios donde hay que actuar."""
    cpe = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
    groups = build_service_rollup([
        _finding(cpe=cpe, port=80),
        _finding(cpe=cpe, port=8080),
    ])
    assert {group.port for group in groups} == {80, 8080}


def test_the_group_recommends_the_highest_fix_bound():
    """La cota más alta cierra también todas las inferiores, así que es la
    única versión destino que tiene sentido recomendar — y hay que compararlas
    numéricamente: '2.4.9' es *anterior* a '2.4.52', no posterior."""
    cpe = "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    groups = build_service_rollup([
        _finding(cpe=cpe, fixed_version="2.4.9"),
        _finding(cpe=cpe, fixed_version="2.4.52"),
        _finding(cpe=cpe, fixed_version=None),
    ])
    assert groups[0].fixed_version == "2.4.52"


def test_groups_come_ordered_by_severity_and_the_cap_drops_the_mildest():
    groups = build_service_rollup([
        _finding(cpe="cpe:2.3:a:v:leve:1.0:*:*:*:*:*:*:*", port=1, cvss_score=2.0),
        _finding(cpe="cpe:2.3:a:v:grave:1.0:*:*:*:*:*:*:*", port=2, cvss_score=9.8),
        _finding(cpe="cpe:2.3:a:v:media:1.0:*:*:*:*:*:*:*", port=3, cvss_score=5.0),
    ])
    assert [group.label for group in groups] == ["grave 1.0", "media 1.0", "leve 1.0"]

    capped = build_service_rollup([
        _finding(cpe="cpe:2.3:a:v:leve:1.0:*:*:*:*:*:*:*", port=1, cvss_score=2.0),
        _finding(cpe="cpe:2.3:a:v:grave:1.0:*:*:*:*:*:*:*", port=2, cvss_score=9.8),
    ], max_groups=1)
    assert [group.label for group in capped] == ["grave 1.0"]


def test_products_and_non_products_stay_distinguishable():
    """Lo que separa «actualiza Apache» de «faltan cabeceras»: dos clases de
    trabajo distintas, que la interfaz presenta aparte."""
    groups = build_service_rollup([
        _finding(cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"),
        _finding(cpe=None, category="security_header"),
    ])
    by_label = {group.label: group.is_product for group in groups}
    assert by_label == {"http server 2.4.52": True, "security_header (http)": False}


# ---------------------------------------------------- contrato con el prompt

def test_the_ai_prompt_still_gets_the_keys_its_system_text_describes():
    """El texto de sistema del prompt enumera estas claves una por una
    ('total_hallazgos', 'cves_en_kev', 'corregido_en'…). Si la extracción las
    renombrara, el modelo dejaría de encontrarlas sin que fallara nada."""
    rollup = LybraAIWriter._build_service_rollup(  # pylint: disable=protected-access
        LybraAIWriter.__new__(LybraAIWriter),
        [_finding(cpe="cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
                  cve_ids=["CVE-2023-1"], cvss_score=7.5, in_kev=True,
                  confirmed=True, priority="HIGH", fixed_version="2.4.58")],
    )

    assert rollup == [{
        "producto": "http server 2.4.52",
        "puerto": 80,
        "servicio": "http",
        "total_hallazgos": 1,
        "cves_en_kev": ["CVE-2023-1"],
        "max_cvss": 7.5,
        "max_epss": None,
        "corregido_en": "2.4.58",
        "confirmados": 1,
        "por_prioridad": {"HIGH": 1},
        "total_cves": 1,
    }]
