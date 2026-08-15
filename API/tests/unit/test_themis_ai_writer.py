"""Tests unitarios del payload que LybraAIWriter manda al modelo.

Lo que se protege aquí es la razón de ser del cambio: el análisis IA sonaba
genérico ("actualizar a la última versión estable") porque el prompt no recibía
ni la versión corregida ni la descripción del CVE, y porque la muestra de
hallazgos se recortaba en orden de repositorio en vez de por prioridad.

Cubre:
- El rollup por servicio agrupa por producto/puerto y elige la versión destino
  más alta del grupo (comparación numérica, no lexicográfica).
- Los hallazgos destacados llegan ordenados por prioridad real y con
  'corregido_en' y 'descripcion' dentro.
- Un hallazgo confirmado o en KEV nunca se cae del payload por el tope.
"""

from __future__ import annotations

import json

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.themis.services.analyzers import LybraAIWriter

pytestmark = pytest.mark.unit

_FAKE_PROMPTS = {
    "lybra": {
        "system": "Eres un analista senior.",
        "userTemplate": (
            "Objetivo {{target}} exposicion {{exposure}} inicio {{started}} "
            "total {{total_findings}} confirmados {{confirmed_count}} kev {{kev_count}}\n"
            "SERVICIOS:\n{{services_json}}\nHALLAZGOS:\n{{findings_json}}"
        ),
    }
}


def _finding(**overrides) -> dict:
    """Un hallazgo con la forma que produce FindingsPrintingStrategy.append_body."""
    base = {
        "title": "Apache 2.4.7 — CVE-2021-44790",
        "category": "outdated_software",
        "port": 80,
        "service": "http",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*",
        "cve_ids": ["CVE-2021-44790"],
        "cvss_score": 9.8,
        "epss_score": 0.97,
        "in_kev": False,
        "confirmed": False,
        "qod": 70,
        "state": "open",
        "priority": "CRITICAL",
        "description": "Un cuerpo de petición manipulado provoca un desbordamiento.",
        "fixed_version": "2.4.52",
    }
    base.update(overrides)
    return base


def _build(findings: list, monkeypatch) -> dict:
    """Renderiza el user prompt y devuelve los dos bloques JSON que contiene."""
    monkeypatch.setattr(CR, "get_prompts_config", lambda: _FAKE_PROMPTS)

    writer = LybraAIWriter(generator=object())
    prompt = writer._build_user_prompt(
        {"target": "45.33.32.156", "started_at": "2026-08-11", "exposure": "public"},
        findings,
    )

    services_block, _, findings_block = prompt.partition("HALLAZGOS:\n")
    services_json = services_block.split("SERVICIOS:\n", 1)[1]
    return {"servicios": json.loads(services_json), "hallazgos": json.loads(findings_block)}


def test_rollup_agrupa_por_servicio_y_toma_la_version_destino_mas_alta(monkeypatch):
    findings = [
        _finding(cve_ids=["CVE-2021-44790"], fixed_version="2.4.52"),
        # 2.4.9 es mayor que 2.4.52 en orden lexicográfico: si la comparación no
        # es numérica, el informe recomendaría una versión que no cierra el grupo.
        _finding(cve_ids=["CVE-2014-0117"], cvss_score=4.3, fixed_version="2.4.9", priority="MEDIUM"),
        _finding(
            title="OpenSSH 6.6.1p1 — CVE-2023-38408",
            port=22, service="ssh",
            cpe="cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*",
            cve_ids=["CVE-2023-38408"], fixed_version="9.3", in_kev=True,
        ),
    ]

    servicios = _build(findings, monkeypatch)["servicios"]

    assert len(servicios) == 2, "dos productos distintos deben dar dos grupos"

    apache = next(group for group in servicios if group["puerto"] == 80)
    assert apache["producto"] == "http server 2.4.7"
    assert apache["total_hallazgos"] == 2
    assert apache["total_cves"] == 2
    assert apache["corregido_en"] == "2.4.52"
    assert apache["max_cvss"] == 9.8
    assert apache["por_prioridad"] == {"CRITICAL": 1, "MEDIUM": 1}

    ssh = next(group for group in servicios if group["puerto"] == 22)
    assert ssh["cves_en_kev"] == ["CVE-2023-38408"]


def test_los_hallazgos_sin_cpe_se_agrupan_por_categoria_no_por_titulo(monkeypatch):
    # Tres cabeceras ausentes son una sola pasada por la configuración del
    # servidor. Agrupadas por título darían tres "productos" de un elemento.
    findings = [
        _finding(title=f"Cabecera {header} ausente", category="security_header",
                 cpe=None, cve_ids=[], cvss_score=None, epss_score=None,
                 confirmed=True, priority="MEDIUM", fixed_version=None, description="")
        for header in ("HSTS", "X-Frame-Options", "X-Content-Type-Options")
    ]

    servicios = _build(findings, monkeypatch)["servicios"]

    assert len(servicios) == 1
    assert servicios[0]["producto"] == "security_header (http)"
    assert servicios[0]["total_hallazgos"] == 3
    assert servicios[0]["confirmados"] == 3


def test_hallazgos_destacados_llevan_version_y_descripcion(monkeypatch):
    hallazgos = _build([_finding()], monkeypatch)["hallazgos"]

    assert hallazgos[0]["corregido_en"] == "2.4.52"
    assert hallazgos[0]["descripcion"].startswith("Un cuerpo de petición manipulado")
    assert hallazgos[0]["puerto"] == 80
    assert hallazgos[0]["prioridad"] == "CRITICAL"


def test_la_cola_se_recorta_por_prioridad_y_nunca_descarta_confirmados(monkeypatch):
    # Más ruido de baja prioridad que el tope, más un confirmado escondido al
    # final: en el orden de repositorio anterior, el confirmado no llegaba.
    ruido = [
        _finding(title=f"Puerto {port} abierto", category="open_port", cve_ids=[],
                 cvss_score=None, epss_score=None, priority="INFO", port=port,
                 description="", fixed_version=None)
        for port in range(1000, 1000 + LybraAIWriter._MAX_HIGHLIGHTED_FINDINGS + 10)
    ]
    critico = _finding(title="Apache 2.4.7 — CVE-2021-40438", confirmed=True, in_kev=True)

    payload = _build(ruido + [critico], monkeypatch)
    hallazgos = payload["hallazgos"]

    assert len(hallazgos) == LybraAIWriter._MAX_HIGHLIGHTED_FINDINGS
    assert hallazgos[0]["titulo"] == "Apache 2.4.7 — CVE-2021-40438"
    assert hallazgos[0]["confirmado"] is True
    # El recuento total sigue siendo el real aunque el detalle esté recortado.
    assert sum(group["total_hallazgos"] for group in payload["servicios"]) == len(ruido) + 1
