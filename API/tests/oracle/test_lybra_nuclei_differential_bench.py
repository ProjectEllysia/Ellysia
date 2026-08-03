"""Oráculo diferencial de Nuclei para Lybra (roadmap Fase U3, §8 segunda pata).

Distinto de ``test_lybra_oracle_bench.py``, que afirma "el motor debe
encontrar la CVE tal en la imagen cual" contra objetivos con verdad conocida
de antemano (VulHub-style, etiquetados a mano). Este módulo mide la otra
mitad que esa verdad por etiqueta no puede cubrir: **falsos positivos** que
Lybra produce y que un tercero no corrobora, y **hallazgos que se escapan**
porque el propio banco no los tenía anticipados.

El método: se lanza un escaneo Lybra de autodescubrimiento real y, por
separado, el binario real de Nuclei —ambos contra el mismo contenedor Docker,
por la red real, nada mockeado—, y se comparan los CVE que cada uno reporta.
El traductor ``nuclei_result_to_finding`` es el mismo que usa U1 en
producción (roadmap: "el mismo traductor de U1, en un contenedor efímero") —
aquí se invoca directamente sobre el JSONL, sin pasar por
``NucleiScanManager``/TaskQueue, igual que el resto de este paquete evita
Redis real en tests (ver conftest.py, T5).

Requiere Docker y el binario ``nuclei`` (con plantillas ya descargadas —
``nuclei -update-templates``, una vez, no en cada corrida). Se salta entero
si cualquiera de los dos falta.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from src.modules.features.themis.lybra import nuclei_result_to_finding
from src.modules.features.themis.services.processors import NucleiResultProcessor

from ._docker_helpers import resolve_docker
from ._real_kb import seed_from_real_backfill
# pylint: disable=unused-import
# Las tres fixtures se usan por nombre (parámetro directo o
# request.getfixturevalue), que es como pytest las descubre — pylint no lo ve.
from .test_lybra_oracle_bench import (
    _run_self_discovery,
    httpd_2449_port,
    git_exposed_port,
    tls_healthy_port,
)

pytestmark = [pytest.mark.oracle, pytest.mark.integration]

_DOCKER = resolve_docker()
_NUCLEI = shutil.which("nuclei")

pytestmark.append(pytest.mark.skipif(_DOCKER is None, reason="Docker no disponible"))
pytestmark.append(pytest.mark.skipif(_NUCLEI is None, reason="Nuclei no disponible"))

# httpd_2449_port, git_exposed_port y tls_healthy_port son fixtures
# reimportadas tal cual del banco de verdad-por-etiqueta (mismo paquete): no
# hay ninguna razón para levantar contenedores duplicados solo porque este
# módulo mide algo distinto sobre ellos. "Sin etiqueta previa" (§8) describe
# el MÉTODO —la comparación no consulta la lista de CVEs que
# ``test_lybra_oracle_bench.py`` ya conoce, deriva su propia verdad de
# Nuclei—, no una exigencia de que el contenedor sea uno nuevo.


def _run_nuclei(target_url: str) -> list[dict]:
    """Lanza el binario real de Nuclei contra ``target_url`` y devuelve sus
    hallazgos ya traducidos a dicts de ``Finding`` (sin persistir nada).

    ``-pt http,ssl`` restringe los tipos de plantilla a los dos protocolos que
    estos objetivos hablan de verdad. Sin esto, Nuclei por defecto también
    ejecuta plantillas ``dns``/``tcp``/``javascript``/``code``/``headless`` —
    contra ``127.0.0.1`` eso significó sondear puerto 161/SNMP y ejecutar
    plantillas JS pesadas que no tienen nada que ver con lo que se está
    midiendo aquí, y disparó el primer intento muy por encima de los 180s.
    """
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "nuclei_oracle.jsonl"
        subprocess.run(
            [
                _NUCLEI, "-target", target_url,
                "-jsonl-export", str(output_path),
                "-duc", "-nc", "-silent",
                "-pt", "http,ssl",
                "-severity", "critical,high,medium,low",
                "-rate-limit", "50",
                "-timeout", "10",
            ],
            capture_output=True, text=True, timeout=300, check=False,
            # check=False: Nuclei devuelve código de salida no-cero cuando no
            # encuentra nada en algunos modos — el fichero de salida (o su
            # ausencia) es la señal real, igual que NucleiScanTask ya asume.
        )
        raw_results = NucleiResultProcessor().process(str(output_path))

    return [nuclei_result_to_finding(r, feed_version="oracle-differential") for r in raw_results]


def _cve_ids(findings) -> set[str]:
    """Extrae el conjunto de CVE de una lista de Finding (ORM rows o dicts)."""
    ids: set[str] = set()
    for f in findings:
        cve_ids = f.cve_ids if hasattr(f, "cve_ids") else f.get("cve_ids")
        if cve_ids:
            ids.update(cve_ids)
    return ids


def _differential_report(lybra_cves: set[str], nuclei_cves: set[str]) -> dict:
    """Compara dos conjuntos de CVE y arma el resumen que U3 pide medir.

    - ``corroborated``: CVE que ambos motores reportan de forma independiente
      — la señal más fuerte de que la detección es real.
    - ``lybra_only`` (posible falso positivo): Lybra los afirma, Nuclei no.
      No es automáticamente un falso positivo —Nuclei puede simplemente no
      tener plantilla para esa CVE— pero es exactamente la lista que un
      humano debe revisar, que es todo lo que un oráculo diferencial puede
      prometer (a diferencia de la verdad por etiqueta, que sí es una
      aserción dura).
    - ``nuclei_only`` (hallazgo que se escapa): Nuclei los encuentra, Lybra
      no — apunta a un hueco real en la KB o en la resolución de CPE.
    """
    return {
        "corroborated": sorted(lybra_cves & nuclei_cves),
        "lybra_only": sorted(lybra_cves - nuclei_cves),
        "nuclei_only": sorted(nuclei_cves - lybra_cves),
    }


@pytest.fixture(scope="module")
def real_kb(app):
    """Puebla la KB del test desde el backfill NVD real (ver ``_real_kb``).

    Sin esto la comparación es vacua: la mitad Lybra del diferencial no tiene
    ninguna CVE que consultar y devuelve el conjunto vacío, que se lee como
    "acuerdo perfecto" cuando en realidad no se midió nada. Se salta el módulo
    entero si el Postgres con el backfill no está levantado, por la misma razón.
    """
    with app.app_context():
        copied = seed_from_real_backfill()
    if copied is None:
        pytest.skip("El Postgres con el backfill real de NVD no está disponible")
    print(f"\n[oráculo diferencial] KB del banco poblada con {copied} CVE reales")
    return copied


@pytest.mark.parametrize("fixture_name,url_template", [
    ("httpd_2449_port", "http://127.0.0.1:{port}"),
    ("git_exposed_port", "http://127.0.0.1:{port}"),
    ("tls_healthy_port", "https://127.0.0.1:{port}"),
])
def test_differential_oracle_against_three_unlabeled_targets(
    request, app, admin_user, monkeypatch, real_kb, fixture_name, url_template,
):
    """El banco diferencial de U3: por cada uno de los (al menos) tres
    objetivos, compara Lybra contra Nuclei y deja el desglose en el resumen
    del test (visible con ``-s`` o en un fallo) — la definición de hecho de
    la Fase U pide "un número", no una aserción binaria por objetivo."""
    port = request.getfixturevalue(fixture_name)

    lybra_findings = _run_self_discovery(app, admin_user, "127.0.0.1", port, monkeypatch)
    nuclei_findings = _run_nuclei(url_template.format(port=port))

    report = _differential_report(_cve_ids(lybra_findings), _cve_ids(nuclei_findings))
    print(f"\n[oráculo diferencial] {fixture_name}: {report}")

    # No hay aserción por CVE concreto a propósito (ver docstring del módulo):
    # el punto de este banco es medir el desacuerdo, no prescribirlo. La única
    # invariante dura es que ningún CVE aparezca en dos columnas a la vez —
    # una violación indicaría un bug en el propio cálculo del diff, no en el
    # motor.
    assert not set(report["lybra_only"]) & set(report["nuclei_only"])
    assert not set(report["corroborated"]) & set(report["lybra_only"])
    assert not set(report["corroborated"]) & set(report["nuclei_only"])


def test_nuclei_translator_pipeline_corroborates_a_real_exposure(git_exposed_port):
    """Guarda de cordura del mecanismo (subproceso → JSONL → traductor), NO
    del acuerdo CVE-a-CVE que miden los tests de arriba.

    Se probó primero con CVE-2021-41773 (la plantilla más veterana del
    repositorio para este contenedor) y falló, mostrando algo real: la
    plantilla de Nuclei es una explotación activa (RCE vía ``mod_cgi``) que
    exige un ``ExecCGI`` habilitado que ni la imagen vanilla ``httpd:2.4.49``
    ni siquiera ``vulhub/httpd:2.4.49`` traen listo con un ``docker run``
    suelto (vulhub monta configuración extra vía ``docker-compose`` que este
    banco no reproduce) — mientras que la detección de Lybra es por
    versión/banner, no por explotación. Corroborar esa CVE necesitaría un
    contenedor genuinamente explotable, no solo de la versión correcta; son
    señales distintas y no siempre van a coincidir, que es precisamente el
    tipo de hecho que un oráculo diferencial existe para sacar a la luz.

    La exposición de ``.git/config`` sí es una señal puramente pasiva en
    ambos lados —Nuclei solo hace un GET y compara el contenido, igual que
    el check propio de Lybra— así que sirve de guarda de cordura fiable y
    rápida sin depender de que un exploit dispare de verdad.
    """
    output = _run_nuclei(f"http://127.0.0.1:{git_exposed_port}")

    git_findings = [f for f in output if f["check_id"].startswith("nuclei:git-config")]
    assert git_findings, f"la plantilla git-config de Nuclei no disparó — resultados: {output}"
    assert git_findings[0]["confirmed"] is True
