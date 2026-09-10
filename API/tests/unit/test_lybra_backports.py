"""Verificación de backports contra la palabra del proveedor.

Un backport es una distribución corrigiendo un fallo sin subir el número de
versión visible: Debian parchea `apache2`, el banner sigue diciendo `2.4.49`, y
el motor emite una CVE que ya no existe. La tasa medida es **0,42**:
cuatro de cada diez CVEs reportados contra un Debian o un Ubuntu ya estaban
corregidos.

Lo que se fija aquí es sobre todo **cuándo no se toca nada**. Bajar un hallazgo
por una suposición cambiaría falsos positivos por falsos negativos, que en un
escáner es el peor negocio posible.
"""

from __future__ import annotations

import pytest

from src.modules.features.themis.lybra.backports import (
    BACKPORT_CHECK_ID, apply_backport_verdicts,
)
from src.modules.features.themis.lybra.distro import infer_distro_release

pytestmark = pytest.mark.unit


def _finding(**overrides) -> dict:
    base = {
        "category": "outdated_software",
        "title": "apache2 2.4.49 — CVE-2021-41773",
        "cve_ids": ["CVE-2021-41773"],
        "confirmed": False,
        "qod": 70,
        "state": "open",
        "check_id": "lybra:version-match@1",
        "_installed_version": "2.4.49-1~deb11u1",
        "_package_name": "apache2",
    }
    base.update(overrides)
    return base


def _says(status, fixed_in=None):
    return lambda *_args: (status, fixed_in)


# ───────────────────────────────── el desmentido

def test_a_backported_package_is_marked_fixed():
    findings = apply_backport_verdicts(
        [_finding()], _says("fixed", "2.4.49-1~deb11u1"))

    assert findings[0]["state"] == "fixed"
    assert findings[0]["confirmed"] is False
    assert findings[0]["check_id"] == BACKPORT_CHECK_ID


def test_a_host_behind_the_fix_is_not_absolved():
    """Que Debian lo corrigiera en `-1~deb11u2` no dice nada bueno de un host
    que sigue en `-1~deb11u1`. Sin esta comparación, la verificación
    desmentiría hallazgos legítimos — peor que no tenerla."""
    findings = apply_backport_verdicts(
        [_finding(_installed_version="2.4.49-1~deb11u1")],
        _says("fixed", "2.4.49-1~deb11u2"))

    assert findings[0]["state"] == "open"
    assert findings[0]["check_id"] == "lybra:version-match@1"


# ───────────────────────────────── la confirmación

def test_a_vendor_confirming_the_flaw_promotes_the_finding():
    """Dos fuentes independientes coinciden: la versión y el propio
    empaquetador. Eso es mucho más que una deducción."""
    findings = apply_backport_verdicts([_finding()], _says("vulnerable"))

    assert findings[0]["confirmed"] is True
    assert findings[0]["qod"] == 90
    assert findings[0]["state"] == "open"


# ───────────────────────────────── cuándo no se toca nada

def test_a_package_with_no_distro_is_left_alone():
    """Un binario compilado a mano no pertenece a ninguna distribución, y es
    justo el caso donde la vulnerabilidad sí existe."""
    called = []

    def lookup(*args):
        called.append(args)
        return ("fixed", "2.4.50")

    findings = apply_backport_verdicts(
        [_finding(_installed_version="2.4.49", title="Apache 2.4.49 — CVE-2021-41773")],
        lookup)

    assert called == [], "no había distribución: no había a quién preguntar"
    assert findings[0]["state"] == "open"


def test_a_vendor_that_has_not_spoken_changes_nothing():
    """`None` no significa "está a salvo": significa que no consta."""
    findings = apply_backport_verdicts([_finding()], lambda *_a: None)
    assert findings[0]["state"] == "open"
    assert findings[0]["confirmed"] is False


def test_an_unknown_status_changes_nothing():
    """El proveedor conoce el paquete pero no se pronuncia. Traducirlo a
    cualquiera de los otros dos estados sería inventar."""
    findings = apply_backport_verdicts([_finding()], _says("unknown"))
    assert findings[0]["state"] == "open"


def test_findings_that_are_not_version_matches_are_ignored():
    """Un puerto abierto o una cabecera ausente no nacen de comparar versiones,
    así que ningún backport puede desmentirlos."""
    other = {"category": "open_port", "title": "80/tcp abierto", "state": "open"}
    findings = apply_backport_verdicts([dict(other)], _says("fixed", "9.9.9"))
    assert findings[0] == other


def test_a_version_finding_without_cves_is_ignored():
    findings = apply_backport_verdicts([_finding(cve_ids=[])], _says("fixed", "9.9.9"))
    assert findings[0]["state"] == "open"


# ───────────────────────────── de qué distribución es esto

@pytest.mark.parametrize("version,vendor,release", [
    ("1:2.4.49-1~deb11u1", "debian", "11"),
    ("2.4.49-1ubuntu1", "ubuntu", None),
    ("2.4.37-43.el8", "rhel", "8"),
    ("2.4.49-r0", "alpine", None),
])
def test_the_package_revision_names_its_distribution(version, vendor, release):
    """La señal más fuerte no es el banner sino la revisión: sólo la escribe
    quien empaqueta, así que no admite ambigüedad."""
    inferred = infer_distro_release(version)
    assert inferred is not None
    assert (inferred.vendor, inferred.release) == (vendor, release)


def test_the_banner_answers_when_the_version_does_not():
    assert infer_distro_release("2.4.49", "Apache/2.4.49 (Ubuntu)").vendor == "ubuntu"


def test_nothing_is_inferred_from_a_plain_version():
    assert infer_distro_release("2.4.49", "Apache httpd") is None
