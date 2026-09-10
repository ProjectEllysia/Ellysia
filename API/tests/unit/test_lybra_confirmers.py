"""El encadenamiento versión → confirmador.

Es lo más diferencial del motor: la razón de existir del runtime propio frente
a Nuclei. Convierte
una hipótesis ``confirmed=false, qod=70`` —que puede ser un falso positivo por
backport— en un hecho verificado, que es lo que separa un informe entregable de
uno que hay que revisar a mano.

Dos garantías, y la segunda es la que lo hace seguro: un confirmador **sólo
corre si su CVE ya fue propuesta**, y **nunca explota**.
"""

import pytest

from src.modules.features.themis.lybra.checks import (
    CheckRuntime,
    Response,
    Service,
    load_checks,
    validate_checks,
)
from src.modules.features.themis.lybra.correlation import compute_dedup_key, merge_findings

pytestmark = pytest.mark.unit

_HTTP = Service(80, "tcp", "http", "apache", "2.4.49", None)
_CHECKS = load_checks()
_CVE = "CVE-2021-41773"
_TRAVERSAL_PATH = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"


def _vulnerable_fetch(host, port, method, path):
    """Un Apache 2.4.49 que sirve /etc/passwd por la ruta vulnerable."""
    if path == _TRAVERSAL_PATH:
        return Response(200, "root:x:0:0:root:/root:/bin/bash\n", {})
    return Response(404, "", {})


def _fired(fetch, proposed_cves):
    findings = CheckRuntime(_CHECKS, fetch).run(
        "10.0.0.5", [_HTTP], proposed_cves=frozenset(proposed_cves))
    return {f["check_id"].split(":")[1].split("@")[0] for f in findings}


# =============================================== el gating: la garantía central


def test_a_confirmer_does_not_run_without_its_cve_proposed():
    """Un confirmador nunca corre 'por si acaso'. Aunque el objetivo sea
    vulnerable, sin la hipótesis del matcher de versiones el confirmador ni se
    intenta — es la diferencia con un check normal."""
    fired = _fired(_vulnerable_fetch, proposed_cves=frozenset())
    assert "apache-cve-2021-41773-path-traversal" not in fired


def test_a_confirmer_runs_when_its_cve_was_proposed():
    """Con la CVE ya propuesta, el confirmador corre y —contra un objetivo
    vulnerable— dispara."""
    fired = _fired(_vulnerable_fetch, proposed_cves={_CVE})
    assert "apache-cve-2021-41773-path-traversal" in fired


def test_a_confirmer_whose_cve_was_proposed_but_target_is_safe_does_not_fire():
    """Propuesta la CVE, pero el objetivo NO es vulnerable (ya parcheado): el
    confirmador corre y no dispara. Es justamente el falso positivo por backport
    que este mecanismo existe para descartar."""
    def patched_fetch(host, port, method, path):
        return Response(404, "Not Found", {})       # la ruta ya no traversa

    fired = _fired(patched_fetch, proposed_cves={_CVE})
    assert "apache-cve-2021-41773-path-traversal" not in fired


# =============================================== el ascenso hipótesis → hecho


def test_the_confirmer_promotes_the_hypothesis_on_merge():
    """El salto que separa un informe entregable de uno por revisar: la
    hipótesis (qod 70, confirmed false) y el confirmador (qod 99, confirmed
    true) comparten dedup_key y merge_findings los funde en uno solo, ascendido.
    """
    hypothesis = {
        "host_id": 1, "port": 80, "cve_ids": [_CVE],
        "confirmed": False, "qod": 70, "source": "lybra",
        "check_id": "lybra:outdated@1",
    }
    confirmation = {
        "host_id": 1, "port": 80, "cve_ids": [_CVE],
        "confirmed": True, "qod": 99, "source": "lybra",
        "check_id": "lybra:apache-cve-2021-41773-path-traversal@1",
    }
    # Comparten identidad de vulnerabilidad (la CVE), luego el mismo dedup_key.
    assert compute_dedup_key(hypothesis) == compute_dedup_key(confirmation)

    merged = merge_findings([hypothesis, confirmation])
    assert len(merged) == 1
    assert merged[0]["confirmed"] is True
    assert merged[0]["qod"] == 99
    assert merged[0]["cve_ids"] == [_CVE]


def test_the_confirmer_finding_carries_its_cve_for_the_merge():
    """Para que el ascenso funcione, el confirmador debe emitir la CVE en
    cve_ids —si no, su dedup_key no coincidiría con la hipótesis y quedarían dos
    hallazgos sueltos en vez de uno ascendido."""
    findings = CheckRuntime(_CHECKS, _vulnerable_fetch).run(
        "10.0.0.5", [_HTTP], proposed_cves={_CVE})
    confirmer = next(
        f for f in findings
        if f["check_id"] == "lybra:apache-cve-2021-41773-path-traversal@1")
    assert confirmer["cve_ids"] == [_CVE]
    assert confirmer["confirmed"] is True


# ============================================================= validación


def test_the_feed_confirmers_are_well_formed():
    confirmers = [c for c in _CHECKS if c.confirms]
    assert len(confirmers) >= 2
    assert validate_checks(_CHECKS) == []
    for check in confirmers:
        assert check.confirms.startswith("CVE-")


def test_a_confirmer_with_a_malformed_cve_is_reported():
    """Sin este bloque, un `confirms: not-a-cve` se colaría y su dedup_key nunca
    casaría con ninguna hipótesis — un confirmador que no confirma nada."""
    from dataclasses import replace

    good = next(c for c in _CHECKS if c.confirms)
    broken = replace(good, confirms="no-es-una-cve")
    assert any("confirms" in problem for problem in validate_checks([broken]))
