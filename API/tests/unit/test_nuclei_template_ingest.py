"""Unit tests del traductor y el selector de plantillas ingeridas (Fase R).

Puro: plantillas escritas a mano, sin feed real y sin red. Se verifica el
*criterio* de traducción y de selección, no el comportamiento contra objetivos
reales, que exige el equipo con el binario y las plantillas instaladas.
"""

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.themis.lybra import CheckRuntime, Response, Service
from src.modules.features.themis.lybra.ingest import (
    DEFAULT_MIN_SEVERITY,
    is_relevant,
    select_for_services,
    translate_all,
    translate_template,
)

pytestmark = pytest.mark.unit

_FEED_VERSION = "nuclei-templates-v9.9.9"

_GIT_CONFIG_TEMPLATE = {
    "id": "git-config",
    "info": {
        "name": "Git Configuration Exposure",
        "severity": "high",
        "tags": ["config", "exposure", "git"],
        "classification": {"cve-id": "cve-2021-9999"},
    },
    "http": [{
        "method": "GET",
        "path": ["{{BaseURL}}/.git/config"],
        "matchers-condition": "and",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]"]},
        ],
    }],
}


# ------------------------------------------------------------------ traductor

def test_translates_a_simple_http_template():
    check = translate_template(_GIT_CONFIG_TEMPLATE, _FEED_VERSION)

    assert check is not None
    assert check.id == "git-config"
    assert check.type == "http"
    assert check.severity == "HIGH"
    assert check.requests[0].path == "/.git/config"     # {{BaseURL}} despojado
    assert check.requests[0].method == "GET"
    assert len(check.requests[0].matchers) == 2


def test_a_translated_check_does_not_claim_to_be_ours():
    """Procedencia, no autoría: el check_id dice de dónde viene."""
    check = translate_template(_GIT_CONFIG_TEMPLATE, _FEED_VERSION)

    assert check.namespace == "nuclei"
    assert check.check_id == "nuclei:git-config@1"
    assert check.feed_version == _FEED_VERSION


def test_the_feed_version_of_the_tree_reaches_the_finding():
    """Sin esto el hallazgo no sería reproducible (garantía del §9 del roadmap)."""
    check = translate_template(_GIT_CONFIG_TEMPLATE, _FEED_VERSION)
    fetch = lambda host, port, method, path: Response(200, "[core]", {})  # noqa: E731
    findings = CheckRuntime([check], fetch).run("h", [Service(80, "tcp", "http", "", "", None)])

    assert len(findings) == 1
    assert findings[0]["feed_version"] == _FEED_VERSION
    assert findings[0]["check_id"] == "nuclei:git-config@1"


def test_first_party_checks_keep_their_own_namespace_and_feed_version():
    """El default preserva el comportamiento anterior sin tocar el feed propio."""
    from src.modules.features.themis.lybra import CHECKS_FEED_VERSION, load_checks

    git = next(c for c in load_checks() if c.id == "git-config-exposure")
    assert git.namespace == "lybra"
    assert git.check_id == "lybra:git-config-exposure@1"
    assert git.feed_version is None

    fetch = lambda host, port, method, path: Response(200, "[core] repositoryformatversion", {})  # noqa: E731
    findings = CheckRuntime([git], fetch).run("h", [Service(80, "tcp", "http", "", "", None)])
    assert findings[0]["feed_version"] == CHECKS_FEED_VERSION


def test_cve_ids_are_upper_cased():
    """Sin normalizar el caso, la fusión por dedup_key con la KB nunca ocurriría."""
    check = translate_template(_GIT_CONFIG_TEMPLATE, _FEED_VERSION)
    assert check.finding["cve_ids"] == ["CVE-2021-9999"]


def test_external_templates_are_always_safe_mode():
    """No las hemos revisado una a una: no se les concede el modo agresivo."""
    template = {**_GIT_CONFIG_TEMPLATE, "info": {**_GIT_CONFIG_TEMPLATE["info"]}}
    check = translate_template(template, _FEED_VERSION)
    assert check.mode == "safe"


def test_a_non_ingestible_template_is_rejected_rather_than_half_translated():
    """Traducir a medias produciría un check que corre y comprueba otra cosa."""
    with_payloads = {
        **_GIT_CONFIG_TEMPLATE,
        "http": [{**_GIT_CONFIG_TEMPLATE["http"][0], "payloads": {"u": ["a"]}}],
    }
    assert translate_template(with_payloads, _FEED_VERSION) is None


def test_a_multi_path_template_is_rejected():
    """Nuclei dispara si ALGUNA ruta casa; el runtime combinaría con AND.

    Traducirla cambiaría su significado a uno más estricto que casi nunca
    dispararía, así que se descarta.
    """
    multi = {
        **_GIT_CONFIG_TEMPLATE,
        "http": [{
            **_GIT_CONFIG_TEMPLATE["http"][0],
            "path": ["{{BaseURL}}/.git/config", "{{BaseURL}}/.git/HEAD"],
        }],
    }
    assert translate_template(multi, _FEED_VERSION) is None


def test_a_template_without_an_id_is_rejected():
    assert translate_template({**_GIT_CONFIG_TEMPLATE, "id": ""}, _FEED_VERSION) is None


def test_a_template_without_matchers_is_rejected():
    """Un Request sin matchers nunca dispara: sería un check muerto que cuesta
    una petición contra el objetivo."""
    empty = {
        **_GIT_CONFIG_TEMPLATE,
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers": []}],
    }
    assert translate_template(empty, _FEED_VERSION) is None


def test_translate_all_skips_what_it_cannot_translate():
    templates = [
        _GIT_CONFIG_TEMPLATE,
        {"id": "scripted", "info": {"severity": "high"}, "code": "..."},
        {"id": "no-protocol", "info": {"severity": "low"}},
    ]
    checks = translate_all(templates, _FEED_VERSION)
    assert [c.id for c in checks] == ["git-config"]


def test_relevance_tags_gather_product_metadata():
    template = {
        **_GIT_CONFIG_TEMPLATE,
        "info": {
            **_GIT_CONFIG_TEMPLATE["info"],
            "metadata": {"vendor": "Apache", "product": "HTTP_Server"},
        },
    }
    check = translate_template(template, _FEED_VERSION)
    assert "apache" in check.tags and "http_server" in check.tags


# ------------------------------------------------------------------- selector

def _check(check_id, severity="HIGH", tags=()):
    return translate_template(
        {
            "id": check_id,
            "info": {"name": check_id, "severity": severity.lower(), "tags": list(tags)},
            "http": [{
                "method": "GET",
                "path": ["{{BaseURL}}/x"],
                "matchers": [{"type": "status", "status": [200]}],
            }],
        },
        _FEED_VERSION,
    )


_NGINX = Service(80, "tcp", "http", "nginx", "1.18", None)


def test_a_product_specific_check_is_skipped_for_another_product():
    wordpress = _check("wp-thing", tags=["wordpress", "cve"])
    assert is_relevant(wordpress, {"nginx", "http"}) is False


def test_a_generic_check_always_runs():
    """Sin etiquetas de producto es genérico (una ruta, una cabecera): descartarlo
    perdería justo los más aplicables."""
    generic = _check("exposed-path", tags=["exposure", "config"])
    assert is_relevant(generic, {"nginx"}) is True


def test_a_matching_product_check_runs():
    nginx_check = _check("nginx-thing", tags=["nginx", "cve"])
    assert is_relevant(nginx_check, {"nginx", "http"}) is True


def test_selection_filters_by_severity_floor():
    checks = [_check("a", "INFO"), _check("b", "LOW"), _check("c", "HIGH")]
    selected = select_for_services(checks, [_NGINX], min_severity=DEFAULT_MIN_SEVERITY)
    assert [c.id for c in selected] == ["c"]


def test_selection_applies_the_hard_cap_keeping_the_worst_first():
    checks = [_check("low-one", "LOW"), _check("crit", "CRITICAL"), _check("med", "MEDIUM")]
    selected = select_for_services(checks, [_NGINX], min_severity="LOW", max_checks=2)

    assert [c.id for c in selected] == ["crit", "med"]   # lo que se pierde es lo menos grave


def test_selection_drops_irrelevant_products():
    checks = [_check("wp", tags=["wordpress"]), _check("generic", tags=["exposure"])]
    selected = select_for_services(checks, [_NGINX])
    assert [c.id for c in selected] == ["generic"]


def test_selection_of_an_empty_feed_is_empty():
    assert select_for_services([], [_NGINX]) == []


# --------------------------------------------------- cableado en el manager

def test_ingest_is_disabled_by_default():
    """El código existe; la activación la decide el número del censo (U4).

    Mientras el flag esté apagado, el motor corre exactamente con su feed
    propio — la ingesta no puede cambiar el comportamiento de nadie por
    accidente.
    """
    import src.modules.system.config_reading as CR
    assert CR.lybra_ingest_config().enabled is False


def test_manager_skips_ingestion_entirely_when_disabled(monkeypatch):
    """Con el flag apagado no se toca ni el almacén de plantillas."""
    from src.modules.features.themis.managers.lybra.engine import LybraEngineManager

    def _explode():
        raise AssertionError("no debería construirse el almacén con la ingesta apagada")

    monkeypatch.setattr(
        "src.modules.features.themis.managers.lybra.engine.NucleiTemplateStore", _explode
    )
    assert LybraEngineManager._ingested_checks(object(), [_NGINX]) == []


def test_manager_falls_back_to_the_own_feed_when_the_tree_is_missing(monkeypatch):
    """Activar la ingesta sin plantillas instaladas avisa, no revienta el escaneo."""
    from src.modules.features.themis.managers.lybra.engine import LybraEngineManager

    class _EmptyStore:
        is_available = False

    monkeypatch.setattr(
        "src.modules.features.themis.managers.lybra.engine.CR.lybra_ingest_config",
        lambda: CR.LybraIngestConfig(enabled=True),
    )
    monkeypatch.setattr(
        "src.modules.features.themis.managers.lybra.engine.NucleiTemplateStore",
        lambda: _EmptyStore(),
    )
    assert LybraEngineManager._ingested_checks(object(), [_NGINX]) == []
