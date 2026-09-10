"""Unit tests del clasificador de ingestibilidad de plantillas.

Puro: cada test construye una plantilla a mano, así que nada aquí necesita el
feed real de Nuclei. Lo que se verifica es el *criterio* — qué cuenta como
obstáculo y en qué cubo cae cada cosa —, no el número del censo, que solo puede
medirse en una máquina con las plantillas instaladas.

El clasificador es compartido a propósito entre el censo del feed instalado y
la ingesta de plantillas: si midieran con criterios distintos, el número no
describiría lo que la ingesta acabaría haciendo.
"""

import pytest

from src.modules.features.themis.lybra.ingest import (
    Bucket,
    classify_template,
    is_ingestible,
    summarize,
)

pytestmark = pytest.mark.unit


def _http_template(request: dict, **root) -> dict:
    return {
        "id": root.pop("id", "some-template"),
        "info": {"name": "X", "severity": root.pop("severity", "high")},
        "http": [request],
        **root,
    }


_SIMPLE_REQUEST = {
    "method": "GET",
    "path": ["{{BaseURL}}/.git/config"],
    "matchers-condition": "and",
    "matchers": [
        {"type": "status", "status": [200]},
        {"type": "word", "part": "body", "words": ["[core]"]},
    ],
}


# ------------------------------------------------------------ ingerible ya

def test_a_plain_status_and_word_template_is_ingestible_now():
    profile = classify_template(_http_template(_SIMPLE_REQUEST))

    assert profile.bucket is Bucket.INGESTIBLE_NOW
    assert profile.blockers == set()
    assert profile.protocol == "http"
    assert profile.matcher_types == {"status", "word"}
    assert profile.request_count == 1


def test_the_requests_alias_is_recognised_as_http():
    """Nuclei acepta `requests:` como alias histórico de `http:`."""
    template = {"id": "x", "info": {"severity": "low"}, "requests": [_SIMPLE_REQUEST]}
    assert classify_template(template).protocol == "http"


def test_base_url_interpolation_does_not_count_as_a_blocker():
    """Aparece en casi toda plantilla HTTP y el runtime ya la resuelve; contarla
    marcaría el feed entero como no ingerible por algo que ya funciona."""
    profile = classify_template(_http_template(_SIMPLE_REQUEST))
    assert "interpolacion" not in profile.blockers


def test_regex_matchers_are_supported():
    request = {**_SIMPLE_REQUEST, "matchers": [{"type": "regex", "regex": ["^root:"]}]}
    assert classify_template(_http_template(request)).bucket is Bucket.INGESTIBLE_NOW


# ------------------------------------------------------------- extractors

def test_extractors_land_in_their_own_bucket():
    request = {**_SIMPLE_REQUEST, "extractors": [{"type": "regex", "regex": ["v[0-9.]+"]}]}
    profile = classify_template(_http_template(request))

    assert profile.bucket is Bucket.NEEDS_EXTRACTORS
    assert profile.blockers == {"extractors"}


def test_real_interpolation_lands_in_the_extractor_bucket():
    request = {**_SIMPLE_REQUEST, "path": ["{{BaseURL}}/{{username}}/profile"]}
    profile = classify_template(_http_template(request))

    assert profile.bucket is Bucket.NEEDS_EXTRACTORS
    assert profile.blockers == {"interpolacion"}


# -------------------------------------------------- payloads / binario / dsl

def test_payloads_land_in_the_heavier_bucket():
    request = {**_SIMPLE_REQUEST, "payloads": {"user": ["admin"]}, "attack": "clusterbomb"}
    profile = classify_template(_http_template(request))

    assert profile.bucket is Bucket.NEEDS_PAYLOADS_OR_BINARY
    assert "payloads" in profile.blockers


def test_dsl_matcher_is_a_blocker():
    request = {**_SIMPLE_REQUEST, "matchers": [{"type": "dsl", "dsl": ["len(body) > 10"]}]}
    profile = classify_template(_http_template(request))

    assert profile.bucket is Bucket.NEEDS_PAYLOADS_OR_BINARY
    assert "matcher:dsl" in profile.blockers


def test_hex_input_is_counted_separately():
    """Es justo lo que desbloquearía los checks de SMB que hoy no se pueden
    construir sin entrada binaria, así que interesa poder contarlo aparte en
    el histograma."""
    template = {
        "id": "smb-thing",
        "info": {"severity": "medium"},
        "network": [{
            "inputs": [{"data": "00000085ff534d42", "type": "hex"}],
            "matchers": [{"type": "binary", "binary": ["fe534d42"]}],
        }],
    }
    profile = classify_template(template)

    assert profile.protocol == "network"
    assert profile.bucket is Bucket.NEEDS_PAYLOADS_OR_BINARY
    assert "input-hex" in profile.blockers
    assert "matcher:binary" in profile.blockers


def test_condition_inside_a_matcher_is_a_blocker():
    """`Matcher._raw_match` fija any() sobre las palabras: un "and" interno
    cambiaría el resultado en silencio en vez de fallar."""
    request = {
        **_SIMPLE_REQUEST,
        "matchers": [{"type": "word", "words": ["a", "b"], "condition": "and"}],
    }
    assert "matcher-condition-interna" in classify_template(_http_template(request)).blockers


def test_condition_between_requests_is_a_blocker():
    request = {**_SIMPLE_REQUEST, "req-condition": True}
    assert "condicion-entre-peticiones" in classify_template(_http_template(request)).blockers


def test_matchers_condition_between_matchers_is_supported():
    """A diferencia del `condition` interno: el runtime ya combina con and/or."""
    request = {**_SIMPLE_REQUEST, "matchers-condition": "or"}
    assert classify_template(_http_template(request)).bucket is Bucket.INGESTIBLE_NOW


# ----------------------------------------------------- descartadas / fuera

@pytest.mark.parametrize("key", ["code", "flow", "javascript"])
def test_scripting_templates_are_rejected_by_design(key):
    template = {"id": "x", "info": {"severity": "high"}, key: "whatever"}
    profile = classify_template(template)

    assert profile.bucket is Bucket.REJECTED_BY_DESIGN
    assert profile.blockers == {f"protocolo:{key}"}


@pytest.mark.parametrize("key", ["dns", "headless", "whois", "file"])
def test_unsupported_protocols_are_out_of_scope(key):
    template = {"id": "x", "info": {"severity": "info"}, key: [{}]}
    assert classify_template(template).bucket is Bucket.OUT_OF_SCOPE


def test_a_template_with_no_recognisable_protocol_is_out_of_scope():
    assert classify_template({"id": "x", "info": {}}).bucket is Bucket.OUT_OF_SCOPE


def test_scripting_wins_over_a_present_http_block():
    """Una plantilla con `code:` se descarta aunque además declare http."""
    template = {"id": "x", "info": {}, "http": [_SIMPLE_REQUEST], "code": "..."}
    assert classify_template(template).bucket is Bucket.REJECTED_BY_DESIGN


# --------------------------------------------------- el cubo del peor caso

def test_a_template_falls_in_the_bucket_of_its_worst_blocker():
    request = {
        **_SIMPLE_REQUEST,
        "extractors": [{"type": "regex", "regex": ["x"]}],
        "payloads": {"u": ["a"]},
    }
    profile = classify_template(_http_template(request))

    assert profile.blockers == {"extractors", "payloads"}
    assert profile.bucket is Bucket.NEEDS_PAYLOADS_OR_BINARY


# ------------------------------------------------------ is_ingestible / resumen

def test_is_ingestible_is_strict():
    assert is_ingestible(_http_template(_SIMPLE_REQUEST)) is True
    with_extractors = {**_SIMPLE_REQUEST, "extractors": [{"type": "regex", "regex": ["x"]}]}
    assert is_ingestible(_http_template(with_extractors)) is False


def test_summarize_reports_the_number_that_decides_phase_r():
    profiles = [
        classify_template(_http_template(_SIMPLE_REQUEST, id="a")),
        classify_template(_http_template(_SIMPLE_REQUEST, id="b")),
        classify_template(_http_template(
            {**_SIMPLE_REQUEST, "payloads": {"u": ["a"]}}, id="c"
        )),
        classify_template({"id": "d", "info": {}, "code": "..."}),
    ]

    summary = summarize(profiles)

    assert summary["total"] == 4
    assert summary["by_bucket"]["ingestible_now"] == 2
    assert summary["by_bucket"]["rejected_by_design"] == 1
    # 2 de 3 plantillas HTTP: la de `code` no cuenta como HTTP.
    assert summary["http_total"] == 3
    assert summary["http_ingestible_now"] == 2
    assert summary["http_ingestible_pct"] == pytest.approx(66.67, abs=0.01)


def test_summarize_handles_an_empty_census_without_dividing_by_zero():
    summary = summarize([])
    assert summary["total"] == 0
    assert summary["http_ingestible_pct"] == 0.0
