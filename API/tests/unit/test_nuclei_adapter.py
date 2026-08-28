"""Unit tests for the Nuclei -> Finding adapter (roadmap Fase U1).

Pure functions over dicts (one decoded JSONL line) — no DB, no subprocess.
"""

import pytest

from src.modules.features.themis.lybra.adapters import nuclei_result_to_finding, finding_to_json, QOD_NUCLEI_MATCH

pytestmark = pytest.mark.unit


def _result(**overrides):
    base = {
        "template-id": "CVE-2021-41773",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "critical",
            "tags": ["cve", "apache", "kev"],
            "classification": {
                "cve-id": ["cve-2021-41773"],
                "cvss-score": 9.8,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "epss-score": 0.97,
            },
        },
        "type": "http",
        "host": "https://example.com:8443",
        "matched-at": "https://example.com:8443/icons/.%2e/%2e%2e/etc/passwd",
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------------- CVE case

def test_cve_ids_normalized_to_uppercase():
    """compute_dedup_key hashes 'cve:' + sorted(cve_ids) — Nuclei's own
    lowercase ids would never merge with Lybra's uppercase ones
    without this normalization (the Definición de Hecho of Fase U1)."""
    f = nuclei_result_to_finding(_result())
    assert f["cve_ids"] == ["CVE-2021-41773"]


def test_no_cve_ids_when_classification_empty():
    f = nuclei_result_to_finding(_result(info={"name": "x", "severity": "info", "tags": []}))
    assert f["cve_ids"] is None


# ------------------------------------------------------------------- confirmed/qod

def test_always_confirmed_with_fixed_qod():
    """A Nuclei matcher is a structured assertion, not a text-pattern
    heuristic like Nikto's — always actively confirmed."""
    f = nuclei_result_to_finding(_result())
    assert f["confirmed"] is True
    assert f["qod"] == QOD_NUCLEI_MATCH == 90


# ------------------------------------------------------------------- CVSS fallback

@pytest.mark.parametrize("severity,expected", [
    ("critical", 9.5), ("high", 8.0), ("medium", 5.5), ("low", 3.0), ("info", None),
])
def test_cvss_falls_back_to_severity_band_without_classification_score(severity, expected):
    f = nuclei_result_to_finding(_result(info={
        "name": "Exposed .env file", "severity": severity, "tags": [],
    }))
    assert f["cvss_score"] == expected


def test_cvss_score_from_classification_takes_priority_over_severity():
    f = nuclei_result_to_finding(_result())
    assert f["cvss_score"] == 9.8


# ------------------------------------------------------------------- KEV

def test_in_kev_true_when_kev_tag_present():
    f = nuclei_result_to_finding(_result())
    assert f["in_kev"] is True


def test_in_kev_false_without_kev_tag():
    f = nuclei_result_to_finding(_result(info={
        "name": "x", "severity": "medium", "tags": ["misconfig"],
    }))
    assert f["in_kev"] is False


# ------------------------------------------------------------------- port extraction

def test_port_parsed_from_matched_at_when_no_explicit_port():
    f = nuclei_result_to_finding(_result())
    assert f["port"] == 8443


def test_port_falls_back_to_host_when_matched_at_has_no_port():
    f = nuclei_result_to_finding(_result(host="https://example.com:9000", **{"matched-at": None}))
    assert f["port"] == 9000


def test_port_none_when_nothing_resolvable():
    f = nuclei_result_to_finding({
        "template-id": "generic-detect", "info": {"name": "x", "severity": "info", "tags": []},
        "type": "http", "host": "example.com", "matched-at": "example.com",
    })
    assert f["port"] is None


def test_explicit_port_field_used_when_present():
    f = nuclei_result_to_finding(_result(port="443"))
    assert f["port"] == 443


# ------------------------------------------------------------------- title / check_id

def test_title_falls_back_to_template_id_without_info_name():
    f = nuclei_result_to_finding(_result(info={"severity": "medium", "tags": []}))
    assert f["title"] == "CVE-2021-41773"


def test_check_id_is_namespaced_by_template_id():
    f = nuclei_result_to_finding(_result())
    assert f["check_id"] == "nuclei:CVE-2021-41773"


def test_check_id_unknown_when_template_id_missing():
    f = nuclei_result_to_finding({"info": {"name": "x", "severity": "info", "tags": []}, "type": "http"})
    assert f["check_id"] == "nuclei:unknown"


# ------------------------------------------------------------------- category

def test_category_outdated_software_when_cve_present():
    f = nuclei_result_to_finding(_result())
    assert f["category"] == "outdated_software"


@pytest.mark.parametrize("template_type,expected_category", [
    ("http", "web_finding"), ("ssl", "tls"), ("tls", "tls"), ("dns", "vulnerability"),
])
def test_category_from_type_without_cve(template_type, expected_category):
    f = nuclei_result_to_finding(_result(
        type=template_type, info={"name": "x", "severity": "low", "tags": []},
    ))
    assert f["category"] == expected_category


# ------------------------------------------------------------------- misc fields

def test_source_and_feed_version():
    f = nuclei_result_to_finding(_result(), feed_version="nuclei-templates-9.9.9")
    assert f["source"] == "nuclei"
    assert f["feed_version"] == "nuclei-templates-9.9.9"
    assert f["state"] == "open"


def test_feed_version_defaults_when_not_provided():
    f = nuclei_result_to_finding(_result())
    assert f["feed_version"] == "nuclei-templates-unknown"


def test_cpe_and_cvss_vector_read_from_classification():
    f = nuclei_result_to_finding(_result(info={
        "name": "x", "severity": "critical", "tags": [],
        "classification": {"cpe": "cpe:2.3:a:apache:http_server:2.4.49", "cvss-metrics": "CVSS:3.1/x"},
    }))
    assert f["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49"
    assert f["cvss_vector"] == "CVSS:3.1/x"


# ------------------------------------------------------- finding_to_json (#118)

def test_finding_to_json_exposes_required_os_and_feeds_the_cap_into_priority():
    """An unconfirmed, platform-gated CVSS 9.8 finding must serialize its
    required_os and, via score_finding, read as MEDIUM rather than CRITICAL —
    the same cap the PDF report and the AI writer apply."""
    f = {"cvss_score": 9.8, "confirmed": False, "required_os": "windows_10"}
    out = finding_to_json(f, exposure="public")
    assert out["requiredOs"] == "windows_10"
    assert out["priority"] == "MEDIUM"


def test_finding_to_json_required_os_absent_is_none():
    f = {"cvss_score": 9.8, "confirmed": False}
    out = finding_to_json(f, exposure="public")
    assert out["requiredOs"] is None
    assert out["priority"] == "CRITICAL"
