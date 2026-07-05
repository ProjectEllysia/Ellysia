"""Unit tests for the Nikto/OpenVAS -> Finding adapters (additive write path).

Pure functions over dicts (and a duck-typed vuln object for OpenVAS) — no DB.
"""

from types import SimpleNamespace

import pytest

from src.modules.sentinel.ellysia import nikto_incident_to_finding, openvas_result_to_finding

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------- Nikto

def _incident(**overrides):
    base = {"description": "Repositorio Git expuesto", "osvdb_id": "12345",
            "method": "GET", "url": "/.git/config", "severity": "CRITICAL"}
    return {**base, **overrides}


@pytest.mark.parametrize("severity,expected_qod", [
    ("CRITICAL", 85), ("HIGH", 80), ("MEDIUM", 60), ("LOW", 40), ("INFO", 30),
])
def test_nikto_severity_maps_to_qod(severity, expected_qod):
    f = nikto_incident_to_finding(_incident(severity=severity))
    assert f["qod"] == expected_qod
    assert f["confirmed"] is False  # heuristic pattern match, never confirmed


def test_nikto_unknown_severity_defaults_low():
    assert nikto_incident_to_finding(_incident(severity="WEIRD"))["qod"] == 30


def test_nikto_check_id_uses_osvdb_id_when_present():
    f = nikto_incident_to_finding(_incident(osvdb_id="999"))
    assert f["check_id"] == "nikto:999"


def test_nikto_check_id_falls_back_to_stable_hash_without_osvdb():
    a = nikto_incident_to_finding(_incident(osvdb_id="", description="X"))
    b = nikto_incident_to_finding(_incident(osvdb_id="", description="X"))
    c = nikto_incident_to_finding(_incident(osvdb_id="", description="Y"))
    assert a["check_id"] == b["check_id"]        # same input -> stable identity
    assert a["check_id"] != c["check_id"]        # different finding -> different key
    assert a["check_id"].startswith("nikto:")


def test_nikto_title_includes_method_and_url():
    f = nikto_incident_to_finding(_incident())
    assert f["title"] == "GET /.git/config: Repositorio Git expuesto"
    assert f["source"] == "nikto"
    assert f["category"] == "web_finding"


def test_nikto_title_falls_back_to_description_without_method_url():
    f = nikto_incident_to_finding(_incident(method="", url=""))
    assert f["title"] == "Repositorio Git expuesto"


# ----------------------------------------------------------------- OpenVAS

def _vuln(**overrides):
    base = dict(nvt_oid="1.3.6.1.4.1.25623.1.0.999", name="Apache Path Traversal",
               cve_ids="CVE-2021-41773,CVE-2021-42013", cvss_base_score=9.8,
               severity_score=9.8, cvss_vector="CVSS:3.1/AV:N", severity_class="Critical",
               qod_value=99)
    return SimpleNamespace(**{**base, **overrides})


def _result(**overrides):
    base = {"nvt_oid": "1.3.6.1.4.1.25623.1.0.999", "host_ip": "10.0.0.5",
            "port": "80/tcp", "threat": "Critical"}
    return {**base, **overrides}


def test_openvas_finding_uses_qod_value_directly():
    f = openvas_result_to_finding(_vuln(qod_value=99), _result())
    assert f["qod"] == 99
    assert f["confirmed"] is True   # >= 80


def test_openvas_finding_falls_back_to_severity_when_qod_missing():
    f = openvas_result_to_finding(_vuln(qod_value=None, severity_class="Medium"), _result())
    assert f["qod"] == 60
    assert f["confirmed"] is False  # < 80


def test_openvas_finding_parses_cve_ids():
    f = openvas_result_to_finding(_vuln(), _result())
    assert f["cve_ids"] == ["CVE-2021-41773", "CVE-2021-42013"]
    assert f["category"] == "outdated_software"


def test_openvas_finding_without_cves_is_generic_vulnerability():
    f = openvas_result_to_finding(_vuln(cve_ids=None), _result())
    assert f["cve_ids"] is None
    assert f["category"] == "vulnerability"


@pytest.mark.parametrize("port_str,expected", [
    ("80/tcp", 80), ("443/tcp", 443), ("general/tcp", None), (None, None), ("", None),
])
def test_openvas_port_parsing(port_str, expected):
    f = openvas_result_to_finding(_vuln(), _result(port=port_str))
    assert f["port"] == expected


def test_openvas_check_id_and_source():
    f = openvas_result_to_finding(_vuln(nvt_oid="1.2.3"), _result(nvt_oid="1.2.3"))
    assert f["check_id"] == "openvas:1.2.3"
    assert f["source"] == "openvas"
