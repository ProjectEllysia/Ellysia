"""Unit tests for the Nikto -> Finding adapter (additive write path).

Pure functions over dicts — no DB. OpenVAS had the same kind of adapter
(``openvas_result_to_finding``) until the scanner was removed (roadmap
§7/§6.3, Ronda 2 — E2); its tests were removed with it.
"""

import pytest

from src.modules.features.themis.lybra import nikto_incident_to_finding

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
