"""Unit tests for Lybra correlation (Fase 5): dedup, merge, lifecycle, scoring.

All pure functions over finding dicts — no DB, no network.
"""

import pytest

from src.modules.features.themis.lybra import (
    classify_exposure,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    score_finding,
)

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------ exposure

@pytest.mark.parametrize("target,expected", [
    ("10.0.0.5", "private"),
    ("192.168.1.1", "private"),
    ("127.0.0.1", "private"),
    ("localhost", "private"),
    ("printer.lan", "private"),
    ("8.8.8.8", "public"),
    ("example.com", "public"),
])
def test_classify_exposure(target, expected):
    assert classify_exposure(target) == expected


# ----------------------------------------------------------------- dedup key

def test_dedup_key_stable_by_identity():
    a = {"host_id": 1, "port": 80, "cve_ids": ["CVE-2021-41773"]}
    b = {"host_id": 1, "port": 80, "cve_ids": ["CVE-2021-41773"], "source": "openvas"}
    assert compute_dedup_key(a) == compute_dedup_key(b)      # same issue, any source


def test_dedup_key_differs_by_port_and_identity():
    base = {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"]}
    assert compute_dedup_key(base) != compute_dedup_key({**base, "port": 443})
    assert compute_dedup_key(base) != compute_dedup_key({"host_id": 1, "port": 80, "cve_ids": ["CVE-2"]})
    # No CVE -> keyed on check_id.
    chk = {"host_id": 1, "port": 80, "check_id": "lybra:git@1"}
    assert compute_dedup_key(chk) == compute_dedup_key({**chk, "source": "x"})


# -------------------------------------------------------------------- merge

def test_merge_combines_sources_and_keeps_strongest():
    findings = [
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "lybra",
         "qod": 70, "confirmed": False, "in_kev": False, "title": "by version"},
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "openvas",
         "qod": 99, "confirmed": True, "in_kev": True, "title": "confirmed"},
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    m = merged[0]
    assert m["source"] == "lybra,openvas"
    assert m["qod"] == 99 and m["confirmed"] is True and m["in_kev"] is True
    assert m["title"] == "confirmed"          # title follows the strongest qod


def test_merge_keeps_distinct_keys():
    findings = [
        {"host_id": 1, "port": 80, "cve_ids": ["CVE-1"], "source": "lybra", "qod": 70},
        {"host_id": 1, "port": 443, "cve_ids": ["CVE-1"], "source": "lybra", "qod": 70},
    ]
    assert len(merge_findings(findings)) == 2


# ---------------------------------------------------------------- lifecycle

def _prev(state, key):
    return {key: {"state": state, "snapshot": {"dedup_key": key, "title": "old", "category": "x"}}}


def test_lifecycle_new_is_open():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, {})[0]["state"] == "open"


def test_lifecycle_regressed_when_was_fixed():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, _prev("fixed", "K1"))[0]["state"] == "regressed"


def test_lifecycle_accepted_is_sticky():
    cur = [{"dedup_key": "K1"}]
    assert apply_lifecycle(cur, _prev("accepted", "K1"))[0]["state"] == "accepted"


def test_lifecycle_carries_gone_finding_as_fixed():
    cur = [{"dedup_key": "K2"}]                  # K1 was present before, gone now
    out = apply_lifecycle(cur, _prev("open", "K1"))
    fixed = [f for f in out if f["state"] == "fixed"]
    assert len(fixed) == 1 and fixed[0]["dedup_key"] == "K1"


def test_lifecycle_does_not_recarry_already_fixed():
    cur = [{"dedup_key": "K2"}]
    out = apply_lifecycle(cur, _prev("fixed", "K1"))   # K1 already fixed, absent now
    assert all(f["dedup_key"] != "K1" for f in out)


# ------------------------------------------------------------------ scoring

@pytest.mark.parametrize("finding,exposure,expected", [
    ({"cvss_score": 9.8}, "public", "CRITICAL"),
    ({"cvss_score": 7.5}, "public", "HIGH"),
    ({"cvss_score": 7.5}, "private", "HIGH"),                       # cap doesn't lower HIGH
    ({"cvss_score": 9.8}, "private", "HIGH"),                       # private caps CRITICAL->HIGH
    ({"cvss_score": 7.5, "in_kev": True}, "public", "CRITICAL"),    # KEV escalates
    ({"cvss_score": 5.0, "epss_score": 0.6}, "public", "HIGH"),     # high EPSS escalates
    ({"cvss_score": 0.0, "confirmed": True}, "public", "MEDIUM"),   # confirmed w/o CVSS floors
    ({"cvss_score": 0.0}, "public", "INFO"),
])
def test_score_finding(finding, exposure, expected):
    assert score_finding(finding, exposure) == expected
