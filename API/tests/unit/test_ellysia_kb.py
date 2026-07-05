"""Unit tests for the Ellysia knowledge base logic (Fase 2).

Pure functions only — version comparison/ranges, CPE normalization, and feed
ingest from decoded records. The network fetchers are the thin edge and are not
exercised here.
"""

import pytest

from src.modules.sentinel.ellysia import (
    version_compare,
    version_in_range,
    normalize_cpe_to_23,
    parse_cpe23,
    ingest_nvd_cve,
    ingest_kev,
    parse_epss_rows,
)

pytestmark = pytest.mark.unit


# ------------------------------------------------------------- version compare

@pytest.mark.parametrize("a,b,expected", [
    ("2.4.49", "2.4.49", 0),
    ("2.4.49", "2.4.5", 1),     # numeric, not lexical: 49 > 5
    ("2.4.5", "2.4.49", -1),
    ("1.0", "1.0.0", 0),        # trailing zeros tie
    ("1.2", "1.10", -1),        # 2 < 10
    ("2.4.49", "2.4.50", -1),
    ("7.4p1", "7.4", -1),       # alpha suffix ranks as pre-release, below the bare release
    ("2.4.0a", "2.4.0", -1),
])
def test_version_compare(a, b, expected):
    assert version_compare(a, b) == expected


# --------------------------------------------------------------- version range

def test_range_exact_version():
    m = {"exact_version": "2.4.49"}
    assert version_in_range("2.4.49", m) is True
    assert version_in_range("2.4.48", m) is False


def test_range_start_including_end_excluding():
    # affects [2.4.0, 2.4.50)
    m = {"version_start_including": "2.4.0", "version_end_excluding": "2.4.50"}
    assert version_in_range("2.4.0", m) is True
    assert version_in_range("2.4.49", m) is True
    assert version_in_range("2.4.50", m) is False
    assert version_in_range("2.3.9", m) is False


def test_range_start_excluding_end_including():
    m = {"version_start_excluding": "1.0", "version_end_including": "2.0"}
    assert version_in_range("1.0", m) is False
    assert version_in_range("1.5", m) is True
    assert version_in_range("2.0", m) is True
    assert version_in_range("2.0.1", m) is False


def test_range_unbounded_matches_any_version():
    assert version_in_range("9.9.9", {}) is True


def test_range_empty_version_never_matches():
    assert version_in_range("", {"exact_version": "1.0"}) is False


# ----------------------------------------------------------------- CPE helpers

def test_normalize_cpe_22_to_23():
    assert normalize_cpe_to_23("cpe:/a:apache:http_server:2.4.49") == \
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_normalize_cpe_23_passthrough():
    cpe = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
    assert normalize_cpe_to_23(cpe) == cpe


def test_parse_cpe23_extracts_fields():
    parsed = parse_cpe23("cpe:/a:apache:http_server:2.4.49")
    assert parsed == {"part": "a", "vendor": "apache", "product": "http_server", "version": "2.4.49"}


# ---------------------------------------------------------------- NVD ingest

_NVD_ITEM = {
    "cve": {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T12:15:07.777",
        "lastModified": "2022-01-01T00:00:00.000",
        "descriptions": [
            {"lang": "es", "value": "Traspaso de ruta..."},
            {"lang": "en", "value": "Path traversal in Apache 2.4.49"},
        ],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH",
        }}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
        ]}]}],
    }
}


def test_ingest_nvd_cve_core_fields():
    cve_row, matches = ingest_nvd_cve(_NVD_ITEM)

    assert cve_row["cve_id"] == "CVE-2021-41773"
    assert cve_row["cvss_score"] == 7.5
    assert cve_row["severity"] == "HIGH"
    assert cve_row["cwe_ids"] == ["CWE-22"]
    assert "Path traversal" in cve_row["description"]  # English preferred
    assert cve_row["published"].year == 2021


def test_ingest_nvd_cve_keeps_only_vulnerable_matches():
    _cve, matches = ingest_nvd_cve(_NVD_ITEM)
    assert len(matches) == 1          # the non-vulnerable linux_kernel one is dropped
    m = matches[0]
    assert (m["vendor"], m["product"]) == ("apache", "http_server")
    assert m["exact_version"] == "2.4.49"


def test_ingest_nvd_cve_range_beats_pinned_version():
    item = {"cve": {
        "id": "CVE-2020-0001",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.0",
            "versionEndExcluding": "2.4.50",
        }]}]}],
    }}
    _cve, matches = ingest_nvd_cve(item)
    m = matches[0]
    assert m["exact_version"] is None
    assert m["version_start_including"] == "2.4.0"
    assert m["version_end_excluding"] == "2.4.50"


def test_ingest_nvd_cve_malformed_returns_none():
    assert ingest_nvd_cve({"cve": {}}) is None


# --------------------------------------------------------------- KEV / EPSS

def test_ingest_kev():
    row = ingest_kev({
        "cveID": "CVE-2021-41773", "dateAdded": "2021-11-03",
        "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Known",
    })
    assert row["cve_id"] == "CVE-2021-41773"
    assert row["known_ransomware"] is True
    assert row["date_added"].day == 3


def test_parse_epss_rows_skips_comment_header():
    csv_text = (
        "#model_version:v2023.03.01,score_date=2026-07-01T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2021-41773,0.97,0.995\n"
        "CVE-2020-0001,0.01,0.30\n"
    )
    rows = list(parse_epss_rows(csv_text))
    assert len(rows) == 2
    assert rows[0]["cve_id"] == "CVE-2021-41773"
    assert rows[0]["score"] == 0.97
    assert rows[0]["scored_at"].year == 2026
