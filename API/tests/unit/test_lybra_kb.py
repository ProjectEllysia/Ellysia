"""Unit tests for the Lybra knowledge base logic (Fase 2).

Pure functions only — version comparison/ranges, CPE normalization, and feed
ingest from decoded records. The network fetchers are the thin edge and are not
exercised here.
"""

import pytest

from src.modules.features.themis.lybra import (
    version_compare,
    version_in_range,
    split_distro_version,
    normalize_cpe_to_23,
    normalize_product_name,
    extract_trailing_version,
    load_product_aliases,
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


# ------------------------------------------- versiones de paquete de distribución
#
# La versión de un paquete de distribución no es la del fabricante. Debian y sus
# derivadas escriben `1:2.4.49-1ubuntu1`: el `1:` es el *epoch* (un contador que
# la distribución sube cuando tiene que renumerar hacia abajo) y el `-1ubuntu1`
# es la *revisión* (qué empaquetado de esa misma versión es). Alpine escribe
# `2.4.49-r0`. Sólo el trozo del medio es lo que publicó el fabricante, y es lo
# único de lo que habla NVD.
#
# Los dos extras rompían la comparación en direcciones opuestas: el epoch
# arrastraba la versión hacia abajo (falsos positivos) y la revisión la
# empujaba por encima del final del rango (CVEs perdidos).

@pytest.mark.parametrize("raw,expected", [
    ("1:2.4.49-1ubuntu1", (1, "2.4.49", "1ubuntu1")),   # Debian/Ubuntu completo
    ("2.4.49-1ubuntu1", (None, "2.4.49", "1ubuntu1")),  # sin epoch
    ("2.4.49-r0", (None, "2.4.49", "r0")),              # Alpine
    ("2.4.49+dfsg-1", (None, "2.4.49", "1")),           # Debian con metadato de empaquetado
    ("7.0.11", (None, "7.0.11", None)),                 # versión de fabricante, intacta
    ("1.0.0-rc1", (None, "1.0.0-rc1", None)),           # preversión, NO es una revisión
])
def test_split_distro_version(raw, expected):
    assert split_distro_version(raw) == expected


@pytest.mark.parametrize("a,b,expected", [
    # El caso que perdía CVEs: la revisión empujaba el paquete por encima del
    # final del rango, así que un versionEndIncluding: 2.4.49 no casaba.
    ("2.4.49-1ubuntu1", "2.4.49", 0),
    ("1:2.4.49-1ubuntu1", "2.4.49", 0),
    ("2.4.49-r0", "2.4.49", 0),
    ("2.4.49+dfsg-1", "2.4.49", 0),
    # El caso que producía falsos positivos: el epoch se leía como primer
    # componente, así que 1:1.2.3 se ordenaba por debajo de 1.0.0.
    ("1:1.2.3", "1.0.0", 1),
    # Entre dos versiones de distribución sí mandan epoch y revisión.
    ("1:1.0", "2:0.9", -1),
    ("2.4.49-1", "2.4.49-2", -1),
    ("2.4.49-2", "2.4.49-1", 1),
    # Regresión: una preversión sigue ordenando por debajo de su versión final.
    ("1.0.0-rc1", "1.0.0", -1),
])
def test_version_compare_with_distro_versions(a, b, expected):
    assert version_compare(a, b) == expected


def test_a_distro_package_lands_in_the_range_of_its_upstream_release():
    """El criterio de cierre: un paquete de distribución tiene que casar los
    mismos rangos que su versión upstream, ni más ni menos."""
    rango = {"version_start_including": "2.4.0", "version_end_including": "2.4.49"}

    assert version_in_range("2.4.49", rango) is True            # referencia
    assert version_in_range("1:2.4.49-1ubuntu1", rango) is True  # el mismo paquete, empaquetado
    assert version_in_range("2.4.49-r0", rango) is True          # y en Alpine

    # Y sigue quedándose fuera lo que tiene que quedarse fuera.
    assert version_in_range("2.4.50-1ubuntu1", rango) is False
    assert version_in_range("2.3.9-1ubuntu1", rango) is False


def test_an_exact_pinned_version_also_matches_the_packaged_form():
    assert version_in_range("1:2.4.49-1ubuntu1", {"exact_version": "2.4.49"}) is True


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


def test_range_with_no_version_information_never_matches():
    """A rule with no exact version and no bound cannot support a version-based
    claim. NVD means "all versions" by it, but honouring that turned a single
    up-to-date Microsoft Edge into 695 findings and matched CVE-2009-1099
    against a 2026 JDK — see ``version_in_range``'s docstring for the measured
    impact."""
    assert version_in_range("9.9.9", {}) is False
    # A rule that bounds the range on even one side still works normally.
    assert version_in_range("9.9.9", {"version_start_including": "1.0"}) is True


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
    assert parsed == {
        "part": "a", "vendor": "apache", "product": "http_server", "version": "2.4.49",
        "target_sw": None,
    }


def test_parse_cpe23_extracts_target_sw():
    parsed = parse_cpe23("cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:windows:*:*")
    assert parsed["target_sw"] == "windows"


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*",   # wildcard
    "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:-:*",   # not-applicable marker
    "cpe:/a:apache:http_server:2.4.49",                     # 2.2 form has no target_sw field at all
])
def test_parse_cpe23_target_sw_none_when_unset(cpe):
    assert parse_cpe23(cpe)["target_sw"] is None


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


# ------------------------------------------------------- elección de métrica CVSS
#
# Un CVE puede publicar varias versiones de CVSS a la vez, y se coge la más
# reciente porque es la más precisa. La v4.0 no estaba en esa cadena, así que un
# CVE que sólo publicara v4 entraba sin puntuación — y aguas abajo "sin
# puntuación" no es un hueco cosmético: se lee como 0.0, que es INFO. Una
# vulnerabilidad crítica aparecía en el informe como informativa.

def _nvd_item_with(metrics: dict) -> dict:
    return {"cve": {
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": metrics,
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        }]}]}],
    }}


_CVSS_V40 = {"cvssMetricV40": [{"cvssData": {
    "baseScore": 9.3,
    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "baseSeverity": "CRITICAL",
}}]}

_CVSS_V31 = {"cvssMetricV31": [{"cvssData": {
    "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH",
}}]}


def test_a_cve_published_only_with_cvss_v4_is_scored():
    cve_row, _matches = ingest_nvd_cve(_nvd_item_with(_CVSS_V40))

    assert cve_row["cvss_score"] == 9.3
    assert cve_row["severity"] == "CRITICAL"
    assert cve_row["cvss_vector"].startswith("CVSS:4.0/")


def test_v4_wins_over_v31_when_a_cve_publishes_both():
    # La regla de la cadena es "la métrica más reciente que ofrezca la entrada",
    # y v4 es más precisa que v3.1 sobre el mismo CVE.
    cve_row, _matches = ingest_nvd_cve(_nvd_item_with({**_CVSS_V31, **_CVSS_V40}))

    assert cve_row["cvss_score"] == 9.3
    assert cve_row["severity"] == "CRITICAL"


def test_v31_still_wins_when_there_is_no_v4():
    cve_row, _matches = ingest_nvd_cve(_nvd_item_with(_CVSS_V31))
    assert cve_row["cvss_score"] == 7.5
    assert cve_row["severity"] == "HIGH"


def test_a_cve_with_no_metric_at_all_stays_unscored():
    # Regresión: no tener métrica sigue siendo distinto de tener una de cero.
    cve_row, _matches = ingest_nvd_cve(_nvd_item_with({}))
    assert (cve_row["cvss_score"], cve_row["cvss_vector"], cve_row["severity"]) == (None, None, None)


def test_the_longest_possible_v4_vector_fits_in_the_column():
    """Un vector v4 es bastante más largo que uno de v3.1, y se guarda entero.

    El peor caso de la especificación —base completa, más amenaza, más entorno,
    más suplementarias, cogiendo en cada métrica el valor más largo— se
    construye aquí en vez de fiarse de un ejemplo suelto: un ejemplo corto que
    quepa no demuestra nada sobre el que no quepa. Son 188 caracteres, así que
    ``String(255)`` vale y no hace falta migración; si alguien acorta la
    columna, este test lo dice.
    """
    from src.modules.features.themis.model import CveEntry

    metricas = [
        ("AV", "N"), ("AC", "L"), ("AT", "P"), ("PR", "N"), ("UI", "A"),
        ("VC", "H"), ("VI", "H"), ("VA", "H"), ("SC", "H"), ("SI", "H"), ("SA", "H"),
        ("E", "U"),
        ("CR", "H"), ("IR", "H"), ("AR", "H"),
        ("MAV", "N"), ("MAC", "L"), ("MAT", "P"), ("MPR", "N"), ("MUI", "A"),
        ("MVC", "H"), ("MVI", "H"), ("MVA", "H"),
        ("MSC", "H"), ("MSI", "Safety"), ("MSA", "Safety"),
        ("S", "P"), ("AU", "Y"), ("R", "I"), ("V", "C"), ("RE", "M"), ("U", "Clear"),
    ]
    peor_caso = "/".join(["CVSS:4.0"] + [f"{metrica}:{valor}" for metrica, valor in metricas])

    assert len(peor_caso) <= CveEntry.__table__.c.cvss_vector.type.length


# -------------------------------------------------------- platform-gated CVEs

def _and_node_item(platform_cpe: str) -> dict:
    """One CVE whose only applicability node ANDs an Apache match with a
    platform-only CPE — the shape NVD uses for "product X, but only on
    OS Y" CVEs."""
    return {"cve": {
        "id": "CVE-2024-00001",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{"nodes": [{
            "operator": "AND",
            "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": platform_cpe},
            ],
        }]}],
    }}


def test_ingest_nvd_cve_and_node_tags_software_match_with_platform():
    """NVD's 'product AND platform' node shape must gate the software row
    with the platform's product token — the mechanism behind CVE-2024-38472-
    style ("...on Windows") false positives reported against non-Windows
    hosts."""
    item = _and_node_item("cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*")
    _cve, matches = ingest_nvd_cve(item)
    assert len(matches) == 1  # the platform-only cpeMatch produces no row of its own
    assert matches[0]["product"] == "http_server"
    assert matches[0]["required_os"] == "windows_10"


def test_ingest_nvd_cve_or_node_does_not_gate():
    """An 'OR' node is not the 'product AND this one platform' shape — must
    not guess a required_os from it."""
    item = _and_node_item("cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*")
    item["cve"]["configurations"][0]["nodes"][0]["operator"] = "OR"
    _cve, matches = ingest_nvd_cve(item)
    # Both entries survive as independent rows once there is no AND to fold.
    assert {m["product"] for m in matches} == {"http_server"}
    assert matches[0]["required_os"] is None


def test_ingest_nvd_cve_multiple_platforms_in_and_node_does_not_gate():
    """Two distinct platform products under the same AND node is a shape this
    module does not attempt to resolve (would need real node-tree/OR
    semantics) — conservatively leaves required_os unset rather than
    guessing either platform."""
    item = {"cve": {
        "id": "CVE-2024-00002",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{"nodes": [{
            "operator": "AND",
            "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"},
                {"vulnerable": True, "criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"},
            ],
        }]}],
    }}
    _cve, matches = ingest_nvd_cve(item)
    assert matches[0]["required_os"] is None


def test_ingest_nvd_cve_target_sw_on_software_cpe_gates_directly():
    """When NVD encodes the platform on the software's own CPE (target_sw)
    rather than via a sibling AND node, that must gate the match too."""
    item = {"cve": {
        "id": "CVE-2024-00003",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:windows:*:*"},
        ]}]}],
    }}
    _cve, matches = ingest_nvd_cve(item)
    assert matches[0]["required_os"] == "windows"


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


def test_the_scoring_date_is_read_from_the_header_the_feed_actually_publishes():
    """La cabecera real usa dos puntos, no un igual, y eso costaba el campo entero.

    El test de arriba —y sólo él— cubría este parser, con una cabecera escrita
    a mano que usa ``score_date=``. El feed publica
    ``#model_version:v2026.06.15,score_date:2026-08-30T12:03:42Z``. Con el
    parser buscando únicamente el ``=``, la fecha salía ``None`` **siempre**:
    353.521 filas en un espejo completo, ninguna con fecha, y sin un solo
    error por el camino — una fecha ausente es indistinguible de un feed que
    no la trae.

    Es el motivo de que este caso exista: una fixture inventada valida el
    código contra sí misma, no contra el mundo.
    """
    csv_text = (
        "#model_version:v2026.06.15,score_date:2026-08-30T12:03:42Z\n"
        "cve,epss,percentile\n"
        "CVE-2021-41773,0.97,0.995\n"
    )

    rows = list(parse_epss_rows(csv_text))

    assert rows[0]["scored_at"].date().isoformat() == "2026-08-30"


def test_a_header_without_a_date_leaves_the_field_empty():
    csv_text = "#model_version:v2026.06.15\ncve,epss,percentile\nCVE-2021-41773,0.97,0.995\n"
    assert list(parse_epss_rows(csv_text))[0]["scored_at"] is None


# --------------------------------------- product name normalization (Fase I-b)

@pytest.mark.parametrize("raw,expected", [
    # The real case that motivated this: a Hygeia inventory entry bakes the
    # version into the name itself, and NVD's product string never does.
    ("7-Zip 25.01 (x64)", "7 zip"),
    ("7-zip", "7 zip"),
    # Doubled-up version some Windows registry entries produce.
    ("GBT_Dynamic_Lighting_Lib_UC 25.07.21.01 25.07.21.01", "gbt dynamic lighting lib uc"),
    # A trailing bare digit is NOT a version — must survive intact.
    ("Half-Life 2", "half life 2"),
    ("Python 3", "python 3"),
    # Architecture noise, not identity.
    ("Docker Desktop (x64)", "docker desktop"),
    ("Microsoft Visual C++ 2022 X64 Setup", "microsoft visual c++ 2022 setup"),
    # "Setup"/"Installer" are NOT stripped: NVD has real products whose name
    # contains them (adobe:photoshop_installer), so dropping the word would
    # collapse a distinct product onto another one. "Visual Studio Installer"
    # (a 4.x bootstrapper) must never normalize onto "visual studio" (17.x).
    ("Microsoft Visual Studio Installer", "microsoft visual studio installer"),
    # "msi" is far more often the hardware vendor than a file extension.
    ("MSI Center", "msi center"),
    # Already-clean NVD-style names pass through unchanged.
    ("docker_desktop", "docker desktop"),
    ("", ""),
    (None, ""),
])
def test_normalize_product_name(raw, expected):
    assert normalize_product_name(raw) == expected


def test_normalize_product_name_is_idempotent():
    # Applying it twice must be a no-op — both sides of a comparison
    # (inventory name, NVD product) run through it independently.
    once = normalize_product_name("7-Zip 25.01 (x64)")
    assert normalize_product_name(once) == once


@pytest.mark.parametrize("raw,expected", [
    ("7-Zip 25.01 (x64)", "25.01"),
    ("IntelliJ IDEA 2025.2.2", "2025.2.2"),
    ("GBT_Dynamic_Lighting_Lib_UC 25.07.21.01 25.07.21.01", "25.07.21.01"),  # doubled -> first token
    ("Half-Life 2", None),     # a single bare digit is not a version
    ("Docker Desktop", None),  # no trailing number at all
    ("", None),
    (None, None),
])
def test_extract_trailing_version(raw, expected):
    assert extract_trailing_version(raw) == expected


# ---------------------------------------------- curated alias feed (paso 3)

def test_load_product_aliases_covers_known_entries():
    aliases = load_product_aliases()
    # Server-side entries migrated from the old hand-written CPE_PRODUCT_OVERRIDES.
    assert aliases["openssh"] == ("openbsd", "openssh")
    assert aliases["nginx"] == ("nginx", "nginx")
    # A case NVD itself makes ambiguous (multiple vendors for "git") that the
    # automated index (paso 2) correctly refuses to guess — resolved here by hand.
    assert aliases["git"] == ("git-scm", "git")
    # Feed keys are normalized-name shaped (spaces, not hyphens) so they line
    # up with what normalize_product_name actually produces.
    assert "pure ftpd" in aliases
    assert "pure-ftpd" not in aliases


def test_curated_feed_keys_are_what_normalization_actually_produces():
    """Every key must survive normalize_product_name unchanged — a key the
    normalizer would rewrite can never be looked up, since _resolve_cpe only
    ever queries the feed with an already-normalized name."""
    for key in load_product_aliases():
        assert normalize_product_name(key) == key, f"clave no normalizada: {key!r}"


@pytest.mark.parametrize("raw_name,expected", [
    # El sufijo comercial "CE" impedia casar con oracle:mysql_workbench.
    ("MySQL Workbench 8.0 CE 8.0.45", ("oracle", "mysql_workbench")),
    # La version del runtime (8.0.19) es la escala que NVD usa en sus rangos.
    ("Microsoft .NET Runtime - 8.0.19 (x64)", ("microsoft", ".net")),
    ("Microsoft Windows Desktop Runtime - 8.0.19 (x64)", ("microsoft", ".net")),
])
def test_desktop_aliases_added_from_real_inventory(raw_name, expected):
    assert load_product_aliases()[normalize_product_name(raw_name)] == expected


@pytest.mark.parametrize("raw_name", [
    # Su version pertenece a OTRA escala que la de microsoft:.net (el SDK
    # 8.0.413 empaqueta el runtime 8.0.19; .NET Standard 2.1 no es .NET 2.1).
    # Aliasarlos repetiria el fallo de esquemas mezclados de Adobe Acrobat.
    "Microsoft .NET SDK 8.0.413 (x64)",
    "Microsoft .NET Standard Targeting Pack - 2.1.0 (x64)",
])
def test_version_scheme_mismatches_are_deliberately_not_aliased(raw_name):
    assert normalize_product_name(raw_name) not in load_product_aliases()


# ───────────── la referencia de exploit que NVD ya etiquetaba (L34)


def test_an_exploit_tagged_reference_is_picked_up():
    """El dato ya viajaba en cada registro que se ingiere: sólo se estaba
    tirando."""
    from src.modules.features.themis.lybra.kb import ingest_nvd_cve

    row, _matches = ingest_nvd_cve({"cve": {
        "id": "CVE-2021-41773",
        "references": [
            {"url": "https://example/advisory", "tags": ["Third Party Advisory"]},
            {"url": "https://example/poc", "tags": ["Exploit", "Third Party Advisory"]},
        ],
    }})
    assert row["has_exploit_reference"] is True


def test_a_cve_without_exploit_references_says_so():
    from src.modules.features.themis.lybra.kb import ingest_nvd_cve

    row, _matches = ingest_nvd_cve({"cve": {
        "id": "CVE-2021-0000",
        "references": [{"url": "https://example/advisory", "tags": ["Vendor Advisory"]}],
    }})
    assert row["has_exploit_reference"] is False


def test_a_cve_with_no_references_at_all_does_not_blow_up():
    from src.modules.features.themis.lybra.kb import ingest_nvd_cve

    row, _matches = ingest_nvd_cve({"cve": {"id": "CVE-2021-0001"}})
    assert row["has_exploit_reference"] is False


# ─────────────── avisos de distribución: OVAL y CSAF (Fase O, L32)


_OVAL_DOC = """<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition id="oval:org.debian:def:1" class="vulnerability">
      <metadata>
        <title>DSA-5432-1 apache2 -- security update</title>
        <description>apache2 was fixed in 2.4.49-1~deb11u1</description>
        <reference source="CVE" ref_id="CVE-2021-41773"/>
      </metadata>
    </definition>
    <definition id="oval:org.debian:def:2" class="vulnerability">
      <metadata>
        <title>nginx</title>
        <description>Se conoce el problema pero no hay versión corregida.</description>
        <reference source="CVE" ref_id="CVE-2022-00001"/>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>"""


def test_oval_yields_the_fixed_version_per_package():
    from src.modules.features.themis.lybra.kb import parse_oval_definitions

    rows = list(parse_oval_definitions(_OVAL_DOC, "debian", "11"))
    fixed = next(r for r in rows if r["cve_id"] == "CVE-2021-41773")
    assert fixed == {"vendor": "debian", "release": "11", "package": "apache2",
                     "cve_id": "CVE-2021-41773", "fixed_in": "2.4.49-1~deb11u1",
                     "status": "fixed"}


def test_oval_without_a_fixed_version_is_unknown_not_vulnerable():
    """El proveedor conoce el paquete y no se pronuncia. Traducirlo a
    "vulnerable" o a "corregido" sería inventar."""
    from src.modules.features.themis.lybra.kb import parse_oval_definitions

    rows = list(parse_oval_definitions(_OVAL_DOC, "debian", "11"))
    silent = next(r for r in rows if r["cve_id"] == "CVE-2022-00001")
    assert silent["status"] == "unknown"
    assert silent["fixed_in"] is None


def test_an_unreadable_oval_document_yields_nothing_instead_of_raising():
    """Un feed corrupto no puede tumbar la sincronización de los demás."""
    from src.modules.features.themis.lybra.kb import parse_oval_definitions

    assert list(parse_oval_definitions("<no cierra", "debian", "11")) == []


def test_csaf_reads_both_verdicts_explicitly():
    """CSAF es más explícito que OVAL: dice qué está corregido y qué sigue
    afectado, así que se traduce tal cual."""
    from src.modules.features.themis.lybra.kb import parse_csaf_advisory

    rows = list(parse_csaf_advisory({"vulnerabilities": [{
        "cve": "CVE-2021-41773",
        "product_status": {
            "fixed": ["AppStream-8.6.0:httpd-0:2.4.37-43.el8"],
            "known_affected": ["AppStream-9.0:nginx-1.20.1-1.el9"],
        },
    }]}))

    assert {"vendor": "rhel", "release": "8", "package": "httpd",
            "cve_id": "CVE-2021-41773", "fixed_in": "2.4.37-43.el8",
            "status": "fixed"} in rows
    affected = next(r for r in rows if r["status"] == "vulnerable")
    assert affected["package"] == "nginx"
    assert affected["fixed_in"] is None
