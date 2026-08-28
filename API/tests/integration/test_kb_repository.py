"""Integration tests for the Lybra KB repository (Fase 2).

Exercises the matcher's central query (``cves_for_cpe``) and the upsert
idempotency against the (SQLite) database, without any network.
"""

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.features.themis.repositories import KbRepository

pytestmark = pytest.mark.integration


def _cve_row(cve_id="CVE-2021-41773", score=7.5):
    return {
        "cve_id": cve_id, "cvss_score": score, "cvss_vector": "CVSS:3.1/AV:N",
        "severity": "HIGH", "description": "Path traversal", "cwe_ids": ["CWE-22"],
        "source": "nvd",
    }


def test_cves_for_cpe_respects_version_range(app):
    # CVE affects apache http_server in [2.4.0, 2.4.50)
    match = {"vendor": "apache", "product": "http_server",
             "version_start_including": "2.4.0", "version_end_excluding": "2.4.50",
             "version_start_excluding": None, "version_end_including": None,
             "exact_version": None}
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row(), [match])

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            hit = repo.cves_for_cpe("apache", "http_server", "2.4.49")
            miss = repo.cves_for_cpe("apache", "http_server", "2.4.50")
            wrong_product = repo.cves_for_cpe("apache", "tomcat", "2.4.49")

    assert [c.cve_id for c in hit] == ["CVE-2021-41773"]
    assert miss == []
    assert wrong_product == []


def test_cves_for_cpe_tags_result_with_required_os(app):
    """#118: a match gated behind a platform (CpeMatch.required_os) must
    surface on the returned CveEntry so the caller (LybraEngine) can avoid
    treating an unverifiable OS precondition as a confirmed risk."""
    match = {"vendor": "apache", "product": "http_server", "exact_version": "2.4.59",
             "version_start_including": None, "version_start_excluding": None,
             "version_end_including": None, "version_end_excluding": None,
             "required_os": "windows_10"}
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row(), [match])

        with UnitOfWork() as uow:
            hit = KbRepository(uow).cves_for_cpe("apache", "http_server", "2.4.59")

    assert [c.cve_id for c in hit] == ["CVE-2021-41773"]
    assert hit[0].required_os == "windows_10"


def test_cves_for_cpe_unconditional_rule_wins_over_os_gated_one(app):
    """The same CVE can have several applicability rows for the same product
    (different ranges from different NVD configuration nodes). If even one of
    the rows matching this version is unconditional, the CVE genuinely
    applies regardless of platform — the OS gate from the other row must not
    leak into the result."""
    windows_only = {"vendor": "apache", "product": "http_server", "exact_version": "2.4.59",
                     "version_start_including": None, "version_start_excluding": None,
                     "version_end_including": None, "version_end_excluding": None,
                     "required_os": "windows_10"}
    unconditional = {"vendor": "apache", "product": "http_server",
                      "version_start_including": "2.4.0", "version_end_excluding": "2.4.60",
                      "version_start_excluding": None, "version_end_including": None,
                      "exact_version": None, "required_os": None}
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row(), [windows_only, unconditional])

        with UnitOfWork() as uow:
            hit = KbRepository(uow).cves_for_cpe("apache", "http_server", "2.4.59")

    assert [c.cve_id for c in hit] == ["CVE-2021-41773"]
    assert hit[0].required_os is None


def test_upsert_cve_is_idempotent_and_replaces_matches(app):
    m1 = {"vendor": "apache", "product": "http_server", "exact_version": "2.4.49",
          "version_start_including": None, "version_start_excluding": None,
          "version_end_including": None, "version_end_excluding": None}
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row(score=7.5), [m1])
        # Re-sync the same CVE with a higher score and a different match set.
        m2 = dict(m1, exact_version="2.4.50")
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row(score=9.8), [m2])

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            counts = repo.counts()
            # Old match (2.4.49) is gone, new one (2.4.50) applies.
            gone = repo.cves_for_cpe("apache", "http_server", "2.4.49")
            now = repo.cves_for_cpe("apache", "http_server", "2.4.50")

    assert counts["cves"] == 1          # updated in place, not duplicated
    assert counts["cpeMatches"] == 1    # matches replaced, not appended
    assert gone == []
    assert [c.cve_id for c in now] == ["CVE-2021-41773"]
    assert now[0].cvss_score == 9.8     # fields updated


# ------------------------------------------------- Fase I-b, paso 2: índice CPE

def _match(vendor, product):
    return {"vendor": vendor, "product": product, "exact_version": "1.0",
            "version_start_including": None, "version_start_excluding": None,
            "version_end_including": None, "version_end_excluding": None}


def test_rebuild_cpe_product_index_resolves_unambiguous_names(app):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            # "7-zip" and "http_server" each have exactly one (vendor, product).
            repo.upsert_cve(_cve_row("CVE-1111-1111"), [_match("7-zip", "7-zip")])
            repo.upsert_cve(_cve_row("CVE-2222-2222"), [_match("apache", "http_server")])

        with UnitOfWork() as uow:
            count = KbRepository(uow).rebuild_cpe_product_index()

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            seven_zip = repo.resolve_product_alias("7 zip")
            apache = repo.resolve_product_alias("http server")
            missing = repo.resolve_product_alias("totally unknown app")

    # Two pairs, each indexed twice: by product and by vendor+product.
    assert count == 4
    assert seven_zip == ("7-zip", "7-zip")
    assert apache == ("apache", "http_server")
    assert missing is None


def test_rebuild_cpe_product_index_resolves_vendor_prefixed_names(app):
    """A Windows inventory writes "Microsoft Edge"; NVD's product column says
    only "edge". Without the vendor-qualified key the two could never meet."""
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(_cve_row("CVE-7777-7777"),
                                          [_match("microsoft", "edge")])
        with UnitOfWork() as uow:
            KbRepository(uow).rebuild_cpe_product_index()

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            assert repo.resolve_product_alias("microsoft edge") == ("microsoft", "edge")
            # The bare product name still resolves too — this is additive.
            assert repo.resolve_product_alias("edge") == ("microsoft", "edge")


def test_product_key_wins_over_a_colliding_vendor_qualified_key(app):
    """NVD names the same software both ways ("adobe:adobe_reader" and
    "adobe:reader"), so "adobe reader" is reachable as a product name AND as a
    vendor-qualified one. The direct reading must win rather than the pair
    being discarded as ambiguous — otherwise adding the vendor keys would
    silently *remove* names that resolved before."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_cve_row("CVE-8888-8888"), [_match("adobe", "adobe_reader")])
            repo.upsert_cve(_cve_row("CVE-9999-9999"), [_match("adobe", "reader")])
        with UnitOfWork() as uow:
            KbRepository(uow).rebuild_cpe_product_index()

        with UnitOfWork() as uow:
            resolved = KbRepository(uow).resolve_product_alias("adobe reader")

    assert resolved == ("adobe", "adobe_reader")


def test_rebuild_cpe_product_index_discards_ambiguous_names(app):
    """The real case that motivated the rule: NVD tags "git" under several
    unrelated vendors (a Jenkins plugin, firmware, the real Git SCM...). All
    of them share the exact same product string, so they collide on the same
    normalized key — and none should be guessed."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_cve_row("CVE-3333-3333"), [_match("git-scm", "git")])
            repo.upsert_cve(_cve_row("CVE-4444-4444"), [_match("jenkins", "git")])

        with UnitOfWork() as uow:
            count = KbRepository(uow).rebuild_cpe_product_index()

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            resolved = repo.resolve_product_alias("git")
            qualified = repo.resolve_product_alias("jenkins git")

    # The bare "git" stays ambiguous and unresolved, but each vendor-qualified
    # variant ("git scm git", "jenkins git") names exactly one pair, so those
    # two are indexed — the ambiguity is in the bare name, not in them.
    assert count == 2
    assert resolved is None    # never guesses between git-scm and jenkins
    assert qualified == ("jenkins", "git")


def test_rebuild_cpe_product_index_is_a_full_replace_not_incremental(app):
    """A pair that stops being unique (a second vendor for the same product
    shows up in a later sync) must fall back OUT of the index, not linger."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_cve_row("CVE-5555-5555"), [_match("solo-vendor", "widget")])
        with UnitOfWork() as uow:
            KbRepository(uow).rebuild_cpe_product_index()
        with UnitOfWork() as uow:
            assert KbRepository(uow).resolve_product_alias("widget") == ("solo-vendor", "widget")

        # A second, unrelated vendor for the exact same product name appears.
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_cve_row("CVE-6666-6666"), [_match("other-vendor", "widget")])
        with UnitOfWork() as uow:
            KbRepository(uow).rebuild_cpe_product_index()
        with UnitOfWork() as uow:
            assert KbRepository(uow).resolve_product_alias("widget") is None


def test_upsert_kev_and_epss_lookup(app):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_kev({"cve_id": "CVE-2021-41773", "known_ransomware": True,
                             "date_added": None, "due_date": None})
            repo.upsert_epss({"cve_id": "CVE-2021-41773", "score": 0.97,
                              "percentile": 0.99, "scored_at": None})

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            kev = repo.get_kev("CVE-2021-41773")
            epss = repo.get_epss("CVE-2021-41773")

    assert kev is not None and kev.known_ransomware is True
    assert epss is not None and epss.score == 0.97


# ===========================================================================
# CONSULTAS DE DESCUBRIMIENTO
# ===========================================================================
#
# Responden otra pregunta que ``cves_for_cpe``: no "¿este host con esta
# versión es vulnerable?" sino "¿qué ha sido notable en este producto?", que
# es lo que alimenta el contenido de concienciación de Aegis. La diferencia
# más visible está en ``test_discovery_includes_unbounded_rules``.

from datetime import datetime, timedelta  # noqa: E402

from src.modules.features.themis.managers import KbQueryManager  # noqa: E402

_NOW = datetime(2026, 8, 1)
_UNBOUNDED = {"vendor": "microsoft", "product": "windows", "exact_version": None,
              "version_start_including": None, "version_start_excluding": None,
              "version_end_including": None, "version_end_excluding": None}


def _dated_cve_row(cve_id, published, score=7.5, severity="HIGH"):
    return {
        "cve_id": cve_id, "cvss_score": score, "cvss_vector": "CVSS:3.1/AV:N",
        "severity": severity, "description": "Remote code execution",
        "cwe_ids": [], "source": "nvd", "published": published,
    }


def test_recent_cves_for_products_filters_by_date_and_orders_newest_first(app):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_dated_cve_row("CVE-2026-0001", _NOW - timedelta(days=10)), [_UNBOUNDED])
            repo.upsert_cve(_dated_cve_row("CVE-2026-0002", _NOW - timedelta(days=2)), [_UNBOUNDED])
            repo.upsert_cve(_dated_cve_row("CVE-2019-9999", _NOW - timedelta(days=2500)), [_UNBOUNDED])

        with UnitOfWork() as uow:
            rows = KbRepository(uow).recent_cves_for_products(
                [("microsoft", "windows")], since=_NOW - timedelta(days=365),
            )

    # El viejo queda fuera por 'since'; los otros dos salen del más reciente al más antiguo.
    assert [cve.cve_id for _, _, cve in rows] == ["CVE-2026-0002", "CVE-2026-0001"]


def test_discovery_includes_unbounded_rules_that_the_matcher_drops(app):
    """La diferencia esencial con ``cves_for_cpe``.

    Una regla de aplicabilidad sin límites de versión ("afecta a todo el
    producto") es ruido para el matcher — honrarla convierte "tienes este
    producto" en "tienes esta vulnerabilidad" para siempre. Pero para saber
    qué ha sido noticia en un producto sí es información válida, y por eso son
    dos consultas y no una parametrizada.
    """
    with app.app_context():
        with UnitOfWork() as uow:
            KbRepository(uow).upsert_cve(
                _dated_cve_row("CVE-2026-0003", _NOW - timedelta(days=5)), [_UNBOUNDED],
            )

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            discovered = repo.recent_cves_for_products(
                [("microsoft", "windows")], since=_NOW - timedelta(days=365),
            )
            matched = repo.cves_for_cpe("microsoft", "windows", "10.0.19041")

    assert [cve.cve_id for _, _, cve in discovered] == ["CVE-2026-0003"]
    assert matched == []


def test_recent_cves_caps_per_product(app):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for i in range(8):
                repo.upsert_cve(
                    _dated_cve_row(f"CVE-2026-01{i:02d}", _NOW - timedelta(days=i)), [_UNBOUNDED],
                )

        with UnitOfWork() as uow:
            rows = KbRepository(uow).recent_cves_for_products(
                [("microsoft", "windows")], since=_NOW - timedelta(days=365),
                limit_per_product=3,
            )

    assert len(rows) == 3


def test_min_cvss_keeps_unscored_cves(app):
    """Sin puntuación significa "aún no analizado", no "inofensivo"."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_dated_cve_row("CVE-2026-0201", _NOW, score=9.8), [_UNBOUNDED])
            repo.upsert_cve(_dated_cve_row("CVE-2026-0202", _NOW, score=2.1), [_UNBOUNDED])
            repo.upsert_cve(_dated_cve_row("CVE-2026-0203", _NOW, score=None), [_UNBOUNDED])

        with UnitOfWork() as uow:
            rows = KbRepository(uow).recent_cves_for_products(
                [("microsoft", "windows")], since=_NOW - timedelta(days=365), min_cvss=7.0,
            )

    assert sorted(cve.cve_id for _, _, cve in rows) == ["CVE-2026-0201", "CVE-2026-0203"]


def test_search_products_matches_by_prefix(app):
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_dated_cve_row("CVE-2026-0301", _NOW), [_UNBOUNDED])
            repo.rebuild_cpe_product_index()

        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            by_product = repo.search_products("wind")
            by_vendor_qualified = repo.search_products("microsoft win")
            miss = repo.search_products("nothing-like-this")

    assert ("microsoft", "windows") in [(v, p) for v, p, _ in by_product]
    assert ("microsoft", "windows") in [(v, p) for v, p, _ in by_vendor_qualified]
    assert miss == []


def test_query_manager_enriches_with_kev_and_epss(app):
    """El contrato público que consumen otros módulos: DTOs planos, con la
    señal de KEV/EPSS ya resuelta en lote."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(_dated_cve_row("CVE-2026-0401", _NOW - timedelta(days=1)), [_UNBOUNDED])
            repo.upsert_cve(_dated_cve_row("CVE-2026-0402", _NOW - timedelta(days=3)), [_UNBOUNDED])
            repo.upsert_kev({"cve_id": "CVE-2026-0401", "known_ransomware": False,
                             "date_added": None, "due_date": None})
            repo.upsert_epss({"cve_id": "CVE-2026-0401", "score": 0.87,
                              "percentile": 0.99, "scored_at": None})

        advisories = KbQueryManager().advisories_for_products(
            [("microsoft", "windows")], since=_NOW - timedelta(days=365),
        )

    assert [a.cve_id for a in advisories] == ["CVE-2026-0401", "CVE-2026-0402"]
    exploited, quiet = advisories
    assert exploited.kev is True and exploited.epss == 0.87
    assert exploited.vendor == "microsoft" and exploited.product == "windows"
    assert exploited.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-0401"
    assert quiet.kev is False and quiet.epss is None
