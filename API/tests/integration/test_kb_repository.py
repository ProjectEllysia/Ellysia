"""Integration tests for the Lybra KB repository (Fase 2).

Exercises the matcher's central query (``cves_for_cpe``) and the upsert
idempotency against the (SQLite) database, without any network.
"""

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.themis.repositories import KbRepository

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
