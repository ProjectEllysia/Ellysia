"""Tests de integración de lo que pasa en la superficie HTTP de Iris una vez
la retención purga el raw de un análisis: ``/path`` e
``/iocs`` (derivados del raw) pasan a devolver 410, ``/reanalyze`` también
(no hay nada que reanalizar), pero el resultado principal, la exportación y
el informe de retención siguen funcionando -- "el resultado puede
conservarse sin el raw" es justo lo que se comprueba.
"""

from __future__ import annotations

import json

import pytest

from src.modules.features.iris.model import IrisAnalysis, IrisRuleResult
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration


def _seed_analysis(app, user_id: int, *, purge_raw: bool = False) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: a@b.com\nTo: c@d.com\nSubject: Test\n",
                user_id=user_id, status="finished", total_score=-25.0, verdict="Phishing",
            )
            repo = IrisAnalysisRepository(uow)
            repo.save(analysis)
            analysis_id = analysis.id
            IrisRuleResultRepository(uow).save(IrisRuleResult(
                analysis_id=analysis_id, rule_name="SPF", category="authentication",
                score=-10, verdict="fail", details={"domain": "x.com"},
                recommendation="Revisar SPF", position=0,
            ))
            if purge_raw:
                analysis.raw_headers = None
                repo.update(analysis)
            return analysis_id


# --------------------------------------------------------------------- /path

def test_path_returns_410_once_raw_is_purged(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=True)

    resp = client.get(f"/iris/results/{analysis_id}/path", headers=root_headers)

    assert resp.status_code == 410


def test_path_works_normally_before_raw_is_purged(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=False)

    resp = client.get(f"/iris/results/{analysis_id}/path", headers=root_headers)

    assert resp.status_code == 200


# --------------------------------------------------------------------- /iocs

def test_iocs_returns_410_once_raw_is_purged(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=True)

    resp = client.get(f"/iris/results/{analysis_id}/iocs", headers=root_headers)

    assert resp.status_code == 410


# ---------------------------------------------------------------- /reanalyze

def test_reanalyze_returns_410_once_raw_is_purged(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=True)

    resp = client.post(f"/iris/results/{analysis_id}/reanalyze", headers=root_headers)

    assert resp.status_code == 410


# ------------------------------------------------------------------- /export

def test_export_bundles_result_path_and_iocs_when_raw_is_retained(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=False)

    resp = client.get(f"/iris/results/{analysis_id}/export", headers=root_headers)

    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"] == (
        f'attachment; filename="iris-analysis-{analysis_id}.json"'
    )
    bundle = json.loads(resp.get_data(as_text=True))
    assert bundle["analysis"]["analysisId"] == analysis_id
    assert bundle["receivedPath"] is not None
    assert bundle["iocs"] is not None


def test_export_degrades_gracefully_once_raw_is_purged(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, purge_raw=True)

    resp = client.get(f"/iris/results/{analysis_id}/export", headers=root_headers)

    assert resp.status_code == 200
    bundle = json.loads(resp.get_data(as_text=True))
    assert bundle["analysis"]["analysisId"] == analysis_id
    assert bundle["analysis"]["totalScore"] == -25.0  # el resultado sobrevive
    assert bundle["receivedPath"] is None
    assert bundle["iocs"] is None


def test_export_requires_ownership(client, app, root_user, regular_user, auth_headers):
    analysis_id = _seed_analysis(app, root_user.id)

    resp = client.get(f"/iris/results/{analysis_id}/export", headers=auth_headers(regular_user))

    assert resp.status_code == 404


# ------------------------------------------------------------ /retention-policy

def test_retention_policy_reports_retained_vs_purged_counts(client, app, root_user, root_headers):
    _seed_analysis(app, root_user.id, purge_raw=False)
    _seed_analysis(app, root_user.id, purge_raw=True)

    resp = client.get("/iris/retention-policy", headers=root_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["totalAnalyses"] == 2
    assert body["analysesWithRawRetained"] == 1
    assert body["analysesWithRawPurged"] == 1
    assert body["rawMessageRetentionDays"] == 90


def test_retention_policy_reports_null_when_hard_deletion_is_disabled(client, root_headers):
    resp = client.get("/iris/retention-policy", headers=root_headers)

    assert resp.status_code == 200
    assert resp.get_json()["analysisRetentionDays"] is None


def test_retention_policy_is_scoped_to_the_current_user(client, app, root_user, regular_user, auth_headers):
    _seed_analysis(app, root_user.id, purge_raw=False)

    resp = client.get("/iris/retention-policy", headers=auth_headers(regular_user))

    assert resp.get_json()["totalAnalyses"] == 0
