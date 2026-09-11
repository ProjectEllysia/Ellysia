"""La taxonomía estable viaja con cada análisis real, de la base de datos a la API."""

from __future__ import annotations

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.replay import CORPUS_DIRECTORY
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration

_PHISH = (CORPUS_DIRECTORY / "phish_ip_link_executable.eml").read_text(encoding="utf-8")


def test_every_finding_of_an_analysis_carries_its_stable_reference(client, app, root_user, root_headers):
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=_PHISH, user_id=root_user.id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, _PHISH)

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    assert all(rule["ruleId"] and rule["severity"] for rule in report["rules"])
    assert all(signal["ruleId"] for signal in report["topSignals"])
    attachments = next(rule for rule in report["rules"] if rule["ruleId"] == "iris.attachment.suspicious_attachments")
    assert attachments["mitreTechniques"] == ["T1566.001"]
