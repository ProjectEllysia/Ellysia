"""Simulador de reglas: comparar dos políticas sobre el corpus antes de desplegar.

``POST /iris/admin/replay`` es solo para administradores. Ejecuta el corpus
versionado (y mensajes sueltos, si se pegan) con la política vigente y con una
candidata, y devuelve qué veredictos y gates cambian y los falsos positivos y
negativos de cada una. Nada de lo que evalúa se guarda.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.services.replay import CORPUS_DIRECTORY
from src.modules.infrastructure import UnitOfWork
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_LEGIT_SAMPLES = {"legit_bank_alert", "legit_corporate_notice", "legit_newsletter_esp",
                  "legit_order_confirmation"}


@pytest.fixture
def admin_headers(make_user, auth_headers):
    return auth_headers(make_user(role="role_admin"))


def _replay(client, headers, **payload):
    return client.post("/iris/admin/replay", headers=headers, json=payload)


def test_an_admin_compares_the_current_policy_with_a_candidate(client, admin_headers):
    response = _replay(client, admin_headers, candidate={"profile": "strict"})

    assert response.status_code == 200, response.get_json()
    report = response.get_json()
    assert report["corpusVersion"]
    assert report["detectorVersion"].startswith("iris-rules:")
    assert set(report["policies"]) == {"baseline", "candidate"}
    assert report["policies"]["candidate"]["snapshot"]["profile"] == "strict"
    assert len(report["samples"]) == 7
    baseline = report["policies"]["baseline"]
    assert (baseline["metrics"]["overall"]["falsePositives"], baseline["falsePositiveSamples"]) == (0, [])


def test_a_candidate_that_breaks_the_detector_shows_its_known_false_positives(client, admin_headers):
    """Una candidata en la que nada puede salir Legítimo se delata antes de
    desplegarla: las cuatro muestras legítimas del corpus pasan a ser falsos
    positivos, con su identificador."""
    candidate = {"snapshot": {"profile": "balanced", "legitimateThreshold": 101, "suspiciousThreshold": 100}}

    report = _replay(client, admin_headers, candidate=candidate).get_json()

    assert set(report["policies"]["candidate"]["falsePositiveSamples"]) == _LEGIT_SAMPLES
    assert report["changedCount"] == 4
    changed = [sample for sample in report["samples"] if sample["verdictChanged"]]
    assert {sample["id"] for sample in changed} == _LEGIT_SAMPLES


def test_pasted_messages_are_compared_without_being_stored(client, app, admin_headers):
    raw = (CORPUS_DIRECTORY / "phish_bec_free_provider.eml").read_text(encoding="utf-8")

    report = _replay(client, admin_headers, candidate={"profile": "lenient"},
                     messages=[{"raw": raw, "label": "malicious"}], includeCorpus=False).get_json()

    assert report["corpusVersion"] is None
    assert [sample["id"] for sample in report["samples"]] == ["mensaje-1"]
    with app.app_context():
        with UnitOfWork() as uow:
            assert uow.session.query(IrisAnalysis).count() == 0


def test_an_unparseable_message_is_rejected_saying_which(client, admin_headers):
    response = _replay(client, admin_headers, candidate={}, messages=[{"raw": "esto no es un correo"}],
                       includeCorpus=False)

    assert response.status_code == 400
    assert "mensaje 1" in response.get_json()["error_description"].lower()


def test_nothing_to_compare_is_rejected(client, admin_headers):
    response = _replay(client, admin_headers, candidate={}, includeCorpus=False)

    assert response.status_code == 400


def test_inconsistent_thresholds_are_rejected(client, admin_headers):
    response = _replay(client, admin_headers, candidate={"legitimateThreshold": 50, "suspiciousThreshold": 70})

    assert response.status_code == 400


def test_a_user_with_every_iris_attribute_but_no_admin_role_is_refused(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=[attribute.db_name for attribute in (
        AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
        AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
    )])

    response = _replay(client, auth_headers(user), candidate={"profile": "strict"})

    assert response.status_code == 403
