"""Feedback del analista: corregir un veredicto sin tocarlo, y medir con ello.

Cubre el criterio de cierre: una corrección en una sola petición (dos clics
en la UI: etiqueta y Guardar), con autor, nota y fecha, que nunca modifica el
veredicto emitido; el historial completo; y las métricas por familia.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.model import IrisAnalysis, IrisRuleResult
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_IRIS_ATTRIBUTES = [attribute.db_name for attribute in (
    AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
)]


def _analysis(app, user_id: int, *, verdict: str = "Phishing", score: float = 20.0,
              status: str = "finished", fired_rules: tuple[str, ...] = ()) -> int:
    """Crea un análisis con las reglas indicadas penalizando."""
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: a@b.example\nSubject: Hola\n", user_id=user_id,
                status=status, verdict=verdict if status == "finished" else None,
                total_score=score if status == "finished" else None,
            )
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
            for position, rule_name in enumerate(fired_rules):
                IrisRuleResultRepository(uow).save(IrisRuleResult(
                    analysis_id=analysis_id, rule_name=rule_name, category="x",
                    score=-10.0, verdict="fail", position=position,
                ))
            return analysis_id


@pytest.fixture
def analyst(make_user, auth_headers):
    user = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    return user, auth_headers(user)


def test_an_analyst_corrects_a_verdict_without_changing_it(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id, verdict="Phishing", score=20.0)

    response = client.post(f"/iris/results/{analysis_id}/feedback", headers=headers,
                           json={"label": "legitimate", "note": "  Newsletter del proveedor.  "})

    assert response.status_code == 201
    feedback = response.get_json()
    assert feedback["label"] == "legitimate"
    assert feedback["note"] == "Newsletter del proveedor."
    assert feedback["author"] == user.username
    assert feedback["createdAt"]

    report = client.get(f"/iris/results/{analysis_id}", headers=headers).get_json()
    assert report["verdict"] == "Phishing"
    assert report["totalScore"] == 20.0
    assert report["latestFeedback"]["label"] == "legitimate"


def test_every_correction_is_kept_and_the_latest_wins(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id)

    client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "legitimate"})
    client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "malicious"})

    history = client.get(f"/iris/results/{analysis_id}/feedback", headers=headers).get_json()
    assert [entry["label"] for entry in history["feedback"]] == ["malicious", "legitimate"]
    report = client.get(f"/iris/results/{analysis_id}", headers=headers).get_json()
    assert report["latestFeedback"]["label"] == "malicious"


def test_an_unknown_label_is_rejected(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id)

    response = client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "quizas"})

    assert response.status_code == 422


def test_an_unfinished_analysis_has_no_verdict_to_correct(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id, status="running")

    response = client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "malicious"})

    assert response.status_code == 409


def test_nobody_corrects_someone_elses_analysis(client, app, analyst, make_user):
    _, headers = analyst
    owner = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    analysis_id = _analysis(app, owner.id)

    posted = client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "malicious"})
    listed = client.get(f"/iris/results/{analysis_id}/feedback", headers=headers)

    assert posted.status_code == 404
    assert listed.status_code == 404


def test_metrics_measure_the_detector_per_family(client, app, analyst):
    """Un acierto (links), un falso positivo (identity), un falso negativo
    y un indeterminado: la métrica global y la de cada familia salen de ahí."""
    user, headers = analyst
    true_positive = _analysis(app, user.id, verdict="Phishing", fired_rules=("Body Links",))
    false_positive = _analysis(app, user.id, verdict="Phishing", fired_rules=("Display Name Spoofing",))
    false_negative = _analysis(app, user.id, verdict="Legitimate", score=95.0)
    undecided = _analysis(app, user.id, verdict="Suspicious", score=60.0)
    for analysis_id, label in ((true_positive, "malicious"), (false_positive, "legitimate"),
                               (false_negative, "malicious"), (undecided, "unknown")):
        client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": label})

    metrics = client.get("/iris/feedback/metrics", headers=headers).get_json()

    assert metrics["analysesTotal"] == 4
    assert metrics["reviewed"] == 4
    assert metrics["unknown"] == 1
    assert metrics["feedbackCoverage"] == 1.0
    overall = metrics["overall"]
    assert (overall["truePositives"], overall["falsePositives"], overall["falseNegatives"]) == (1, 1, 1)
    assert overall["precision"] == 0.5
    assert overall["recall"] == 0.5
    assert overall["disagreementRate"] == 0.6667

    by_family = {entry["family"]: entry for entry in metrics["families"]}
    assert by_family["links"]["fired"] == 1
    assert by_family["links"]["precision"] == 1.0
    assert by_family["links"]["recall"] == 0.5
    assert by_family["identity"]["precision"] == 0.0
    assert by_family["auth"]["fired"] == 0
    assert by_family["auth"]["precision"] is None
    assert by_family["auth"]["coverage"] == 1.0


def test_metrics_only_count_the_latest_label_of_each_analysis(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id, verdict="Phishing")
    client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "legitimate"})
    client.post(f"/iris/results/{analysis_id}/feedback", headers=headers, json={"label": "malicious"})

    metrics = client.get("/iris/feedback/metrics", headers=headers).get_json()

    assert metrics["reviewed"] == 1
    assert metrics["overall"]["truePositives"] == 1
    assert metrics["overall"]["falsePositives"] == 0
