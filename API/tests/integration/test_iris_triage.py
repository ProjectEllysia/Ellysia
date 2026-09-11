"""Historial de triaje: vistas guardadas, etiquetas, búsqueda por IOC y pendientes.

Cubre el criterio de cierre: un analista vuelve a una cola de trabajo sin
reconstruir cada filtro (vistas guardadas), agrupa análisis con etiquetas,
encuentra todos los análisis que tocan un dominio o una IP aunque el raw ya se
haya purgado, y ve qué le queda por revisar.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis, IrisAnalystFeedback
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisAnalystFeedbackRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_IRIS_ATTRIBUTES = [attribute.db_name for attribute in (
    AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
)]

_PHISH = (
    "Received: from mail.evil.example (mail.evil.example [198.51.100.7]) "
    "by mx.example.com with ESMTP id x1; Mon, 07 Sep 2026 09:30:00 +0000\n"
    'From: "Banco" <alertas@evil.example>\n'
    "To: cliente@example.com\n"
    "Subject: Verifique su cuenta\n"
    "Date: Mon, 07 Sep 2026 09:30:00 +0000\n"
    "Message-ID: <x1@evil.example>\n"
    "Content-Type: text/html; charset=utf-8\n\n"
    '<p>Entre aquí: <a href="https://login.evil.example/verify">https://banco.example</a></p>\n'
)
_OTHER = (
    'From: "Ana" <ana@example.org>\nTo: luis@example.com\nSubject: Comida\n'
    "Date: Mon, 07 Sep 2026 09:30:00 +0000\nMessage-ID: <c1@example.org>\n"
    "Content-Type: text/plain\n\n¿Comemos el jueves?\n"
)


def _run(app, user_id: int, raw: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


def _seed(app, user_id: int, **fields) -> int:
    values = dict(raw_headers="From: a@b.example\nSubject: x\n", user_id=user_id,
                  status="finished", verdict="Suspicious", total_score=60.0)
    values.update(fields)
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(**values)
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _ids(response) -> list[int]:
    return sorted(item["analysisId"] for item in response.get_json()["analyses"])


@pytest.fixture
def analyst(make_user, auth_headers):
    user = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    return user, auth_headers(user)


# ----------------------------------------------------------- vistas guardadas

def test_a_saved_view_brings_back_the_same_queue(client, analyst):
    _, headers = analyst
    filters = {"verdict": "Phishing", "review": "pending", "search": "", "sort_by": "score", "sort_dir": "asc"}

    created = client.post("/iris/triage/views", headers=headers, json={"name": "  Phishing sin revisar ", "filters": filters})

    assert created.status_code == 201, created.get_json()
    view = created.get_json()
    assert view["name"] == "Phishing sin revisar"
    assert view["filters"] == {"verdict": "Phishing", "review": "pending", "sort_by": "score", "sort_dir": "asc"}
    listed = client.get("/iris/triage/views", headers=headers).get_json()["views"]
    assert [entry["viewId"] for entry in listed] == [view["viewId"]]


def test_a_saved_view_only_accepts_the_filters_the_list_understands(client, analyst):
    _, headers = analyst

    response = client.post("/iris/triage/views", headers=headers,
                           json={"name": "Mala", "filters": {"verdict": "Maybe"}})

    assert response.status_code == 422


def test_two_views_cannot_share_a_name(client, analyst):
    _, headers = analyst
    body = {"name": "Cola", "filters": {"status": "finished"}}
    assert client.post("/iris/triage/views", headers=headers, json=body).status_code == 201

    assert client.post("/iris/triage/views", headers=headers, json=body).status_code == 400


def test_a_view_belongs_to_whoever_saved_it(client, analyst, make_user, auth_headers):
    _, headers = analyst
    view_id = client.post("/iris/triage/views", headers=headers,
                          json={"name": "Mía", "filters": {}}).get_json()["viewId"]
    stranger = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))

    assert client.delete(f"/iris/triage/views/{view_id}", headers=stranger).status_code == 404
    assert client.get("/iris/triage/views", headers=stranger).get_json()["views"] == []
    assert client.delete(f"/iris/triage/views/{view_id}", headers=headers).status_code == 200
    assert client.get("/iris/triage/views", headers=headers).get_json()["views"] == []


# ------------------------------------------------------------------ etiquetas

def test_tags_are_normalized_counted_and_filterable(client, app, analyst):
    user, headers = analyst
    tagged = _seed(app, user.id)
    untagged = _seed(app, user.id)

    response = client.put(f"/iris/results/{tagged}/tags", headers=headers,
                          json={"tags": ["Campaña  Q3", "campaña q3", " urgente ", ""]})

    assert response.status_code == 200
    assert response.get_json()["tags"] == ["campaña q3", "urgente"]
    assert client.get("/iris/tags", headers=headers).get_json()["tags"] == [
        {"name": "campaña q3", "count": 1}, {"name": "urgente", "count": 1},
    ]
    filtered = client.get("/iris/results?tag=urgente", headers=headers)
    assert _ids(filtered) == [tagged]
    listing = {item["analysisId"]: item for item in client.get("/iris/results", headers=headers).get_json()["analyses"]}
    assert listing[tagged]["tags"] == ["campaña q3", "urgente"]
    assert listing[untagged]["tags"] == []


def test_an_empty_list_removes_every_tag(client, app, analyst):
    user, headers = analyst
    analysis_id = _seed(app, user.id)
    client.put(f"/iris/results/{analysis_id}/tags", headers=headers, json={"tags": ["a"]})

    client.put(f"/iris/results/{analysis_id}/tags", headers=headers, json={"tags": []})

    assert client.get("/iris/tags", headers=headers).get_json()["tags"] == []


def test_too_many_tags_are_rejected(client, app, analyst):
    user, headers = analyst
    analysis_id = _seed(app, user.id)

    response = client.put(f"/iris/results/{analysis_id}/tags", headers=headers,
                          json={"tags": [f"t{i}" for i in range(11)]})

    assert response.status_code == 400


def test_nobody_tags_someone_elses_analysis(client, app, analyst, make_user, auth_headers):
    user, _ = analyst
    analysis_id = _seed(app, user.id)
    stranger = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))

    assert client.put(f"/iris/results/{analysis_id}/tags", headers=stranger,
                      json={"tags": ["x"]}).status_code == 404


# ------------------------------------------------------- pendiente de revisar

def test_pending_review_lists_finished_analyses_nobody_has_corrected(client, app, analyst):
    user, headers = analyst
    reviewed = _seed(app, user.id)
    pending = _seed(app, user.id)
    _seed(app, user.id, status="failed", verdict=None, total_score=None)
    with app.app_context():
        with UnitOfWork() as uow:
            IrisAnalystFeedbackRepository(uow).save(
                IrisAnalystFeedback(analysis_id=reviewed, author_id=user.id, label="legitimate"))

    assert _ids(client.get("/iris/results?review=pending", headers=headers)) == [pending]
    assert _ids(client.get("/iris/results?review=reviewed", headers=headers)) == [reviewed]
    listing = {item["analysisId"]: item for item in client.get("/iris/results", headers=headers).get_json()["analyses"]}
    assert listing[reviewed]["reviewed"] is True
    assert listing[pending]["reviewed"] is False


# ---------------------------------------------------------------- búsqueda IOC

def test_an_analysis_can_be_found_by_one_of_its_indicators(client, app, analyst):
    user, headers = analyst
    phish = _run(app, user.id, _PHISH)
    _run(app, user.id, _OTHER)

    for query in ("login.evil.example", "hxxps://login.evil[.]example/verify", "198.51.100.7", "EVIL.EXAMPLE"):
        response = client.get("/iris/results", headers=headers, query_string={"ioc": query})
        assert _ids(response) == [phish], query


def test_indicators_survive_the_raw_purge(client, app, analyst):
    """La retención purga el raw pero no los IOCs: seguir pudiendo responder
    «¿he visto antes este dominio?» es justo lo que la retención quiere conservar."""
    user, headers = analyst
    phish = _run(app, user.id, _PHISH)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            analysis = repo.get_by_id(phish)
            analysis.raw_headers = None
            repo.update(analysis)

    assert _ids(client.get("/iris/results?ioc=evil.example", headers=headers)) == [phish]


def test_the_ioc_search_never_crosses_users(client, app, analyst, make_user, auth_headers):
    user, _ = analyst
    _run(app, user.id, _PHISH)
    stranger = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))

    assert _ids(client.get("/iris/results?ioc=evil.example", headers=stranger)) == []
