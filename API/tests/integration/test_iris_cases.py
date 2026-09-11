"""Casos de analista: convertir informes aislados en trabajo operativo medible.

Cubre el criterio de cierre: un caso se abre (con uno o varios análisis), se
asigna, se anota y se cierra con una razón, todo queda en su timeline, y los
análisis que agrupa no cambian nunca.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_IRIS_ATTRIBUTES = [attribute.db_name for attribute in (
    AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
)]


def _analysis(app, user_id: int, verdict: str = "Phishing", score: float = 20.0) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers="From: a@b.example\nSubject: x\n", user_id=user_id,
                                    status="finished", verdict=verdict, total_score=score)
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


@pytest.fixture
def analyst(make_user, auth_headers):
    user = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    return user, auth_headers(user)


def _open(client, headers, **body):
    payload = {"title": "Campaña de facturas falsas"}
    payload.update(body)
    return client.post("/iris/cases", headers=headers, json=payload)


def _status(client, headers, case_id, status, reason=None):
    return client.post(f"/iris/cases/{case_id}/status", headers=headers,
                       json={"status": status, "reason": reason})


# -------------------------------------------------------------- apertura

def test_a_case_groups_several_analyses_without_changing_them(client, app, analyst):
    user, headers = analyst
    first, second = _analysis(app, user.id), _analysis(app, user.id, "Suspicious", 60.0)

    response = _open(client, headers, analysisIds=[first, second, first], priority="high", tags=["Facturas"])

    assert response.status_code == 201, response.get_json()
    case = response.get_json()
    assert case["status"] == "new" and case["priority"] == "high" and case["tags"] == ["facturas"]
    assert [entry["analysisId"] for entry in case["analyses"]] == [first, second]
    assert [event["kind"] for event in case["timeline"]] == ["created"]
    assert case["timeline"][0]["actor"] == user.username
    report = client.get(f"/iris/results/{first}", headers=headers).get_json()
    assert (report["verdict"], report["totalScore"]) == ("Phishing", 20.0)


def test_a_case_needs_a_title_and_a_known_priority(client, analyst):
    _, headers = analyst

    assert _open(client, headers, title="   ").status_code == 400
    assert _open(client, headers, priority="urgentísimo").status_code == 422


def test_nobody_opens_a_case_with_someone_elses_analysis(client, app, analyst, make_user, auth_headers):
    _, headers = analyst
    stranger = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    foreign = _analysis(app, stranger.id)

    assert _open(client, headers, analysisIds=[foreign]).status_code == 404


# ------------------------------------------------------------ ciclo de vida

def test_a_case_moves_through_its_lifecycle_and_closes_with_a_reason(client, analyst):
    _, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]

    assert _status(client, headers, case_id, "triage").status_code == 200
    assert _status(client, headers, case_id, "contained").status_code == 200
    assert _status(client, headers, case_id, "resolved").status_code == 400
    closed = _status(client, headers, case_id, "resolved", "Enlaces bloqueados y buzones limpios.")

    assert closed.status_code == 200
    case = closed.get_json()
    assert case["status"] == "resolved"
    assert case["resolutionReason"] == "Enlaces bloqueados y buzones limpios."
    assert case["closedAt"]
    transitions = [(event["detail"]["from"], event["detail"]["to"])
                   for event in case["timeline"] if event["kind"] == "status_changed"]
    assert transitions == [("new", "triage"), ("triage", "contained"), ("contained", "resolved")]


def test_a_closed_case_only_reopens_to_triage(client, analyst):
    _, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]
    _status(client, headers, case_id, "false_positive", "Newsletter legítima del proveedor.")

    assert _status(client, headers, case_id, "contained").status_code == 400
    reopened = _status(client, headers, case_id, "triage").get_json()

    assert reopened["status"] == "triage"
    assert reopened["closedAt"] is None and reopened["resolutionReason"] is None
    reasons = [event["detail"]["reason"] for event in reopened["timeline"] if event["kind"] == "status_changed"]
    assert reasons == ["Newsletter legítima del proveedor.", None]


def test_an_unknown_status_is_rejected(client, analyst):
    _, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]

    assert _status(client, headers, case_id, "archived").status_code == 422


# ------------------------------------------------- notas, asignación, cambios

def test_notes_and_changes_land_in_the_timeline(client, analyst):
    user, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]

    client.post(f"/iris/cases/{case_id}/notes", headers=headers, json={"note": "  Tres usuarios hicieron clic. "})
    case = client.patch(f"/iris/cases/{case_id}", headers=headers,
                        json={"priority": "critical", "title": "Campaña Q3", "assigneeId": user.id}).get_json()

    assert case["priority"] == "critical" and case["title"] == "Campaña Q3"
    assert case["assignee"] == user.username
    kinds = [event["kind"] for event in case["timeline"]]
    assert kinds == ["created", "note", "title_changed", "priority_changed", "assigned"]
    note = case["timeline"][1]
    assert note["note"] == "Tres usuarios hicieron clic." and note["actor"] == user.username


def test_an_empty_note_is_rejected(client, analyst):
    _, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]

    assert client.post(f"/iris/cases/{case_id}/notes", headers=headers, json={"note": "   "}).status_code == 400


def test_a_case_is_only_assigned_to_whoever_can_see_its_analyses(client, analyst, make_user):
    """Un caso muestra análisis de correo personal: asignarlo a otra persona le
    daría acceso a ese correo, y una organización comparte plan, no datos."""
    user, headers = analyst
    other = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    case = _open(client, headers).get_json()
    case_id = case["caseId"]
    assert case["ownerId"] == user.id

    assert client.patch(f"/iris/cases/{case_id}", headers=headers, json={"assigneeId": other.id}).status_code == 400
    assigned = client.patch(f"/iris/cases/{case_id}", headers=headers, json={"assigneeId": user.id}).get_json()
    assert assigned["assigneeId"] == user.id
    unassigned = client.patch(f"/iris/cases/{case_id}", headers=headers, json={"assigneeId": None}).get_json()
    assert unassigned["assigneeId"] is None


# ------------------------------------------------------------------ análisis

def test_analyses_are_linked_and_unlinked(client, app, analyst):
    user, headers = analyst
    first, second = _analysis(app, user.id), _analysis(app, user.id)
    case_id = _open(client, headers, analysisIds=[first]).get_json()["caseId"]

    linked = client.post(f"/iris/cases/{case_id}/analyses", headers=headers, json={"analysisId": second})
    assert [entry["analysisId"] for entry in linked.get_json()["analyses"]] == [first, second]
    assert client.post(f"/iris/cases/{case_id}/analyses", headers=headers,
                       json={"analysisId": second}).status_code == 400

    unlinked = client.delete(f"/iris/cases/{case_id}/analyses/{first}", headers=headers).get_json()
    assert [entry["analysisId"] for entry in unlinked["analyses"]] == [second]
    assert client.get(f"/iris/results/{first}", headers=headers).status_code == 200
    kinds = [event["kind"] for event in unlinked["timeline"]]
    assert kinds == ["created", "analysis_linked", "analysis_unlinked"]


def test_deleting_an_analysis_leaves_the_case(client, app, analyst):
    user, headers = analyst
    analysis_id = _analysis(app, user.id)
    case_id = _open(client, headers, analysisIds=[analysis_id]).get_json()["caseId"]

    assert client.delete(f"/iris/results/{analysis_id}", headers=headers).status_code == 200

    case = client.get(f"/iris/cases/{case_id}", headers=headers).get_json()
    assert case["analyses"] == []
    assert [event["kind"] for event in case["timeline"]] == ["created"]


# ----------------------------------------------------------- listado y dueño

def test_the_list_counts_the_queue_by_status_and_filters(client, analyst):
    user, headers = analyst
    first = _open(client, headers, title="Uno").get_json()["caseId"]
    _open(client, headers, title="Dos")
    _status(client, headers, first, "triage")
    client.patch(f"/iris/cases/{first}", headers=headers, json={"assigneeId": user.id})

    everything = client.get("/iris/cases", headers=headers).get_json()
    assert everything["total"] == 2
    assert everything["countsByStatus"] == {"new": 1, "triage": 1}
    triage = client.get("/iris/cases?status=triage", headers=headers).get_json()
    assert [case["caseId"] for case in triage["cases"]] == [first]
    mine = client.get("/iris/cases?assignedToMe=true", headers=headers).get_json()
    assert [case["caseId"] for case in mine["cases"]] == [first]
    assert mine["cases"][0]["analysisCount"] == 0


def test_a_case_belongs_to_whoever_opened_it(client, app, analyst, make_user, auth_headers):
    user, headers = analyst
    case_id = _open(client, headers).get_json()["caseId"]
    stranger = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))
    mine = _analysis(app, user.id)

    assert client.get(f"/iris/cases/{case_id}", headers=stranger).status_code == 404
    assert _status(client, stranger, case_id, "triage").status_code == 404
    assert client.post(f"/iris/cases/{case_id}/notes", headers=stranger, json={"note": "x"}).status_code == 404
    assert client.get("/iris/cases", headers=stranger).get_json()["cases"] == []
    stranger_case = _open(client, stranger).get_json()["caseId"]
    assert client.post(f"/iris/cases/{stranger_case}/analyses", headers=stranger,
                       json={"analysisId": mine}).status_code == 404
