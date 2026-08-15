"""Tests de integración de la generación de informes PDF de Iris.

Cubre el ciclo completo: encolar generación, consultar estado, listar,
descargar y eliminar un ``IrisDocument``, además de las fronteras de
autorización/propiedad. La cola de tareas se sustituye por una versión
síncrona (sin Redis/worker real) y el directorio de salida del PDF se
redirige a un ``tmp_path`` para no escribir en datos reales.
"""

from __future__ import annotations

from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.system.taskqueue import Task, TaskStatus

import src.modules.features.iris.managers.analysis as managers_mod
import src.modules.features.iris.services.reports as reports_mod

pytestmark = pytest.mark.integration


class _SyncTaskQueue:
    """Cola fake que ejecuta el job en el acto (sin Redis ni worker)."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        self.submitted.append({"name": name, "category": category, "external_id": external_id})
        func(*args, **(kwargs or {}))  # ejecuta el job de forma síncrona
        return Task(id=name or "job", name=name, category=category,
                    external_id=external_id, status=TaskStatus.COMPLETED)

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None):
        return None

    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


@pytest.fixture()
def fake_queue():
    """Inyecta la cola síncrona en cualquier ``IrisReportManager`` del request."""
    queue = _SyncTaskQueue()
    with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
        yield queue


@pytest.fixture(autouse=True)
def _redirect_pdf_output(tmp_path, monkeypatch):
    """Evita escribir los PDFs generados en el directorio real de salida."""
    monkeypatch.setattr(
        reports_mod.CR, "get_directory_of", lambda *_a, **_k: str(tmp_path)
    )


def _seed_analysis(app, user_id: int, status: str = "finished",
                    verdict: str = "Phishing", total_score: float = -25.0) -> int:
    """Persist an IrisAnalysis (with one rule result) and return its id."""
    from src.modules.infrastructure import unit_of_work as uow_mod
    from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
    from src.modules.features.iris.model import IrisAnalysis, IrisRuleResult

    with app.app_context():
        with uow_mod.UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: a@b.com\nTo: c@d.com\nSubject: Test\n",
                user_id=user_id,
                status=status,
                total_score=total_score if status == "finished" else None,
                verdict=verdict if status == "finished" else None,
            )
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id

            if status == "finished":
                rr = IrisRuleResult(
                    analysis_id=analysis_id, rule_name="SPF", category="authentication",
                    score=-10, verdict="fail", details={"domain": "x.com"},
                    recommendation="Revisar SPF", position=0,
                )
                IrisRuleResultRepository(uow).save(rr)

            return analysis_id


# --------------------------------------------------------------- generate_document

def test_generate_document_requires_authentication(client):
    resp = client.post("/iris/results/1/document")
    assert resp.status_code == 401


def test_generate_document_requires_create_attribute(client, stripped_user, auth_headers):
    resp = client.post("/iris/results/1/document", headers=auth_headers(stripped_user))
    assert resp.status_code == 403


def test_generate_document_unknown_analysis_returns_404(client, root_headers):
    resp = client.post("/iris/results/999999/document", headers=root_headers)
    assert resp.status_code == 404


def test_generate_document_not_finished_returns_409(client, app, root_user, root_headers):
    analysis_id = _seed_analysis(app, root_user.id, status="pending")
    resp = client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)
    assert resp.status_code == 409


def test_generate_document_submit_failure_marks_document_error(client, app, root_user, root_headers):
    """Si el encolado rechaza el job (p.ej. choque con uno en curso), el
    documento ya creado no debe quedarse en "running" para siempre."""
    analysis_id = _seed_analysis(app, root_user.id)

    class _RejectingQueue(_SyncTaskQueue):
        def submit(self, *args, **kwargs):
            raise RuntimeError("job ya en ejecución")

    queue = _RejectingQueue()
    with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
        resp = client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)
    assert resp.status_code == 500

    from src.modules.features.iris.repositories import IrisReportRepository
    from src.modules.infrastructure import UnitOfWork
    with app.app_context():
        with UnitOfWork() as uow:
            docs = IrisReportRepository(uow).get_documents_by_parent(analysis_id)
            assert len(docs) == 1
            assert docs[0].status == "error"


def test_generate_document_success_then_download(client, app, root_user, root_headers, fake_queue):
    analysis_id = _seed_analysis(app, root_user.id)

    resp = client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)
    assert resp.status_code == 202
    doc_id = resp.get_json()["documentId"]

    status_resp = client.get(f"/iris/document-status?documentId={doc_id}", headers=root_headers)
    assert status_resp.status_code == 200
    body = status_resp.get_json()
    assert body["status"] == "done"
    assert body["downloadUrl"] == f"/iris/document/{doc_id}/download"

    download_resp = client.get(f"/iris/document/{doc_id}/download", headers=root_headers)
    assert download_resp.status_code == 200
    assert download_resp.mimetype == "application/pdf"


def test_list_documents_for_analysis(client, app, root_user, root_headers, fake_queue):
    analysis_id = _seed_analysis(app, root_user.id)
    client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)

    resp = client.get(f"/iris/results/{analysis_id}/documents", headers=root_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 1
    assert body["documents"][0]["status"] == "done"


def test_list_all_documents_for_user(client, app, root_user, root_headers, fake_queue):
    analysis_id = _seed_analysis(app, root_user.id)
    client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)

    resp = client.get("/iris/documents", headers=root_headers)
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 1


def test_document_not_owned_by_other_user_is_hidden(client, app, root_user, regular_user, auth_headers, root_headers, fake_queue):
    analysis_id = _seed_analysis(app, root_user.id)
    resp = client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)
    doc_id = resp.get_json()["documentId"]

    # Same error for "not found" and "not owned" to prevent ID enumeration.
    other_resp = client.get(f"/iris/document/{doc_id}/download", headers=auth_headers(regular_user))
    assert other_resp.status_code == 404


def test_delete_document(client, app, root_user, root_headers, fake_queue):
    analysis_id = _seed_analysis(app, root_user.id)
    gen_resp = client.post(f"/iris/results/{analysis_id}/document", headers=root_headers)
    doc_id = gen_resp.get_json()["documentId"]

    del_resp = client.delete(f"/iris/document/{doc_id}", headers=root_headers)
    assert del_resp.status_code == 200

    after = client.get(f"/iris/document-status?documentId={doc_id}", headers=root_headers)
    assert after.status_code == 404
