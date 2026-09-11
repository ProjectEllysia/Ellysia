"""Análisis por lotes: varios .eml o un ZIP, con límites, duplicados y back pressure.

Cubre el criterio de cierre: un lote devuelve un resumen, el resultado de cada
elemento y el análisis que creó, y una entrada que falla no pierde el resto.
Y lo que el roadmap pedía evitar: un bucle HTTP que crea cientos de tareas sin
freno. Un lote que no cabe —demasiados mensajes, demasiados bytes o demasiados
análisis en curso— se rechaza entero antes de crear nada.
"""

from __future__ import annotations

import io
import zipfile
from typing import Callable, Optional
from unittest import mock

import pytest
from _iris_msg_fixtures import build_msg

import src.modules.system.config_reading as CR
from src.modules.features.iris.managers import analysis as analysis_mod
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork, build_repository
from src.modules.system.taskqueue import Task, TaskStatus
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_IRIS_ATTRIBUTES = [attribute.db_name for attribute in (
    AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
)]


class _NoopQueue:
    """Cola que acepta el encolado y no ejecuta nada: aquí importa qué se crea."""

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        return Task(id=name or "job", name=name, category=category,
                    external_id=external_id, status=TaskStatus.PENDING)

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None): return None
    def is_recoverable(self, external_id: str, category: Optional[str] = None) -> bool: return True
    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


def _eml(subject: str) -> bytes:
    return (
        f'From: "Ana" <ana@example.org>\nTo: luis@example.com\nSubject: {subject}\n'
        "Date: Mon, 07 Sep 2026 09:30:00 +0000\n"
        f"Message-ID: <{subject.replace(' ', '-')}@example.org>\n"
        "Content-Type: text/plain; charset=utf-8\n\nCuerpo del mensaje.\n"
    ).encode("utf-8")


def _zip(entries: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _upload(client, headers, files):
    data = {"files": [(io.BytesIO(content), name) for name, content in files]}
    with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
        return client.post("/iris/analyze/batch", headers=headers, data=data, content_type="multipart/form-data")


def _limits(monkeypatch, **fields):
    config = CR.IrisConfig(**fields)
    monkeypatch.setattr(CR, "iris_config", lambda: config)


@pytest.fixture
def analyst(make_user, auth_headers):
    user = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    return user, auth_headers(user)


def _statuses(batch) -> list:
    return [(item["filename"], item["status"]) for item in batch["items"]]


# ---------------------------------------------------- .msg de Outlook

def test_outlook_msg_files_are_converted_and_analysed(client, app, analyst):
    """Un .msg entra en el lote como un .eml más, suelto o dentro de un ZIP, y
    lo que se guarda es el .eml convertido: el reanálisis no vuelve a pasar por
    el conversor. Uno dañado se rechaza con su motivo sin tumbar el resto."""
    user, headers = analyst
    loose = build_msg(subject="Aviso", sender_email="alertas@evil.example", body="Entre ya.",
                      message_id="<aviso@evil.example>")
    zipped = build_msg(subject="Otro", sender_email="otro@evil.example", body="Hola.")
    broken = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100

    batch = _upload(client, headers, [("aviso.msg", loose), ("roto.msg", broken),
                                      ("buzon.zip", _zip({"dentro.MSG": zipped}))]).get_json()

    assert _statuses(batch) == [("aviso.msg", "created"), ("roto.msg", "rejected"),
                                ("buzon.zip/dentro.MSG", "created")]
    assert "dañado" in batch["items"][1]["error"]
    with app.app_context():
        stored = build_repository(IrisAnalysisRepository).get_by_id(batch["items"][0]["analysisId"])
        assert stored.user_id == user.id
        assert stored.raw_headers.startswith("From: alertas@evil.example")
        assert "X-Iris-Source-Format: outlook-msg" in stored.raw_headers


# -------------------------------------------------------------- resumen

def test_a_batch_returns_a_summary_and_a_link_per_message(client, app, analyst):
    user, headers = analyst

    response = _upload(client, headers, [("uno.eml", _eml("Uno")), ("dos.eml", _eml("Dos")),
                                         ("notas.txt", b"no es un correo")])

    assert response.status_code == 201, response.get_json()
    batch = response.get_json()
    assert batch["counts"] == {"created": 2, "duplicate": 0, "rejected": 1, "failed": 0}
    assert _statuses(batch) == [("uno.eml", "created"), ("dos.eml", "created"), ("notas.txt", "rejected")]
    assert batch["items"][2]["error"] == "No es un fichero .eml ni .msg."
    with app.app_context():
        repo = build_repository(IrisAnalysisRepository)
        created = [repo.get_by_id(item["analysisId"]) for item in batch["items"][:2]]
    assert [analysis.user_id for analysis in created] == [user.id, user.id]
    assert created[0].raw_headers == _eml("Uno").decode("utf-8")


def test_a_zip_is_expanded_and_its_bad_entries_rejected_one_by_one(client, analyst):
    _, headers = analyst
    archive = _zip({"lote/a.eml": _eml("A"), "lote/b.eml": _eml("B"),
                    "lote/foto.png": b"\x89PNG", "lote/otro.zip": _zip({"c.eml": _eml("C")})})

    batch = _upload(client, headers, [("buzon.zip", archive)]).get_json()

    assert _statuses(batch) == [
        ("buzon.zip/lote/a.eml", "created"), ("buzon.zip/lote/b.eml", "created"),
        ("buzon.zip/lote/foto.png", "rejected"), ("buzon.zip/lote/otro.zip", "rejected"),
    ]


def test_one_broken_message_does_not_lose_the_rest(client, analyst):
    _, headers = analyst

    batch = _upload(client, headers, [("roto.eml", b"hola, esto no tiene cabeceras"),
                                      ("bueno.eml", _eml("Bueno"))]).get_json()

    assert _statuses(batch) == [("roto.eml", "failed"), ("bueno.eml", "created")]
    assert batch["items"][0]["error"]
    assert batch["items"][0]["analysisId"] is None


# ------------------------------------------------------------ duplicados

def test_the_same_message_twice_is_analysed_once(client, analyst):
    _, headers = analyst

    batch = _upload(client, headers, [("a.eml", _eml("Mismo")), ("copia.eml", _eml("Mismo"))]).get_json()

    assert _statuses(batch) == [("a.eml", "created"), ("copia.eml", "duplicate")]
    assert batch["items"][1]["analysisId"] == batch["items"][0]["analysisId"]


def test_a_message_already_analysed_is_not_analysed_again(client, analyst):
    _, headers = analyst
    with mock.patch.object(analysis_mod.TaskQueue, "get_instance", return_value=_NoopQueue()):
        single = client.post("/iris/analyze", headers=headers,
                             json={"mode": "message", "message": _eml("Visto").decode("utf-8")}).get_json()

    batch = _upload(client, headers, [("visto.eml", _eml("Visto"))]).get_json()

    assert _statuses(batch) == [("visto.eml", "duplicate")]
    assert batch["items"][0]["analysisId"] == single["analysisId"]


# ------------------------------------------------------ límites y back pressure

def test_a_batch_over_the_item_limit_is_rejected_whole(client, app, analyst, monkeypatch):
    user, headers = analyst
    _limits(monkeypatch, batch_max_items=2)

    response = _upload(client, headers, [(f"{i}.eml", _eml(f"M{i}")) for i in range(3)])

    assert response.status_code == 400
    with app.app_context():
        assert build_repository(IrisAnalysisRepository).count_by_user(user.id) == 0


def test_an_oversized_message_is_rejected_and_the_rest_analysed(client, analyst, monkeypatch):
    _, headers = analyst
    _limits(monkeypatch, max_message_bytes=2048)

    batch = _upload(client, headers, [("grande.eml", _eml("Grande") + b"x" * 4096),
                                      ("zip.zip", _zip({"grande.eml": _eml("G") + b"y" * 4096})),
                                      ("normal.eml", _eml("Normal"))]).get_json()

    assert _statuses(batch) == [("grande.eml", "rejected"), ("zip.zip/grande.eml", "rejected"),
                                ("normal.eml", "created")]


def test_too_many_analyses_in_flight_rejects_the_batch_before_creating_anything(client, app, analyst, monkeypatch):
    user, headers = analyst
    _limits(monkeypatch, max_active_analyses_per_user=2)
    with app.app_context():
        with UnitOfWork() as uow:
            IrisAnalysisRepository(uow).save(IrisAnalysis(raw_headers="From: a@b.example\nSubject: x\n",
                                                          user_id=user.id, status="running"))

    response = _upload(client, headers, [("a.eml", _eml("A")), ("b.eml", _eml("B"))])

    assert response.status_code == 429
    with app.app_context():
        assert build_repository(IrisAnalysisRepository).count_by_user(user.id) == 1


def test_an_empty_batch_is_rejected(client, analyst):
    _, headers = analyst

    assert _upload(client, headers, []).status_code == 400


# ---------------------------------------------------------- consulta y dueño

def test_a_batch_can_be_consulted_later_with_each_analysis_status(client, analyst):
    _, headers = analyst
    batch_id = _upload(client, headers, [("a.eml", _eml("A"))]).get_json()["batchId"]

    batch = client.get(f"/iris/batches/{batch_id}", headers=headers).get_json()

    assert batch["items"][0]["analysisStatus"] == "pending"
    listed = client.get("/iris/batches", headers=headers).get_json()["batches"]
    assert [(entry["batchId"], entry["total"]) for entry in listed] == [(batch_id, 1)]


def test_a_batch_belongs_to_whoever_uploaded_it(client, analyst, make_user, auth_headers):
    _, headers = analyst
    batch_id = _upload(client, headers, [("a.eml", _eml("A"))]).get_json()["batchId"]
    stranger = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))

    assert client.get(f"/iris/batches/{batch_id}", headers=stranger).status_code == 404
    assert client.get("/iris/batches", headers=stranger).get_json()["batches"] == []
