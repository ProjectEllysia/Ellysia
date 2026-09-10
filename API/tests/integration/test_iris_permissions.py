"""La matriz ABAC de Iris, atada a un test.

El `README.md` documentaba `IRIS_UPDATE` para reanálisis, resumen de IA y
generación de PDF, mientras el código exigía `IRIS_CREATE`. Un cliente que
siguiera el contrato publicado se llevaba un 403 inesperado.

Al contrastar las dos versiones contra lo que las operaciones **hacen de
verdad**, la que estaba mal era la documentación: las tres crean una entidad
nueva (un análisis, un resumen, un documento) y consumen cuota por ella, que
es exactamente lo que distingue `CREATE` de `UPDATE`. `UPDATE` queda para lo
que modifica algo que ya existe: cancelar un análisis en curso, pausar una
conexión de buzón, forzar una sincronización.

Este fichero fija esa matriz para que la divergencia no pueda repetirse en
silencio: si alguien cambia un decorador, aquí falla algo.
"""

from __future__ import annotations

from typing import Callable, Optional

import pytest

import src.modules.features.iris.managers.analysis as analysis_mod
from src.modules.system.taskqueue import Task, TaskStatus
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration


class _NoopQueue:
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


# Cada fila es (método, ruta, atributo exigido, cuerpo). La ruta usa un id que
# no existe a propósito: lo que se comprueba aquí es la puerta de entrada, y un
# 404 ya demuestra que el guardia dejó pasar.
#
# Los dos endpoints con cuerpo obligatorio lo llevan relleno porque
# flask-smorest valida el schema **antes** de que corra `@require_attributes`:
# sin cuerpo válido, la petición muere en un 422 y la comprobación de permisos
# nunca llega a ejecutarse — con lo que el test no probaría nada.
_ENDPOINTS = [
    ("post", "/iris/analyze", AttributeType.IRIS_CREATE,
     {"headers": "From: a@b.com\nSubject: Hola"}),
    ("get", "/iris/status?id=999999", AttributeType.IRIS_READ, None),
    ("get", "/iris/results", AttributeType.IRIS_READ, None),
    ("get", "/iris/capabilities", AttributeType.IRIS_READ, None),
    ("get", "/iris/results/999999", AttributeType.IRIS_READ, None),
    ("get", "/iris/results/999999/path", AttributeType.IRIS_READ, None),
    ("get", "/iris/results/999999/iocs", AttributeType.IRIS_READ, None),
    ("get", "/iris/results/999999/export", AttributeType.IRIS_READ, None),
    ("post", "/iris/results/999999/reanalyze", AttributeType.IRIS_CREATE, None),
    ("post", "/iris/results/999999/ai-summary", AttributeType.IRIS_CREATE, None),
    ("post", "/iris/results/999999/document", AttributeType.IRIS_CREATE, None),
    ("post", "/iris/analyze/999999/cancel", AttributeType.IRIS_UPDATE, None),
    ("delete", "/iris/results/999999", AttributeType.IRIS_DELETE, None),
    ("get", "/iris/documents", AttributeType.IRIS_READ, None),
    ("get", "/iris/results/999999/documents", AttributeType.IRIS_READ, None),
    ("get", "/iris/document/999999/download", AttributeType.IRIS_READ, None),
    ("delete", "/iris/document/999999", AttributeType.IRIS_DELETE, None),
    ("get", "/iris/mailbox/providers", AttributeType.IRIS_READ, None),
    ("post", "/iris/mailbox/connect", AttributeType.IRIS_CREATE, {"provider": "gmail"}),
    ("get", "/iris/mailbox/connections", AttributeType.IRIS_READ, None),
    ("patch", "/iris/mailbox/connections/999999", AttributeType.IRIS_UPDATE, None),
    ("delete", "/iris/mailbox/connections/999999", AttributeType.IRIS_DELETE, None),
    ("post", "/iris/mailbox/connections/999999/sync", AttributeType.IRIS_UPDATE, None),
    ("get", "/iris/mailbox/connections/999999/folders", AttributeType.IRIS_READ, None),
    ("get", "/iris/mailbox/connections/999999/health", AttributeType.IRIS_READ, None),
    ("get", "/iris/notification-preferences", AttributeType.IRIS_READ, None),
    ("put", "/iris/notification-preferences", AttributeType.IRIS_UPDATE, {}),
    ("get", "/iris/retention-policy", AttributeType.IRIS_READ, None),
]

_ALL_IRIS_ATTRIBUTES = [
    AttributeType.IRIS_READ,
    AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE,
    AttributeType.IRIS_DELETE,
]


def _call(client, method: str, path: str, headers: dict, body):
    if body is None:
        return getattr(client, method)(path, headers=headers)
    return getattr(client, method)(path, headers=headers, json=body)


_IDS = [f"{method.upper()} {path.split('?')[0]}" for method, path, _, _ in _ENDPOINTS]


@pytest.mark.parametrize("method,path,required,body", _ENDPOINTS, ids=_IDS)
def test_the_documented_attribute_opens_the_door(client, make_user, auth_headers,
                                                 method, path, required, body, monkeypatch):
    """Con el atributo que el contrato dice, la petición **no** da 403.

    El resultado puede ser 404 (el id no existe), 422 (falta cuerpo) o 200:
    cualquiera de ellos significa que la autorización dejó pasar, que es lo
    único que este test juzga.
    """
    monkeypatch.setattr(analysis_mod.TaskQueue, "get_instance", lambda: _NoopQueue())
    user = make_user(role="role_user", attributes=[required.db_name])

    response = _call(client, method, path, auth_headers(user), body)

    assert response.status_code != 403, (
        f"{method.upper()} {path} exige más que {required}, "
        "pero el contrato publica ese atributo"
    )


@pytest.mark.parametrize("method,path,required,body", _ENDPOINTS, ids=_IDS)
def test_every_other_attribute_is_refused(client, make_user, auth_headers,
                                          method, path, required, body, monkeypatch):
    """Y con cualquier **otro** atributo de Iris, 403.

    Esta es la mitad que convierte la matriz en un contrato de verdad. Sin
    ella, dar todos los permisos a todo el mundo pasaría el test de arriba.
    """
    monkeypatch.setattr(analysis_mod.TaskQueue, "get_instance", lambda: _NoopQueue())
    others = [attribute for attribute in _ALL_IRIS_ATTRIBUTES if attribute is not required]
    user = make_user(role="role_user", attributes=[attribute.db_name for attribute in others])

    response = _call(client, method, path, auth_headers(user), body)

    assert response.status_code == 403, (
        f"{method.upper()} {path} deja pasar sin {required}"
    )


def test_a_refusal_reveals_nothing_about_the_resource(client, app, make_user, auth_headers):
    """Criterio de cierre del issue: un 403 no puede filtrar existencia ni
    contenido.

    Se piden dos análisis, uno que no existe y otro que sí existe pero es de
    otro usuario. Las dos respuestas tienen que ser indistinguibles: si el
    cuerpo o el código cambiaran, el 403 se convertiría en un oráculo para
    enumerar qué análisis hay.
    """
    from src.modules.features.iris.model import IrisAnalysis
    from src.modules.features.iris.repositories import IrisAnalysisRepository
    from src.modules.infrastructure import UnitOfWork

    owner = make_user(role="role_user")
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=owner.id,
                                    status="finished")
            IrisAnalysisRepository(uow).save(analysis)
            existing_id = analysis.id

    intruder = make_user(role="role_user", attributes=[])
    headers = auth_headers(intruder)

    missing = client.get("/iris/results/999999", headers=headers)
    existing = client.get(f"/iris/results/{existing_id}", headers=headers)

    assert missing.status_code == existing.status_code == 403
    assert missing.get_json() == existing.get_json()
