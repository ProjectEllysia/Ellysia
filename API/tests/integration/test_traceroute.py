"""Tests de integración del traceroute (asíncrono) del módulo Themis.

El traceroute se calcula en segundo plano (worker RQ): el endpoint encola el
trabajo y responde ``status="pending"`` al instante; el resultado se sirve de la
caché en lecturas posteriores. Aquí la cola se sustituye por una *fake* que
ejecuta el job de forma síncrona, de modo que la fila queda persistida en el
mismo request y la segunda lectura ya ve el resultado.

Cubre: frontera de autorización, ciclo pending→done, cacheo por (usuario,
target), recálculo forzado, el caso de fallo (sin saltos) cacheado como
``failed`` con TTL corto, invalidación por antigüedad y aislamiento entre
usuarios. El comando real ``traceroute`` se mockea para no depender del binario
ni de la red.
"""

from datetime import datetime, timedelta
from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.system.taskqueue import Task, TaskStatus

import src.modules.features.themis.managers as managers_mod

pytestmark = pytest.mark.integration


_TARGET = "93.184.216.34"
_HOPS = [
    {"ttl": 1, "ip": "192.168.1.1", "hostname": "router", "rtt_ms": 1.2},
    {"ttl": 2, "ip": None, "hostname": None, "rtt_ms": None},
    {"ttl": 3, "ip": _TARGET, "hostname": None, "rtt_ms": 10.0},
]

_TRACE_PATH = "src.modules.features.themis.services.traceroute.TracerouteService.trace"


class _SyncTaskQueue:
    """Cola fake que ejecuta el job en el acto (sin Redis ni worker).

    Modela la consistencia eventual del flujo real: tras ``submit`` la fila ya
    está persistida, pero el manager sigue devolviendo ``pending`` (igual que en
    producción, donde el worker corre en paralelo). Una segunda lectura sirve el
    resultado de la caché.
    """

    def __init__(self) -> None:
        self.submitted: list[dict] = []
        self.running_task: Optional[Task] = None  # forzar la rama "pending"

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        self.submitted.append({"name": name, "category": category,
                               "external_id": external_id, "args": args})
        func(*args, **(kwargs or {}))  # ejecuta el job de forma síncrona
        return Task(id=name or "job", name=name, category=category,
                    external_id=external_id, status=TaskStatus.PENDING)

    def get_task_by_external_id(self, external_id: str,
                                category: Optional[str] = None) -> Optional[Task]:
        return self.running_task

    # Métodos restantes del contrato ITaskQueue (no usados aquí).
    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


@pytest.fixture()
def fake_queue():
    """Inyecta la cola síncrona en cualquier ``TracerouteManager`` del request."""
    queue = _SyncTaskQueue()
    with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
        yield queue


def _create_scan(app, user_id: int, target: str = _TARGET) -> int:
    """Persist a finished NmapScan owned by ``user_id`` and return its id."""
    from src.modules.infrastructure import unit_of_work as uow_mod
    from src.modules.features.themis.repositories import ScanRepository
    from src.modules.features.themis.model import NmapScan

    with app.app_context():
        with uow_mod.UnitOfWork() as uow:
            scan = NmapScan(target=target, user_id=user_id)
            ScanRepository(uow).save(scan)
            return scan.id


def _seed_trace(app, user_id: int, hops: list, target: str = _TARGET,
                age: timedelta = timedelta(0)) -> None:
    """Seed a cached Traceroute row with a controllable ``created_at`` age."""
    from src.modules.infrastructure import unit_of_work as uow_mod
    from src.modules.features.themis.repositories import TracerouteRepository

    with app.app_context():
        with uow_mod.UnitOfWork() as uow:
            trace = TracerouteRepository(uow).upsert(user_id, target, hops)
            trace.created_at = datetime.utcnow() - age


def _url(scan_id: int) -> str:
    return f"/themis/scan/{scan_id}/traceroute"


# ------------------------------------------------------------------ autorización

def test_traceroute_requires_authentication(client, app, regular_user):
    scan_id = _create_scan(app, regular_user.id)
    assert client.get(_url(scan_id)).status_code == 401


def test_traceroute_scan_not_found(client, regular_user, auth_headers, fake_queue):
    resp = client.get(_url(999999), headers=auth_headers(regular_user))
    assert resp.status_code == 404
    assert fake_queue.submitted == []  # no se encola nada para un scan ajeno


# ------------------------------------------------------------------ pending → done

def test_first_read_enqueues_then_serves_from_cache(client, app, regular_user, auth_headers, fake_queue):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        first = client.get(_url(scan_id), headers=headers)
        assert first.status_code == 200
        body = first.get_json()
        # La primera lectura encola el cálculo y responde "pending".
        assert body["status"] == "pending"
        assert body["hops"] == []
        assert len(fake_queue.submitted) == 1

        # La fila ya está persistida (la cola fake corrió el job): se sirve de caché.
        second = client.get(_url(scan_id), headers=headers)
        assert second.status_code == 200
        body2 = second.get_json()
        assert body2["status"] == "done"
        assert body2["hops"] == _HOPS
        assert body2["hopCount"] == 3
        assert body2["cached"] is True

        # La segunda lectura sale de caché: no se vuelve a ejecutar ni a encolar.
        assert traced.call_count == 1
        assert len(fake_queue.submitted) == 1


def test_pending_while_a_job_is_already_running(client, app, regular_user, auth_headers, fake_queue):
    # Si ya hay un job vivo para (usuario, target), la lectura responde "pending"
    # sin encolar otro ni ejecutar el comando.
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)
    fake_queue.running_task = Task(
        id="job", category="themis.traceroute", status=TaskStatus.RUNNING
    )

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        resp = client.get(_url(scan_id), headers=headers)
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "pending"
        assert traced.call_count == 0
        assert fake_queue.submitted == []


def test_refresh_forces_recompute(client, app, regular_user, auth_headers, fake_queue):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        client.get(_url(scan_id), headers=headers)  # primer cálculo (cachea)
        assert traced.call_count == 1

        refreshed = client.post(f"{_url(scan_id)}/refresh", headers=headers)
        assert refreshed.status_code == 200
        assert refreshed.get_json()["status"] == "pending"
        # El refresco recalcula aunque haya caché fresca.
        assert traced.call_count == 2


# ------------------------------------------------------------------ fallos (sin saltos)

def test_empty_result_is_cached_as_failed(client, app, regular_user, auth_headers, fake_queue):
    # Un traceroute sin saltos (host inalcanzable) se persiste como fallo terminal
    # y se sirve de caché durante el TTL corto: no se reintenta en cada apertura.
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=[]) as traced:
        client.get(_url(scan_id), headers=headers)  # encola; el job persiste fila vacía

        # Hay fila vacía persistida.
        from src.modules.infrastructure import unit_of_work as uow_mod
        from src.modules.features.themis.repositories import TracerouteRepository
        with app.app_context():
            with uow_mod.UnitOfWork() as uow:
                row = TracerouteRepository(uow).get_by_user_and_target(regular_user.id, _TARGET)
                assert row is not None
                assert row.hops == []

        second = client.get(_url(scan_id), headers=headers)
        body = second.get_json()
        assert body["status"] == "failed"
        assert body["hops"] == []
        assert body["cached"] is True
        # El fallo fresco se sirve de caché: no se reintenta.
        assert traced.call_count == 1


def test_stale_failed_entry_is_recomputed(client, app, regular_user, auth_headers, fake_queue):
    # Una fila fallida vieja (más allá del TTL corto) se recalcula al abrir.
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)
    _seed_trace(app, regular_user.id, hops=[], age=timedelta(hours=1))

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        client.get(_url(scan_id), headers=headers)  # stale → encola recálculo
        assert traced.call_count == 1

        done = client.get(_url(scan_id), headers=headers)
        assert done.get_json()["status"] == "done"
        assert done.get_json()["hops"] == _HOPS


def test_stale_done_cache_is_recomputed(client, app, regular_user, auth_headers, fake_queue):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)
    # Caché con saltos pero envejecida por encima del TTL (24 h por defecto).
    _seed_trace(app, regular_user.id, hops=_HOPS, age=timedelta(hours=48))

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        again = client.get(_url(scan_id), headers=headers)
        assert again.get_json()["status"] == "pending"
        assert traced.call_count == 1  # recalculó por antigüedad


# ------------------------------------------------------------------ aislamiento

def test_traceroute_isolation_between_users(client, app, make_user, auth_headers, fake_queue):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")
    scan_id = _create_scan(app, owner.id)

    with mock.patch(_TRACE_PATH, return_value=_HOPS):
        resp = client.get(_url(scan_id), headers=auth_headers(other))
        assert resp.status_code == 404
        assert fake_queue.submitted == []


def test_traceroute_cache_is_scoped_per_user(client, app, make_user, auth_headers, fake_queue):
    # Dos usuarios con el mismo target mantienen cachés independientes.
    user_a = make_user(role="role_user")
    user_b = make_user(role="role_user")
    scan_a = _create_scan(app, user_a.id)
    scan_b = _create_scan(app, user_b.id)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        assert client.get(_url(scan_a), headers=auth_headers(user_a)).status_code == 200
        assert client.get(_url(scan_b), headers=auth_headers(user_b)).status_code == 200
        # Cada usuario calcula la suya pese a compartir target.
        assert traced.call_count == 2
        assert len(fake_queue.submitted) == 2
