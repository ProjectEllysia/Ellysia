"""#551: los escáneres de Themis crean el escaneo y su encolado en una sola transacción.

Antes, los cinco ``run_scan()`` hacían dos pasos separados:
``_create_scan_record()`` confirmaba la fila del escaneo y, ya fuera de esa
transacción, un ``TaskQueue.submit()`` publicaba el trabajo. Entre uno y otro
hay una ventana real —la API se reinicia, o Redis falla en ese instante— y lo
que quedaba era un escaneo creado que ningún worker iba a procesar nunca, con
la cuota del usuario ya cobrada. La reconciliación de arranque acababa
marcándolo FAILED, pero solo al reiniciar la API y sin devolver la cuota: el
usuario pagaba por un escaneo que nunca corrió.

Estos tests fijan el comportamiento nuevo: con Redis caído en el momento exacto
del encolado, el escaneo existe **y** existe su fila ``TaskDispatch``
pendiente, así que el trabajo se recupera después en vez de perderse.

``ScanManager._create_scan_and_dispatch`` es la ayuda compartida por los cinco
escáneres, así que se ejercita una vez por escáner en lugar de confiar en que
"como es el mismo método, basta probar uno": lo que cada escáner aporta por su
cuenta —qué argumentos mete en el job y con qué nombre— es justo lo que un
cambio despistado puede romper sin tocar la ayuda.
"""

from __future__ import annotations

import pytest

from src.modules.accounts.services.limits import LimitKey
from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.managers import AuthorizedTargetManager
from src.modules.features.themis.managers.lybra.engine import LybraEngineManager
from src.modules.features.themis.managers.nikto import NiktoScanManager
from src.modules.features.themis.managers.nmap import NmapScanManager
from src.modules.features.themis.managers.nuclei import NucleiScanManager
from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

pytestmark = pytest.mark.integration


class _RecordingQueue:
    """Doble de ITaskQueue que apunta lo que se le publica, sin Redis real."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


class _RejectingQueue:
    """Simula Redis caído justo en el instante del encolado."""

    def submit(self, **kwargs):
        raise ConnectionError("Redis no disponible")


def _only_pending_dispatch() -> dict:
    """Devuelve la única fila de outbox pendiente, fallando si no hay exactamente una.

    Los atributos se leen dentro del ``UnitOfWork`` y se devuelven como dict:
    fuera del bloque la instancia queda desligada de la sesión y tocar un
    atributo dispararía un lazy load contra una sesión ya cerrada.

    Returns:
        dict: Campos de la fila (``func_path``, ``name``, ``category``,
            ``args``, ``external_id``, ``timeout``) ya materializados.
    """
    with UnitOfWork() as uow:
        pending = TaskDispatchRepository(uow).get_pending()
        assert len(pending) == 1, f"se esperaba una fila pendiente, hay {len(pending)}"
        row = pending[0]
        return {
            "func_path": row.func_path,
            "name": row.name,
            "category": row.category,
            "args": list(row.args),
            "external_id": row.external_id,
            "timeout": row.timeout,
        }


class TestScanAndDispatchAreAtomic:
    """Con el encolado caído, el escaneo y su intención de publicar sobreviven juntos."""

    def test_nmap_leaves_a_recoverable_dispatch(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_THIRDPARTY_SCANS: 5})
        with app.app_context():
            manager = NmapScanManager()
            monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
            scan_id = manager.run_scan(
                target_host="8.8.8.8", target_ports="1-100", user_id=admin_user.id, timeout=300,
            )

            dispatch = _only_pending_dispatch()
            assert dispatch["name"] == f"NmapScan-{scan_id}"
            assert dispatch["category"] == manager.TASK_CATEGORY
            assert dispatch["args"] == [scan_id, "8.8.8.8", "1-100", 300]
            assert dispatch["external_id"] == manager.external_id_for(scan_id)
            # El margen lo suma la ayuda compartida, no cada escáner.
            assert dispatch["timeout"] == 300 + manager._scan_timeout_margin

    def test_nikto_leaves_a_recoverable_dispatch(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_THIRDPARTY_SCANS: 5})
        with app.app_context():
            manager = NiktoScanManager()
            monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
            scan_id = manager.run_scan(target_domain="8.8.8.8", user_id=admin_user.id, timeout=600)

            dispatch = _only_pending_dispatch()
            assert dispatch["name"] == f"NiktoScan-{scan_id}"
            assert dispatch["args"] == [scan_id, "8.8.8.8", 600]

    def test_nuclei_leaves_a_recoverable_dispatch(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_THIRDPARTY_SCANS: 5})
        with app.app_context():
            manager = NucleiScanManager()
            monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
            monkeypatch.setattr(
                "src.modules.features.themis.managers.authorized_target."
                "AuthorizedTargetManager.is_authorized",
                staticmethod(lambda user_id, target: True),
            )
            scan_id = manager.run_scan(
                target="8.8.8.8", user_id=admin_user.id,
                severities=["critical"], tags=["cve"], timeout=120,
            )

            dispatch = _only_pending_dispatch()
            assert dispatch["name"] == f"NucleiScan-{scan_id}"
            # severities y tags viajan como listas JSON, no como tuplas.
            assert dispatch["args"][:4] == [scan_id, "8.8.8.8", ["critical"], ["cve"]]

    def test_lybra_leaves_a_recoverable_dispatch(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_LYBRA_SCANS: 5})
        with app.app_context():
            # El modo autodescubrimiento sondea el objetivo, así que exige
            # tenerlo en el registro de objetivos autorizados (roadmap §6).
            AuthorizedTargetManager().add(admin_user.id, "8.8.8.8")
            manager = LybraEngineManager()
            monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
            scan_id = manager.run_scan(
                target="8.8.8.8", user_id=admin_user.id, discover_ports=[80, 443], timeout=60,
            )

            dispatch = _only_pending_dispatch()
            assert dispatch["name"] == f"LybraScan-{scan_id}"
            assert dispatch["args"] == [scan_id, [80, 443], None, 60, False]


class TestLybraServicesSurviveJsonb:
    """Los ``Service`` de Lybra cruzan la outbox como dicts y vuelven enteros.

    Es el único escáner cuyos argumentos no eran ya JSON-serializables: RQ los
    pickleaba, pero ``TaskDispatch.args`` es una columna JSONB. Si la ida y la
    vuelta no fuesen simétricas, el modo external-payload (la puerta de Hygeia)
    se rompería solo en producción, que es donde sí pasa por la cola.
    """

    def test_external_payload_travels_as_plain_dicts(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_LYBRA_SCANS: 5})
        services = [Service(port=80, protocol="tcp", name="http", product="nginx", version="1.18.0")]

        with app.app_context():
            manager = LybraEngineManager()
            monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
            scan_id = manager.run_scan(target="8.8.8.8", user_id=admin_user.id, services=services)

            dispatch = _only_pending_dispatch()
            assert dispatch["args"][0] == scan_id
            assert dispatch["args"][2] == [{
                "port": 80, "protocol": "tcp", "name": "http",
                "product": "nginx", "version": "1.18.0", "cpe": None, "origin": "network",
            }]

    def test_rehydrate_restores_the_dataclass(self):
        """La vuelta: lo que el worker recibe como dict vuelve a ser ``Service``."""
        original = Service(port=443, protocol="tcp", name="https", cpe="cpe:/a:nginx:nginx:1.18.0")
        payload = [{
            "port": 443, "protocol": "tcp", "name": "https", "product": "",
            "version": "", "cpe": "cpe:/a:nginx:nginx:1.18.0", "origin": "network",
        }]

        assert LybraEngineManager._rehydrate_services(payload) == [original]

    def test_rehydrate_passes_through_dataclasses_and_none(self):
        """Compatibilidad: un job pickleado por RQ antes de la outbox trae ``Service``
        ya construidos, y el modo autodescubrimiento no trae ninguno."""
        original = Service(port=22, protocol="tcp", name="ssh")

        assert LybraEngineManager._rehydrate_services([original]) == [original]
        assert LybraEngineManager._rehydrate_services(None) is None


class TestHappyPathStillPublishesImmediately:
    """Con Redis arriba no se añade latencia: el job sale en la misma llamada."""

    def test_nmap_publishes_and_marks_the_dispatch_done(self, app, admin_user, set_plan_limits, monkeypatch):
        set_plan_limits({LimitKey.THEMIS_THIRDPARTY_SCANS: 5})
        with app.app_context():
            queue = _RecordingQueue()
            manager = NmapScanManager()
            monkeypatch.setattr(manager, "_task_queue", queue)
            scan_id = manager.run_scan(
                target_host="8.8.8.8", target_ports="1-100", user_id=admin_user.id,
            )

            assert len(queue.submitted) == 1
            assert queue.submitted[0]["name"] == f"NmapScan-{scan_id}"
            # Nada queda pendiente: la fila se marcó `dispatched` al publicar.
            with UnitOfWork() as uow:
                assert TaskDispatchRepository(uow).get_pending() == []


def test_a_failed_publish_is_recovered_by_a_later_sweep(app, admin_user, set_plan_limits, monkeypatch):
    """El criterio de cierre, de punta a punta para Themis: el escaneo creado con
    Redis caído acaba encolado cuando el barrido (o la reconciliación de
    arranque) vuelve a intentarlo, y repetir el barrido no lo duplica."""
    set_plan_limits({LimitKey.THEMIS_THIRDPARTY_SCANS: 5})

    with app.app_context():
        manager = NmapScanManager()
        monkeypatch.setattr(manager, "_task_queue", _RejectingQueue())
        scan_id = manager.run_scan(
            target_host="8.8.8.8", target_ports="1-100", user_id=admin_user.id,
        )

        recovery_queue = _RecordingQueue()
        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        monkeypatch.setattr(
            dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: recovery_queue),
        )

        assert OutboxDispatcher.dispatch_pending() == 1
        assert len(recovery_queue.submitted) == 1
        assert recovery_queue.submitted[0]["name"] == f"NmapScan-{scan_id}"

        # Un segundo barrido no republica: la fila ya quedó `dispatched`.
        assert OutboxDispatcher.dispatch_pending() == 0
        assert len(recovery_queue.submitted) == 1
