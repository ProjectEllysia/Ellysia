"""
Tests de integración HTTP de la ingesta de heartbeats de Hygeia.

Cierran el ciclo completo agente → API → base de datos: que el payload se
guarda íntegro, que los escalares aterrizan ya desnormalizados en columnas
propias, y que kernel/uptime del bloque ``host`` dejan de descartarse.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia import managers as hygeia_managers
from src.modules.features.hygeia.managers import HygeiaAssetManager
from src.modules.features.hygeia.model import MonitoredAsset
from src.modules.features.hygeia.repositories import (
    AnomalyRepository,
    AssetSnapshotRepository,
    MonitoredAssetRepository,
)
from src.modules.system.taskqueue import TaskQueue
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    """Doble sin Redis: una anomalía crítica encolaría una notificación real."""

    def submit(self, **kwargs):
        return None


@pytest.fixture(autouse=True)
def _fake_task_queue():
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        yield


def _create_asset_with_key(app, user):
    """Da de alta un activo por el manager, que devuelve la clave en claro una vez.

    El manager solo lee ``user.id``, así que el handle de la fixture sirve tal
    cual: no hace falta materializar el modelo User.
    """
    with app.app_context():
        result = HygeiaAssetManager(user).create_asset(
            hostname="ingest-test", os_name="linux", labels={},
        )
        return result["asset"]["id"], result["agentKey"]


def _heartbeat(**overrides):
    payload = {
        "agentVersion": "0.4.1",
        "collectedAt": utcnow_naive().isoformat() + "Z",
        "host": {
            "hostname": "ingest-test",
            "os": "linux",
            "kernel": "6.1.0-18-amd64",
            "uptimeSec": 123456,
        },
        "metrics": {
            "cpu": {
                "usagePct": 47.5,
                "loadAvg": [2.1, 1.8, 1.5],
                "perCorePct": [48.0, 47.0],
            },
            "memory": {
                "totalBytes": 16_000_000_000,
                "usedBytes": 9_000_000_000,
                "usagePct": 56.25,
                "swapUsedPct": 12.5,
            },
            "disk": [
                {"mount": "/", "usagePct": 41.0, "freeBytes": 60_000_000_000},
                {"mount": "/data", "usagePct": 72.0, "freeBytes": 9_000_000_000},
            ],
            "network": [
                {"iface": "lo", "rxBytesPerSec": 999_999, "txBytesPerSec": 999_999},
                {"iface": "eth0", "rxBytesPerSec": 120_000, "txBytesPerSec": 45_000},
            ],
            "processes": {
                "total": 210, "zombie": 1,
                "topCpu": [{"pid": 8123, "name": "nginx", "cpuPct": 12.5}],
                "topMem": [{"pid": 991, "name": "postgres", "memPct": 31.0}],
            },
        },
        "localAlerts": [],
    }
    payload.update(overrides)
    return payload


def _latest_snapshot(app, asset_id: int) -> dict:
    """Últimas columnas del snapshot, ya materializadas.

    Se devuelve un dict y no la entidad: fuera del UnitOfWork la instancia
    quedaría desligada de su sesión y cualquier acceso a un atributo fallaría.
    """
    with app.app_context():
        with UnitOfWork() as uow:
            s = AssetSnapshotRepository(uow).get_latest(asset_id)
            return {
                "cpu_pct": s.cpu_pct, "mem_pct": s.mem_pct, "swap_pct": s.swap_pct,
                "load1": s.load1, "disk_max_pct": s.disk_max_pct,
                "disk_max_mount": s.disk_max_mount,
                "net_rx_bps": s.net_rx_bps, "net_tx_bps": s.net_tx_bps,
                "power_watts": s.power_watts, "power_estimated": s.power_estimated,
                "power_source": s.power_source,
                "metrics": s.metrics,
            }


def test_heartbeat_lands_denormalized_scalars(client, app, regular_user):
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest",
        json=_heartbeat(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    snapshot = _latest_snapshot(app, asset_id)
    assert snapshot["cpu_pct"] == 47.5
    assert snapshot["mem_pct"] == 56.25
    assert snapshot["swap_pct"] == 12.5
    assert snapshot["load1"] == 2.1
    assert snapshot["disk_max_pct"] == 72.0
    assert snapshot["disk_max_mount"] == "/data"
    # Solo eth0: la loopback no cuenta.
    assert snapshot["net_rx_bps"] == 120_000
    assert snapshot["net_tx_bps"] == 45_000


# ------------------------------------------ outbox del aviso de anomalía crítica

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


def _make_data_disk_critical(app, asset_id: int) -> None:
    """Da al activo umbrales propios con los que ``/data`` (al 72 % en
    ``_heartbeat()``) abre una anomalía crítica al primer heartbeat, sin
    depender de los umbrales globales de la config."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = repo.get_by_id(asset_id)
            asset.thresholds = {"diskPct": {"warning": 60, "critical": 70}}
            repo.update(asset)


def _active_anomaly_ids(app, asset_id: int) -> list[int]:
    with app.app_context():
        with UnitOfWork() as uow:
            return [anomaly.id for anomaly in AnomalyRepository(uow).get_all_active(asset_id)]


def _pending_dispatch_names(app) -> list[str]:
    with app.app_context():
        with UnitOfWork() as uow:
            return [row.name for row in TaskDispatchRepository(uow).get_pending()]


def test_critical_anomaly_notice_is_published_with_the_heartbeat(
    client, app, regular_user, monkeypatch,
):
    """Camino feliz: el aviso sale en la misma request y nada queda pendiente."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)
    _make_data_disk_critical(app, asset_id)
    queue = _RecordingQueue()
    monkeypatch.setattr(TaskQueue, "get_instance", staticmethod(lambda: queue))

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat(), headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    anomaly_ids = _active_anomaly_ids(app, asset_id)
    assert len(anomaly_ids) == 1
    assert [job["name"] for job in queue.submitted] == [f"HygeiaNotify-{anomaly_ids[0]}"]
    assert _pending_dispatch_names(app) == []


def test_critical_anomaly_notice_survives_redis_down_at_enqueue(
    client, app, regular_user, monkeypatch,
):
    """La anomalía abierta ya no puede suprimir su propio aviso.

    La anomalía abierta es lo que impide que el siguiente heartbeat la vuelva
    a abrir. Antes se confirmaba y el encolado venía después; si Redis fallaba
    ahí, la anomalía quedaba registrada y el correo no salía nunca. Ahora las
    dos cosas van en el mismo commit y el barrido publica el aviso después.
    """
    monkeypatch.setattr(
        hygeia_managers.CR, "hygeia_limits",
        lambda: hygeia_managers.CR.HygeiaLimits(min_interval_sec=0),
    )
    asset_id, agent_key = _create_asset_with_key(app, regular_user)
    _make_data_disk_critical(app, asset_id)
    monkeypatch.setattr(TaskQueue, "get_instance", staticmethod(_RejectingQueue))
    headers = {"Authorization": f"Bearer {agent_key}"}

    assert client.post("/hygeia/ingest", json=_heartbeat(), headers=headers).status_code == 200
    # El disco sigue lleno: el siguiente heartbeat ve la anomalía abierta y
    # no añade una segunda intención de avisar.
    assert client.post("/hygeia/ingest", json=_heartbeat(), headers=headers).status_code == 200

    anomaly_ids = _active_anomaly_ids(app, asset_id)
    assert len(anomaly_ids) == 1
    assert _pending_dispatch_names(app) == [f"HygeiaNotify-{anomaly_ids[0]}"]

    recovery_queue = _RecordingQueue()
    monkeypatch.setattr(TaskQueue, "get_instance", staticmethod(lambda: recovery_queue))
    with app.app_context():
        assert OutboxDispatcher.dispatch_pending() == 1

    assert [job["name"] for job in recovery_queue.submitted] == [f"HygeiaNotify-{anomaly_ids[0]}"]


def test_heartbeat_keeps_the_whole_payload(client, app, regular_user):
    """Los escalares son una proyección, no un reemplazo: el JSONB sigue íntegro."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    client.post(
        "/hygeia/ingest", json=_heartbeat(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    metrics = _latest_snapshot(app, asset_id)["metrics"]
    assert [d["mount"] for d in metrics["disk"]] == ["/", "/data"]
    assert [n["iface"] for n in metrics["network"]] == ["lo", "eth0"]
    assert metrics["cpu"]["perCorePct"] == [48.0, 47.0]
    assert metrics["processes"]["topCpu"][0]["name"] == "nginx"


def test_heartbeat_records_kernel_and_uptime(client, app, regular_user):
    """Ambos se validaban y se descartaban antes de llegar a la base de datos."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    client.post(
        "/hygeia/ingest", json=_heartbeat(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            assert asset.kernel == "6.1.0-18-amd64"
            assert asset.uptime_sec == 123456
            assert asset.status == "online"


def test_windows_heartbeat_without_loadavg_or_network(client, app, regular_user):
    """Un agente que no reporta algo deja NULL, no un cero inventado."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    payload = _heartbeat()
    payload["host"]["kernel"] = None
    payload["metrics"]["cpu"]["loadAvg"] = []
    payload["metrics"]["memory"].pop("swapUsedPct")
    payload["metrics"]["network"] = []

    resp = client.post(
        "/hygeia/ingest", json=payload,
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    snapshot = _latest_snapshot(app, asset_id)
    assert snapshot["load1"] is None
    assert snapshot["swap_pct"] is None
    assert snapshot["net_rx_bps"] is None
    assert snapshot["net_tx_bps"] is None
    assert snapshot["cpu_pct"] == 47.5


def test_ingest_without_agent_key_is_401(client, app, regular_user):
    _create_asset_with_key(app, regular_user)
    assert client.post("/hygeia/ingest", json=_heartbeat()).status_code == 401


def test_ingest_with_wrong_agent_key_is_401(client, app, regular_user):
    _, agent_key = _create_asset_with_key(app, regular_user)
    key_id = agent_key.split(".", 1)[0]

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat(),
        headers={"Authorization": f"Bearer {key_id}.secreto-equivocado"},
    )

    assert resp.status_code == 401


def test_ingest_rejects_skewed_clock(client, app, regular_user):
    """`collectedAt` fuera de la ventana de cordura no entra."""
    _, agent_key = _create_asset_with_key(app, regular_user)
    far_future = (utcnow_naive() + timedelta(hours=2)).isoformat() + "Z"

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat(collectedAt=far_future),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 400


# =============================================================================
# POTENCIA — validación y persistencia de la lectura de consumo
# =============================================================================

def _heartbeat_with_power(**power_overrides):
    power = {"watts": 187.5, "estimated": False, "source": "rapl"}
    power.update(power_overrides)
    payload = _heartbeat()
    payload["metrics"]["power"] = power
    return payload


def test_heartbeat_with_power_is_accepted_and_persisted(client, app, regular_user):
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat_with_power(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    snapshot = _latest_snapshot(app, asset_id)
    assert snapshot["power_watts"] == 187.5
    assert snapshot["power_estimated"] is False
    assert snapshot["power_source"] == "rapl"


def test_heartbeat_without_power_is_accepted_for_backward_compatibility(client, app, regular_user):
    """Un agente que aún no manda potencia (o hardware sin sensores) no debe romper nada."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    snapshot = _latest_snapshot(app, asset_id)
    assert snapshot["power_watts"] is None
    assert snapshot["power_estimated"] is None
    assert snapshot["power_source"] is None


def test_heartbeat_with_zero_watts_persists_zero_not_null(client, app, regular_user):
    """Lo que sostiene el cálculo de consumo: 0 W medidos no es ausencia de dato."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat_with_power(watts=0.0),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    snapshot = _latest_snapshot(app, asset_id)
    assert snapshot["power_watts"] == 0.0
    assert snapshot["power_watts"] is not None


def test_heartbeat_with_negative_watts_is_rejected(client, app, regular_user):
    """Atrapa un contador de RAPL desbordado antes de persistir un dato imposible."""
    _, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat_with_power(watts=-5.0),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 422


def test_heartbeat_with_empty_source_is_rejected(client, app, regular_user):
    _, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat_with_power(source=""),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 422


def test_heartbeat_with_power_missing_estimated_is_rejected(client, app, regular_user):
    """Los tres campos son obligatorios dentro del bloque, aunque el bloque entero sea opcional."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)
    payload = _heartbeat()
    payload["metrics"]["power"] = {"watts": 100.0, "source": "rapl"}

    resp = client.post(
        "/hygeia/ingest", json=payload,
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 422


# =============================================================================
# VIRTUALIZACIÓN DEL HOST — distingue "sin sensores" de "es un invitado"
# =============================================================================

def test_heartbeat_records_virtualization_fields(client, app, regular_user):
    asset_id, agent_key = _create_asset_with_key(app, regular_user)
    payload = _heartbeat()
    payload["host"]["virtualizationSystem"] = "kvm"
    payload["host"]["virtualizationRole"] = "guest"

    resp = client.post(
        "/hygeia/ingest", json=payload,
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            assert asset.virtualization_system == "kvm"
            assert asset.virtualization_role == "guest"


def test_heartbeat_without_virtualization_fields_leaves_columns_null(client, app, regular_user):
    """Un agente anterior a esta necesidad no debe romper, y no es lo mismo que 'no es una VM'."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = client.post(
        "/hygeia/ingest", json=_heartbeat(),
        headers={"Authorization": f"Bearer {agent_key}"},
    )

    assert resp.status_code == 200
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            assert asset.virtualization_system is None
            assert asset.virtualization_role is None


def test_virtualization_fields_are_conserved_like_kernel(client, app, regular_user, monkeypatch):
    """Son identidad del host: un heartbeat que no los traiga no debe borrar lo ya sabido."""
    # Dos heartbeats seguidos del mismo activo: se levanta el suelo de
    # cadencia (`_enforce_min_interval`), que si no rechazaría el segundo
    # por llegar antes de los 5 s por defecto.
    monkeypatch.setattr(hygeia_managers.CR, "hygeia_limits", lambda: hygeia_managers.CR.HygeiaLimits(min_interval_sec=0))
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    first = _heartbeat()
    first["host"]["virtualizationSystem"] = "vmware"
    first["host"]["virtualizationRole"] = "guest"
    client.post(
        "/hygeia/ingest", json=first, headers={"Authorization": f"Bearer {agent_key}"},
    )

    client.post(
        "/hygeia/ingest", json=_heartbeat(), headers={"Authorization": f"Bearer {agent_key}"},
    )

    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            assert asset.virtualization_system == "vmware"
            assert asset.virtualization_role == "guest"
