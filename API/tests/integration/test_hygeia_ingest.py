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
    AssetSnapshotRepository,
    MonitoredAssetRepository,
)

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    """Doble sin Redis: una anomalía crítica encolaría una notificación real."""

    def submit(self, **kwargs):
        return None


@pytest.fixture(autouse=True)
def _fake_task_queue():
    with mock.patch.object(hygeia_managers.TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
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
