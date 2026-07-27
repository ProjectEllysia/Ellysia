"""
Tests de integración HTTP del inventario de software de Hygeia (§ contrato
de ingesta v1.0): campo opcional ``inventory`` a nivel de ``Payload``, sin
delta — cada escaneo reemplaza por completo al anterior.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia import managers as hygeia_managers
from src.modules.features.hygeia.managers import HygeiaAssetManager
from src.modules.features.hygeia.repositories import MonitoredAssetRepository

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    def submit(self, **kwargs):
        return None


@pytest.fixture(autouse=True)
def _fake_task_queue():
    with mock.patch.object(hygeia_managers.TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        yield


def _create_asset_with_key(app, user):
    with app.app_context():
        result = HygeiaAssetManager(user).create_asset(
            hostname="inventory-test", os_name="windows", labels={},
        )
        return result["asset"]["id"], result["agentKey"]


def _software(name="Visual Studio Code", **overrides):
    entry = {
        "name": name,
        "type": "EXE",
        "vendor": "Microsoft Corporation",
        "version": "1.90.0",
        "guid": "{D628A17A-9713-46BF-8D57-E0E08D1822C1}",
        "installedAt": "2024-01-15T00:00:00Z",
        "installPath": "C:\\Program Files\\Microsoft VS Code",
        "architecture": "x64",
        "sizeBytes": 314572800,
        "status": "installed",
        "source": "registry",
    }
    entry.update(overrides)
    return entry


def _heartbeat(**overrides):
    payload = {
        "agentVersion": "1.0.0",
        "collectedAt": utcnow_naive().isoformat() + "Z",
        "host": {"hostname": "inventory-test", "os": "windows", "kernel": "10.0.26200"},
        "metrics": {
            "cpu": {"usagePct": 12.0},
            "memory": {"usagePct": 30.0},
        },
    }
    payload.update(overrides)
    return payload


def _ingest(client, agent_key, **overrides):
    return client.post(
        "/hygeia/ingest", json=_heartbeat(**overrides),
        headers={"Authorization": f"Bearer {agent_key}"},
    )


def _rewind_last_seen(app, asset_id):
    """Empuja `last_seen_at` al pasado para poder mandar un segundo heartbeat
    en el mismo test sin chocar con el suelo de cadencia (`minIntervalSec`)."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = repo.get_by_id(asset_id)
            asset.last_seen_at = utcnow_naive() - timedelta(seconds=30)
            repo.update(asset)


def test_heartbeat_without_inventory_field_omits_it(client, app, regular_user):
    """Ausente en el payload: el activo no tiene inventario tras el primer heartbeat."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = _ingest(client, agent_key)
    assert resp.status_code == 200

    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAssetRepository(uow).get_by_id(asset_id)
            assert asset.inventory is None
            assert asset.inventory_collected_at is None


def test_heartbeat_with_inventory_persists_it(client, app, regular_user, auth_headers):
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    resp = _ingest(client, agent_key, inventory={"software": [_software(), _software("Git")]})
    assert resp.status_code == 200

    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["collectedAt"] is not None
    assert [s["name"] for s in data["software"]] == ["Visual Studio Code", "Git"]
    assert data["software"][0]["vendor"] == "Microsoft Corporation"


def test_next_scan_replaces_previous_inventory_without_merging(client, app, regular_user, auth_headers):
    """No hay delta: el segundo escaneo reemplaza al primero entero, no lo fusiona."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    _ingest(client, agent_key, inventory={"software": [_software("Old App")]})
    _rewind_last_seen(app, asset_id)
    _ingest(client, agent_key, inventory={"software": [_software("New App")]})

    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(regular_user))
    names = [s["name"] for s in resp.get_json()["software"]]
    assert names == ["New App"]


def test_heartbeat_without_inventory_after_a_scan_keeps_the_last_one(client, app, regular_user, auth_headers):
    """Un heartbeat sin `inventory` no borra el último escaneo conocido."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    _ingest(client, agent_key, inventory={"software": [_software()]})
    _rewind_last_seen(app, asset_id)
    _ingest(client, agent_key)  # heartbeat "normal", sin inventory

    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(regular_user))
    assert [s["name"] for s in resp.get_json()["software"]] == ["Visual Studio Code"]


def test_empty_software_list_is_a_valid_replacement(client, app, regular_user, auth_headers):
    """`[]` es un reemplazo válido (host sin software, o stub Linux/macOS), no se ignora."""
    asset_id, agent_key = _create_asset_with_key(app, regular_user)

    _ingest(client, agent_key, inventory={"software": [_software()]})
    _rewind_last_seen(app, asset_id)
    _ingest(client, agent_key, inventory={"software": []})

    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(regular_user))
    assert resp.get_json()["software"] == []


def test_asset_that_never_scanned_returns_empty_inventory(client, app, regular_user, auth_headers):
    asset_id, _ = _create_asset_with_key(app, regular_user)

    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["collectedAt"] is None
    assert data["software"] == []


def test_inventory_of_another_users_asset_is_404(client, app, make_user, auth_headers):
    asset_id, agent_key = _create_asset_with_key(app, make_user())
    _ingest(client, agent_key, inventory={"software": [_software()]})

    other = make_user()
    resp = client.get(f"/hygeia/assets/{asset_id}/inventory", headers=auth_headers(other))
    assert resp.status_code == 404
