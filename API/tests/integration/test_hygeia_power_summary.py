"""
Tests de integración HTTP del resumen de consumo eléctrico de un activo
(``GET /hygeia/assets/<id>/power-summary``).

Siembra snapshots directamente por repositorio (igual que
``test_hygeia_metrics_api.py``): el suelo de cadencia de la ingesta impide
construir por HTTP una serie lo bastante densa para ejercitar la media
ponderada.
"""

import secrets
from datetime import timedelta

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia.model import AssetSnapshot, MonitoredAsset
from src.modules.features.hygeia.repositories import MonitoredAssetRepository

pytestmark = pytest.mark.integration


def _create_asset(app, user_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname="power-test",
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=15,
                status="online",
                last_seen_at=utcnow_naive(),
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _save_snapshot(app, asset_id: int, received_at, watts, estimated=False, source="rapl"):
    with app.app_context():
        with UnitOfWork() as uow:
            from src.modules.features.hygeia.repositories import AssetSnapshotRepository
            AssetSnapshotRepository(uow).save(AssetSnapshot(
                asset_id=asset_id, collected_at=received_at, received_at=received_at,
                metrics={"cpu": {"usagePct": 1.0}, "memory": {"usagePct": 1.0}},
                power_watts=watts, power_estimated=estimated, power_source=source,
            ))


def test_current_reflects_the_latest_snapshot(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    now = utcnow_naive()
    _save_snapshot(app, asset_id, now - timedelta(minutes=1), 100.0)
    _save_snapshot(app, asset_id, now, 200.0, estimated=True, source="windows-model")

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    assert body["current"]["watts"] == 200.0
    assert body["current"]["estimated"] is True
    assert body["current"]["source"] == "windows-model"


def test_asset_without_any_snapshot_has_no_current_reading(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    assert body["current"] == {"watts": None, "estimated": None, "source": None}
    assert body["day"]["kwh"] is None
    assert body["day"]["cost"] is None


def test_day_window_computes_energy_from_dense_samples(client, app, regular_user, auth_headers):
    """Dos muestras de 200 W separadas una hora: 200 Wh observados = 0.2 kWh."""
    asset_id = _create_asset(app, regular_user.id)
    now = utcnow_naive()
    _save_snapshot(app, asset_id, now - timedelta(hours=1), 200.0)
    _save_snapshot(app, asset_id, now, 200.0)

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    assert body["day"]["averageWatts"] == pytest.approx(200.0)
    assert body["day"]["kwh"] == pytest.approx(0.2)
    assert body["day"]["classification"] in ("observed", "observed_partial")


def test_a_long_silent_gap_does_not_get_averaged_as_zero(client, app, regular_user, auth_headers):
    """Un activo con un único heartbeat aislado no produce una media de 0 W."""
    asset_id = _create_asset(app, regular_user.id)
    _save_snapshot(app, asset_id, utcnow_naive(), 150.0)

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    # Una única muestra en la ventana no tiene ni un intervalo que promediar.
    assert body["day"]["averageWatts"] is None
    assert body["day"]["kwh"] is None


def test_month_projected_is_always_projected(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    now = utcnow_naive()
    _save_snapshot(app, asset_id, now - timedelta(hours=1), 100.0)
    _save_snapshot(app, asset_id, now, 100.0)

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    assert body["monthProjected"]["classification"] == "projected"


def test_response_carries_the_configured_currency(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)

    body = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(regular_user)
    ).get_json()

    assert body["day"]["currency"] == "EUR"


def test_power_summary_of_another_users_asset_is_404(client, app, make_user, auth_headers):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")
    asset_id = _create_asset(app, owner.id)

    resp = client.get(
        f"/hygeia/assets/{asset_id}/power-summary", headers=auth_headers(other)
    )

    assert resp.status_code == 404


def test_power_summary_without_token_is_401(client, app, regular_user):
    asset_id = _create_asset(app, regular_user.id)
    assert client.get(f"/hygeia/assets/{asset_id}/power-summary").status_code == 401
