"""
Tests de integración del detector de presencia y la poda de snapshots de Hygeia.

Sigue el patrón de ``test_scheduling.py`` (Themis): invoca el entry point del
manager directamente dentro de ``app.app_context()``, sin pasar por
APScheduler ni por HTTP — aquí solo importa el ciclo de vida de la
presencia, no el temporizador real.
"""

import secrets
from datetime import timedelta

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia.managers import HygeiaMaintenanceManager
from src.modules.features.hygeia.model import Anomaly, AssetSnapshot, MonitoredAsset
from src.modules.features.hygeia.repositories import (
    AnomalyRepository,
    AssetSnapshotRepository,
    MonitoredAssetRepository,
)

pytestmark = pytest.mark.integration

_INTERVAL = 15
_OFFLINE_AFTER_MISSED = 4


def _create_asset(app, user_id: int, status: str, last_seen_at, interval: int = _INTERVAL) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname="presence-test",
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=interval,
                status=status,
                last_seen_at=last_seen_at,
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _fetch_asset(app, asset_id: int) -> MonitoredAsset:
    with app.app_context():
        with UnitOfWork() as uow:
            return MonitoredAssetRepository(uow).get_by_id(asset_id)


def _open_anomalies(app, asset_id: int, kind: str = "host_down"):
    with app.app_context():
        with UnitOfWork() as uow:
            return [
                a for a in AnomalyRepository(uow).get_all_active(asset_id) if a.kind == kind
            ]


def test_online_asset_transitions_to_stale_after_missing_one_heartbeat(app, regular_user):
    last_seen = utcnow_naive() - timedelta(seconds=_INTERVAL + 5)
    asset_id = _create_asset(app, regular_user.id, "online", last_seen)

    with app.app_context():
        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "stale"
    assert _open_anomalies(app, asset_id) == []


def test_online_asset_within_interval_is_untouched(app, regular_user):
    last_seen = utcnow_naive() - timedelta(seconds=5)  # bien dentro del intervalo de 15s
    asset_id = _create_asset(app, regular_user.id, "online", last_seen)

    with app.app_context():
        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "online"


def test_stale_asset_not_yet_past_offline_cutoff_stays_stale(app, regular_user):
    # Entre el corte de stale (15s) y el de offline (4 * 15s = 60s).
    last_seen = utcnow_naive() - timedelta(seconds=30)
    asset_id = _create_asset(app, regular_user.id, "stale", last_seen)

    with app.app_context():
        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "stale"
    assert _open_anomalies(app, asset_id) == []


def test_stale_asset_past_offline_cutoff_transitions_and_opens_host_down(app, regular_user):
    last_seen = utcnow_naive() - timedelta(seconds=_INTERVAL * _OFFLINE_AFTER_MISSED + 5)
    asset_id = _create_asset(app, regular_user.id, "stale", last_seen)

    with app.app_context():
        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "offline"
    anomalies = _open_anomalies(app, asset_id)
    assert len(anomalies) == 1
    assert anomalies[0].severity == "critical"
    assert anomalies[0].state == "open"


def test_offline_asset_is_excluded_from_presence_check(app, regular_user):
    """Un activo ya offline no debe volver a tocarse en pasadas sucesivas."""
    last_seen = utcnow_naive() - timedelta(days=1)
    asset_id = _create_asset(app, regular_user.id, "offline", last_seen)

    with app.app_context():
        with UnitOfWork() as uow:
            candidates = [a.id for a in MonitoredAssetRepository(uow).get_active_for_presence_check()]
        assert asset_id not in candidates

        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "offline"


def test_presence_check_does_not_duplicate_an_already_open_host_down(app, regular_user):
    """Apertura idempotente: si ya hay un host_down abierto, no se crea otro."""
    last_seen = utcnow_naive() - timedelta(seconds=_INTERVAL * _OFFLINE_AFTER_MISSED + 5)
    asset_id = _create_asset(app, regular_user.id, "stale", last_seen)

    with app.app_context():
        with UnitOfWork() as uow:
            AnomalyRepository(uow).save(Anomaly(
                asset_id=asset_id, kind="host_down", severity="critical", state="open",
            ))

        HygeiaMaintenanceManager.execute_presence_check()

    anomalies = _open_anomalies(app, asset_id)
    assert len(anomalies) == 1, "no debe duplicarse una anomalía host_down ya abierta"


def test_asset_own_heartbeat_interval_is_used_over_global_default(app, regular_user):
    """Un activo con un intervalo propio mucho mayor no debe declararse stale
    solo por compararlo contra el intervalo global (15s)."""
    last_seen = utcnow_naive() - timedelta(seconds=30)  # stale si se comparase contra 15s
    asset_id = _create_asset(app, regular_user.id, "online", last_seen, interval=120)

    with app.app_context():
        HygeiaMaintenanceManager.execute_presence_check()

    assert _fetch_asset(app, asset_id).status == "online"


def test_retention_deletes_only_snapshots_older_than_cutoff(app, regular_user):
    asset_id = _create_asset(app, regular_user.id, "online", utcnow_naive())

    with app.app_context():
        with UnitOfWork() as uow:
            repo = AssetSnapshotRepository(uow)
            old_snap = AssetSnapshot(
                asset_id=asset_id,
                collected_at=utcnow_naive() - timedelta(days=60),
                received_at=utcnow_naive() - timedelta(days=60),
                metrics={},
            )
            recent_snap = AssetSnapshot(
                asset_id=asset_id,
                collected_at=utcnow_naive() - timedelta(days=1),
                received_at=utcnow_naive() - timedelta(days=1),
                metrics={},
            )
            repo.save(old_snap)
            repo.save(recent_snap)

        deleted = HygeiaMaintenanceManager.execute_retention()

        with UnitOfWork() as uow:
            remaining = AssetSnapshotRepository(uow).get_series(asset_id)

    assert deleted == 1
    assert len(remaining) == 1
    assert remaining[0].collected_at > utcnow_naive() - timedelta(days=2)
