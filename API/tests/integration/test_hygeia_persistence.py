"""
Tests de integración HTTP de la persistencia de un activo de Hygeia.

``isPersistent`` marca si se espera que el host esté siempre encendido. Aquí
se cubre el ciclo por HTTP (alta, lectura y ``PATCH``) y el efecto lateral de
desmarcarlo: un ``host_down`` abierto se resuelve, porque silenciar un host
mientras su aviso sigue sonando no silenciaría nada.

El efecto sobre el detector de presencia (no abrir anomalía ni encolar
correo) vive en ``test_hygeia_scheduling.py``, junto al resto del ciclo de
vida de la presencia.
"""

import secrets

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia.model import Anomaly, MonitoredAsset
from src.modules.features.hygeia.repositories import (
    AnomalyRepository,
    MonitoredAssetRepository,
)

pytestmark = pytest.mark.integration


def _create_asset(app, user_id: int, is_persistent: bool = True) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname="persistence-test",
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=15,
                status="offline",
                last_seen_at=utcnow_naive(),
                is_persistent=is_persistent,
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _open_host_down(app, asset_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            anomaly = Anomaly(
                asset_id=asset_id, kind="host_down", severity="critical", state="open",
            )
            AnomalyRepository(uow).save(anomaly)
            return anomaly.id


def _anomaly_state(app, anomaly_id: int) -> str:
    with app.app_context():
        with UnitOfWork() as uow:
            return AnomalyRepository(uow).get_by_id(anomaly_id).state


def test_new_asset_is_persistent_by_default(client, regular_user, auth_headers):
    resp = client.post(
        "/hygeia/assets",
        json={"hostname": "default-test"},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 201
    assert resp.get_json()["asset"]["isPersistent"] is True


def test_asset_can_be_created_as_non_persistent(client, regular_user, auth_headers):
    resp = client.post(
        "/hygeia/assets",
        json={"hostname": "portatil", "isPersistent": False},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 201
    assert resp.get_json()["asset"]["isPersistent"] is False


def test_patch_marks_asset_as_non_persistent(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)

    resp = client.patch(
        f"/hygeia/assets/{asset_id}",
        json={"isPersistent": False},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 200
    assert resp.get_json()["isPersistent"] is False

    detail = client.get(f"/hygeia/assets/{asset_id}", headers=auth_headers(regular_user))
    assert detail.get_json()["isPersistent"] is False


def test_marking_non_persistent_resolves_an_open_host_down(
    client, app, regular_user, auth_headers,
):
    asset_id = _create_asset(app, regular_user.id)
    anomaly_id = _open_host_down(app, asset_id)

    resp = client.patch(
        f"/hygeia/assets/{asset_id}",
        json={"isPersistent": False},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 200
    assert _anomaly_state(app, anomaly_id) == "resolved"


def test_marking_persistent_again_leaves_anomalies_untouched(
    client, app, regular_user, auth_headers,
):
    """Volver a marcarlo como persistente no resuelve nada: solo reactiva el aviso."""
    asset_id = _create_asset(app, regular_user.id, is_persistent=False)
    anomaly_id = _open_host_down(app, asset_id)

    resp = client.patch(
        f"/hygeia/assets/{asset_id}",
        json={"isPersistent": True},
        headers=auth_headers(regular_user),
    )

    assert resp.status_code == 200
    assert resp.get_json()["isPersistent"] is True
    assert _anomaly_state(app, anomaly_id) == "open"


def test_patch_on_another_users_asset_returns_404(
    client, app, regular_user, make_user, auth_headers,
):
    intruder = make_user()
    asset_id = _create_asset(app, regular_user.id)

    resp = client.patch(
        f"/hygeia/assets/{asset_id}",
        json={"isPersistent": False},
        headers=auth_headers(intruder),
    )

    assert resp.status_code == 404


def test_patch_requires_the_field(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)

    resp = client.patch(
        f"/hygeia/assets/{asset_id}", json={}, headers=auth_headers(regular_user),
    )

    assert resp.status_code == 422
