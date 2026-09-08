"""
Tests de integración HTTP del aviso de agente desactualizado en
``GET /hygeia/assets`` (``agentOutdated``).

Siembra activos directamente por repositorio (no por ``POST /hygeia/ingest``):
lo único que importa aquí es el valor guardado de ``agent_version``, no el
recorrido completo de un heartbeat.
"""

import secrets

import pytest

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia.model import MonitoredAsset
from src.modules.features.hygeia.repositories import MonitoredAssetRepository

pytestmark = pytest.mark.integration


def _create_asset(app, user_id: int, agent_version, hostname="freshness-test") -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname=hostname,
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=15,
                status="online",
                last_seen_at=utcnow_naive(),
                agent_version=agent_version,
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _list_assets(client, user, auth_headers) -> dict:
    body = client.get("/hygeia/assets", headers=auth_headers(user)).get_json()
    return {asset["id"]: asset for asset in body["assets"]}


def test_asset_below_the_configured_floor_is_flagged(
    client, app, regular_user, auth_headers, monkeypatch,
):
    monkeypatch.setattr(CR, "hygeia_config", lambda: CR.HygeiaConfig(min_agent_version="0.5.0"))
    asset_id = _create_asset(app, regular_user.id, agent_version="0.4.1")

    assets = _list_assets(client, regular_user, auth_headers)

    assert assets[asset_id]["agentOutdated"] is True


def test_asset_at_or_above_the_floor_is_not_flagged(
    client, app, regular_user, auth_headers, monkeypatch,
):
    monkeypatch.setattr(CR, "hygeia_config", lambda: CR.HygeiaConfig(min_agent_version="0.5.0"))
    asset_id = _create_asset(app, regular_user.id, agent_version="0.5.0")

    assets = _list_assets(client, regular_user, auth_headers)

    assert assets[asset_id]["agentOutdated"] is False


def test_the_default_floor_flags_nothing(client, app, regular_user, auth_headers):
    """Sin configurar nada, el suelo por defecto (0.0.0) no marca ningún agente real."""
    asset_id = _create_asset(app, regular_user.id, agent_version="0.1.0")

    assets = _list_assets(client, regular_user, auth_headers)

    assert assets[asset_id]["agentOutdated"] is False


def test_asset_that_never_reported_a_version_is_unknown(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id, agent_version=None)

    assets = _list_assets(client, regular_user, auth_headers)

    assert assets[asset_id]["agentOutdated"] is None


def test_malformed_agent_version_is_unknown_not_outdated(
    client, app, regular_user, auth_headers, monkeypatch,
):
    """El caso central del issue: un dato que no encaja en el formato no se lee como desactualizado."""
    monkeypatch.setattr(CR, "hygeia_config", lambda: CR.HygeiaConfig(min_agent_version="0.5.0"))
    asset_id = _create_asset(app, regular_user.id, agent_version="dev-build")

    assets = _list_assets(client, regular_user, auth_headers)

    assert assets[asset_id]["agentOutdated"] is None


def test_config_change_applies_without_restarting(
    client, app, regular_user, auth_headers, monkeypatch,
):
    """El suelo se lee en cada listado (`CR.hygeia_config()`), no se hornea al importar el módulo."""
    asset_id = _create_asset(app, regular_user.id, agent_version="0.4.1")

    monkeypatch.setattr(CR, "hygeia_config", lambda: CR.HygeiaConfig(min_agent_version="0.0.0"))
    assert _list_assets(client, regular_user, auth_headers)[asset_id]["agentOutdated"] is False

    monkeypatch.setattr(CR, "hygeia_config", lambda: CR.HygeiaConfig(min_agent_version="1.0.0"))
    assert _list_assets(client, regular_user, auth_headers)[asset_id]["agentOutdated"] is True
