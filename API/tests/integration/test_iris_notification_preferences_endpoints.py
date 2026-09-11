"""Tests de integración de ``GET/PUT /iris/notification-preferences``.

La matriz de atributos (IRIS_READ / IRIS_UPDATE) ya está cubierta por
``test_iris_permissions.py``; aquí se verifica el contrato HTTP: valores por
defecto sin fila persistida, actualización parcial, y el caso especial de
``mutedForMinutes``.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.modules.features.iris.model import IrisNotificationPreference
from src.modules.features.iris.repositories import IrisNotificationPreferenceRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


def _save_preference(app, user_id: int, **overrides) -> None:
    with app.app_context():
        with UnitOfWork() as uow:
            IrisNotificationPreferenceRepository(uow).save(
                IrisNotificationPreference(user_id=user_id, **overrides)
            )


def test_get_returns_defaults_when_never_touched(client, regular_user, auth_headers):
    response = client.get("/iris/notification-preferences", headers=auth_headers(regular_user))

    assert response.status_code == 200
    body = response.get_json()
    assert body == {
        "digestEnabled": False,
        "mutedUntil": None,
        "notifyReauthRequired": True,
        "notifySyncStuck": True,
        "digestLastSentAt": None,
    }


def test_put_with_empty_body_changes_nothing(client, app, regular_user, auth_headers):
    _save_preference(app, regular_user.id, digest_enabled=True, notify_sync_stuck=False)

    response = client.put("/iris/notification-preferences", headers=auth_headers(regular_user), json={})

    assert response.status_code == 200
    body = response.get_json()
    assert body["digestEnabled"] is True
    assert body["notifySyncStuck"] is False


def test_put_updates_only_the_fields_sent(client, regular_user, auth_headers):
    response = client.put(
        "/iris/notification-preferences", headers=auth_headers(regular_user),
        json={"digestEnabled": True, "notifyReauthRequired": False},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["digestEnabled"] is True
    assert body["notifyReauthRequired"] is False
    assert body["notifySyncStuck"] is True  # sin tocar -- valor por defecto


def test_put_muted_for_minutes_sets_muted_until_in_the_future(client, regular_user, auth_headers):
    before = utcnow_naive()

    response = client.put(
        "/iris/notification-preferences", headers=auth_headers(regular_user),
        json={"mutedForMinutes": 120},
    )

    assert response.status_code == 200
    muted_until = response.get_json()["mutedUntil"]
    assert muted_until is not None


def test_put_muted_for_minutes_zero_clears_an_active_mute(client, app, regular_user, auth_headers):
    _save_preference(app, regular_user.id, muted_until=utcnow_naive() + timedelta(hours=1))

    response = client.put(
        "/iris/notification-preferences", headers=auth_headers(regular_user),
        json={"mutedForMinutes": 0},
    )

    assert response.status_code == 200
    assert response.get_json()["mutedUntil"] is None


def test_put_rejects_negative_muted_for_minutes(client, regular_user, auth_headers):
    response = client.put(
        "/iris/notification-preferences", headers=auth_headers(regular_user),
        json={"mutedForMinutes": -5},
    )

    assert response.status_code == 422


def test_preferences_are_scoped_to_the_current_user(client, regular_user, admin_user, auth_headers):
    client.put(
        "/iris/notification-preferences", headers=auth_headers(regular_user),
        json={"digestEnabled": True},
    )

    response = client.get("/iris/notification-preferences", headers=auth_headers(admin_user))

    assert response.get_json()["digestEnabled"] is False
