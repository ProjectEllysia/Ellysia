"""Tests de integración de MFA (TOTP + códigos de recuperación)."""

import pyotp
import pytest
from sqlalchemy import text

from src.modules.infrastructure import UnitOfWork
from src.modules.shared._crypto import decrypt_at_rest

pytestmark = pytest.mark.integration


def _enable_totp(client, headers):
    """Activa TOTP para el usuario autenticado y devuelve (secret, recovery_codes)."""
    setup = client.post("/users/mfa/totp/setup", headers=headers).get_json()
    secret = setup["secret"]
    code = pyotp.TOTP(secret).now()
    confirm = client.post(
        "/users/mfa/totp/confirm", headers=headers, json={"code": code}
    ).get_json()
    return secret, confirm["recoveryCodes"]


# ── Estado por defecto ────────────────────────────────────────────────────


def test_mfa_status_defaults_disabled(client, regular_user, auth_headers):
    resp = client.get("/users/mfa", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["enabled"] is False
    assert body["confirmedAt"] is None


def test_login_without_mfa_is_unchanged(client, regular_user):
    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["access_token"]
    assert "mfaRequired" not in body


# ── Inscripción TOTP ──────────────────────────────────────────────────────


def test_totp_setup_returns_secret_and_provisioning_uri(client, regular_user, auth_headers):
    resp = client.post("/users/mfa/totp/setup", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["secret"]
    assert body["provisioningUri"].startswith("otpauth://totp/")


def test_totp_confirm_with_wrong_code_is_rejected(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    client.post("/users/mfa/totp/setup", headers=headers)
    resp = client.post("/users/mfa/totp/confirm", headers=headers, json={"code": "000000"})
    assert resp.status_code == 401


def test_totp_confirm_enables_mfa_and_returns_recovery_codes(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    _, recovery_codes = _enable_totp(client, headers)
    assert len(recovery_codes) == 10
    assert all("-" in c for c in recovery_codes)

    status = client.get("/users/mfa", headers=headers).get_json()
    assert status["enabled"] is True
    assert status["confirmedAt"] is not None


def test_totp_setup_already_confirmed_is_rejected(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    _enable_totp(client, headers)
    resp = client.post("/users/mfa/totp/setup", headers=headers)
    assert resp.status_code == 409


# ── Login con MFA activado ────────────────────────────────────────────────


def test_login_with_mfa_enabled_returns_challenge(client, regular_user, auth_headers):
    _enable_totp(client, auth_headers(regular_user))

    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mfaRequired"] is True
    assert body["challengeToken"]
    assert body["methods"] == ["totp"]
    assert "access_token" not in body


def test_mfa_verify_with_valid_totp_issues_tokens(client, regular_user, auth_headers):
    secret, _ = _enable_totp(client, auth_headers(regular_user))

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()

    code = pyotp.TOTP(secret).now()
    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": login["challengeToken"],
        "code": code,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["access_token"]
    assert body["refresh_token"]

    # El access token ya autentica normalmente en el resto de la API.
    me = client.get("/users/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200


def test_mfa_verify_with_wrong_code_is_rejected(client, regular_user, auth_headers):
    _enable_totp(client, auth_headers(regular_user))

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()

    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": login["challengeToken"],
        "code": "000000",
    })
    assert resp.status_code == 401


def test_mfa_verify_with_invalid_challenge_token_is_rejected(client, regular_user, auth_headers):
    _enable_totp(client, auth_headers(regular_user))
    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": "no-existe",
        "code": "123456",
    })
    assert resp.status_code == 401


def test_mfa_challenge_locks_after_max_attempts(client, regular_user, auth_headers):
    _enable_totp(client, auth_headers(regular_user))

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()
    challenge_token = login["challengeToken"]

    # 5 intentos fallidos agotan el challenge (max_challenge_attempts por defecto = 5).
    for _ in range(5):
        resp = client.post("/oauth/mfa/verify", json={
            "challengeToken": challenge_token,
            "code": "000000",
        })
        assert resp.status_code == 401

    # Un sexto intento, aunque el código ahora sea correcto, debe rechazarse:
    # el challenge ya superó el máximo de intentos.
    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": challenge_token,
        "code": "000000",
    })
    assert resp.status_code == 401


def test_mfa_verify_is_rate_limited(client, rate_limiting_enabled):
    # T4: mismo idioma que test_password_grant_is_rate_limited — reactiva el
    # limiter real para verificar que /oauth/mfa/verify ("10 per minute")
    # efectivamente devuelve 429. Un challenge token inexistente basta (falla
    # rápido, sin consumir el contador de intentos de ningún challenge real).
    body = {"challengeToken": "no-existe", "code": "000000"}
    for _ in range(10):
        resp = client.post("/oauth/mfa/verify", json=body)
        assert resp.status_code == 401

    resp = client.post("/oauth/mfa/verify", json=body)
    assert resp.status_code == 429


# ── Códigos de recuperación ───────────────────────────────────────────────


def test_recovery_code_can_be_used_once(client, regular_user, auth_headers):
    _, recovery_codes = _enable_totp(client, auth_headers(regular_user))
    a_code = recovery_codes[0]

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()

    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": login["challengeToken"],
        "recoveryCode": a_code,
    })
    assert resp.status_code == 200

    # Un segundo login con el MISMO código de recuperación debe fallar.
    login2 = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()
    resp2 = client.post("/oauth/mfa/verify", json={
        "challengeToken": login2["challengeToken"],
        "recoveryCode": a_code,
    })
    assert resp2.status_code == 401


# ── Desactivación ─────────────────────────────────────────────────────────


def test_disable_totp_requires_valid_code(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    _enable_totp(client, headers)

    resp = client.delete("/users/mfa/totp", headers=headers, json={"code": "000000"})
    assert resp.status_code == 401

    status = client.get("/users/mfa", headers=headers).get_json()
    assert status["enabled"] is True


def test_disable_totp_with_valid_code_disables_mfa(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    secret, _ = _enable_totp(client, headers)

    resp = client.delete("/users/mfa/totp", headers=headers, json={"code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 200

    status = client.get("/users/mfa", headers=headers).get_json()
    assert status["enabled"] is False

    # Login ya no pide MFA.
    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    })
    assert login.status_code == 200
    assert "mfaRequired" not in login.get_json()


# ── Cifrado en reposo del secreto ─────────────────────────────────────────


def test_the_totp_secret_is_encrypted_in_the_database(app, client, regular_user, auth_headers):
    """El secreto que devuelve /setup nunca debe llegar tal cual a la fila.

    Lo cifra el tipo de columna (``EncryptedText``), no el manager, así que
    la única forma de comprobarlo es saltarse el ORM y mirar el valor crudo:
    leyendo ``credential.totp_secret`` se vería ya descifrado y el test
    pasaría aunque el cifrado hubiera desaparecido.
    """
    headers = auth_headers(regular_user)
    secret = client.post("/users/mfa/totp/setup", headers=headers).get_json()["secret"]

    with app.app_context():
        with UnitOfWork() as uow:
            row = uow.session.execute(
                text('SELECT totp_secret FROM "MFATotpCredential" WHERE user_id = :id'),
                {"id": regular_user.id},
            ).first()

    stored = row[0]
    assert stored != secret
    assert decrypt_at_rest(stored, purpose="mfa") == secret
