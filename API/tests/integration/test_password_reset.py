"""Recuperación de contraseña por magic link.

Lo que se protege aquí es el intercambio del token: el enlace vale una sola
vez y caduca, en la base de datos solo queda su hash, la solicitud no revela
si la cuenta existe, y con MFA activado el enlace no sale sin el segundo
factor. Sin esas propiedades, el formulario de recuperación sería una puerta
trasera mejor que adivinar la contraseña.
"""

from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest

from src.modules.infrastructure import unit_of_work
from src.modules.shared import utcnow_naive
from src.modules.users.repositories import UserRepository

pytestmark = pytest.mark.integration

RESET_PASSWORD = "NuevaClave123!"


@pytest.fixture()
def sent_emails():
    """Intercepta el correo saliente y devuelve los mensajes enviados."""
    mailer = mock.Mock()
    with mock.patch("src.modules.users.managers.build_mailer", return_value=mailer):
        yield mailer.send.call_args_list


def _token_from(sent_emails) -> str:
    """Extrae el token del enlace del último correo enviado."""
    assert sent_emails, "no se envio ningun correo de recuperacion"
    message = sent_emails[-1].args[0]
    url = next(
        fragment for fragment in message.text_body.split()
        if fragment.startswith("http") and "token=" in fragment
    )
    assert "/recuperar?" in url, f"el enlace no aterriza en /recuperar: {url}"
    return parse_qs(urlparse(url).query)["token"][0]


def _enable_totp(client, headers):
    """Activa TOTP para el usuario autenticado y devuelve (secret, recovery_codes)."""
    setup = client.post("/users/mfa/totp/setup", headers=headers).get_json()
    secret = setup["secret"]
    code = pyotp.TOTP(secret).now()
    confirm = client.post(
        "/users/mfa/totp/confirm", headers=headers, json={"code": code}
    ).get_json()
    return secret, confirm["recoveryCodes"]


def _request(client, identifier):
    return client.post("/users/password-reset/request", json={"identifier": identifier})


def _confirm(client, payload):
    """Fase 2 de la recuperación con MFA (endpoint aparte, con su propio rate
    limit de reintentos)."""
    return client.post("/users/password-reset/mfa", json=payload)


# -------------------------------------------------------------- la solicitud


def test_request_for_unknown_user_is_indistinguishable(client, sent_emails):
    """Misma respuesta que un envío real y ningún correo: el formulario no
    debe servir de oráculo de usuarios registrados."""
    resp = _request(client, "no-existe-nadie")

    assert resp.status_code == 200
    assert resp.get_json() == {"sent": True}
    assert sent_emails == []


def test_request_without_mfa_sends_the_link(client, sent_emails, make_user):
    user = make_user()

    resp = _request(client, user.username)

    assert resp.status_code == 200
    assert resp.get_json() == {"sent": True}
    assert len(sent_emails) == 1
    message = sent_emails[0].args[0]
    assert message.to == f"{user.username}@ellysia.test"
    assert "token=" in message.text_body


def test_request_accepts_an_email_identifier(client, sent_emails, make_user):
    user = make_user()

    resp = _request(client, f"{user.username}@ellysia.test")

    assert resp.status_code == 200
    assert sent_emails and sent_emails[0].args[0].to == f"{user.username}@ellysia.test"


def test_an_identifier_with_at_but_no_email_shape_is_a_username(client, sent_emails, make_user):
    """'x@y' tiene arroba pero no forma de correo: se busca como nombre de
    usuario. Un correo real con dominio sin TLD jamás se verá aquí; la
    respuesta genérica no distingue el caso."""
    make_user()

    resp = _request(client, "alguien@algo")

    assert resp.status_code == 200
    assert resp.get_json() == {"sent": True}
    assert sent_emails == []


def test_request_with_mfa_returns_a_challenge_without_sending(
    client, sent_emails, make_user, auth_headers,
):
    user = make_user()
    _enable_totp(client, auth_headers(user))

    resp = _request(client, user.username)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mfaRequired"] is True
    assert body["challengeToken"]
    assert "sent" not in body
    # El enlace no sale hasta que el segundo factor verifica: un buzón
    # robado no basta para resetear una cuenta con MFA.
    assert sent_emails == []


# --------------------------------------------------- la fase 2 (con MFA)


def test_mfa_phase_two_with_valid_totp_sends_the_link(client, sent_emails, make_user, auth_headers):
    user = make_user()
    secret, _ = _enable_totp(client, auth_headers(user))
    challenge = _request(client, user.username).get_json()["challengeToken"]

    resp = _confirm(client, {"challengeToken": challenge,
        "code": pyotp.TOTP(secret).now(),
    })

    assert resp.status_code == 200
    assert resp.get_json() == {"sent": True}
    assert len(sent_emails) == 1


def test_mfa_phase_two_accepts_a_recovery_code(client, sent_emails, make_user, auth_headers):
    user = make_user()
    _, recovery_codes = _enable_totp(client, auth_headers(user))
    challenge = _request(client, user.username).get_json()["challengeToken"]

    resp = _confirm(client, {"challengeToken": challenge,
        "recoveryCode": recovery_codes[0],
    })

    assert resp.status_code == 200
    assert resp.get_json() == {"sent": True}
    assert len(sent_emails) == 1


def test_mfa_phase_two_with_wrong_code_sends_nothing(client, sent_emails, make_user, auth_headers):
    user = make_user()
    _enable_totp(client, auth_headers(user))
    challenge = _request(client, user.username).get_json()["challengeToken"]

    resp = _confirm(client, {"challengeToken": challenge,
        "code": "000000",
    })

    assert resp.status_code == 401
    assert sent_emails == []


def test_mfa_phase_two_with_unknown_challenge_is_rejected(client, sent_emails):
    resp = _confirm(client, {"challengeToken": "no-existe",
        "code": "123456",
    })
    assert resp.status_code == 401
    assert sent_emails == []


def test_a_login_challenge_does_not_work_in_the_reset_flow(
    client, sent_emails, make_user, auth_headers,
):
    """Los challenges van marcados por propósito: el del login no debe
    disparar el envío del enlace de recuperación."""
    user = make_user()
    secret, _ = _enable_totp(client, auth_headers(user))

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": user.username,
        "password": user.password,
    }).get_json()

    resp = _confirm(client, {"challengeToken": login["challengeToken"],
        "code": pyotp.TOTP(secret).now(),
    })

    assert resp.status_code == 401
    assert sent_emails == []


def test_a_reset_challenge_does_not_issue_login_tokens(client, make_user, auth_headers):
    """Y al revés: el challenge de recuperación no se canjea por tokens en
    /oauth/mfa/verify."""
    user = make_user()
    secret, _ = _enable_totp(client, auth_headers(user))
    challenge = _request(client, user.username).get_json()["challengeToken"]

    resp = client.post("/oauth/mfa/verify", json={
        "challengeToken": challenge,
        "code": pyotp.TOTP(secret).now(),
    })

    assert resp.status_code == 401
    assert "access_token" not in resp.get_json()


# -------------------------------------------------- la comprobación del token


def test_check_reports_a_valid_token_without_consuming_it(client, sent_emails, make_user):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    assert client.post(
        "/users/password-reset/check", json={"token": token},
    ).get_json() == {"valid": True}
    assert client.post(
        "/users/password-reset/check", json={"token": token},
    ).get_json() == {"valid": True}


def test_check_reports_an_unknown_token(client):
    resp = client.post("/users/password-reset/check", json={"token": "no-existe"})
    assert resp.status_code == 200
    assert resp.get_json() == {"valid": False}


def test_the_stored_token_is_a_hash_not_the_token(client, app, sent_emails, make_user):
    """Leer la base de datos no debe permitir resetear contraseñas ajenas."""
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            stored = UserRepository(uow).get_by_field("username", user.username).password_reset_hash

    assert stored != token
    assert len(stored) == 64   # SHA-256 en hexadecimal


# -------------------------------------------------------------- el reseteo


def test_the_link_resets_the_password_end_to_end(client, sent_emails, make_user):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    resp = client.post("/users/password-reset/reset", json={
        "token": token,
        "newPassword": RESET_PASSWORD,
    })
    assert resp.status_code == 200

    old = client.post("/oauth/token", json={
        "grantType": "password",
        "username": user.username,
        "password": user.password,
    })
    assert old.status_code == 401

    fresh = client.post("/oauth/token", json={
        "grantType": "password",
        "username": user.username,
        "password": RESET_PASSWORD,
    })
    assert fresh.status_code == 200


def test_a_reset_token_works_only_once(client, sent_emails, make_user):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    first = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD},
    )
    second = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": "OtraClave456!"},
    )

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.get_json()["code"] == 1617   # PASSWORD_RESET_TOKEN_INVALID


def test_an_expired_token_is_rejected(client, app, sent_emails, make_user):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", user.username)
            found.password_reset_expires_at = utcnow_naive() - timedelta(minutes=1)
            uow.session.flush()

    assert client.post(
        "/users/password-reset/check", json={"token": token},
    ).get_json() == {"valid": False}
    resp = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD},
    )
    assert resp.status_code == 400
    assert resp.get_json()["code"] == 1617


def test_reset_rejects_the_same_password_but_keeps_the_link(
    client, sent_emails, make_user,
):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    same = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": user.password},
    )
    assert same.status_code == 400

    # El enlace sigue vivo: solo se consume con un cambio real de clave.
    retry = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD},
    )
    assert retry.status_code == 200


def test_reset_rejects_a_short_password(client, sent_emails, make_user):
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    resp = client.post("/users/password-reset/reset", json={"token": token, "newPassword": "corta"})
    assert resp.status_code == 422


def test_reset_revokes_existing_sessions(client, sent_emails, make_user, auth_headers):
    """El enlace es la identidad de quien lo pulsa, que puede no ser quien
    tenía la sesión abierta: todas las sesiones previas mueren."""
    user = make_user()
    headers = auth_headers(user)

    assert client.get("/users/me", headers=headers).status_code == 200

    _request(client, user.username)
    token = _token_from(sent_emails)
    client.post("/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD})

    assert client.get("/users/me", headers=headers).status_code == 401


def test_reset_satisfies_the_must_change_password_flag(client, app, sent_emails, make_user):
    """Una cuenta nacida por invitación arrastra 'debes cambiar la clave';
    resetearla por enlace la cumple."""
    user = make_user()
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", user.username)
            found.must_change_password = True
            uow.session.flush()

    _request(client, user.username)
    token = _token_from(sent_emails)
    client.post("/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD})

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", user.username)
            assert found.must_change_password is False


# --------------------------------------------------- el cooldown anti-spam


def test_a_second_request_within_the_cooldown_does_not_resend(client, sent_emails, make_user):
    """Quien conoce un nombre de usuario no debe poder inundar el buzón: la
    segunda solicitud responde igual pero no re-minta ni reenvía."""
    user = make_user()

    assert _request(client, user.username).status_code == 200
    assert _request(client, user.username).status_code == 200

    assert len(sent_emails) == 1


def test_a_new_request_after_the_cooldown_invalidates_the_previous_link(
    client, app, sent_emails, make_user,
):
    """Pasada la pausa, un enlace nuevo invalida el anterior: el usuario que
    pidió dos enlaces no debe quedarse con dos vivos."""
    user = make_user()
    _request(client, user.username)
    first = _token_from(sent_emails)

    # Envejece el enlace hasta dejarlo fuera del cooldown (no caducado).
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", user.username)
            found.password_reset_expires_at = utcnow_naive() + timedelta(minutes=10)
            uow.session.flush()

    _request(client, user.username)
    second = _token_from(sent_emails)

    assert first != second
    assert client.post(
        "/users/password-reset/check", json={"token": first},
    ).get_json() == {"valid": False}
    assert client.post(
        "/users/password-reset/check", json={"token": second},
    ).get_json() == {"valid": True}


# ----------------------------------------------------------- el rate limit


def test_request_is_rate_limited(client, rate_limiting_enabled):
    """El endpoint es anónimo y vive expuesto: 3 por hora por IP, igual que
    el reenvío de la verificación de correo."""
    for _ in range(3):
        resp = _request(client, "no-existe-nadie")
        assert resp.status_code == 200

    resp = _request(client, "no-existe-nadie")
    assert resp.status_code == 429


def test_the_mfa_phase_has_its_own_rate_limit(
    client, rate_limiting_enabled, make_user, auth_headers,
):
    """Fase 1 y fase 2 comparten propósito pero no límite: la fase 2 admite
    reintentos (10 por minuto), como /oauth/mfa/verify. Un usuario que erra
    códigos no debe quemar su cupo de solicitudes."""
    user = make_user()
    _enable_totp(client, auth_headers(user))
    challenge = _request(client, user.username).get_json()["challengeToken"]

    for _ in range(10):
        resp = _confirm(client, {"challengeToken": challenge, "code": "000000"})
        assert resp.status_code == 401

    resp = _confirm(client, {"challengeToken": challenge, "code": "000000"})
    assert resp.status_code == 429


# --------------------------------------------- los casos borde de la auditoría


def test_request_accepts_an_email_identifier_ignoring_case(
    client, sent_emails, make_user,
):
    """El usuario escribe su correo como lo recuerda, no como lo tecleó el día
    del alta: la comparación no distingue mayúsculas."""
    user = make_user()

    resp = _request(client, f"{user.username.upper()}@Ellysia.Test")

    assert resp.status_code == 200
    assert sent_emails and sent_emails[0].args[0].to == f"{user.username}@ellysia.test"


def test_a_successful_login_invalidates_the_pending_link(
    client, sent_emails, make_user,
):
    """Pedir el enlace y luego recordar la contraseña: el login correcto
    anula el enlace, que no debe quedar vivo en el buzón."""
    user = make_user()
    _request(client, user.username)
    token = _token_from(sent_emails)

    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": user.username,
        "password": user.password,
    })
    assert login.status_code == 200

    assert client.post(
        "/users/password-reset/check", json={"token": token},
    ).get_json() == {"valid": False}
    resp = client.post(
        "/users/password-reset/reset", json={"token": token, "newPassword": RESET_PASSWORD},
    )
    assert resp.status_code == 400
