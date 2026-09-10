"""Alta pública y verificación de correo.

Lo que se prueba aquí es sobre todo la frontera: una cuenta recién creada por un
desconocido entra y navega, pero no gasta dinero nuestro hasta que confirma su
dirección. Sin esa frontera, el plan gratuito es un grifo abierto a cuentas
desechables.
"""

from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

import src.modules.system.config_reading as CR
from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager
from src.modules.infrastructure import unit_of_work
from src.modules.shared import utcnow_naive
from src.modules.users.model import User
from src.modules.users.repositories import UserRepository

pytestmark = pytest.mark.integration


VALID = {
    "username": "nuevo",
    "email": "nuevo@ellysia.test",
    "first_name": "Nueva",
    "last_name": "Cuenta",
    "password": "Secret123!",
}


@pytest.fixture()
def sent_emails():
    """Intercepta el correo saliente y devuelve los mensajes enviados."""
    mailer = mock.Mock()
    with mock.patch("src.modules.users.managers.build_mailer", return_value=mailer):
        yield mailer.send.call_args_list


def _token_from(sent_emails) -> str:
    """Extrae el token del enlace del último correo enviado."""
    assert sent_emails, "no se envio ningun correo de verificacion"
    message = sent_emails[-1].args[0]
    url = next(
        fragment for fragment in message.text_body.split()
        if fragment.startswith("http") and "token=" in fragment
    )
    return parse_qs(urlparse(url).query)["token"][0]


def _user(app, username: str) -> dict:
    """Datos planos del usuario: fuera del UnitOfWork la entidad quedaría
    desligada de su sesión."""
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", username)
            return {
                "id": found.id,
                "role": found.role,
                "email_verified_at": found.email_verified_at,
                "attributes": {attribute.attribute_name for attribute in found.attributes},
            }


# ------------------------------------------------------------------- el alta

def test_register_creates_an_unverified_account(client, app, sent_emails):
    resp = client.post("/users/register", json=VALID)

    assert resp.status_code == 201
    assert resp.get_json()["emailVerified"] is False
    assert _user(app, "nuevo")["email_verified_at"] is None


def test_register_sends_a_verification_email(client, sent_emails):
    client.post("/users/register", json=VALID)

    assert len(sent_emails) == 1
    message = sent_emails[0].args[0]
    assert message.to == VALID["email"]
    assert "token=" in message.text_body


def test_registered_account_gets_the_default_attributes(client, app, sent_emails):
    """Un usuario que se da de alta solo tiene el mismo llavero que uno Gold:
    lo que los separa son los topes del plan."""
    from src.modules.users.services.permissions import DEFAULT_USER_ATTRIBUTES

    client.post("/users/register", json=VALID)

    assert _user(app, "nuevo")["attributes"] == {
        attribute.db_name for attribute in DEFAULT_USER_ATTRIBUTES
    }


def test_registered_account_is_always_a_plain_user(client, app, sent_emails):
    """El rol no se acepta del cliente. Si se aceptara, el alta pública sería
    una puerta abierta al panel de administración."""
    resp = client.post("/users/register", json={**VALID, "role": "role_admin"})

    if resp.status_code == 201:
        assert _user(app, "nuevo")["role"] == "role_user"
    else:
        assert resp.status_code in (400, 422)


def test_registered_account_can_log_in(client, sent_emails):
    client.post("/users/register", json=VALID)

    token = client.post("/oauth/token", json={
        "grantType": "password",
        "username": VALID["username"],
        "password": VALID["password"],
    })
    assert token.status_code == 200
    assert token.get_json()["access_token"]


def test_register_rejects_a_taken_username(client, sent_emails):
    client.post("/users/register", json=VALID)
    again = client.post("/users/register", json={**VALID, "email": "otro@ellysia.test"})
    assert again.status_code == 409


def test_register_rejects_a_malformed_email(client, sent_emails):
    resp = client.post("/users/register", json={**VALID, "email": "esto-no-es-un-correo"})
    assert resp.status_code in (400, 422)


def test_register_can_be_closed_by_configuration(client, sent_emails, monkeypatch):
    """Un Ellysia interno de una empresa no quiere registros de desconocidos."""
    monkeypatch.setattr(
        CR, "registration_config",
        lambda: CR.RegistrationConfig(enabled=False, verification_ttl_hours=48),
    )
    resp = client.post("/users/register", json=VALID)

    assert resp.status_code == 403
    assert resp.get_json()["code"] == 1616   # REGISTRATION_CLOSED


# ------------------------------------------------------------- la frontera

def test_an_unverified_account_can_look_but_not_spend(
    client, app, auth_headers, make_user
):
    """La frontera entre "tener cuenta" y "poder gastar", en un test.

    Entrar y consultar, sí. Dar de alta un activo —que es lo que empieza a
    costar dinero— no, hasta confirmar el correo.
    """
    user = make_user(unverified=True)
    headers = auth_headers(user)

    assert client.get("/users/me", headers=headers).status_code == 200
    assert client.get("/plans/me", headers=headers).status_code == 200

    blocked = client.post("/hygeia/assets", headers=headers,
                          json={"hostname": "host-1", "os": "linux", "labels": {}})
    assert blocked.status_code == 403
    assert blocked.get_json()["code"] == 1614   # EMAIL_NOT_VERIFIED


def test_the_guard_is_not_a_payment_problem(app, make_user):
    """403 y no 402: esto no se arregla pagando, se arregla pulsando el enlace
    del correo."""
    from src.modules.accounts.exceptions import EmailNotVerifiedError

    user = make_user(unverified=True)
    with app.app_context():
        with pytest.raises(EmailNotVerifiedError) as raised:
            QuotaManager().consume(user.id, LimitKey.AI_REQUESTS)
        assert raised.value.status_code == 403


# ---------------------------------------------------------- la verificación

def test_verifying_the_email_unlocks_spending(client, app, sent_emails, auth_headers, make_user):
    client.post("/users/register", json=VALID)
    token = _token_from(sent_emails)

    assert client.post("/users/verify-email", json={"token": token}).status_code == 200
    assert _user(app, "nuevo")["email_verified_at"] is not None

    # Y ahora sí puede gastar.
    with app.app_context():
        QuotaManager().consume(_user(app, "nuevo")["id"], LimitKey.AI_REQUESTS)


def test_verify_email_is_public(client, sent_emails):
    """Quien pulsa el enlace no tiene por qué tener la sesión abierta, ni
    siquiera estar en el mismo dispositivo: el token es la única identidad."""
    client.post("/users/register", json=VALID)
    token = _token_from(sent_emails)

    assert client.post("/users/verify-email", json={"token": token}).status_code == 200


def test_a_verification_token_works_only_once(client, sent_emails):
    client.post("/users/register", json=VALID)
    token = _token_from(sent_emails)

    assert client.post("/users/verify-email", json={"token": token}).status_code == 200
    assert client.post("/users/verify-email", json={"token": token}).status_code == 400


def test_an_unknown_token_is_rejected(client):
    resp = client.post("/users/verify-email", json={"token": "no-existe"})
    assert resp.status_code == 400
    assert resp.get_json()["code"] == 1615   # INVALID_VERIFICATION_TOKEN


def test_an_expired_token_is_rejected(client, app, sent_emails):
    client.post("/users/register", json=VALID)
    token = _token_from(sent_emails)

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            found = UserRepository(uow).get_by_field("username", "nuevo")
            found.email_verification_expires_at = utcnow_naive() - timedelta(hours=1)
            uow.session.flush()

    assert client.post("/users/verify-email", json={"token": token}).status_code == 400


def test_the_stored_token_is_a_hash_not_the_token(client, app, sent_emails):
    """Leer la base de datos no debe permitir confirmar cuentas ajenas."""
    client.post("/users/register", json=VALID)
    token = _token_from(sent_emails)

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            stored = UserRepository(uow).get_by_field("username", "nuevo").email_verification_hash

    assert stored != token
    assert len(stored) == 64   # SHA-256 en hexadecimal


# ------------------------------------------------------------------ reenvío

def test_resend_requires_authentication(client):
    assert client.post("/users/verify-email/resend").status_code == 401


def test_resend_invalidates_the_previous_link(client, sent_emails, auth_headers, make_user):
    """Quien pide otro enlace porque "no le llegó" no debe quedarse con dos
    vivos."""
    user = make_user(unverified=True)

    client.post("/users/verify-email/resend", headers=auth_headers(user))
    first = _token_from(sent_emails)
    client.post("/users/verify-email/resend", headers=auth_headers(user))
    second = _token_from(sent_emails)

    assert first != second
    assert client.post("/users/verify-email", json={"token": first}).status_code == 400
    assert client.post("/users/verify-email", json={"token": second}).status_code == 200


def test_resend_on_a_verified_account_is_rejected(client, sent_emails, auth_headers, regular_user):
    resp = client.post("/users/verify-email/resend", headers=auth_headers(regular_user))
    assert resp.status_code == 409


def test_a_broken_mail_relay_does_not_break_the_signup(client, app):
    """El alta no se cae porque el SMTP esté caído: la cuenta queda creada y el
    usuario puede pedir otro enlace. Tumbar el registro sería peor."""
    with mock.patch("src.modules.users.managers.build_mailer",
                    side_effect=RuntimeError("relay caido")):
        resp = client.post("/users/register", json=VALID)

    assert resp.status_code == 201
    assert _user(app, "nuevo")["email_verified_at"] is None
