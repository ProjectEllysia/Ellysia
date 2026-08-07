"""Organizaciones: un titular paga y sus miembros heredan derechos.

Lo que se prueba aquí, por encima de todo, es que **heredar no es sustituir**.
Un empleado que entra en una organización no pierde su plan, y al salir se lo
lleva intacto. Esa promesa es la que hace vendible el modelo y la que más fácil
sería romper sin querer.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


FUTURE = utcnow_naive() + timedelta(days=30)
PAST = utcnow_naive() - timedelta(days=1)


@pytest.fixture()
def owner(make_user, make_subscription):
    """Responsable de seguridad: Gold con el toggle de organización."""
    user = make_user()
    make_subscription(user, plan_code="gold", organization_enabled=True,
                      current_period_end=FUTURE)
    return user


@pytest.fixture()
def sent_emails():
    mailer = mock.Mock()
    with mock.patch("src.modules.accounts.managers.invitations.build_mailer",
                    return_value=mailer):
        yield mailer.send.call_args_list


def _create_org(client, headers, name="Acme"):
    resp = client.post("/organizations", headers=headers, json={"name": name})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def _join(app, organization_id, user_id):
    """Mete a alguien en la organización sin pasar por la invitación."""
    from src.modules.accounts.model import OrganizationMember
    from src.modules.infrastructure import unit_of_work

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            uow.session.add(OrganizationMember(
                organization_id=organization_id, user_id=user_id, member_role="member",
            ))
            uow.session.flush()


# ------------------------------------------------------------------- el alta

def test_creating_an_organization_requires_the_addon(client, regular_user, auth_headers):
    """Sin el toggle no hay organización, y se dice con un 402: esto se
    arregla pagando, no pidiendo permiso."""
    resp = client.post("/organizations", headers=auth_headers(regular_user),
                       json={"name": "Acme"})
    assert resp.status_code == 402


def test_the_owner_is_a_member_of_their_own_organization(client, owner, auth_headers):
    """Así el recuento de miembros y la resolución de derechos no necesitan un
    caso especial, y el dueño consume de la misma bolsa que su gente."""
    headers = auth_headers(owner)
    organization = _create_org(client, headers)

    assert organization["memberCount"] == 1
    members = client.get(f"/organizations/{organization['id']}/members",
                         headers=headers).get_json()["members"]
    assert [m["userId"] for m in members] == [owner.id]
    assert members[0]["role"] == "owner"


def test_one_organization_per_owner(client, owner, auth_headers):
    headers = auth_headers(owner)
    _create_org(client, headers)
    assert client.post("/organizations", headers=headers,
                       json={"name": "Otra"}).status_code == 409


def test_the_slug_is_unique(client, owner, make_user, make_subscription, auth_headers):
    other = make_user()
    make_subscription(other, plan_code="gold", organization_enabled=True,
                      current_period_end=FUTURE)

    first = _create_org(client, auth_headers(owner), "Acme SL")
    second = _create_org(client, auth_headers(other), "Acme SL")

    assert first["slug"] == "acme-sl"
    assert second["slug"] == "acme-sl-2"


def test_members_only_see_identity(client, app, owner, regular_user, auth_headers):
    """El dueño ve quiénes son, nunca qué tienen. Es la garantía que se vende,
    no una carencia: sus bóvedas son zero-knowledge y sus correos, personales."""
    organization = _create_org(client, auth_headers(owner))
    _join(app, organization["id"], regular_user.id)

    members = client.get(f"/organizations/{organization['id']}/members",
                         headers=auth_headers(owner)).get_json()["members"]
    fields = set(members[0])

    assert fields == {"userId", "username", "email", "fullName", "role", "joinedAt"}


def test_an_outsider_cannot_read_the_members(client, owner, regular_user, auth_headers):
    """Mismo error que si no existiera: si "no es tuya" y "no existe" dieran
    respuestas distintas, se podrían enumerar organizaciones ajenas."""
    organization = _create_org(client, auth_headers(owner))
    resp = client.get(f"/organizations/{organization['id']}/members",
                      headers=auth_headers(regular_user))
    assert resp.status_code == 404


# --------------------------------------------------- heredar no es sustituir

def test_membership_adds_to_the_personal_plan(client, app, owner, regular_user, auth_headers):
    """El empleado sigue siendo Freemium en lo suyo y además recibe lo que su
    empresa cubre. La bóveda pasa de 1 a ilimitada porque Gold lo incluye."""
    organization = _create_org(client, auth_headers(owner))

    with app.app_context():
        before = QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS)
        assert before.limit == 1
        assert before.source == "default"

    _join(app, organization["id"], regular_user.id)

    with app.app_context():
        after = QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS)
        assert after.limit is None          # ilimitado, cortesía de la organización
        assert after.source == "organization"


def test_a_paid_personal_plan_wins_where_it_is_higher(
    client, app, owner, make_user, make_subscription, auth_headers
):
    """Gana el mayor de los dos, no "el de la organización".

    El empleado tiene Bronze pagado (100 análisis) y su organización le da 200
    por ser Gold: se queda con 200. Si tuviera un plan mejor que el heredado,
    mandaría el suyo.
    """
    organization = _create_org(client, auth_headers(owner))
    employee = make_user()
    make_subscription(employee, plan_code="bronze", current_period_end=FUTURE)
    _join(app, organization["id"], employee.id)

    with app.app_context():
        state = QuotaManager().state(employee.id, LimitKey.IRIS_ANALYSES)
        assert state.limit == 200
        assert state.source == "organization"


def test_leaving_gives_back_the_personal_plan_untouched(
    client, app, owner, make_user, make_subscription, auth_headers
):
    """Al salir, el Bronze que se pagó sigue ahí. Nunca se sustituyó."""
    organization = _create_org(client, auth_headers(owner))
    employee = make_user()
    make_subscription(employee, plan_code="bronze", current_period_end=FUTURE)
    _join(app, organization["id"], employee.id)

    assert client.delete("/organizations/mine",
                         headers=auth_headers(employee)).status_code == 200

    with app.app_context():
        state = QuotaManager().state(employee.id, LimitKey.IRIS_ANALYSES)
        assert state.limit == 100          # su Bronze, intacto
        assert state.source == "personal"


# ------------------------------------------------------------- la bolsa común

def test_members_share_one_bag(client, app, owner, make_user, auth_headers):
    """Lo que consume uno lo nota el otro: la organización paga una bolsa, no
    una por cabeza."""
    organization = _create_org(client, auth_headers(owner))
    first, second = make_user(), make_user()
    _join(app, organization["id"], first.id)
    _join(app, organization["id"], second.id)

    with app.app_context():
        QuotaManager().consume(first.id, LimitKey.IRIS_ANALYSES, amount=30)
        assert QuotaManager().state(second.id, LimitKey.IRIS_ANALYSES).used == 30


def test_the_bag_runs_out_for_everyone(client, app, owner, make_user, auth_headers):
    from src.modules.accounts.exceptions import QuotaExceededError

    organization = _create_org(client, auth_headers(owner))
    first, second = make_user(), make_user()
    _join(app, organization["id"], first.id)
    _join(app, organization["id"], second.id)

    with app.app_context():
        QuotaManager().consume(first.id, LimitKey.IRIS_ANALYSES, amount=200)
        with pytest.raises(QuotaExceededError):
            QuotaManager().consume(second.id, LimitKey.IRIS_ANALYSES)


# ------------------------------------------- el dueño deja de pagar (§12.8)

def test_when_the_owner_stops_paying_nothing_is_destroyed(
    client, app, owner, regular_user, auth_headers, make_subscription
):
    """La organización y sus miembros siguen existiendo; lo único que se pierde
    son los derechos heredados. Borrarlos haría irreversible un problema que
    casi siempre es una tarjeta caducada."""
    from src.modules.accounts.model import Subscription
    from src.modules.infrastructure import unit_of_work

    organization = _create_org(client, auth_headers(owner))
    _join(app, organization["id"], regular_user.id)

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            subscription = uow.session.query(Subscription).filter(
                Subscription.user_id == owner.id
            ).one()
            subscription.current_period_end = PAST
            uow.session.flush()

    # El miembro cae a su plan personal, pero sigue dentro de la organización.
    with app.app_context():
        state = QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS)
        assert state.limit == 1
        assert state.source == "default"

    assert client.get("/organizations/mine",
                      headers=auth_headers(regular_user)).status_code == 200


def test_an_unpaid_owner_cannot_grow_the_organization(
    client, app, owner, auth_headers, sent_emails
):
    """Lo que ya tiene sigue en pie, pero no suma gente mientras no paga."""
    from src.modules.accounts.model import Subscription
    from src.modules.infrastructure import unit_of_work

    organization = _create_org(client, auth_headers(owner))
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            subscription = uow.session.query(Subscription).filter(
                Subscription.user_id == owner.id
            ).one()
            subscription.status = "canceled"
            subscription.current_period_end = PAST
            uow.session.flush()

    resp = client.post(f"/organizations/{organization['id']}/invitations",
                       headers=auth_headers(owner), json={"email": "nuevo@ellysia.test"})
    assert resp.status_code == 402


# ------------------------------------------------------------- invitaciones

def test_inviting_an_existing_user_changes_nothing_until_they_accept(
    client, app, owner, regular_user, auth_headers, sent_emails
):
    """Es la decisión de consentimiento del diseño: un tercero no puede meter a
    nadie en su organización sin permiso."""
    organization = _create_org(client, auth_headers(owner))

    resp = client.post(f"/organizations/{organization['id']}/invitations",
                       headers=auth_headers(owner),
                       json={"email": f"user{regular_user.id}@ellysia.test"})
    assert resp.status_code == 201
    assert resp.get_json()["status"] == "pending"

    # Sigue sin organización y con su plan de siempre. El endpoint responde
    # 200 con null: no estar en ninguna es un estado, no un recurso que falte.
    mia = client.get("/organizations/mine", headers=auth_headers(regular_user))
    assert mia.status_code == 200
    assert mia.get_json()["organization"] is None
    with app.app_context():
        assert QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS).source == "default"


def test_accepting_an_invitation_joins_without_touching_the_plan(
    client, app, owner, regular_user, auth_headers, sent_emails
):
    organization = _create_org(client, auth_headers(owner))
    client.post(f"/organizations/{organization['id']}/invitations",
                headers=auth_headers(owner),
                json={"email": f"user{regular_user.id}@ellysia.test"})
    token = _invitation_token(sent_emails)

    resp = client.post("/organizations/invitations/accept", json={"token": token})
    assert resp.status_code == 200

    with app.app_context():
        assert QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS).source == "organization"


def test_an_invitation_works_only_once(client, owner, regular_user, auth_headers, sent_emails):
    organization = _create_org(client, auth_headers(owner))
    client.post(f"/organizations/{organization['id']}/invitations",
                headers=auth_headers(owner),
                json={"email": f"user{regular_user.id}@ellysia.test"})
    token = _invitation_token(sent_emails)

    assert client.post("/organizations/invitations/accept", json={"token": token}).status_code == 200
    assert client.post("/organizations/invitations/accept", json={"token": token}).status_code == 400


def test_a_revoked_invitation_stops_working(client, owner, regular_user, auth_headers, sent_emails):
    organization = _create_org(client, auth_headers(owner))
    created = client.post(f"/organizations/{organization['id']}/invitations",
                          headers=auth_headers(owner),
                          json={"email": f"user{regular_user.id}@ellysia.test"}).get_json()
    token = _invitation_token(sent_emails)

    assert client.delete(f"/organizations/invitations/{created['id']}",
                         headers=auth_headers(owner)).status_code == 200
    assert client.post("/organizations/invitations/accept", json={"token": token}).status_code == 400


def test_inviting_an_unknown_email_creates_the_account(
    client, app, owner, auth_headers, sent_emails
):
    """Sin cuenta no hay consentimiento que pedir: se crea y entra directa, con
    una contraseña que tendrá que cambiar."""
    from src.modules.infrastructure import unit_of_work
    from src.modules.users.repositories import UserRepository

    organization = _create_org(client, auth_headers(owner))
    resp = client.post(f"/organizations/{organization['id']}/invitations",
                       headers=auth_headers(owner), json={"email": "nadie@ellysia.test"})

    assert resp.status_code == 201
    assert resp.get_json()["status"] == "accepted"

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            created = UserRepository(uow).get_by_field("email", "nadie@ellysia.test")
            assert created is not None
            assert created.must_change_password is True
            assert created.email_verified_at is not None   # responde quien invita

    members = client.get(f"/organizations/{organization['id']}/members",
                         headers=auth_headers(owner)).get_json()["members"]
    assert len(members) == 2


def test_the_member_cap_counts_pending_invitations(
    client, owner, make_user, auth_headers, sent_emails, make_subscription
):
    """Si solo contaran los miembros, se invitaría a 300 con un plan de 5 y
    bastaría con que fueran aceptando."""
    organization = _create_org(client, auth_headers(owner))   # gold: 5 miembros

    # El dueño ya ocupa 1; cuatro invitaciones más agotan el cupo.
    for index in range(4):
        resp = client.post(f"/organizations/{organization['id']}/invitations",
                           headers=auth_headers(owner),
                           json={"email": f"p{index}@ellysia.test"})
        assert resp.status_code == 201

    blocked = client.post(f"/organizations/{organization['id']}/invitations",
                          headers=auth_headers(owner), json={"email": "uno-mas@ellysia.test"})
    assert blocked.status_code == 402


# --------------------------------------------------------- expulsar y salir

def test_expelling_removes_rights_but_never_data(
    client, app, owner, regular_user, auth_headers
):
    organization = _create_org(client, auth_headers(owner))
    _join(app, organization["id"], regular_user.id)

    assert client.delete(
        f"/organizations/{organization['id']}/members/{regular_user.id}",
        headers=auth_headers(owner),
    ).status_code == 200

    # La cuenta sigue viva y con su plan personal.
    assert client.get("/users/me", headers=auth_headers(regular_user)).status_code == 200
    with app.app_context():
        assert QuotaManager().state(regular_user.id, LimitKey.ACHERON_VAULTS).source == "default"


def test_the_owner_cannot_be_expelled_nor_leave(client, owner, auth_headers):
    """La organización se quedaría sin titular y sin nadie que pague."""
    organization = _create_org(client, auth_headers(owner))
    headers = auth_headers(owner)

    assert client.delete(
        f"/organizations/{organization['id']}/members/{owner.id}", headers=headers,
    ).status_code == 409
    assert client.delete("/organizations/mine", headers=headers).status_code == 409


def test_leaving_without_an_organization_is_a_404(client, regular_user, auth_headers):
    assert client.delete("/organizations/mine",
                         headers=auth_headers(regular_user)).status_code == 404


# --------------------------------------- el dueño gestiona a los suyos (§8.6)

def test_the_owner_manages_the_attributes_of_their_members(
    client, app, owner, make_user, auth_headers
):
    """Sin ser administrador de Ellysia. Es lo que hay detrás de "ser dueño de
    una organización": restar dentro de lo comprado."""
    organization = _create_org(client, auth_headers(owner))
    employee = make_user()
    _join(app, organization["id"], employee.id)

    removed = client.delete(f"/users/{employee.id}/attributes",
                            headers=auth_headers(owner),
                            json={"attributes": ["themis_create"]})
    assert removed.status_code == 200

    denied = client.post("/themis/nmap", headers=auth_headers(employee),
                         json={"target": "scanme.example.com", "ports": "80"})
    assert denied.status_code == 403


def test_the_owner_cannot_touch_someone_outside_the_organization(
    client, owner, regular_user, auth_headers
):
    _create_org(client, auth_headers(owner))
    resp = client.delete(f"/users/{regular_user.id}/attributes",
                         headers=auth_headers(owner),
                         json={"attributes": ["themis_create"]})
    assert resp.status_code == 403


def test_nobody_can_grant_attributes_to_themselves(client, owner, auth_headers):
    """La barrera que sustituye a require_role(ADMIN) en estos endpoints.

    ``can_manage_user`` empieza con ``actor == target -> True``, que para
    escribir sería una escalada de privilegios: cualquiera se concedería lo que
    quisiera.
    """
    _create_org(client, auth_headers(owner))
    resp = client.put(f"/users/{owner.id}/attributes", headers=auth_headers(owner),
                      json={"attributes": ["themis_create"]})
    assert resp.status_code == 403


def test_an_owner_cannot_manage_an_admin_who_is_a_member(
    client, app, owner, make_user, auth_headers
):
    """Un administrador de Ellysia que esté en una organización no queda bajo
    el mando de su dueño."""
    organization = _create_org(client, auth_headers(owner))
    admin = make_user(role="role_admin")
    _join(app, organization["id"], admin.id)

    resp = client.delete(f"/users/{admin.id}/attributes", headers=auth_headers(owner),
                         json={"attributes": ["themis_create"]})
    assert resp.status_code == 403


# ------------------------------------------------------------------ helpers

def _invitation_token(sent_emails) -> str:
    from urllib.parse import parse_qs, urlparse

    assert sent_emails, "no se envio ninguna invitacion"
    message = sent_emails[-1].args[0]
    url = next(
        fragment for fragment in message.text_body.split()
        if fragment.startswith("http") and "token=" in fragment
    )
    return parse_qs(urlparse(url).query)["token"][0]
