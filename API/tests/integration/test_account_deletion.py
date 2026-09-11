"""Baja de una cuenta y todo lo que arrastra.

El test que más vale de este fichero es
``test_deleting_an_account_leaves_no_dangling_reference``: recorre el grafo real
de claves ajenas en vez de fiarse de que el borrado "pareció funcionar". La
suite corre sobre SQLite, que **no** aplica claves ajenas, así que un barrido
incompleto pasaría verde aquí y daría un 500 en Postgres. Ese test es lo único
que se interpone.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.infrastructure import unit_of_work
from src.modules.shared import Base, utcnow_naive

pytestmark = pytest.mark.integration


FUTURE = utcnow_naive() + timedelta(days=30)
PASSWORD = "Secret123!"


@pytest.fixture()
def owner(make_user, make_subscription):
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


def _seed_user_data(app, user_id: int) -> None:
    """Siembra una fila en cada tabla que NO tiene cascada hacia User.

    Son justo las que un borrado ingenuo dejaría colgando y las que harían
    fallar el DELETE en Postgres.
    """
    from src.modules.features.aegis.model import (
        AegisDocument,
        AegisOrgProfile,
        Campaign,
        DistributionList,
        Topic,
    )
    from src.modules.features.hygeia.model import MonitoredAsset
    from src.modules.features.iris.model import IrisMailboxConnection
    from src.modules.features.themis.model import AuthorizedTarget, ProgramedScan, ScanFolder

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            session = uow.session
            session.add(MonitoredAsset(
                hostname="host", user_id=user_id, labels={},
                agent_key_id="k1", agent_key_hash="h", heartbeat_interval_sec=60,
            ))
            session.add(ProgramedScan(
                user_id=user_id, scan_type="nmap", arguments={},
                schedule_type="interval", schedule_config={"every": 1, "unit": "hours"},
            ))
            session.add(ScanFolder(user_id=user_id, name="Carpeta"))
            session.add(AuthorizedTarget(user_id=user_id, target="10.0.0.1"))
            session.add(IrisMailboxConnection(
                user_id=user_id, provider="gmail", account_email="a@b.test",
                scopes="", refresh_token="x",
            ))
            session.add(AegisOrgProfile(user_id=user_id))
            distribution_list = DistributionList(user_id=user_id, name="Lista")
            topic = Topic(title="Phishing")
            session.add_all([distribution_list, topic])
            session.flush()

            document = AegisDocument(
                title="pildora", filename="p.json", status="done", format="json",
                topic_id=topic.id, user_id=user_id,
            )
            session.add(document)
            session.flush()
            session.add(Campaign(
                user_id=user_id, document_id=document.id,
                list_id=distribution_list.id, name="Campanya",
            ))
            session.flush()


def _rows_referencing_user(app, user_id: int) -> dict[str, int]:
    """Filas que todavía apuntan al usuario, tabla a tabla.

    Recorre ``Base.metadata`` buscando toda columna con una clave ajena hacia
    ``User``, en vez de una lista escrita a mano que se quedaría vieja en cuanto
    alguien añadiera una tabla.
    """
    leftovers: dict[str, int] = {}
    with app.app_context():
        session = unit_of_work.get_db_session()
        for table in Base.metadata.tables.values():
            if table.name == "User":
                continue
            for column in table.columns:
                if not any(fk.column.table.name == "User" for fk in column.foreign_keys):
                    continue
                found = session.execute(table.select().where(column == user_id)).fetchall()
                if found:
                    leftovers[f"{table.name}.{column.name}"] = len(found)
    return leftovers


# ------------------------------------------------------------------ el aviso

def test_preview_says_nothing_special_for_a_plain_account(client, regular_user, auth_headers):
    body = client.get("/users/me/deletion-preview",
                      headers=auth_headers(regular_user)).get_json()

    assert body["ownedOrganization"] is None
    assert body["leavesOrganizationId"] is None


def test_preview_warns_the_owner_about_their_members(
    client, app, owner, make_user, auth_headers
):
    """Es el aviso que pediste: al borrar tu cuenta, tu organización desaparece
    y tu gente se queda sin ella."""
    from src.modules.accounts.model import OrganizationMember

    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    for _ in range(3):
        member = make_user()
        with app.app_context():
            with unit_of_work.UnitOfWork() as uow:
                uow.session.add(OrganizationMember(
                    organization_id=organization["id"], user_id=member.id,
                    member_role="member",
                ))
                uow.session.flush()

    body = client.get("/users/me/deletion-preview",
                      headers=auth_headers(owner)).get_json()

    assert body["ownedOrganization"]["name"] == "Acme"
    # Tres, no cuatro: al dueño no se le cuenta entre los que se quedan sin nada.
    assert body["ownedOrganization"]["membersLosingAccess"] == 3


def test_preview_does_not_delete_anything(client, owner, auth_headers):
    client.get("/users/me/deletion-preview", headers=auth_headers(owner))
    assert client.get("/users/me", headers=auth_headers(owner)).status_code == 200


def test_admin_preview_warns_about_the_organization_that_dies_with_the_user(
    client, app, admin_user, owner, make_user, auth_headers
):
    """El mismo aviso, pero para quien da de baja a otro.

    Un administrador que borra al duenyo de una organizacion la disuelve sin
    saberlo si nadie se lo dice.
    """
    from src.modules.accounts.model import OrganizationMember

    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    member = make_user()
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            uow.session.add(OrganizationMember(
                organization_id=organization["id"], user_id=member.id,
                member_role="member",
            ))
            uow.session.flush()

    body = client.get(f"/users/{owner.id}/deletion-preview",
                      headers=auth_headers(admin_user)).get_json()

    assert body["ownedOrganization"]["name"] == "Acme"
    assert body["ownedOrganization"]["membersLosingAccess"] == 1


def test_admin_preview_does_not_delete_anything(client, admin_user, regular_user, auth_headers):
    client.get(f"/users/{regular_user.id}/deletion-preview", headers=auth_headers(admin_user))
    assert client.get("/users/me", headers=auth_headers(regular_user)).status_code == 200


def test_admin_preview_needs_the_same_permission_as_deleting(
    client, admin_user, regular_user, make_user, auth_headers
):
    """El aviso solo lo ve quien puede ejecutar la baja."""
    other_admin = make_user(role="role_admin")

    assert client.get(f"/users/{regular_user.id}/deletion-preview",
                      headers=auth_headers(regular_user)).status_code == 403
    assert client.get(f"/users/{other_admin.id}/deletion-preview",
                      headers=auth_headers(admin_user)).status_code == 403


# ----------------------------------------------------------------- el borrado

def test_deleting_requires_the_password(client, regular_user, auth_headers):
    """La operación más destructiva del producto: un token robado no basta."""
    resp = client.delete("/users/me", headers=auth_headers(regular_user),
                         json={"password": "no-es-la-suya"})
    assert resp.status_code == 401
    assert client.get("/users/me", headers=auth_headers(regular_user)).status_code == 200


def test_deleting_an_account_leaves_no_dangling_reference(
    client, app, make_user, auth_headers
):
    """El test que impide que SQLite nos engañe.

    Se siembra una fila en cada tabla sin cascada y después se recorre el grafo
    real de claves ajenas. Si el barrido se deja una, aquí sale — y en Postgres
    habría sido un 500 al borrar.
    """
    user = make_user()
    _seed_user_data(app, user.id)

    resp = client.delete("/users/me", headers=auth_headers(user),
                         json={"password": PASSWORD})
    assert resp.status_code == 200

    assert _rows_referencing_user(app, user.id) == {}


def test_deleting_an_account_removes_the_user(client, make_user, auth_headers):
    from src.modules.users.repositories import UserRepository

    user = make_user()
    client.delete("/users/me", headers=auth_headers(user), json={"password": PASSWORD})

    with unit_of_work.UnitOfWork() as uow:
        assert UserRepository(uow).get_by_id(user.id) is None


# --------------------------------------------- el duenyo borra: se disuelve

def test_deleting_the_owner_dissolves_the_organization(
    client, app, owner, make_user, auth_headers
):
    """Lo que pediste: la organización desaparece con su dueño."""
    from src.modules.accounts.model import Organization, OrganizationMember

    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    member = make_user()
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            uow.session.add(OrganizationMember(
                organization_id=organization["id"], user_id=member.id, member_role="member",
            ))
            uow.session.flush()

    assert client.delete("/users/me", headers=auth_headers(owner),
                         json={"password": PASSWORD}).status_code == 200

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            assert uow.session.get(Organization, organization["id"]) is None


def test_the_members_survive_the_dissolution(
    client, app, owner, make_user, make_subscription, auth_headers
):
    """Se quedan sin organización, no sin cuenta.

    Conservan su acceso, sus datos y su plan personal — lo único que pierden es
    lo que heredaban. Es la misma regla que cuando el dueño deja de pagar, solo
    que aquí es definitiva.
    """
    from src.modules.accounts.model import OrganizationMember
    from src.modules.accounts.services.limits import LimitKey
    from src.modules.accounts.services.quotas import QuotaManager

    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    member = make_user()
    make_subscription(member, plan_code="bronze", current_period_end=FUTURE)
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            uow.session.add(OrganizationMember(
                organization_id=organization["id"], user_id=member.id, member_role="member",
            ))
            uow.session.flush()

    client.delete("/users/me", headers=auth_headers(owner), json={"password": PASSWORD})

    assert client.get("/users/me", headers=auth_headers(member)).status_code == 200
    mia = client.get("/organizations/mine", headers=auth_headers(member))
    assert mia.get_json()["organization"] is None

    with app.app_context():
        state = QuotaManager().state(member.id, LimitKey.IRIS_ANALYSES)
        assert state.limit == 100          # su Bronze, intacto
        assert state.source == "personal"


def test_deleting_a_member_only_removes_their_membership(
    client, app, owner, make_user, auth_headers
):
    """Al revés que el dueño: la organización sigue en pie."""
    from src.modules.accounts.model import Organization, OrganizationMember

    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    member = make_user()
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            uow.session.add(OrganizationMember(
                organization_id=organization["id"], user_id=member.id, member_role="member",
            ))
            uow.session.flush()

    client.delete("/users/me", headers=auth_headers(member), json={"password": PASSWORD})

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            assert uow.session.get(Organization, organization["id"]) is not None

    members = client.get(f"/organizations/{organization['id']}/members",
                         headers=auth_headers(owner)).get_json()["members"]
    assert [m["userId"] for m in members] == [owner.id]


def test_an_invitation_the_deleted_user_sent_does_not_block_the_delete(
    client, app, owner, regular_user, auth_headers, sent_emails
):
    """``invited_by_user_id`` es NOT NULL: sin barrerla, la fila bloquearía el
    borrado en Postgres."""
    organization = client.post("/organizations", headers=auth_headers(owner),
                               json={"name": "Acme"}).get_json()
    client.post(f"/organizations/{organization['id']}/invitations",
                headers=auth_headers(owner),
                json={"email": f"user{regular_user.id}@ellysia.test"})

    assert client.delete("/users/me", headers=auth_headers(owner),
                         json={"password": PASSWORD}).status_code == 200
    assert _rows_referencing_user(app, owner.id) == {}
