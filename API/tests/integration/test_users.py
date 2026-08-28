"""Tests de integración de la gestión de usuarios y perfil."""

import pytest

pytestmark = pytest.mark.integration


def test_me_requires_authentication(client):
    assert client.get("/users/me").status_code == 401


def test_me_returns_current_profile(client, regular_user, auth_headers):
    resp = client.get("/users/me", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == regular_user.username
    assert body["role"] == "role_user"


def test_update_own_profile(client, regular_user, auth_headers):
    resp = client.put("/users/me", headers=auth_headers(regular_user), json={
        "first_name": "Nuevo",
        "last_name": "Nombre",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["first_name"] == "Nuevo"
    assert body["last_name"] == "Nombre"


def test_change_password(client, regular_user, auth_headers):
    resp = client.put("/users/change-password", headers=auth_headers(regular_user), json={
        "currentPassword": regular_user.password,
        "newPassword": "NuevaP@ss1",
    })
    assert resp.status_code == 200

    # La nueva contraseña funciona en un nuevo login.
    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": "NuevaP@ss1",
    })
    assert login.status_code == 200


def test_change_password_rejects_wrong_current_password(client, regular_user, auth_headers):
    # S11: el servidor reverifica currentPassword, no solo el cliente.
    resp = client.put("/users/change-password", headers=auth_headers(regular_user), json={
        "currentPassword": "esto-no-es-la-contrasena-actual",
        "newPassword": "NuevaP@ss1",
    })
    assert resp.status_code == 401

    # La contraseña original sigue funcionando: el cambio no se aplicó.
    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    })
    assert login.status_code == 200


def test_signup_requires_admin_role(client, regular_user, auth_headers):
    resp = client.post("/users/sign-up", headers=auth_headers(regular_user), json={
        "username": "nuevo",
        "email": "nuevo@x.com",
        "first_name": "N",
        "last_name": "U",
        "password": "secret",
    })
    assert resp.status_code == 403


def test_admin_can_create_user(client, admin_user, auth_headers):
    resp = client.post("/users/sign-up", headers=auth_headers(admin_user), json={
        "username": "creado_por_admin",
        "email": "cba@x.com",
        "first_name": "C",
        "last_name": "A",
        "password": "secret",
        "role": "role_user",
    })
    assert resp.status_code == 201
    assert resp.get_json()["username"] == "creado_por_admin"


def test_list_users_requires_admin(client, regular_user, auth_headers):
    assert client.get("/users", headers=auth_headers(regular_user)).status_code == 403


def test_admin_lists_users(client, admin_user, auth_headers):
    resp = client.get("/users", headers=auth_headers(admin_user))
    assert resp.status_code == 200
    usernames = [u["username"] for u in resp.get_json()]
    assert admin_user.username in usernames


def test_admin_manages_user_attributes(client, admin_user, make_user, auth_headers):
    """Alta y baja de un atributo, ida y vuelta.

    El objetivo se crea sin ningún atributo para que las dos mitades midan algo:
    sobre un usuario con el conjunto por defecto, el PUT sería un no-op.
    """
    target = make_user(role="role_user", attributes=[])
    headers = auth_headers(admin_user)

    add = client.put(f"/users/{target.id}/attributes", headers=headers, json={
        "attributes": ["themis_create"],
    })
    assert add.status_code == 200

    listed = client.get(f"/users/{target.id}/attributes", headers=headers)
    assert listed.status_code == 200
    assert "themis_create" in listed.get_json()["attributes"]

    removed = client.delete(f"/users/{target.id}/attributes", headers=headers, json={
        "attributes": ["themis_create"],
    })
    assert removed.status_code == 200


def test_admin_can_actually_revoke_an_attribute(client, admin_user, regular_user, auth_headers):
    """Quitar un atributo tiene efecto real, no solo un 200.

    Antes de vaciar el baseline de Role.USER esto era imposible: themis_read lo
    concedía el rol, `require_attributes` calculaba la unión y borrar la fila no
    cambiaba nada. Con el baseline vacío, retirar el permiso se nota.
    """
    headers = auth_headers(admin_user)

    removed = client.delete(f"/users/{regular_user.id}/attributes", headers=headers, json={
        "attributes": ["themis_read"],
    })
    assert removed.status_code == 200

    listed = client.get(f"/users/{regular_user.id}/attributes", headers=headers)
    assert "themis_read" not in listed.get_json()["attributes"]

    denied = client.get("/themis/results", headers=auth_headers(regular_user))
    assert denied.status_code == 403


def test_role_user_cannot_grant_attributes_to_itself(client, regular_user, auth_headers):
    """Un usuario normal no puede autoconcederse permisos.

    Hoy lo tapa `require_role(Role.ADMIN)` en el endpoint. Cuando la fase 5 lo
    retire para que el dueño de una organización pueda gestionar a los suyos, la
    única barrera será `can_manage_user` — que empieza con
    `if actor_id == target_id: return True` y convertiría esta llamada en una
    escalada de privilegios. Este test es el que lo impedirá.
    """
    resp = client.put(f"/users/{regular_user.id}/attributes",
                      headers=auth_headers(regular_user),
                      json={"attributes": ["themis_create"]})
    assert resp.status_code == 403


def test_admin_deletes_a_user(client, admin_user, make_user, auth_headers):
    """La baja administrativa borra de verdad: el usuario deja de estar en la lista."""
    target = make_user(role="role_user")
    headers = auth_headers(admin_user)

    resp = client.delete(f"/users/{target.id}", headers=headers)
    assert resp.status_code == 200

    listed = client.get("/users", headers=headers)
    assert target.username not in [u["username"] for u in listed.get_json()]


def test_delete_user_requires_admin(client, regular_user, make_user, auth_headers):
    target = make_user(role="role_user")
    resp = client.delete(f"/users/{target.id}", headers=auth_headers(regular_user))
    assert resp.status_code == 403


def test_admin_cannot_delete_another_admin(client, admin_user, make_user, auth_headers):
    """La jerarquia de `can_administer_user`: un admin solo llega a role_user.

    Sin esta comprobacion, `require_role(Role.ADMIN)` dejaria que cualquier
    administrador se quitase de encima a sus pares y al root.
    """
    other_admin = make_user(role="role_admin")
    root = make_user(role="role_root")
    headers = auth_headers(admin_user)

    assert client.delete(f"/users/{other_admin.id}", headers=headers).status_code == 403
    assert client.delete(f"/users/{root.id}", headers=headers).status_code == 403


def test_root_cannot_delete_itself_from_the_admin_panel(client, root_user, auth_headers):
    """Auto-borrado cortado a mano.

    `can_administer_user` se lo permite al root a proposito (lo necesita para
    sus propios atributos), asi que sin este corte el root se quedaria sin
    sistema de un clic. Para darse de baja esta DELETE /users/me, que
    re-verifica la contrasenya.
    """
    resp = client.delete(f"/users/{root_user.id}", headers=auth_headers(root_user))
    assert resp.status_code == 400


def test_root_deletes_an_admin(client, root_user, make_user, auth_headers):
    target = make_user(role="role_admin")
    resp = client.delete(f"/users/{target.id}", headers=auth_headers(root_user))
    assert resp.status_code == 200
