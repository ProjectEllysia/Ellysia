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
    target = make_user(role="role_user")
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
