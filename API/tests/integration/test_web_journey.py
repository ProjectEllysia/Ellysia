"""El recorrido completo que hace alguien desde la interfaz web.

Los tests del resto de ficheros prueban cada pieza por separado. Este prueba la
**secuencia**, que es donde aparecieron los fallos reales: registrarse, que root
te asigne un plan con organización, crear la organización e invitar a alguien.
Cada paso usa el mismo endpoint y el mismo cuerpo que manda el navegador.
"""

from datetime import timedelta
from unittest import mock

import pytest

from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


FUTURE = (utcnow_naive() + timedelta(days=30)).isoformat()


@pytest.fixture()
def sent_emails():
    mailer = mock.Mock()
    with mock.patch("src.modules.users.managers.build_mailer", return_value=mailer), \
         mock.patch("src.modules.accounts.managers.invitations.build_mailer", return_value=mailer):
        yield mailer.send.call_args_list


def _link_token(sent_emails) -> str:
    """Saca el token del enlace del último correo, como haría quien lo pulsa."""
    from urllib.parse import parse_qs, urlparse

    assert sent_emails, "no se envio ningun correo"
    cuerpo = sent_emails[-1].args[0].text_body
    url = next(t for t in cuerpo.split() if t.startswith("http") and "token=" in t)
    return parse_qs(urlparse(url).query)["token"][0]


def _token(client, username, password="Secret123!"):
    resp = client.post("/oauth/token", json={
        "grantType": "password", "username": username, "password": password,
    })
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


def test_the_whole_journey_from_the_web(client, seeded_plans, root_user, auth_headers, sent_emails):
    root = auth_headers(root_user)

    # 1. Alguien se registra desde el modal de acceso.
    registro = client.post("/users/register", json={
        "username": "responsable", "email": "responsable@empresa.test",
        "first_name": "Marta", "last_name": "Ruiz", "password": "Secret123!",
    })
    assert registro.status_code == 201, registro.get_json()
    user_id = registro.get_json()["userId"]

    # 2. Entra, y arranca en el plan por defecto sin haber tocado nada.
    suyo = _token(client, "responsable")
    plan = client.get("/plans/me", headers=suyo).get_json()
    assert plan["plan"]["code"] == "freemium"
    assert plan["organizationEnabled"] is False

    # Y su perfil dice que está pendiente de confirmar, que es lo que la
    # interfaz necesita para avisarle en vez de dejarle chocar con un 403.
    perfil = client.get("/users/me", headers=suyo).get_json()
    assert perfil["emailVerified"] is False

    # 3. Pulsa el enlace del correo. Sin esto no puede consumir nada — una
    #    cuenta sin confirmar creando organizaciones e invitando gente sería
    #    un amplificador de correo no deseado.
    verificado = client.post("/users/verify-email", json={"token": _link_token(sent_emails)})
    assert verificado.status_code == 200, verificado.get_json()
    assert client.get("/users/me", headers=suyo).get_json()["emailVerified"] is True

    # 4. Root ve el catálogo COMPLETO en el gestor y le asigna Gold con
    #    organización — el paso que antes solo se podía hacer con curl.
    catalogo = client.get("/plans/all", headers=root).get_json()["plans"]
    assert "gold" in [p["code"] for p in catalogo]

    asignada = client.put(f"/plans/subscriptions/{user_id}", headers=root, json={
        "operation": "activate", "planCode": "gold",
        "periodEnd": FUTURE, "organizationEnabled": True,
    })
    assert asignada.status_code == 200, asignada.get_json()

    # 5. Lo nota en la siguiente petición: el plan no viaja en el token.
    plan = client.get("/plans/me", headers=suyo).get_json()
    assert plan["plan"]["code"] == "gold"
    assert plan["organizationEnabled"] is True

    # 6. Crea su organización e invita a alguien.
    organizacion = client.post("/organizations", headers=suyo, json={"name": "Acme"})
    assert organizacion.status_code == 201, organizacion.get_json()

    invitacion = client.post(
        f"/organizations/{organizacion.get_json()['id']}/invitations",
        headers=suyo, json={"email": "empleado@empresa.test"},
    )
    assert invitacion.status_code == 201, invitacion.get_json()

    # 7. El empleado no tenía cuenta: se le creó y entró directo.
    miembros = client.get(
        f"/organizations/{organizacion.get_json()['id']}/members", headers=suyo,
    ).get_json()["members"]
    assert len(miembros) == 2

    # 8. Y el consumo se puede consultar desde "Mi plan".
    uso = client.get("/plans/me/usage", headers=suyo).get_json()
    assert uso["planCode"] == "gold"
    assert "iris.analyses" in uso["usage"]


def test_a_bad_registration_says_which_field_is_wrong(client, seeded_plans):
    """El fallo que dejaba a ciegas: un 422 sin `error_description`.

    El cuerpo tiene que traer `errors.json` con el campo y el motivo, porque es
    lo único que el cliente puede convertir en un mensaje útil.
    """
    resp = client.post("/users/register", json={
        "username": "ab", "email": "no-es-un-correo",
        "first_name": "A", "last_name": "B", "password": "corta",
    })

    assert resp.status_code == 422
    problemas = resp.get_json()["errors"]["json"]
    assert set(problemas) == {"username", "email", "password"}


def test_root_can_read_a_subscription_that_does_not_exist_yet(
    client, seeded_plans, root_user, regular_user, auth_headers
):
    """El gestor pregunta por la suscripción nada más elegir una cuenta. Sin
    fila es un 404, y es un estado normal — la cuenta está en el plan por
    defecto — no un error que deba romper la pantalla."""
    resp = client.get(f"/plans/subscriptions/{regular_user.id}", headers=auth_headers(root_user))
    assert resp.status_code == 404
