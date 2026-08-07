"""Gestor del catálogo: el equipo rellena los números sin tocar código.

Es lo que convierte `PlanLimit` de "tabla que alguien rellenó a mano en una
migración" en algo editable. Y por eso mismo es el sitio donde más fácil se
mete una errata: casi todos estos tests van de lo que se rechaza.
"""

import pytest

pytestmark = pytest.mark.integration


def _plan_id(client, headers, code: str) -> int:
    plans = client.get("/plans").get_json()["plans"]
    return next(plan["id"] for plan in plans if plan["code"] == code)


# ------------------------------------------------------------------ permisos

@pytest.mark.parametrize("method, path, body", [
    ("post", "/plans", {"code": "nuevo", "name": "Nuevo"}),
    ("put", "/plans/1", {"name": "Otro"}),
    ("put", "/plans/1/limits", {"limits": []}),
    ("delete", "/plans/1", None),
])
def test_the_catalog_is_root_only(client, seeded_plans, admin_user, auth_headers,
                                  method, path, body):
    """Ni siquiera un administrador toca los precios."""
    call = getattr(client, method)
    resp = call(path, headers=auth_headers(admin_user), json=body) if body is not None \
        else call(path, headers=auth_headers(admin_user))
    assert resp.status_code == 403


def test_the_catalog_is_not_public(client, seeded_plans):
    """El cuerpo tiene que ser válido para llegar al 401: en todo el proyecto
    ``@blp.arguments`` envuelve a ``@require_oauth_token``, así que el schema se
    valida antes que la sesión y un cuerpo mal formado da 422 sin mirar quién
    llama."""
    resp = client.post("/plans", json={"code": "nuevo", "name": "Nuevo"})
    assert resp.status_code == 401


# --------------------------------------------------------------------- alta

def test_creating_a_plan(client, seeded_plans, root_user, auth_headers):
    resp = client.post("/plans", headers=auth_headers(root_user), json={
        "code": "platinum", "name": "Platinum", "rank": 9,
        "monthlyPriceCents": 49900, "tagline": "Para quien lo quiere todo",
    })

    assert resp.status_code == 201
    assert resp.get_json()["code"] == "platinum"


def test_a_new_plan_starts_with_no_limits(client, seeded_plans, root_user, auth_headers):
    """Fallo cerrado: un plan a medio configurar no regala nada."""
    client.post("/plans", headers=auth_headers(root_user),
                json={"code": "platinum", "name": "Platinum"})

    plan = next(p for p in client.get("/plans").get_json()["plans"] if p["code"] == "platinum")
    assert plan["limits"]["holder"] == {}


def test_a_duplicate_code_is_rejected(client, seeded_plans, root_user, auth_headers):
    resp = client.post("/plans", headers=auth_headers(root_user),
                       json={"code": "gold", "name": "Otro Gold"})
    assert resp.status_code == 409


# ------------------------------------------------------------------ edición

def test_updating_a_plan(client, seeded_plans, root_user, auth_headers):
    headers = auth_headers(root_user)
    resp = client.put(f"/plans/{seeded_plans['bronze']}", headers=headers,
                      json={"monthlyPriceCents": 3400, "tagline": "Nuevo precio"})

    assert resp.status_code == 200
    assert resp.get_json()["monthlyPriceCents"] == 3400


def test_the_code_cannot_be_changed(client, seeded_plans, root_user, auth_headers):
    """Cambiarlo rompería las asignaciones que lo nombran. El schema lo ignora
    o lo rechaza; lo que no puede es aplicarlo."""
    headers = auth_headers(root_user)
    client.put(f"/plans/{seeded_plans['bronze']}", headers=headers,
               json={"code": "otro-codigo", "name": "Bronze"})

    codes = [plan["code"] for plan in client.get("/plans").get_json()["plans"]]
    assert "bronze" in codes
    assert "otro-codigo" not in codes


def test_hiding_a_plan_takes_it_off_the_price_table(
    client, seeded_plans, root_user, auth_headers
):
    client.put(f"/plans/{seeded_plans['bronze']}", headers=auth_headers(root_user),
               json={"isPublic": False})

    codes = [plan["code"] for plan in client.get("/plans").get_json()["plans"]]
    assert "bronze" not in codes


# -------------------------------------------------------------- plan por defecto

def test_changing_the_default_plan_moves_the_flag(
    client, seeded_plans, root_user, auth_headers
):
    """Un índice único parcial impide que haya dos: quitar y poner tienen que ir
    en la misma transacción o falla."""
    headers = auth_headers(root_user)
    resp = client.put(f"/plans/{seeded_plans['bronze']}/default", headers=headers)

    assert resp.status_code == 200
    plans = {p["code"]: p for p in client.get("/plans").get_json()["plans"]}
    assert plans["bronze"]["isDefault"] is True
    assert plans["freemium"]["isDefault"] is False


# ------------------------------------------------------------------- topes

def test_replacing_the_limits_of_a_plan(client, seeded_plans, root_user, auth_headers):
    headers = auth_headers(root_user)
    resp = client.put(f"/plans/{seeded_plans['bronze']}/limits", headers=headers, json={
        "limits": [
            {"limitKey": "iris.analyses", "scope": "holder", "value": 500},
            {"limitKey": "acheron.vaults", "scope": "member", "value": None},
        ],
    })

    assert resp.status_code == 200
    limits = resp.get_json()["limits"]
    assert limits["holder"]["iris.analyses"]["value"] == 500
    assert limits["member"]["acheron.vaults"]["value"] is None


def test_replacing_really_replaces(client, seeded_plans, root_user, auth_headers):
    """Lo que se ve en el panel es lo que queda: una clave que se quita de la
    lista desaparece de verdad, no se queda con su valor viejo."""
    headers = auth_headers(root_user)
    client.put(f"/plans/{seeded_plans['bronze']}/limits", headers=headers, json={
        "limits": [{"limitKey": "iris.analyses", "scope": "holder", "value": 500}],
    })

    plan = next(p for p in client.get("/plans").get_json()["plans"] if p["code"] == "bronze")
    assert set(plan["limits"]["holder"]) == {"iris.analyses"}


def test_the_period_comes_from_the_catalog_not_the_form(
    client, seeded_plans, root_user, auth_headers
):
    """Si lo eligiera quien rellena, un contador mensual podría acabar
    declarado como existencias y no se reiniciaría nunca."""
    headers = auth_headers(root_user)
    resp = client.put(f"/plans/{seeded_plans['bronze']}/limits", headers=headers, json={
        "limits": [
            {"limitKey": "iris.analyses", "scope": "holder", "value": 10},
            {"limitKey": "acheron.vaults", "scope": "holder", "value": 2},
        ],
    })

    limits = resp.get_json()["limits"]["holder"]
    assert limits["iris.analyses"]["period"] == "month"
    assert limits["acheron.vaults"]["period"] == "stock"


def test_an_unknown_limit_key_is_rejected(client, seeded_plans, root_user, auth_headers):
    """La errata que este endpoint existe para impedir: guardarla crearía una
    fila que nadie consulta y dejaría la característica desactivada."""
    resp = client.put(f"/plans/{seeded_plans['bronze']}/limits",
                      headers=auth_headers(root_user),
                      json={"limits": [{"limitKey": "acheron.vault", "value": 3}]})

    assert resp.status_code == 400
    assert "acheron.vault" in resp.get_json()["error_description"]


def test_a_rejected_limit_set_changes_nothing(client, seeded_plans, root_user, auth_headers):
    """O entra la lista entera o no entra nada: media configuración sería peor
    que ninguna."""
    headers = auth_headers(root_user)
    before = next(p for p in client.get("/plans").get_json()["plans"] if p["code"] == "bronze")

    client.put(f"/plans/{seeded_plans['bronze']}/limits", headers=headers, json={
        "limits": [
            {"limitKey": "iris.analyses", "value": 999},
            {"limitKey": "clave.inventada", "value": 1},
        ],
    })

    after = next(p for p in client.get("/plans").get_json()["plans"] if p["code"] == "bronze")
    assert after["limits"] == before["limits"]


def test_editing_a_limit_takes_effect_immediately(
    client, app, seeded_plans, root_user, regular_user, auth_headers, make_subscription
):
    """El objetivo de toda la fase: cambiar un número en el panel y que corte
    distinto, sin desplegar."""
    from datetime import timedelta

    from src.modules.accounts.services.limits import LimitKey
    from src.modules.accounts.services.quotas import QuotaManager
    from src.modules.shared import utcnow_naive

    make_subscription(regular_user, plan_code="bronze",
                      current_period_end=utcnow_naive() + timedelta(days=30))

    with app.app_context():
        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).limit == 100

    client.put(f"/plans/{seeded_plans['bronze']}/limits", headers=auth_headers(root_user),
               json={"limits": [{"limitKey": "iris.analyses", "value": 7}]})

    with app.app_context():
        assert QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES).limit == 7


# ------------------------------------------------------------------- borrado

def test_deleting_an_unused_plan(client, seeded_plans, root_user, auth_headers):
    headers = auth_headers(root_user)
    created = client.post("/plans", headers=headers,
                          json={"code": "temporal", "name": "Temporal"}).get_json()

    assert client.delete(f"/plans/{created['id']}", headers=headers).status_code == 200


def test_a_plan_someone_has_cannot_be_deleted(
    client, seeded_plans, root_user, regular_user, auth_headers, make_subscription
):
    """Dejar cuentas apuntando a un plan inexistente convertiría cada lectura de
    sus derechos en un error."""
    make_subscription(regular_user, plan_code="gold")
    resp = client.delete(f"/plans/{seeded_plans['gold']}", headers=auth_headers(root_user))

    assert resp.status_code == 409


def test_the_default_plan_cannot_be_deleted(client, seeded_plans, root_user, auth_headers):
    """Sin plan por defecto, cada cuenta sin suscripción daría un 500."""
    resp = client.delete(f"/plans/{seeded_plans['freemium']}", headers=auth_headers(root_user))
    assert resp.status_code == 409


# ------------------------------------------------------- catálogo de claves

def test_the_limit_key_catalog_is_offered_to_the_panel(
    client, seeded_plans, root_user, auth_headers
):
    """Para que el panel las ofrezca en un desplegable en vez de que alguien
    las escriba."""
    body = client.get("/plans/limit-keys", headers=auth_headers(root_user)).get_json()
    keys = {entry["key"]: entry["period"] for entry in body["keys"]}

    assert len(keys) == 15
    assert keys["iris.analyses"] == "month"
    assert keys["acheron.vaults"] == "stock"
