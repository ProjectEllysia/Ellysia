"""Tests de integración del catálogo de planes (módulo accounts)."""

from datetime import timedelta

import pytest
import sqlalchemy as sa

from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


NOW = utcnow_naive()
FUTURE = NOW + timedelta(days=10)
PAST = NOW - timedelta(days=10)


# ------------------------------------------------------------------ GET /plans

def test_get_plans_is_public(client, seeded_plans):
    """Es la tabla de precios: la ve quien todavía no tiene cuenta."""
    assert client.get("/plans").status_code == 200


def test_get_plans_returns_catalog_sorted_by_rank(client, seeded_plans):
    plans = client.get("/plans").get_json()["plans"]
    assert [plan["code"] for plan in plans] == ["freemium", "bronze", "gold"]


def test_get_plans_hides_non_public_plans(client, seeded_plans):
    """Los planes a medida existen en el catálogo pero no se anuncian."""
    codes = [plan["code"] for plan in client.get("/plans").get_json()["plans"]]
    assert "custom" not in codes


def test_get_plans_exposes_both_scopes(client, seeded_plans):
    """holder y member aparecen siempre, aunque uno venga vacío: así el cliente
    no tiene que distinguir "sin límites de miembro" de "campo ausente"."""
    plans = {plan["code"]: plan for plan in client.get("/plans").get_json()["plans"]}
    assert plans["freemium"]["limits"]["member"] == {}
    assert plans["gold"]["limits"]["member"]["acheron.vaults"]["value"] is None


def test_get_plans_null_limit_means_unlimited(client, seeded_plans):
    """Ilimitado viaja como null, no como 0 ni como campo ausente: son tres
    cosas distintas y el cliente las pinta distinto."""
    plans = {plan["code"]: plan for plan in client.get("/plans").get_json()["plans"]}
    gold = plans["gold"]["limits"]["holder"]
    freemium = plans["freemium"]["limits"]["holder"]

    assert gold["iris.analyses"]["value"] is None
    assert freemium["iris.analyses"]["value"] == 10
    assert freemium["themis.thirdparty.scans"]["value"] == 0


def test_get_plans_reports_the_period_of_each_limit(client, seeded_plans):
    plans = {plan["code"]: plan for plan in client.get("/plans").get_json()["plans"]}
    holder = plans["bronze"]["limits"]["holder"]
    assert holder["iris.analyses"]["period"] == "month"
    assert holder["acheron.vaults"]["period"] == "stock"


# --------------------------------------------------------------- GET /plans/me

def test_get_plans_me_requires_authentication(client, seeded_plans):
    assert client.get("/plans/me").status_code == 401


def test_without_subscription_falls_back_to_the_default_plan(
    client, seeded_plans, regular_user, auth_headers
):
    """No tener fila en Subscription es lo normal, no un error: significa plan
    por defecto. Por eso no hace falta crearla en el alta ni rellenarla con un
    backfill."""
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()

    assert body["plan"]["code"] == "freemium"
    assert body["source"] == "default"
    assert body["status"] is None
    assert body["isEffective"] is False
    assert body["organizationEnabled"] is False


def test_active_subscription_returns_its_plan(
    client, seeded_plans, regular_user, auth_headers, make_subscription
):
    make_subscription(regular_user, plan_code="gold", current_period_end=FUTURE)
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()

    assert body["plan"]["code"] == "gold"
    assert body["source"] == "personal"
    assert body["isEffective"] is True
    assert body["limits"]["iris.analyses"]["value"] is None


def test_expired_subscription_degrades_but_keeps_explaining_itself(
    client, seeded_plans, regular_user, auth_headers, make_subscription
):
    """Los topes que se aplican son los del plan por defecto, pero el estado y
    la fecha de la suscripción siguen viajando: sin ellos la interfaz solo
    podría degradar en silencio, en vez de decir "tu plan terminó el día 27"."""
    make_subscription(regular_user, plan_code="gold", current_period_end=PAST)
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()

    assert body["plan"]["code"] == "freemium"
    assert body["isEffective"] is False
    assert body["status"] == "active"
    assert body["currentPeriodEnd"] is not None
    assert body["limits"]["iris.analyses"]["value"] == 10


def test_canceled_within_period_keeps_the_paid_plan(
    client, seeded_plans, regular_user, auth_headers, make_subscription
):
    """Cancelar no corta: hasta el final del periodo se disfruta lo pagado."""
    make_subscription(
        regular_user, plan_code="gold", status="canceled",
        current_period_end=FUTURE, cancel_at_period_end=True,
    )
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()

    assert body["plan"]["code"] == "gold"
    assert body["isEffective"] is True
    assert body["cancelAtPeriodEnd"] is True


def test_past_due_within_grace_keeps_the_plan(
    client, seeded_plans, regular_user, auth_headers, make_subscription
):
    """Un impago abre una ventana de cortesía, no un corte."""
    make_subscription(
        regular_user, plan_code="bronze", status="past_due",
        current_period_end=PAST, grace_until=FUTURE,
    )
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()

    assert body["plan"]["code"] == "bronze"
    assert body["isEffective"] is True
    assert body["graceUntil"] is not None


def test_limits_carry_no_usage_counters_yet(
    client, seeded_plans, regular_user, auth_headers
):
    """/plans/me solo dice cuánto incluye el plan, nunca cuánto se lleva
    gastado -- eso vive aparte, en /plans/me/usage. Que "used" no aparezca
    aquí es a propósito, no un olvido."""
    body = client.get("/plans/me", headers=auth_headers(regular_user)).get_json()
    for limit in body["limits"].values():
        assert set(limit) == {"value", "period"}


# ------------------------------------------------------------------ invariantes

def test_a_second_default_plan_is_rejected_by_the_database(app, seeded_plans):
    """"Exactamente un plan por defecto" lo impone un índice único parcial, no
    una comprobación en Python. Este test verifica además que el índice se emite
    también en SQLite, donde corre la suite."""
    from src.modules.accounts.model import Plan
    from src.modules.infrastructure import unit_of_work

    with app.app_context():
        with pytest.raises(sa.exc.IntegrityError):
            with unit_of_work.UnitOfWork() as uow:
                uow.session.add(Plan(
                    code="otro", name="Otro", rank=5,
                    monthly_price_cents=0, org_addon_price_cents=0,
                    currency="EUR", is_public=True, is_default=True,
                ))
                uow.session.flush()
