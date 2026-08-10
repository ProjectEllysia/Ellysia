"""Las seis operaciones que mueven una suscripción.

Es la máquina de estados que el día de mañana moverá la pasarela. Se prueba
entera hoy, sin pasarela, porque root la mueve por el mismo puerto: cuando entre
el cobro, lo único sin probar será el adaptador.
"""

from datetime import timedelta

import pytest

from src.modules.accounts.exceptions import SubscriptionNotFoundError
from src.modules.accounts.managers import SubscriptionManager
from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.integration


NOW = utcnow_naive()
FUTURE = NOW + timedelta(days=30)
PAST = NOW - timedelta(days=1)


def _plan_of(client, user, auth_headers) -> dict:
    return client.get("/plans/me", headers=auth_headers(user)).get_json()


# ------------------------------------------------------------------ activate

def test_activate_creates_the_subscription(app, seeded_plans, regular_user):
    with app.app_context():
        result = SubscriptionManager().activate(regular_user.id, "gold", period_end=FUTURE)

    assert result["status"] == "active"
    assert result["planId"] == seeded_plans["gold"]


def test_activate_is_idempotent(app, seeded_plans, regular_user, client, auth_headers):
    """Escribe estado absoluto, nunca un delta: aplicarla dos veces con el mismo
    evento deja exactamente lo mismo."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        manager.activate(regular_user.id, "gold", period_end=FUTURE)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["plan"]["code"] == "gold"
    assert body["isEffective"] is True


def test_upgrading_does_not_reset_the_counters(app, seeded_plans, regular_user):
    """40 gastados de 100 pasan a ser 40 de 400, no 0 de 400. Pagar más sube el
    techo; no borra el historial."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "bronze", period_end=FUTURE)
        QuotaManager().consume(regular_user.id, LimitKey.IRIS_ANALYSES, amount=40)

        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        state = QuotaManager().state(regular_user.id, LimitKey.IRIS_ANALYSES)

    assert state.used == 40
    assert state.limit is None      # gold: ilimitado


def test_downgrading_leaves_the_key_in_exceeded_mode(
    app, seeded_plans, regular_user, client, auth_headers
):
    """Bajar de plan no devuelve nada ni borra nada: lo que estaba por encima
    del tope nuevo queda en solo lectura hasta volver por debajo."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        QuotaManager().consume(regular_user.id, LimitKey.IRIS_ANALYSES, amount=150)
        manager.activate(regular_user.id, "bronze", period_end=FUTURE)

    usage = client.get("/plans/me/usage", headers=auth_headers(regular_user)).get_json()
    entry = usage["usage"]["iris.analyses"]

    assert entry["used"] == 150
    assert entry["value"] == 100
    assert entry["exceeded"] is True


# --------------------------------------------------------------- trial

def test_a_trial_grants_the_same_as_a_paid_plan(
    app, seeded_plans, regular_user, client, auth_headers
):
    """Lo único que cambia es lo que dice la interfaz."""
    with app.app_context():
        SubscriptionManager().start_trial(regular_user.id, "gold", ends_at=FUTURE)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["status"] == "trialing"
    assert body["isEffective"] is True
    assert body["plan"]["code"] == "gold"


# ------------------------------------------------------------------ impago

def test_past_due_keeps_the_plan_during_the_grace_window(
    app, seeded_plans, regular_user, client, auth_headers
):
    """Un impago no corta. Una tarjeta caducada es más frecuente que un moroso."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=PAST)
        manager.mark_past_due(regular_user.id, grace_until=FUTURE)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["status"] == "past_due"
    assert body["isEffective"] is True
    assert body["plan"]["code"] == "gold"


def test_resume_clears_the_grace_window(app, seeded_plans, regular_user, client, auth_headers):
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        manager.mark_past_due(regular_user.id, grace_until=FUTURE)
        manager.resume(regular_user.id)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["status"] == "active"
    assert body["graceUntil"] is None


# -------------------------------------------------------------------- bajas

def test_cancel_does_not_cut(app, seeded_plans, regular_user, client, auth_headers):
    """Cancelar significa "no se renueva", no "córtame ahora". Hasta el final
    del periodo el cliente disfruta lo que ya pagó."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        manager.cancel(regular_user.id)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["status"] == "canceled"
    assert body["cancelAtPeriodEnd"] is True
    assert body["isEffective"] is True
    assert body["plan"]["code"] == "gold"


def test_an_immediate_cancel_does_cut(app, seeded_plans, regular_user, client, auth_headers):
    """Para devoluciones y contracargos: ahí no queda periodo que respetar."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        manager.cancel(regular_user.id, immediate=True)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["isEffective"] is False
    assert body["plan"]["code"] == "freemium"


def test_expire_falls_back_to_the_default_plan(
    app, seeded_plans, regular_user, client, auth_headers
):
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE)
        manager.expire(regular_user.id)

    body = _plan_of(client, regular_user, auth_headers)
    assert body["plan"]["code"] == "freemium"
    assert body["isEffective"] is False


def test_moving_a_subscription_that_does_not_exist(app, seeded_plans, regular_user):
    """Cancelar lo que nadie contrató no es "está en el plan gratuito": es que
    no hay nada que mover."""
    with app.app_context():
        with pytest.raises(SubscriptionNotFoundError):
            SubscriptionManager().cancel(regular_user.id)


# ------------------------------------------------------------- idempotencia

def test_an_older_event_is_ignored(app, seeded_plans, regular_user, client, auth_headers):
    """Toda pasarela reintenta y entrega desordenado. Sin este descarte, una
    renovación que llega DESPUÉS de un impago dejaría la suscripción marcada
    como impagada para siempre."""
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE, event_at=NOW)
        # Un evento anterior, entregado tarde.
        manager.mark_past_due(
            regular_user.id, grace_until=FUTURE, event_at=NOW - timedelta(hours=1),
        )

    body = _plan_of(client, regular_user, auth_headers)
    assert body["status"] == "active"      # el impago viejo no se aplicó


def test_a_newer_event_is_applied(app, seeded_plans, regular_user, client, auth_headers):
    with app.app_context():
        manager = SubscriptionManager()
        manager.activate(regular_user.id, "gold", period_end=FUTURE, event_at=NOW)
        manager.mark_past_due(
            regular_user.id, grace_until=FUTURE, event_at=NOW + timedelta(hours=1),
        )

    assert _plan_of(client, regular_user, auth_headers)["status"] == "past_due"


# ------------------------------------------------------- el panel de root

def test_the_admin_endpoint_drives_the_six_operations(
    client, seeded_plans, root_user, regular_user, auth_headers
):
    """El driver manual del mismo puerto que usará la pasarela."""
    headers = auth_headers(root_user)
    url = f"/plans/subscriptions/{regular_user.id}"

    activated = client.put(url, headers=headers, json={
        "operation": "activate", "planCode": "gold",
        "periodEnd": FUTURE.isoformat(), "organizationEnabled": True,
    })
    assert activated.status_code == 200
    assert activated.get_json()["status"] == "active"

    past_due = client.put(url, headers=headers, json={
        "operation": "mark_past_due", "graceUntil": FUTURE.isoformat(),
    })
    assert past_due.get_json()["status"] == "past_due"

    assert client.put(url, headers=headers, json={"operation": "resume"}).get_json()["status"] == "active"
    assert client.put(url, headers=headers, json={"operation": "cancel"}).get_json()["status"] == "canceled"
    assert client.put(url, headers=headers, json={"operation": "expire"}).get_json()["status"] == "canceled"


def test_the_lifecycle_endpoint_is_root_only(client, seeded_plans, admin_user, auth_headers):
    """Ni siquiera un administrador mueve dinero."""
    resp = client.put(f"/plans/subscriptions/{admin_user.id}", headers=auth_headers(admin_user),
                      json={"operation": "cancel"})
    assert resp.status_code == 403


def test_an_operation_without_its_argument_is_a_400(
    client, seeded_plans, root_user, regular_user, auth_headers
):
    """``mark_past_due`` sin ``graceUntil`` no es una cortesía de cero
    segundos: es una llamada mal hecha."""
    resp = client.put(f"/plans/subscriptions/{regular_user.id}",
                      headers=auth_headers(root_user), json={"operation": "mark_past_due"})
    assert resp.status_code == 400
