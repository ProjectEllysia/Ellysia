"""Motor de cuotas: consumo, corte y el 402 que ve el cliente.

Estos tests necesitan base de datos porque lo que se prueba es precisamente el
contador y el conteo de la tabla real — un motor de cuotas con la base de datos
mockeada no prueba nada de lo que puede fallar.
"""

import pytest

from src.modules.accounts.exceptions import PlanFeatureDisabledError, QuotaExceededError
from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------ el contador

def test_consume_increments_until_the_limit_and_then_cuts(
    app, regular_user, set_plan_limits
):
    set_plan_limits({LimitKey.AI_REQUESTS: 2})

    with app.app_context():
        manager = QuotaManager()
        manager.consume(regular_user.id, LimitKey.AI_REQUESTS)
        manager.consume(regular_user.id, LimitKey.AI_REQUESTS)

        with pytest.raises(QuotaExceededError):
            manager.consume(regular_user.id, LimitKey.AI_REQUESTS)

        assert manager.state(regular_user.id, LimitKey.AI_REQUESTS).used == 2


def test_a_rejected_consume_does_not_count(app, regular_user, set_plan_limits):
    """El UPDATE condicional o incrementa o no hace nada: no hay estado a medias.

    Si el contador subiera igualmente al rechazar, el usuario que reintenta se
    hundiría más en el pozo cada vez.
    """
    set_plan_limits({LimitKey.AI_REQUESTS: 1})

    with app.app_context():
        manager = QuotaManager()
        manager.consume(regular_user.id, LimitKey.AI_REQUESTS)
        for _ in range(3):
            with pytest.raises(QuotaExceededError):
                manager.consume(regular_user.id, LimitKey.AI_REQUESTS)

        assert manager.state(regular_user.id, LimitKey.AI_REQUESTS).used == 1


def test_a_limit_of_zero_is_a_feature_not_a_quota(app, regular_user, set_plan_limits):
    """Tope 0 y tope agotado son 402 los dos, pero no significan lo mismo: uno
    se arregla mejorando de plan y el otro esperando al mes que viene."""
    set_plan_limits({LimitKey.AI_REQUESTS: 0})

    with app.app_context():
        with pytest.raises(PlanFeatureDisabledError):
            QuotaManager().consume(regular_user.id, LimitKey.AI_REQUESTS)


def test_unlimited_never_cuts_but_still_counts(app, regular_user, set_plan_limits):
    """Ilimitado sigue apuntando el consumo: sin eso, el dueño de una
    organización no podría ver quién se está comiendo el presupuesto de IA."""
    set_plan_limits({LimitKey.AI_REQUESTS: None})

    with app.app_context():
        manager = QuotaManager()
        for _ in range(5):
            manager.consume(regular_user.id, LimitKey.AI_REQUESTS)

        state = manager.state(regular_user.id, LimitKey.AI_REQUESTS)
        assert state.is_unlimited is True
        assert state.used == 5
        assert state.remaining is None


def test_consume_accepts_an_amount(app, regular_user, set_plan_limits):
    set_plan_limits({LimitKey.AI_REQUESTS: 10})

    with app.app_context():
        QuotaManager().consume(regular_user.id, LimitKey.AI_REQUESTS, amount=4)
        assert QuotaManager().state(regular_user.id, LimitKey.AI_REQUESTS).used == 4


def test_quotas_are_per_user(app, make_user, set_plan_limits):
    """Dos usuarios con el mismo plan no comparten bolsa. La compartirán los
    miembros de una misma organización, y eso llega en la fase 5."""
    set_plan_limits({LimitKey.AI_REQUESTS: 1})
    first, second = make_user(), make_user()

    with app.app_context():
        QuotaManager().consume(first.id, LimitKey.AI_REQUESTS)
        QuotaManager().consume(second.id, LimitKey.AI_REQUESTS)  # no debe cortar

        with pytest.raises(QuotaExceededError):
            QuotaManager().consume(first.id, LimitKey.AI_REQUESTS)


# --------------------------------------------------------------- existencias

def test_stock_counts_the_real_table_so_deleting_frees_room(
    client, app, regular_user, auth_headers, set_plan_limits
):
    """La diferencia entre existencias y consumo, en un test.

    Un contador de existencias se desincronizaría en el primer borrado: diría 2
    cuando en la tabla queda 1. Como se cuenta la tabla real, borrar un activo
    devuelve el hueco de verdad.
    """
    set_plan_limits({LimitKey.HYGEIA_ASSETS: 1})
    headers = auth_headers(regular_user)

    created = client.post("/hygeia/assets", headers=headers,
                          json={"hostname": "host-1", "os": "linux", "labels": {}})
    assert created.status_code == 201
    asset_id = created.get_json()["asset"]["id"]

    blocked = client.post("/hygeia/assets", headers=headers,
                          json={"hostname": "host-2", "os": "linux", "labels": {}})
    assert blocked.status_code == 402

    assert client.delete(f"/hygeia/assets/{asset_id}", headers=headers).status_code == 200

    again = client.post("/hygeia/assets", headers=headers,
                        json={"hostname": "host-3", "os": "linux", "labels": {}})
    assert again.status_code == 201


def test_stock_key_without_counter_is_a_programming_error(app, regular_user, set_plan_limits):
    """Exigir una clave de existencias sin contador registrado no es culpa del
    usuario, y no debe salir como un 402 que le invite a pagar."""
    set_plan_limits({LimitKey.ACHERON_VAULTS: 1})

    with app.app_context():
        with pytest.raises(NotImplementedError):
            QuotaManager().consume(regular_user.id, LimitKey.ACHERON_VAULTS)


# --------------------------------------------------------------- el 402 por HTTP

def test_the_402_carries_the_limit_in_its_body(
    client, app, regular_user, auth_headers, set_plan_limits
):
    """El cuerpo del 402 es contrato, no diagnóstico: sin el tope y el consumo,
    el cliente solo puede decir "error 402"."""
    set_plan_limits({LimitKey.HYGEIA_ASSETS: 0})

    resp = client.post("/hygeia/assets", headers=auth_headers(regular_user),
                       json={"hostname": "host-1", "os": "linux", "labels": {}})

    assert resp.status_code == 402
    body = resp.get_json()
    assert body["code"] == 1902           # PLAN_FEATURE_NOT_INCLUDED
    assert body["details"]["limitKey"] == "hygeia.assets"
    assert body["details"]["value"] == 0


def test_the_402_of_an_exhausted_quota_says_when_it_renews(
    client, app, regular_user, auth_headers, set_plan_limits
):
    set_plan_limits({LimitKey.HYGEIA_ASSETS: 1})
    headers = auth_headers(regular_user)

    client.post("/hygeia/assets", headers=headers,
                json={"hostname": "host-1", "os": "linux", "labels": {}})
    resp = client.post("/hygeia/assets", headers=headers,
                       json={"hostname": "host-2", "os": "linux", "labels": {}})

    assert resp.status_code == 402
    body = resp.get_json()
    assert body["code"] == 1901           # PLAN_LIMIT_REACHED
    assert body["details"]["used"] == 1
    assert body["details"]["value"] == 1


def test_a_plan_cut_is_not_an_abac_cut(
    client, app, stripped_user, regular_user, auth_headers, set_plan_limits
):
    """402 y 403 tienen que seguir siendo distinguibles: uno se arregla pagando
    y el otro pidiéndole el permiso a un administrador."""
    set_plan_limits({LimitKey.HYGEIA_ASSETS: 0})
    payload = {"hostname": "host-1", "os": "linux", "labels": {}}

    sin_permiso = client.post("/hygeia/assets", headers=auth_headers(stripped_user), json=payload)
    sin_plan = client.post("/hygeia/assets", headers=auth_headers(regular_user), json=payload)

    assert sin_permiso.status_code == 403
    assert sin_plan.status_code == 402


# -------------------------------------------------- el corte vive en el manager

def test_lybra_is_cut_inside_run_scan_not_at_the_endpoint(
    app, regular_user, set_plan_limits
):
    """Se llama al manager directamente, sin pasar por HTTP.

    Es la comprobación que importa: por ``run_scan`` entran también el flujo
    programado (``scheduling.py`` lo invoca sin endpoint de por medio) y la
    puerta de Hygeia. Una cuota que viviera en el decorador del endpoint la
    esquivarían los dos, igual que en su día pasó con la validación anti-SSRF.
    """
    from src.modules.features.themis.managers.lybra.engine import LybraEngineManager

    set_plan_limits({LimitKey.THEMIS_LYBRA_SCANS: 0})

    with app.app_context():
        with pytest.raises(PlanFeatureDisabledError):
            LybraEngineManager().run_scan(user_id=regular_user.id, target="scanme.example.com")


def test_a_cut_lybra_scan_never_reaches_the_queue(app, regular_user, set_plan_limits):
    """El corte va antes de encolar: si fuera después, la cuota diría que no y
    el worker haría el trabajo igualmente."""
    from unittest import mock

    from src.modules.features.themis.managers.lybra.engine import LybraEngineManager

    set_plan_limits({LimitKey.THEMIS_LYBRA_SCANS: 0})

    with app.app_context():
        manager = LybraEngineManager()
        with mock.patch.object(manager, "_task_queue") as queue:
            with pytest.raises(PlanFeatureDisabledError):
                manager.run_scan(user_id=regular_user.id, target="scanme.example.com")
            queue.submit.assert_not_called()


# ------------------------------------------------------------ GET /plans/me/usage

def test_usage_endpoint_requires_authentication(client):
    assert client.get("/plans/me/usage").status_code == 401


def test_usage_reports_what_has_been_spent(
    client, app, regular_user, auth_headers, set_plan_limits
):
    set_plan_limits({LimitKey.AI_REQUESTS: 10})
    with app.app_context():
        QuotaManager().consume(regular_user.id, LimitKey.AI_REQUESTS, amount=3)

    body = client.get("/plans/me/usage", headers=auth_headers(regular_user)).get_json()
    entry = body["usage"]["ai.requests"]

    assert entry["used"] == 3
    assert entry["value"] == 10
    assert entry["exceeded"] is False
    assert entry["resetsAt"] is not None


def test_usage_survives_keys_without_a_counter(
    client, regular_user, auth_headers
):
    """Las claves de existencias que todavía no saben contarse llegan con
    ``used: null``, que no es lo mismo que cero — y sobre todo, no tumban la
    vista entera."""
    body = client.get("/plans/me/usage", headers=auth_headers(regular_user)).get_json()

    assert body["usage"]["acheron.vaults"]["used"] is None
    assert body["usage"]["hygeia.assets"]["used"] == 0


def test_usage_flags_a_key_over_its_limit(
    client, app, regular_user, auth_headers, set_plan_limits
):
    """Modo excedido: pasa al bajar de plan sin haber hecho nada malo. No se
    borra nada; la clave queda en solo lectura hasta volver por debajo.
    """
    set_plan_limits({LimitKey.HYGEIA_ASSETS: 5})
    headers = auth_headers(regular_user)
    for index in range(3):
        client.post("/hygeia/assets", headers=headers,
                    json={"hostname": f"host-{index}", "os": "linux", "labels": {}})

    set_plan_limits({LimitKey.HYGEIA_ASSETS: 1})   # la bajada de plan
    body = client.get("/plans/me/usage", headers=headers).get_json()

    assert body["usage"]["hygeia.assets"]["exceeded"] is True
    assert body["usage"]["hygeia.assets"]["used"] == 3
    # Lo ya creado sigue ahí: degradar nunca borra.
    assert len(client.get("/hygeia/assets", headers=headers).get_json()["assets"]) == 3
