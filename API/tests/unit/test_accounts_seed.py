"""Forma del catálogo comercial sembrado por la migración.

La migración congela los planes como literal Python, a propósito: tiene que
seguir dando el mismo resultado dentro de un año, cuando los precios se editen
desde el panel. El precio de eso es que nadie mira ese literal — y una errata
en una clave (``acheron.vault`` por ``acheron.vaults``) no da error: crea una
fila que nadie consulta y deja la característica desactivada en silencio,
porque una fila ausente vale 0.

Estos tests miran la **forma**, nunca los números: si comercial sube Bronze a
34 €, aquí no se entera nadie.
"""

import importlib.util
from pathlib import Path

import pytest

from src.modules.accounts.services.limits import PERIODS, SCOPES, LimitKey

pytestmark = pytest.mark.unit


def _load_migration():
    """Carga el módulo de la migración por ruta.

    ``alembic/versions/`` no es un paquete importable, así que no vale un
    import normal.
    """
    path = (
        Path(__file__).resolve().parents[2]
        / "alembic" / "versions"
        / "f2b3c4d5e6f7_accounts_plans_and_organizations.py"
    )
    spec = importlib.util.spec_from_file_location("accounts_seed_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = _load_migration()
PLAN_CODES = [plan[0] for plan in MIGRATION._PLANS]


def test_seed_has_exactly_one_default_plan():
    """Y solo uno: es el que reciben las cuentas sin suscripción vigente. La
    base de datos lo impone con un índice único parcial, así que sembrar dos
    haría fallar la migración entera."""
    defaults = [plan[0] for plan in MIGRATION._PLANS if plan[7]]
    assert defaults == ["freemium"]


def test_seed_plan_codes_are_unique():
    assert len(PLAN_CODES) == len(set(PLAN_CODES))


def test_seed_limit_keys_exist_in_the_enum():
    """Caza erratas: una clave que no está en LimitKey siembra una fila que
    nadie consultará nunca."""
    unknown = {
        limit_key
        for table in (MIGRATION._HOLDER_LIMITS, MIGRATION._MEMBER_LIMITS)
        for limit_key in table
    } - {key.value for key in LimitKey}
    assert unknown == set()


def test_seed_plan_codes_in_limits_exist():
    """Un código mal escrito en la tabla de topes reventaría la migración al
    buscar su id; mejor enterarse aquí."""
    referenced = {
        code
        for table in (MIGRATION._HOLDER_LIMITS, MIGRATION._MEMBER_LIMITS)
        for _, values_by_plan in table.values()
        for code in values_by_plan
    }
    assert referenced <= set(PLAN_CODES)


def test_seed_covers_every_holder_key_for_every_plan():
    """Las 15 claves, en los 4 planes, explícitamente.

    Omitir una no da error: se lee como 0 y desactiva la característica. Es el
    fallo cerrado que queremos cuando alguien añade una clave nueva y se olvida
    de rellenarla, pero no algo que deba pasar en el catálogo de partida.
    """
    assert set(MIGRATION._HOLDER_LIMITS) == {key.value for key in LimitKey}
    for limit_key, (_, values_by_plan) in MIGRATION._HOLDER_LIMITS.items():
        assert set(values_by_plan) == set(PLAN_CODES), f"falta algun plan en '{limit_key}'"


def test_seed_periods_match_the_enum():
    """El periodo se guarda en la fila además de estar en el código; si los dos
    no dicen lo mismo, un contador mensual se leería como existencias."""
    for table in (MIGRATION._HOLDER_LIMITS, MIGRATION._MEMBER_LIMITS):
        for limit_key, (period, _) in table.items():
            assert period == PERIODS[LimitKey(limit_key)].value, limit_key


def test_seed_scopes_are_only_holder_and_member():
    assert set(SCOPES) == {"holder", "member"}


def test_freemium_has_no_member_limits():
    """El plan gratuito no admite organización, así que no reparte derechos
    heredados: si apareciera aquí, alguien habría copiado una fila de más."""
    for _, values_by_plan in MIGRATION._MEMBER_LIMITS.values():
        assert "freemium" not in values_by_plan


def test_seed_values_are_positive_or_zero_or_unlimited():
    """``None`` es ilimitado y ``0`` es "no incluido"; un negativo no significa
    nada y pasaría desapercibido hasta que alguien lo comparase con un uso."""
    for table in (MIGRATION._HOLDER_LIMITS, MIGRATION._MEMBER_LIMITS):
        for limit_key, (_, values_by_plan) in table.items():
            for code, value in values_by_plan.items():
                assert value is None or value >= 0, f"{limit_key} / {code}"
