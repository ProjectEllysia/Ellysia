"""Que ninguna clave del catálogo se quede sin exigir.

Una clave declarada y no cableada no da error en ninguna parte: el plan la
anuncia, la tabla de precios la pinta, y no corta nada. Es un fallo silencioso y
de los caros — se descubre cuando llega la factura de OpenAI, no cuando se
escribe el código.

Estos dos tests son el recordatorio: quien añada una clave a ``LimitKey`` tiene
que cablearla en el manager que corresponda o declararla aquí como diferida, con
su motivo.
"""

import re
from pathlib import Path

import pytest

from src.modules.accounts.services.limits import (
    PERIODS,
    STOCK_COUNTERS,
    LimitKey,
    LimitPeriod,
)

pytestmark = pytest.mark.unit


#: Claves que todavía no se exigen, y por qué. Vaciar esta lista es el objetivo.
DEFERRED: dict[LimitKey, str] = {
    LimitKey.ORGANIZATION_MEMBERS:
        "Las organizaciones llegan en la fase 5; hoy nadie escribe la tabla.",
}

FEATURES_DIR = Path(__file__).resolve().parents[2] / "src" / "modules" / "features"


def _keys_used_in_feature_managers() -> set[str]:
    """Nombres de LimitKey que aparecen en el código de los módulos de features.

    Se lee el texto en vez de importar y reflexionar sobre los managers porque
    lo que se quiere comprobar es justo que *existe una línea* que la consume,
    y eso no se puede preguntar en tiempo de ejecución sin lanzar la acción.
    """
    pattern = re.compile(r"LimitKey\.([A-Z_]+)")
    found: set[str] = set()
    for path in FEATURES_DIR.rglob("*.py"):
        found.update(pattern.findall(path.read_text(encoding="utf-8")))
    return found


def test_every_limit_key_is_enforced_somewhere():
    used = _keys_used_in_feature_managers()
    missing = {
        key for key in LimitKey
        if key.name not in used and key not in DEFERRED
    }
    assert not missing, (
        "Estas claves están en el catálogo pero no las consume nadie, así que "
        "el plan las anuncia y no cortan nada: "
        f"{sorted(key.value for key in missing)}. "
        "Cabléalas en su manager o añádelas a DEFERRED con su motivo."
    )


def test_every_stock_key_has_a_counter():
    """Sin contador, una clave de existencias revienta con NotImplementedError
    la primera vez que alguien la exige — en producción, no aquí."""
    missing = {
        key for key, period in PERIODS.items()
        if period is LimitPeriod.STOCK
        and key not in STOCK_COUNTERS
        and key not in DEFERRED
    }
    assert not missing, (
        "Claves de existencias sin funcion de recuento en STOCK_COUNTERS: "
        f"{sorted(key.value for key in missing)}."
    )


def test_counters_are_only_registered_for_stock_keys():
    """Un contador de existencias sobre una clave de consumo no se llamaría
    nunca: el consumo lo lleva UsageCounter."""
    wrong = {key for key in STOCK_COUNTERS if PERIODS[key] is not LimitPeriod.STOCK}
    assert wrong == set()


def test_deferred_keys_are_real_keys():
    """Una entrada obsoleta en DEFERRED taparía una clave que sí hay que
    cablear."""
    assert set(DEFERRED) <= set(LimitKey)
