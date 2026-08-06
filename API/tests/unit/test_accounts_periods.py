"""Aritmética de periodos del motor de cuotas.

``period_start`` es la cuarta parte de la clave primaria de ``UsageCounter``: al
cambiar de periodo cambia ese valor y nace una fila nueva con ``used = 0``. Ahí
está la razón de que no exista ningún proceso que reinicie contadores — pero
también significa que un error en estas cuatro líneas regala un mes de cuota o
lo corta un día antes, y en silencio.
"""

from datetime import date, datetime

import pytest

from src.modules.accounts.services.limits import (
    LimitPeriod,
    next_period_start,
    period_start_for,
)

pytestmark = pytest.mark.unit


MID_MONTH = datetime(2026, 8, 6, 17, 42, 3)


def test_month_period_starts_on_the_first():
    assert period_start_for(LimitPeriod.MONTH, MID_MONTH) == date(2026, 8, 1)


def test_month_period_is_stable_within_the_month():
    """Dos momentos del mismo mes tienen que dar la misma fila de contador."""
    first = period_start_for(LimitPeriod.MONTH, datetime(2026, 8, 1, 0, 0, 0))
    last = period_start_for(LimitPeriod.MONTH, datetime(2026, 8, 31, 23, 59, 59))
    assert first == last


def test_day_period_is_the_date_itself():
    assert period_start_for(LimitPeriod.DAY, MID_MONTH) == date(2026, 8, 6)


def test_stock_has_no_period():
    """Las existencias no se cuentan por periodo: se cuenta la tabla real."""
    assert period_start_for(LimitPeriod.STOCK, MID_MONTH) is None


def test_next_month_is_the_first_of_the_next():
    assert next_period_start(LimitPeriod.MONTH, MID_MONTH) == date(2026, 9, 1)


def test_next_month_rolls_over_the_year():
    """Diciembre es el caso que se olvida y el que se nota en Nochevieja."""
    assert next_period_start(LimitPeriod.MONTH, datetime(2026, 12, 20)) == date(2027, 1, 1)


def test_next_day_rolls_over_the_month():
    assert next_period_start(LimitPeriod.DAY, datetime(2026, 8, 31, 10)) == date(2026, 9, 1)


def test_next_day_rolls_over_the_year():
    assert next_period_start(LimitPeriod.DAY, datetime(2026, 12, 31, 10)) == date(2027, 1, 1)


def test_stock_has_no_reset():
    """No hay "resetsAt" que enseñar para unas existencias: no se renuevan, se
    liberan borrando."""
    assert next_period_start(LimitPeriod.STOCK, MID_MONTH) is None
