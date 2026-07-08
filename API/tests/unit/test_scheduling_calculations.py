"""Tests unitarios de la matemática de scheduling (sin BD ni Flask).

``Scheduler.calculate_next_run`` es una función pura: dado un schedule_type y
su config, calcula la próxima ejecución. Se cubre aquí de forma aislada
porque concentra toda la lógica de fechas que antes estaba duplicada (y a
veces incoherente, ver IMPROVEMENTS.md) entre el repositorio y el scheduler.
"""

from datetime import datetime, timedelta

import pytest

from src.modules.themis.services.scheduling import Scheduler

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------ interval

def test_interval_advances_by_configured_unit():
    last_run = datetime(2026, 1, 1, 12, 0, 0)
    next_run = Scheduler.calculate_next_run(
        schedule_type="interval",
        schedule_config={"every": 5, "unit": "minutes"},
        last_run=last_run,
    )
    assert next_run == last_run + timedelta(minutes=5)


def test_interval_supports_hours_and_days():
    last_run = datetime(2026, 1, 1, 12, 0, 0)

    hours = Scheduler.calculate_next_run("interval", {"every": 2, "unit": "hours"}, last_run)
    assert hours == last_run + timedelta(hours=2)

    days = Scheduler.calculate_next_run("interval", {"every": 1, "unit": "days"}, last_run)
    assert days == last_run + timedelta(days=1)


def test_interval_invalid_unit_raises_value_error():
    with pytest.raises(ValueError):
        Scheduler.calculate_next_run("interval", {"every": 1, "unit": "fortnights"}, datetime.utcnow())


def test_interval_without_last_run_uses_now():
    before = datetime.utcnow()
    next_run = Scheduler.calculate_next_run("interval", {"every": 10, "unit": "minutes"})
    after = datetime.utcnow()

    assert before + timedelta(minutes=10) <= next_run <= after + timedelta(minutes=10)
    # Coherente con las columnas DateTime (naive) y con datetime.utcnow().
    assert next_run.tzinfo is None


# ---------------------------------------------------------------------- cron

def test_cron_returns_next_occurrence_after_reference():
    last_run = datetime(2026, 1, 1, 12, 0, 0)
    next_run = Scheduler.calculate_next_run(
        schedule_type="cron",
        schedule_config={"cron": "0 0 * * *"},  # diario a medianoche
        last_run=last_run,
    )
    assert next_run == datetime(2026, 1, 2, 0, 0, 0)
    assert next_run > last_run


def test_cron_without_last_run_does_not_run_immediately():
    """Regresión: el repositorio calculaba antes next_run_at = now() para
    cron, lo que disparaba el escaneo en el primer tick del scheduler en
    lugar de esperar a la próxima ocurrencia real del cron."""
    before = datetime.utcnow()
    next_run = Scheduler.calculate_next_run("cron", {"cron": "0 0 * * *"})
    assert next_run > before


# ------------------------------------------------------------------- errores

def test_unknown_schedule_type_raises_value_error():
    with pytest.raises(ValueError):
        Scheduler.calculate_next_run("weekly", {}, datetime.utcnow())
