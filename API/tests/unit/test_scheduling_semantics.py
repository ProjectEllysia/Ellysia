"""``calculate_next_run`` y ``_build_trigger`` no pueden divergir en silencio.

``ThemisScheduler`` calcula "cuándo dispara" por dos caminos independientes:

- ``_build_trigger`` construye el ``IntervalTrigger``/``CronTrigger`` de
  APScheduler que de verdad dispara el job — la fuente autoritativa.
- ``calculate_next_run`` (croniter/timedelta) es lo que se muestra en la UI
  y se persiste en ``next_run_at`` — una estimación independiente, porque
  llamarla no requiere que el scheduler esté corriendo.

Dos librerías distintas interpretando la misma expresión cron. Coinciden
hoy; nada lo garantizaba. Este test lo fija: si alguna vez divergen (un caso
raro de DST, un `*/7` de día del mes, una versión nueva de una librería),
cae aquí en vez de manifestarse como "la UI dice una hora y el escaneo salta
en otra".
"""

from datetime import datetime, timezone

import pytest

from src.modules.features.themis.services.scheduling import ThemisScheduler

pytestmark = pytest.mark.unit

_REFERENCE = datetime(2026, 8, 4, 10, 0, 0, tzinfo=timezone.utc)

_CRON_CASES = [
    "0 2 * * *",        # diario a las 02:00
    "*/15 * * * *",      # cada 15 minutos
    "0 0 1 * *",         # el día 1 de cada mes
    "0 3 * * 1-5",       # laborables a las 03:00
    "30 23 * * 0",       # domingos 23:30
    "0 */6 * * *",       # cada 6 horas
]

_INTERVAL_CASES = [
    {"every": 15, "unit": "minutes"},
    {"every": 2, "unit": "hours"},
    {"every": 1, "unit": "days"},
    {"every": 45, "unit": "minutes"},
]


@pytest.mark.parametrize("cron_expr", _CRON_CASES)
def test_cron_next_run_matches_trigger(cron_expr):
    schedule_config = {"cron": cron_expr}

    estimated = ThemisScheduler.calculate_next_run(
        "cron", schedule_config, last_run=_REFERENCE.replace(tzinfo=None)
    )

    trigger = ThemisScheduler._build_trigger("cron", schedule_config)  # pylint: disable=protected-access
    authoritative = trigger.get_next_fire_time(_REFERENCE, _REFERENCE)

    assert estimated == authoritative.replace(tzinfo=None), (
        f"cron '{cron_expr}': calculate_next_run={estimated} "
        f"pero el trigger real dispararía en {authoritative}"
    )


@pytest.mark.parametrize("schedule_config", _INTERVAL_CASES)
def test_interval_next_run_matches_trigger(schedule_config):
    estimated = ThemisScheduler.calculate_next_run(
        "interval", schedule_config, last_run=_REFERENCE.replace(tzinfo=None)
    )

    trigger = ThemisScheduler._build_trigger("interval", schedule_config)  # pylint: disable=protected-access
    authoritative = trigger.get_next_fire_time(_REFERENCE, _REFERENCE)

    assert estimated == authoritative.replace(tzinfo=None), (
        f"interval {schedule_config}: calculate_next_run={estimated} "
        f"pero el trigger real dispararía en {authoritative}"
    )
