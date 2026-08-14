"""Tests unitarios de hygeia.services.ingest_guard.check_clock_skew.

La ventana de cordura del reloj es asimétrica a propósito (§16.3): corta
hacia el futuro (un reloj adelantado no tiene explicación legítima) y larga
hacia el pasado (el buffer en disco del agente drenando una caída sí la
tiene). Estos tests fijan esa asimetría, que es justo lo que se pierde de
vista si alguien "simplifica" la comprobación a un abs().
"""

from datetime import timedelta

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.hygeia.exceptions import IngestClockSkewError
from src.modules.features.hygeia.services.ingest_guard import check_clock_skew
from src.modules.shared import utcnow_naive

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _limits():
    """Los valores por defecto del bloque, para no depender del JSON del repo."""
    return CR.hygeia_limits()


def test_accepts_a_fresh_heartbeat():
    check_clock_skew(utcnow_naive())


def test_accepts_a_heartbeat_slightly_ahead(_limits):
    """Un adelanto pequeño es deriva normal de reloj entre dos máquinas."""
    check_clock_skew(utcnow_naive() + timedelta(seconds=_limits.clock_skew_sec - 10))


def test_rejects_a_heartbeat_too_far_ahead(_limits):
    """Un reloj muy adelantado es un fallo de configuración, no un retardo de red."""
    with pytest.raises(IngestClockSkewError):
        check_clock_skew(utcnow_naive() + timedelta(seconds=_limits.clock_skew_sec + 60))


def test_accepts_a_buffered_heartbeat_hours_old(_limits):
    """El caso que motivó la asimetría (A-02).

    El agente retiene mil heartbeats en su buffer en disco (unas cuatro horas
    con el intervalo por defecto). Con la ventana simétrica de 300 s anterior,
    drenar ese buffer tras una caída de más de cinco minutos descartaba casi
    todo: el servidor respondía 400, el agente lo clasificaba como permanente
    y tiraba el payload. El buffer existía pero no servía para nada.
    """
    four_hours_ago = utcnow_naive() - timedelta(hours=4)
    assert _limits.max_backfill_sec >= 4 * 3600, (
        "maxBackfillSec debe cubrir al menos el buffer completo del agente"
    )
    check_clock_skew(four_hours_ago)


def test_rejects_a_heartbeat_older_than_the_backfill_window(_limits):
    """El pasado es tolerante, no infinito: sigue habiendo un tope."""
    with pytest.raises(IngestClockSkewError):
        check_clock_skew(utcnow_naive() - timedelta(seconds=_limits.max_backfill_sec + 60))


def test_the_window_is_asymmetric(_limits):
    """La asimetría es el punto, no un efecto colateral.

    Un mismo desfase de una hora se acepta hacia atrás y se rechaza hacia
    delante. Si alguien vuelve a escribir esto con un abs(), este test cae.
    """
    one_hour = timedelta(hours=1)
    assert _limits.max_backfill_sec > 3600 > _limits.clock_skew_sec

    check_clock_skew(utcnow_naive() - one_hour)  # backfill: se acepta
    with pytest.raises(IngestClockSkewError):
        check_clock_skew(utcnow_naive() + one_hour)  # reloj adelantado: se rechaza
