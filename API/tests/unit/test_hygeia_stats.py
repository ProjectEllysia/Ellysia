"""
Tests unitarios de hygeia.services.stats: media ponderada por duración
(P21), energía y coste (P23) y su clasificación de procedencia (P24).

Sin base de datos ni Flask: son funciones puras sobre secuencias de
``(instante, vatios)`` construidas a mano.
"""

from datetime import datetime, timedelta

import pytest

from src.modules.features.hygeia.services.stats import (
    classify_period,
    energy_and_cost,
    weighted_average_with_observed_time,
)

pytestmark = pytest.mark.unit

_T0 = datetime(2026, 1, 1, 0, 0, 0)


def _series(hours: list[float]) -> list[tuple[datetime, float]]:
    """Construye ``(instante, vatios)`` a razón de una muestra por hora."""
    return [(_T0 + timedelta(hours=i), watts) for i, watts in enumerate(hours)]


# =============================================================================
# P21 — MEDIA PONDERADA POR DURACIÓN
# =============================================================================

def test_regular_samples_match_the_simple_average():
    """Con intervalos regulares y potencia constante, la ponderada coincide con la aritmética."""
    samples = _series([200.0] * 6)
    result = weighted_average_with_observed_time(samples)
    assert result.average_watts == pytest.approx(200.0)
    assert result.observed == timedelta(hours=5)


def test_the_plans_literal_example_12h_on_12h_gap():
    """200 W durante 12 h y 12 h sin datos: la media es 200 W, no 100 W."""
    samples = [
        (_T0, 200.0),
        (_T0 + timedelta(hours=1), 200.0),
        (_T0 + timedelta(hours=12), 200.0),
        (_T0 + timedelta(hours=13), 200.0),
    ]
    result = weighted_average_with_observed_time(samples)
    assert result.average_watts == pytest.approx(200.0)
    # Solo los dos tramos de 1 h entran; el hueco de 11 h queda excluido.
    assert result.observed == timedelta(hours=2)


def test_a_long_gap_in_the_middle_is_excluded():
    samples = [
        (_T0, 100.0),
        (_T0 + timedelta(minutes=1), 120.0),
        (_T0 + timedelta(hours=5), 300.0),
        (_T0 + timedelta(hours=5, minutes=1), 310.0),
    ]
    result = weighted_average_with_observed_time(samples)
    # Los dos tramos que sobreviven pesan 100 y 300, ambos de 1 minuto.
    assert result.average_watts == pytest.approx(200.0)
    assert result.observed == timedelta(minutes=2)


def test_a_single_isolated_sample_has_no_observed_time():
    """Ni una muestra, cero intervalos: la media es None, no un valor inventado."""
    result = weighted_average_with_observed_time([(_T0, 150.0)])
    assert result.average_watts is None
    assert result.observed == timedelta(0)


def test_empty_series_has_no_observed_time():
    result = weighted_average_with_observed_time([])
    assert result.average_watts is None
    assert result.observed == timedelta(0)


def test_unordered_input_is_sorted_before_computing():
    samples = [
        (_T0 + timedelta(hours=1), 100.0),
        (_T0, 50.0),
        (_T0 + timedelta(hours=2), 150.0),
    ]
    result = weighted_average_with_observed_time(samples)
    # 50 W durante la primera hora + 100 W durante la segunda.
    assert result.average_watts == pytest.approx(75.0)
    assert result.observed == timedelta(hours=2)


# =============================================================================
# P23 — ENERGÍA Y COSTE
# =============================================================================

def test_the_plans_literal_example_250w_4h_1kwh():
    kwh, cost = energy_and_cost(250.0, timedelta(hours=4), price_per_kwh=0.15)
    assert kwh == pytest.approx(1.0)
    assert cost == pytest.approx(0.15)


def test_energy_is_computed_over_observed_time_not_the_full_period():
    """Un hueco largo dentro del periodo no debe imputarse como consumo."""
    # 2 h observadas a 500 W, aunque el "periodo" pedido fuera mucho mayor.
    kwh, cost = energy_and_cost(500.0, timedelta(hours=2), price_per_kwh=0.20)
    assert kwh == pytest.approx(1.0)
    assert cost == pytest.approx(0.20)


def test_no_observed_time_yields_none_not_zero():
    """Un activo del que no se sabe nada no ha consumido cero euros."""
    kwh, cost = energy_and_cost(None, timedelta(0), price_per_kwh=0.15)
    assert kwh is None
    assert cost is None


def test_zero_observed_duration_with_average_still_yields_none():
    kwh, cost = energy_and_cost(100.0, timedelta(0), price_per_kwh=0.15)
    assert kwh is None
    assert cost is None


# =============================================================================
# P24 — CLASIFICACIÓN DE PROCEDENCIA
# =============================================================================

def test_full_coverage_within_retention_is_observed():
    result = classify_period(
        _T0, _T0 + timedelta(hours=24), observed=timedelta(hours=23),
        retention_days=30,
    )
    assert result.classification == "observed"
    assert result.coverage_fraction == pytest.approx(23 / 24)


def test_partial_coverage_within_retention_is_observed_partial():
    result = classify_period(
        _T0, _T0 + timedelta(hours=24), observed=timedelta(hours=12),
        retention_days=30,
    )
    assert result.classification == "observed_partial"
    assert result.coverage_fraction == pytest.approx(0.5)


def test_a_period_longer_than_retention_is_always_projected():
    """Un año excede la retención: siempre proyectado, tenga o no cobertura completa."""
    result = classify_period(
        _T0, _T0 + timedelta(days=365), observed=timedelta(days=365),
        retention_days=30,
    )
    assert result.classification == "projected"
    assert result.coverage_fraction is None


def test_period_exactly_at_the_retention_boundary_is_not_projected():
    result = classify_period(
        _T0, _T0 + timedelta(days=30), observed=timedelta(days=29),
        retention_days=30,
    )
    assert result.classification in ("observed", "observed_partial")


def test_coverage_is_capped_at_one():
    """Un solape de reloj no debe producir una cobertura por encima del 100 %."""
    result = classify_period(
        _T0, _T0 + timedelta(hours=1), observed=timedelta(hours=2),
        retention_days=30,
    )
    assert result.coverage_fraction == 1.0
