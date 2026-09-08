"""
hygeia.services.stats
──────────────────────
Agregados sobre una serie de potencia ya guardada, para la Fase 3 del
proyecto de consumo energético (media ponderada, energía, coste y su
procedencia).

Funciones puras: sin ORM, sin Flask. Entra una secuencia de ``(instante,
vatios)`` ya leída por el repositorio y salen los números que consume el
manager. No existe todavía el ``HygeiaStatsService`` genérico del roadmap de
estadísticas (proyecto 5, E01/E06) — mientras no lo haya, este módulo es la
pieza mínima que la Fase 3 necesita, con la forma que E01 define (funciones
puras en ``hygeia/services/stats.py``), para que las dos converjan en vez de
duplicarse cuando E01 llegue.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NamedTuple, Optional, Sequence, Tuple

# Suelo del umbral de hueco cuando la mediana de los intervalos es pequeña o
# no existe (menos de dos muestras). Replica el criterio de `gapThresholdMs`
# del frontend (`chartMath.js`) en su modo "serie cruda" (sin cubo): un
# activo late cada pocos segundos, así que 90 s de silencio ya es una señal,
# no ruido de red.
_GAP_FLOOR = timedelta(seconds=90)

# Múltiplo de la mediana que se considera todavía "el mismo ritmo". El mismo
# factor (3×) que usa `gapThresholdMs`, para que servidor y gráfico no
# discrepen sobre qué es un hueco.
_GAP_MULTIPLIER = 3


class PowerAverage(NamedTuple):
    """Resultado de :func:`weighted_average_with_observed_time`.

    Attributes:
        average_watts: Potencia media ponderada por duración sobre los
            tramos observados, o ``None`` si no hubo ni un intervalo válido
            (menos de dos muestras, o todas separadas por huecos).
        observed: Tiempo total cubierto por los intervalos que entraron en
            la media. Nunca incluye los huecos: es lo que permite a quien
            consume este resultado decir "esta media cubre 18 de las 24
            horas" en vez de presentar el número como si cubriera el
            periodo entero.
    """
    average_watts: Optional[float]
    observed: timedelta


class EnergyCost(NamedTuple):
    """Resultado de :func:`energy_and_cost`.

    ``kwh``/``cost`` son ``None`` (no ``0``) cuando no hay tiempo observado:
    un activo del que no se sabe nada no ha consumido cero euros, no se sabe
    cuánto ha consumido.
    """
    kwh: Optional[float]
    cost: Optional[float]


@dataclass(frozen=True)
class PeriodClassification:
    """Procedencia de una cifra de energía/coste sobre un periodo (P24).

    Attributes:
        classification: ``"observed"`` (el periodo cabe en la retención y la
            cobertura de datos es alta), ``"observed_partial"`` (cabe pero
            con cobertura baja) o ``"projected"`` (el periodo excede la
            retención configurada).
        coverage_fraction: Fracción del periodo con datos observados
            (``observed / duración_del_periodo``), acotada a 1.0. ``None``
            si el periodo tiene duración cero.
    """
    classification: str
    coverage_fraction: Optional[float]


def median_delta(times: Sequence[datetime]) -> Optional[timedelta]:
    """
    Mediana de los intervalos entre instantes consecutivos ya ordenados.

    La mediana, no la media: un único apagón largo en medio de una serie
    regular no debe inflar el "intervalo típico" y perdonar huecos que en
    realidad sí lo son.

    Returns:
        La mediana, o ``None`` con menos de dos instantes.
    """
    if len(times) < 2:
        return None
    deltas = sorted(t2 - t1 for t1, t2 in zip(times, times[1:]))
    mid = len(deltas) // 2
    if len(deltas) % 2:
        return deltas[mid]
    return (deltas[mid - 1] + deltas[mid]) / 2


def _gap_threshold(times: Sequence[datetime]) -> timedelta:
    """Umbral de hueco derivado de la mediana de los intervalos observados.

    Se deriva de los datos, no del intervalo de heartbeat configurado: un
    activo puede estar reportando cada minuto legítimamente porque su
    configuración lo dice, y un umbral fijo lo penalizaría por eso.
    """
    delta = median_delta(times)
    if delta is None:
        return _GAP_FLOOR
    return max(delta * _GAP_MULTIPLIER, _GAP_FLOOR)


def weighted_average_with_observed_time(
    samples: Sequence[Tuple[datetime, float]],
) -> PowerAverage:
    """
    Potencia media ponderada por duración, sobre los tramos realmente
    observados de una serie de ``(instante, vatios)``.

    Un activo apagado doce horas y midiendo 200 W las otras doce no tiene
    una media de 100 W: tiene una media observada de 200 W durante el
    tiempo que hubo datos, y doce horas sin información. Meter los huecos en
    el promedio como si fueran ceros hunde la media en proporción al tiempo
    que la máquina estuvo apagada — cuanto menos se sabe, más bajo parecería
    el consumo, que es exactamente al revés de lo útil.

    Cada intervalo `[t_i, t_{i+1})` cuya separación no supere el umbral de
    hueco (derivado de la mediana de los intervalos de esta misma serie)
    aporta `v_i × Δt_i` a la suma ponderada; los intervalos que sí son un
    hueco se excluyen enteros, tanto del numerador como del tiempo
    observado. Se pondera por el valor de la muestra **inicial** del
    intervalo (la lectura se trata como constante hasta la siguiente, igual
    que el resto del módulo trata un heartbeat como el estado del activo
    hasta que llegue otro), no por su promedio con la siguiente.

    Args:
        samples: Pares ``(instante, vatios)``, en cualquier orden.

    Returns:
        Un :class:`PowerAverage`. Con menos de dos muestras, o si todas
        están separadas por huecos, ``average_watts`` es ``None`` y
        ``observed`` es cero — no hay ni un intervalo que promediar, y
        eso no es lo mismo que una media de 0 W.
    """
    if len(samples) < 2:
        return PowerAverage(average_watts=None, observed=timedelta(0))

    ordered = sorted(samples, key=lambda sample: sample[0])
    times = [instant for instant, _ in ordered]
    threshold = _gap_threshold(times)

    weighted_sum = 0.0
    observed = timedelta(0)
    for (t1, watts1), (t2, _watts2) in zip(ordered, ordered[1:]):
        delta = t2 - t1
        if delta <= threshold:
            weighted_sum += watts1 * delta.total_seconds()
            observed += delta

    if observed <= timedelta(0):
        return PowerAverage(average_watts=None, observed=timedelta(0))
    return PowerAverage(average_watts=weighted_sum / observed.total_seconds(), observed=observed)


def energy_and_cost(
    average_watts: Optional[float], observed: timedelta, price_per_kwh: float,
) -> EnergyCost:
    """
    Convierte una potencia media observada en energía (kWh) y coste.

    La energía se calcula sobre el **tiempo observado**, nunca sobre la
    duración nominal del periodo que se pidió: multiplicar la media
    observada por la duración completa del periodo imputaría consumo a las
    horas en que el activo no reportó (o estuvo apagado) — el mismo error
    contra el que ``weighted_average_with_observed_time`` ya se protege,
    reintroducido en el último paso si se ignorara ``observed``.

    Args:
        average_watts: Potencia media ponderada, o ``None`` sin datos.
        observed: Tiempo cubierto por esa media.
        price_per_kwh: Precio de la electricidad configurado.

    Returns:
        Un :class:`EnergyCost`. ``(None, None)`` si no hay ni un intervalo
        observado — un activo sin datos no ha consumido cero euros.
    """
    if average_watts is None or observed <= timedelta(0):
        return EnergyCost(kwh=None, cost=None)

    hours = observed.total_seconds() / 3600
    kwh = (average_watts / 1000) * hours
    return EnergyCost(kwh=kwh, cost=kwh * price_per_kwh)


def classify_period(
    period_start: datetime, period_end: datetime, observed: timedelta,
    retention_days: int, coverage_threshold: float = 0.9,
) -> PeriodClassification:
    """
    Clasifica una cifra de energía/coste según cuánto se puede confiar en ella (P24).

    Contra ``retention_days`` de retención y sin tabla de rollup, un periodo
    que exceda esa ventana **nunca** puede ser histórico real: se etiqueta
    siempre como proyección, con independencia de la cobertura que tenga —
    el propio periodo pedido ya no cabe en lo que el servidor conserva.
    Dentro de la ventana, la cobertura decide entre observado (por encima
    del umbral) y observado con datos incompletos (por debajo): "últimas
    24 h" de un activo que estuvo apagado dieciocho es un dato sobre seis
    horas, y hay que decirlo en vez de presentarlo como si cubriera el día
    entero.

    Args:
        period_start: Inicio del periodo pedido.
        period_end: Fin del periodo pedido.
        observed: Tiempo observado dentro de ese periodo (de
            :attr:`PowerAverage.observed`).
        retention_days: Ventana de retención configurada
            (``features.hygeia.retentionDays``).
        coverage_threshold: Fracción de cobertura mínima para contar como
            observado sin matizar (por defecto 0.9, del orden del 90 % que
            describe el issue de origen).

    Returns:
        Un :class:`PeriodClassification`.
    """
    period_duration = period_end - period_start
    if period_duration > timedelta(days=retention_days):
        return PeriodClassification(classification="projected", coverage_fraction=None)

    if period_duration <= timedelta(0):
        return PeriodClassification(classification="observed_partial", coverage_fraction=None)

    coverage = min(1.0, observed.total_seconds() / period_duration.total_seconds())
    classification = "observed" if coverage >= coverage_threshold else "observed_partial"
    return PeriodClassification(classification=classification, coverage_fraction=coverage)


def summarize_power_period(
    samples: Sequence[Tuple[datetime, float]], period_start: datetime, period_end: datetime,
    price_per_kwh: float, retention_days: int,
) -> dict:
    """
    Combina media ponderada, energía/coste y clasificación para un periodo.

    Es el punto de entrada que consume el manager: junta P21, P23 y P24 en
    una sola llamada por ventana (24 h, 7 d, 30 d...), para no repetir el
    mismo triplete de pasos por cada una.

    Returns:
        Diccionario con ``averageWatts``, ``kwh``, ``cost``,
        ``classification``, ``coverageFraction``, ``periodFrom`` y
        ``periodTo`` — la forma que espera ``PowerPeriodSchema``.
    """
    average = weighted_average_with_observed_time(samples)
    cost = energy_and_cost(average.average_watts, average.observed, price_per_kwh)
    period = classify_period(period_start, period_end, average.observed, retention_days)

    return {
        "averageWatts": average.average_watts,
        "kwh": cost.kwh,
        "cost": cost.cost,
        "classification": period.classification,
        "coverageFraction": period.coverage_fraction,
        "periodFrom": period_start,
        "periodTo": period_end,
    }


def project_month(
    samples: Sequence[Tuple[datetime, float]], period_start: datetime, period_end: datetime,
    price_per_kwh: float,
) -> dict:
    """
    Proyección mensual, extrapolando la media ponderada de una ventana corta.

    Se apoya en la misma ventana que ``week`` (7 días) en vez de en los 30
    días de ``month``: es la que sigue dando una cifra útil aunque el activo
    lleve poco tiempo reportando, y es lo bastante corta para reflejar el
    ritmo de consumo actual sin que un solo día atípico la desvíe del todo.

    Se marca siempre ``"projected"``, sin excepción: contra la ventana de
    retención configurada, un mes natural nunca es histórico real, así que
    no tiene sentido aplicarle ``classify_period`` — ahí siempre daría el
    mismo resultado por la vía larga.

    Args:
        samples: Muestras de la ventana de origen (la misma que ``week``).
        period_start: Inicio de esa ventana de origen, para que la respuesta
            documente sobre qué datos se extrapoló.
        period_end: Fin de esa ventana de origen.
        price_per_kwh: Precio de la electricidad configurado.

    Returns:
        Igual forma que :func:`summarize_power_period`. ``kwh``/``cost``
        están calculados sobre un mes nominal de 30 días, no sobre la
        duración de la ventana de origen; ``periodFrom``/``periodTo``
        documentan esa ventana de origen, no el mes proyectado.
    """
    average = weighted_average_with_observed_time(samples)
    nominal_month = timedelta(days=30)
    cost = energy_and_cost(average.average_watts, nominal_month, price_per_kwh)

    window_duration = period_end - period_start
    coverage = (
        min(1.0, average.observed.total_seconds() / window_duration.total_seconds())
        if window_duration > timedelta(0) else None
    )

    return {
        "averageWatts": average.average_watts,
        "kwh": cost.kwh,
        "cost": cost.cost,
        "classification": "projected",
        "coverageFraction": coverage,
        "periodFrom": period_start,
        "periodTo": period_end,
    }
