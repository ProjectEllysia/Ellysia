"""
hygeia.services.detection
──────────────────────────
Evaluación de umbrales de CPU/memoria/disco con histéresis (§6).

Función pura: sin DB, sin Flask, sin ORM. Entra el estado (métricas del
heartbeat + contadores de cruces consecutivos + qué está ya abierto +
umbrales efectivos) y sale el estado siguiente (qué abrir, qué resolver,
contadores actualizados). El manager es quien persiste el resultado — así
``evaluate()`` se puede testear sin app ni base de datos.

Reglas del beta: umbral estático con histéresis, ``warning``/``critical``
por métrica. Una anomalía se abre al primer cruce sostenido durante
``sustainedHeartbeats`` heartbeats consecutivos (1 si la métrica no define
ese campo — disco y swap se consideran suficientemente estables como para
no necesitar confirmación) y se resuelve en el primer heartbeat en el que
la métrica vuelve a estar por debajo del umbral ``warning``. Mientras sigue
abierta, no se toca en absoluto hasta que se resuelve — "ciclo de vida, no
spam" (§3.3): ni se reabre, ni se actualiza su severidad o valor heartbeat
a heartbeat.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class AnomalyChange:
    """Una anomalía nueva a abrir, con el valor y umbral que la dispararon."""
    kind: str
    severity: str
    metric: Optional[str]
    value: float
    threshold: float


@dataclass(frozen=True)
class DetectionOutcome:
    """
    Resultado de evaluar un heartbeat contra los umbrales configurados.

    Attributes:
        to_open: Anomalías nuevas a crear en estado ``open``.
        to_resolve: Pares ``(kind, metric)`` de anomalías ya abiertas que
            deben pasar a ``resolved`` en este heartbeat.
        breach_counters: Contadores de cruces consecutivos ya actualizados,
            listos para persistir de vuelta en ``MonitoredAsset``.
    """
    to_open: List[AnomalyChange] = field(default_factory=list)
    to_resolve: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    breach_counters: Dict[str, int] = field(default_factory=dict)


def evaluate(
    metrics: dict,
    breach_counters: Dict[str, int],
    open_kinds: Set[Tuple[str, Optional[str]]],
    thresholds: dict,
) -> DetectionOutcome:
    """
    Evalúa un único heartbeat contra los umbrales efectivos del activo.

    Args:
        metrics: Métricas ya validadas del heartbeat (forma de ``IngestRequestSchema``).
        breach_counters: Contadores de cruces consecutivos tal como quedaron
            tras el heartbeat anterior de este mismo activo (clave libre por
            regla, p. ej. ``"cpu_spike"`` o ``"disk_full:/data"``).
        open_kinds: Conjunto de ``(kind, metric)`` actualmente abiertos para
            este activo — evita reabrir o duplicar lo que ya está en curso.
        thresholds: Umbrales efectivos (global + override por activo, ya
            combinados por el llamador), con la forma del bloque
            ``hygeia.thresholds`` de la config: ``cpuPct``, ``memPct``,
            ``diskPct``, ``swapPct``, cada uno con ``warning``/``critical``
            y, opcionalmente, ``sustainedHeartbeats``.

    Returns:
        El ``DetectionOutcome`` con las altas, bajas y contadores a persistir.
    """
    counters = dict(breach_counters)
    to_open: List[AnomalyChange] = []
    to_resolve: List[Tuple[str, Optional[str]]] = []

    def _check(
        kind: str,
        metric_name: str,
        value: Optional[float],
        cfg: Optional[dict],
        counter_key: str
    ) -> None:
        if value is None or not cfg:
            return

        warning_threshold = cfg.get("warning")
        if warning_threshold is None:
            return

        critical_threshold = cfg.get("critical")
        heartbeat_streak = cfg.get("sustainedHeartbeats", 1)
        is_open = (kind, metric_name) in open_kinds

        if value < warning_threshold:
            counters[counter_key] = 0
            if is_open:
                to_resolve.append((kind, metric_name))
            return

        if is_open:
            # Ya abierta y sigue rota: nada que hacer hasta que se resuelva.
            return

        counters[counter_key] = counters.get(counter_key, 0) + 1
        if counters[counter_key] >= heartbeat_streak:
            severity = "critical" if critical_threshold is not None and value >= critical_threshold else "warning"
            threshold_crossed = critical_threshold if severity == "critical" else warning_threshold
            anomaly = AnomalyChange(kind, severity, metric_name, value, threshold_crossed)
            to_open.append(anomaly)

    cpu = metrics.get("cpu") or {}
    _check(
        "cpu_spike",
        "cpu.usagePct",
        cpu.get("usagePct"),
        thresholds.get("cpuPct"),
        "cpu_spike"
    )

    memory = metrics.get("memory") or {}
    _check(
        "mem_high",
        "memory.usagePct",
        memory.get("usagePct"),
        thresholds.get("memPct"),
        "mem_high"
    )
    _check(
        "swap_thrash",
        "memory.swapUsedPct",
        memory.get("swapUsedPct"),
        thresholds.get("swapPct"),
        "swap_thrash"
    )

    disk_cfg = thresholds.get("diskPct")
    for disk in metrics.get("disk") or []:
        mount = disk.get("mount")
        if not mount:
            continue
        _check(
            "disk_full",
            f"disk.{mount}",
            disk.get("usagePct"),
            disk_cfg,
            f"disk_full:{mount}"
        )

    return DetectionOutcome(
        to_open=to_open,
        to_resolve=to_resolve,
        breach_counters=counters
    )
