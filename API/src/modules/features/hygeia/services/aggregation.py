"""
hygeia.services.aggregation
────────────────────────────
Desnormalización de un payload de métricas a los escalares por snapshot (§5).

Función pura: sin DB, sin Flask, sin ORM. Entra el bloque ``metrics`` ya
validado de un heartbeat y salen los valores que se persisten en columnas
propias de ``AssetSnapshot``, con las claves ya nombradas como esas columnas.

Existe para que el **camino de lectura no conozca la forma del payload del
agente**. Ese conocimiento vive en exactamente dos sitios: el schema de
ingesta, que lo valida, y esta función, que lo proyecta a escalares. La
serie temporal luego lee columnas y no abre el JSONB jamás.

Qué se desnormaliza y qué no: solo lo **escalar por snapshot** (un número
por heartbeat), que es lo que tiene sentido graficar en el tiempo. Lo que
tiene cardinalidad por entidad (uso por punto de montaje, tráfico por
interfaz) o solo tiene sentido "ahora" (uso por núcleo, procesos top) se
queda en el JSONB y se sirve por el endpoint de últimas métricas.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

# "lo"/"lo0" en Linux, BSD y macOS; en Windows la interfaz se llama
# "Loopback Pseudo-Interface 1", de ahí la comprobación por subcadena.
_LOOPBACK_EXACT = {"lo", "lo0"}


def _is_loopback(iface: Optional[str]) -> bool:
    """
    Indica si el nombre de una interfaz corresponde a loopback.

    Se compara por igualdad exacta y no con ``startswith("lo")``, que se
    llevaría por delante interfaces reales como ``lom0`` o ``lon0``.

    No se excluyen puentes ni interfaces virtuales de contenedores
    (``docker0``, ``veth*``, ``br-*``): en un host de contenedores ese
    tráfico es real, y si duplica o no el de la interfaz física es una
    decisión de política, no de corrección. El desglose por interfaz sigue
    disponible en las últimas métricas para quien quiera mirarlo.
    """
    name = (iface or "").strip().lower()
    return name in _LOOPBACK_EXACT or "loopback" in name


def _sum_or_none(values: Iterable[Optional[float]]) -> Optional[float]:
    """
    Suma los valores no nulos, o devuelve ``None`` si no hay ni uno.

    La distinción importa: ``0`` significa "el agente reportó y no había
    tráfico"; ``None`` significa "el agente no reportó esto". Devolver ``0``
    en el segundo caso pintaría una línea plana en el fondo del gráfico,
    afirmando un dato que nadie ha medido.
    """
    present = [measurement for measurement in values if measurement is not None]
    return sum(present) if present else None


def denormalize(metrics: dict) -> dict:
    """
    Extrae los escalares por snapshot de un payload de métricas.

    Args:
        metrics: Bloque ``metrics`` ya validado de un heartbeat, con la forma
            de ``MetricsSchema``. Todos los bloques internos se tratan como
            opcionales: un agente de Windows no manda ``loadAvg``, y uno sin
            interfaces visibles no manda ``network``.

    Returns:
        Diccionario con las claves nombradas exactamente como las columnas
        de ``AssetSnapshot``, listo para expandir en su constructor. Cada
        valor es ``None`` cuando el dato no viene en el payload.
    """
    metrics = metrics or {}
    cpu = metrics.get("cpu") or {}
    memory = metrics.get("memory") or {}
    power = metrics.get("power") or {}

    load_avg: List[float] = cpu.get("loadAvg") or []
    load1 = load_avg[0] if load_avg else None

    disk_max_pct: Optional[float] = None
    disk_max_mount: Optional[str] = None
    for mount in metrics.get("disk") or []:
        usage = mount.get("usagePct")
        if usage is not None and (disk_max_pct is None or usage > disk_max_pct):
            disk_max_pct = usage
            disk_max_mount = mount.get("mount")

    interfaces = [
        iface for iface in (metrics.get("network") or [])
        if not _is_loopback(iface.get("iface"))
    ]

    return {
        "cpu_pct":        cpu.get("usagePct"),
        "mem_pct":        memory.get("usagePct"),
        "swap_pct":       memory.get("swapUsedPct"),
        "load1":          load1,
        "disk_max_pct":   disk_max_pct,
        "disk_max_mount": disk_max_mount,
        "net_rx_bps":     _sum_or_none(i.get("rxBytesPerSec") for i in interfaces),
        "net_tx_bps":     _sum_or_none(i.get("txBytesPerSec") for i in interfaces),
        # Sin valores por defecto en los `get`: un activo sin fuente de
        # potencia debe quedar a None en las tres, nunca a 0 — ver el
        # docstring de `_sum_or_none` para el mismo principio aplicado a red.
        "power_watts":     power.get("watts"),
        "power_estimated": power.get("estimated"),
        "power_source":    power.get("source"),
    }
