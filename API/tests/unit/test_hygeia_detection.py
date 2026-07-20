"""Tests unitarios de hygeia.services.detection.evaluate (histéresis de umbrales)."""

import pytest

from src.modules.features.hygeia.services.detection import evaluate

pytestmark = pytest.mark.unit

THRESHOLDS = {
    "cpuPct":  {"warning": 85, "critical": 95, "sustainedHeartbeats": 3},
    "memPct":  {"warning": 85, "critical": 95, "sustainedHeartbeats": 3},
    "diskPct": {"warning": 85, "critical": 95},
    "swapPct": {"warning": 40, "critical": 70},
}


def _metrics(cpu=10.0, mem=10.0, swap=0.0, disk=None):
    return {
        "cpu": {"usagePct": cpu},
        "memory": {"usagePct": mem, "swapUsedPct": swap},
        "disk": disk or [],
    }


def test_no_anomaly_below_warning():
    outcome = evaluate(_metrics(cpu=50.0), {}, set(), THRESHOLDS)
    assert outcome.to_open == []
    assert outcome.to_resolve == []
    assert outcome.breach_counters.get("cpu_spike", 0) == 0


def test_does_not_open_before_sustained_heartbeats():
    counters = {}
    for _ in range(2):  # sustainedHeartbeats=3: dos cruces no bastan
        outcome = evaluate(_metrics(cpu=90.0), counters, set(), THRESHOLDS)
        counters = outcome.breach_counters
        assert outcome.to_open == []
    assert counters["cpu_spike"] == 2


def test_opens_warning_on_nth_sustained_heartbeat():
    counters = {}
    outcome = None
    for _ in range(3):
        outcome = evaluate(_metrics(cpu=90.0), counters, set(), THRESHOLDS)
        counters = outcome.breach_counters
    assert len(outcome.to_open) == 1
    change = outcome.to_open[0]
    assert change.kind == "cpu_spike"
    assert change.severity == "warning"
    assert change.metric == "cpu.usagePct"
    assert change.value == 90.0
    assert change.threshold == 85


def test_opens_critical_when_value_crosses_critical_threshold():
    counters = {}
    outcome = None
    for _ in range(3):
        outcome = evaluate(_metrics(cpu=97.0), counters, set(), THRESHOLDS)
        counters = outcome.breach_counters
    assert outcome.to_open[0].severity == "critical"
    assert outcome.to_open[0].threshold == 95


def test_does_not_reopen_or_touch_already_open_anomaly():
    open_kinds = {("cpu_spike", "cpu.usagePct")}
    outcome = evaluate(_metrics(cpu=99.0), {"cpu_spike": 3}, open_kinds, THRESHOLDS)
    assert outcome.to_open == []
    assert outcome.to_resolve == []


def test_resolves_when_metric_drops_below_warning():
    open_kinds = {("cpu_spike", "cpu.usagePct")}
    outcome = evaluate(_metrics(cpu=50.0), {"cpu_spike": 3}, open_kinds, THRESHOLDS)
    assert outcome.to_resolve == [("cpu_spike", "cpu.usagePct")]
    assert outcome.breach_counters["cpu_spike"] == 0


def test_disk_full_tracked_independently_per_mount():
    disk = [
        {"mount": "/", "usagePct": 90.0},
        {"mount": "/data", "usagePct": 10.0},
    ]
    outcome = evaluate(_metrics(disk=disk), {}, set(), THRESHOLDS)
    # diskPct no define sustainedHeartbeats -> por defecto 1, abre en el primer cruce.
    assert len(outcome.to_open) == 1
    assert outcome.to_open[0].kind == "disk_full"
    assert outcome.to_open[0].metric == "disk./"
    assert outcome.breach_counters["disk_full:/"] == 1
    assert outcome.breach_counters["disk_full:/data"] == 0


def test_two_mounts_can_be_open_simultaneously_and_independently():
    open_kinds = {("disk_full", "disk./")}
    disk = [
        {"mount": "/", "usagePct": 90.0},       # ya abierta: no se toca
        {"mount": "/data", "usagePct": 92.0},   # nueva: se abre
    ]
    outcome = evaluate(_metrics(disk=disk), {}, open_kinds, THRESHOLDS)
    assert len(outcome.to_open) == 1
    assert outcome.to_open[0].metric == "disk./data"


def test_missing_metric_value_is_ignored():
    outcome = evaluate({"cpu": {}, "memory": {}, "disk": []}, {}, set(), THRESHOLDS)
    assert outcome.to_open == []
    assert outcome.to_resolve == []


def test_metric_without_configured_threshold_is_ignored():
    outcome = evaluate(_metrics(cpu=99.0), {}, set(), {"cpuPct": None})
    assert outcome.to_open == []
