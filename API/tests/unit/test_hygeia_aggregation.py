"""Tests unitarios de hygeia.services.aggregation.denormalize (escalares por snapshot)."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.modules.features.hygeia.repositories import AssetSnapshotRepository
from src.modules.features.hygeia.services.aggregation import denormalize

pytestmark = pytest.mark.unit


def _linux_metrics():
    """Payload completo tal como lo manda un agente en Linux."""
    return {
        "cpu": {
            "usagePct": 87.5,
            "loadAvg": [2.1, 1.8, 1.5],
            "ctxSwitches": 12345,
            "perCorePct": [88.0, 91.0, 80.0, 90.0],
        },
        "memory": {
            "totalBytes": 16_000_000_000,
            "usedBytes": 9_000_000_000,
            "usagePct": 56.25,
            "swapUsedPct": 12.5,
        },
        "disk": [
            {"mount": "/", "usagePct": 62.0, "freeBytes": 50_000_000_000},
            {"mount": "/data", "usagePct": 91.2, "freeBytes": 5_000_000_000},
            {"mount": "/boot", "usagePct": 30.0, "freeBytes": 400_000_000},
        ],
        "network": [
            {"iface": "lo", "rxBytesPerSec": 999_999, "txBytesPerSec": 999_999},
            {"iface": "eth0", "rxBytesPerSec": 120_000, "txBytesPerSec": 45_000},
            {"iface": "eth1", "rxBytesPerSec": 30_000, "txBytesPerSec": 5_000},
        ],
        "processes": {"total": 210, "zombie": 1, "topCpu": [], "topMem": []},
    }


def test_linux_payload_extracts_every_scalar():
    result = denormalize(_linux_metrics())

    assert result["cpu_pct"] == 87.5
    assert result["mem_pct"] == 56.25
    assert result["swap_pct"] == 12.5
    assert result["load1"] == 2.1
    assert result["disk_max_pct"] == 91.2
    assert result["disk_max_mount"] == "/data"
    # 120_000 + 30_000, sin la loopback.
    assert result["net_rx_bps"] == 150_000
    assert result["net_tx_bps"] == 50_000


def test_returned_keys_match_snapshot_columns():
    """Las claves se expanden con ** en el constructor de AssetSnapshot."""
    assert set(denormalize(_linux_metrics())) == {
        "cpu_pct", "mem_pct", "swap_pct", "load1",
        "disk_max_pct", "disk_max_mount", "net_rx_bps", "net_tx_bps",
    }


def test_windows_payload_leaves_absent_blocks_as_none():
    """Windows no reporta loadAvg ni swap, y puede no reportar red."""
    metrics = {
        "cpu": {"usagePct": 40.0, "loadAvg": [], "perCorePct": [40.0, 40.0]},
        "memory": {"usagePct": 55.0},
        "disk": [{"mount": "C:\\", "usagePct": 70.0}],
        "network": [],
    }
    result = denormalize(metrics)

    assert result["cpu_pct"] == 40.0
    assert result["mem_pct"] == 55.0
    assert result["load1"] is None
    assert result["swap_pct"] is None
    assert result["net_rx_bps"] is None
    assert result["net_tx_bps"] is None
    assert result["disk_max_pct"] == 70.0


def test_empty_disk_gives_none_not_zero():
    result = denormalize({"cpu": {"usagePct": 1.0}, "memory": {"usagePct": 2.0}, "disk": []})
    assert result["disk_max_pct"] is None
    assert result["disk_max_mount"] is None


def test_disk_picks_the_max_not_the_first():
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "disk": [
            {"mount": "/first", "usagePct": 10.0},
            {"mount": "/fullest", "usagePct": 95.0},
            {"mount": "/last", "usagePct": 50.0},
        ],
    }
    result = denormalize(metrics)
    assert result["disk_max_pct"] == 95.0
    assert result["disk_max_mount"] == "/fullest"


def test_disk_ignores_mounts_without_usage():
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "disk": [
            {"mount": "/no-reading", "usagePct": None},
            {"mount": "/real", "usagePct": 33.0},
        ],
    }
    result = denormalize(metrics)
    assert result["disk_max_pct"] == 33.0
    assert result["disk_max_mount"] == "/real"


@pytest.mark.parametrize("iface", ["lo", "lo0", "LO", "Loopback Pseudo-Interface 1"])
def test_loopback_interfaces_are_excluded(iface):
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "network": [
            {"iface": iface, "rxBytesPerSec": 500, "txBytesPerSec": 500},
            {"iface": "eth0", "rxBytesPerSec": 100, "txBytesPerSec": 200},
        ],
    }
    result = denormalize(metrics)
    assert result["net_rx_bps"] == 100
    assert result["net_tx_bps"] == 200


@pytest.mark.parametrize("iface", ["lom0", "lon0", "loop-vpn0"])
def test_real_interfaces_starting_with_lo_are_not_excluded(iface):
    """`startswith("lo")` se llevaría por delante interfaces reales."""
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "network": [{"iface": iface, "rxBytesPerSec": 700, "txBytesPerSec": 300}],
    }
    result = denormalize(metrics)
    assert result["net_rx_bps"] == 700
    assert result["net_tx_bps"] == 300


def test_network_without_any_reading_is_none_not_zero():
    """Un 0 falso pintaría una línea plana afirmando un dato que nadie midió."""
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "network": [
            {"iface": "eth0", "rxBytesPerSec": None, "txBytesPerSec": None},
            {"iface": "eth1", "rxBytesPerSec": None, "txBytesPerSec": None},
        ],
    }
    result = denormalize(metrics)
    assert result["net_rx_bps"] is None
    assert result["net_tx_bps"] is None


def test_network_with_real_zero_stays_zero():
    """Contrapunto del anterior: reportar 0 tráfico sí es un dato."""
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "network": [{"iface": "eth0", "rxBytesPerSec": 0, "txBytesPerSec": 0}],
    }
    result = denormalize(metrics)
    assert result["net_rx_bps"] == 0
    assert result["net_tx_bps"] == 0


def test_partial_network_readings_sum_what_exists():
    metrics = {
        "cpu": {"usagePct": 1.0},
        "memory": {"usagePct": 2.0},
        "network": [
            {"iface": "eth0", "rxBytesPerSec": 1000, "txBytesPerSec": None},
            {"iface": "eth1", "rxBytesPerSec": None, "txBytesPerSec": 250},
        ],
    }
    result = denormalize(metrics)
    assert result["net_rx_bps"] == 1000
    assert result["net_tx_bps"] == 250


def test_empty_payload_yields_all_none():
    """Defensa en el borde: nada explota si el payload llega vacío."""
    assert all(value is None for value in denormalize({}).values())


def test_bucketed_series_accepts_postgres_decimal_bucket_ids():
    """PostgreSQL devuelve Decimal para FLOOR(EXTRACT(...))."""
    query = Mock()
    query.filter.return_value = query
    query.group_by.return_value = query
    query.order_by.return_value = query
    query.limit.return_value = query
    query.all.return_value = [SimpleNamespace(
        bucket_id=Decimal("29793074"),
        cpu_pct=12.5,
        mem_pct=None,
        swap_pct=None,
        load1=None,
        disk_max_pct=None,
        net_rx_bps=None,
        net_tx_bps=None,
    )]

    repository = AssetSnapshotRepository(session=Mock(query=Mock(return_value=query)))

    points = repository.get_series_bucketed(1, 60)

    assert points[0]["cpuPct"] == 12.5
