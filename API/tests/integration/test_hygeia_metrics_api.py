"""
Tests de integración HTTP de los endpoints de métricas de Hygeia.

Cubren la serie temporal (``GET /hygeia/assets/<id>/metrics``) y el último
heartbeat completo (``.../metrics/latest``): recorte por la cola, orden,
eje temporal, proyección de campos y propiedad del activo.

La serie se siembra escribiendo filas ``AssetSnapshot`` por repositorio, no
vía ``POST /hygeia/ingest``: el suelo de cadencia (``_enforce_min_interval``)
rechaza heartbeats consecutivos rápidos, así que por HTTP no se puede
construir una serie densa.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.features.hygeia.model import AssetSnapshot, MonitoredAsset
from src.modules.features.hygeia.repositories import (
    AssetSnapshotRepository,
    MonitoredAssetRepository,
)

pytestmark = pytest.mark.integration

# Debe coincidir con hygeia.limits.maxSeriesPoints de SecOpsConfig.json.
_MAX_POINTS = 1000


def _metrics(cpu=10.0, mem=20.0):
    """Payload completo, con todos los bloques que el agente puede mandar."""
    return {
        "cpu": {
            "usagePct": cpu,
            "loadAvg": [1.5, 1.2, 0.9],
            "ctxSwitches": 4242,
            "perCorePct": [11.0, 9.0, 12.0, 8.0],
        },
        "memory": {
            "totalBytes": 8_000_000_000,
            "usedBytes": 1_600_000_000,
            "usagePct": mem,
            "swapUsedPct": 3.5,
        },
        "disk": [
            {"mount": "/", "usagePct": 41.0, "freeBytes": 60_000_000_000},
            {"mount": "/data", "usagePct": 72.0, "freeBytes": 9_000_000_000},
        ],
        "network": [
            {"iface": "lo", "rxBytesPerSec": 5_000, "txBytesPerSec": 5_000},
            {"iface": "eth0", "rxBytesPerSec": 120_000, "txBytesPerSec": 45_000,
             "errIn": 0, "errOut": 2},
        ],
        "processes": {
            "total": 210,
            "zombie": 1,
            "topCpu": [{"pid": 8123, "name": "nginx", "cpuPct": 12.5, "memPct": None}],
            "topMem": [{"pid": 991, "name": "postgres", "cpuPct": None, "memPct": 31.0}],
        },
    }


def _create_asset(app, user_id: int, hostname: str = "metrics-test") -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            asset = MonitoredAsset(
                hostname=hostname,
                agent_key_id=secrets.token_hex(8),
                agent_key_hash="dummy",
                heartbeat_interval_sec=15,
                status="online",
                last_seen_at=utcnow_naive(),
                user_id=user_id,
            )
            MonitoredAssetRepository(uow).save(asset)
            return asset.id


def _seed_snapshots(app, asset_id: int, count: int, *, step_sec: int = 15, **overrides):
    """Siembra ``count`` snapshots consecutivos, el último en el instante actual.

    Returns:
        Lista de los ``received_at`` sembrados, de más antiguo a más reciente.
    """
    now = utcnow_naive()
    stamps = [now - timedelta(seconds=step_sec * (count - 1 - i)) for i in range(count)]

    with app.app_context():
        with UnitOfWork() as uow:
            repo = AssetSnapshotRepository(uow)
            for index, stamp in enumerate(stamps):
                fields = {
                    "asset_id": asset_id,
                    "collected_at": stamp,
                    "received_at": stamp,
                    "metrics": _metrics(cpu=float(index % 100)),
                    "cpu_pct": float(index % 100),
                    "mem_pct": 20.0,
                    "swap_pct": 3.5,
                    "load1": 1.5,
                    "disk_max_pct": 72.0,
                    "disk_max_mount": "/data",
                    "net_rx_bps": 120_000,
                    "net_tx_bps": 45_000,
                }
                fields.update(overrides)
                repo.save(AssetSnapshot(**fields))
    return stamps


# =============================================================================
# SERIE TEMPORAL
# =============================================================================

def test_series_returns_the_most_recent_points_not_the_oldest(client, app, regular_user, auth_headers):
    """Regresión: un ORDER BY ASC + LIMIT devolvía las primeras horas de vida del activo."""
    asset_id = _create_asset(app, regular_user.id)
    stamps = _seed_snapshots(app, asset_id, _MAX_POINTS + 50)

    resp = client.get(f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user))

    assert resp.status_code == 200
    snapshots = resp.get_json()["snapshots"]
    assert len(snapshots) == _MAX_POINTS

    # El último punto devuelto es el heartbeat más reciente sembrado, no el
    # punto número 1000 contando desde el principio del histórico.
    newest = stamps[-1].isoformat()
    assert snapshots[-1]["receivedAt"].startswith(newest[:19])


def test_series_flags_truncation(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, _MAX_POINTS + 10)

    resp = client.get(f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user))
    assert resp.get_json()["truncated"] is True


def test_series_not_flagged_when_it_fits(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 5)

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()

    assert len(body["snapshots"]) == 5
    assert body["truncated"] is False


def test_series_is_ordered_oldest_to_newest(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 20)

    snapshots = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()["snapshots"]

    stamps = [s["receivedAt"] for s in snapshots]
    assert stamps == sorted(stamps)


def test_series_orders_by_received_at_not_collected_at(client, app, regular_user, auth_headers):
    """Un agente con el reloj adelantado no debe colarse al final de la serie."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 5)

    now = utcnow_naive()
    with app.app_context():
        with UnitOfWork() as uow:
            AssetSnapshotRepository(uow).save(AssetSnapshot(
                asset_id=asset_id,
                # Reloj del agente una hora adelantado, recepción muy anterior
                # a la del resto de la serie.
                collected_at=now + timedelta(hours=1),
                received_at=now - timedelta(hours=2),
                metrics=_metrics(),
                cpu_pct=99.0,
            ))

    snapshots = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()["snapshots"]

    assert len(snapshots) == 6
    assert snapshots[0]["cpuPct"] == 99.0     # el más viejo por recepción, el primero
    assert snapshots[-1]["cpuPct"] != 99.0


def test_series_point_exposes_every_denormalized_scalar(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 1)

    point = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()["snapshots"][0]

    assert point["cpuPct"] == 0.0
    assert point["memPct"] == 20.0
    assert point["swapPct"] == 3.5
    assert point["load1"] == 1.5
    assert point["diskMaxPct"] == 72.0
    assert point["diskMaxMount"] == "/data"
    assert point["netRxBps"] == 120_000
    assert point["netTxBps"] == 45_000


def test_series_point_never_carries_the_full_payload(client, app, regular_user, auth_headers):
    """El JSONB completo por punto multiplicaría el peso de la respuesta sin aportar nada."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 3)

    snapshots = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()["snapshots"]

    assert all("metrics" not in point for point in snapshots)


def test_series_tolerates_rows_without_the_new_columns(client, app, regular_user, auth_headers):
    """Filas anteriores a la migración: los escalares nuevos llegan a null, sin romper."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(
        app, asset_id, 2,
        swap_pct=None, load1=None, disk_max_pct=None,
        disk_max_mount=None, net_rx_bps=None, net_tx_bps=None,
    )

    resp = client.get(f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user))

    assert resp.status_code == 200
    point = resp.get_json()["snapshots"][0]
    assert point["netRxBps"] is None
    assert point["load1"] is None
    assert point["cpuPct"] is not None


def test_series_of_asset_without_snapshots_is_empty(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()

    assert body["snapshots"] == []
    assert body["truncated"] is False


# =============================================================================
# ÚLTIMAS MÉTRICAS COMPLETAS
# =============================================================================

def test_latest_returns_the_whole_payload(client, app, regular_user, auth_headers):
    """Lo que la serie temporal no cabe: disco, red, procesos y núcleos."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 3)

    resp = client.get(
        f"/hygeia/assets/{asset_id}/metrics/latest", headers=auth_headers(regular_user)
    )

    assert resp.status_code == 200
    metrics = resp.get_json()["metrics"]

    assert [d["mount"] for d in metrics["disk"]] == ["/", "/data"]
    assert [n["iface"] for n in metrics["network"]] == ["lo", "eth0"]
    assert metrics["network"][1]["errOut"] == 2
    assert metrics["cpu"]["perCorePct"] == [11.0, 9.0, 12.0, 8.0]
    assert metrics["cpu"]["loadAvg"] == [1.5, 1.2, 0.9]
    assert metrics["processes"]["total"] == 210
    assert metrics["processes"]["topCpu"][0]["name"] == "nginx"
    assert metrics["processes"]["topMem"][0]["name"] == "postgres"
    assert metrics["memory"]["totalBytes"] == 8_000_000_000


def test_latest_returns_the_newest_snapshot(client, app, regular_user, auth_headers):
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 4)

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics/latest", headers=auth_headers(regular_user)
    ).get_json()

    # _seed_snapshots numera la CPU por índice: el último sembrado es el 3.
    assert body["metrics"]["cpu"]["usagePct"] == 3.0


def test_latest_on_asset_without_snapshots_is_200_with_nulls(client, app, regular_user, auth_headers):
    """Un activo dado de alta que aún no ha latido es un estado legítimo, no un 404."""
    asset_id = _create_asset(app, regular_user.id)

    resp = client.get(
        f"/hygeia/assets/{asset_id}/metrics/latest", headers=auth_headers(regular_user)
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["metrics"] is None
    assert body["collectedAt"] is None
    assert body["receivedAt"] is None


# =============================================================================
# SERIE AGREGADA POR CUBOS (bucket) — ventanas largas sin recortar
# =============================================================================

def test_series_bucketed_one_point_per_bucket_with_max(client, app, regular_user, auth_headers):
    """Un punto por cubo, con el máximo de cada métrica dentro del cubo.

    La alineación de los cubos depende del segundo exacto del reloj en el
    momento de sembrar, así que el recuento y los máximos se calculan contra
    los propios ``received_at`` sembrados, no contra constantes.
    """
    asset_id = _create_asset(app, regular_user.id)
    stamps = _seed_snapshots(app, asset_id, 300)  # 300 × 15 s ≈ 75 min

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket=60", headers=auth_headers(regular_user)
    ).get_json()

    assert body["bucket"] == 60
    assert body["truncated"] is False

    def utc_epoch(t):
        return t.replace(tzinfo=timezone.utc).timestamp()

    first_bucket = int(utc_epoch(stamps[0]) // 60)
    expected = int(utc_epoch(stamps[-1]) // 60) - first_bucket + 1
    assert len(body["snapshots"]) == expected

    # El índice numera la CPU por snapshot (i % 100): cada cubo debe llevar
    # el valor más alto entre los snapshots que caen dentro de su minuto.
    for offset, point in enumerate(body["snapshots"]):
        bucket_no = first_bucket + offset
        in_bucket = [
            i % 100 for i, stamp in enumerate(stamps)
            if int(utc_epoch(stamp) // 60) == bucket_no
        ]
        assert point["cpuPct"] == max(in_bucket)
        # La memoria es constante 20.0: el máximo por cubo la conserva.
        assert point["memPct"] == 20.0


def test_series_bucketed_points_are_bucket_starts_and_ordered(client, app, regular_user, auth_headers):
    """El instante del punto es el inicio del cubo, y la serie va en orden.

    La alineación de los cubos depende del segundo exacto del reloj en el
    momento de sembrar (ver test_series_bucketed_one_point_per_bucket_with_max),
    así que el recuento esperado se calcula contra los propios ``received_at``
    sembrados, no contra una constante.
    """
    asset_id = _create_asset(app, regular_user.id)
    stamps = _seed_snapshots(app, asset_id, 10)  # 10 × 15 s = 2,5 min

    snapshots = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket=60", headers=auth_headers(regular_user)
    ).get_json()["snapshots"]

    def utc_epoch(t):
        return t.replace(tzinfo=timezone.utc).timestamp()

    expected = int(utc_epoch(stamps[-1]) // 60) - int(utc_epoch(stamps[0]) // 60) + 1
    assert len(snapshots) == expected
    received = [datetime.fromisoformat(s["receivedAt"]).replace(tzinfo=None) for s in snapshots]
    collected = [datetime.fromisoformat(s["collectedAt"]).replace(tzinfo=None) for s in snapshots]

    # Alineados al minuto (inicio de cubo) y en orden cronológico.
    assert all(t.second == 0 and t.microsecond == 0 for t in received)
    assert received == sorted(received)
    # El primero es el suelo del snapshot más antiguo; el último, el del más reciente.
    assert received[0] == stamps[0].replace(second=0, microsecond=0)
    assert received[-1] == stamps[-1].replace(second=0, microsecond=0)
    # El punto sintético usa el mismo instante en ambos ejes.
    assert received == collected


def test_series_bucketed_omits_empty_buckets(client, app, regular_user, auth_headers):
    """Un cubo sin heartbeats no existe: la ausencia es el dato de la caída."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 2, step_sec=3600)  # dos puntos a una hora

    snapshots = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket=60", headers=auth_headers(regular_user)
    ).get_json()["snapshots"]

    assert len(snapshots) == 2


def test_series_bucketed_respects_from(client, app, regular_user, auth_headers):
    """La ventana ``from`` se aplica igual sobre los cubos."""
    asset_id = _create_asset(app, regular_user.id)
    stamps = _seed_snapshots(app, asset_id, 300)  # 75 min de histórico

    since = stamps[0] + timedelta(seconds=1800)  # últimos 30 min

    def utc_epoch(t):
        return t.replace(tzinfo=timezone.utc).timestamp()

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket=60&from={since.isoformat()}",
        headers=auth_headers(regular_user),
    ).get_json()

    expected = int(utc_epoch(stamps[-1]) // 60) - int(utc_epoch(since) // 60) + 1
    assert len(body["snapshots"]) == expected
    first = datetime.fromisoformat(body["snapshots"][0]["receivedAt"]).replace(tzinfo=None)
    assert first >= since.replace(second=0, microsecond=0)


def test_series_bucketed_drops_disk_max_mount(client, app, regular_user, auth_headers):
    """En modo agregado el montaje del máximo no viaja: llega null, sin romper."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 5)

    point = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket=60", headers=auth_headers(regular_user)
    ).get_json()["snapshots"][0]

    assert point["diskMaxPct"] == 72.0
    assert point["diskMaxMount"] is None


def test_series_bucketed_echoes_null_in_raw_mode(client, app, regular_user, auth_headers):
    """Sin ``bucket``, la respuesta lo dice: la serie es cruda."""
    asset_id = _create_asset(app, regular_user.id)
    _seed_snapshots(app, asset_id, 5)

    body = client.get(
        f"/hygeia/assets/{asset_id}/metrics", headers=auth_headers(regular_user)
    ).get_json()

    assert body["bucket"] is None
    assert len(body["snapshots"]) == 5


@pytest.mark.parametrize("bucket", ["0", "-30", "1.5", "abc"])
def test_series_bucketed_rejects_invalid_bucket(client, app, regular_user, auth_headers, bucket):
    asset_id = _create_asset(app, regular_user.id)

    resp = client.get(
        f"/hygeia/assets/{asset_id}/metrics?bucket={bucket}", headers=auth_headers(regular_user)
    )

    assert resp.status_code == 422


# =============================================================================
# PROPIEDAD Y AUTENTICACIÓN
# =============================================================================

@pytest.mark.parametrize("suffix", ["", "/latest"])
def test_metrics_of_another_users_asset_is_404(client, app, make_user, auth_headers, suffix):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")
    asset_id = _create_asset(app, owner.id)
    _seed_snapshots(app, asset_id, 2)

    resp = client.get(
        f"/hygeia/assets/{asset_id}/metrics{suffix}", headers=auth_headers(other)
    )

    assert resp.status_code == 404


@pytest.mark.parametrize("suffix", ["", "/latest"])
def test_metrics_without_token_is_401(client, app, regular_user, suffix):
    asset_id = _create_asset(app, regular_user.id)

    assert client.get(f"/hygeia/assets/{asset_id}/metrics{suffix}").status_code == 401
