"""Tests unitarios de los MetricExtractor por tipo de escaneo (sin BD ni Flask).

``MetricExtractor`` es puro dado un objeto scan con los atributos que espera
(``findings``, ``open_ports_relation``... según el tipo) — no toca la sesión
de SQLAlchemy, así que se cubre aquí con objetos falsos en vez de un scan real.
"""

from dataclasses import dataclass
from typing import Optional

import pytest

from src.modules.features.themis.model import ScanType
from src.modules.features.themis.services.history import LybraMetricExtractor, MetricExtractor

pytestmark = pytest.mark.unit


@dataclass
class _FakeFinding:
    id: int
    dedup_key: Optional[str] = None


@dataclass
class _FakeScan:
    findings: list


def test_lybra_extractor_is_registered_for_its_scan_type():
    """Regresión: Lybra no tenía extractor propio, así que el historial no
    tenía ninguna métrica que mostrar para sus escaneos."""
    assert isinstance(MetricExtractor.resolve(ScanType.LYBRA), LybraMetricExtractor)


def test_lybra_extractor_identifies_findings_by_dedup_key():
    scan = _FakeScan(findings=[
        _FakeFinding(id=1, dedup_key="host:80:cve-2021-41773"),
        _FakeFinding(id=2, dedup_key="host:80:cve-2021-41773"),  # mismo hallazgo, dos fuentes
        _FakeFinding(id=3, dedup_key="host:22:cve-9999"),
    ])
    extractor = LybraMetricExtractor()

    assert extractor.identities(scan) == {"host:80:cve-2021-41773", "host:22:cve-9999"}
    assert extractor.count(scan) == 2


def test_lybra_extractor_falls_back_to_row_id_without_dedup_key():
    scan = _FakeScan(findings=[_FakeFinding(id=1, dedup_key=None)])
    extractor = LybraMetricExtractor()

    assert extractor.identities(scan) == {"finding:1"}


def test_lybra_extractor_handles_scan_with_no_findings():
    assert LybraMetricExtractor().identities(_FakeScan(findings=[])) == set()
