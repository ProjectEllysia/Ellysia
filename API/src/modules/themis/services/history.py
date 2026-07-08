"""
Historical statistics for Themis scans.

This module computes the chart-ready payload that describes how a host has
evolved across the user's last *N* scans. It is the single source of truth
shared by the REST endpoint (web statistics tab) and the PDF report
(``reports.py``), so the logic lives in exactly one place.

The per-tool difference — *what counts as a finding and what is its identity* —
is isolated in small ``MetricExtractor`` strategies (Open/Closed): adding a new
scan tool only requires registering a new extractor, without touching the
service or its consumers.

Classes:
    MetricExtractor:        Abstract per-tool finding extractor.
    NmapMetricExtractor:    Open ports as the metric.
    NiktoMetricExtractor:   Web incidents as the metric.
    OpenVASMetricExtractor: Vulnerabilities as the metric.
    HistoryStatsService:    Builds the serializable chart payload from a scan list.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Set, Type

from ..model import NiktoScan, NmapScan, OpenVASScan, Scan, ScanType

logger = logging.getLogger(__name__)


# =========================================================================
# METRIC EXTRACTORS (one per scan tool)
# =========================================================================

class MetricExtractor(ABC):
    """Strategy that turns a scan into a measurable set of findings.

    Subclasses define what the chart metric *is* for a given tool (open ports,
    incidents, vulnerabilities) and how to identify a single finding so that two
    scans can be diffed (new / unchanged / disappeared).
    """

    #: Human label of the metric, e.g. "Puertos abiertos".
    metric_label: str = "Hallazgos"

    _registry: Dict[ScanType, Type["MetricExtractor"]] = {}

    @classmethod
    def register(cls, scan_type: ScanType):
        def decorator(subclass: Type["MetricExtractor"]):
            cls._registry[scan_type] = subclass
            return subclass
        return decorator

    @classmethod
    def resolve(cls, scan_type: ScanType) -> "MetricExtractor":
        extractor_cls = cls._registry.get(scan_type)
        if extractor_cls is None:
            raise ValueError(f"No hay extractor de métrica para: {scan_type}")
        return extractor_cls()

    @abstractmethod
    def identities(self, scan: Scan) -> Set[str]:
        """Return the set of unique finding identifiers for a scan."""
        raise NotImplementedError

    def count(self, scan: Scan) -> int:
        """Number of distinct findings in a scan."""
        return len(self.identities(scan))


@MetricExtractor.register(ScanType.NMAP)
class NmapMetricExtractor(MetricExtractor):
    """Metric: open ports. Identity: the port protocol string (e.g. ``80/tcp``)."""

    metric_label = "Puertos abiertos"

    def identities(self, scan: NmapScan) -> Set[str]:
        return {
            op.port.protocol
            for op in (scan.open_ports_relation or [])
            if op.port is not None
        }


@MetricExtractor.register(ScanType.NIKTO)
class NiktoMetricExtractor(MetricExtractor):
    """Metric: web incidents. Identity mirrors ``get_or_create_nikto_incident``."""

    metric_label = "Incidencias"

    def identities(self, scan: NiktoScan) -> Set[str]:
        return {
            f"{inc.method}|{inc.url}|{inc.description}"
            for inc in (scan.incidents or [])
        }


@MetricExtractor.register(ScanType.OPENVAS)
class OpenVASMetricExtractor(MetricExtractor):
    """Metric: vulnerabilities. Identity: the NVT OID."""

    metric_label = "Vulnerabilidades"

    def identities(self, scan: OpenVASScan) -> Set[str]:
        return {
            res.vulnerability.nvt_oid
            for res in (scan.results or [])
            if res.vulnerability is not None
        }


# =========================================================================
# SERVICE
# =========================================================================

class HistoryStatsService:
    """Builds a chart-ready payload from a chronological list of scans.

    The payload bundles everything a renderer needs (axis labels, axis step,
    series points and a diff legend) so both the web chart and the PDF chart
    consume the exact same structure.
    """

    _X_AXIS_LABEL = "Escaneo (fecha)"

    def build(self, scans: List[Scan], scan_type: ScanType, target: str) -> dict:
        """Compute the statistics payload.

        Args:
            scans:     Scans ordered ascending (oldest -> newest), same
                       user + target + scan_type, only finished ones.
            scan_type: The tool discriminator.
            target:    The scanned host.

        Returns:
            A JSON-serializable dict (see module docstring / endpoint schema).
        """
        scan_type = ScanType(scan_type)
        extractor = MetricExtractor.resolve(scan_type)
        label = extractor.metric_label

        points = []
        x_values = []
        for scan in scans:
            when = (
                scan.started_at.strftime("%Y-%m-%d %H:%M")
                if scan.started_at else "N/A"
            )
            x_values.append(when)
            points.append({
                "x": when,
                "y": extractor.count(scan),
                "scanId": scan.id,
            })

        max_value = max((p["y"] for p in points), default=0)
        diff = self._compute_diff(scans, extractor)

        return {
            "scanType": scan_type.value,
            "target": target,
            "metricLabel": label,
            "axes": {
                "x": {"label": self._X_AXIS_LABEL, "values": x_values},
                "y": {"label": label, "step": self._nice_step(max_value), "max": max_value},
            },
            "series": [{"name": label, "points": points}],
            "diff": diff,
            "legend": [
                {"label": "Nuevos", "value": diff["new"]},
                {"label": "Iguales", "value": diff["unchanged"]},
                {"label": "Desaparecidos", "value": diff["disappeared"]},
            ],
            "scanCount": len(scans),
        }

    @staticmethod
    def _compute_diff(scans: List[Scan], extractor: MetricExtractor) -> dict:
        """Diff the most recent scan against the immediately previous one."""
        empty = {
            "new": 0, "unchanged": 0, "disappeared": 0,
            "currentScanId": None, "previousScanId": None,
        }
        if len(scans) < 2:
            if scans:
                empty["currentScanId"] = scans[-1].id
            return empty

        previous, current = scans[-2], scans[-1]
        prev_ids = extractor.identities(previous)
        cur_ids = extractor.identities(current)

        return {
            "new": len(cur_ids - prev_ids),
            "unchanged": len(cur_ids & prev_ids),
            "disappeared": len(prev_ids - cur_ids),
            "currentScanId": current.id,
            "previousScanId": previous.id,
        }

    @staticmethod
    def _nice_step(max_value: int) -> int:
        """Pick a readable Y-axis step for the given maximum value."""
        if max_value <= 10:
            return 1
        if max_value <= 50:
            return 5
        if max_value <= 100:
            return 10
        if max_value <= 500:
            return 50
        return 100
