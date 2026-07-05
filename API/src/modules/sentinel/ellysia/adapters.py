"""Adapters: turn Nikto/OpenVAS raw results into normalized Finding dicts.

Nikto and OpenVAS keep writing their own tables exactly as before (their PDF
reports and history charts read those, untouched) — these adapters are an
**additive** second write, giving every scanner a presence in the shared
``Finding`` table so a future cross-scanner correlation pass (Fase 6: "lanzar
Nmap/Nikto/OpenVAS y fusionar") has something to fuse. The same duplication the
project already accepted for Nmap (``OpenPort`` stays, plus an informational
Finding) applied here to two scanners whose PDF/report code has no test
coverage to safely rewrite in one pass.

No lifecycle (``apply_lifecycle``) or merge (``merge_findings``) is wired for
these two scanners here — that stays an Ellysia-scan-only concern until a
correlation pass that spans scan types exists (Fase 6). Only ``dedup_key`` is
computed, so that future pass has a stable key to group by.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional


# Nikto's own severity classification (_classify_threat_level) is a pattern
# match on the response text, not a structured assertion — so confirmed=False
# throughout, with qod scaled by how strong that pattern match is.
_NIKTO_SEVERITY_QOD = {
    "CRITICAL": 85,
    "HIGH":     80,
    "MEDIUM":   60,
    "LOW":      40,
    "INFO":     30,
}

# Fallback when an NVT doesn't carry its own qod_value.
_OPENVAS_SEVERITY_QOD = {
    "Critical": 80,
    "High":     80,
    "Medium":   60,
    "Low":      40,
    "Log":      30,
}


def nikto_incident_to_finding(inc: dict) -> dict:
    """Adapt one Nikto incident dict (as produced by ``NiktoResultProcessor``)
    into a Finding dict. Caller still attaches ``host_id`` and ``dedup_key``.
    """
    method = (inc.get("method") or "").strip()
    url = (inc.get("url") or "").strip()
    description = (inc.get("description") or "").strip()
    severity = (inc.get("severity") or "LOW").upper()
    osvdb_id = inc.get("osvdb_id") or ""

    title = f"{method} {url}: {description}".strip() if (method or url) else description
    check_id = f"nikto:{osvdb_id}" if osvdb_id else f"nikto:{_stable_hash(method, url, description)}"

    return {
        "title":     title or "Hallazgo Nikto",
        "category":  "web_finding",
        "port":      None,   # Nikto's own persistence never populates a port either
        "service":   "http",
        "source":    "nikto",
        "check_id":  check_id,
        "qod":       _NIKTO_SEVERITY_QOD.get(severity, 30),
        "confirmed": False,  # pattern match on text, not a structured assertion
        "state":     "open",
    }


def openvas_result_to_finding(vuln, result: dict) -> dict:
    """Adapt one OpenVAS scan result + its vulnerability into a Finding dict.

    ``vuln`` is the ``OpenVASVulnerability`` row (or any object exposing the
    same attributes via ``getattr`` — duck-typed like
    :func:`~.engine.services_from_open_ports`). ``result`` is one entry of
    ``scan_results_data`` (``nvt_oid``/``host_ip``/``port``/``threat``). Caller
    still attaches ``host_id`` and ``dedup_key``.
    """
    cve_ids_raw = getattr(vuln, "cve_ids", None)
    cve_ids = [c.strip() for c in cve_ids_raw.split(",") if c.strip()] if cve_ids_raw else None

    severity_class = getattr(vuln, "severity_class", None)
    qod_value = getattr(vuln, "qod_value", None)
    qod = qod_value if qod_value is not None else _OPENVAS_SEVERITY_QOD.get(severity_class, 30)

    return {
        "title":        getattr(vuln, "name", None) or "Hallazgo OpenVAS",
        "category":     "outdated_software" if cve_ids else "vulnerability",
        "port":         _parse_port(result.get("port")),
        "service":      None,
        "cve_ids":      cve_ids,
        "cvss_score":   getattr(vuln, "cvss_base_score", None) or getattr(vuln, "severity_score", None),
        "cvss_vector":  getattr(vuln, "cvss_vector", None),
        "source":       "openvas",
        "check_id":     f"openvas:{getattr(vuln, 'nvt_oid', 'unknown')}",
        "qod":          qod,
        "confirmed":    qod >= 80,  # OpenVAS's own QoD ladder: banner ~30-80, exploit-based ~99
        "state":        "open",
    }


def _parse_port(port_str: Optional[str]) -> Optional[int]:
    """"80/tcp" -> 80; "general/tcp" or None -> None (best-effort, never raises)."""
    if not port_str:
        return None
    digits = port_str.split("/", 1)[0]
    return int(digits) if digits.isdigit() else None


def _stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
