"""Adapters that give Nikto and OpenVAS a presence in the shared Finding table.

Nikto and OpenVAS still write their own result tables exactly as they always
have — their PDF reports and history charts read from those, and are left
untouched. What these adapters add is a *second*, additive write: for each Nikto
incident or OpenVAS result, a normalized :class:`Finding` row is also produced,
so every scanner shows up in one shared table and the deep-analysis correlation
pass has something to fuse together.

This mirrors a duplication the project already accepted for Nmap, where the
``OpenPort`` rows stay put and an informational Finding is written alongside
them. A full replacement — making Nikto and OpenVAS stop writing their own tables
— was ruled out because their report/chart code has no test coverage and could
not be rewritten safely in a single pass.

These adapters only build the finding dicts and compute nothing about lifecycle
or merging; the caller attaches ``host_id`` and ``dedup_key`` and persists them.
"""

from __future__ import annotations

import hashlib
from typing import Optional


# Nikto's severity classification (its ``_classify_threat_level``) is a pattern
# match against the response text, not a structured assertion — so its findings
# are never marked confirmed, and their QoD is scaled by how strong the matched
# pattern is.
_NIKTO_SEVERITY_QOD = {
    "CRITICAL": 85,
    "HIGH":     80,
    "MEDIUM":   60,
    "LOW":      40,
    "INFO":     30,
}

# Fallback QoD for an OpenVAS result whose NVT does not carry its own qod_value.
_OPENVAS_SEVERITY_QOD = {
    "Critical": 80,
    "High":     80,
    "Medium":   60,
    "Low":      40,
    "Log":      30,
}


def nikto_incident_to_finding(inc: dict) -> dict:
    """Adapt one Nikto incident into a Finding dict.

    Args:
        inc: An incident dict as produced by ``NiktoResultProcessor`` (with
            ``method`` / ``url`` / ``description`` / ``severity`` / ``osvdb_id``).

    Returns:
        A dict of ``Finding`` column values. The caller still attaches
        ``host_id`` and ``dedup_key`` before persisting.
    """
    method = (inc.get("method") or "").strip()
    url = (inc.get("url") or "").strip()
    description = (inc.get("description") or "").strip()
    severity = (inc.get("severity") or "LOW").upper()
    osvdb_id = inc.get("osvdb_id") or ""

    title = f"{method} {url}: {description}".strip() if (method or url) else description
    # Prefer the OSVDB id as a stable check id; when Nikto did not provide one,
    # fall back to a hash of the incident's identifying fields so the same
    # incident keeps the same check id across scans.
    check_id = f"nikto:{osvdb_id}" if osvdb_id else f"nikto:{_stable_hash(method, url, description)}"

    return {
        "title":     title or "Hallazgo Nikto",
        "category":  "web_finding",
        "port":      None,   # Nikto's own persistence does not record a port either
        "service":   "http",
        "source":    "nikto",
        "check_id":  check_id,
        "qod":       _NIKTO_SEVERITY_QOD.get(severity, 30),
        "confirmed": False,  # a text pattern match, not a structured assertion
        "state":     "open",
    }


def openvas_result_to_finding(vuln, result: dict) -> dict:
    """Adapt one OpenVAS result plus its vulnerability into a Finding dict.

    OpenVAS carries its own Quality of Detection value, which is reused directly
    as the finding's ``qod`` when present. The ``confirmed`` flag follows
    OpenVAS's own QoD ladder — a banner-based detection sits around 30-80, while
    an exploit-based one reaches ~99 — so a QoD of 80 or more is treated as
    actively confirmed.

    Args:
        vuln: The ``OpenVASVulnerability`` row, or any object exposing the same
            attributes (read by duck typing, like
            :func:`~.engine.services_from_open_ports`).
        result: One entry of ``scan_results_data`` (with ``nvt_oid`` / ``host_ip``
            / ``port`` / ``threat``).

    Returns:
        A dict of ``Finding`` column values. The caller still attaches
        ``host_id`` and ``dedup_key`` before persisting.
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
        "confirmed":    qod >= 80,
        "state":        "open",
    }


def _parse_port(port_str: Optional[str]) -> Optional[int]:
    """Extract a port number from an OpenVAS port string.

    Args:
        port_str: A string like ``"80/tcp"`` or ``"general/tcp"``, or ``None``.

    Returns:
        The port number (``80``), or ``None`` when there is no numeric port.
        Best-effort — never raises.
    """
    if not port_str:
        return None
    digits = port_str.split("/", 1)[0]
    return int(digits) if digits.isdigit() else None


def _stable_hash(*parts: str) -> str:
    """Return a short, stable hex digest of the given strings joined together."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
