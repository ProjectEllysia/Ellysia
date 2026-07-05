"""Correlation, deduplication, lifecycle and contextual scoring (Fase 5).

Turns per-scan finding lists into "state of a vulnerability on an asset over
time". All pure functions over finding dicts, so they are unit-tested without a
DB and work regardless of which scanner produced the finding — which is exactly
what lets multiple sources fold into one finding once Nikto/OpenVAS also write
to the Finding table.

* ``compute_dedup_key`` / ``merge_findings`` — collapse the same issue reported
  more than once (or by more than one source) into a single finding.
* ``apply_lifecycle`` — set ``open`` / ``fixed`` / ``regressed`` / ``accepted``
  by comparing against the previous scan of the same target.
* ``classify_exposure`` / ``score_finding`` — contextual priority beyond raw
  CVSS (EPSS + KEV escalate; a private LAN caps the ceiling).
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Dict, List, Optional

# Kept in one place so scoring and any future consumer agree on the ladder.
PRIORITY_LADDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home")


# =========================================================================
# EXPOSURE
# =========================================================================

def classify_exposure(target: str) -> str:
    """Return "private" (LAN) or "public" for a target.

    Mirrors ``analyzers._classify_network_context`` private-address detection,
    duplicated as a few lines here to avoid building the (heavy) AI writer.
    """
    try:
        addr = ipaddress.ip_address(target.strip())
        private = addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        low = target.strip().lower()
        private = low == "localhost" or any(low.endswith(s) for s in _PRIVATE_SUFFIXES)
    return "private" if private else "public"


# =========================================================================
# DEDUPLICATION
# =========================================================================

def compute_dedup_key(finding: dict) -> str:
    """Stable, scanner-independent key for the same issue on the same service.

    Keyed on host + port + vulnerability identity: the CVE set if present (so any
    scanner reporting that CVE merges), else the producing check, else category.
    """
    host = finding.get("host_id")
    port = finding.get("port")
    cves = finding.get("cve_ids")
    if cves:
        identity = "cve:" + ",".join(sorted(cves))
    elif finding.get("check_id"):
        identity = "check:" + str(finding["check_id"])
    else:
        identity = "cat:" + str(finding.get("category"))
    return hashlib.sha256(f"{host}|{port}|{identity}".encode()).hexdigest()[:32]


def _union_cves(a: Optional[list], b: Optional[list]) -> Optional[list]:
    combined = sorted(set((a or []) + (b or [])))
    return combined or None


def merge_findings(findings: List[dict]) -> List[dict]:
    """Collapse findings sharing a dedup_key, keeping the strongest signal.

    The merged finding takes the highest ``qod`` (and that finding's title/CVSS),
    is ``confirmed``/``in_kev`` if any input was, unions the CVE ids, and joins
    the distinct sources into ``source`` ("ellysia,openvas"). Output dicts only
    contain Finding columns, so they persist directly.
    """
    merged: Dict[str, dict] = {}
    sources: Dict[str, list] = {}
    for original in findings:
        f = dict(original)
        key = f.get("dedup_key") or compute_dedup_key(f)
        f["dedup_key"] = key
        src = f.get("source")

        if key not in merged:
            merged[key] = f
            sources[key] = [src] if src else []
            continue

        m = merged[key]
        if (f.get("qod") or 0) > (m.get("qod") or 0):
            m["qod"] = f.get("qod")
            m["title"] = f.get("title", m.get("title"))
            m["cvss_score"] = f.get("cvss_score", m.get("cvss_score"))
        m["confirmed"] = bool(m.get("confirmed")) or bool(f.get("confirmed"))
        m["in_kev"] = bool(m.get("in_kev")) or bool(f.get("in_kev"))
        m["cve_ids"] = _union_cves(m.get("cve_ids"), f.get("cve_ids"))
        if src and src not in sources[key]:
            sources[key].append(src)

    for key, m in merged.items():
        if sources[key]:
            m["source"] = ",".join(sorted(set(sources[key])))
    return list(merged.values())


# =========================================================================
# LIFECYCLE
# =========================================================================

def apply_lifecycle(current: List[dict], previous: Dict[str, dict]) -> List[dict]:
    """Set each current finding's ``state`` vs the previous scan and carry over
    now-fixed findings.

    Args:
        current: This scan's findings (each already has ``dedup_key``).
        previous: ``dedup_key -> {"state", "snapshot"}`` from the previous scan.

    Returns:
        ``current`` (states set) plus one ``fixed`` finding for each key that was
        present-and-not-yet-fixed before and is absent now (recorded once).
    """
    current_keys = set()
    for f in current:
        key = f["dedup_key"]
        current_keys.add(key)
        prev = previous.get(key)
        if prev is None:
            f["state"] = "open"
        elif prev["state"] == "accepted":
            f["state"] = "accepted"            # user decision is sticky
        elif prev["state"] == "fixed":
            f["state"] = "regressed"           # was gone, came back
        else:
            f["state"] = "open"

    carried: List[dict] = []
    for key, prev in previous.items():
        if key not in current_keys and prev["state"] in ("open", "regressed", "accepted"):
            ghost = dict(prev["snapshot"])
            ghost["state"] = "fixed"
            carried.append(ghost)
    return current + carried


# =========================================================================
# CONTEXTUAL SCORING
# =========================================================================

def _cvss_band(cvss: float) -> int:
    if cvss >= 9.0:
        return 4  # CRITICAL
    if cvss >= 7.0:
        return 3  # HIGH
    if cvss >= 4.0:
        return 2  # MEDIUM
    if cvss > 0.0:
        return 1  # LOW
    return 0      # INFO


def score_finding(finding: dict, exposure: str) -> str:
    """Contextual priority label (one of :data:`PRIORITY_LADDER`).

    Beyond raw CVSS: real-world exploitation signal (KEV, or EPSS ≥ 0.5)
    escalates one band; an actively-confirmed finding without a CVSS floors at
    MEDIUM; a private-LAN target caps the ceiling at HIGH.
    """
    cvss = finding.get("cvss_score") or 0.0
    band = _cvss_band(cvss)

    if finding.get("in_kev") or (finding.get("epss_score") or 0.0) >= 0.5:
        band = min(band + 1, len(PRIORITY_LADDER) - 1)

    if finding.get("confirmed") and cvss == 0.0:
        band = max(band, PRIORITY_LADDER.index("MEDIUM"))

    if exposure == "private":
        band = min(band, PRIORITY_LADDER.index("HIGH"))

    return PRIORITY_LADDER[band]
