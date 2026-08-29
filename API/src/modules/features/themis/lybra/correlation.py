"""Correlation, deduplication, lifecycle and contextual scoring.

This is what turns a flat list of per-scan findings into "the state of a
vulnerability on an asset, over time" — the part of the product that is more than
just running three scanners and reading three reports.

Everything here is a pure function over finding dicts, so it can be unit-tested
without a database and works no matter which scanner produced a finding. That
scanner-independence is exactly what lets several sources fold into a single
finding once Nikto and Nuclei also write to the shared ``Finding`` table.

The module covers three concerns:

Deduplication
    :func:`compute_dedup_key` and :func:`merge_findings` collapse the same issue,
    reported more than once or by more than one scanner, into a single finding.

Lifecycle
    :func:`apply_lifecycle` assigns each finding a state — ``open``, ``fixed``,
    ``regressed`` or ``accepted`` — by comparing this scan against the previous
    one of the same target.

Contextual scoring
    :func:`classify_exposure` and :func:`score_finding` produce a priority that
    goes beyond raw CVSS: real-world exploitation signals push it up, and a
    private (LAN) target caps it.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Dict, List, Optional

# The severity ladder, kept in one place so scoring and any future consumer agree
# on the ordering.
PRIORITY_LADDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home")


# =========================================================================
# EXPOSURE
# =========================================================================

def classify_exposure(target: str) -> str:
    """Classify a target as internal (LAN) or internet-facing.

    Mirrors the private-address detection in
    ``analyzers._classify_network_context``; it is duplicated here as a handful of
    lines to avoid pulling in that module's much heavier AI-writer dependency.

    Args:
        target: An IP address or hostname.

    Returns:
        ``"private"`` for a LAN/loopback/link-local address or an internal-looking
        hostname, otherwise ``"public"``.
    """
    try:
        addr = ipaddress.ip_address(target.strip())
        private = addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        low = target.strip().lower()
        private = low == "localhost" or any(low.endswith(private_suffix) for private_suffix in _PRIVATE_SUFFIXES)
    return "private" if private else "public"


# =========================================================================
# DEDUPLICATION
# =========================================================================

def compute_dedup_key(finding: dict) -> str:
    """Compute a stable key identifying the same issue on the same service.

    The key is deliberately scanner-independent so that two scanners reporting
    the same vulnerability produce the same key and get merged. It is built from
    the host and port plus a "vulnerability identity", chosen in order of
    preference: the CVE set if present (so any scanner naming that CVE merges),
    otherwise the producing check, otherwise the finding's category.

    Args:
        finding: A finding dict, expected to carry ``host_id``, ``port`` and one
            of ``cve_ids`` / ``check_id`` / ``category``.

    Returns:
        A 32-character hexadecimal digest.
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
    material = f"{host}|{port}|{identity}"
    protocol = (finding.get("protocol") or "tcp").lower()
    if protocol != "tcp":
        # Ronda 1 (roadmap §6.3): la sonda UDP puede abrir el mismo número de
        # puerto que ya vigilábamos por TCP (161 es el caso real: SNMP). Sin
        # esto, un 161/tcp y un 161/udp del mismo host colisionarían bajo la
        # misma identidad ("check:lybra:open-port@1") y uno pisaría al otro en
        # el merge. Condicionado a "no tcp" para que cada dedup_key ya
        # almacenada quede intacta: hasta esta ronda todo hallazgo era TCP.
        material += "|" + protocol
    if port is None:
        # A portless finding (Fase 0.9 — an inventory-origin service, e.g. an
        # installed package with nothing listening) has no port to
        # disambiguate different assets that happen to share the same
        # check/category identity, or even the same CVE. ``service`` carries
        # the product name in that case (engine.py falls back to it when
        # there is no service name), which stays stable across a version
        # bump — mirroring how a port's own identity already stays stable
        # across a network service's product/version changing. Only
        # reachable for a case that never existed before Fase 0.9 (port was
        # always populated until now), so this cannot collide with any
        # pre-existing dedup_key.
        material += "|" + (finding.get("service") or "")
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _union_cves(a: Optional[list], b: Optional[list]) -> Optional[list]:
    """Merge two CVE-id lists into a sorted, de-duplicated list (or ``None``)."""
    combined = sorted(set((a or []) + (b or [])))
    return combined or None


def merge_findings(findings: List[dict]) -> List[dict]:
    """Collapse findings that share a dedup key into one, keeping the best signal.

    When several findings describe the same issue, the merged result keeps the
    highest ``qod`` (along with that finding's title and CVSS score), is marked
    ``confirmed`` / ``in_kev`` if *any* input was, unions the CVE ids, and joins
    the distinct sources into ``source`` (e.g. ``"lybra,nuclei"``). This is the
    mechanism behind both within-scan dedup and the read-time fusion of
    corroborator scans.

    Args:
        findings: Findings to merge. Each may already carry a ``dedup_key``; any
            that do not get one computed on the fly.

    Returns:
        One finding per distinct dedup key. Every dict contains only ``Finding``
        columns, so the result can be persisted or displayed directly.
    """
    merged: Dict[str, dict] = {}
    sources: Dict[str, list] = {}
    for original in findings:
        finding = dict(original)
        key = finding.get("dedup_key") or compute_dedup_key(finding)
        finding["dedup_key"] = key
        source = finding.get("source")

        if key not in merged:
            merged[key] = finding
            sources[key] = [source] if source else []
            continue

        merged_finding = merged[key]
        if (finding.get("qod") or 0) > (merged_finding.get("qod") or 0):
            merged_finding["qod"] = finding.get("qod")
            merged_finding["title"] = finding.get("title", merged_finding.get("title"))
            merged_finding["cvss_score"] = finding.get("cvss_score", merged_finding.get("cvss_score"))
        merged_finding["confirmed"] = bool(merged_finding.get("confirmed")) or bool(finding.get("confirmed"))
        merged_finding["in_kev"] = bool(merged_finding.get("in_kev")) or bool(finding.get("in_kev"))
        merged_finding["cve_ids"] = _union_cves(merged_finding.get("cve_ids"), finding.get("cve_ids"))
        if source and source not in sources[key]:
            sources[key].append(source)

    for key, merged_finding in merged.items():
        if sources[key]:
            merged_finding["source"] = ",".join(sorted(set(sources[key])))
    return list(merged.values())


# =========================================================================
# LIFECYCLE
# =========================================================================

def apply_lifecycle(current: List[dict], previous: Dict[str, dict]) -> List[dict]:
    """Assign each finding a lifecycle state relative to the previous scan.

    Each current finding is labelled by comparing it against the previous scan of
    the same target:

    * Not seen before → ``open`` (a new finding).
    * Seen before and marked ``accepted`` → stays ``accepted`` (the user's
      decision is sticky).
    * Seen before as ``fixed`` and back now → ``regressed``.
    * Otherwise (still present since last time) → ``open``.

    In addition, any issue that *was* present last time but is absent now is
    carried forward once as a ``fixed`` finding, so the timeline records the
    remediation. An already-``fixed`` issue is not carried again, which keeps this
    bounded.

    Args:
        current: This scan's findings. Each must already have a ``dedup_key``.
        previous: A map ``dedup_key -> {"state", "snapshot"}`` describing the
            previous scan's findings.

    Returns:
        The ``current`` findings with their ``state`` set, plus one ``fixed``
        finding for each issue that has just disappeared.
    """
    current_keys = set()
    for finding in current:
        key = finding["dedup_key"]
        current_keys.add(key)
        prev = previous.get(key)
        if prev is None:
            finding["state"] = "open"
        elif prev["state"] == "accepted":
            finding["state"] = "accepted"            # the user's decision is sticky
        elif prev["state"] == "fixed":
            finding["state"] = "regressed"           # was gone, has come back
        else:
            finding["state"] = "open"

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
    """Map a CVSS base score onto an index into :data:`PRIORITY_LADDER`."""
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
    """Assign a finding a contextual priority label.

    Starts from the CVSS band, then adjusts for real-world context:

    * A real exploitation signal — the CVE is in KEV, or its EPSS score is at
      least 0.5 — pushes the priority up one band.
    * An actively-confirmed finding with no CVSS (e.g. an exposed path) is floored
      at MEDIUM, so a confirmed issue never reads as merely informational.
    * An unconfirmed match whose CVE only applies on a specific platform
      (``required_os`` set — see ``CpeMatch.required_os``) is capped at
      MEDIUM: Lybra has no OS-detection signal, so it cannot verify that
      precondition, and treating an unverifiable "on Windows"-type CVE as
      CRITICAL against every banner-matched host — regardless of its actual
      OS — is exactly the false-positive pattern this cap closes. A
      confirmed finding (Hygeia inventory, where the host's own OS is already
      known) is exempt.
    * A private-LAN target caps the priority at HIGH, since it is not exposed to
      the internet.

    Args:
        finding: A finding dict, read for ``cvss_score`` / ``in_kev`` /
            ``epss_score`` / ``confirmed`` / ``required_os``.
        exposure: ``"private"`` or ``"public"``, as returned by
            :func:`classify_exposure`.

    Returns:
        One of the labels in :data:`PRIORITY_LADDER`.
    """
    cvss = finding.get("cvss_score") or 0.0
    band = _cvss_band(cvss)

    if finding.get("in_kev") or (finding.get("epss_score") or 0.0) >= 0.5:
        band = min(band + 1, len(PRIORITY_LADDER) - 1)

    if finding.get("confirmed") and cvss == 0.0:
        band = max(band, PRIORITY_LADDER.index("MEDIUM"))

    if finding.get("required_os") and not finding.get("confirmed"):
        band = min(band, PRIORITY_LADDER.index("MEDIUM"))

    if exposure == "private":
        band = min(band, PRIORITY_LADDER.index("HIGH"))

    return PRIORITY_LADDER[band]
