"""Adapters that give Nikto a presence in the shared Finding table.

Nikto still writes its own result table exactly as it always has — its PDF
reports and history charts read from that, and it is left untouched. What
this adapter adds is a *second*, additive write: for each Nikto incident, a
normalized :class:`Finding` row is also produced, so every scanner shows up
in one shared table and the deep-analysis correlation pass has something to
fuse together.

This mirrors a duplication the project already accepted for Nmap, where the
``OpenPort`` rows stay put and an informational Finding is written alongside
them. A full replacement — making Nikto stop writing its own table — was
ruled out because its report/chart code has no test coverage and could not
be rewritten safely in a single pass.

OpenVAS had the same adapter (``openvas_result_to_finding``) until the
scanner was removed (roadmap §7/§6.3, Ronda 2 — E2). Its historical
``Finding`` rows — ``source="openvas"``, ``check_id`` prefixed
``"openvas:"`` — are unaffected: they live in the source-agnostic Finding
table this module writes into, not in anything this file owns.

These adapters only build the finding dicts and compute nothing about lifecycle
or merging; the caller attaches ``host_id`` and ``dedup_key`` and persists them.
"""

from __future__ import annotations

import hashlib
from typing import Optional
from urllib.parse import urlparse


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

# A Nuclei matcher is a structured assertion against a real response (a status
# code, a regex, a word match) — the same kind of certainty an active check in
# Lybra's own runtime carries, not a text-pattern heuristic like Nikto's. Every
# Nuclei finding is therefore "confirmed" at this fixed QoD, the same way
# ``lybra/checks.py``'s own active checks are.
QOD_NUCLEI_MATCH = 90

# Fallback CVSS band for a Nuclei finding whose template carries no
# ``info.classification`` (no CVE, no explicit cvss-score) — the common case for
# misconfiguration/exposure templates. Derived from the template author's own
# ``info.severity`` rating. This is *not* an NVD CVSS score — it is the
# author's severity judgement expressed on the CVSS numeric scale, so
# priority scoring has something to work with instead of treating every
# CVE-less finding as a flat zero.
_NUCLEI_SEVERITY_CVSS = {
    "critical": 9.5,
    "high":     8.0,
    "medium":   5.5,
    "low":      3.0,
    "info":     None,
}

# Nuclei's own "type" families that do not map to a CVE, bucketed into the
# Finding categories the rest of the system already understands.
_NUCLEI_TYPE_CATEGORY = {
    "http": "web_finding",
    "ssl":  "tls",
    "tls":  "tls",
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


def nuclei_result_to_finding(result: dict, feed_version: str = "nuclei-templates-unknown") -> dict:
    """Adapt one Nuclei JSONL result line into a Finding dict.

    Nuclei's output maps almost 1:1 onto ``Finding`` — unlike Nikto's
    ``osvdb_id``, a matched template can carry a real CVE, CVSS and EPSS score
    straight from its ``info.classification`` block. That is what lets a Nuclei
    scan enter the multi-source deduplication (Fase 5) for free.

    Args:
        result: One decoded JSONL line, as produced by ``NucleiResultProcessor``.
        feed_version: The templates version the scan ran with (read from the
            binary's own startup banner by ``NucleiScanTask``, so it reflects
            what actually ran, not a config default).

    Returns:
        A dict of ``Finding`` column values. The caller still attaches
        ``host_id`` and ``dedup_key`` before persisting.
    """
    info = result.get("info") or {}
    classification = info.get("classification") or {}

    # Nuclei emits CVE ids lowercase ("cve-2021-41773"). compute_dedup_key
    # builds its identity from "cve:" + sorted(cve_ids) — without normalizing
    # here, the same CVE reported by Lybra ("CVE-2021-41773") and Nuclei would
    # hash to two different keys and never merge, which is the entire point of
    # giving Nuclei this adapter in the first place.
    raw_cve_ids = classification.get("cve-id") or []
    cve_ids = sorted({c.upper() for c in raw_cve_ids if c}) or None

    cvss_score = classification.get("cvss-score")
    if cvss_score is None:
        severity = (info.get("severity") or "").strip().lower()
        cvss_score = _NUCLEI_SEVERITY_CVSS.get(severity)

    template_id = result.get("template-id") or "unknown"
    title = info.get("name") or template_id

    template_type = (result.get("type") or "").strip().lower()
    category = "outdated_software" if cve_ids else _NUCLEI_TYPE_CATEGORY.get(template_type, "vulnerability")

    tags = info.get("tags") or []
    in_kev = "kev" in [str(t).strip().lower() for t in tags]

    return {
        "title":        title,
        "category":     category,
        "port":         _nuclei_port(result),
        "service":      template_type or None,
        "cpe":          classification.get("cpe"),
        "cve_ids":      cve_ids,
        "cvss_score":   cvss_score,
        "cvss_vector":  classification.get("cvss-metrics"),
        "epss_score":   classification.get("epss-score"),
        "in_kev":       in_kev,
        "source":       "nuclei",
        "check_id":     f"nuclei:{template_id}",
        "feed_version": feed_version,
        # A matcher (status/word/regex/binary) is a structured assertion
        # against a real response — always actively confirmed, never a guess.
        "qod":          QOD_NUCLEI_MATCH,
        "confirmed":    True,
        "state":        "open",
    }


def _nuclei_port(result: dict) -> Optional[int]:
    """Best-effort port extraction for a Nuclei result.

    Nuclei does not always carry an explicit ``port`` field; when present it
    is reused directly, otherwise the scheme's URL (``matched-at`` first, then
    ``host``) is parsed for an explicit port. Never raises — returns ``None``
    when nothing can be resolved.
    """
    port = result.get("port")
    if port:
        try:
            return int(port)
        except (TypeError, ValueError):
            pass

    for field in ("matched-at", "host"):
        value = result.get(field)
        if not value:
            continue
        try:
            parsed = urlparse(value if "://" in value else f"//{value}")
            if parsed.port:
                return parsed.port
        except ValueError:
            continue
    return None


def _stable_hash(*parts: str) -> str:
    """Return a short, stable hex digest of the given strings joined together."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
