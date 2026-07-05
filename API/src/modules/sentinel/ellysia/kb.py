"""Ellysia's local vulnerability knowledge base (the "Ellysia Feed").

Everything needed to mirror NVD / CISA-KEV / FIRST-EPSS locally and to answer
"which CVEs affect this product at this version?" without a per-target network
call. Split into three concerns, all in one file to avoid noise:

* **Version logic** — ``version_compare`` / ``version_in_range``: the correctness
  heart of version→CVE matching (respects NVD's four range bounds).
* **CPE helpers** — ``normalize_cpe_to_23`` / ``parse_cpe23``: turn Nmap's 2.2
  URIs and NVD's 2.3 strings into (vendor, product, version).
* **Ingest + fetch** — parse a feed record into rows ready to persist, and pull
  the feeds over HTTP (urllib + backoff, same shape as AegisAlertFetcher).

The ingest/parse functions are pure and take already-decoded records, so they
are unit-tested with small fixtures; the fetchers are the thin network edge.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Iterable, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =========================================================================
# VERSION LOGIC
# =========================================================================

def _version_key(version: str) -> List[tuple]:
    """Tokenize a version into comparable components.

    Numeric runs compare as integers, alphabetic runs as lowercased strings, and
    alphabetic sorts *below* numeric so pre-release tags ("2.4.0a") rank under
    their release ("2.4.0"). Good enough for the dotted vendor versions the
    matcher sees; not a full PEP 440 / semver implementation.
    """
    key: List[tuple] = []
    for run in re.findall(r"\d+|[A-Za-z]+", version.strip()):
        if run.isdigit():
            key.append((1, int(run), ""))
        else:
            key.append((0, 0, run.lower()))
    return key


def version_compare(a: str, b: str) -> int:
    """Return -1/0/1 for a<b / a==b / a>b. Trailing zero components tie
    ("1.0" == "1.0.0")."""
    ka, kb = _version_key(a), _version_key(b)
    for i in range(max(len(ka), len(kb))):
        ta = ka[i] if i < len(ka) else (1, 0, "")
        tb = kb[i] if i < len(kb) else (1, 0, "")
        if ta < tb:
            return -1
        if ta > tb:
            return 1
    return 0


def _bound(match, name: str) -> Optional[str]:
    """Read a range bound off a CpeMatch ORM row or a plain dict."""
    if isinstance(match, dict):
        return match.get(name)
    return getattr(match, name, None)


def version_in_range(version: str, match) -> bool:
    """True if ``version`` falls inside a CpeMatch's applicability.

    ``match`` may be a CpeMatch ORM row or a dict with the same field names. An
    ``exact_version`` wins outright; otherwise the four NVD bounds apply; a match
    with neither affects every version of the product.
    """
    if not version:
        return False

    exact = _bound(match, "exact_version")
    if exact:
        return version_compare(version, exact) == 0

    vsi = _bound(match, "version_start_including")
    vse = _bound(match, "version_start_excluding")
    vei = _bound(match, "version_end_including")
    vee = _bound(match, "version_end_excluding")

    if not any([vsi, vse, vei, vee]):
        return True
    if vsi and version_compare(version, vsi) < 0:
        return False
    if vse and version_compare(version, vse) <= 0:
        return False
    if vei and version_compare(version, vei) > 0:
        return False
    if vee and version_compare(version, vee) >= 0:
        return False
    return True


# =========================================================================
# CPE HELPERS
# =========================================================================

def normalize_cpe_to_23(cpe: str) -> str:
    """Convert Nmap's 2.2 URI form to NVD's 2.3 form; pass 2.3 through unchanged.

    ``cpe:/a:apache:http_server:2.4.49`` →
    ``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``.
    """
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        fields = (cpe[len("cpe:/"):].split(":") + ["*"] * 7)[:7]
        part, vendor, product, version, update, edition, lang = [f or "*" for f in fields]
        return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{lang}:*:*:*:*"
    return cpe


def parse_cpe23(cpe: str) -> Optional[dict]:
    """Return ``{"part", "vendor", "product", "version"}`` from a CPE, or None."""
    parts = normalize_cpe_to_23(cpe).split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


# =========================================================================
# INGEST (pure: decoded feed record -> rows ready to persist)
# =========================================================================

def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-ish feed timestamp; tolerate a trailing Z and date-only."""
    if not value:
        return None
    text = value.strip().replace("Z", "").replace("z", "")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None


def _pick_cvss(metrics: dict) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """Prefer CVSS v3.1, then v3.0, then v2, returning (score, vector, severity)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return data.get("baseScore"), data.get("vectorString"), severity
    return None, None, None


def ingest_nvd_cve(item: dict) -> Optional[Tuple[dict, List[dict]]]:
    """Parse one NVD 2.0 ``vulnerabilities[]`` item into (cve_row, cpe_match_rows).

    Returns None for a malformed item (missing CVE id). Only ``vulnerable`` CPE
    matches are kept — those are the ones that actually make a product affected.
    """
    cve = item.get("cve", item)
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value") if descriptions else None,
    )
    score, vector, severity = _pick_cvss(cve.get("metrics", {}))
    cwe_ids = sorted({
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })

    cve_row = {
        "cve_id":        cve_id,
        "published":     _parse_dt(cve.get("published")),
        "last_modified": _parse_dt(cve.get("lastModified")),
        "cvss_score":    score,
        "cvss_vector":   vector,
        "severity":      (severity or "").upper() or None,
        "description":   description,
        "cwe_ids":       cwe_ids or None,
        "source":        "nvd",
    }

    matches: List[dict] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable"):
                    continue
                row = _cpe_match_row(cm)
                if row:
                    matches.append(row)

    return cve_row, matches


def _cpe_match_row(cm: dict) -> Optional[dict]:
    """Turn one NVD ``cpeMatch`` into a CpeMatch row dict."""
    parsed = parse_cpe23(cm.get("criteria", ""))
    if not parsed:
        return None
    # A pinned version in the CPE (not "*"/"-") becomes exact_version, unless the
    # match also carries explicit range bounds (then the range wins).
    bounds = (
        cm.get("versionStartIncluding"), cm.get("versionStartExcluding"),
        cm.get("versionEndIncluding"), cm.get("versionEndExcluding"),
    )
    pinned = parsed["version"] if parsed["version"] not in ("*", "-", "") else None
    return {
        "vendor":  parsed["vendor"],
        "product": parsed["product"],
        "version_start_including": cm.get("versionStartIncluding"),
        "version_start_excluding": cm.get("versionStartExcluding"),
        "version_end_including":   cm.get("versionEndIncluding"),
        "version_end_excluding":   cm.get("versionEndExcluding"),
        "exact_version":           None if any(bounds) else pinned,
    }


def ingest_kev(vuln: dict) -> Optional[dict]:
    """Parse one CISA KEV ``vulnerabilities[]`` entry into a KevEntry row."""
    cve_id = vuln.get("cveID")
    if not cve_id:
        return None
    return {
        "cve_id":           cve_id,
        "date_added":       _parse_dt(vuln.get("dateAdded")),
        "due_date":         _parse_dt(vuln.get("dueDate")),
        "known_ransomware": (vuln.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
    }


def parse_epss_rows(csv_text: str) -> Iterator[dict]:
    """Yield EpssScore rows from the EPSS CSV (a ``#`` comment header, then
    ``cve,epss,percentile``)."""
    scored_at = _epss_scored_at(csv_text)
    reader = csv.DictReader(line for line in csv_text.splitlines() if not line.startswith("#"))
    for row in reader:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        try:
            yield {
                "cve_id":     cve_id,
                "score":      float(row["epss"]),
                "percentile": float(row.get("percentile") or 0.0),
                "scored_at":  scored_at,
            }
        except (KeyError, ValueError):
            continue


def _epss_scored_at(csv_text: str) -> Optional[datetime]:
    """Extract the score_date from the EPSS ``#model_version...,score_date=...``
    comment."""
    match = re.search(r"score_date=(\d{4}-\d{2}-\d{2})", csv_text[:512])
    return _parse_dt(match.group(1)) if match else None


# =========================================================================
# FETCH (the thin network edge: urllib + backoff)
# =========================================================================

_RETRIES = 3
_BACKOFF_BASE = 1.5


def _http_get(url: str, timeout: int = 30, api_key: Optional[str] = None) -> bytes:
    """GET a URL with exponential backoff. Raises the last error on give-up."""
    headers = {"User-Agent": "Ellysia-KB/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    last_error: Optional[Exception] = None
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:  # noqa: BLE001 - retried, then re-raised
            last_error = exc
            if attempt < _RETRIES - 1:
                time.sleep(_BACKOFF_BASE ** attempt)
    raise last_error  # type: ignore[misc]


def fetch_kev(url: str, timeout: int = 30) -> List[dict]:
    """Fetch the CISA KEV catalogue; return its ``vulnerabilities`` list."""
    data = json.loads(_http_get(url, timeout))
    return data.get("vulnerabilities", [])


def fetch_epss(url: str, timeout: int = 60) -> str:
    """Fetch the current EPSS scores (gzipped CSV) and return the CSV text."""
    raw = _http_get(url, timeout)
    try:
        return gzip.decompress(raw).decode("utf-8")
    except (OSError, gzip.BadGzipFile):
        return raw.decode("utf-8")  # already plain CSV


def fetch_nvd_page(
    base_url: str,
    start_index: int = 0,
    last_mod_start: Optional[str] = None,
    last_mod_end: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 60,
) -> dict:
    """Fetch one page of the NVD 2.0 CVE API.

    Returns the raw JSON (``vulnerabilities``, ``totalResults``,
    ``resultsPerPage``, ``startIndex``). The caller paginates on ``totalResults``.
    """
    params = {"startIndex": start_index}
    if last_mod_start and last_mod_end:
        params["lastModStartDate"] = last_mod_start
        params["lastModEndDate"] = last_mod_end
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    return json.loads(_http_get(url, timeout, api_key=api_key))


def iter_nvd_pages(
    base_url: str,
    last_mod_start: Optional[str] = None,
    last_mod_end: Optional[str] = None,
    api_key: Optional[str] = None,
    page_pause: float = 6.0,
) -> Iterator[dict]:
    """Yield every NVD ``vulnerabilities[]`` item across all pages.

    Sleeps ``page_pause`` between pages to respect NVD's rate limit (6s without
    an API key, ~0.6s with one). An empty page ends iteration.
    """
    start_index = 0
    while True:
        page = fetch_nvd_page(base_url, start_index, last_mod_start, last_mod_end, api_key)
        items = page.get("vulnerabilities", [])
        if not items:
            break
        yield from items
        start_index += page.get("resultsPerPage", len(items))
        if start_index >= page.get("totalResults", 0):
            break
        time.sleep(page_pause)
