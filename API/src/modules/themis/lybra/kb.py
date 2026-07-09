"""Local mirror of the public vulnerability feeds — Lybra's knowledge base.

This module is what lets Lybra answer "which CVEs affect this product at this
version?" from its own database, without reaching out to the network once per
scanned target. It mirrors three public feeds locally — NVD (the CVE catalogue),
CISA-KEV (vulnerabilities known to be exploited in the wild) and FIRST-EPSS
(exploitation-probability scores) — and knows how to compare software versions
against the ranges NVD publishes.

Everything lives in one file on purpose, grouped into three concerns:

Version logic
    ``version_compare`` and ``version_in_range`` are the correctness-critical
    heart of the matcher: they decide whether a discovered version falls inside
    the affected range NVD declares for a CVE.

CPE helpers
    ``normalize_cpe_to_23`` and ``parse_cpe23`` translate between the CPE string
    Nmap emits (the older 2.2 URI form) and the one NVD uses (the 2.3 form), and
    pull out the vendor/product/version we actually match on.

Ingest and fetch
    The ``ingest_*`` / ``parse_*`` functions turn a decoded feed record into a
    plain dict ready to persist; the ``fetch_*`` functions are the thin network
    edge that downloads the feeds over HTTP (with a small retry/backoff, mirroring
    the pattern already used by ``AegisAlertFetcher``).

The ingest and parse functions are deliberately pure — they take an
already-decoded record and return a dict — so they can be unit-tested with tiny
fixtures. Only the ``fetch_*`` functions touch the network.
"""

from __future__ import annotations

import csv
import gzip
import json
import logging
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =========================================================================
# VERSION LOGIC
# =========================================================================

def _version_key(version: str) -> List[tuple]:
    """Break a version string into components that sort correctly.

    Each numeric run becomes an integer and each alphabetic run a lowercased
    string, tagged so that letters always sort *below* numbers. That way a
    pre-release tag like "2.4.0a" ranks under its final release "2.4.0", which is
    the conventional meaning.

    Args:
        version: A raw version string such as "2.4.49" or "1.0.0-rc1".

    Returns:
        A list of comparison tuples, one per run, ready to compare with Python's
        built-in tuple ordering.
    """
    key: List[tuple] = []
    for run in re.findall(r"\d+|[A-Za-z]+", version.strip()):
        if run.isdigit():
            key.append((1, int(run), ""))
        else:
            key.append((0, 0, run.lower()))
    return key


def version_compare(a: str, b: str) -> int:
    """Compare two version strings component by component.

    Comparing the numeric runs as integers (rather than as text) is what makes
    "2.4.9" correctly rank below "2.4.49" — a plain string comparison would get
    that backwards. Trailing zero components do not count, so "1.0" and "1.0.0"
    are treated as equal. This is good enough for the dotted vendor versions the
    matcher sees; it is not a full PEP 440 / semver implementation.

    Args:
        a: The first version string.
        b: The second version string.

    Returns:
        ``-1`` if ``a`` is older than ``b``, ``0`` if they are equal, ``1`` if
        ``a`` is newer.
    """
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
    """Read one range-bound field off a match, whether it is an ORM row or a dict.

    Args:
        match: A ``CpeMatch`` ORM row or a plain dict with the same field names.
        name: The field to read, e.g. ``"version_start_including"``.

    Returns:
        The field value, or ``None`` if it is absent.
    """
    if isinstance(match, dict):
        return match.get(name)
    return getattr(match, name, None)


def version_in_range(version: str, match) -> bool:
    """Decide whether a version is affected by a CVE's applicability rule.

    NVD expresses "which versions are affected" in one of two ways, and this
    function handles both:

    * An exact pinned version — the CVE affects that single version only.
    * A range built from up to four bounds (start including/excluding, end
      including/excluding) — the CVE affects everything inside that range.

    A rule with neither an exact version nor any bound is taken to affect *every*
    version of the product.

    Args:
        version: The discovered version to test, e.g. "2.4.49".
        match: A ``CpeMatch`` ORM row or a dict with the same field names.

    Returns:
        ``True`` if ``version`` falls within the rule's applicability, ``False``
        otherwise. An empty ``version`` never matches.
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
    """Convert a CPE to the modern 2.3 string form.

    Nmap emits the older 2.2 URI form (``cpe:/a:apache:http_server:2.4.49``)
    while NVD uses the 2.3 form
    (``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``). A string already in
    2.3 form is returned unchanged, and anything unrecognised is passed through
    as-is.

    Args:
        cpe: A CPE string in either the 2.2 or 2.3 form.

    Returns:
        The CPE in 2.3 form.
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
    """Pull the identifying fields out of a CPE string.

    Normalizes the input to 2.3 form first, so it accepts either form.

    Args:
        cpe: A CPE string in 2.2 or 2.3 form.

    Returns:
        A dict with ``"part"``, ``"vendor"``, ``"product"`` and ``"version"``, or
        ``None`` if the string is not a recognisable CPE.
    """
    parts = normalize_cpe_to_23(cpe).split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


# =========================================================================
# INGEST (pure: decoded feed record -> rows ready to persist)
# =========================================================================

def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse a feed timestamp into a naive datetime, tolerating loose formats.

    Feeds are inconsistent: some timestamps carry a trailing ``Z``, some are
    date-only. This strips the ``Z`` and falls back to a plain date if the full
    ISO parse fails, returning ``None`` rather than raising on anything it cannot
    make sense of.

    Args:
        value: A timestamp string from a feed, or ``None``.

    Returns:
        A naive ``datetime`` (UTC, matching the rest of the codebase), or
        ``None`` if the value is missing or unparseable.
    """
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
    """Choose the best available CVSS metric from an NVD ``metrics`` block.

    A CVE may carry several CVSS versions at once; we prefer the newest
    (v3.1 over v3.0 over v2), since that is the most accurate scoring the entry
    offers.

    Args:
        metrics: The ``metrics`` object of an NVD CVE record.

    Returns:
        A ``(base_score, vector_string, severity)`` tuple. Each element is
        ``None`` if no CVSS metric of any version is present.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return data.get("baseScore"), data.get("vectorString"), severity
    return None, None, None


def ingest_nvd_cve(item: dict) -> Optional[Tuple[dict, List[dict]]]:
    """Turn one NVD 2.0 CVE record into rows ready to persist.

    Extracts the CVE's core fields (score, severity, description, CWEs) plus its
    applicability rules. Only CPE matches flagged ``vulnerable`` are kept — those
    are the ones that actually make a product affected, as opposed to context
    entries like a required operating system.

    Args:
        item: One element of an NVD 2.0 response's ``vulnerabilities`` list.

    Returns:
        A ``(cve_row, cpe_match_rows)`` tuple: a dict for the ``CveEntry`` and a
        list of dicts for its ``CpeMatch`` rows. Returns ``None`` if the record
        is malformed (has no CVE id).
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
    """Turn one NVD ``cpeMatch`` object into a ``CpeMatch`` row dict.

    A CPE that pins a concrete version (not ``*`` or ``-``) becomes an
    ``exact_version`` match — unless the object also carries explicit range
    bounds, in which case the range takes precedence and the pinned version is
    ignored.

    Args:
        cm: One ``cpeMatch`` object from an NVD configuration node.

    Returns:
        A dict of ``CpeMatch`` column values, or ``None`` if the object's CPE
        string cannot be parsed.
    """
    parsed = parse_cpe23(cm.get("criteria", ""))
    if not parsed:
        return None
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
    """Turn one CISA KEV catalogue entry into a ``KevEntry`` row.

    Args:
        vuln: One element of the KEV catalogue's ``vulnerabilities`` list.

    Returns:
        A dict of ``KevEntry`` column values, or ``None`` if the entry has no
        CVE id.
    """
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
    """Yield ``EpssScore`` rows from the EPSS CSV export.

    The EPSS file starts with one or more ``#`` comment lines (which also carry
    the scoring date) followed by a ``cve,epss,percentile`` table. Rows that are
    missing a CVE id or have unparseable numbers are skipped rather than aborting
    the whole import.

    Args:
        csv_text: The full decoded text of the EPSS CSV file.

    Yields:
        A dict of ``EpssScore`` column values for each valid row.
    """
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
    """Read the scoring date out of the EPSS file's comment header.

    The header looks like ``#model_version:...,score_date=2026-07-01T...``.

    Args:
        csv_text: The full decoded text of the EPSS CSV file.

    Returns:
        The parsed scoring date, or ``None`` if the header does not carry one.
    """
    match = re.search(r"score_date=(\d{4}-\d{2}-\d{2})", csv_text[:512])
    return _parse_dt(match.group(1)) if match else None


# =========================================================================
# FETCH (the thin network edge: urllib + backoff)
# =========================================================================

_RETRIES = 3
_BACKOFF_BASE = 1.5


def _http_get(url: str, timeout: int = 30, api_key: Optional[str] = None) -> bytes:
    """GET a URL, retrying a few times with exponential backoff.

    Args:
        url: The URL to fetch.
        timeout: Per-attempt socket timeout, in seconds.
        api_key: Optional API key sent as the ``apiKey`` header (NVD uses this to
            grant a higher rate limit).

    Returns:
        The raw response body.

    Raises:
        Exception: The last error encountered, re-raised after all retries are
            exhausted.
    """
    headers = {"User-Agent": "Lybra-KB/1.0"}
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
    """Download the CISA KEV catalogue.

    Args:
        url: The KEV catalogue JSON URL.
        timeout: Socket timeout, in seconds.

    Returns:
        The catalogue's ``vulnerabilities`` list (empty if the field is absent).
    """
    data = json.loads(_http_get(url, timeout))
    return data.get("vulnerabilities", [])


def fetch_epss(url: str, timeout: int = 60) -> str:
    """Download the current EPSS scores.

    The published file is a gzipped CSV; this transparently decompresses it, and
    also copes with an already-plain CSV in case the server serves one.

    Args:
        url: The EPSS scores URL (typically a ``.csv.gz``).
        timeout: Socket timeout, in seconds.

    Returns:
        The decoded CSV text.
    """
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
    """Fetch a single page from the NVD 2.0 CVE API.

    The NVD API is paginated; callers usually go through :func:`iter_nvd_pages`
    rather than calling this directly. Passing both ``last_mod_start`` and
    ``last_mod_end`` restricts the page to CVEs modified in that window, which is
    how an incremental (delta) sync is done.

    Args:
        base_url: The NVD CVE API base URL.
        start_index: The offset of the first result to return.
        last_mod_start: Start of the "last modified" window (NVD date format).
        last_mod_end: End of the "last modified" window (NVD date format).
        api_key: Optional NVD API key for a higher rate limit.
        timeout: Socket timeout, in seconds.

    Returns:
        The raw JSON page, including ``vulnerabilities``, ``totalResults``,
        ``resultsPerPage`` and ``startIndex``.
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
    """Walk every page of the NVD CVE API and yield the individual CVE records.

    Sleeps between pages to stay under NVD's rate limit (roughly six seconds
    without an API key, well under a second with one). Iteration stops at the
    first empty page or once ``totalResults`` has been reached.

    Args:
        base_url: The NVD CVE API base URL.
        last_mod_start: Start of the "last modified" window (NVD date format).
        last_mod_end: End of the "last modified" window (NVD date format).
        api_key: Optional NVD API key for a higher rate limit.
        page_pause: Seconds to wait between pages.

    Yields:
        Each element of every page's ``vulnerabilities`` list, in order.
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
