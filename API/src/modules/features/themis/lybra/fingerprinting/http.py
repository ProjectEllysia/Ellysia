"""The HTTP dissector — the fingerprinting package's highest-value protocol.

Reads the ``Server`` / ``X-Powered-By`` headers, the page ``<title>``, a hash
of the favicon, and a data-driven, Wappalyzer-style signature feed
(``tech_signatures.json``) covering both web CMS/software (WordPress,
Drupal...) and network-appliance vendors (SonicWall, pfSense, MikroTik...). A
signature can also match a deliberately-nonexistent path's error page — some
vendors brand their 404 more than their homepage, which is exactly how the
SonicWall entry was found in the first place (see ``error_body`` below).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..checks import HttpProbe, Response, is_http_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector


@dataclass(frozen=True)
class HttpFingerprint:
    """The result of fingerprinting an HTTP service.

    Attributes:
        product: The identified product name, or ``None``.
        version: The identified version, or ``None``.
        title: The page ``<title>``, or ``None``.
        favicon_hash: A SHA-256 hex digest of the favicon, or ``None``. This is
            deliberately *not* the Shodan-compatible mmh3 hash — see the module
            docstring.
        technologies: A tuple of technology names matched by signature.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    title: Optional[str]
    favicon_hash: Optional[str]
    technologies: tuple
    confidence: float


# The signature feed, in the package's feeds/ directory alongside every other
# Lybra feed (checks_feed.json for the check runtime, ...) — see
# load_tech_signatures. Two directories up: fingerprinting/http.py -> lybra/feeds/.
_BUNDLED_TECH_SIGNATURES = Path(__file__).parent.parent / "feeds" / "tech_signatures.json"


@dataclass(frozen=True)
class TechMatcher:
    """One piece of evidence a :class:`TechSignature` can match against.

    Attributes:
        part: Which piece of evidence to search — ``"body"`` (the homepage),
            ``"error_body"`` (a deliberately nonexistent path's response, if
            fetched), ``"title"``, or ``"header:<name>"`` for a specific
            response header.
        words: Case-insensitive substrings; any one present is a match.
    """
    part: str
    words: tuple


@dataclass(frozen=True)
class TechSignature:
    """A named technology/vendor, identified by one or more :class:`TechMatcher`.

    Matchers within a signature are OR'd — any single one firing identifies
    the technology, the same "one piece of evidence is enough" model
    Wappalyzer itself uses. Never claims a version, only a name.
    """
    name: str
    matchers: tuple


def load_tech_signatures(path: Optional[str] = None) -> List[TechSignature]:
    """Load the technology/vendor signature feed.

    Externalized as data (rather than a hand-written table of lambdas) so a
    new signature — a CMS, a router/firewall vendor, whatever the next
    unrecognised device turns out to be — is one JSON entry, not a code
    change. Same "Lybra feed" philosophy as ``checks.load_checks``.

    Args:
        path: Path to a JSON feed file. Defaults to the feed bundled with this
            module.

    Returns:
        The parsed signatures.
    """
    feed_path = Path(path) if path else _BUNDLED_TECH_SIGNATURES
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    return [
        TechSignature(
            name=signature["name"],
            matchers=tuple(
                TechMatcher(part=m["part"], words=tuple(m["words"]))
                for m in signature["matchers"]
            ),
        )
        for signature in data.get("signatures", [])
    ]


_TECH_SIGNATURES: List[TechSignature] = load_tech_signatures()


def _tech_evidence(response: Response, title: Optional[str], error_resp: Optional[Response]) -> Dict[str, str]:
    """Assemble the named evidence parts a :class:`TechMatcher` can target."""
    evidence = {
        "body": response.body,
        "title": title or "",
        "error_body": error_resp.body if error_resp else "",
    }
    for name, value in response.headers.items():
        evidence[f"header:{name}"] = value
    return evidence


def _signature_matches(signature: TechSignature, evidence: Dict[str, str]) -> bool:
    """Return whether any of a signature's matchers fires against ``evidence``."""
    for matcher in signature.matchers:
        text = evidence.get(matcher.part, "").lower()
        if any(word.lower() in text for word in matcher.words):
            return True
    return False


def _extract_title(body: str) -> Optional[str]:
    """Extract the ``<title>`` text from an HTML body, best-effort.

    Args:
        body: The HTML response body.

    Returns:
        The title text, or ``None`` if there is no well-formed title tag.
    """
    lower = body.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    start = lower.find(">", start)
    if start == -1:
        return None
    end = lower.find("</title>", start)
    if end == -1:
        return None
    return body[start + 1:end].strip() or None


def _parse_server_header(server: str) -> Tuple[Optional[str], Optional[str]]:
    """Split an HTTP ``Server`` header into product and version.

    Drops any trailing comment such as ``(Unix)`` or ``(Ubuntu)``.

    Args:
        server: The raw ``Server`` header value, e.g. ``"Apache/2.4.49 (Unix)"``.

    Returns:
        A ``(product, version)`` tuple. The version is ``None`` when the header
        carries only a bare product name (e.g. ``"nginx"``).
    """
    server = (server or "").strip()
    if not server:
        return None, None
    token = server.split()[0]  # drop trailing "(Unix)" / "(Ubuntu)" comments
    if "/" in token:
        product, version = token.split("/", 1)
        return product or None, version or None
    return token, None


def fingerprint_http(
    response: Response,
    favicon: Optional[bytes] = None,
    error_resp: Optional[Response] = None,
) -> HttpFingerprint:
    """Fingerprint an HTTP service from a response and, optionally, its favicon.

    The confidence follows a simple three-tier scheme: a versioned ``Server``
    header is the strongest signal (0.9), a bare product name is weaker (0.6),
    and a technology matched only from the body or title contributes a name but
    no confidence on its own. These stay below what Nmap's own direct CPE would
    earn, because this layer has not yet been calibrated against the oracle.

    Args:
        resp: The HTTP response to analyse (a plain ``GET /``).
        favicon: The raw bytes of the site's favicon, if fetched.
        error_resp: The response to a deliberately nonexistent path, if
            fetched — lets an ``error_body`` signature match branding that
            only shows up on a custom error page, not the homepage.

    Returns:
        An :class:`HttpFingerprint`.
    """
    server = response.headers.get("server", "")
    product, version = _parse_server_header(server)
    title = _extract_title(response.body)
    evidence = _tech_evidence(response, title, error_resp)
    technologies = tuple(sig.name for sig in _TECH_SIGNATURES if _signature_matches(sig, evidence))
    favicon_hash = hashlib.sha256(favicon).hexdigest() if favicon else None

    if not product and technologies:
        product = technologies[0]

    if product and version:
        confidence = 0.9
    elif product:
        confidence = 0.6
    else:
        confidence = 0.0

    return HttpFingerprint(
        product=product, version=version, title=title,
        favicon_hash=favicon_hash, technologies=technologies, confidence=confidence,
    )


@register_dissector
class HttpDissector(Dissector):
    """Fase F's highest-value protocol: GET /, its favicon, and a nonexistent
    path (for error-page-only vendor signatures), combined into one fingerprint."""

    label = "HTTP"

    def __init__(self, probe: Optional[HttpProbe] = None) -> None:
        self._probe = probe or HttpProbe()

    def applies(self, service) -> bool:
        return is_http_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        response = self._probe.fetch(target, service.port, "GET", "/")
        if response is None:
            return None
        rate_limiter.acquire(target)
        favicon = self._probe.fetch_bytes(target, service.port, "/favicon.ico")
        rate_limiter.acquire(target)
        # Some vendors brand their error page more than their homepage (a
        # SonicWall's 404 body says so, its "/" doesn't) — see fingerprint_http.
        error_resp = self._probe.fetch(target, service.port, "GET", "/lybra-nonexistent-check")
        fingerprint = fingerprint_http(response, favicon, error_resp)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
