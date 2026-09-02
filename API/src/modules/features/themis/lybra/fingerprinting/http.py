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
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

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
        version_pattern: Expresión regular opcional con un grupo llamado
            ``version``, evaluada sobre **la misma parte** que ``words``. Vive
            en el matcher y no en la firma porque el sitio donde está la
            versión depende del sitio donde se detectó el producto: WordPress
            se reconoce por ``wp-content`` en el cuerpo y publica su versión en
            un ``<meta name="generator">`` del mismo cuerpo, mientras que un
            ``X-Generator`` la trae en la cabecera. Un patrón por firma
            obligaría a elegir una de las dos.
    """
    part: str
    words: tuple
    version_pattern: Optional[Pattern] = None


@dataclass(frozen=True)
class TechSignature:
    """A named technology/vendor, identified by one or more :class:`TechMatcher`.

    Matchers within a signature are OR'd — any single one firing identifies
    the technology, the same "one piece of evidence is enough" model
    Wappalyzer itself uses.

    Una firma **puede** aportar versión, si alguno de sus matchers trae
    ``version_pattern`` y ese patrón captura. Si no, aporta sólo el nombre: la
    regla que separa esto de inventar CPEs es que un producto reconocido sin
    versión capturada se emite sin versión, nunca con una adivinada. El motor
    ya sigue ese criterio con Postfix y con Pure-FTPd.
    """
    name: str
    matchers: tuple


@dataclass(frozen=True)
class SignatureHit:
    """Lo que una firma aporta cuando casa: siempre el nombre, a veces la versión."""
    name: str
    version: Optional[str]


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
            matchers=tuple(_load_matcher(matcher) for matcher in signature["matchers"]),
        )
        for signature in data.get("signatures", [])
    ]


def _load_matcher(matcher: dict) -> TechMatcher:
    """Construye un :class:`TechMatcher` desde su entrada JSON.

    El ``versionPattern`` se compila al cargar y no en cada evaluación: es una
    vez por arranque en vez de una por servicio sondado, y además un patrón
    inválido revienta aquí —donde se ve— en vez de fallar en silencio contra
    un objetivo real.
    """
    pattern = matcher.get("versionPattern")
    return TechMatcher(
        part=matcher["part"],
        words=tuple(matcher["words"]),
        version_pattern=re.compile(pattern, re.IGNORECASE) if pattern else None,
    )


def validate_tech_signatures(signatures: List[TechSignature]) -> List[str]:
    """Comprueba que cada firma pueda llegar a casar, y describe las que no.

    Mismo criterio que ``checks.validate_checks`` (L27): el feed son datos que
    deciden si un producto se identifica, y su modo de fallo es el silencio —
    una firma sin matchers no casa nunca, un ``versionPattern`` sin grupo
    ``version`` casa y no aporta nada, y en los dos casos el escaneo termina en
    verde con un producto menos identificado. Convertirlo en fallo de CI es lo
    que impide que el catálogo crezca rompiéndose por el camino.

    ``load_tech_signatures`` ya rechaza un patrón que no compile (revienta al
    compilarlo), así que aquí no hace falta comprobarlo otra vez.

    Args:
        signatures: Las firmas cargadas.

    Returns:
        Una lista de problemas legibles, vacía si el feed está bien formado.
    """
    problems: List[str] = []
    seen: set = set()
    for signature in signatures:
        if not signature.name:
            problems.append("Una firma no tiene nombre")
            continue
        if signature.name in seen:
            problems.append(f"Firma duplicada: {signature.name}")
        seen.add(signature.name)
        if not signature.matchers:
            problems.append(f"{signature.name}: sin matchers, no casará nunca")
        for matcher in signature.matchers:
            if not matcher.part:
                problems.append(f"{signature.name}: un matcher no declara 'part'")
            if not matcher.words:
                problems.append(f"{signature.name}: un matcher no declara 'words'")
            if matcher.version_pattern is None:
                continue
            if "version" not in matcher.version_pattern.groupindex:
                problems.append(
                    f"{signature.name}: versionPattern sin grupo llamado 'version' "
                    f"({matcher.version_pattern.pattern})"
                )
    return problems


_TECH_SIGNATURES: List[TechSignature] = load_tech_signatures()


def _tech_evidence(
    response: Response,
    title: Optional[str],
    error_resp: Optional[Response],
) -> Dict[str, str]:
    """Assemble the named evidence parts a :class:`TechMatcher` can target."""
    evidence = {
        "body": response.body,
        "title": title or "",
        "error_body": error_resp.body if error_resp else "",
    }
    for name, value in response.headers.items():
        evidence[f"header:{name}"] = value
    return evidence


def _signature_hit(signature: TechSignature, evidence: Dict[str, str]) -> Optional[SignatureHit]:
    """Evalúa una firma contra la evidencia y devuelve lo que aporta.

    Se recorren **todos** los matchers aunque el primero ya haya casado: el que
    identifica el producto y el que captura la versión pueden ser distintos
    (``wp-content`` en el cuerpo detecta WordPress; el ``<meta generator>``,
    también en el cuerpo, es el que trae el número). Se para en cuanto hay
    versión, que es lo máximo que una firma puede aportar.

    Args:
        signature: La firma a evaluar.
        evidence: Las partes nombradas que un matcher puede inspeccionar.

    Returns:
        Un :class:`SignatureHit`, o ``None`` si ningún matcher casó.
    """
    did_match = False
    for matcher in signature.matchers:
        raw = evidence.get(matcher.part, "")
        text = raw.lower()
        if not any(word.lower() in text for word in matcher.words):
            continue
        did_match = True
        if matcher.version_pattern is None:
            continue
        found = matcher.version_pattern.search(raw)
        if found:
            return SignatureHit(name=signature.name, version=found.group("version"))
    return SignatureHit(name=signature.name, version=None) if did_match else None


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
    candidates = (_signature_hit(signature, evidence) for signature in _TECH_SIGNATURES)
    hits = [hit for hit in candidates if hit]
    technologies = tuple(hit.name for hit in hits)
    favicon_hash = hashlib.sha256(favicon).hexdigest() if favicon else None

    if not product and hits:
        # La versión de la firma sólo se acepta junto al producto de esa misma
        # firma. Un WordPress 6.4.2 detrás de un `Server: nginx` daría, si no,
        # "nginx 6.4.2": un CPE que no existe y una búsqueda de CVEs de otro
        # producto — exactamente el error que la regla de "no inventar CPE"
        # existe para evitar.
        product, version = hits[0].name, hits[0].version

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
