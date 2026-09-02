"""The HTTP dissector — the fingerprinting package's highest-value protocol.

Reads the ``Server`` / ``X-Powered-By`` headers, the page ``<title>``, a hash
of the favicon, and a data-driven, Wappalyzer-style signature feed
(``tech_signatures.json``) covering both web CMS/software (WordPress,
Drupal...) and network-appliance vendors (SonicWall, pfSense, MikroTik...). A
signature can also match a deliberately-nonexistent path's error page — some
vendors brand their 404 more than their homepage, which is exactly how the
SonicWall entry was found in the first place (see ``error_body`` below).

**La versión no sale de una sola fuente** (L18). Salía: la cabecera
``Server``, y nada más. Y ``server_tokens off`` en nginx, ``ServerTokens
Prod`` en Apache y prácticamente cualquier CDN o WAF la suprimen, así que el
caso más común en producción era justo el que dejaba al motor sin versión —
luego sin CPE, luego sin un solo CVE. El banco lo tenía documentado como punto
ciego: uno de sus contenedores es un nginx con ``server_tokens off`` que ni
Lybra ni el propio Nmap identifican.

:func:`_version_readings` es la cascada que lo sustituye. Recorre, en orden de
confianza decreciente, la evidencia que la sonda **ya se ha descargado**, y se
queda con la primera lectura que traiga producto y versión juntos:

===== ============================================ ==========
Nivel Fuente                                       Confianza
===== ============================================ ==========
1     Cabecera ``Server`` con versión                   0,90
2     ``X-AspNet-Version`` / ``X-Powered-By`` / ...     0,85
3     ``<meta name="generator">``                       0,80
4     Firma del feed con ``versionPattern``             0,75
5     Página de error por defecto                       0,60
6     Versión repetida en rutas de assets               0,60
===== ============================================ ==========

Cada nivel deja escrito de dónde salió (``HttpFingerprint.version_source``),
que es lo que permite que el ``qod`` del hallazgo refleje la calidad de la
evidencia en vez de ser una constante.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

from ..checks import HttpProbe, Response, is_http_service
from .dispatch import Dissector, DissectorResult, QOD_FINGERPRINT
from .favicon import FaviconCatalog, favicon_hash as favicon_hash_value
from .registry import register_dissector


@dataclass(frozen=True)
class HttpFingerprint:  # pylint: disable=too-many-instance-attributes
    """The result of fingerprinting an HTTP service.

    Es un objeto de valor: cada atributo es una lectura distinta de la misma
    respuesta, y agruparlos en sub-objetos sólo añadiría un nivel de acceso sin
    quitar ningún dato.

    Attributes:
        product: The identified product name, or ``None``.
        version: The identified version, or ``None``.
        title: The page ``<title>``, or ``None``.
        favicon_hash: A SHA-256 hex digest of the favicon, or ``None`` — la
            identidad exacta del fichero.
        favicon_catalog_hash: El hash de catálogo del favicon (MurmurHash3 en
            la convención pública), o ``None``. Es el que se busca en
            ``feeds/favicon_hashes.json``; ver ``fingerprinting/favicon.py``
            para por qué se guardan los dos.
        layers: Todas las capas de servidor observadas en el puerto, no sólo la
            que ``product`` reporta (ver :class:`ServiceLayer`). Tiene una sola
            entrada en el caso normal y dos cuando hay un proxy inverso
            delante de un servidor distinto.
        technologies: A tuple of technology names matched by signature.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
        version_source: De qué nivel de la cascada salió la versión (uno de
            :data:`VERSION_SOURCES`), o ``None`` si no hay versión. Es la
            procedencia, no un adorno: una versión leída de un ``Server``
            explícito y otra deducida de una página de error no merecen el
            mismo ``qod``, y hasta ahora las dos recibían el mismo porque sólo
            había un nivel.
    """
    product: Optional[str]
    version: Optional[str]
    title: Optional[str]
    favicon_hash: Optional[str]
    technologies: tuple
    confidence: float
    version_source: Optional[str] = None
    favicon_catalog_hash: Optional[int] = None
    layers: Tuple[ServiceLayer, ...] = ()


@dataclass(frozen=True)
class ServiceLayer:
    """Una de las capas de software que atienden un mismo puerto.

    Un servicio HTTP no es siempre **un** programa. La topología más corriente
    que existe —un nginx haciendo de proxy inverso por delante de un Apache— son
    dos, y el modelo anterior (``product`` + ``version``, uno y sólo uno) no
    podía expresarlo: se quedaba con lo que dijera la cabecera ``Server``, que
    la pone el de delante.

    Eso salió caro en la medición real (L48-b): cinco servicios en tres hosts,
    siempre el mismo patrón — Lybra decía ``nginx``, Nmap decía ``Apache
    httpd``. **Ninguno de los dos estaba equivocado**; describían capas
    distintas de la misma pila. Pero para resolver un CPE y correlacionar CVEs
    la diferencia es enorme: buscar vulnerabilidades de nginx en un host cuyo
    servidor real es Apache produce falsos negativos por un lado y falsos
    positivos por el otro.

    Attributes:
        product: El producto de esta capa.
        version: Su versión, si se leyó.
        role: ``"edge"`` para lo que contesta en el puerto (lo que la cabecera
            ``Server`` nombra) y ``"origin"`` para lo que se deduce que hay
            detrás. Es una descripción de dónde se observó, no una jerarquía de
            importancia: las dos capas están expuestas y las dos tienen CVEs.
        source: El nivel de la cascada del que salió (:data:`VERSION_SOURCES`).
    """
    product: str
    version: Optional[str]
    role: str
    source: str


@dataclass(frozen=True)
class VersionReading:
    """Un nivel de la cascada que ha conseguido leer algo.

    Producto y versión viajan juntos a propósito: son la misma lectura. Un
    ``Server: nginx/1.24.0`` y un ``<meta generator> WordPress 6.4.2`` en la
    misma respuesta describen dos capas distintas de la pila, y cruzarlos
    produciría ``nginx 6.4.2`` — un CPE que no existe.

    Attributes:
        product: El producto que esta fuente nombra, o ``None`` si la fuente
            sólo aporta versión (``X-AspNet-Version``, que implica ASP.NET).
        version: La versión leída, o ``None``.
        confidence: La confianza del nivel.
        source: El identificador del nivel (:data:`VERSION_SOURCES`).
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float
    source: str


# Los niveles de la cascada, del más explícito al más deducido. El orden de
# esta tabla **es** el orden de preferencia: :func:`_version_readings` la
# recorre y se queda con la primera lectura completa.
VERSION_SOURCES: Tuple[str, ...] = (
    "server-header",
    "powered-by-header",
    "meta-generator",
    "tech-signature",
    "error-page",
    "asset-path",
)

# Confianza por nivel. Un salto pequeño entre niveles contiguos y grande entre
# "lo dijo el servidor" y "lo he deducido de la página": la diferencia que de
# verdad importa aguas abajo.
_SOURCE_CONFIDENCE: Dict[str, float] = {
    "server-header": 0.9,
    "powered-by-header": 0.85,
    "meta-generator": 0.8,
    "tech-signature": 0.75,
    "error-page": 0.6,
    "asset-path": 0.6,
}


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

# El catálogo de favicons, cargado una vez al importar igual que el feed de
# firmas. ``HttpDissector`` consulta ``is_empty`` para decidir si merece la
# pena pedir ``/favicon.ico`` siquiera.
_FAVICON_CATALOG = FaviconCatalog()


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


# ``<meta name="generator" content="WordPress 6.4.2">`` — la etiqueta que
# WordPress, Drupal, Joomla, TYPO3, Hugo y Jekyll rellenan sin que nadie se lo
# pida. Los atributos pueden ir en cualquier orden y con comillas de los dos
# tipos, de ahí las dos alternativas.
_META_GENERATOR_RE = re.compile(
    r"""<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']"""
    r"""|<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']generator["']""",
    re.IGNORECASE,
)

# "WordPress 6.4.2", "Drupal 10", "TYPO3 CMS 12.4.8" — nombre (una o dos
# palabras) seguido de un número de versión.
# El producto admite signos de marca (el "!" de "Joomla!", el "+" de "C++") y
# se recorta después: en NVD el producto se llama `joomla`, no `Joomla!`.
_PRODUCT_VERSION_RE = re.compile(
    r"^\s*(?P<product>[A-Za-z][\w.\-!+]*(?:\s+[A-Za-z][\w.\-!+]*)?)"
    r"\s+v?(?P<version>\d+(?:\.\d+)*)",
)

# Cabeceras que anuncian plataforma y, a veces, versión. El orden es el de
# utilidad: X-AspNet-Version trae la versión exacta y nada más, así que gana.
_POWERED_BY_HEADERS: Tuple[Tuple[str, Optional[str]], ...] = (
    ("x-aspnet-version", "ASP.NET"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-powered-by", None),
    ("x-generator", None),
)

# "Apache/2.4.49 (Debian) Server at example.com Port 80" — la firma que Apache,
# nginx y Tomcat estampan en sus páginas de error por defecto. "Apache Tomcat"
# va antes que "Apache" porque el primero contiene al segundo.
_ERROR_PAGE_RE = re.compile(
    r"\b(?P<product>Apache Tomcat|Apache|nginx|lighttpd|Microsoft-IIS|openresty)"
    r"[/ ](?P<version>\d+(?:\.\d+)+)",
    re.IGNORECASE,
)

# "?ver=6.4.2" / "&v=1.2.3" en la URL de un asset. Ver
# :func:`_version_from_asset_paths` para por qué esta señal es la última y por
# qué exige repetición.
_ASSET_VERSION_RE = re.compile(r"[?&](?:ver|v|version)=(\d+(?:\.\d+)+)")


def _split_product_version(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Parte un texto tipo ``"WordPress 6.4.2"`` en producto y versión.

    Args:
        text: El texto a partir.

    Returns:
        Un par ``(producto, versión)``; ambos ``None`` si el texto está vacío.
        Un producto sin número detrás devuelve ``(producto, None)``: el nombre
        se leyó, la versión no estaba.
    """
    text = (text or "").strip()
    if not text:
        return None, None
    match = _PRODUCT_VERSION_RE.match(text)
    if match:
        return match.group("product").strip(" !+.-"), match.group("version")
    # Sin número: sigue siendo un nombre de producto utilizable.
    first = text.split(";")[0].split("(")[0].strip()
    return (first or None), None


def _powered_by_reading(headers: Dict[str, str]) -> Optional[VersionReading]:
    """Nivel 2: la plataforma que la respuesta anuncia en sus propias cabeceras.

    El docstring del paquete prometía desde el principio que se leía
    ``X-Powered-By``; el código sólo miraba ``Server``. Esto lo cumple.

    ``X-AspNet-Version`` es un caso aparte: su valor es la versión desnuda
    (``4.0.30319``), sin nombre, así que el producto lo pone la cabecera misma.

    Args:
        headers: Las cabeceras de la respuesta, con las claves en minúsculas.

    Returns:
        La lectura, o ``None`` si ninguna de estas cabeceras aporta versión.
    """
    for name, implied_product in _POWERED_BY_HEADERS:
        value = (headers.get(name) or "").strip()
        if not value:
            continue
        if implied_product:
            product = implied_product
            version = value if re.fullmatch(r"\d+(?:\.\d+)*", value) else None
        else:
            # "PHP/8.1.2", "Express", "Drupal 10 (https://www.drupal.org)"
            product, version = _split_product_version(value.replace("/", " "))
        if product and version:
            return VersionReading(product, version,
                                  _SOURCE_CONFIDENCE["powered-by-header"],
                                  "powered-by-header")
    return None


def _generator_reading(body: str) -> Optional[VersionReading]:
    """Nivel 3: la etiqueta ``<meta name="generator">`` de la página.

    Args:
        body: El cuerpo HTML de la respuesta.

    Returns:
        La lectura, o ``None`` si no hay etiqueta o no nombra producto.
    """
    match = _META_GENERATOR_RE.search(body or "")
    if not match:
        return None
    content = match.group(1) or match.group(2) or ""
    product, version = _split_product_version(content)
    if not product:
        return None
    return VersionReading(product, version,
                          _SOURCE_CONFIDENCE["meta-generator"], "meta-generator")


def _error_page_reading(error_resp: Optional[Response]) -> Optional[VersionReading]:
    """Nivel 5: la página de error por defecto, que el motor ya se descarga.

    ``HttpDissector.probe`` pide una ruta inexistente para que las firmas de
    fabricante puedan mirar un 404 con marca. Esa misma respuesta lleva, cuando
    el servidor no la ha personalizado, su propia firma con versión — y no se
    estaba leyendo.

    Args:
        error_resp: La respuesta a la ruta inexistente, si se pidió.

    Returns:
        La lectura, o ``None``.
    """
    if error_resp is None:
        return None
    match = _ERROR_PAGE_RE.search(error_resp.body or "")
    if not match:
        return None
    return VersionReading(match.group("product"), match.group("version"),
                          _SOURCE_CONFIDENCE["error-page"], "error-page")


def _version_from_asset_paths(body: str) -> Optional[str]:
    """Nivel 6: la versión estampada en las URLs de los assets de la página.

    La señal más débil de la cascada, y la única que exige una condición
    adicional: **el mismo número tiene que aparecer en al menos dos assets
    distintos**. Un ``?ver=`` suelto es casi siempre la versión de *ese*
    fichero —una librería de terceros, un plugin— y no la de la aplicación;
    tomarlo por bueno produciría un CPE de la aplicación con la versión de una
    dependencia, que es peor que no dar versión. Cuando un CMS estampa su
    propia versión, en cambio, la estampa en todos sus assets de núcleo, y esa
    repetición es lo que distingue la señal del ruido.

    Nunca aporta producto: sólo completa uno ya identificado por otra vía.

    Args:
        body: El cuerpo HTML de la respuesta.

    Returns:
        La versión repetida, o ``None`` si no hay ninguna o si hay más de una
        candidata (ambigüedad: mejor callar).
    """
    counts: Dict[str, int] = {}
    for version in _ASSET_VERSION_RE.findall(body or ""):
        counts[version] = counts.get(version, 0) + 1
    repeated = [version for version, count in counts.items() if count >= 2]
    return repeated[0] if len(repeated) == 1 else None


def _version_readings(
    response: Response,
    hits: List[SignatureHit],
    error_resp: Optional[Response],
) -> List[VersionReading]:
    """Construye la cascada completa, en orden de confianza decreciente.

    Args:
        response: La respuesta a ``GET /``.
        hits: Las firmas del feed que han casado.
        error_resp: La respuesta a la ruta inexistente, si se pidió.

    Returns:
        Las lecturas que alguna fuente ha conseguido producir, ordenadas.
    """
    server_product, server_version = _parse_server_header(response.headers.get("server", ""))
    readings: List[Optional[VersionReading]] = [
        VersionReading(server_product, server_version,
                       _SOURCE_CONFIDENCE["server-header"], "server-header")
        if server_product else None,
        _powered_by_reading(response.headers),
        _generator_reading(response.body),
    ]
    readings += [
        VersionReading(hit.name, hit.version,
                       _SOURCE_CONFIDENCE["tech-signature"], "tech-signature")
        for hit in hits
    ]
    readings.append(_error_page_reading(error_resp))
    return [reading for reading in readings if reading is not None]


# Productos que son servidores HTTP, no aplicaciones. Sólo entre dos de éstos
# tiene sentido hablar de "proxy delante de un origen": un WordPress detectado
# junto a un nginx no son dos capas de servidor, son el servidor y lo que sirve.
_SERVER_PRODUCTS = (
    "nginx", "apache", "apache tomcat", "tomcat", "microsoft-iis", "iis",
    "lighttpd", "openresty", "caddy", "jetty", "gunicorn", "cherokee",
    "litespeed", "haproxy", "varnish", "envoy", "traefik", "squid",
)

# Cabeceras cuya sola presencia delata que hay un intermediario. No identifican
# el origen —para eso hace falta una lectura de producto— pero sí confirman que
# la respuesta ha pasado por más de una mano, y eso decide si dos lecturas
# distintas son "dos capas" o "una lectura equivocada".
_PROXY_EVIDENCE_HEADERS = (
    "via", "x-cache", "x-cache-hits", "x-varnish", "x-proxy-cache",
    "cf-ray", "x-served-by", "x-forwarded-server", "x-backend-server",
)


# Los productos de la lista anterior que además se despliegan habitualmente
# **por delante** de otro servidor. Que el borde sea uno de éstos es, por sí
# solo, evidencia de que puede haber algo detrás.
_PROXY_PRODUCTS = ("nginx", "haproxy", "varnish", "envoy", "traefik",
                   "squid", "openresty", "caddy")


def _is_known_proxy(product: Optional[str]) -> bool:
    """Si un producto se despliega habitualmente como proxy inverso."""
    lowered = (product or "").lower()
    return any(proxy in lowered for proxy in _PROXY_PRODUCTS)


def _is_server_product(product: Optional[str]) -> bool:
    """Si un nombre de producto es un servidor HTTP y no una aplicación."""
    lowered = (product or "").lower()
    return any(server in lowered for server in _SERVER_PRODUCTS)


def _same_product(first: Optional[str], second: Optional[str]) -> bool:
    """Si dos nombres se refieren al mismo producto.

    Comparación por solapamiento de subcadena, igual que hace el arnés de
    concordancia: "Apache" y "Apache Tomcat" no son lo mismo, pero "nginx" y
    "nginx" escritos con distinta caja sí.
    """
    if not first or not second:
        return False
    first, second = first.lower(), second.lower()
    return first in second or second in first


def _detect_layers(
    response: Response,
    readings: List[VersionReading],
    chosen: Optional[ServiceLayer],
) -> Tuple[ServiceLayer, ...]:
    """Reconoce las capas de servidor que atienden el puerto.

    **El rol de una capa lo decide dónde se observó, no cuál gana la versión.**
    La capa de borde es siempre la que nombra la cabecera ``Server``: es
    literalmente quien ha escrito la respuesta. Lo que se deduce por cualquier
    otra vía —una página de error sin personalizar, una cabecera de plataforma—
    es el origen, aunque su lectura sea la más completa de las dos. Confundir
    esto daría exactamente la vuelta al diagnóstico: diría que el Apache está
    delante porque su versión se leyó mejor.

    Una segunda capa se declara sólo cuando se cumplen las dos condiciones:

    1. Alguna otra fuente nombra un **servidor** distinto. Una aplicación
       identificada por firma no cuenta: un WordPress detrás de un nginx no son
       dos capas de servidor, son el servidor y lo que sirve.
    2. Hay evidencia de intermediario — o la cabecera ``Server`` nombra un
       proxy conocido, o la respuesta trae alguna cabecera que sólo pone un
       intermediario.

    Sin la segunda condición esto degeneraría en declarar una capa nueva cada
    vez que dos fuentes discrepan, que es justo el ruido que se quiere evitar.

    Args:
        response: La respuesta a ``GET /``.
        readings: Las lecturas de la cascada.
        chosen: La capa que ``_resolve_identity`` eligió reportar, si hay.

    Returns:
        Las capas observadas, la de borde primero. Vacía si no se identificó
        ningún producto.
    """
    if chosen is None:
        return ()

    # Quien escribe la cabecera ``Server`` **es** el borde, se reconozca su
    # nombre o no: un producto a medida sigue siendo lo que contesta en el
    # puerto. La lista de servidores conocidos sólo filtra al candidato a
    # origen, más abajo, donde sí hace falta distinguir un servidor de una
    # aplicación.
    edge = next(
        (reading for reading in readings if reading.source == "server-header"),
        None,
    )
    if edge is None:
        return (chosen,)

    origin = next(
        (reading for reading in readings
         if reading.source != "server-header"
         and _is_server_product(reading.product)
         and not _same_product(reading.product, edge.product)),
        None,
    )
    has_proxy_header = any(response.headers.get(name) for name in _PROXY_EVIDENCE_HEADERS)
    if origin is None or not (has_proxy_header or _is_known_proxy(edge.product)):
        return (chosen,)

    return (
        ServiceLayer(edge.product, edge.version, "edge", edge.source),
        ServiceLayer(origin.product, origin.version, "origin", origin.source),
    )


def _resolve_identity(
    readings: List[VersionReading],
    body: str,
) -> Tuple[Optional[str], Optional[str], float, Optional[str]]:
    """Elige, entre todas las lecturas, la identidad que se va a reportar.

    Gana la primera lectura **completa** (producto y versión juntos), porque la
    lista ya viene en orden de confianza decreciente. Si ninguna lo está, se
    conserva el producto de la lectura más fiable que al menos lo nombre y se
    intenta el último nivel: la versión que las rutas de assets confirmen por
    repetición, que sólo completa un producto ya identificado.

    Args:
        readings: Las lecturas de la cascada, en orden.
        body: El cuerpo de la respuesta, para el nivel de rutas de assets.

    Returns:
        Una tupla ``(producto, versión, confianza, procedencia)``.
    """
    complete = next((reading for reading in readings if reading.product and reading.version), None)
    if complete is not None:
        return complete.product, complete.version, complete.confidence, complete.source

    named = next((reading for reading in readings if reading.product), None)
    product = named.product if named else None
    if not product:
        return None, None, 0.0, None

    version = _version_from_asset_paths(body)
    if version:
        return product, version, _SOURCE_CONFIDENCE["asset-path"], "asset-path"
    return product, None, 0.6, None


def fingerprint_http(
    response: Response,
    favicon: Optional[bytes] = None,
    error_resp: Optional[Response] = None,
) -> HttpFingerprint:
    """Fingerprint an HTTP service from a response and, optionally, its favicon.

    La versión sale de una **cascada** de fuentes, no de la cabecera ``Server``
    (ver el docstring del módulo). Se recorren en orden de confianza
    decreciente y gana la primera lectura que traiga producto y versión juntos;
    si ninguna los trae, se conserva el mejor producto disponible y la versión
    se queda sin rellenar, salvo que las rutas de assets de la página ofrezcan
    una repetida (el último nivel, que sólo completa un producto ya conocido).

    Producto y versión salen siempre de la **misma** lectura. Cruzarlos —el
    nombre de una fuente con el número de otra— produciría un CPE que no
    existe; es la misma regla que gobierna las firmas del feed.

    Args:
        response: The HTTP response to analyse (a plain ``GET /``).
        favicon: The raw bytes of the site's favicon, if fetched.
        error_resp: The response to a deliberately nonexistent path, if
            fetched — lets an ``error_body`` signature match branding that
            only shows up on a custom error page, not the homepage.

    Returns:
        An :class:`HttpFingerprint`.
    """
    title = _extract_title(response.body)
    evidence = _tech_evidence(response, title, error_resp)
    candidates = (_signature_hit(signature, evidence) for signature in _TECH_SIGNATURES)
    hits = [hit for hit in candidates if hit]
    technologies = tuple(hit.name for hit in hits)
    favicon_digest = hashlib.sha256(favicon).hexdigest() if favicon else None

    readings = _version_readings(response, hits, error_resp)
    product, version, confidence, version_source = _resolve_identity(readings, response.body)

    edge = (
        ServiceLayer(product, version, "edge", version_source or "server-header")
        if product else None
    )
    layers = _detect_layers(response, readings, edge)

    catalog_hash = favicon_hash_value(favicon) if favicon else None
    if not product:
        # Última red: el icono. Sólo se consulta cuando ninguna otra fuente ha
        # nombrado el producto — un favicon identifica producto y casi nunca
        # versión, así que nunca debe desplazar a una lectura que sí la trae.
        catalogued = _FAVICON_CATALOG.identify(favicon)
        if catalogued is not None:
            product = catalogued.product
            confidence = 0.5

    return HttpFingerprint(
        product=product, version=version, title=title,
        favicon_hash=favicon_digest, technologies=technologies,
        confidence=confidence, version_source=version_source,
        favicon_catalog_hash=catalog_hash, layers=layers,
    )


# ``qod`` del hallazgo de fingerprint según de dónde salió la versión. Es la
# tabla del §10 del roadmap ("banner que coincide con un patrón específico del
# producto: qod 80") aplicada por fin: hasta ahora todos los fingerprints
# llevaban la misma constante, así que una versión leída de un ``Server``
# explícito y otra deducida de una página de error valían exactamente lo
# mismo. Sigue siendo un hallazgo informativo —no alimenta la confianza de
# ninguna vulnerabilidad, ver ``dispatch.QOD_FINGERPRINT``—; lo que cambia es
# que ahora dice **cuánto se fía de su propia lectura**.
VERSION_SOURCE_QOD: Dict[str, int] = {
    "server-header": 90,
    "powered-by-header": 85,
    "meta-generator": 80,
    "tech-signature": 75,
    "error-page": 60,
    "asset-path": 60,
}


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
        # L20: la petición del favicon sólo se paga cuando puede pagarse a sí
        # misma. Con el catálogo vacío no hay nada con lo que comparar el icono,
        # así que pedirlo sería una petición de red por servicio HTTP —con su
        # turno de limitador— a cambio de un dato que nadie consulta.
        favicon = None
        if not _FAVICON_CATALOG.is_empty:
            rate_limiter.acquire(target)
            favicon = self._probe.fetch_bytes(target, service.port, "/favicon.ico")
        rate_limiter.acquire(target)
        # Some vendors brand their error page more than their homepage (a
        # SonicWall's 404 body says so, its "/" doesn't) — see fingerprint_http.
        error_resp = self._probe.fetch(target, service.port, "GET", "/lybra-nonexistent-check")
        fingerprint = fingerprint_http(response, favicon, error_resp)
        return DissectorResult(
            fingerprint.product,
            fingerprint.version,
            self.label,
            qod=VERSION_SOURCE_QOD.get(fingerprint.version_source or "", QOD_FINGERPRINT),
            # Sólo las capas que product/version no está ya reportando. Cuál
            # de las dos gana ese sitio lo decide la cascada de versión, no el
            # rol: en la topología medida en real es el origen quien trae
            # versión y el proxy quien no, así que la capa "sobrante" puede ser
            # cualquiera de las dos.
            extra_layers=tuple(
                (layer.product, layer.version, layer.role)
                for layer in fingerprint.layers
                if not _same_product(layer.product, fingerprint.product)
            ),
        )
