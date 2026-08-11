"""
Utilidades de texto/dominio compartidas entre las reglas de Iris (D6 en
plans/deuda-tecnica-y-calidad.md — antes mezclado con wordlists.py en un
único shared.py de 957 líneas).

Extracción de dominios/hosts, distancia de edición, homóglifos, y el
análisis de URL completo (``analyze_url``) que usan tanto Body Links (sobre
anchors HTML reales) como QR Code Links (sobre URLs decodificadas de una
imagen QR embebida). Los pocos datasets que esta capa necesita (marcas
canónicas, dominios de acortadores, ESPs conocidos…) se leen de
``wordlists.py``, nunca al revés.

Una regla nunca importa de otra regla — si dos reglas necesitan la misma
utilidad, vive aquí; si necesitan un dataset, vive en ``wordlists.py``.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from .wordlists import (
    canonical_brands,
    esp_tracker_domains,
    free_provider_domains,
    homoglyph_table,
    multi_level_tlds,
    multitenant_hosting_domains,
    shortener_domains,
    url_phishing_keywords,
)


# =============================================================================
# HELPERS DE DOMINIO / TEXTO COMPARTIDOS
# =============================================================================

_TAG_RE = re.compile(r"<[^>]+>")


def extract_domain(email: str) -> Optional[str]:
    """Extract the domain part from an email address string."""
    match = re.search(r"@([\w.-]+)", email)
    return match.group(1).lower() if match else None


def registrable_domain(domain: Optional[str]) -> Optional[str]:
    """Reduce a hostname to its registrable domain (best-effort, no PSL).

    ``mail.corp.paypal.com`` -> ``paypal.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``.  Good enough to compare organisational alignment.
    """
    if not domain:
        return None
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return domain.lower()
    last_two = ".".join(labels[-2:])
    if last_two in multi_level_tlds() and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def registrable_label(domain: str) -> str:
    """Return the owner-identifying label of the registrable domain.

    ``mail.paypal.com`` -> ``paypal``; ``a.example.co.uk`` -> ``example``.
    """
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return labels[0] if labels else ""
    last_two = ".".join(labels[-2:])
    if last_two in multi_level_tlds() and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def extract_display_name(from_header: str) -> str:
    """Extract the display-name portion of a ``From`` header.

    ``"ACME" <ops@acme.com>`` -> ``ACME``; a bare ``Marketing Team`` with no
    address -> ``Marketing Team``; a bare address -> ``""``.
    """
    if "<" in from_header:
        return from_header.split("<")[0].strip().strip('"').strip("'")
    name_part = from_header.strip()
    if "@" not in name_part:
        return name_part
    return ""


def url_host(url: str) -> Optional[str]:
    """Hostname (lowercase, sin credenciales ni puerto) de una URL, o None.

    Soporta netloc IPv6 entre corchetes (``[::1]:8080``) — un ``.split(":")``
    ingenuo lo destroza y deja solo ``"["`` (N4).
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    netloc = parsed.netloc
    if not netloc:
        return None
    netloc = netloc.split("@")[-1]
    if netloc.startswith("["):
        return netloc.split("]")[0].lstrip("[").lower() or None
    return netloc.split(":")[0].lower() or None


# Host numérico decimal (``http://2130706433/``) — rango completo de un IPv4.
_DECIMAL_IP_HOST_RE = re.compile(r"^\d{7,10}$")
# Host numérico hex (``http://0x7f000001/``).
_HEX_IP_HOST_RE = re.compile(r"^0x[0-9a-f]{1,8}$", re.IGNORECASE)


def is_obfuscated_ip_host(host: str) -> bool:
    """True cuando *host* es un literal IPv4 disfrazado de decimal u hex (N4).

    ``_URL_IP_HOST_RE`` (dotted-quad) no detecta estas formas — un enlace de
    phishing puede usarlas para evadir el chequeo de "IP literal" a simple vista.
    """
    if _DECIMAL_IP_HOST_RE.match(host):
        try:
            return 0 <= int(host) <= 0xFFFFFFFF
        except ValueError:
            return False
    return bool(_HEX_IP_HOST_RE.match(host))


def strip_html(html: str) -> str:
    """Reemplaza cualquier tag HTML por un espacio."""
    return _TAG_RE.sub(" ", html or "")


def is_free_provider(domain: Optional[str]) -> bool:
    """True cuando *domain* es (o es subdominio de) un webmail gratuito conocido."""
    if not domain:
        return False
    domain = domain.lower()
    return any(
        domain == provider or domain.endswith("." + provider)
        for provider in free_provider_domains()
    )


def levenshtein(a: str, b: str) -> int:
    """Distancia de edición clásica entre dos strings (DP en O(len_a*len_b))."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = temp
    return dp[n]


# Adyacencia física de teclas en un layout QWERTY (la misma tabla que usa
# dnstwist para su fuzzer "replacement"). Una sustitución de un solo
# carácter solo es un typo PLAUSIBLE -- lo que un humano tecleando rápido
# comete por accidente -- cuando las dos teclas están una al lado de la
# otra. Sin este filtro, `levenshtein(token, brand) == 1` también acepta
# cualquier sustitución arbitraria entre letras no relacionadas, y una
# palabra común de 5 letras cae a distancia 1 de *alguna* marca de 5 letras
# por pura coincidencia de diccionario (p. ej. "email" vs "gmail": la "e" y
# la "g" ni siquiera son vecinas) -- eso no es typosquatting, es ruido.
_QWERTY_ADJACENT: dict[str, str] = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4",
    "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "q23esa", "e": "w34rds", "r": "e45tfd", "t": "r56ygf",
    "y": "t67uhg", "u": "y78ijh", "i": "u89okj", "o": "i90plk", "p": "o0l",
    "a": "qwsz", "s": "qweadzx", "d": "wersfxc", "f": "ertdgcv", "g": "rtyfhvb",
    "h": "tyugjbn", "j": "yuihknm", "k": "uiojlm", "l": "iopk",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}


def is_plausible_typo(a: str, b: str) -> bool:
    """True cuando ``a`` y ``b`` están a distancia de edición 1 y esa edición
    es del tipo que un fat-finger real produce.

    Inserción/omisión de un carácter (longitudes distintas) siempre cuenta --
    "gmai.com"/"ggmail.com" son typos comunes independientes del layout. Una
    SUSTITUCIÓN (misma longitud) solo cuenta si las dos teclas son vecinas en
    QWERTY -- de lo contrario es una coincidencia de diccionario, no un typo.
    """
    if levenshtein(a, b) != 1:
        return False
    if len(a) != len(b):
        return True
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) != 1:
        return False  # defensivo: longitud igual + distancia 1 siempre es una sustitución
    i = diffs[0]
    return b[i] in _QWERTY_ADJACENT.get(a[i], "") or a[i] in _QWERTY_ADJACENT.get(b[i], "")


def normalize_homoglyphs(text: str) -> str:
    """Sustituye homóglifos comunes (0->o, 1->l, $->s…) y pasa a minúsculas."""
    return text.lower().translate(homoglyph_table())


def find_brand_in_subdomain(domain: str) -> Optional[dict]:
    """Detect a known brand used as a *non-registrable* label of ``domain``.

    ``github.com.sessions-security.com`` -> brand ``github`` appears to the
    left while the real registrable domain is ``sessions-security.com``. This
    is the brand-as-subdomain deception, reusable for both the From domain
    and body-link hosts. Returns ``{"brand", "label"}`` or ``None`` when the
    domain genuinely belongs to the brand (or no brand is embedded).
    """
    if not domain or "xn--" in domain:
        return None
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) < 3:
        return None
    brands = canonical_brands()
    if registrable_label(domain) in brands:
        return None  # genuinely the brand's own domain (e.g. mail.github.com)
    pre_labels = (
        labels[:-3] if ".".join(labels[-2:]) in multi_level_tlds() else labels[:-2]
    )
    for lbl in pre_labels:
        for token in re.split(r"[^a-z0-9]+", lbl):
            if token in brands:
                return {"brand": token, "label": lbl}
    return None


# =============================================================================
# URL analysis (shared by rules/body_links_rules.py's Body Links, over real
# HTML anchors, and its QR Code Links, over URLs decoded from an embedded
# QR image — a bare decoded URL has no "visible text" to compare against,
# hence the optional ``visible_text`` parameter).
# =============================================================================

_URL_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
_URL_IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_URL_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# More than this many labels in a host is structurally unusual for a
# legitimate sender (``click.email.notices.secure-portal-x7.info``) — kept
# as a low-weight signal since deep-but-legitimate infra hosts do exist.
URL_MAX_NORMAL_HOST_LABELS = 4

# Below this many percent-encoded triplets we don't even bother checking the
# ratio — a couple of ``%20``s in a query string is completely normal.
URL_MIN_ENCODED_TRIPLETS = 4
# Share of the URL's length made up of percent-encoded triplets (each worth
# 3 characters) above which the encoding looks like deliberate obfuscation
# rather than ordinary query-string escaping.
URL_DENSE_ENCODING_RATIO = 0.3


def _has_dense_encoding(href: str) -> bool:
    count = len(_URL_PERCENT_ENCODED_RE.findall(href))
    if count < URL_MIN_ENCODED_TRIPLETS:
        return False
    return (count * 3) / max(len(href), 1) >= URL_DENSE_ENCODING_RATIO


def analyze_url(href: str, sender_domain: Optional[str] = None,
                 visible_text: str = "") -> tuple[list[dict], int]:
    """Run the full battery of per-URL phishing heuristics against *href*.

    Checks: ``data:`` payloads, userinfo-as-lure (``user@host``), brand
    impersonation via subdomain trick, punycode/IDN, IP-literal hosts,
    known shorteners, visible-text-vs-href cloaking (only when
    *visible_text* is given — a QR-decoded URL has none), excessive
    subdomains, dense percent-encoding, and credential-harvesting
    keywords in the path/query of a non-sender/non-brand host.

    Returns:
        ``(findings, score)`` — *findings* is a list of per-URL finding
        dicts; *score* is the (negative) total penalty for this single
        URL, **not** floored — callers accumulate across multiple URLs
        and apply their own rule-level floor.
    """
    findings: list[dict] = []
    score = 0

    try:
        parsed = urlparse(href)
    except ValueError:
        return findings, score

    # A ``data:`` URI as a clickable link target has no host to inspect
    # and is itself unusual enough to flag on sight — legitimate mail
    # essentially never links to an inline data payload.
    if parsed.scheme == "data":
        findings.append({"type": "data_uri_link", "href": href[:120]})
        score -= 10
        return findings, score

    # Userinfo-as-lure: ``http://paypal.com@evil.io/`` — the text before
    # ``@`` is attacker-controlled and can be *any* string designed to
    # look like the real destination, while the browser only ever
    # navigates to the host after it.
    if parsed.scheme in ("http", "https") and "@" in parsed.netloc:
        findings.append({"type": "userinfo_credential_lure", "href": href})
        score -= 15

    host = url_host(href)
    if not host:
        return findings, score

    brands = canonical_brands()
    phishing_keywords = url_phishing_keywords()

    # Brand-as-subdomain impersonation: a known brand (or the sender's own
    # domain) appears as a left-hand label while the real registrable
    # domain is someone else's — e.g. ``github.com.sessions-security.com``.
    brand_hit = find_brand_in_subdomain(host)
    host_reg = registrable_domain(host)
    sender_impersonation = bool(
        sender_domain
        and host_reg != sender_domain
        and ("." + sender_domain + ".") in ("." + host + ".")
    )
    if brand_hit or sender_impersonation:
        findings.append({
            "type": "brand_impersonation",
            "href": href,
            "host": host,
            "real_domain": host_reg,
            "impersonates": (brand_hit or {}).get("brand") or sender_domain,
        })
        score -= 20

    if any(label.startswith("xn--") for label in host.split(".")):
        findings.append({"type": "punycode", "href": href})
        score -= 8

    if _URL_IP_HOST_RE.match(host) or is_obfuscated_ip_host(host):
        findings.append({"type": "ip_literal", "href": href})
        score -= 6

    if host in shortener_domains():
        findings.append({"type": "shortener", "href": href})
        score -= 4

    text_domain_match = _URL_DOMAIN_IN_TEXT_RE.search(visible_text or "")
    if text_domain_match:
        claimed = text_domain_match.group(1).lower()
        mismatch = claimed != host and not host.endswith("." + claimed) and claimed not in host
        # Calibración FP: el click-tracking reescribe el href a un subdominio
        # redirector dejando intacto el texto visible, así que un "mismatch"
        # literal es la forma NORMAL de todo boletín con tracking. Dos casos
        # son estructuralmente inocuos:
        #   1. claimed y host son el mismo dominio registrable (el redirector
        #      es otro subdominio de la misma organización);
        #   2. el href apunta al dominio registrable del PROPIO remitente --
        #      el destino es quien la víctima ya ve en el From, no un tercero.
        # El caso 2 NO se exime cuando el dominio del texto visible es una
        # marca conocida: ahí el texto sí promete una identidad ajena
        # ("paypal.com" visible, href al dominio del atacante), que es
        # exactamente el cloaking que esta señal existe para gatear.
        same_organisation = registrable_domain(claimed) == host_reg
        sender_owned_redirect = (
            sender_domain is not None
            and host_reg == sender_domain
            and registrable_label(claimed) not in brands
        )
        if mismatch and not same_organisation and not sender_owned_redirect:
            findings.append({
                "type": "cloaked_link",
                "visible_text": visible_text.strip(),
                "actual_href": href,
            })
            score -= 12

    # Recalibración de pesos: un enlace de tracking de un ESP conocido tiene
    # subdominios profundos (click.e.mailchimp.com) y codificación densa por
    # diseño (URL-encodea la URL de destino real en la query) — ninguna de
    # las dos cosas es evasión ahí, es la forma estructural normal de la
    # infraestructura de click-tracking. brand_impersonation/cloaked_link/
    # credential-harvest siguen activos sin excepción: un ESP comprometido
    # sigue siendo detectable por esas señales.
    is_esp_host = host in esp_tracker_domains() or registrable_domain(host) in esp_tracker_domains()

    # Unusually deep host — structurally weird even when no single label
    # matches a known brand. Low weight: legitimate deep CDN/infra
    # subdomains do exist, this is a soft additive signal, not a gate.
    if not is_esp_host and len(host.split(".")) > URL_MAX_NORMAL_HOST_LABELS:
        findings.append({"type": "excessive_subdomains", "href": href, "host": host})
        score -= 5

    if not is_esp_host and _has_dense_encoding(href):
        findings.append({"type": "dense_encoding", "href": href})
        score -= 6

    # Credential-harvesting keywords in the path/query — only counted
    # against a host that is neither the sender's own domain nor a known
    # brand's domain, since "login"/"verify"/"account" are completely
    # normal on a company's own site. An insecure (http) page asking for
    # credentials on top of that is the textbook harvesting-page pattern.
    #
    # N3: that "known brand's domain" carve-out is also what let a
    # credential-harvest form hosted on ``docs.google.com`` or
    # ``sharepoint.com`` through with zero findings — those are
    # multi-tenant hosting services where the path/subdomain is
    # attacker-controlled even though the registrable domain genuinely
    # belongs to the brand. Multi-tenant hosts are checked regardless of
    # the brand carve-out, at a lower weight (it can still be a
    # legitimate form) and tagged distinctly so the report doesn't read
    # as "the sender's own site is malicious".
    is_multitenant_host = any(
        host == hosting_domain or host.endswith("." + hosting_domain)
        for hosting_domain in multitenant_hosting_domains()
    )
    if is_multitenant_host or (host_reg != sender_domain and registrable_label(host) not in brands):
        path_and_query = f"{parsed.path} {parsed.query}".lower()
        kw_hits = [kw for kw in phishing_keywords if kw in path_and_query]
        if kw_hits:
            if is_multitenant_host:
                finding_type = "multitenant_credential_page"
                penalty = 8
            else:
                is_insecure = parsed.scheme == "http"
                finding_type = "insecure_credential_page" if is_insecure else "credential_harvest_path"
                penalty = 10 if is_insecure else 6
            findings.append({"type": finding_type, "href": href, "keywords": kw_hits})
            score -= penalty

    return findings, score
