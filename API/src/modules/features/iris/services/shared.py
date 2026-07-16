"""
Helpers y datos compartidos entre las reglas de Iris.

Este módulo es el ÚNICO punto de compartición entre reglas hermanas: una
regla nunca importa de otra regla — si dos reglas necesitan el mismo
símbolo, vive aquí (ver ROADMAP.md, reglas transversales).

Los datasets de detección (marcas, dominios, keywords, extensiones…) se
leen de ``SecOpsConfig.json`` (bloque ``iris.data.*``) a través de
``config_reading.get_iris_data``. Cada dataset tiene un default embebido
en ``_DEFAULTS`` para que la aplicación arranque aunque la clave falte en
el JSON; el valor del JSON, cuando existe, tiene prioridad. Los regex se
quedan compilados en código (son lógica, no configuración).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlparse

import src.modules.system.config_reading as CR


# =============================================================================
# DEFAULTS DE DATASETS (fallback si SecOpsConfig.json no define iris.data.<key>)
# =============================================================================

_DEFAULTS: dict[str, Any] = {
    # Public-suffix de segundo nivel que requieren conservar dos labels
    # (lista pequeña y pragmática — un PSL completo es excesivo aquí).
    "multi_level_tlds": [
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.mx", "com.br",
        "com.ar", "com.au", "com.es", "co.in", "co.nz", "com.tr", "com.co",
    ],

    # Marcas canónicas usadas por lookalike/typosquat/subdomain checks.
    "canonical_brands": [
        "microsoft", "paypal", "netflix", "amazon", "google", "apple",
        "facebook", "instagram", "linkedin", "twitter", "whatsapp",
        "adobe", "dropbox", "spotify", "yahoo", "outlook", "hotmail",
        "gmail", "youtube", "tiktok", "snapchat", "pinterest",
        "telegram", "signal", "discord", "github", "gitlab",
        "bitbucket", "salesforce", "oracle", "ibm", "intel", "nvidia",
        "amd", "cisco", "vmware", "sap", "accenture", "deloitte",
        "pwc", "kpmg", "ey",
        "mercadopago", "bbva", "santander", "banamex",
        "bancomer", "hsbc", "amex", "mastercard", "visa",
        "wellsfargo", "chase", "bankofamerica",
        "alibaba", "aliexpress", "ebay", "shopify", "etsy",
        "walmart", "target", "costco", "homedepot", "bestbuy",
        "nike", "adidas", "zara", "hm", "uniqlo",
        "uber", "lyft", "airbnb", "booking", "expedia",
        "hulu", "disney", "hbomax", "primevideo",
        "wechat", "messenger", "skype",
        "zoom", "teams", "slack", "notion", "trello",
        "wordpress", "wix", "godaddy",
        "cloudflare", "digitalocean", "aws", "azure", "gcp",
    ],

    # Sustituciones de homóglifos char->char (Micr0soft, PayPa1, …).
    "homoglyph_map": {
        "0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s",
        "7": "t", "8": "b", "9": "g",
        "@": "a", "$": "s", "€": "e",
    },

    # Marca (keywords en display name) -> dominios legítimos de la marca.
    "brand_trusted_domains": [
        {"keywords": ["microsoft", "windows", "office 365", "microsoft 365",
                      "outlook", "azure", "msn"],
         "domains": ["microsoft.com", "microsoftsupport.com", "office.com",
                     "office365.com", "outlook.com", "hotmail.com", "live.com",
                     "azure.com", "msn.com", "windows.com", "xbox.com",
                     "microsoftonline.com", "sharepoint.com",
                     "teams.microsoft.com"]},
        {"keywords": ["paypal"],
         "domains": ["paypal.com", "paypal.de", "paypal.fr", "paypal.es",
                     "paypal.com.mx", "paypal.co.uk"]},
        {"keywords": ["netflix"],
         "domains": ["netflix.com", "nflx.com"]},
        {"keywords": ["amazon", "amazon prime", "amazon web services", "aws"],
         "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
                     "amazon.es", "amazon.it", "amazon.ca", "amazon.co.jp",
                     "amazonaws.com", "aws.amazon.com"]},
        {"keywords": ["google", "gmail", "youtube", "google drive"],
         "domains": ["google.com", "gmail.com", "youtube.com", "googlemail.com",
                     "googleusercontent.com", "googleapis.com"]},
        {"keywords": ["apple", "icloud", "itunes", "app store", "apple store"],
         "domains": ["apple.com", "icloud.com", "me.com", "mac.com"]},
        {"keywords": ["facebook", "meta", "instagram", "whatsapp", "messenger"],
         "domains": ["facebook.com", "fb.com", "fbcdn.net", "meta.com",
                     "instagram.com", "whatsapp.com", "messenger.com"]},
        {"keywords": ["linkedin"],
         "domains": ["linkedin.com", "linkedin-mail.com"]},
        {"keywords": ["twitter", "x.com"],
         "domains": ["twitter.com", "x.com"]},
        {"keywords": ["dropbox"],
         "domains": ["dropbox.com", "dropboxmail.com"]},
        {"keywords": ["adobe"],
         "domains": ["adobe.com", "adobeemail.com"]},
        {"keywords": ["bank of america", "boa"],
         "domains": ["bankofamerica.com", "ml.com"]},
        {"keywords": ["chase", "jpmorgan"],
         "domains": ["chase.com", "jpmorgan.com"]},
        {"keywords": ["wells fargo"],
         "domains": ["wellsfargo.com"]},
        {"keywords": ["bbva", "bancomer"],
         "domains": ["bbva.com", "bbva.com.mx", "bbvanet.com.mx"]},
        {"keywords": ["santander"],
         "domains": ["santander.com", "santander.com.mx", "santander.es",
                     "openbank.com"]},
        {"keywords": ["mercadopago", "mercadolibre"],
         "domains": ["mercadopago.com", "mercadolibre.com",
                     "mercadolibre.com.mx"]},
    ],

    # Proveedores de correo gratuito (webmail).
    "free_provider_domains": [
        "gmail.com", "googlemail.com",
        "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "yahoo.com.mx", "yahoo.es", "ymail.com",
        "aol.com", "aim.com",
        "protonmail.com", "proton.me",
        "mail.com", "email.com",
        "icloud.com", "me.com",
        "zoho.com", "yandex.com",
        "gmx.com", "gmx.es",
        "tutanota.com", "tutanota.de",
        "fastmail.com",
        "rediffmail.com",
        "mail.ru",
    ],

    # Acortadores de URL conocidos.
    "shortener_domains": [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
        "soo.gd", "s.id", "v.gd",
    ],

    # Extensiones de adjunto peligrosas.
    "dangerous_extensions": [
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi",
        ".msp", ".mst", ".cpl", ".pif", ".gadget",
        ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".psd1",
        ".ps1xml", ".wsf", ".wsh", ".wsc", ".sct", ".hta",
        ".py", ".rb", ".pl", ".sh", ".bash", ".zsh",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xla",
        ".ppa", ".ppam", ".sldm",
        ".lnk", ".url", ".website",
        ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf",
        ".jar",
        ".reg",
        ".appref-ms", ".settingcontent-ms", ".searchconnector-ms",
        ".application", ".xps",
    ],

    # MIME types sospechosos en Content-Type.
    "suspicious_mime_types": [
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-msi",
        "application/x-javascript",
        "application/javascript",
        "application/x-vb",
        "application/x-vbs",
        "application/x-powershell",
        "application/x-sh",
        "application/x-bat",
        "application/x-ms-shortcut",
        "application/x-iso9660-image",
        "application/java-archive",
        "application/octet-stream",
    ],

    # Documentos Office con macros habilitadas.
    "macro_extensions": [
        ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam", ".sldm",
    ],

    # Frases de captura de credenciales/pago en el cuerpo.
    "credential_phrases": [
        "verify your password", "confirm your password", "enter your password",
        "verify your account", "your account has been locked", "update your billing",
        "confirm your identity", "log in to verify", "click the link below to verify",
        "your account will be suspended", "unusual activity detected",
        "wire transfer", "payment is overdue", "outstanding invoice attached",
        "verify your social security", "update your payment information",
        "confirma tu contraseña", "verifica tu cuenta", "tu cuenta ha sido bloqueada",
        "actualiza tu información de pago", "transferencia bancaria urgente",
    ],

    # Keywords alarmantes de alta señal (account takeover, fraude, premios).
    "high_signal_keywords": [
        "action required", "acción requerida", "act now", "actúa ahora",
        "verify now", "verifica ahora", "verification required", "verificación requerida",
        "account suspended", "cuenta suspendida", "account blocked", "cuenta bloqueada",
        "password expired", "contraseña expirada",
        "security alert", "alerta de seguridad", "unauthorized access", "acceso no autorizado",
        "confirm your account", "confirma tu cuenta",
        "last warning", "último aviso", "final notice", "aviso final",
        "suspension notice", "aviso de suspensión", "reactivate", "reactivar",
        "billing issue", "problema de facturación", "payment failed", "pago fallido",
        "claim your prize", "reclama tu premio", "you won", "has ganado",
    ],

    # Keywords de baja señal (lenguaje de marketing también legítimo).
    "low_signal_keywords": [
        "urgent", "urgente", "immediate", "inmediato",
        "password reset", "restablecer contraseña",
        "limited time", "tiempo limitado", "expires soon", "vence pronto",
        "update required", "actualización requerida",
        "click here", "haz clic aquí", "download now", "descarga ahora",
        "exclusive offer", "oferta exclusiva", "free", "gratis",
        "dear customer", "estimado cliente", "dear user", "estimado usuario",
    ],

    # Emojis de alarma en Subject/display name.
    "alarming_emojis": [
        "\N{DOUBLE EXCLAMATION MARK}",
        "\N{EXCLAMATION QUESTION MARK}",
        "\N{CROSS MARK}",
        "\N{WARNING SIGN}",
    ],

    # TLDs desproporcionadamente abusados en phishing.
    "suspicious_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".club", ".top", ".loan", ".work",
        ".click", ".zip", ".download", ".review",
        ".country", ".kim", ".men", ".bid",
        ".trade", ".webcam", ".party", ".date",
        ".science", ".racing", ".win",
        ".faith", ".stream", ".accountant",
        ".cricket", ".pro",
        ".lol", ".mom",
        ".bar", ".name", ".info",
        ".mobi", ".pw",
    ],

    # Saludos genéricos de phishing masivo.
    "generic_greetings": [
        "dear customer", "dear user", "dear member", "dear sir", "dear madam",
        "dear sir or madam", "dear sir/madam", "dear account holder",
        "dear valued customer", "dear client", "dear subscriber",
        "dear email owner", "hello dear", "hello customer", "hello user",
        "attention customer", "attention user", "important notice to all",
        "to our valued customer", "to whom it may concern",
        "estimado cliente", "estimado usuario", "estimado miembro",
        "estimado cliente de", "distinguido cliente", "querido usuario",
        "hola cliente", "hola usuario", "atención cliente", "atención usuario",
        "a quien corresponda", "a todos los usuarios",
        "notificación para todos", "apreciable cliente", "apreciable usuario",
    ],

    # Verbos de acción combinables con el saludo genérico.
    "action_verbs": [
        "verify your account", "verify your identity", "verify your password",
        "verify your email", "verify your information", "verify your payment",
        "confirm your account", "confirm your identity", "confirm your password",
        "confirm your information", "confirm your payment", "confirm your billing",
        "confirm your details",
        "update your account", "update your billing", "update your payment",
        "update your information", "update your password",
        "reactivate your account", "re-activate your account",
        "unlock your account", "restore your account", "secure your account",
        "validate your account",
        "click here to verify", "click the link below", "click below to",
        "log in to verify", "sign in to confirm",
        "verifica tu cuenta", "verifica tu identidad", "verifica tu contraseña",
        "verifica tu correo", "verifica tu información", "verifica tu pago",
        "confirma tu cuenta", "confirma tu identidad", "confirma tu contraseña",
        "confirma tu información", "confirma los datos de su cuenta",
        "actualiza tu cuenta", "actualiza tu información",
        "actualiza tu contraseña", "actualiza tus datos", "actualiza tu pago",
        "reactiva tu cuenta", "desbloquea tu cuenta", "asegura tu cuenta",
        "valida tu cuenta",
        "haz clic aquí para verificar", "inicia sesión para verificar",
    ],

    # Frases de payload BEC (wire transfer, cripto, gift cards…), EN+ES.
    "bec_phrases": [
        "wire transfer", "wire the funds", "initiate a wire",
        "send the payment", "process the payment", "urgent payment",
        "outstanding invoice", "overdue invoice", "pay this invoice",
        "outstanding balance", "settle the balance", "make the deposit",
        "send gift cards", "buy gift cards", "purchase gift cards",
        "send bitcoin", "send crypto", "wire cryptocurrency", "usdt transfer",
        "change the bank account", "update our banking details",
        "new bank account", "new routing number", "new wire instructions",
        "change of vendor payment", "vendor banking update",
        "confidential transaction", "do not notify", "keep this confidential",
        "do this while i'm out", "while i'm in a meeting", "asap",
        "w-2 form", "w2 form", "employee tax forms", "1099 form",
        "transferencia urgente", "transferencia bancaria urgente",
        "realizar el pago", "procesar el pago", "pago pendiente",
        "factura pendiente", "factura vencida", "saldo pendiente",
        "comprar tarjetas de regalo", "tarjetas de regalo",
        "enviar bitcoin", "transferencia cripto", "criptomonedas",
        "cambiar la cuenta bancaria", "nueva cuenta bancaria",
        "número de ruta", "datos bancarios nuevos",
        "confidencial", "no notifiques", "no informar a",
        "mientras estoy en reunión", "con urgencia", "lo antes posible",
    ],

    # Action-words combinables con marcas en subdominios (secure-paypal…).
    "subdomain_action_words": [
        "login", "log-in", "signin", "sign-in", "secure", "security", "verify",
        "verification", "verification1", "account", "accounts", "support",
        "billing", "invoice", "update", "confirm", "auth", "authenticate",
        "service", "help", "alert", "alerts", "notification", "notifications",
        "online", "web", "portal", "office", "365", "mail", "team", "reset",
        "unlock", "recovery",
    ],

    # CDNs/trackers de ESPs legítimos (imágenes remotas esperables).
    "esp_tracker_domains": [
        "sendgrid.net", "mailgun.org", "mailchimp.com", "constantcontact.com",
        "hubspot.com", "hubspotusercontent-na1.net", "hubspotusercontent-eu1.net",
        "marketo.com", "eloqua.com", "exacttarget.com", "responsys.net",
        "mailerlite.com", "mailjet.com", "postmarkapp.com", "smtp.com",
        "amazonaws.com", "cloudfront.net", "googleusercontent.com",
        "s3.amazonaws.com", "mailchimpusercontent.com", "list-manage.com",
        "mktoresp.com", "en25.com", "s4.exacttarget.com",
        "s7.addthis.com", "addthis.com", "tracking.mi-al.it",
        "mta-in.com", "rs6.net", "t.sendgrid.net", "click.mi-al.it",
        "link.mi-al.it", "open.mi-al.it",
    ],

    # ESPs que estampan el Message-ID con su propio dominio (legítimo).
    "esp_msgid_domains": [
        "amazonses.com", "sendgrid.net", "sendgrid.com", "mailchimp.com",
        "mcsv.net", "rsgsv.net", "mcdlv.net", "mandrillapp.com", "mailgun.org",
        "mailgun.net", "sparkpostmail.com", "mtasv.net", "sendinblue.com",
        "sendibm1.com", "smtp.sendinblue.com", "postmarkapp.com", "mtaroutes.com",
        "mailjet.com", "mlsend.com", "sailthru.com", "exct.net", "cmail19.com",
        "cmail20.com", "icpbounce.com", "infusionmail.com", "klaviyomail.com",
        "constantcontact.com", "ctctemail.com", "hubspotemail.net",
    ],

    # Parámetros de query típicos de open redirectors.
    "redirect_params": [
        "url", "u", "redirect", "redirect_uri", "redirecturl", "redirect_url",
        "redir", "redirurl", "r", "return", "returnurl", "return_url",
        "next", "nexturl", "next_url", "continue", "dest", "destination",
        "target", "to", "link", "goto", "go", "out", "view", "ref", "referer",
        "forward", "forwarding", "external", "site", "page", "load", "loadurl",
    ],

    # Keywords de cosecha de credenciales en path/query de un enlace del cuerpo
    # (distinto de subdomain_action_words: éste se matchea contra la URL
    # completa, no contra labels de subdominio).
    "url_phishing_keywords": [
        "login", "log-in", "signin", "sign-in", "verify", "verification",
        "secure", "security", "account", "update", "confirm", "password",
        "credential", "authenticate", "unlock", "recovery", "billing",
        "invoice", "wallet", "suspended",
    ],

    # Charsets RFC 2047 casi nunca legítimos en correo moderno (todo lo
    # multilingüe genuino usa UTF-8 hoy) y con historial de uso como vector
    # de evasión de filtros/XSS. Deliberadamente NO incluye charsets
    # regionales legítimos (shift-jis, iso-2022-jp, koi8-r…) para no
    # penalizar correo internacional real.
    "exotic_charsets": [
        "utf-7", "unicode-1-1-utf-7", "csunicode11utf7", "x-unicode-2-0-utf-7",
    ],

    # Patrones de destinatarios ocultos en el To.
    "undisclosed_patterns": [
        "undisclosed", "undisclosed-recipients", "undisclosed recipients",
        "recipients not shown", "hidden recipients",
        "destinatarios no mostrados", "destinatarios ocultos",
        "para no mostrado",
    ],
}


def _data(key: str) -> Any:
    """Dataset ``iris.data.<key>``: valor del JSON si existe, si no el default."""
    value = CR.get_iris_data(key)
    return value if value is not None else _DEFAULTS[key]


@lru_cache(maxsize=None)
def _cached_set(key: str) -> frozenset[str]:
    return frozenset(_data(key))


@lru_cache(maxsize=None)
def _cached_tuple(key: str) -> tuple[str, ...]:
    return tuple(_data(key))


# --- Accessors públicos (uno por dataset) ------------------------------------

def multi_level_tlds() -> frozenset[str]:
    return _cached_set("multi_level_tlds")

def canonical_brands() -> frozenset[str]:
    return _cached_set("canonical_brands")

def free_provider_domains() -> tuple[str, ...]:
    return _cached_tuple("free_provider_domains")

def shortener_domains() -> frozenset[str]:
    return _cached_set("shortener_domains")

def dangerous_extensions() -> frozenset[str]:
    return _cached_set("dangerous_extensions")

def suspicious_mime_types() -> tuple[str, ...]:
    return _cached_tuple("suspicious_mime_types")

def macro_extensions() -> frozenset[str]:
    return _cached_set("macro_extensions")

def credential_phrases() -> tuple[str, ...]:
    return _cached_tuple("credential_phrases")

def high_signal_keywords() -> tuple[str, ...]:
    return _cached_tuple("high_signal_keywords")

def low_signal_keywords() -> tuple[str, ...]:
    return _cached_tuple("low_signal_keywords")

def alarming_emojis() -> tuple[str, ...]:
    return _cached_tuple("alarming_emojis")

def suspicious_tlds() -> frozenset[str]:
    return _cached_set("suspicious_tlds")

def generic_greetings() -> tuple[str, ...]:
    return _cached_tuple("generic_greetings")

def action_verbs() -> tuple[str, ...]:
    return _cached_tuple("action_verbs")

def bec_phrases() -> tuple[str, ...]:
    return _cached_tuple("bec_phrases")

def subdomain_action_words() -> frozenset[str]:
    return _cached_set("subdomain_action_words")

def esp_tracker_domains() -> frozenset[str]:
    return _cached_set("esp_tracker_domains")

def esp_msgid_domains() -> frozenset[str]:
    return _cached_set("esp_msgid_domains")

def redirect_params() -> frozenset[str]:
    return _cached_set("redirect_params")

def undisclosed_patterns() -> tuple[str, ...]:
    return _cached_tuple("undisclosed_patterns")

def url_phishing_keywords() -> tuple[str, ...]:
    return _cached_tuple("url_phishing_keywords")

def exotic_charsets() -> tuple[str, ...]:
    return _cached_tuple("exotic_charsets")


@lru_cache(maxsize=None)
def homoglyph_table() -> dict[int, str]:
    """Tabla para ``str.translate`` construida desde ``homoglyph_map``."""
    mapping = {str(k): str(v) for k, v in dict(_data("homoglyph_map")).items()}
    return str.maketrans(mapping)


@lru_cache(maxsize=None)
def brand_trusted_domains() -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    """Pares (keywords, dominios legítimos) por marca, desde ``brand_trusted_domains``."""
    return tuple(
        (tuple(entry["keywords"]), tuple(entry["domains"]))
        for entry in _data("brand_trusted_domains")
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
    """Hostname (lowercase, sin credenciales ni puerto) de una URL, o None."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    netloc = parsed.netloc
    if not netloc:
        return None
    return netloc.split("@")[-1].split(":")[0].lower() or None


def strip_html(html: str) -> str:
    """Reemplaza cualquier tag HTML por un espacio."""
    return _TAG_RE.sub(" ", html or "")


def is_free_provider(domain: Optional[str]) -> bool:
    """True cuando *domain* es (o es subdominio de) un webmail gratuito conocido."""
    if not domain:
        return False
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in free_provider_domains())


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
    labels = [l for l in domain.lower().strip(".").split(".") if l]
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

    if _URL_IP_HOST_RE.match(host):
        findings.append({"type": "ip_literal", "href": href})
        score -= 6

    if host in shortener_domains():
        findings.append({"type": "shortener", "href": href})
        score -= 4

    text_domain_match = _URL_DOMAIN_IN_TEXT_RE.search(visible_text or "")
    if text_domain_match:
        claimed = text_domain_match.group(1).lower()
        if claimed != host and not host.endswith("." + claimed) and claimed not in host:
            findings.append({
                "type": "cloaked_link",
                "visible_text": visible_text.strip(),
                "actual_href": href,
            })
            score -= 12

    # Unusually deep host — structurally weird even when no single label
    # matches a known brand. Low weight: legitimate deep CDN/infra
    # subdomains do exist, this is a soft additive signal, not a gate.
    if len(host.split(".")) > URL_MAX_NORMAL_HOST_LABELS:
        findings.append({"type": "excessive_subdomains", "href": href, "host": host})
        score -= 5

    if _has_dense_encoding(href):
        findings.append({"type": "dense_encoding", "href": href})
        score -= 6

    # Credential-harvesting keywords in the path/query — only counted
    # against a host that is neither the sender's own domain nor a known
    # brand's domain, since "login"/"verify"/"account" are completely
    # normal on a company's own site. An insecure (http) page asking for
    # credentials on top of that is the textbook harvesting-page pattern.
    if host_reg != sender_domain and registrable_label(host) not in brands:
        path_and_query = f"{parsed.path} {parsed.query}".lower()
        kw_hits = [kw for kw in phishing_keywords if kw in path_and_query]
        if kw_hits:
            is_insecure = parsed.scheme == "http"
            finding_type = "insecure_credential_page" if is_insecure else "credential_harvest_path"
            findings.append({"type": finding_type, "href": href, "keywords": kw_hits})
            score -= 10 if is_insecure else 6

    return findings, score
