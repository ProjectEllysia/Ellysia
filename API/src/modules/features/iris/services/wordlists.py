"""
Datasets de detección (marcas, dominios, keywords, extensiones…) compartidos
entre las reglas de Iris (D6 en plans/deuda-tecnica-y-calidad.md — antes
mezclado con text.py en un único shared.py de 957 líneas).

Los datasets se leen de ``SecOpsConfig.json`` (bloque ``features.iris.data.*``)
a través de ``config_reading.get_iris_data``. Cada dataset tiene un default
embebido en ``_DEFAULTS`` para que la aplicación arranque aunque la clave
falte en el JSON; el valor del JSON, cuando existe, tiene prioridad. Los
regex se quedan compilados en código (son lógica, no configuración).

Una regla nunca importa de otra regla — si dos reglas necesitan el mismo
dataset, vive aquí; si necesitan una utilidad de texto/dominio, vive en
``text.py``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import src.modules.system.config_reading as CR


# =============================================================================
# DEFAULTS DE DATASETS (fallback si SecOpsConfig.json no define features.iris.data.<key>)
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
        "do this while i'm out", "while i'm in a meeting",
        "w-2 form", "w2 form", "employee tax forms", "1099 form",
        "transferencia urgente", "transferencia bancaria urgente",
        "realizar el pago", "procesar el pago", "pago pendiente",
        "factura pendiente", "factura vencida", "saldo pendiente",
        "comprar tarjetas de regalo", "tarjetas de regalo",
        # Calibración FP: el sustantivo suelto "criptomonedas" era la única
        # entrada no-accionable de la lista y matcheaba el pie regulatorio de
        # cualquier fintech ("los productos de criptomonedas son
        # proporcionados por..."). El patrón BEC es la PETICIÓN de transferir,
        # que ya cubren "enviar bitcoin"/"transferencia cripto"/"send crypto".
        "enviar bitcoin", "transferencia cripto",
        "cambiar la cuenta bancaria", "nueva cuenta bancaria",
        "número de ruta", "datos bancarios nuevos",
        "no notifiques", "no informar a",
        "mientras estoy en reunión",
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
        # CDNs mainstream usadas por correo legítimo para servir imágenes
        # (logos, banners) — "imagen externa" no ESP-específica no es señal
        # de phishing por sí sola (F5).
        "akamaized.net", "akamaihd.net", "fastly.net", "cloudinary.com",
        "imgix.net",
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
        # Exchange Online / Microsoft 365 acuña el Message-ID con el nombre
        # del propio buzón (AS8P193MB1861.EURP193.PROD.OUTLOOK.COM), no con
        # el dominio del tenant -- exactamente el mismo patrón legítimo que
        # un ESP, y el caso de todo correo enviado desde M365.
        "outlook.com", "protection.outlook.com",
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

    # Servicios de hosting multi-tenant abusables: el registrable_label es
    # de la marca (google.com, sharepoint.com...) pero el path/subdominio
    # es de un usuario cualquiera, así que una página de cosecha de
    # credenciales alojada ahí hoy se salta el chequeo pensado solo para
    # "es la propia web de la marca" (N3).
    "multitenant_hosting_domains": [
        "docs.google.com", "forms.gle", "forms.office.com", "drive.google.com",
        "sites.google.com", "sharepoint.com", "onedrive.live.com",
        "notion.site", "web.app", "pages.dev", "vercel.app", "netlify.app",
        "t.me", "cdn.discordapp.com", "firebasestorage.googleapis.com",
        "typeform.com", "airtable.com",
    ],

    # Lenguaje de pago/facturación/suscripción/soporte combinable con un
    # número de teléfono para el patrón TOAD (Telephone-Oriented Attack
    # Delivery, G-D): "su suscripción se renovó, llame para cancelar" -- sin
    # enlaces ni adjuntos, invisible al resto de reglas.
    "toad_phrases": [
        "subscription", "auto-renewal", "auto renewal", "renewal", "renewed",
        "billing issue", "billing department", "unauthorized charge",
        "unrecognized charge", "customer support", "customer service",
        "call us", "call the number below", "call to cancel",
        "suscripcion", "suscripción", "renovacion automatica",
        "renovación automática", "se ha renovado", "cargo no autorizado",
        "cargo no reconocido", "atencion al cliente", "atención al cliente",
        "llamenos", "llámenos", "llame al", "para cancelar",
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
    """Dataset ``features.iris.data.<key>``: valor del JSON si existe, si no el default."""
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

def toad_phrases() -> tuple[str, ...]:
    return _cached_tuple("toad_phrases")

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

def multitenant_hosting_domains() -> frozenset[str]:
    return _cached_set("multitenant_hosting_domains")

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
# MATCHING DE FRASES CON LÍMITES DE PALABRA (B1)
# =============================================================================
#
# Los datasets de frases (bec_phrases, credential_phrases, high/low_signal_
# keywords, generic_greetings, action_verbs) se comparaban históricamente con
# `kw in texto`, lo que hace matchear "you won" dentro de "you won't" o
# "free" dentro de "freelance"/"free shipping". `phrase_matches` compila cada
# dataset una vez (cacheado) como alternancia regex con límites `\b` y
# devuelve las frases del dataset que de verdad aparecen como palabra(s)
# completa(s), en el mismo orden que el dataset (para no cambiar el
# comportamiento de "primeros N matches" que ya consumían las reglas).

@lru_cache(maxsize=None)
def _phrase_pattern(key: str) -> re.Pattern:
    phrases = sorted(_data(key), key=len, reverse=True)
    alternation = "|".join(re.escape(phras) for phras in phrases)
    return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)


def phrase_matches(key: str, text: str) -> list[str]:
    """Frases del dataset ``key`` presentes en *text* como palabra(s) completa(s).

    *text* debe venir ya en minúsculas (mismo contrato que los datasets).
    """
    if not text:
        return []
    hits = {match.lower() for match in _phrase_pattern(key).findall(text)}
    return [phrase for phrase in _data(key) if phrase.lower() in hits]
