"""
Indicadores de compromiso (IOCs) de un mensaje: extracción e índice de búsqueda.

Los IOCs —dominios, URLs, IPs, direcciones y hashes de adjuntos— se derivan
del mensaje parseado, no de los ``details`` de cada regla: el
``MessageContext`` da una vista uniforme de cabeceras, enlaces del cuerpo y
cadena ``Received`` sea cual sea la regla que disparó, así que la extracción
sigue siendo correcta cuando se añaden o cambian reglas.

Se usan en dos sitios: la vista bajo demanda de un análisis
(``IrisManager.get_analysis_iocs``) y el índice ``IrisIndicator``, que se
rellena al terminar cada análisis. El índice existe porque el raw se guarda
cifrado —no se puede buscar en él con SQL— y porque la retención lo purga: los
indicadores sobreviven a la purga, que es justo lo que un analista necesita
para responder «¿he visto antes este dominio?» meses después.

Módulo puro: sin base de datos ni red.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Tuple

from .parsers import parse_received_line
from .text import extract_domain, url_host

#: Longitud máxima de un indicador en el índice. Una URL puede ser enorme; para
#: encontrarla basta con su principio, y la columna tiene que poder indexarse.
MAX_INDICATOR_LENGTH = 2048

#: Categoría de la respuesta de IOCs → ``IrisIndicator.kind``.
INDICATOR_KIND_BY_CATEGORY = {
    "domains": "domain",
    "urls": "url",
    "ips": "ip",
    "emails": "email",
    "hashes": "hash",
}

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")
_DEFANGED_SCHEME_RE = re.compile(r"\bhxxp(s?)", re.IGNORECASE)


def extract_indicators(context: Any) -> Dict[str, List[str]]:
    """Extrae los IOCs pivotables de un mensaje parseado.

    Args:
        context: ``MessageContext`` del mensaje (el contexto ganador del
            análisis, que es el que describe el veredicto).

    Returns:
        dict: ``domains``, ``urls``, ``ips``, ``emails`` y ``hashes`` (SHA-256 de
            **cada** adjunto, no solo de los que alguna regla marcó: quien
            pivota a una búsqueda de threat intel quiere el hash igualmente).
            Cada una es una lista ordenada y sin duplicados; vacía, nunca
            ``None``, si la categoría no da nada.
    """
    domains: set[str] = set()
    emails: set[str] = set()
    urls: set[str] = set()
    ips: set[str] = set()
    hashes: set[str] = set()

    for header_name in ("from", "reply-to", "return-path"):
        raw_value = context.headers.get(header_name, "")
        domain = extract_domain(raw_value)
        if domain:
            domains.add(domain)
        email_match = _EMAIL_RE.search(raw_value)
        if email_match:
            emails.add(email_match.group(0).lower())

    for link in context.links:
        href = (link.href or "").strip()
        if not href:
            continue
        urls.add(href)
        host = url_host(href)
        if host:
            domains.add(host)

    for line in context.received_headers:
        hop = parse_received_line(line)
        if hop.get("fromIp"):
            ips.add(hop["fromIp"])

    for attachment in context.attachments:
        if attachment.content:
            hashes.add(hashlib.sha256(attachment.content).hexdigest())

    return {
        "domains": sorted(domains),
        "urls": sorted(urls),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "hashes": sorted(hashes),
    }


def indicator_rows(indicators: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """Convierte la salida de ``extract_indicators`` en filas del índice.

    Args:
        indicators: Salida de ``extract_indicators``.

    Returns:
        List[Tuple[str, str]]: Pares ``(kind, value)`` con ``kind`` en
            singular (``domain``, ``url``…) y el valor en minúsculas y
            recortado a ``MAX_INDICATOR_LENGTH``, sin duplicados.
    """
    rows = {
        (INDICATOR_KIND_BY_CATEGORY[category], value.lower()[:MAX_INDICATOR_LENGTH])
        for category, values in indicators.items() if category in INDICATOR_KIND_BY_CATEGORY
        for value in values if value
    }
    return sorted(rows)


def refang(text: str) -> str:
    """Deshace la desactivación habitual de un IOC pegado desde un informe.

    Los informes (el PDF de Iris incluido) escriben ``hxxp://evil[.]com`` o
    ``user[@]evil[.]com`` para que nadie haga clic por accidente; quien busca
    ese indicador lo pega tal cual.

    Args:
        text: Indicador tal como lo escribió el usuario.

    Returns:
        str: El indicador en minúsculas, sin espacios alrededor, con ``hxxp``
            → ``http``, ``[.]``/``(.)`` → ``.`` y ``[@]`` → ``@``.
    """
    cleaned = _DEFANGED_SCHEME_RE.sub(lambda match: "http" + match.group(1), (text or "").strip())
    return cleaned.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@").lower()
