"""Traductor de plantillas de Nuclei a checks del runtime propio.

Convierte una plantilla upstream en un :class:`~..checks.Check` **solo si el
runtime la entiende entera**. La decisión de si la entiende no se toma aquí:
la toma :func:`~.classifier.is_ingestible`, el mismo criterio que usa el censo
de cobertura del feed para medir. Esa es la razón de que el clasificador sea
un módulo aparte y no lógica embebida en cualquiera de los dos.

**Traducir a medias no es una opción.** Una plantilla que use extractors o
payloads podría "casi" traducirse ignorando esas partes, y el resultado sería un
check que corre, no falla, y comprueba algo distinto de lo que la plantilla
dice — la peor clase de error posible en un motor de detección, porque produce
hallazgos con la confianza de un check confirmado. Ante la duda se descarta.

**Procedencia, no autoría.** Un check traducido no es nuestro y no lo aparenta:
nace con ``namespace="nuclei"`` (así su ``check_id`` es
``nuclei:git-config@...``, no ``lybra:...``) y con el ``feed_version`` del árbol
de plantillas, no con el del feed propio. Y entra siempre en ``mode="safe"``,
sin importar lo que la plantilla diga de sí misma: no hemos revisado esas
plantillas una a una, así que no se les concede el modo agresivo.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from ..checks import Check, Matcher, Request
from .classifier import Bucket, classify_template

logger = logging.getLogger(__name__)

# Severidad de Nuclei → la etiqueta que usa el feed propio. Nuclei escribe en
# minúsculas; el resto del motor espera mayúsculas.
_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}

# Un hallazgo de una plantilla traducida es una aserción de un matcher
# estructurado contra una respuesta real, igual que uno del feed propio: mismo
# QoD. Lo que cambia no es la calidad de la detección, es quién escribió la
# regla — y eso se registra en la procedencia, no rebajando el QoD.
_QOD_TRANSLATED = 99

_HTTP_KEYS = ("http", "requests")
_NETWORK_KEYS = ("network", "tcp")

# Las tres claves bajo las que Nuclei declara los valores de un matcher, según
# su tipo. ``_parse_check`` del feed propio acepta exactamente las mismas.
_VALUE_KEYS = ("words", "regex", "status", "value")


def _matcher_values(matcher: dict) -> tuple:
    """Extrae los valores de un matcher, mire bajo la clave que mire."""
    for key in _VALUE_KEYS:
        values = matcher.get(key)
        if values:
            return tuple(values)
    return ()


def _translate_matcher(matcher: dict) -> Matcher:
    """Traduce un matcher de Nuclei al del runtime.

    ``part`` se normaliza a lo que el runtime entiende: Nuclei usa ``all`` y
    ``response`` para "todo el cuerpo", que es su valor por defecto aquí.
    """
    part = str(matcher.get("part") or "body").lower()
    if part in ("all", "response", ""):
        part = "body"
    return Matcher(
        type=str(matcher.get("type") or ""),
        part=part,
        values=_matcher_values(matcher),
        negative=bool(matcher.get("negative", False)),
    )


def _translate_request(request: dict, is_http: bool) -> List[Request]:
    """Traduce una petición de Nuclei a una o varias del runtime.

    Una petición HTTP de Nuclei puede declarar **varias rutas** bajo ``path``,
    que el binario recorre una a una. El runtime propio no tiene ese concepto:
    su ``Request`` es una ruta. Se expande a una petición por ruta.

    Ojo con la consecuencia semántica, que es real y está aceptada a
    conciencia: el runtime combina sus peticiones con AND, mientras que Nuclei
    dispara si *alguna* de las rutas casa. Por eso una plantilla multi-ruta
    solo se traduce cuando tiene una única ruta — el llamador
    (:func:`translate_template`) la descarta en caso contrario en vez de
    producir un check más estricto que el original y que casi nunca dispararía.
    """
    matchers = tuple(_translate_matcher(matcher) for matcher in request.get("matchers") or [])
    condition = str(request.get("matchers-condition") or "and").lower()

    if not is_http:
        return [Request(matchers=matchers, condition=condition, send=request.get("data"))]

    paths = request.get("path") or ["/"]
    if isinstance(paths, str):
        paths = [paths]
    method = str(request.get("method") or "GET").upper()
    return [
        Request(
            method=method,
            path=_strip_base_url(str(path)),
            matchers=matchers,
            condition=condition,
        )
        for path in paths
    ]


def _strip_base_url(path: str) -> str:
    """Convierte la ruta de Nuclei en la del runtime.

    Nuclei escribe rutas absolutas interpoladas (``{{BaseURL}}/.git/config``);
    el runtime recibe la ruta y construye la URL él mismo a partir del host y el
    puerto del servicio. Quitar el prefijo es toda la traducción que hace falta.
    """
    for prefix in ("{{BaseURL}}", "{{RootURL}}", "{{Hostname}}"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return path or "/"


def translate_template(document: dict, feed_version: str) -> Optional[Check]:
    """Traduce una plantilla de Nuclei a un :class:`~..checks.Check`.

    Args:
        document: La plantilla ya parseada.
        feed_version: La versión del árbol de plantillas, sellada en el check
            para que el hallazgo sea reproducible.

    Returns:
        El check traducido, o ``None`` si la plantilla usa algo que el runtime
        no soporta entero — incluida una plantilla HTTP con varias rutas, que no
        se puede expresar sin cambiarle el significado (ver
        :func:`_translate_request`).
    """
    profile = classify_template(document)
    if profile.bucket is not Bucket.INGESTIBLE_NOW:
        return None

    template_id = str(document.get("id") or "").strip()
    if not template_id:
        return None

    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    is_http = any(key in document for key in _HTTP_KEYS)
    protocol_key = next(
        (key for key in _HTTP_KEYS + _NETWORK_KEYS if key in document), None
    )
    raw_requests = document.get(protocol_key) or []

    requests: List[Request] = []
    for raw_request in raw_requests:
        if not isinstance(raw_request, dict):
            return None
        translated = _translate_request(raw_request, is_http)
        if len(translated) != 1:
            # Multi-ruta: el runtime la volvería un AND, Nuclei la trata como
            # OR. Se descarta en vez de traducirla con otro significado.
            logger.debug("Plantilla %s descartada: varias rutas por petición", template_id)
            return None
        requests.extend(translated)

    if not requests or any(not request.matchers for request in requests):
        return None

    return Check(
        id=template_id,
        version=1,
        type="http" if is_http else "network",
        category="web_finding" if is_http else "network_config",
        severity=_SEVERITY_LABELS.get(profile.severity, "INFO"),
        service="http" if is_http else str(document.get("service") or ""),
        # Toda plantilla externa entra en modo seguro, sin excepción: no las
        # hemos revisado una a una y no se les concede el modo agresivo.
        mode="safe",
        requests=tuple(requests),
        finding={
            "title": str(info.get("name") or template_id),
            "cve_ids": _cve_ids(info),
            "qod": _QOD_TRANSLATED,
            "confirmed": True,
        },
        namespace="nuclei",
        feed_version=feed_version,
        tags=_relevance_tags(info),
    )


def _relevance_tags(info: dict) -> tuple:
    """Reúne las etiquetas por las que un selector puede filtrar este check.

    Junta ``info.tags`` con el vendor y el producto de ``info.metadata``, todo
    en minúsculas. No lo usa el runtime —que ejecuta lo que le den— sino la
    selección previa: es lo que permite no lanzar una plantilla de WordPress
    contra un nginx.
    """
    values = []
    raw_tags = info.get("tags")
    if isinstance(raw_tags, str):
        values.extend(part.strip() for part in raw_tags.split(","))
    elif isinstance(raw_tags, (list, tuple)):
        values.extend(str(tag).strip() for tag in raw_tags)

    metadata = info.get("metadata")
    if isinstance(metadata, dict):
        for key in ("vendor", "product", "framework"):
            value = metadata.get(key)
            if value:
                values.append(str(value).strip())

    return tuple(sorted({raw_value.lower() for raw_value in values if raw_value}))


def _cve_ids(info: dict) -> Optional[List[str]]:
    """Extrae las CVE de una plantilla, en mayúsculas.

    Normalizar el caso no es cosmético: es lo que permite que un hallazgo
    traducido se funda por ``dedup_key`` con el del mismo CVE venido de la KB o
    del binario de Nuclei. Es la misma normalización que
    ``nuclei_result_to_finding`` ya hace para la salida del binario.
    """
    classification = info.get("classification")
    if not isinstance(classification, dict):
        return None
    raw = classification.get("cve-id")
    if not raw:
        return None
    values = [raw] if isinstance(raw, str) else list(raw)
    normalized = [str(raw_value).strip().upper() for raw_value in values if str(raw_value).strip()]
    return normalized or None


def translate_all(documents: Iterable[dict], feed_version: str) -> List[Check]:
    """Traduce las plantillas que se puedan, saltando el resto en silencio.

    Args:
        documents: Las plantillas ya parseadas.
        feed_version: La versión del árbol, sellada en cada check.

    Returns:
        Los checks traducidos. Las plantillas no ingeribles simplemente no
        aparecen: es el caso normal, no un error.
    """
    checks = []
    for document in documents:
        try:
            check = translate_template(document, feed_version)
        except Exception:  # noqa: BLE001 - una plantilla rota no arruina la ingesta
            logger.debug("Fallo traduciendo la plantilla %s", document.get("id"), exc_info=True)
            continue
        if check is not None:
            checks.append(check)
    return checks
