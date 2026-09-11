"""
Evidencia anclada: dónde, dentro del mensaje, está lo que una regla encontró.

Un hallazgo sin ancla obliga al analista a reconstruir la decisión leyendo el
raw entero. Este módulo define el contrato de evidencia que acompaña a cada
``RuleResult`` que penaliza, los constructores que usan las reglas para
producirla y la desactivación (*defang*) de URLs, dominios y direcciones, que
permite mostrar un extracto en la UI o en un PDF sin dejar un enlace vivo.

Cada elemento de evidencia es un dict serializable tal cual a JSONB::

    {"kind": "header", "locator": {"header": "from", "occurrence": 0},
     "excerpt": "Soporte <alerta[@]evil[.]example>"}

``kind`` dice qué parte del mensaje señala y ``locator`` cómo encontrarla:

- ``header``: ``header`` (nombre en minúsculas) y ``occurrence`` (0 = la
  primera aparición, que para cabeceras de traza como ``Received`` es la más
  reciente).
- ``body``: ``part`` (``text`` o ``html``), ``start`` y ``end`` (offsets).
- ``mime_part``: ``partIndex``.
- ``attachment``: ``attachmentIndex`` (posición en
  ``MessageContext.attachments``), más ``filename``, ``contentType``, ``size``
  y ``sha256`` cuando se conocen.
- ``url``: ``linkIndex`` (posición en ``MessageContext.links``) o
  ``attachmentIndex`` si la URL salió de un adjunto (un QR), con ``source``.

``excerpt`` es siempre texto ya desactivado y recortado.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import replace
from typing import Any, Dict, Iterable, List, Sequence

logger = logging.getLogger(__name__)

EVIDENCE_HEADER = "header"
EVIDENCE_BODY = "body"
EVIDENCE_MIME_PART = "mime_part"
EVIDENCE_ATTACHMENT = "attachment"
EVIDENCE_URL = "url"

#: Claves de ``locator`` obligatorias por tipo. ``url`` va aparte porque le
#: basta una de dos (``_URL_LOCATOR_KEYS``).
_REQUIRED_LOCATOR_KEYS = {
    EVIDENCE_HEADER: ("header", "occurrence"),
    EVIDENCE_BODY: ("part", "start", "end"),
    EVIDENCE_MIME_PART: ("partIndex",),
    EVIDENCE_ATTACHMENT: ("attachmentIndex",),
}
_URL_LOCATOR_KEYS = ("linkIndex", "attachmentIndex")

#: Longitud máxima de un extracto: suficiente para leer una cabecera o una
#: URL, corto para que un informe no se convierta en una copia del raw.
MAX_EXCERPT_LENGTH = 240

#: Cuántas apariciones de una cabecera repetida (``Received``) se anclan.
MAX_REPEATED_HEADER_OCCURRENCES = 10

_URL_SCHEME_RE = re.compile(r"(?i)\bhttp(s?)(?=://)")
#: Un token con forma de dominio: etiquetas separadas por puntos cuya última
#: empieza por letra. Así una IP (``203.0.113.9``) queda legible — en la cadena
#: Received es evidencia forense, no un enlace.
_DOMAIN_TOKEN_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*\b")


def defang(text: str) -> str:
    """Desactiva URLs, dominios y direcciones de un texto y lo recorta.

    ``https://evil.example/x`` pasa a ``hxxps://evil[.]example/x`` y
    ``a@evil.example`` a ``a[@]evil[.]example``: el analista sigue leyendo el
    indicador, pero ni el visor de PDF ni el navegador lo convierten en un
    enlace que se pueda pulsar por error.

    Args:
        text: Texto original (valor de cabecera, URL, nombre de fichero…).

    Returns:
        str: El texto desactivado, de como mucho ``MAX_EXCERPT_LENGTH``
            caracteres (termina en ``…`` si se recortó).
    """
    defanged = _URL_SCHEME_RE.sub(lambda match: f"hxxp{match.group(1)}", text or "")
    defanged = _DOMAIN_TOKEN_RE.sub(lambda match: match.group(0).replace(".", "[.]"), defanged)
    defanged = defanged.replace("@", "[@]")
    if len(defanged) > MAX_EXCERPT_LENGTH:
        defanged = defanged[:MAX_EXCERPT_LENGTH - 1] + "…"
    return defanged


def validate_evidence(item: Any) -> None:
    """Comprueba que un elemento de evidencia cumple el contrato del módulo.

    Args:
        item: Elemento que una regla devolvió en ``RuleResult.evidence``.

    Raises:
        ValueError: Si no es un dict con ``kind`` conocido, ``locator`` con
            las claves que ese tipo exige y ``excerpt`` de texto.
    """
    if not isinstance(item, dict):
        raise ValueError(f"La evidencia debe ser un dict, no {type(item).__name__}.")
    kind = item.get("kind")
    locator = item.get("locator")
    if not isinstance(locator, dict):
        raise ValueError(f"La evidencia de tipo {kind!r} no trae un locator.")
    if not isinstance(item.get("excerpt"), str):
        raise ValueError(f"La evidencia de tipo {kind!r} no trae un extracto de texto.")
    if kind == EVIDENCE_URL:
        if not any(key in locator for key in _URL_LOCATOR_KEYS):
            raise ValueError("La evidencia de tipo 'url' necesita linkIndex o attachmentIndex.")
        return
    required = _REQUIRED_LOCATOR_KEYS.get(kind)
    if required is None:
        raise ValueError(f"Tipo de evidencia desconocido: {kind!r}.")
    missing = [key for key in required if key not in locator]
    if missing:
        raise ValueError(f"A la evidencia de tipo {kind!r} le faltan claves en el locator: {missing}.")


def _header_item(header_name: str, occurrence: int, value: str) -> Dict[str, Any]:
    """Construye la evidencia de una aparición concreta de una cabecera.

    Args:
        header_name: Nombre de la cabecera en minúsculas.
        occurrence: Aparición (0 = la primera del mensaje).
        value: Valor de la cabecera, sin desactivar.

    Returns:
        dict: Elemento de evidencia de tipo ``header``.
    """
    return {
        "kind": EVIDENCE_HEADER,
        "locator": {"header": header_name, "occurrence": occurrence},
        "excerpt": defang(value),
    }


def header_evidence(rule_input: Any, header_names: Sequence[str]) -> List[Dict[str, Any]]:
    """Evidencia de las cabeceras indicadas que existen en el mensaje.

    Las que faltan se omiten: señalar una cabecera ausente no ancla nada.
    ``received`` se ancla aparición por aparición (hasta
    ``MAX_REPEATED_HEADER_OCCURRENCES``) cuando la entrada es un
    ``MessageContext``, porque las reglas de la cadena Received hablan de la
    cadena entera; con un dict de cabeceras solo existe la primera.

    Args:
        rule_input: Lo que recibió la regla: un ``MessageContext`` o el dict
            de cabeceras (claves en minúsculas).
        header_names: Cabeceras a anclar, en minúsculas y en el orden en que
            se quieren mostrar.

    Returns:
        List[dict]: Un elemento ``header`` por aparición encontrada; lista
            vacía si no existe ninguna.
    """
    headers = getattr(rule_input, "headers", rule_input) or {}
    received_lines = getattr(rule_input, "received_headers", None)
    items: List[Dict[str, Any]] = []
    for header_name in header_names:
        if header_name == "received" and received_lines:
            for occurrence, line in enumerate(received_lines[:MAX_REPEATED_HEADER_OCCURRENCES]):
                items.append(_header_item(header_name, occurrence, line))
            continue
        value = headers.get(header_name)
        if value:
            items.append(_header_item(header_name, 0, value))
    return items


def received_hop_evidence(received_lines: Sequence[str], hop_index: int) -> Dict[str, Any]:
    """Evidencia de un salto concreto de la cadena Received.

    Args:
        received_lines: ``MessageContext.received_headers`` (el primero es el
            salto más reciente).
        hop_index: Posición del salto en esa lista.

    Returns:
        dict: Elemento ``header`` de ``received`` con esa aparición.
    """
    return _header_item("received", hop_index, received_lines[hop_index])


def link_evidence(link_index: int, link: Any) -> Dict[str, Any]:
    """Evidencia de un enlace del cuerpo.

    Args:
        link_index: Posición del enlace en ``MessageContext.links``.
        link: El ``Link`` (``href`` y texto visible).

    Returns:
        dict: Elemento ``url`` con el destino desactivado y, si difiere, el
            texto visible entre comillas latinas.
    """
    href = link.href or ""
    excerpt = href
    if link.text and link.text != href:
        excerpt = f"{href} («{link.text}»)"
    return {"kind": EVIDENCE_URL, "locator": {"linkIndex": link_index}, "excerpt": defang(excerpt)}


def qr_url_evidence(attachment_index: int, url: str) -> Dict[str, Any]:
    """Evidencia de una URL decodificada de un código QR de un adjunto.

    Args:
        attachment_index: Posición de la imagen en ``MessageContext.attachments``.
        url: URL decodificada del QR.

    Returns:
        dict: Elemento ``url`` con ``source="qr_code"``.
    """
    return {
        "kind": EVIDENCE_URL,
        "locator": {"attachmentIndex": attachment_index, "source": "qr_code"},
        "excerpt": defang(url),
    }


def attachment_evidence(attachment_index: int, attachment: Any) -> Dict[str, Any]:
    """Evidencia de un adjunto: cuál es, qué tipo declara y su huella.

    Args:
        attachment_index: Posición en ``MessageContext.attachments``.
        attachment: El ``Attachment`` parseado.

    Returns:
        dict: Elemento ``attachment`` con ``filename``, ``contentType``,
            ``size`` y ``sha256`` (``None`` si el adjunto no trae contenido).
    """
    content = attachment.content or b""
    filename = attachment.filename or "sin nombre"
    return {
        "kind": EVIDENCE_ATTACHMENT,
        "locator": {
            "attachmentIndex": attachment_index,
            "filename": attachment.filename,
            "contentType": attachment.content_type,
            "size": attachment.size,
            "sha256": hashlib.sha256(content).hexdigest() if content else None,
        },
        "excerpt": defang(f"{filename} ({attachment.content_type}, {attachment.size} bytes)"),
    }


def unique_evidence(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Quita elementos repetidos conservando el orden.

    Una regla puede anclar la misma cabecera por dos motivos (p. ej. el
    remitente con un carácter de control y con alfabetos mezclados); el
    analista solo necesita verla una vez.

    Args:
        items: Elementos de evidencia.

    Returns:
        List[dict]: Los mismos elementos sin duplicados de ``kind`` y
            ``locator``.
    """
    seen = set()
    unique: List[Dict[str, Any]] = []
    for item in items:
        key = (item["kind"], tuple(sorted(item["locator"].items())))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def anchor_result(result: Any, rule_input: Any, evidence_headers: Sequence[str],
                  unanchorable_reason: str, rule_name: str) -> Any:
    """Asegura que un resultado que penaliza lleva evidencia o dice por qué no.

    Es lo que el registro de reglas ejecuta tras cada regla. Solo actúa sobre
    resultados que restan puntos (``score < 0``): lo que no penaliza no es un
    hallazgo que justificar. En orden:

    1. Si la regla ya trajo evidencia, se valida y se deja tal cual.
    2. Si declaró cabeceras, se anclan las que existan; si no existe
       ninguna, el motivo dice que la señal es precisamente su ausencia.
    3. Si declaró un motivo de no anclaje, se usa ese motivo.
    4. Si no hay nada de lo anterior (una regla que se ancla sola pero no lo
       hizo en este camino), se deja constancia en el log y en el resultado,
       sin tumbar la regla: la detección vale más que su presentación.

    Args:
        result: ``RuleResult`` devuelto por la regla.
        rule_input: Lo que recibió la regla (``MessageContext`` o cabeceras).
        evidence_headers: Cabeceras declaradas por la regla; puede estar vacío.
        unanchorable_reason: Motivo declarado de no anclaje; puede estar vacío.
        rule_name: Nombre de la regla, para el log.

    Returns:
        RuleResult: El mismo resultado si no penaliza o ya traía evidencia; si
            no, una copia con ``evidence`` o con ``evidence_unavailable_reason``.

    Raises:
        ValueError: Si la evidencia que trajo la regla no cumple el contrato
            (ver ``validate_evidence``). Es un error de programación de la
            regla y el motor lo trata como una regla que falló.
    """
    for item in result.evidence:
        validate_evidence(item)

    if float(result.score) >= 0 or result.evidence or result.evidence_unavailable_reason:
        return result

    if evidence_headers:
        items = header_evidence(rule_input, evidence_headers)
        if items:
            return replace(result, evidence=items)
        return replace(result, evidence_unavailable_reason=(
            f"Ninguna de las cabeceras que examina la regla ({', '.join(evidence_headers)}) "
            "está presente: la señal es precisamente su ausencia, así que no hay "
            "ningún fragmento del mensaje que señalar."
        ))

    if unanchorable_reason:
        return replace(result, evidence_unavailable_reason=unanchorable_reason)

    logger.warning("La regla '%s' penalizó sin aportar evidencia", rule_name)
    return replace(result, evidence_unavailable_reason="La regla no aportó evidencia para este hallazgo.")
