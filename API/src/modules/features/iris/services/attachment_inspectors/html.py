"""
Inspector estático de adjuntos HTML (y SVG, que también ejecuta scripts).

Un HTML adjunto se abre en el navegador, fuera de los filtros del correo, y
de ahí dos técnicas conocidas:

- **HTML smuggling**: el HTML trae un fichero (un ZIP, un ISO, un ejecutable)
  codificado dentro, lo reconstruye con JavaScript (``Blob``,
  ``URL.createObjectURL``) y fuerza su descarga. El fichero dañino nunca viajó
  como adjunto, así que ningún filtro de adjuntos lo vio.
- **Página de phishing local**: un formulario con campo de contraseña que se
  abre desde el disco y envía lo que se escribe a un servidor del atacante.

Además se señala el JavaScript ofuscado: varias funciones de decodificación
(``atob``, ``unescape``, ``String.fromCharCode``…) o una de ellas junto a un
bloque base64 grande.

Nada se renderiza ni se ejecuta: son búsquedas de texto. Todas las
expresiones son lineales (sin retroceso anidado), así que su coste está
acotado por el tamaño del adjunto.
"""

from __future__ import annotations

import re

from .common import InspectionResult, make_finding

_FORM_ACTION_RE = re.compile(r"<form\b[^>]*?\baction\s*=\s*[\"']?\s*(https?://[^\"'\s>]+)", re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]*?\btype\s*=\s*[\"']?password", re.IGNORECASE)
_BLOB_RE = re.compile(r"new\s+Blob\s*\(|URL\.createObjectURL|msSaveOrOpenBlob|navigator\.msSaveBlob", re.IGNORECASE)
_DOWNLOAD_RE = re.compile(r"\bdownload\s*=|\.download\s*=|\.click\s*\(\s*\)", re.IGNORECASE)
_DATA_URI_PAYLOAD_RE = re.compile(
    r"data:application/(?:octet-stream|zip|x-zip-compressed|x-msdownload|x-iso9660-image|x-rar|vnd\.ms-)",
    re.IGNORECASE,
)
_DECODER_RE = re.compile(r"\b(atob|unescape|eval|String\.fromCharCode|decodeURIComponent)\s*\(", re.IGNORECASE)
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{4000,}")


def inspect_html(content: bytes) -> InspectionResult:
    """Busca smuggling, formularios de credenciales y scripts ofuscados.

    Args:
        content: Bytes del HTML o SVG.

    Returns:
        InspectionResult: Hallazgos ``html_smuggling``,
            ``html_credential_form``, ``html_external_form`` (solo si no hay ya
            uno de credenciales) y ``html_obfuscated_script``, y los destinos
            de los formularios como URLs.
    """
    text = content.decode("utf-8", errors="replace")
    result = InspectionResult()
    has_base64_blob = bool(_BASE64_RUN_RE.search(text))

    if (_BLOB_RE.search(text) and (_DOWNLOAD_RE.search(text) or has_base64_blob)) or _DATA_URI_PAYLOAD_RE.search(text):
        result.findings.append(make_finding(
            "html_smuggling",
            "El HTML reconstruye un fichero dentro del navegador y fuerza su descarga (HTML smuggling).",
        ))

    actions = [match.group(1) for match in _FORM_ACTION_RE.finditer(text)]
    result.add_urls(actions)
    if _PASSWORD_INPUT_RE.search(text):
        destination = f" y lo envía a {actions[0]}" if actions else ""
        result.findings.append(make_finding(
            "html_credential_form", f"El HTML pide una contraseña{destination}.",
        ))
    elif actions:
        result.findings.append(make_finding(
            "html_external_form", f"El HTML tiene un formulario que envía los datos a {actions[0]}.",
        ))

    decoders = {match.group(1).lower() for match in _DECODER_RE.finditer(text)}
    if len(decoders) >= 2 or (decoders and has_base64_blob):
        result.findings.append(make_finding(
            "html_obfuscated_script",
            f"El HTML decodifica código en tiempo de ejecución ({', '.join(sorted(decoders))}).",
        ))
    return result
