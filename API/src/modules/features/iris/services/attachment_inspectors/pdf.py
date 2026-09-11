"""
Inspector estático de PDF.

Un PDF puede llevar comportamiento, no solo contenido: JavaScript que el lector
ejecuta, una acción ``/Launch`` que abre un programa, ficheros incrustados o
formularios que envían lo que el usuario escribe a una URL. Aquí no se
interpreta ni se renderiza el documento: se buscan los *nombres* de PDF que
activan ese comportamiento en el texto del fichero y en sus flujos Flate
descomprimidos (con tope), porque los PDF modernos meten los objetos
comprimidos dentro de *object streams* y ahí un ``/JavaScript`` no se ve a
simple vista.

También se deshacen los escapes ``#xx`` de los nombres (``/J#61vaScript`` es
``/JavaScript``), un truco clásico para esquivar búsquedas literales, y su mera
presencia es en sí un hallazgo: un PDF legítimo no tiene motivo para usarlos.

``/OpenAction`` y ``/AA`` (acciones automáticas) no son un hallazgo por sí
solas —muchos PDF legítimos las usan para fijar el zoom—, pero agravan el de
JavaScript o ``/Launch``: significan que se ejecutan al abrir el documento.
"""

from __future__ import annotations

import re

from .common import InspectionBudget, InspectionResult, make_finding

_HEX_ESCAPE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
_OBFUSCATED_NAME_RE = re.compile(rb"/[A-Za-z0-9]*#[0-9A-Fa-f]{2}")
# «endstream» también acaba en «stream»: sin el lookbehind, cada fin de flujo
# se tomaría por el principio de otro y se saltaría el flujo real siguiente.
_STREAM_RE = re.compile(rb"(?<!end)stream\r?\n(.*?)endstream", re.DOTALL)
_AUTO_ACTION_RE = re.compile(rb"/(?:OpenAction|AA)(?![A-Za-z])")
_URI_RE = re.compile(rb"/URI\s*\(([^)]{1,2048})\)")

_KEYWORD_FINDINGS = (
    (re.compile(rb"/(?:JavaScript|JS)(?![A-Za-z])"), "pdf_javascript",
     "El PDF contiene JavaScript, que el lector ejecuta."),
    (re.compile(rb"/Launch(?![A-Za-z])"), "pdf_launch_action",
     "El PDF tiene una acción /Launch, que abre un programa o un fichero del equipo."),
    (re.compile(rb"/EmbeddedFile(?![A-Za-z])"), "pdf_embedded_file",
     "El PDF lleva ficheros incrustados dentro."),
    (re.compile(rb"/SubmitForm(?![A-Za-z])"), "pdf_form_submit",
     "El PDF tiene un formulario que envía lo que se escribe en él a una URL."),
)
_AUTO_REASONS = frozenset({"pdf_javascript", "pdf_launch_action"})


def _decode_name_escapes(data: bytes) -> bytes:
    """Deshace los escapes ``#xx`` de los nombres de PDF."""
    return _HEX_ESCAPE_RE.sub(lambda match: bytes([int(match.group(1), 16)]), data)


def inspect_pdf(content: bytes, limits, budget: InspectionBudget) -> InspectionResult:
    """Busca comportamiento activo en un PDF sin interpretarlo.

    Args:
        content: Bytes del PDF.
        limits: Topes (``IrisAttachmentInspection``); se usa
            ``max_pdf_streams``.
        budget: Presupuesto de bytes descomprimidos del adjunto.

    Returns:
        InspectionResult: Un hallazgo por comportamiento encontrado
            (``pdf_javascript``, ``pdf_launch_action``, ``pdf_embedded_file``,
            ``pdf_form_submit``, ``pdf_obfuscated_names``) y las URLs de sus
            enlaces.
    """
    inflated = []
    for index, match in enumerate(_STREAM_RE.finditer(content)):
        if index >= limits.max_pdf_streams or budget.remaining <= 0:
            break
        inflated.append(budget.inflate(match.group(1).strip(b"\r\n")))
    searchable = content + b"\n" + b"\n".join(inflated)

    result = InspectionResult()
    has_escapes = bool(_OBFUSCATED_NAME_RE.search(searchable))
    text = _decode_name_escapes(searchable) if has_escapes else searchable
    is_automatic = bool(_AUTO_ACTION_RE.search(text))
    for pattern, reason, detail in _KEYWORD_FINDINGS:
        if pattern.search(text):
            if is_automatic and reason in _AUTO_REASONS:
                detail += " Además se dispara solo, al abrir el documento (/OpenAction o /AA)."
            result.findings.append(make_finding(reason, detail))
    if has_escapes:
        result.findings.append(make_finding(
            "pdf_obfuscated_names",
            "El PDF escribe sus nombres con escapes #xx, una forma de esconder palabras como /JavaScript.",
        ))
    result.add_urls(match.group(1).decode("latin-1").strip() for match in _URI_RE.finditer(text))
    return result
