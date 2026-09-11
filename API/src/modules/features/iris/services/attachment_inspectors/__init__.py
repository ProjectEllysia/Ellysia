"""
Inspección estática de adjuntos por tipo: PDF, documentos Office (OOXML),
HTML y ZIP.

La regla de adjuntos mira el nombre, el tipo y el tamaño; estos inspectores
abren el contenido y buscan lo que lo hace peligroso —JavaScript en un PDF,
macros o plantillas remotas en un documento, HTML smuggling, bombas ZIP—.

Dos garantías, que ``test_iris_attachment_inspectors.py`` fija:

- **Nada se ejecuta ni se renderiza.** Todo son lecturas de bytes y búsquedas
  de texto; ningún inspector importa nada capaz de ejecutar código.
- **Todo está acotado.** Un adjunto más grande que ``max_inspected_bytes``
  no se abre; lo que se descomprime o se extrae de él (entradas de un ZIP,
  flujos de un PDF, ZIP anidados) comparte un único presupuesto de
  ``max_expanded_bytes``; el anidamiento, las entradas de un ZIP y los flujos
  de un PDF tienen su propio tope. Como las búsquedas son lineales, el tiempo
  de CPU queda acotado por esos mismos bytes.

Paquete puro: sin configuración, base de datos ni red; la regla le pasa los
límites (``CR.iris_attachment_inspection()``).
"""

from __future__ import annotations

import io
import zipfile
from typing import FrozenSet

from .archive import inspect_archive
from .common import HTML_KIND, PDF_KIND, ZIP_KIND, InspectionBudget, InspectionResult, kind_of
from .html import inspect_html
from .ooxml import inspect_ooxml
from .pdf import inspect_pdf

__all__ = ["InspectionResult", "inspect_attachment"]

_OOXML_MARKER = "[Content_Types].xml"


def _inspect(filename: str, content_type: str, content: bytes, depth: int, limits,
             budget: InspectionBudget, dangerous_extensions: FrozenSet[str]) -> InspectionResult:
    """Despacha un fichero (el adjunto o una entrada de un ZIP) a su inspector.

    Args:
        filename: Nombre del fichero.
        content_type: Tipo MIME declarado (``""`` dentro de un ZIP).
        content: Sus bytes.
        depth: Nivel de anidamiento (0 es el adjunto).
        limits: Topes (``CR.IrisAttachmentInspection``).
        budget: Presupuesto de bytes compartido por todo el adjunto.
        dangerous_extensions: Extensiones que cuentan como ejecutable.

    Returns:
        InspectionResult: Lo que encontró su inspector; vacío si no hay
            inspector para su tipo o si no se puede abrir.
    """
    kind = kind_of(filename, content_type, content[:1024])
    if kind == PDF_KIND:
        return inspect_pdf(content, limits, budget)
    if kind == HTML_KIND:
        return inspect_html(content)
    if kind != ZIP_KIND:
        return InspectionResult()
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except (zipfile.BadZipFile, OSError, ValueError):
        return InspectionResult()
    with archive:
        if _OOXML_MARKER in archive.namelist():
            return inspect_ooxml(archive, limits, budget)
        return inspect_archive(
            archive, limits, budget, depth, dangerous_extensions,
            lambda name, data, nested_depth: _inspect(name, "", data, nested_depth, limits,
                                                      budget, dangerous_extensions),
        )


def inspect_attachment(filename: str, content_type: str, content: bytes, limits,
                       dangerous_extensions: FrozenSet[str]) -> InspectionResult:
    """Inspecciona el contenido de un adjunto con el inspector de su tipo.

    Args:
        filename: Nombre del adjunto (puede ser ``""``).
        content_type: Tipo MIME declarado (puede ser ``""``).
        content: Bytes del adjunto.
        limits: Topes (``CR.IrisAttachmentInspection``).
        dangerous_extensions: Extensiones que cuentan como ejecutable dentro
            de un ZIP.

    Returns:
        InspectionResult: Hallazgos y URLs del adjunto; vacío si no hay
            contenido, si pasa de ``max_inspected_bytes`` o si ningún inspector
            sabe leer su tipo.
    """
    if not content or len(content) > limits.max_inspected_bytes:
        return InspectionResult()
    budget = InspectionBudget(limits.max_expanded_bytes)
    return _inspect(filename, content_type, content, 0, limits, budget, dangerous_extensions)
