"""
Inspector estático de documentos Office modernos (OOXML: ``.docx``,
``.xlsx``, ``.pptx`` y sus variantes).

Un documento OOXML es un ZIP de ficheros XML. Lo que lo vuelve peligroso no
está en el texto, sino en su estructura:

- **Macros**: el proyecto VBA vive en ``vbaProject.bin``, y las macros de
  Excel 4.0 en ``xl/macrosheets/``. Un ``.docx`` con ``vbaProject.bin`` es
  además un disfraz: la extensión dice «sin macros».
- **Plantilla remota**: una relación ``attachedTemplate`` con
  ``TargetMode="External"`` hace que Word descargue una plantilla (con macros)
  de un servidor al abrir el documento, sin que el fichero adjunto lleve nada
  ejecutable.
- **Relaciones externas**: objetos OLE, marcos o libros enlazados que se
  cargan de fuera. Los hipervínculos, que también son relaciones externas, no
  cuentan: son enlaces normales (sus destinos se recogen como URLs).
- **DDE**: campos ``DDE``/``DDEAUTO`` de Word o enlaces DDE de Excel, que
  lanzan un comando al actualizar el documento.

Solo se leen los ``.rels`` y el XML de Word y de los enlaces externos de
Excel, cada uno con el presupuesto de bytes del adjunto.
"""

from __future__ import annotations

import re
import zipfile

from .common import InspectionBudget, InspectionResult, make_finding

_RELATIONSHIP_RE = re.compile(rb"<Relationship\b[^>]*>", re.IGNORECASE)
_ATTRIBUTE_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')
_WORD_DDE_RE = re.compile(rb"(?:instrText[^>]*>|instr=\")\s*DDE(?:AUTO)?\b", re.IGNORECASE)
_EXCEL_DDE_RE = re.compile(rb"<(?:\w+:)?ddeLink\b", re.IGNORECASE)


def _reads_for_dde(name: str) -> bool:
    """Si una entrada puede llevar campos o enlaces DDE."""
    lowered = name.lower()
    return lowered.endswith(".xml") and (lowered.startswith("word/") or lowered.startswith("xl/externallinks/"))


def inspect_ooxml(archive: zipfile.ZipFile, limits, budget: InspectionBudget) -> InspectionResult:
    """Busca macros, plantillas remotas, relaciones externas y DDE en un OOXML.

    Args:
        archive: El documento, abierto como ZIP.
        limits: Topes (``IrisAttachmentInspection``); se usa
            ``max_archive_entries``.
        budget: Presupuesto de bytes extraídos del adjunto.

    Returns:
        InspectionResult: Hallazgos ``ooxml_macro``, ``ooxml_remote_template``,
            ``ooxml_external_relationship`` y ``ooxml_dde`` (cada uno una vez,
            con la primera ruta en la que aparece) y los destinos externos
            como URLs.
    """
    result = InspectionResult()
    seen = set()

    def add(reason: str, detail: str, path: str) -> None:
        if reason not in seen:
            seen.add(reason)
            result.findings.append(make_finding(reason, detail, path))

    for info in archive.infolist()[:limits.max_archive_entries]:
        name = info.filename
        lowered = name.lower()
        if lowered.endswith("vbaproject.bin") or lowered.startswith("xl/macrosheets/"):
            add("ooxml_macro", "El documento lleva macros (VBA o Excel 4.0).", name)
            continue
        is_rels = lowered.endswith(".rels")
        if not (is_rels or _reads_for_dde(name)) or info.flag_bits & 0x1 or budget.remaining <= 0:
            continue
        with archive.open(info) as handle:
            data = budget.read(handle)
        if is_rels:
            for tag in _RELATIONSHIP_RE.findall(data):
                attributes = {key.decode("ascii").lower(): value.decode("utf-8", "replace")
                              for key, value in _ATTRIBUTE_RE.findall(tag)}
                if attributes.get("targetmode", "").lower() != "external":
                    continue
                target = attributes.get("target", "")
                if target.lower().startswith(("http://", "https://", "\\\\", "file:")):
                    result.add_urls([target])
                relationship_type = attributes.get("type", "").rsplit("/", 1)[-1].lower()
                if relationship_type == "attachedtemplate":
                    add("ooxml_remote_template",
                        f"El documento descarga su plantilla de fuera al abrirse: {target}", name)
                elif relationship_type != "hyperlink":
                    add("ooxml_external_relationship",
                        f"El documento carga un recurso externo ({relationship_type}): {target}", name)
        elif _WORD_DDE_RE.search(data) or _EXCEL_DDE_RE.search(data):
            add("ooxml_dde", "El documento tiene un campo o enlace DDE, que puede lanzar un comando.", name)
    return result
