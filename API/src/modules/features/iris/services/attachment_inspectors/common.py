"""
Piezas comunes de los inspectores de adjuntos: el resultado, el presupuesto de
bytes y la decisión de qué inspector le toca a cada fichero.

Módulo puro: sin configuración, base de datos ni red.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, Dict, List, Optional

PDF_KIND = "pdf"
ZIP_KIND = "zip"
HTML_KIND = "html"

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_EXTENSIONS = frozenset({".zip", ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx",
                             ".xltm", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"})
_ZIP_MIME_TYPES = frozenset({"application/zip", "application/x-zip-compressed"})
_HTML_EXTENSIONS = frozenset({".htm", ".html", ".shtml", ".xhtml", ".svg"})
_HTML_MIME_TYPES = frozenset({"text/html", "application/xhtml+xml", "image/svg+xml"})

#: Cuántas URLs se guardan como mucho por adjunto: son evidencia para el
#: analista, no un inventario completo.
MAX_URLS = 20


def extension_of(filename: str) -> str:
    """Extensión en minúsculas con su punto (``".pdf"``), o ``""`` si no tiene."""
    _, dot, extension = filename.rpartition(".")
    return f".{extension.lower()}" if dot and extension else ""


def kind_of(filename: str, content_type: str, head: bytes) -> Optional[str]:
    """Qué inspector le toca a un fichero.

    Manda el contenido (la firma de los primeros bytes) sobre el nombre y el
    tipo declarados, que los pone el remitente: un PDF renombrado a ``.txt``
    se sigue inspeccionando como PDF.

    Args:
        filename: Nombre del fichero (puede ser ``""``).
        content_type: Tipo MIME declarado (puede ser ``""``).
        head: Los primeros bytes del contenido (basta con 1024).

    Returns:
        Optional[str]: ``PDF_KIND``, ``ZIP_KIND`` (un ZIP u OOXML: se
            distinguen al abrirlo) o ``HTML_KIND``; ``None`` si ningún
            inspector sabe leerlo.
    """
    extension = extension_of(filename)
    content_type = (content_type or "").lower()
    if _PDF_MAGIC in head[:1024]:
        return PDF_KIND
    if head.startswith(_ZIP_MAGIC):
        return ZIP_KIND
    if extension == ".pdf" or content_type == "application/pdf":
        return PDF_KIND
    if extension in _ZIP_EXTENSIONS or content_type in _ZIP_MIME_TYPES:
        return ZIP_KIND
    if extension in _HTML_EXTENSIONS or content_type in _HTML_MIME_TYPES:
        return HTML_KIND
    return None


def make_finding(reason: str, detail: str, path: Optional[str] = None) -> Dict[str, str]:
    """Hallazgo de un inspector.

    Args:
        reason: Código estable del hallazgo (``pdf_javascript``,
            ``archive_bomb``…); la regla lo traduce a peso con
            ``attachment.<reason>``.
        detail: Qué se encontró, en castellano, para el analista.
        path: Ruta dentro del adjunto (una entrada de un ZIP), si aplica.

    Returns:
        Dict[str, str]: ``reason``, ``detail`` y, si hay, ``path``.
    """
    finding = {"reason": reason, "detail": detail}
    if path:
        finding["path"] = path
    return finding


@dataclass
class InspectionResult:
    """Lo que un inspector sacó de un adjunto.

    Attributes:
        findings: Hallazgos (ver ``make_finding``), en el orden en que se
            encontraron. Vacío si no hay nada sospechoso.
        urls: URLs que el adjunto contiene (enlaces de un PDF, destinos de un
            formulario, relaciones externas de un documento), como evidencia;
            como mucho ``MAX_URLS``.
    """
    findings: List[Dict[str, str]] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    def add_urls(self, urls) -> None:
        """Añade URLs sin repetir y sin pasar de ``MAX_URLS``.

        Args:
            urls: Iterable de URLs (``str``).
        """
        for url in urls:
            if len(self.urls) >= MAX_URLS:
                return
            if url not in self.urls:
                self.urls.append(url)

    def merge(self, other: "InspectionResult", path: str) -> None:
        """Incorpora el resultado de algo contenido en este adjunto.

        Args:
            other: Resultado de la pieza interior (una entrada de un ZIP).
            path: Ruta de esa pieza; se antepone a la ruta de sus hallazgos.
        """
        for finding in other.findings:
            inner = finding.get("path")
            self.findings.append({**finding, "path": f"{path}/{inner}" if inner else path})
        self.add_urls(other.urls)


@dataclass
class InspectionBudget:
    """Bytes que aún se pueden descomprimir o extraer al inspeccionar un adjunto.

    Se comparte entre el adjunto y todo lo que contiene —las entradas de un ZIP
    y los ZIP dentro de ellas, los flujos de un PDF—, así que un adjunto nunca
    ocupa en memoria más de lo que el presupuesto tenía al empezar, diga lo que
    diga su cabecera sobre los tamaños.

    Attributes:
        remaining: Bytes que quedan; nunca baja de cero.
        is_exhausted: Si alguna lectura se quedó a medias por agotarlo.
    """
    remaining: int
    is_exhausted: bool = False

    def read(self, stream: BinaryIO) -> bytes:
        """Lee de un flujo como mucho lo que queda de presupuesto.

        Args:
            stream: Flujo abierto (una entrada de un ZIP).

        Returns:
            bytes: Lo leído; si el flujo tenía más, solo el principio, y el
                presupuesto queda agotado.
        """
        data = stream.read(self.remaining)
        self.remaining -= len(data)
        if stream.read(1):
            self.is_exhausted = True
        return data

    def inflate(self, data: bytes) -> bytes:
        """Descomprime un flujo zlib/Flate como mucho hasta lo que queda.

        Args:
            data: Bytes comprimidos.

        Returns:
            bytes: Lo descomprimido (solo el principio si no cabía, y el
                presupuesto queda agotado); ``b""`` si no es zlib válido.
        """
        if self.remaining <= 0:
            self.is_exhausted = True
            return b""
        decompressor = zlib.decompressobj()
        try:
            output = decompressor.decompress(data, self.remaining)
        except zlib.error:
            return b""
        self.remaining -= len(output)
        if decompressor.unconsumed_tail:
            self.is_exhausted = True
        return output
