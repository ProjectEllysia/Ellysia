"""
Inspector estático de archivos ZIP.

Un ZIP es el envoltorio favorito para pasar un ejecutable por delante de un
filtro, y también un arma contra el propio filtro. Aquí se busca:

- **Ejecutables dentro** (``archive_contains_executable``), también en ZIP
  anidados.
- **Cifrado** (``archive_encrypted``): un ZIP con contraseña, que viene en el
  cuerpo del correo, es la forma clásica de que nadie pueda mirar dentro.
- **Rutas que escapan** (``archive_path_traversal``): entradas con ``..`` o
  rutas absolutas, que al descomprimir escriben fuera de la carpeta elegida.
- **Bombas** (``archive_bomb``): unos KB que se expanden a GB, por la razón
  de compresión que declaran o porque, al leerlos, agotan el presupuesto.
- **Anidamiento excesivo** o **demasiadas entradas**, que solo sirven para
  cansar al analizador.

Las cabeceras del ZIP pueden mentir sobre los tamaños; el presupuesto de
bytes no, porque cuenta lo que de verdad se lee. Las entradas que otro
inspector sabe leer (un PDF, un documento Office, un HTML, otro ZIP) se
extraen, con ese presupuesto, y se inspeccionan también.
"""

from __future__ import annotations

import re
import zipfile
from typing import Callable, FrozenSet

from .common import InspectionBudget, InspectionResult, extension_of, kind_of, make_finding

#: Tamaño a partir del cual una razón de compresión alta cuenta como bomba:
#: un fichero pequeño de ceros comprime muchísimo sin ser un ataque.
_BOMB_MIN_BYTES = 1024 * 1024
_ABSOLUTE_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:)")

NestedInspector = Callable[[str, bytes, int], InspectionResult]


def _escapes_folder(name: str) -> bool:
    """Si una ruta de entrada escribiría fuera de la carpeta de destino."""
    normalized = name.replace("\\", "/")
    return bool(_ABSOLUTE_PATH_RE.match(normalized)) or ".." in normalized.split("/")


def inspect_archive(archive: zipfile.ZipFile, limits, budget: InspectionBudget, depth: int,
                    dangerous_extensions: FrozenSet[str], inspect_nested: NestedInspector) -> InspectionResult:
    """Revisa un ZIP y lo que contiene.

    Args:
        archive: El ZIP, abierto.
        limits: Topes (``IrisAttachmentInspection``): ``max_archive_entries``,
            ``max_archive_depth``, ``max_compression_ratio`` y
            ``max_expanded_bytes``.
        budget: Presupuesto de bytes extraídos del adjunto.
        depth: Nivel de anidamiento de este ZIP (0 es el adjunto).
        dangerous_extensions: Extensiones que cuentan como ejecutable.
        inspect_nested: Inspector para una entrada extraída:
            ``(nombre, bytes, profundidad) -> InspectionResult``.

    Returns:
        InspectionResult: Hallazgos ``archive_*`` (cada motivo una vez por
            ZIP, con la primera ruta), más los de las entradas inspeccionadas,
            con su ruta dentro del ZIP.
    """
    result = InspectionResult()
    seen = set()

    def add(reason: str, detail: str, path: str) -> None:
        if reason not in seen:
            seen.add(reason)
            result.findings.append(make_finding(reason, detail, path))

    entries = [info for info in archive.infolist() if not info.is_dir()]
    if len(entries) > limits.max_archive_entries:
        add("archive_too_many_entries",
            f"El ZIP tiene {len(entries)} entradas; solo se revisan las {limits.max_archive_entries} primeras.", "")
        entries = entries[:limits.max_archive_entries]
    if sum(info.file_size for info in entries) > limits.max_expanded_bytes:
        add("archive_bomb", "El ZIP declara más contenido descomprimido del que se admite.", "")

    for info in entries:
        name = info.filename
        if _escapes_folder(name):
            add("archive_path_traversal", f"La entrada «{name}» escribiría fuera de la carpeta al descomprimir.", name)
        if extension_of(name) in dangerous_extensions:
            add("archive_contains_executable", f"El ZIP contiene un ejecutable: «{name}».", name)
        if info.flag_bits & 0x1:
            add("archive_encrypted", "El ZIP está cifrado: su contenido no se puede revisar.", name)
            continue
        if (info.compress_size and info.file_size >= _BOMB_MIN_BYTES
                and info.file_size / info.compress_size > limits.max_compression_ratio):
            add("archive_bomb", f"«{name}» se expande {info.file_size // info.compress_size} veces al descomprimir.", name)
            continue
        if kind_of(name, "", b"") is None:
            continue
        if depth + 1 > limits.max_archive_depth:
            add("archive_too_deep", f"«{name}» está anidado a más de {limits.max_archive_depth} niveles.", name)
            continue
        with archive.open(info) as handle:
            data = budget.read(handle)
        if budget.is_exhausted:
            add("archive_bomb", "El contenido del ZIP supera el tope de bytes descomprimidos.", name)
            break
        result.merge(inspect_nested(name, data, depth + 1), name)
    return result
