"""
OCR local de imágenes para las reglas de contenido de Iris.

Un phishing puede poner toda su carga —la marca, la urgencia, la petición de
la contraseña, la URL— dentro de una imagen, donde ninguna regla de texto la
ve. Este servicio saca el texto de una imagen con Tesseract, un motor de OCR
libre (licencia Apache 2.0) que se ejecuta **en la propia máquina**: la imagen
no sale nunca a un servicio de terceros.

Aislamiento y límites:

- El tamaño en píxeles se lee de la cabecera de la imagen (Pillow no
  decodifica nada al abrirla) y se comprueba **antes** de decodificar: una
  imagen de 20.000 × 20.000 píxeles cabe en pocos KB comprimida y, una vez
  decodificada, agotaría la memoria.
- Al motor no le llega el fichero del atacante, sino un PNG en escala de
  grises recodificado desde los píxeles: Tesseract nunca parsea el formato
  original.
- Tesseract corre en un proceso aparte con tiempo máximo; si se pasa, se mata.
- Si el binario no está instalado, el servicio lo dice y la regla se queda
  neutral: el OCR suma señales, no es un requisito para analizar.
"""

from __future__ import annotations

import io
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from PIL import Image

#: Ejecutable de Tesseract; se busca en el ``PATH``.
ENGINE_BINARY = "tesseract"

OCR_OK = "ok"
OCR_NO_ENGINE = "no_engine"
OCR_NOT_IMAGE = "not_image"
OCR_TOO_LARGE = "too_large"
OCR_TIMEOUT = "timeout"
OCR_FAILED = "failed"


@dataclass(frozen=True)
class OcrResult:
    """Resultado de pasar una imagen por el OCR.

    Attributes:
        status: ``OCR_OK`` (se leyó, aunque puede no haber texto),
            ``OCR_NO_ENGINE`` (Tesseract no está instalado),
            ``OCR_NOT_IMAGE`` (no se puede decodificar como imagen),
            ``OCR_TOO_LARGE`` (pasa de los píxeles permitidos),
            ``OCR_TIMEOUT`` (el motor tardó demasiado) u ``OCR_FAILED`` (el
            motor terminó con error, por ejemplo por faltar un idioma).
        text: Texto reconocido, sin espacios en los extremos; vacío salvo
            con ``OCR_OK``.
    """
    status: str
    text: str = ""


def find_engine() -> Optional[str]:
    """Ruta del ejecutable de Tesseract.

    Returns:
        Optional[str]: La ruta, o ``None`` si no está en el ``PATH``.
    """
    return shutil.which(ENGINE_BINARY)


def extract_text(image_bytes: bytes, *, languages: str, max_pixels: int, timeout_seconds: float) -> OcrResult:
    """Lee el texto de una imagen con Tesseract en local.

    Args:
        image_bytes: Bytes de la imagen, en cualquier formato que Pillow
            reconozca (PNG, JPEG, GIF…).
        languages: Idiomas de Tesseract separados por ``+`` (``"spa+eng"``);
            cada uno necesita su paquete de datos instalado.
        max_pixels: Píxeles máximos (ancho × alto) de una imagen para leerla.
        timeout_seconds: Tiempo máximo del motor por imagen.

    Returns:
        OcrResult: El texto y cómo fue (ver ``OcrResult.status``).
    """
    engine = find_engine()
    if engine is None:
        return OcrResult(OCR_NO_ENGINE)
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if width * height > max_pixels:
                return OcrResult(OCR_TOO_LARGE)
            normalized = io.BytesIO()
            image.convert("L").save(normalized, format="PNG")
    except (OSError, ValueError, Image.DecompressionBombError):
        return OcrResult(OCR_NOT_IMAGE)
    try:
        completed = subprocess.run(
            [engine, "stdin", "stdout", "-l", languages],
            input=normalized.getvalue(), capture_output=True, timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return OcrResult(OCR_TIMEOUT)
    except OSError:
        return OcrResult(OCR_FAILED)
    if completed.returncode != 0:
        return OcrResult(OCR_FAILED)
    return OcrResult(OCR_OK, completed.stdout.decode("utf-8", errors="replace").strip())
