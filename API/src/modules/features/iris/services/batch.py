"""
Análisis por lotes: qué entra en un lote y qué se queda fuera.

Un lote llega como varios ``.eml`` o ``.msg`` de Outlook, o como un ZIP que
los contiene. Este módulo lo convierte en una lista de entradas, una por
mensaje, y decide las que no se pueden analizar —no son un correo, pasan del
tamaño máximo, están cifradas, son un ZIP dentro de otro o un ``.msg`` dañado—
sin que eso tumbe el resto del lote.

Un ``.msg`` se convierte aquí a ``.eml`` (``msg_converter``), así que lo que
sale de este módulo son siempre mensajes RFC 5322 y el resto de Iris no
distingue de qué formato vino cada uno.

Los límites de lote (cuántos mensajes y cuántos bytes en total) sí lo tumban
entero, y antes de crear nada: un lote que no cabe se rechaza con un motivo
claro en vez de aceptarse a medias.

Un ZIP se lee con tope: de cada entrada se leen como mucho
``max_message_bytes + 1`` bytes, así que un ZIP bomba (unos KB comprimidos que
se expanden a GB) nunca llega a descomprimirse entero; la cabecera del ZIP
puede mentir sobre el tamaño, la lectura acotada no.

Módulo puro: sin base de datos ni red.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .msg_converter import MsgConversionError, convert_msg_to_eml

_EML_SUFFIX = ".eml"
_MSG_SUFFIX = ".msg"
_ZIP_SUFFIX = ".zip"
_NOT_A_MESSAGE = "No es un fichero .eml ni .msg."


class BatchLimitError(ValueError):
    """El lote entero no cabe en los límites; el mensaje es apto para el usuario."""


@dataclass(frozen=True)
class BatchEntry:
    """Un mensaje del lote, listo para analizar o con el motivo de rechazo.

    Attributes:
        filename: Nombre del ``.eml`` (dentro del ZIP, su ruta en él).
        content: Bytes del mensaje; ``None`` si se rechazó.
        rejection: Por qué no se analiza; ``None`` si se puede analizar.
    """
    filename: str
    content: Optional[bytes] = None
    rejection: Optional[str] = None


def _is_message_file(filename: str) -> bool:
    """Si un nombre de fichero es un ``.eml`` o un ``.msg`` (sin distinguir mayúsculas)."""
    return filename.lower().endswith((_EML_SUFFIX, _MSG_SUFFIX))


def _message_entry(name: str, data: bytes, max_message_bytes: int) -> BatchEntry:
    """Entrada de un mensaje, suelto o sacado de un ZIP.

    Un ``.eml`` pasa tal cual; un ``.msg`` se convierte a ``.eml``. El tope se
    aplica al fichero recibido y, en un ``.msg``, también al resultado: la
    conversión pasa los adjuntos a base64, que ocupa un tercio más.

    Args:
        name: Nombre del fichero (dentro de un ZIP, ``zip/ruta``).
        data: Sus bytes.
        max_message_bytes: Tamaño máximo de un mensaje.

    Returns:
        BatchEntry: Con el ``.eml`` en ``content``, o con el motivo de rechazo
            si pasa del tamaño o es un ``.msg`` que no se puede convertir.
    """
    too_big = f"Supera el tamaño máximo ({max_message_bytes} bytes)."
    if len(data) > max_message_bytes:
        return BatchEntry(name, rejection=too_big)
    if name.lower().endswith(_MSG_SUFFIX):
        try:
            data = convert_msg_to_eml(data).encode("utf-8")
        except MsgConversionError as e:
            return BatchEntry(name, rejection=str(e))
        if len(data) > max_message_bytes:
            return BatchEntry(name, rejection=f"Convertido a .eml, supera el tamaño máximo ({max_message_bytes} bytes).")
    return BatchEntry(name, content=data)


def _expand_zip(filename: str, data: bytes, max_message_bytes: int) -> List[BatchEntry]:
    """Saca los mensajes de un ZIP, leyendo cada entrada con tope.

    Args:
        filename: Nombre del ZIP, para los motivos de rechazo.
        data: Bytes del ZIP.
        max_message_bytes: Tamaño máximo de un mensaje.

    Returns:
        List[BatchEntry]: Una entrada por fichero del ZIP (los directorios no
            cuentan). Si el ZIP no se puede abrir, una sola entrada rechazada.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [BatchEntry(filename, rejection="No es un ZIP válido.")]

    entries: List[BatchEntry] = []
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = f"{filename}/{info.filename}"
            if info.flag_bits & 0x1:
                entries.append(BatchEntry(name, rejection="Está cifrado dentro del ZIP."))
            elif info.filename.lower().endswith(_ZIP_SUFFIX):
                entries.append(BatchEntry(name, rejection="No se admiten ZIP dentro de un ZIP."))
            elif not _is_message_file(info.filename):
                entries.append(BatchEntry(name, rejection=_NOT_A_MESSAGE))
            elif info.file_size > max_message_bytes:
                entries.append(BatchEntry(name, rejection=f"Supera el tamaño máximo ({max_message_bytes} bytes)."))
            else:
                with archive.open(info) as handle:
                    entries.append(_message_entry(name, handle.read(max_message_bytes + 1), max_message_bytes))
    return entries


def expand_uploads(uploads: Sequence[Tuple[str, bytes]], *, max_items: int,
                   max_message_bytes: int, max_total_bytes: int) -> List[BatchEntry]:
    """Convierte los ficheros subidos en las entradas del lote.

    Args:
        uploads: Pares ``(nombre, bytes)`` tal como llegaron: ``.eml`` y
            ``.msg`` sueltos y/o ZIP.
        max_items: Mensajes como máximo en el lote, contando los rechazados.
        max_message_bytes: Tamaño máximo de un mensaje.
        max_total_bytes: Suma máxima de los mensajes que se van a analizar.

    Returns:
        List[BatchEntry]: En el orden en que llegaron; las de un ZIP, en su
            orden dentro del ZIP.

    Raises:
        BatchLimitError: Si no llega ningún fichero, si hay más de
            ``max_items`` mensajes o si los analizables suman más de
            ``max_total_bytes``.
    """
    if not uploads:
        raise BatchLimitError("El lote está vacío: adjunta ficheros .eml o .msg, o un ZIP que los contenga.")
    entries: List[BatchEntry] = []
    for filename, data in uploads:
        name = filename or "sin-nombre"
        if name.lower().endswith(_ZIP_SUFFIX):
            entries.extend(_expand_zip(name, data, max_message_bytes))
        elif not _is_message_file(name):
            entries.append(BatchEntry(name, rejection=_NOT_A_MESSAGE))
        else:
            entries.append(_message_entry(name, data, max_message_bytes))
        if len(entries) > max_items:
            raise BatchLimitError(f"Un lote admite como mucho {max_items} mensajes.")

    total_bytes = sum(len(entry.content) for entry in entries if entry.content is not None)
    if total_bytes > max_total_bytes:
        raise BatchLimitError(f"Los mensajes del lote suman más de {max_total_bytes} bytes.")
    return entries


def decode_message(content: bytes) -> str:
    """Texto de un ``.eml`` para el analizador.

    Un ``.eml`` es casi siempre ASCII o UTF-8; si no lo es, Latin-1 no falla
    nunca y conserva cada byte, que es lo que necesita el parser MIME para
    decodificar después las partes con su propio charset.

    Args:
        content: Bytes del mensaje.

    Returns:
        str: El mensaje como texto.
    """
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def message_fingerprint(raw: str) -> str:
    """Huella de un mensaje para reconocer el mismo correo enviado dos veces.

    Args:
        raw: Cabeceras o ``.eml`` completo, como texto.

    Returns:
        str: SHA-256 hexadecimal del texto en UTF-8 (64 caracteres).
    """
    return hashlib.sha256(raw.encode("utf-8", errors="surrogatepass")).hexdigest()
