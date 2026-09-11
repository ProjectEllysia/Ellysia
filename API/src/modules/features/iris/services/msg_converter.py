"""
Conversor de ``.msg`` de Outlook a un ``.eml`` canónico.

Outlook exporta los correos en ``.msg``: un fichero *Compound File Binary*
(el contenedor OLE de Microsoft) con una propiedad MAPI por flujo, no texto
RFC 5322. Iris analiza ``.eml``, así que este módulo lee las propiedades del
``.msg`` y reconstruye el mensaje en MIME; a partir de ahí todo sigue igual —el
parser, las reglas, la evidencia anclada, el reanálisis— porque lo que se guarda
y se analiza es ese ``.eml``.

Qué se conserva:

- **Las cabeceras originales** cuando el ``.msg`` es de un correo recibido:
  Outlook guarda el bloque de cabeceras de Internet tal como llegó
  (``PR_TRANSPORT_MESSAGE_HEADERS``), con ``Received``,
  ``Authentication-Results``, DKIM y ``Message-ID``. Sin él (un borrador o un
  enviado), las cabeceras básicas se reconstruyen desde las propiedades.
- **Los cuerpos**: texto, HTML y, si solo hay RTF comprimido, su texto.
- **Los adjuntos**, con nombre Unicode, tipo y ``Content-ID`` de los que van en
  línea, y los **mensajes incrustados** (el «reenviar como adjunto» de
  Outlook), que pasan a ser una parte ``message/rfc822``.

Nunca se ejecuta ni se interpreta el contenido de un adjunto: sus bytes se
copian tal cual. Se usa ``olefile`` (BSD) para leer el contenedor; la
descompresión del RTF (MS-OXRTFCP) está implementada aquí.

Módulo puro: sin base de datos ni red.
"""

from __future__ import annotations

import io
import mimetypes
import re
import struct
from datetime import datetime, timedelta, timezone
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from email.utils import format_datetime, formataddr
from typing import Dict, List, Optional, Tuple

import olefile

#: Firma de un Compound File Binary (``.msg``, y también ``.doc``/``.xls``).
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

#: Adjuntos como máximo por mensaje (contando los de los incrustados).
MAX_ATTACHMENTS = 100

#: Profundidad máxima de mensajes incrustados (un reenvío de un reenvío…).
MAX_EMBEDDING_DEPTH = 3

#: Tamaño máximo del RTF descomprimido: el tamaño declarado en la cabecera del
#: RTF puede mentir, así que la descompresión se corta aquí pase lo que pase.
MAX_RTF_BYTES = 4 * 1024 * 1024

#: Cabeceras que describen la estructura MIME original del correo. No se
#: copian: el cuerpo se reconstruye, y con él su propia estructura.
_MIME_STRUCTURE_HEADERS = frozenset({"content-type", "content-transfer-encoding", "mime-version"})

# Propiedades MAPI (id de 4 hexadecimales).
_PR_SUBJECT = "0037"
_PR_MESSAGE_CLASS = "001A"
_PR_TRANSPORT_MESSAGE_HEADERS = "007D"
_PR_SENDER_NAME = "0C1A"
_PR_SENDER_EMAIL = "0C1F"
_PR_SENDER_SMTP = "5D01"
_PR_DISPLAY_TO = "0E04"
_PR_DISPLAY_CC = "0E03"
_PR_BODY = "1000"
_PR_RTF_COMPRESSED = "1009"
_PR_HTML = "1013"
_PR_INTERNET_MESSAGE_ID = "1035"
_PR_ATTACH_DATA = "3701"
_PR_ATTACH_FILENAME = "3704"
_PR_ATTACH_LONG_FILENAME = "3707"
_PR_ATTACH_MIME_TAG = "370E"
_PR_ATTACH_CONTENT_ID = "3712"
_TAG_CLIENT_SUBMIT_TIME = 0x00390040
_TAG_MESSAGE_CODEPAGE = 0x3FFD0003
_TAG_INTERNET_CPID = 0x3FDE0003

# Cabecera del flujo de propiedades según el objeto (MS-OXMSG §2.4).
_PROPERTIES_STREAM = "__properties_version1.0"
_TOP_LEVEL_HEADER_SIZE = 32
_EMBEDDED_HEADER_SIZE = 24
_ATTACHMENT_HEADER_SIZE = 8

_ATTACHMENT_STORAGE_PREFIX = "__attach_version1.0_"
_EMBEDDED_MESSAGE_STORAGE = "__substg1.0_3701000D"

# Diccionario inicial del RTF comprimido (MS-OXRTFCP §3.1.3.1).
_RTF_PREBUFFER = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss "
    b"\\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier"
    b"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)
_RTF_COMPRESSED = 0x75465A4C    # "LZFu"
_RTF_UNCOMPRESSED = 0x414C454D  # "MELA"
_RTF_DICTIONARY_SIZE = 4096

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class MsgConversionError(ValueError):
    """El fichero no es un ``.msg`` de Outlook que se pueda convertir.

    El mensaje es apto para el usuario.
    """


def is_msg(data: bytes) -> bool:
    """Si unos bytes empiezan por la firma de un Compound File Binary.

    Args:
        data: Contenido del fichero (basta con los 8 primeros bytes).

    Returns:
        bool: ``True`` si puede ser un ``.msg`` (la conversión confirma que lo es).
    """
    return data[:8] == OLE_MAGIC


def decompress_rtf(data: bytes, max_bytes: int = MAX_RTF_BYTES) -> bytes:
    """Descomprime el RTF de ``PR_RTF_COMPRESSED`` (MS-OXRTFCP).

    Args:
        data: El valor de la propiedad: cabecera de 16 bytes y contenido.
        max_bytes: Tope de la salida, pase lo que diga la cabecera. Por
            defecto ``MAX_RTF_BYTES``.

    Returns:
        bytes: El RTF sin comprimir (recortado a ``max_bytes``).

    Raises:
        MsgConversionError: Si la cabecera no es de RTF comprimido.
    """
    if len(data) < 16:
        raise MsgConversionError("El cuerpo RTF del .msg está incompleto.")
    compressed_size, raw_size, compression_type, _crc = struct.unpack("<IIII", data[:16])
    if compression_type == _RTF_UNCOMPRESSED:
        return data[16:16 + min(raw_size, max_bytes)]
    if compression_type != _RTF_COMPRESSED:
        raise MsgConversionError("El cuerpo RTF del .msg tiene un formato desconocido.")

    dictionary = bytearray(_RTF_DICTIONARY_SIZE)
    dictionary[:len(_RTF_PREBUFFER)] = _RTF_PREBUFFER
    write_position = len(_RTF_PREBUFFER)
    output = bytearray()
    position, end = 16, min(len(data), compressed_size + 4)
    while position < end and len(output) < max_bytes:
        control = data[position]
        position += 1
        for bit in range(8):
            if position >= end or len(output) >= max_bytes:
                break
            if control & (1 << bit):
                if position + 1 >= end:
                    return bytes(output)
                token = (data[position] << 8) | data[position + 1]
                position += 2
                offset, length = token >> 4, (token & 0x0F) + 2
                if offset == write_position:
                    return bytes(output[:max_bytes])
                for index in range(length):
                    byte = dictionary[(offset + index) % _RTF_DICTIONARY_SIZE]
                    output.append(byte)
                    dictionary[write_position] = byte
                    write_position = (write_position + 1) % _RTF_DICTIONARY_SIZE
            else:
                byte = data[position]
                position += 1
                output.append(byte)
                dictionary[write_position] = byte
                write_position = (write_position + 1) % _RTF_DICTIONARY_SIZE
    return bytes(output[:max_bytes])


_RTF_TOKEN_RE = re.compile(
    rb"\\([a-z]+)(-?\d+)? ?|\\'([0-9a-f]{2})|\\([\\{}])|(\\\*)|([{}])|\r?\n|([^\\{}\r\n]+)", re.IGNORECASE,
)
_RTF_HIDDEN_DESTINATIONS = (b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict")


def rtf_to_text(rtf: bytes) -> str:
    """Texto legible de un RTF: suficiente para las reglas de contenido.

    Descarta los grupos que no se muestran (``{\\*…}``, tablas de fuentes y
    colores) y traduce los saltos, tabuladores, escapes ``\\'hh`` (Windows-1252)
    y caracteres ``\\uN``.

    Args:
        rtf: RTF sin comprimir.

    Returns:
        str: El texto, sin marcado.
    """
    parts: List[str] = []
    # Profundidad del grupo oculto que se está saltando; un grupo oculto dentro
    # de otro ya queda cubierto por el de fuera.
    skip_depth: Optional[int] = None
    depth = 0
    skip_next = 0
    for match in _RTF_TOKEN_RE.finditer(rtf):
        word, number, hex_value, escaped, star, brace, text = match.groups()
        if brace == b"{":
            depth += 1
            continue
        if brace == b"}":
            if skip_depth == depth:
                skip_depth = None
            depth -= 1
            continue
        if star is not None or (word is not None and word.lower() in _RTF_HIDDEN_DESTINATIONS):
            if skip_depth is None:
                skip_depth = depth
            continue
        if skip_depth is not None:
            continue
        if skip_next and (text or hex_value):
            skip_next -= 1
            if text and len(text) > 1:
                parts.append(text[1:].decode("cp1252", errors="replace"))
            continue
        if word is not None:
            lowered = word.lower()
            if lowered in (b"par", b"line"):
                parts.append("\n")
            elif lowered == b"tab":
                parts.append("\t")
            elif lowered == b"u" and number is not None:
                parts.append(chr(int(number) % 0x10000))
                skip_next = 1
        elif hex_value is not None:
            parts.append(bytes([int(hex_value, 16)]).decode("cp1252", errors="replace"))
        elif escaped is not None:
            parts.append(escaped.decode("ascii"))
        elif text is not None:
            parts.append(text.decode("cp1252", errors="replace"))
    return re.sub(r"\n{3,}", "\n\n", "".join(parts)).strip()


def _fixed_properties(ole: olefile.OleFileIO, prefix: str, header_size: int) -> Dict[int, bytes]:
    """Propiedades de tamaño fijo de un objeto, por etiqueta MAPI.

    Args:
        ole: Contenedor abierto.
        prefix: Ruta del objeto (``""`` para el mensaje raíz).
        header_size: Bytes de cabecera del flujo según el tipo de objeto.

    Returns:
        Dict[int, bytes]: Etiqueta (id << 16 | tipo) -> 8 bytes de valor; vacío
            si el objeto no tiene flujo de propiedades.
    """
    path = prefix + _PROPERTIES_STREAM
    if not ole.exists(path):
        return {}
    raw = ole.openstream(path).read()
    properties: Dict[int, bytes] = {}
    for offset in range(header_size, len(raw) - 15, 16):
        tag = struct.unpack("<I", raw[offset:offset + 4])[0]
        properties[tag] = raw[offset + 8:offset + 16]
    return properties


def _codec_for(codepage: Optional[int], fallback: str = "cp1252") -> str:
    """Codec de Python para una página de códigos de Windows."""
    if not codepage:
        return fallback
    if codepage == 65001:
        return "utf-8"
    codec = f"cp{codepage}"
    try:
        "".encode(codec)
    except LookupError:
        return fallback
    return codec


def _read_string(ole: olefile.OleFileIO, prefix: str, property_id: str, codec: str) -> Optional[str]:
    """Valor de texto de una propiedad, en Unicode o en la página de códigos del mensaje."""
    for suffix, encoding in (("001F", "utf-16-le"), ("001E", codec)):
        path = f"{prefix}__substg1.0_{property_id}{suffix}"
        if ole.exists(path):
            return ole.openstream(path).read().decode(encoding, errors="replace").rstrip("\x00")
    return None


def _read_binary(ole: olefile.OleFileIO, prefix: str, property_id: str) -> Optional[bytes]:
    """Valor binario de una propiedad, o ``None`` si no está."""
    path = f"{prefix}__substg1.0_{property_id}0102"
    return ole.openstream(path).read() if ole.exists(path) else None


def _long(properties: Dict[int, bytes], tag: int) -> Optional[int]:
    value = properties.get(tag)
    return struct.unpack("<i", value[:4])[0] if value else None


def _systime(properties: Dict[int, bytes], tag: int) -> Optional[datetime]:
    value = properties.get(tag)
    if not value:
        return None
    filetime = struct.unpack("<Q", value)[0]
    return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10) if filetime else None


def _attachment_storages(ole: olefile.OleFileIO, prefix: str) -> List[str]:
    """Rutas de los adjuntos directos de un objeto, en su orden."""
    depth = prefix.count("/")
    names = set()
    for entry in ole.listdir(streams=False, storages=True):
        if len(entry) == depth + 1 and "/".join(entry[:-1]) + ("/" if depth else "") == prefix \
                and entry[-1].startswith(_ATTACHMENT_STORAGE_PREFIX):
            names.add(entry[-1])
    return [f"{prefix}{name}/" for name in sorted(names)]


def _headers_block(ole: olefile.OleFileIO, prefix: str, properties: Dict[int, bytes], codec: str) -> str:
    """Bloque de cabeceras RFC 5322 del mensaje, sin las de estructura MIME.

    Returns:
        str: Las cabeceras de transporte originales si el ``.msg`` las guarda;
            si no, las básicas reconstruidas. Termina en salto de línea.
    """
    transport = _read_string(ole, prefix, _PR_TRANSPORT_MESSAGE_HEADERS, codec)
    if transport and transport.strip():
        parsed = Parser().parsestr(transport.strip() + "\n\n", headersonly=True)
        lines = [f"{name}: {value}" for name, value in parsed.items()
                 if name.lower() not in _MIME_STRUCTURE_HEADERS]
        return "\n".join(lines) + "\n"

    sender_address = (_read_string(ole, prefix, _PR_SENDER_SMTP, codec)
                      or _read_string(ole, prefix, _PR_SENDER_EMAIL, codec) or "")
    sender_name = _read_string(ole, prefix, _PR_SENDER_NAME, codec) or ""
    headers = []
    if sender_address or sender_name:
        headers.append(("From", formataddr((sender_name, sender_address), charset="utf-8")))
    for header_name, property_id in (("To", _PR_DISPLAY_TO), ("Cc", _PR_DISPLAY_CC)):
        value = _read_string(ole, prefix, property_id, codec)
        if value:
            headers.append((header_name, Header(value, "utf-8").encode()))
    subject = _read_string(ole, prefix, _PR_SUBJECT, codec)
    if subject:
        headers.append(("Subject", Header(subject, "utf-8").encode()))
    submitted = _systime(properties, _TAG_CLIENT_SUBMIT_TIME)
    if submitted:
        headers.append(("Date", format_datetime(submitted)))
    message_id = _read_string(ole, prefix, _PR_INTERNET_MESSAGE_ID, codec)
    if message_id:
        headers.append(("Message-ID", message_id))
    return "".join(f"{name}: {value}\n" for name, value in headers)


def _body_part(ole: olefile.OleFileIO, prefix: str, properties: Dict[int, bytes], codec: str):
    """Parte MIME con el cuerpo del mensaje (texto, HTML o los dos)."""
    text = _read_string(ole, prefix, _PR_BODY, codec)
    html_bytes = _read_binary(ole, prefix, _PR_HTML)
    html = None
    if html_bytes:
        html = html_bytes.decode(_codec_for(_long(properties, _TAG_INTERNET_CPID), "utf-8"), errors="replace")
    if not text and not html:
        rtf = _read_binary(ole, prefix, _PR_RTF_COMPRESSED)
        if rtf:
            text = rtf_to_text(decompress_rtf(rtf))
    parts = []
    if text:
        parts.append(MIMEText(text, "plain", "utf-8"))
    if html:
        parts.append(MIMEText(html, "html", "utf-8"))
    if not parts:
        return MIMEText("", "plain", "utf-8")
    if len(parts) == 1:
        return parts[0]
    alternative = MIMEMultipart("alternative")
    for part in parts:
        alternative.attach(part)
    return alternative


def _is_embedded_message(ole: olefile.OleFileIO, storage: str, codec: str) -> bool:
    """Si una carpeta ``3701000D`` es un mensaje (y no un documento OLE incrustado)."""
    message_class = _read_string(ole, storage, _PR_MESSAGE_CLASS, codec) or ""
    return message_class.upper().startswith("IPM") or ole.exists(storage + _PROPERTIES_STREAM)


def _build_message(ole: olefile.OleFileIO, prefix: str, header_size: int, depth: int,
                   attachment_count: List[int]) -> str:
    """Reconstruye un mensaje (el raíz o uno incrustado) como texto ``.eml``.

    Args:
        ole: Contenedor abierto.
        prefix: Ruta del mensaje dentro del contenedor.
        header_size: Cabecera de su flujo de propiedades.
        depth: Nivel de incrustación (0 es el raíz).
        attachment_count: Contador compartido de adjuntos, en una lista para
            poder sumarlo desde los mensajes incrustados.

    Returns:
        str: El mensaje en RFC 5322 / MIME.

    Raises:
        MsgConversionError: Si se superan ``MAX_ATTACHMENTS`` o
            ``MAX_EMBEDDING_DEPTH``.
    """
    properties = _fixed_properties(ole, prefix, header_size)
    codec = _codec_for(_long(properties, _TAG_MESSAGE_CODEPAGE))
    headers = _headers_block(ole, prefix, properties, codec)
    body = _body_part(ole, prefix, properties, codec)

    attachments = []
    for storage in _attachment_storages(ole, prefix):
        attachment_count[0] += 1
        if attachment_count[0] > MAX_ATTACHMENTS:
            raise MsgConversionError(f"El .msg tiene más de {MAX_ATTACHMENTS} adjuntos.")
        filename = (_read_string(ole, storage, _PR_ATTACH_LONG_FILENAME, codec)
                    or _read_string(ole, storage, _PR_ATTACH_FILENAME, codec) or "adjunto")
        embedded = storage + _EMBEDDED_MESSAGE_STORAGE + "/"
        if ole.exists(storage + _EMBEDDED_MESSAGE_STORAGE) and _is_embedded_message(ole, embedded, codec):
            if depth + 1 > MAX_EMBEDDING_DEPTH:
                raise MsgConversionError(
                    f"El .msg anida más de {MAX_EMBEDDING_DEPTH} mensajes incrustados.")
            nested = _build_message(ole, embedded, _EMBEDDED_HEADER_SIZE, depth + 1, attachment_count)
            part = MIMEMessage(Parser().parsestr(nested))
            part.add_header("Content-Disposition", "attachment", filename=("utf-8", "", filename + ".eml"))
            attachments.append(part)
            continue
        data = _read_binary(ole, storage, _PR_ATTACH_DATA)
        if data is None:
            continue  # objeto OLE incrustado sin datos que copiar
        mime_type = (_read_string(ole, storage, _PR_ATTACH_MIME_TAG, codec)
                     or mimetypes.guess_type(filename)[0] or "application/octet-stream")
        maintype, _, subtype = mime_type.partition("/")
        part = MIMEBase(maintype or "application", subtype or "octet-stream")
        part.set_payload(data)
        encoders.encode_base64(part)
        content_id = _read_string(ole, storage, _PR_ATTACH_CONTENT_ID, codec)
        part.add_header("Content-Disposition", "inline" if content_id else "attachment",
                        filename=("utf-8", "", filename))
        if content_id:
            part.add_header("Content-ID", f"<{content_id.strip('<>')}>")
        attachments.append(part)

    if attachments:
        root = MIMEMultipart("mixed")
        root.attach(body)
        for part in attachments:
            root.attach(part)
    else:
        root = body
    return headers + root.as_string()


def convert_msg_to_eml(data: bytes) -> str:
    """Convierte un ``.msg`` de Outlook en un ``.eml`` que Iris analiza como cualquier otro.

    Args:
        data: Contenido completo del ``.msg``. El llamante ya ha comprobado su
            tamaño contra ``iris.maxMessageBytes``.

    Returns:
        str: El mensaje en RFC 5322 / MIME, con la cabecera
            ``X-Iris-Source-Format: outlook-msg`` al final del bloque para que
            el analista sepa que viene de una conversión.

    Raises:
        MsgConversionError: Si no es un ``.msg`` válido, o si supera
            ``MAX_ATTACHMENTS`` o ``MAX_EMBEDDING_DEPTH``.
    """
    if not is_msg(data):
        raise MsgConversionError("No es un fichero .msg de Outlook.")
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, ValueError, struct.error) as e:
        raise MsgConversionError("El fichero .msg está dañado y no se puede leer.") from e
    with ole:
        if not ole.exists(_PROPERTIES_STREAM):
            raise MsgConversionError("El fichero no es un mensaje de Outlook (.msg).")
        try:
            converted = _build_message(ole, "", _TOP_LEVEL_HEADER_SIZE, 0, [0])
        except (OSError, struct.error) as e:
            raise MsgConversionError("El fichero .msg está dañado y no se puede leer.") from e
    header_end = converted.find("\n\n")
    marker = "X-Iris-Source-Format: outlook-msg\n"
    return converted[:header_end + 1] + marker + converted[header_end + 1:] if header_end >= 0 else marker + converted
