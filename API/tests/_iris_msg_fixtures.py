"""Generador de ficheros ``.msg`` de Outlook para los tests del conversor.

``olefile`` solo lee, así que para probar el conversor con muestras
controladas (sin ficheros binarios de origen dudoso en el repositorio) se
escribe aquí un *Compound File Binary* mínimo: versión 3, sectores de 512
bytes, los flujos de menos de 4096 bytes en el *mini stream* (sectores de 64
bytes, como manda el formato) y los demás en la FAT normal. El único atajo es
el árbol de directorio: cada hermano cuelga del anterior en vez de formar un
árbol rojo-negro equilibrado, algo que los lectores aceptan.

No es un test: pytest no lo recoge (no empieza por ``test_``). Vive en
``tests/`` porque el conftest de ahí pone el directorio en ``sys.path`` y así
lo importan igual los tests unitarios y los de integración.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

_SECTOR = 512
_MINI_SECTOR = 64
_MINI_CUTOFF = 4096
_FREE, _END, _FAT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
_NO_STREAM = 0xFFFFFFFF


def _entry(name: str, kind: int, child: int, right: int, start: int, size: int) -> bytes:
    encoded = (name + "\x00").encode("utf-16-le")
    return (encoded.ljust(64, b"\x00") + struct.pack("<HBB", len(encoded), kind, 1)
            + struct.pack("<III", _NO_STREAM, right, child) + b"\x00" * 16 + b"\x00" * 4
            + b"\x00" * 16 + struct.pack("<IQ", start, size))


def build_cfb(streams: Dict[str, bytes]) -> bytes:
    """Contenedor CFB con los flujos dados; las carpetas se crean solas.

    Args:
        streams: Ruta (``"a/b/flujo"``) -> contenido.

    Returns:
        bytes: El fichero completo.
    """
    storages = {""}
    for path in streams:
        parts = path.split("/")
        for index in range(1, len(parts)):
            storages.add("/".join(parts[:index]))
    nodes = sorted(storages | set(streams), key=lambda path: (path.count("/"), path))
    children: Dict[str, List[str]] = {node: [] for node in storages}
    for node in nodes:
        if node:
            children[node.rsplit("/", 1)[0] if "/" in node else ""].append(node)

    def order(path: str) -> Tuple[int, str]:
        name = path.rsplit("/", 1)[-1]
        return len(name), name.upper()

    for key in children:
        children[key].sort(key=order)
    index_of = {node: position for position, node in enumerate(nodes)}

    sectors: List[bytes] = []
    fat: List[int] = []

    def put(data: bytes, padding: bytes = b"\x00") -> int:
        """Escribe una cadena de sectores normales y devuelve el primero."""
        start, count = len(sectors), -(-len(data) // _SECTOR)
        for chunk in range(count):
            sectors.append(data[chunk * _SECTOR:(chunk + 1) * _SECTOR].ljust(_SECTOR, padding))
            fat.append(len(sectors) if chunk < count - 1 else _END)
        return start

    mini_stream = bytearray()
    mini_fat: List[int] = []
    starts: Dict[str, int] = {}
    for path in nodes:
        data = streams.get(path) if path not in storages else None
        if not data:
            continue
        if len(data) >= _MINI_CUTOFF:
            starts[path] = put(data)
            continue
        starts[path] = len(mini_stream) // _MINI_SECTOR
        count = -(-len(data) // _MINI_SECTOR)
        for chunk in range(count):
            mini_fat.append(len(mini_fat) + 1 if chunk < count - 1 else _END)
        mini_stream += data.ljust(count * _MINI_SECTOR, b"\x00")
    root_start = put(bytes(mini_stream)) if mini_stream else _END
    first_mini_fat = put(struct.pack(f"<{len(mini_fat)}I", *mini_fat), b"\xff") if mini_fat else _END
    mini_fat_sectors = -(-len(mini_fat) * 4 // _SECTOR)

    directory = b""
    for path in nodes:
        siblings = children[path.rsplit("/", 1)[0] if "/" in path else ""] if path else []
        right = index_of[siblings[siblings.index(path) + 1]] if path and siblings.index(path) + 1 < len(siblings) else _NO_STREAM
        child = index_of[children[path][0]] if path in storages and children[path] else _NO_STREAM
        if path == "":
            directory += _entry("Root Entry", 5, child, _NO_STREAM, root_start, len(mini_stream))
        elif path in storages:
            directory += _entry(path.rsplit("/", 1)[-1], 1, child, right, _END, 0)
        else:
            data = streams[path]
            directory += _entry(path.rsplit("/", 1)[-1], 2, _NO_STREAM, right,
                                starts.get(path, _END), len(data))
    first_directory = put(directory)

    fat_sectors = 1
    while (len(sectors) + fat_sectors) > fat_sectors * (_SECTOR // 4):
        fat_sectors += 1
    first_fat = len(sectors)
    fat.extend([_FAT] * fat_sectors)
    fat.extend([_FREE] * (fat_sectors * (_SECTOR // 4) - len(fat)))
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for chunk in range(fat_sectors):
        sectors.append(fat_bytes[chunk * _SECTOR:(chunk + 1) * _SECTOR])

    difat = [first_fat + chunk for chunk in range(fat_sectors)] + [_FREE] * (109 - fat_sectors)
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
              + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, fat_sectors, first_directory, 0, _MINI_CUTOFF,
                            first_mini_fat, mini_fat_sectors, _END, 0)
              + struct.pack("<109I", *difat))
    return header + b"".join(sectors)


def compress_rtf(raw: bytes) -> bytes:
    """RTF comprimido válido (MS-OXRTFCP) formado solo por literales."""
    tokens: List[bytes] = [bytes([byte]) for byte in raw]
    end_position = (207 + len(raw)) % 4096
    tokens.append(bytes([(end_position >> 4) & 0xFF, (end_position << 4) & 0xF0]))
    body = bytearray()
    for start in range(0, len(tokens), 8):
        group = tokens[start:start + 8]
        control = sum(1 << bit for bit, token in enumerate(group) if len(token) == 2)
        body.append(control)
        for token in group:
            body += token
    return struct.pack("<IIII", len(body) + 12, len(raw), 0x75465A4C, 0) + bytes(body)


def _utf16(value: str) -> bytes:
    return value.encode("utf-16-le")


def _properties(header_size: int, submitted: Optional[datetime] = None, cpid: Optional[int] = None) -> bytes:
    stream = b"\x00" * header_size
    if submitted is not None:
        filetime = int((submitted - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
        stream += struct.pack("<IIQ", 0x00390040, 6, filetime)
    if cpid is not None:
        stream += struct.pack("<IIi", 0x3FDE0003, 6, cpid) + b"\x00" * 4
    return stream


def msg_streams(*, prefix: str = "", header_size: int = 32, subject: Optional[str] = None,
                sender_name: Optional[str] = None, sender_email: Optional[str] = None,
                transport_headers: Optional[str] = None, body: Optional[str] = None,
                html: Optional[str] = None, rtf: Optional[bytes] = None,
                submitted: Optional[datetime] = None, message_id: Optional[str] = None,
                attachments: Sequence[dict] = (), embedded: Optional[dict] = None) -> Dict[str, bytes]:
    """Flujos de un mensaje de Outlook (el raíz, o uno incrustado con ``prefix``).

    ``attachments`` son dicts con ``filename``, ``data`` y, opcionales,
    ``mime`` y ``content_id``. ``embedded`` son los argumentos de otro mensaje,
    que se añade como adjunto incrustado (el «reenviar como adjunto» de Outlook).
    """
    streams = {prefix + "__properties_version1.0": _properties(header_size, submitted, 65001 if html else None),
               prefix + "__substg1.0_001A001F": _utf16("IPM.Note")}

    def put(property_id: str, value: Optional[str]) -> None:
        if value is not None:
            streams[f"{prefix}__substg1.0_{property_id}001F"] = _utf16(value)

    put("0037", subject)
    put("0C1A", sender_name)
    put("5D01", sender_email)
    put("007D", transport_headers)
    put("1000", body)
    put("1035", message_id)
    if html is not None:
        streams[prefix + "__substg1.0_10130102"] = html.encode("utf-8")
    if rtf is not None:
        streams[prefix + "__substg1.0_10090102"] = compress_rtf(rtf)
    for index, attachment in enumerate(attachments):
        storage = f"{prefix}__attach_version1.0_#{index:08X}/"
        streams[storage + "__properties_version1.0"] = b"\x00" * 8
        streams[storage + "__substg1.0_3707001F"] = _utf16(attachment["filename"])
        streams[storage + "__substg1.0_37010102"] = attachment["data"]
        if attachment.get("mime"):
            streams[storage + "__substg1.0_370E001F"] = _utf16(attachment["mime"])
        if attachment.get("content_id"):
            streams[storage + "__substg1.0_3712001F"] = _utf16(attachment["content_id"])
    if embedded is not None:
        storage = f"{prefix}__attach_version1.0_#{len(attachments):08X}/"
        streams[storage + "__properties_version1.0"] = b"\x00" * 8
        streams[storage + "__substg1.0_3707001F"] = _utf16(embedded.get("subject") or "reenviado")
        streams.update(msg_streams(prefix=storage + "__substg1.0_3701000D/", header_size=24, **embedded))
    return streams


def build_msg(**fields) -> bytes:
    """Un ``.msg`` completo; los argumentos son los de ``msg_streams``."""
    return build_cfb(msg_streams(**fields))
