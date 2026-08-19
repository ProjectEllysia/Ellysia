"""Lectura paginada y segura del fichero de log de la aplicación.

El log es un fichero vivo: la auditoría de peticiones puede añadir líneas
mientras el administrador navega por sus páginas. Por eso cada consulta se
ancla al tamaño que tenía el fichero en la primera petición y las peticiones
posteriores leen siempre ese mismo prefijo.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import re

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import src.modules.system.config_reading as CR
from ..exceptions import LogNotFoundError, LogQueryError, LogSnapshotChangedError


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
_SNAPSHOT_PREFIX_BYTES = 64 * 1024
_SNAPSHOT_TOKEN_MAX_LENGTH = 512

_LOG_LINE_RE = re.compile(
    r"^\[\+\]\s+\[(?P<level>[A-Z]+)\]\s+"
    r"\((?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\)"
)
_SNAPSHOT_TOKEN_RE = re.compile(
    r"^(?P<device>\d+):(?P<inode>\d+):(?P<size>\d+):(?P<prefix>[0-9a-f]{64})$"
)


@dataclass(frozen=True)
class _Snapshot:
    token: str
    size: int
    current_size: int
    modified_at: str


@dataclass(frozen=True)
class _LogFilters:
    start: datetime | None
    end: datetime | None
    level: str | None
    contains: str | None


@dataclass(frozen=True)
class _ParsedLine:
    number: int
    text: str
    timestamp: datetime | None
    level: str | None


def read_logs(query: dict) -> dict:
    """Lee una página del log y devuelve el contrato listo para JSON.

    ``position=head`` ordena las páginas desde las líneas más antiguas y
    ``position=tail`` desde las más recientes. El contenido de la página se
    comprime antes de codificarse en base64 para que viaje como texto seguro
    dentro de la respuesta JSON.
    """
    page = query.get("page", 1)
    per_page = query.get("per_page", DEFAULT_PAGE_SIZE)
    position = query.get("position", "tail")

    if not 1 <= page:
        raise LogQueryError("page debe ser un entero positivo")
    if not 1 <= per_page <= MAX_PAGE_SIZE:
        raise LogQueryError(f"per_page debe estar entre 1 y {MAX_PAGE_SIZE}")
    if position not in {"head", "tail"}:
        raise LogQueryError("position debe ser 'head' o 'tail'")

    filters = _build_filters(query)
    log_path = _log_path()
    snapshot = _resolve_snapshot(log_path, query.get("snapshot"))

    total_lines, selected = _select_page(
        log_path, snapshot.size, filters, page, per_page, position
    )

    total_pages = (total_lines + per_page - 1) // per_page if total_lines else 0
    content = "\n".join(line.text for line in selected)
    content_bytes = content.encode("utf-8")
    compressed = gzip.compress(content_bytes, compresslevel=9, mtime=0)

    return {
        "compression": "gzip",
        "encoding": "base64",
        "content": base64.b64encode(compressed).decode("ascii"),
        "totalBytes": snapshot.size,
        "returnedBytes": len(content_bytes),
        "compressedBytes": len(compressed),
        # La respuesta representa una página, no necesariamente todas las
        # coincidencias del snapshot. El tamaño comprimido no sirve para saber
        # si hubo truncado porque gzip cambia la relación entre ambos tamaños.
        "truncated": total_lines > len(selected),
        "totalLines": total_lines,
        "returnedLines": len(selected),
        "page": page,
        "perPage": per_page,
        "totalPages": total_pages,
        "position": position,
        "hasPrevious": page > 1 and total_pages > 0,
        "hasNext": page < total_pages,
        "snapshot": snapshot.token,
        "snapshotBytes": snapshot.size,
        "currentBytes": snapshot.current_size,
        "lastModified": snapshot.modified_at,
        "timeZone": _local_timezone_name(),
        "firstLine": selected[0].number if selected else None,
        "lastLine": selected[-1].number if selected else None,
    }


def _build_filters(query: dict) -> _LogFilters:
    start = _normalise_datetime(query.get("from_"))
    end = _normalise_datetime(query.get("to"))
    if start is not None and end is not None and start > end:
        raise LogQueryError("from no puede ser posterior a to")

    level = query.get("level")
    contains = query.get("contains")
    return _LogFilters(
        start=start,
        end=end,
        level=level.upper() if level else None,
        contains=contains.casefold() if contains else None,
    )


def _normalise_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone().replace(tzinfo=None)
    return value


def _log_path() -> Path:
    log_dir = Path(CR.get_directory_of(CR.DirectoryType.LOG)).resolve()
    return log_dir / "secops.log"


def _resolve_snapshot(path: Path, token: str | None) -> _Snapshot:
    current = _stat_log(path)
    if not token:
        size = current.st_size
        return _make_snapshot(path, current, size)

    if len(token) > _SNAPSHOT_TOKEN_MAX_LENGTH:
        raise LogSnapshotChangedError("El snapshot del log no es válido")

    match = _SNAPSHOT_TOKEN_RE.match(_decode_snapshot_token(token))
    if match is None:
        raise LogSnapshotChangedError("El snapshot del log no es válido")

    expected_device = int(match.group("device"))
    expected_inode = int(match.group("inode"))
    size = int(match.group("size"))
    expected_prefix = match.group("prefix")

    if (
        current.st_dev != expected_device
        or current.st_ino != expected_inode
        or current.st_size < size
        or _prefix_digest(path, size) != expected_prefix
    ):
        raise LogSnapshotChangedError("El fichero de log cambió durante la consulta")

    return _make_snapshot(path, current, size)


def _stat_log(path: Path):
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise LogNotFoundError from exc
    if not path.is_file():
        raise LogNotFoundError
    return stat


def _make_snapshot(path: Path, stat, size: int) -> _Snapshot:
    raw = f"{stat.st_dev}:{stat.st_ino}:{size}:{_prefix_digest(path, size)}"
    token = base64.urlsafe_b64encode(raw.encode("ascii")).decode("ascii").rstrip("=")
    return _Snapshot(
        token=token,
        size=size,
        current_size=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    )


def _decode_snapshot_token(token: str) -> str:
    try:
        padding = "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(token + padding).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""


def _prefix_digest(path: Path, size: int) -> str:
    with path.open("rb") as handle:
        return hashlib.sha256(handle.read(min(size, _SNAPSHOT_PREFIX_BYTES))).hexdigest()


def _iter_lines(path: Path, snapshot_size: int):
    consumed = 0
    line_number = 0
    previous_timestamp = None
    previous_level = None

    try:
        with path.open("rb") as handle:
            while consumed < snapshot_size:
                raw = handle.readline()
                if not raw:
                    break

                remaining = snapshot_size - consumed
                if len(raw) > remaining:
                    # El snapshot termina en mitad de una línea que se estaba
                    # escribiendo. No se entrega una línea parcial.
                    break
                consumed += len(raw)
                line_number += 1

                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                timestamp, level = _parse_line_prefix(text)
                if timestamp is None:
                    timestamp = previous_timestamp
                if level is None:
                    level = previous_level
                if timestamp is not None:
                    previous_timestamp = timestamp
                if level is not None:
                    previous_level = level

                yield _ParsedLine(line_number, text, timestamp, level)
    except OSError as exc:
        raise LogNotFoundError from exc


def _parse_line_prefix(text: str) -> tuple[datetime | None, str | None]:
    match = _LOG_LINE_RE.match(text)
    if match is None:
        return None, None
    try:
        timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None, None
    return timestamp, match.group("level")


def _matches(line: _ParsedLine, filters: _LogFilters) -> bool:
    if filters.level and line.level != filters.level:
        return False
    if filters.contains and filters.contains not in line.text.casefold():
        return False
    if filters.start and (line.timestamp is None or line.timestamp < filters.start):
        return False
    if filters.end and (line.timestamp is None or line.timestamp > filters.end):
        return False
    return True


def _scan_head(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    start_index: int,
    end_index: int,
) -> tuple[int, list[_ParsedLine]]:
    total = 0
    selected = []
    for line in _iter_lines(path, snapshot_size):
        if not _matches(line, filters):
            continue
        if start_index <= total < end_index:
            selected.append(line)
        total += 1
    return total, selected


def _select_page(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    page: int,
    per_page: int,
    position: str,
) -> tuple[int, list[_ParsedLine]]:
    if position == "head":
        page_start = (page - 1) * per_page
        return _scan_head(path, snapshot_size, filters, page_start, page_start + per_page)

    total_lines = _count_matches(path, snapshot_size, filters)
    end_index = total_lines - (page - 1) * per_page
    start_index = max(0, end_index - per_page)
    selected = (
        _collect_range(path, snapshot_size, filters, start_index, end_index)
        if end_index > 0
        else []
    )
    return total_lines, selected


def _count_matches(path: Path, snapshot_size: int, filters: _LogFilters) -> int:
    return sum(1 for line in _iter_lines(path, snapshot_size) if _matches(line, filters))


def _collect_range(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    start_index: int,
    end_index: int,
) -> list[_ParsedLine]:
    selected = []
    index = 0
    for line in _iter_lines(path, snapshot_size):
        if not _matches(line, filters):
            continue
        if start_index <= index < end_index:
            selected.append(line)
        index += 1
        if index >= end_index:
            break
    return selected


def _local_timezone_name() -> str:
    return datetime.now().astimezone().tzname() or "local"
