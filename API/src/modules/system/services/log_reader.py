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

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import src.modules.system.config_reading as CR
from ..exceptions import LogNotFoundError, LogQueryError, LogSnapshotChangedError


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

# Orden de severidad de los niveles de logging. Es lo que permite pedir
# "WARNING y por encima" en una sola consulta en vez de una consulta por nivel.
_LEVEL_SEVERITY = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}
_SNAPSHOT_PREFIX_BYTES = 64 * 1024
_SNAPSHOT_TOKEN_MAX_LENGTH = 512

# El log lo escriben dos procesos (la API y el worker), así que su orden
# cronológico no es perfecto. Medido sobre un log real de 190 000 líneas: 10
# inversiones, y la peor de 18 ms. Un segundo de holgura al bisecar cubre ese
# desorden con varios órdenes de magnitud de margen.
_MONOTONIC_SLACK = timedelta(seconds=1)

# Por debajo de este tamaño, leer el fichero entero cuesta menos que bisecarlo.
_BISECTION_MIN_BYTES = 256 * 1024

# Líneas que se aceptan sin marca de tiempo antes de darse por vencido en un
# sondeo de la bisección. Un traceback de Python es la razón de que haga falta
# más de una: solo su primera línea lleva prefijo.
_PROBE_MAX_LINES = 200

# Tope del búfer que permite resolver el modo `tail` en una sola pasada. Por
# encima —páginas muy profundas— se vuelve a las dos pasadas, que son más
# lentas pero no retienen nada.
_TAIL_BUFFER_MAX_LINES = 5000

_LINE_COUNT_CHUNK_BYTES = 1024 * 1024

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
    """Filtros de una consulta, separados en dos grupos a propósito.

    ``start``/``end``/``contains`` delimitan la **ventana**: el conjunto de
    líneas sobre el que se cuenta cuántas hay de cada nivel. ``level`` y
    ``minimum_severity`` filtran *dentro* de esa ventana. Contar antes de
    aplicarlos es lo que hace útiles los contadores: quien está mirando solo
    los errores sigue viendo cuántos avisos hay al lado, y sabe si vale la
    pena ampliar la consulta.
    """

    start: datetime | None
    end: datetime | None
    contains: str | None
    level: str | None
    minimum_severity: int | None


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

    total_lines, selected, level_counts = _select_page(
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
        # Cuenta por nivel de la ventana (fechas + texto), *antes* de aplicar
        # el filtro de nivel: así el panel puede decir "aquí hay 3 errores"
        # aunque en ese momento se estén mirando solo los avisos.
        "levelCounts": level_counts,
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
    minimum_level = query.get("min_level")

    minimum_severity = None
    if minimum_level:
        minimum_severity = _LEVEL_SEVERITY.get(minimum_level.upper())
        if minimum_severity is None:
            raise LogQueryError("min_level no es un nivel de logging conocido")

    return _LogFilters(
        start=start,
        end=end,
        contains=contains.casefold() if contains else None,
        level=level.upper() if level else None,
        minimum_severity=minimum_severity,
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


def _iter_lines(
    path: Path,
    snapshot_size: int,
    start_offset: int = 0,
    first_line_number: int = 1,
):
    """Recorre el log desde ``start_offset``, que debe caer en inicio de línea.

    ``first_line_number`` es el número absoluto de la línea que empieza en ese
    desplazamiento: quien salta a mitad del fichero tiene que traerlo contado
    aparte para que ``firstLine``/``lastLine`` sigan siendo números de línea
    del fichero y no de la ventana.
    """
    consumed = start_offset
    line_number = first_line_number - 1
    previous_timestamp = None
    previous_level = None

    try:
        with path.open("rb") as handle:
            handle.seek(start_offset)
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


@dataclass(frozen=True)
class _Probe:
    """Primera línea con marca de tiempo encontrada a partir de un sondeo."""

    offset: int
    next_offset: int
    timestamp: datetime


def _iter_window(path: Path, snapshot_size: int, filters: _LogFilters):
    """Recorre solo el tramo del fichero que la ventana temporal puede tocar.

    Filtrar por fecha después de leer no ahorra ni un byte: pedir los últimos
    diez minutos de un log de 21 MB seguía leyendo los 21 MB. Como el log se
    escribe en orden cronológico, el principio de la ventana se encuentra por
    bisección sobre desplazamientos de byte, y el final corta la lectura en
    cuanto se pasa de la fecha pedida.
    """
    start_offset, first_line_number = _window_start(path, snapshot_size, filters.start)
    limit = filters.end + _MONOTONIC_SLACK if filters.end else None

    for line in _iter_lines(path, snapshot_size, start_offset, first_line_number):
        if limit is not None and line.timestamp is not None and line.timestamp > limit:
            return
        yield line


def _window_start(
    path: Path, snapshot_size: int, start: datetime | None
) -> tuple[int, int]:
    """Devuelve el desplazamiento donde empezar a leer y su número de línea."""
    if start is None or snapshot_size <= _BISECTION_MIN_BYTES:
        return 0, 1

    offset = _bisect_offset(path, snapshot_size, start - _MONOTONIC_SLACK)
    if offset <= 0:
        return 0, 1
    return offset, _count_lines_before(path, offset) + 1


def _bisect_offset(path: Path, snapshot_size: int, target: datetime) -> int:
    """Busca el primer inicio de línea cuya marca de tiempo alcanza ``target``."""
    low = 0
    high = snapshot_size
    answer = snapshot_size

    try:
        with path.open("rb") as handle:
            while low < high:
                middle = (low + high) // 2
                probe = _probe_timestamp(handle, middle, snapshot_size)
                if probe is None:
                    # A partir de aquí no queda ninguna línea legible, así que
                    # lo que se busca solo puede estar por detrás.
                    high = middle
                elif probe.timestamp >= target:
                    answer = min(answer, probe.offset)
                    high = middle
                else:
                    low = probe.next_offset
    except OSError as exc:
        raise LogNotFoundError from exc

    # Los dos límites son inicios de línea válidos, y quedarse corto solo
    # cuesta unas líneas de más que el filtro descartará igualmente. Pasarse
    # de largo, en cambio, perdería líneas sin que nada lo delatara: la
    # bisección nunca llega a examinar la línea que empieza justo en `low`.
    return min(low, answer)


def _probe_timestamp(handle, offset: int, snapshot_size: int) -> _Probe | None:
    """Primera línea con marca de tiempo que empieza en ``offset`` o después."""
    handle.seek(offset)
    if offset > 0:
        # El sondeo cae casi siempre a mitad de línea; ese resto no es una
        # línea y su prefijo no se puede leer.
        partial = handle.readline()
        if not partial:
            return None
        offset += len(partial)

    for _ in range(_PROBE_MAX_LINES):
        if offset >= snapshot_size:
            return None
        raw = handle.readline()
        if not raw or offset + len(raw) > snapshot_size:
            return None
        timestamp, _level = _parse_line_prefix(raw.decode("utf-8", errors="replace"))
        if timestamp is not None:
            return _Probe(offset, offset + len(raw), timestamp)
        offset += len(raw)

    return None


def _count_lines_before(path: Path, offset: int) -> int:
    """Cuenta los saltos de línea anteriores a ``offset``.

    Es la parte del prefijo que sí hay que pagar para no perder la numeración
    absoluta, pero se paga barata: contar saltos de línea en crudo sobre el
    log de 21 MB cuesta 37 ms, frente a 1,18 s de la lectura completa con
    decodificación, expresión regular y parseo de fechas.
    """
    remaining = offset
    newlines = 0
    try:
        with path.open("rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(remaining, _LINE_COUNT_CHUNK_BYTES))
                if not chunk:
                    break
                remaining -= len(chunk)
                newlines += chunk.count(b"\n")
    except OSError as exc:
        raise LogNotFoundError from exc
    return newlines


def _parse_line_prefix(text: str) -> tuple[datetime | None, str | None]:
    match = _LOG_LINE_RE.match(text)
    if match is None:
        return None, None
    try:
        timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None, None
    return timestamp, match.group("level")


def _is_in_window(line: _ParsedLine, filters: _LogFilters) -> bool:
    """Comprueba los filtros que delimitan la ventana, sin mirar el nivel."""
    if filters.contains and filters.contains not in line.text.casefold():
        return False
    if filters.start and (line.timestamp is None or line.timestamp < filters.start):
        return False
    if filters.end and (line.timestamp is None or line.timestamp > filters.end):
        return False
    return True


def _has_requested_level(line: _ParsedLine, filters: _LogFilters) -> bool:
    """Comprueba los filtros de nivel: valor exacto y/o severidad mínima."""
    if filters.level and line.level != filters.level:
        return False
    if filters.minimum_severity is not None:
        severity = _LEVEL_SEVERITY.get(line.level or "")
        if severity is None or severity < filters.minimum_severity:
            return False
    return True


def _matches(line: _ParsedLine, filters: _LogFilters) -> bool:
    return _is_in_window(line, filters) and _has_requested_level(line, filters)


def _empty_level_counts() -> dict[str, int]:
    return {level: 0 for level in _LEVEL_SEVERITY}


def _scan_head(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    start_index: int,
    end_index: int,
) -> tuple[int, list[_ParsedLine], dict[str, int]]:
    total = 0
    selected = []
    level_counts = _empty_level_counts()
    for line in _iter_window(path, snapshot_size, filters):
        if not _is_in_window(line, filters):
            continue
        if line.level in level_counts:
            level_counts[line.level] += 1
        if not _has_requested_level(line, filters):
            continue
        if start_index <= total < end_index:
            selected.append(line)
        total += 1
    return total, selected, level_counts


def _select_page(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    page: int,
    per_page: int,
    position: str,
) -> tuple[int, list[_ParsedLine], dict[str, int]]:
    if position == "head":
        page_start = (page - 1) * per_page
        return _scan_head(path, snapshot_size, filters, page_start, page_start + per_page)

    if page * per_page <= _TAIL_BUFFER_MAX_LINES:
        return _scan_tail(path, snapshot_size, filters, page, per_page)

    # Páginas muy profundas: el búfer de la pasada única sería demasiado
    # grande, así que se vuelve a contar primero y recoger después.
    total_lines, level_counts = _count_matches(path, snapshot_size, filters)
    end_index = total_lines - (page - 1) * per_page
    start_index = max(0, end_index - per_page)
    selected = (
        _collect_range(path, snapshot_size, filters, start_index, end_index)
        if end_index > 0
        else []
    )
    return total_lines, selected, level_counts


def _scan_tail(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    page: int,
    per_page: int,
) -> tuple[int, list[_ParsedLine], dict[str, int]]:
    """Resuelve una página del final del log en una sola pasada.

    Leer desde el final exige saber cuántas coincidencias hay en total, y eso
    obligaba a recorrer el fichero dos veces: una para contarlas y otra para
    recoger la página. Guardando por el camino las últimas ``page × per_page``
    coincidencias —500 líneas para la quinta página de cien— el recuento y la
    página salen del mismo recorrido.
    """
    recent = deque(maxlen=page * per_page)
    total = 0
    level_counts = _empty_level_counts()

    for line in _iter_window(path, snapshot_size, filters):
        if not _is_in_window(line, filters):
            continue
        if line.level in level_counts:
            level_counts[line.level] += 1
        if not _has_requested_level(line, filters):
            continue
        recent.append(line)
        total += 1

    end_index = total - (page - 1) * per_page
    if end_index <= 0:
        return total, [], level_counts

    start_index = max(0, end_index - per_page)
    buffered_from = total - len(recent)
    selected = list(recent)[start_index - buffered_from:end_index - buffered_from]
    return total, selected, level_counts


def _count_matches(
    path: Path, snapshot_size: int, filters: _LogFilters
) -> tuple[int, dict[str, int]]:
    """Cuenta coincidencias y, de paso, cuántas líneas hay de cada nivel."""
    total = 0
    level_counts = _empty_level_counts()
    for line in _iter_window(path, snapshot_size, filters):
        if not _is_in_window(line, filters):
            continue
        if line.level in level_counts:
            level_counts[line.level] += 1
        if _has_requested_level(line, filters):
            total += 1
    return total, level_counts


def _collect_range(
    path: Path,
    snapshot_size: int,
    filters: _LogFilters,
    start_index: int,
    end_index: int,
) -> list[_ParsedLine]:
    selected = []
    index = 0
    for line in _iter_window(path, snapshot_size, filters):
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
