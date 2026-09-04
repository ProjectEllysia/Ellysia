"""La lectura acelerada del log tiene que devolver lo mismo que la lenta.

``log_reader`` gana velocidad saltándose trabajo: en lugar de recorrer el
fichero entero y descartar después las líneas fuera de la ventana temporal,
busca por bisección el byte donde empieza esa ventana y corta la lectura en
cuanto se pasa del final. Cualquier atajo así tiene la misma trampa: si el
salto se pasa de largo, se pierden líneas en silencio y nadie se entera,
porque la respuesta sigue teniendo buena pinta.

Estos tests fijan la invariante que lo impide: **bisecar y no bisecar tienen
que dar exactamente el mismo resultado**. La comparación se hace contra el
mismo lector con la bisección desactivada (subiendo el umbral de tamaño por
encima del fichero de prueba), así que no hay una segunda implementación que
mantener.

Los casos difíciles que se cubren son los dos que rompen la suposición de que
el log está ordenado y de que cada línea lleva su fecha:

- **Inversiones de orden.** Al log le escriben dos procesos, la API y el
  worker, así que una línea puede aparecer unas milésimas antes que otra
  anterior. La bisección lo absorbe con un margen de holgura; aquí se
  introducen inversiones a propósito para comprobarlo.
- **Líneas de continuación.** Un traceback de Python ocupa varias líneas y
  solo la primera lleva el prefijo ``[+] [ERROR] (fecha)``; las demás heredan
  la marca de la anterior. La bisección corta siempre en una línea con
  prefijo, y hay que verificar que eso no deja huérfano el cuerpo de un
  traceback que sí entra en la ventana.
"""

from datetime import datetime, timedelta

import pytest

import src.modules.system.services.log_reader as log_reader

pytestmark = pytest.mark.unit


BASE_TIME = datetime(2026, 9, 1, 12, 0, 0)
LEVELS = ("INFO", "DEBUG", "WARNING", "ERROR", "INFO", "INFO", "CRITICAL")


def _entry(index: int, timestamp: datetime, level: str) -> str:
    """Una entrada del log con el formato exacto que emite la aplicación."""
    stamp = timestamp.strftime("%Y-%m-%d %H:%M:%S,") + f"{timestamp.microsecond // 1000:03d}"
    return f"[+] [{level}] ({stamp}) src.modules.test: entrada numero {index}"


def _build_log(path, entries: int = 4000) -> None:
    """Escribe un log sintético lo bastante grande como para que se bisecte.

    Se pasa del cuarto de mega que exige ``_BISECTION_MIN_BYTES`` y mete a
    propósito los dos casos difíciles: cada cincuenta líneas, una inversión de
    quince milisegundos hacia atrás; cada ciento treinta, un traceback de tres
    líneas sin prefijo.
    """
    lines = []
    for index in range(entries):
        timestamp = BASE_TIME + timedelta(seconds=index)
        if index % 50 == 49:
            timestamp -= timedelta(milliseconds=15)
        lines.append(_entry(index, timestamp, LEVELS[index % len(LEVELS)]))
        if index % 130 == 129:
            lines.append("Traceback (most recent call last):")
            lines.append('  File "algun/sitio.py", line 12, in funcion')
            lines.append("ValueError: continuacion sin prefijo")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    path = log_dir / "secops.log"
    _build_log(path)
    monkeypatch.setattr(log_reader, "_log_path", lambda: path)
    return path


@pytest.fixture
def without_bisection(monkeypatch):
    """Desactiva el atajo subiendo su umbral por encima del fichero de prueba."""
    monkeypatch.setattr(log_reader, "_BISECTION_MIN_BYTES", 1 << 30)


def _read(**query) -> dict:
    return log_reader.read_logs({"per_page": 100, **query})


def _readable(payload: dict) -> str:
    import base64
    import gzip

    return gzip.decompress(base64.b64decode(payload["content"])).decode("utf-8")


def _comparable(payload: dict) -> dict:
    """Lo que tiene que coincidir entre las dos lecturas.

    Se deja fuera el snapshot, que depende del inodo del fichero temporal, y
    el huso horario, que depende de la máquina.
    """
    return {
        "content": _readable(payload),
        "totalLines": payload["totalLines"],
        "returnedLines": payload["returnedLines"],
        "totalPages": payload["totalPages"],
        "firstLine": payload["firstLine"],
        "lastLine": payload["lastLine"],
        "levelCounts": payload["levelCounts"],
    }


QUERIES = [
    pytest.param({"position": "tail"}, id="cola-sin-filtros"),
    pytest.param(
        {"position": "tail", "from_": BASE_TIME + timedelta(minutes=55)},
        id="cola-ultimos-minutos",
    ),
    pytest.param(
        {"position": "head", "from_": BASE_TIME + timedelta(minutes=30)},
        id="cabeza-desde-la-mitad",
    ),
    pytest.param(
        {
            "position": "head",
            "from_": BASE_TIME + timedelta(minutes=20),
            "to": BASE_TIME + timedelta(minutes=25),
        },
        id="ventana-cerrada",
    ),
    pytest.param(
        {
            "position": "tail",
            "from_": BASE_TIME + timedelta(minutes=10),
            "to": BASE_TIME + timedelta(minutes=40),
            "min_level": "WARNING",
        },
        id="ventana-cerrada-solo-avisos",
    ),
    pytest.param(
        {"position": "tail", "from_": BASE_TIME + timedelta(minutes=15), "page": 3},
        id="tercera-pagina-de-la-cola",
    ),
    pytest.param(
        {"position": "tail", "from_": BASE_TIME - timedelta(days=1)},
        id="ventana-anterior-al-log",
    ),
    pytest.param(
        {"position": "tail", "from_": BASE_TIME + timedelta(days=1)},
        id="ventana-posterior-al-log",
    ),
    pytest.param(
        {"position": "head", "from_": BASE_TIME + timedelta(minutes=5), "contains": "numero 3"},
        id="ventana-con-busqueda-de-texto",
    ),
]


@pytest.mark.parametrize("query", QUERIES)
def test_the_bisected_read_matches_the_full_scan(log_file, monkeypatch, query):
    fast = _comparable(_read(**query))

    monkeypatch.setattr(log_reader, "_BISECTION_MIN_BYTES", 1 << 30)
    slow = _comparable(_read(**query))

    assert fast == slow


def test_line_numbers_stay_absolute_after_a_jump(log_file):
    """Saltar a mitad del fichero no puede renumerar las líneas.

    ``firstLine``/``lastLine`` son números de línea del fichero, y el panel los
    enseña tal cual. Si la bisección los contara desde el punto de salto, la
    misma línea tendría un número distinto según qué ventana se pidiera.
    """
    payload = _read(position="head", from_=BASE_TIME + timedelta(minutes=30))
    first_visible = _readable(payload).splitlines()[0]

    every_line = log_file.read_text(encoding="utf-8").splitlines()
    assert every_line[payload["firstLine"] - 1] == first_visible


def test_a_traceback_inside_the_window_keeps_its_body(log_file):
    """El cuerpo de un traceback viaja con su cabecera, también tras un salto.

    Las líneas de continuación no llevan fecha: heredan la de la línea con
    prefijo anterior. Si la bisección cortara entre la cabecera y el cuerpo,
    el error aparecería en el panel sin la pila que explica dónde ocurrió.
    """
    payload = _read(position="head", per_page=500, from_=BASE_TIME + timedelta(minutes=1))
    lines = _readable(payload).splitlines()

    header_positions = [
        index for index, line in enumerate(lines)
        if line.startswith("Traceback (most recent call last):")
    ]
    assert header_positions, "el tramo elegido debería contener algún traceback"
    for position in header_positions:
        assert lines[position + 2] == "ValueError: continuacion sin prefijo"


def test_the_deep_page_fallback_agrees_with_the_single_pass(log_file, monkeypatch):
    """Las páginas profundas usan otro camino, y tiene que dar lo mismo.

    Por debajo del tope de búfer, la cola se resuelve en una sola pasada
    guardando las últimas coincidencias; por encima, se vuelve a las dos
    pasadas de contar y recoger. Son dos implementaciones del mismo resultado.
    """
    query = {"position": "tail", "page": 4, "per_page": 50}
    single_pass = _comparable(_read(**query))

    monkeypatch.setattr(log_reader, "_TAIL_BUFFER_MAX_LINES", 10)
    two_passes = _comparable(_read(**query))

    assert single_pass == two_passes
