"""Invariantes estructurales del motor Lybra.

Son dos, y protegen cosas distintas: que la capa pura ``themis/lybra/`` no
toque el ORM, y que la capa con efectos ``themis/managers/lybra/`` no dependa
de ningún otro escáner.

El propio docstring del paquete lo declara: "Everything here is deliberately
free of the ORM and of network side effects where it can be". Es la única
invariante arquitectónica real del paquete mejor construido del repositorio,
y hasta ahora nada la comprobaba — se sostenía porque nadie la había roto
todavía, no porque algo la protegiera. Este test la congela: si algún día
alguien mueve un fichero con acceso a BD dentro de ``lybra/`` (el error que
D1 evitó al no mover ``lybra_sources.py`` ahí), cae en CI en vez de en code
review.
"""

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_LYBRA_PACKAGE = (
    Path(__file__).resolve().parents[2]
    / "src" / "modules" / "features" / "themis" / "lybra"
)

# Nombres cuya sola presencia en el texto del fichero indica que algo tocó el
# ORM o abrió una transacción — no se buscan imports concretos porque el
# propio docstring del paquete ya explica que las excepciones (los "pocos
# fragmentos que sí deben tocar la red", los probes/fetchers) reciben
# callables inyectables en vez de importar el cliente ellos mismos.
_FORBIDDEN_SUBSTRINGS = (
    "sqlalchemy",
    "UnitOfWork",
    "from ...repositories",
    "from ..repositories",
    "from src.modules.infrastructure",
)


def test_lybra_package_stays_orm_free():
    offenders = []
    for path in _LYBRA_PACKAGE.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for needle in _FORBIDDEN_SUBSTRINGS:
            if needle in source:
                offenders.append(f"{path.relative_to(_LYBRA_PACKAGE)}: contiene '{needle}'")

    assert not offenders, (
        "themis/lybra/ debe quedarse libre de ORM (ver su __init__.py) — "
        "el código con acceso a BD va en themis/managers/:\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------- sin
# dependencia de otros escáneres

_LYBRA_MANAGERS = (
    Path(__file__).resolve().parents[2]
    / "src" / "modules" / "features" / "themis" / "managers" / "lybra"
)

# Los managers de los otros tres escáneres de Themis. Que Themis orqueste
# varios escáneres es sano: es su trabajo. Que **el motor** dependa de sus
# hermanos no lo es — y es exactamente lo que pasaba: el módulo más nuevo
# importaba los tres más viejos para lanzarlos como "corroboradores" de sus
# propios hallazgos.
_SIBLING_SCANNER_MANAGERS = (
    "NmapScanManager",
    "NiktoScanManager",
    "NucleiScanManager",
)


def test_lybra_manager_does_not_depend_on_other_scanners():
    """Un escaneo de Lybra no lanza ningún otro escaneo.

    Esta es la parte del arreglo que sobrevive al tiempo. Retirar el código fue
    lo fácil; lo que impide que vuelva a entrar dentro de seis meses —que es
    justo como entró la primera vez, un import cada vez— es que el import
    falle en CI en lugar de pasar por una revisión distraída.
    """
    offenders = []
    for path in _LYBRA_MANAGERS.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for manager in _SIBLING_SCANNER_MANAGERS:
            for line in source.splitlines():
                stripped = line.strip()
                if manager in stripped and (stripped.startswith("import ")
                                            or stripped.startswith("from ")):
                    offenders.append(f"{path.relative_to(_LYBRA_MANAGERS)}: importa {manager}")

    assert not offenders, (
        "themis/managers/lybra/ no debe importar el manager de otro escáner: "
        "Lybra es un motor independiente, no un orquestador de herramientas "
        "ajenas.\n" + "\n".join(offenders)
    )


# --------------------------------------------------- una sola verdad
# sobre la exposición de un objetivo


def test_nobody_reimplements_the_private_address_check():
    """«Este objetivo es privado o público» se decide en un solo sitio.

    Estuvo escrita dos veces —``lybra.correlation`` y
    ``analyzers._classify_network_context``— por una razón buena: la capa pura
    no puede importar el módulo del escritor de IA. La consecuencia era mala:
    una regla que acota la prioridad de todo hallazgo en red privada **y**
    entra en el prompt del informe, con dos implementaciones que podían
    divergir sin que nada fallara.

    Este test busca la firma de una tercera copia: la comprobación de
    ``ipaddress`` sobre las tres propiedades a la vez. Que ``shared/_exposure``
    quede fuera es justamente el punto — es el sitio donde debe estar.
    """
    themis = Path(__file__).resolve().parents[2] / "src" / "modules" / "features" / "themis"
    offenders = []
    for path in themis.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if "is_private" in source and "is_link_local" in source:
            offenders.append(str(path.relative_to(themis)))

    assert not offenders, (
        "la clasificación de exposición vive en shared/_exposure.py; "
        "reimplementarla deja dos verdades que pueden divergir en silencio: "
        + ", ".join(offenders)
    )
