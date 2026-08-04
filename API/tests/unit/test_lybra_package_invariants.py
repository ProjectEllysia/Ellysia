"""Invariantes estructurales de ``themis/lybra/`` (D1 en
plans/deuda-tecnica-y-calidad.md).

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
