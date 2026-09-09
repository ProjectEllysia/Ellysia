"""Tests de los imports diferidos del arranque de ``run.py``.

Existen por un modo de fallo concreto y silencioso, y el bug que los motiva
ya había llegado a producción: ``_configure_scheduling()`` hace sus imports
**dentro** del cuerpo de la función (para no pagarlos al importar el módulo)
y cada bloque de reconciliación va envuelto en un ``try/except Exception``
que degrada el fallo a un ``logger.warning``.

Esas dos decisiones, cada una razonable por su lado, se combinan mal: un
``ImportError`` -- un símbolo que se movió de fichero, un módulo que se
renombró -- no rompe el arranque ni falla ningún test. Simplemente hace que
esa reconciliación **no se ejecute nunca**, y lo único que queda es una línea
de warning en el log de arranque que nadie mira. Fue exactamente lo que le
pasó a ``OutboxDispatcher``: vivía en ``taskqueue/dispatcher.py``, ``run.py``
lo importaba de ``taskqueue/outbox.py``, y la reconciliación de la outbox al
arrancar (una de las dos redes de seguridad que diseñó B08) llevaba muerta
desde que se escribió.

El test no comprueba un símbolo concreto: extrae del propio código fuente de
``run.py`` todos los imports diferidos y verifica que cada uno resuelve de
verdad. Así cubre también los que se añadan después, sin que nadie tenga que
acordarse de venir aquí.
"""

import ast
import importlib
from pathlib import Path
from typing import List, Tuple

import pytest

RUN_PY = Path(__file__).resolve().parents[2] / "run.py"


def _deferred_imports() -> List[Tuple[str, str, int]]:
    """Extrae los ``from X import Y`` que viven dentro de una función en ``run.py``.

    Un import a nivel de módulo lo verifica ya el propio arranque de la suite
    (si no resolviera, importar ``run`` fallaría en voz alta). Los que
    interesan son los diferidos: solo se ejecutan cuando se llama a la
    función que los contiene, que en el arranque es justo el sitio donde un
    ``try/except`` puede tragárselos.

    Returns:
        List[Tuple[str, str, int]]: Tuplas ``(modulo, simbolo, linea)``, una
            por cada nombre importado. Vacía si ``run.py`` dejara de tener
            imports diferidos.
    """
    tree = ast.parse(RUN_PY.read_text(encoding="utf-8"))
    found: List[Tuple[str, str, int]] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(function):
            # ``level > 0`` es un import relativo; ``run.py`` está fuera del
            # paquete, así que no los usa y no hay que resolverlos aquí.
            if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    found.append((node.module, alias.name, node.lineno))
    return found


@pytest.mark.unit
class TestStartupDeferredImports:
    """Cada import diferido de ``run.py`` debe resolver."""

    def test_there_are_deferred_imports_to_check(self):
        """Guarda del propio test: si la extracción dejara de encontrar nada,
        el test de abajo pasaría en verde sin comprobar absolutamente nada."""
        assert _deferred_imports(), (
            "No se encontró ningún import diferido en run.py. O han "
            "desaparecido todos, o _deferred_imports() ha dejado de "
            "reconocerlos -- en el segundo caso este fichero ya no protege nada."
        )

    @pytest.mark.parametrize(
        "module_path,symbol,line",
        _deferred_imports(),
        ids=lambda value: str(value),
    )
    def test_deferred_import_resolves(self, module_path: str, symbol: str, line: int):
        """El módulo se importa y expone el símbolo que ``run.py`` le pide."""
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            pytest.fail(
                f"run.py:{line} importa '{module_path}', que no se puede "
                f"importar: {e}. En el arranque esto quedaría tragado por un "
                f"try/except y esa reconciliación no se ejecutaría nunca."
            )

        assert hasattr(module, symbol), (
            f"run.py:{line} importa '{symbol}' de '{module_path}', pero ese "
            f"módulo no lo define. En el arranque el ImportError quedaría "
            f"tragado por un try/except y esa reconciliación no se "
            f"ejecutaría nunca -- exactamente el bug de OutboxDispatcher."
        )
