"""Los módulos de mecanismo se importan sin arrastrar el dominio.

``config_reading``, la TaskQueue, ``shared`` e ``infrastructure`` los importa casi
todo el proyecto, y muy pronto. Si cargar cualquiera de ellos arrastra ``users``,
``accounts`` o una feature, basta con que ese módulo de dominio vuelva a importar el
mecanismo para cerrar un ciclo de imports. Y ese ciclo puede quedar escondido
durante meses, porque solo explota con un orden de carga concreto.

Leyendo un fichero suelto el ciclo no se ve, así que el test importa cada módulo en
un **proceso limpio** —dentro de pytest, la suite ya ha cargado todo— y mira qué ha
quedado en ``sys.modules``.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_API_ROOT = Path(__file__).resolve().parents[2]

#: Prefijos de los módulos de dominio (rango 2 y 3 en CONVENCIONES.md § 3.4).
_DOMAIN_PREFIXES = ("src.modules.users", "src.modules.accounts", "src.modules.features")

_PROBE = """
import importlib, json, sys
importlib.import_module(sys.argv[1])
print(json.dumps(sorted(sys.modules)))
"""


@pytest.mark.parametrize("module_name", [
    "src.modules.system.config_reading",
    "src.modules.system.taskqueue",
    "src.modules.shared",
    "src.modules.infrastructure",
])
def test_mechanism_module_imports_without_domain(module_name):
    """Importar un módulo de mecanismo en un proceso limpio no carga ningún módulo de dominio."""
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, module_name],
        cwd=_API_ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, f"importar {module_name} falla en un proceso limpio:\n{result.stderr}"

    loaded_modules = json.loads(result.stdout.strip().splitlines()[-1])
    domain_modules = [name for name in loaded_modules if name.startswith(_DOMAIN_PREFIXES)]
    assert not domain_modules, (
        f"importar {module_name} arrastra módulos de dominio (CONVENCIONES.md § 3.4): "
        f"{domain_modules[:10]}"
    )
