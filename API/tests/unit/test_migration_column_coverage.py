"""Que ninguna columna del modelo se quede sin migración.

El esquema se construye de dos formas distintas y nadie las compara: los tests
lo crean con ``Base.metadata.create_all`` (conftest.py) y el despliegue con
``alembic upgrade head`` (run.py). Una columna declarada en el modelo y
olvidada en la migración pasa la suite entera y revienta en producción con
UndefinedColumn la primera vez que alguien lee esa tabla — que es justo lo que
pasó con ``AegisOrgProfile.brand_color``.

El test es textual a propósito: ejecutar la cadena de migraciones aquí exigiría
un Postgres (hay JSONB, índices parciales y ARRAY por medio), y lo que se
quiere cazar no es un fallo de SQL sino un descuido — el nombre de la columna
no aparece en ninguna migración. Por eso solo busca el nombre, y por eso puede
dar por buena una columna cuyo nombre coincida con el de otra tabla.
"""

from pathlib import Path

import pytest

from src.modules.shared import Base

# Los modelos tienen que estar importados para que estén en el metadata; el
# paquete de cada módulo los arrastra.
import src.modules.features.aegis.model  # noqa: F401  pylint: disable=unused-import
import src.modules.features.hygeia.model  # noqa: F401  pylint: disable=unused-import
import src.modules.features.iris.model  # noqa: F401  pylint: disable=unused-import
import src.modules.features.themis.model  # noqa: F401  pylint: disable=unused-import
import src.modules.accounts.model  # noqa: F401  pylint: disable=unused-import
import src.modules.users.model  # noqa: F401  pylint: disable=unused-import

pytestmark = pytest.mark.unit


VERSIONS_DIR = Path(__file__).resolve().parents[2] / "alembic" / "versions"


def _migration_sources() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in VERSIONS_DIR.glob("*.py")
    )


def test_every_model_column_appears_in_some_migration():
    sources = _migration_sources()
    missing = {
        f"{table.name}.{column.name}"
        for table in Base.metadata.sorted_tables
        for column in table.columns
        if f'"{column.name}"' not in sources and f"'{column.name}'" not in sources
    }
    assert not missing, (
        "Estas columnas están en el modelo y no las crea ninguna migración, así "
        "que la suite pasa (crea el esquema con create_all) y el despliegue "
        f"revienta con UndefinedColumn: {sorted(missing)}."
    )
