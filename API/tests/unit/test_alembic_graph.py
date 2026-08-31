"""El grafo de migraciones, comprobado en la suite rápida.

Este fichero existe por un incidente concreto. Dos ramas de proyecto avanzaron
a la vez, cada una añadió migraciones colgando de la misma punta, y al juntarlas
el árbol quedó con **dos cabezas**. `run.py` ejecuta `alembic upgrade head` en
cada arranque, y con dos cabezas Alembic se niega a elegir: la API no arranca.

Nada lo detectaba antes de ese momento. Los tests que ejecutan Alembic de
verdad viven en ``tests/postgres/`` y se saltan sin un PostgreSQL conectado, así
que el fallo aparecía al desplegar y no al abrir el pull request.

Estas comprobaciones no necesitan motor ni aplicación: leen los ficheros de
``alembic/versions`` y miran la forma del grafo. Van aquí, en los unitarios,
porque cuestan milisegundos y porque el momento útil para enterarse es cuando
se juntan dos ramas, no cuando arranca el servidor.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.unit


def _api_dir() -> str:
    """Ruta de API/: este fichero vive en API/tests/unit/."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _script_directory():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    api_dir = _api_dir()
    config = Config(os.path.join(api_dir, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(api_dir, "alembic"))
    return ScriptDirectory.from_config(config)


def test_there_is_exactly_one_head():
    """Dos cabezas = la API no arranca.

    Es el fallo que motiva el fichero, y su síntoma no se parece a su causa:
    `alembic upgrade head` lanza `CommandError` durante `create_app()`, así que
    lo que se ve es un servidor que no levanta, no una migración mal puesta.

    Cuando esto falle, la corrección es reencadenar la migración **que aún no
    se haya integrado** —cambiar su `down_revision` a la punta actual— y no
    inventar una revisión de mezcla, salvo que las dos líneas ya estén
    aplicadas en alguna base de datos viva.
    """
    heads = _script_directory().get_heads()

    assert len(heads) == 1, (
        f"El árbol de migraciones tiene {len(heads)} cabezas: {heads}. "
        "`run.py` ejecuta `alembic upgrade head` al arrancar y con más de una "
        "no puede elegir, así que la API no levantará. Reencadena la migración "
        "que todavía no se haya integrado sobre la punta actual."
    )


def test_no_revision_identifier_is_repeated():
    """Los identificadores de este repositorio se han venido escribiendo a mano
    siguiendo un patrón (``a1b2c3d4e5f6``, ``d7e8f9a0b1c2``…), que es justo el
    modo de acabar con dos revisiones con el mismo identificador — ha pasado.

    Alembic no avisa: al cargar el directorio, la segunda revisión con un id ya
    visto sustituye a la primera, y esa primera deja de existir para el grafo.
    """
    identifiers = [revision.revision for revision in _script_directory().walk_revisions()]
    duplicates = {identifier for identifier in identifiers
                  if identifiers.count(identifier) > 1}

    assert not duplicates, (
        f"Identificadores de revisión repetidos: {sorted(duplicates)}. "
        "Genera uno aleatorio y comprueba que no esté ya en alembic/versions."
    )


def test_every_down_revision_points_at_a_revision_that_exists():
    """Una referencia rota parte el grafo en dos: las revisiones por debajo del
    hueco dejan de ser alcanzables, y Alembic falla al resolver la cadena."""
    script = _script_directory()
    known = {revision.revision for revision in script.walk_revisions()}

    dangling = []
    for revision in script.walk_revisions():
        parents = revision.down_revision
        if parents is None:
            continue
        if isinstance(parents, str):
            parents = (parents,)
        for parent in parents:
            if parent not in known:
                dangling.append((revision.revision, parent))

    assert not dangling, (
        "Hay `down_revision` que apuntan a revisiones inexistentes: "
        + ", ".join(f"{child} -> {parent}" for child, parent in dangling)
    )


def test_every_migration_file_is_named_after_its_revision():
    """El nombre del fichero empieza por su `revision`, que es la convención de
    Alembic y lo que permite localizar una revisión sin abrir los 50 ficheros.

    Un fichero renombrado a mano sigue funcionando —Alembic lee el contenido,
    no el nombre— pero deja el directorio ilegible.
    """
    versions = os.path.join(_api_dir(), "alembic", "versions")

    mismatched = []
    for revision in _script_directory().walk_revisions():
        filename = os.path.basename(revision.path)
        if not filename.startswith(revision.revision):
            mismatched.append(filename)

    assert not mismatched, (
        f"Ficheros cuyo nombre no empieza por su revision: {sorted(mismatched)} "
        f"(en {versions})"
    )
