"""B20: las migraciones, ejecutadas de verdad.

Alembic solo se ejerce contra PostgreSQL, y la suite rápida crea el esquema
con ``Base.metadata.create_all``, que salta por encima de todas las
migraciones. Es decir que hasta ahora **ninguna migración se ejecutaba en
ningún test**: un ``down_revision`` mal puesto, un identificador repetido, un
tipo que PostgreSQL no acepta o una bajada rota solo se descubrían al
desplegar.

Este módulo cierra ese hueco aplicando la cadena entera sobre una base de
datos vacía creada para la ocasión — que es exactamente lo que ocurre en un
despliegue nuevo.
"""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

pytestmark = pytest.mark.postgres

_MIGRATIONS_DB = "ellysia_migrations_test"


def _api_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def migrations_url(pg_engine):
    """Crea una base de datos vacía y devuelve su URL; la borra al terminar.

    Se usa una base aparte y no el esquema de ``pg_engine`` porque las
    migraciones tienen que correr sobre algo realmente vacío, y ``pg_engine``
    ya tiene el esquema creado por los modelos para el resto de tests.
    ``CREATE DATABASE`` no puede ir dentro de una transacción, de ahí el
    ``AUTOCOMMIT``.
    """
    maintenance = sa.create_engine(
        pg_engine.url.set(database="postgres"),
        isolation_level="AUTOCOMMIT", future=True,
    )
    with maintenance.connect() as connection:
        connection.execute(sa.text(f'DROP DATABASE IF EXISTS "{_MIGRATIONS_DB}"'))
        connection.execute(sa.text(f'CREATE DATABASE "{_MIGRATIONS_DB}"'))

    try:
        yield pg_engine.url.set(database=_MIGRATIONS_DB)
    finally:
        with maintenance.connect() as connection:
            connection.execute(sa.text(f'DROP DATABASE IF EXISTS "{_MIGRATIONS_DB}"'))
        maintenance.dispose()


@pytest.fixture()
def alembic_config(migrations_url):
    from alembic.config import Config

    config = Config(os.path.join(_api_dir(), "alembic.ini"))
    config.set_main_option("script_location", os.path.join(_api_dir(), "alembic"))
    # `%` es el carácter de interpolación de ConfigParser: una contraseña con
    # un `%` rompería la lectura si no se escapa.
    config.set_main_option("sqlalchemy.url", migrations_url.render_as_string(
        hide_password=False).replace("%", "%%"))
    return config


def test_the_migration_graph_is_linear_and_has_one_head():
    """Un segundo head significa dos ramas de esquema sin mezclar: el arranque
    de la aplicación falla y hay que resolverlo a mano.

    Y los identificadores de este repositorio se han venido escribiendo a mano
    siguiendo un patrón (``a1b2c3d4e5f6``, ``d7e8f9a0b1c2``…), que es justo el
    modo de acabar con dos revisiones con el mismo identificador — ha pasado.
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(os.path.join(_api_dir(), "alembic.ini"))
    config.set_main_option("script_location", os.path.join(_api_dir(), "alembic"))
    script = ScriptDirectory.from_config(config)

    assert len(script.get_heads()) == 1, f"se esperaba un head, hay {script.get_heads()}"

    identifiers = [revision.revision for revision in script.walk_revisions()]
    assert len(identifiers) == len(set(identifiers)), "hay identificadores repetidos"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Bug preexistente destapado por esta matriz (#356): la revisión "
        "b2c3d4e5f6a7 inserta en PlanLimit diez migraciones antes de que "
        "f2b3c4d5e6f7 cree la tabla, así que `alembic upgrade head` sobre una "
        "base vacía falla. No se nota en producción porque el primer "
        "despliegue crea el esquema con CREATE_DATABASE=True (create_all) y "
        "Alembic solo aplica los incrementos posteriores. Al arreglarlo, este "
        "test pasa a XPASS y hay que quitar el marcador."
    ),
)
def test_the_whole_chain_applies_to_an_empty_database(alembic_config, migrations_url):
    """``alembic upgrade head`` sobre una base vacía: el despliegue nuevo."""
    from alembic import command

    command.upgrade(alembic_config, "head")

    engine = sa.create_engine(migrations_url, future=True)
    try:
        tables = set(sa.inspect(engine).get_table_names())
        assert "IrisAnalysis" in tables
        assert "IrisMailboxConnection" in tables
    finally:
        engine.dispose()


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Depende de que `upgrade head` funcione sobre una base vacía, que hoy "
        "no lo hace (#356). Se quita junto con el marcador del test anterior."
    ),
)
def test_the_phase_0_columns_survive_a_downgrade_and_a_new_upgrade(alembic_config,
                                                                   migrations_url):
    """Las cuatro migraciones de la fase 0, en los dos sentidos.

    Bajar y volver a subir es lo que hace falta cuando un despliegue se
    revierte, y es donde se ve si una bajada olvidó una columna: la subida
    siguiente fallaría al intentar añadirla otra vez.
    """
    from alembic import command

    command.upgrade(alembic_config, "head")

    engine = sa.create_engine(migrations_url, future=True)
    try:
        columns = {column["name"] for column in sa.inspect(engine).get_columns("IrisAnalysis")}
        assert {"failure_code", "failure_reason"} <= columns                              # B03
        assert {"analysis_quality", "failed_rules", "detector_version"} <= columns        # B05
        assert {"ai_summary_status", "ai_summary_job_id",
                "ai_summary_model", "ai_summary_prompt_version"} <= columns               # B10

        cursor = next(column for column in sa.inspect(engine).get_columns("IrisMailboxConnection")
                      if column["name"] == "sync_cursor")
        assert cursor["type"].length is None, "sync_cursor volvió a tener un límite (B12)"
    finally:
        engine.dispose()

    # Cuatro pasos atrás: las cuatro migraciones de la fase 0.
    command.downgrade(alembic_config, "-4")
    command.upgrade(alembic_config, "head")

    engine = sa.create_engine(migrations_url, future=True)
    try:
        columns = {column["name"] for column in sa.inspect(engine).get_columns("IrisAnalysis")}
        assert {"failure_code", "analysis_quality", "ai_summary_status"} <= columns
    finally:
        engine.dispose()
