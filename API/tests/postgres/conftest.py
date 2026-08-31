"""B20: fixtures para la matriz de integración contra motores reales.

La suite normal corre sobre SQLite con Redis y la red cortados de raíz, y eso
es deliberado: la mantiene en ~2 minutos y hace que el resultado no dependa de
lo que tenga levantado la máquina. Pero significa que hay invariantes de
producción que **hoy no prueba nadie**, porque solo existen en el motor real:

- SQLite ignora la longitud de un ``VARCHAR``, así que una columna demasiado
  corta no falla nunca (es lo que dejó pasar el `sync_cursor` de `B12`).
- SQLite no aplica claves foráneas salvo que se active explícitamente, así que
  ``ON DELETE CASCADE`` y ``ON DELETE SET NULL`` no se ejercitan.
- ``JSONB`` se sustituye por ``JSON`` genérico con un shim, así que ni el tipo
  ni sus operadores son los de producción.
- Las carreras reales entre transacciones no se pueden montar con un fichero
  SQLite compartido por un solo hilo.

Estos tests **no** sustituyen a los de la suite rápida: la complementan en el
único sitio donde SQLite no puede decir la verdad. Y no la ralentizan, porque
se saltan solos cuando no hay motores conectados.

Las fixtures tienen nombres propios (``pg_engine``, ``pg_session``…) en vez de
sobrescribir las de la raíz. Sobrescribir ``_initialized_db`` o ``app`` —que
son de sesión— haría que el primer test en pedirlas fijara el motor para toda
la ejecución, y el resultado dependería del orden de recolección.
"""

from __future__ import annotations

import os
from typing import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

import redis as redis_lib

# Se captura ANTES de que la fixture de sesión de la raíz parchee el pool: los
# conftest se importan en la recolección, y las fixtures autouse no corren
# hasta el primer test. Sin esta referencia no habría forma de volver a hablar
# con un Redis de verdad desde dentro de la suite.
_REAL_REDIS_GET_CONNECTION = redis_lib.connection.ConnectionPool.get_connection


#: URL del PostgreSQL efímero. Sin ella, todo este directorio se salta.
POSTGRES_URL_ENV = "POSTGRES_TEST_URL"

#: URL del Redis efímero. Los tests que lo necesitan se saltan sin ella.
REDIS_URL_ENV = "REDIS_TEST_URL"


def _postgres_url() -> str | None:
    return os.getenv(POSTGRES_URL_ENV) or None


def _redis_url() -> str | None:
    return os.getenv(REDIS_URL_ENV) or None


def pytest_collection_modifyitems(config, items):
    """Marca y salta todo el directorio cuando no hay PostgreSQL conectado.

    Se hace aquí y no con un ``skipif`` por módulo para que no haya forma de
    escribir un test nuevo en esta carpeta y olvidarse del guardia: en un
    portátil sin contenedores la carpeta entera se salta, y en el runner de CI
    con el servicio levantado corre entera.
    """
    if _postgres_url():
        return
    skip = pytest.mark.skip(
        reason=f"sin {POSTGRES_URL_ENV}: la matriz de motores reales solo corre en su job de CI"
    )
    for item in items:
        if "tests/postgres/" in item.nodeid.replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _clean_db():
    """Neutraliza la limpieza de la base SQLite de la suite rápida.

    ``tests/conftest.py`` la declara autouse, así que **cada** test la arrastra
    — y con ella ``_initialized_db``, que aplica el shim de tipos
    PostgreSQL→SQLite. Ese shim sustituye ``JSONB`` por ``JSON`` genérico
    **mutando ``Base.metadata`` en el sitio**, de modo que a partir de ese
    momento el proceso entero cree que esas columnas son ``JSON``: el esquema
    que se crea aquí saldría con el tipo equivocado y los operadores de JSONB
    no existirían.

    Sobrescribirla por nombre es el mecanismo de pytest para esto y solo aplica
    a este directorio. Aquí no hace falta lo que hacía: cada test usa su propia
    sesión, que se deshace al terminar.
    """
    yield


@pytest.fixture(autouse=True)
def _unlimited_default_plan():
    """Igual que arriba: la siembra de planes de la suite rápida arrastra la
    fixture ``app``, que también construye el engine SQLite."""
    yield


@pytest.fixture(scope="session")
def pg_engine() -> Iterator[sa.Engine]:
    """Engine contra el PostgreSQL efímero, con el esquema real creado.

    **Sin el shim de tipos** que la suite normal aplica: aquí las columnas son
    ``JSONB`` de verdad, que es justo lo que se quiere comprobar.
    """
    url = _postgres_url()
    if not url:
        pytest.skip(f"sin {POSTGRES_URL_ENV}")

    # Importar run arrastra todos los blueprints y con ellos cada modelo a
    # Base.metadata, igual que hace el conftest de la raíz.
    import run  # noqa: F401
    from sqlalchemy.dialects.postgresql import JSONB

    from src.modules.shared import Base

    # Guardia contra el shim de la suite rápida. Si algo ha llegado a
    # construir el engine SQLite en este proceso, ``Base.metadata`` ya tiene
    # las columnas JSONB degradadas a JSON y todo lo que se cree aquí sería
    # una imitación del esquema real. Es preferible saltarse la matriz con un
    # motivo legible que dar por buenas unas comprobaciones que no comprueban
    # lo que dicen. En su job de CI (``pytest -m postgres``) no pasa: nada
    # pide el engine SQLite.
    if not isinstance(Base.metadata.tables["IrisAnalysis"].c.failed_rules.type, JSONB):
        pytest.skip(
            "Base.metadata ya tiene aplicado el shim SQLite (JSONB->JSON): "
            "esta matriz debe ejecutarse en su propia invocación, con "
            "`pytest -m postgres`"
        )

    engine = sa.create_engine(url, pool_pre_ping=True, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _truncate_everything(engine: sa.Engine) -> None:
    """Vacía todas las tablas de la aplicación.

    Hace falta porque estos tests **confirman** sus transacciones: un rollback
    al terminar no deshace nada de lo ya escrito, y el siguiente test que
    consulte "todos los análisis" dependería de lo que dejaron los anteriores.
    ``TRUNCATE ... CASCADE`` en una sola sentencia evita además tener que
    ordenar las tablas por sus claves foráneas.
    """
    from src.modules.shared import Base

    names = ", ".join(f'"{table.name}"' for table in Base.metadata.sorted_tables)
    if not names:
        return
    with engine.begin() as connection:
        connection.execute(sa.text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))


@pytest.fixture()
def pg_session(pg_engine) -> Iterator[Session]:
    """Sesión limpia por test, sobre una base vacía."""
    factory = sessionmaker(bind=pg_engine, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        _truncate_everything(pg_engine)


@pytest.fixture()
def pg_sessions(pg_engine):
    """Factory de sesiones **independientes**, para montar carreras de verdad.

    Dos sesiones distintas son dos transacciones distintas contra el mismo
    PostgreSQL, que es la única forma de comprobar que una restricción de
    unicidad o un UPDATE condicional aguantan la concurrencia. Con una sola
    sesión, el ORM resolvería el conflicto en su propio identity map y el test
    pasaría sin haber tocado la base de datos.
    """
    factory = sessionmaker(bind=pg_engine, expire_on_commit=False, future=True)
    opened: list[Session] = []

    def _open() -> Session:
        session = factory()
        opened.append(session)
        return session

    try:
        yield _open
    finally:
        for session in opened:
            session.rollback()
            session.close()


@pytest.fixture()
def real_redis():
    """Cliente contra el Redis efímero, con el corte de la suite levantado.

    El conftest de la raíz parchea ``ConnectionPool.get_connection`` para toda
    la sesión, así que aquí se restaura la función original mientras dure el
    test. Es local y temporal a propósito: fuera de este directorio el corte
    sigue en pie.
    """
    url = _redis_url()
    if not url:
        pytest.skip(f"sin {REDIS_URL_ENV}")

    from unittest import mock

    with mock.patch.object(redis_lib.connection.ConnectionPool, "get_connection",
                           _REAL_REDIS_GET_CONNECTION):
        client = redis_lib.Redis.from_url(url, decode_responses=True)
        client.flushdb()
        try:
            yield client
        finally:
            client.flushdb()
            client.close()
