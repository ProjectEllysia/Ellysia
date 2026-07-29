"""
tests/conftest.py
═════════════════
Infraestructura compartida para toda la suite de tests de la API Ellysia.

Decisiones de diseño (ver el plan de tests):

1.  **Variables de entorno ANTES de importar ``src``.** El módulo
    ``users.managers`` lee la configuración OAuth en *tiempo de import*
    (``JWT_SECRET_KEY`` y compañía quedan capturadas como constantes de módulo).
    Por eso se fijan aquí, en la cabecera del fichero, antes de cualquier
    ``import`` de la aplicación. Lo mismo aplica a ``run.py``, que evalúa
    ``get_app_context()`` al importarse (necesita ``CREATE_DATABASE``/``DEBUG``).

2.  **BD SQLite en fichero temporal** (no ``:memory:``), para que el engine de
    ``infrastructure.unit_of_work`` y la conexión de inspección de esquema vean
    siempre las mismas tablas.

3.  **Shim de tipos PostgreSQL→SQLite.** Los modelos usan ``JSONB`` y ``ARRAY``,
    inexistentes en SQLite. Antes de crear el esquema se sustituyen *en memoria*
    por ``JSON`` genérico. No se toca ningún fichero de ``src/``.

4.  **Servicios externos mockeados.** El ``ping`` a Redis de ``create_app`` se
    parchea; el scheduler se desactiva con ``start_scheduler=False``; el rate
    limiter se desactiva para no contaminar tests entre sí.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Entorno mínimo — DEBE ir antes de importar la aplicación.
# ---------------------------------------------------------------------------

_API_DIR = Path(__file__).resolve().parent.parent
if str(_API_DIR) not in sys.path:
    sys.path.insert(0, str(_API_DIR))

os.environ["JWT_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ.setdefault("JWT_ALGORITHM", "HS256")
# Clave Fernet válida (32 bytes urlsafe-base64) solo para tests — ver
# users.services.secrets.encrypt_totp_secret / config_reading.get_mfa_config().
os.environ.setdefault("MFA_ENCRYPTION_KEY", "oZrC9aq99vdSaSW5nk55KNJFr9flChUBjs16fNhpfuU=")
# Clave Fernet distinta de MFA_ENCRYPTION_KEY (purposes no intercambiables,
# ver shared._crypto) para el refresh token del conector de buzón de Iris.
os.environ.setdefault("IRIS_MAILBOX_ENCRYPTION_KEY", "wMNiTz_4azXsQb3lJg8Fvv0hpRbPz50TV1ZivCMvx_E=")
os.environ.setdefault("ACCESS_TOKEN_EXPIRY_MINUTES", "30")
os.environ.setdefault("REFRESH_TOKEN_EXPIRY_DAYS", "7")
os.environ.setdefault("FLASK_ENV", "development")

# get_app_context() exige estas variables (su comprobación con all() trata el
# bool False por defecto como ausente). Las fijamos como strings para poder
# importar run.py sin que lance ValueError.
os.environ.setdefault("CREATE_DATABASE", "false")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("PORT", "5000")
os.environ.setdefault("SHUTDOWN_TIMEOUT", "30")

# T4: storage en memoria para el rate limiter — permite reactivarlo en tests
# puntuales (ver fixture `rate_limiting_enabled`) sin depender de un Redis
# real. Solo afecta al backend de almacenamiento del limiter, no al resto de
# la app (que sigue mockeando Redis para create_app()).
os.environ.setdefault("RATELIMIT_STORAGE_URI", "memory://")

# T5: aislar Redis del de desarrollo. Solo se mockean `ping`/`close` (arriba)
# para que create_app() arranque sin depender de un Redis real -- cualquier
# otra operación (p. ej. un TaskQueue.submit() no mockeado en algún test) sí
# llega a un Redis de verdad. Sin esto, esos tests encolaban jobs reales en la
# MISMA base Redis que usa el servidor de desarrollo (REDIS_HOST/DB comparten
# valor con .env), dejando jobs huérfanos que un worker real recogía más
# tarde y fallaban con FK violation contra una fila que solo existió en el
# SQLite efímero del test. Redis soporta 16 bases lógicas (0-15); moviendo los
# tests a la 15 quedan en un espacio de claves separado del de dev (DB 0) sin
# necesitar un Redis distinto. Asignación incondicional (no `setdefault`):
# tiene que ganar aunque `.env` ya fije REDIS_DB.
os.environ["REDIS_DB"] = "15"

# Redis/Ollama/OpenVAS: valores inertes; los servicios se mockean.
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("OPENVAS_HOST", "localhost")
os.environ.setdefault("OPENVAS_PORT", "9390")
os.environ.setdefault("OPENVAS_USERNAME", "admin")
os.environ.setdefault("OPENVAS_PASSWORD", "admin")

from unittest import mock  # noqa: E402

import pytest  # noqa: E402
import sqlalchemy as sa  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB  # noqa: E402

from sqlalchemy.orm import scoped_session, sessionmaker  # noqa: E402

from src.modules.shared import Base  # noqa: E402
from src.modules.infrastructure import engine as engine_module  # noqa: E402
from src.modules.infrastructure import unit_of_work  # noqa: E402
from src.modules.users.model import User  # noqa: E402
from src.modules.users.repositories import (  # noqa: E402
    AttributeRepository,
    UserRepository,
)
from src.modules.users.managers import OAuthTokenManager  # noqa: E402
from src.modules.users.services import generate_salt, hash_password, hash_password_with_salt  # noqa: E402


# ---------------------------------------------------------------------------
# 2. Shim de tipos PostgreSQL → SQLite
# ---------------------------------------------------------------------------

def _patch_postgres_types() -> None:
    """Sustituye JSONB/ARRAY por JSON genérico en toda la metadata.

    SQLite no entiende ``JSONB`` ni ``ARRAY``; ``JSON`` serializa la estructura
    a texto y la rehidrata al leer, que es suficiente para los tests. Se aplica
    sobre la metadata ya poblada (los modelos se importan al cargar ``src``).
    """
    for table in Base.metadata.tables.values():
        for column in table.columns:
            col_type = column.type
            if isinstance(col_type, (JSONB, sa.ARRAY)) or col_type.__class__.__name__ == "JSONB":
                column.type = sa.JSON()


# ---------------------------------------------------------------------------
# 3. Engines + esquema (una sola vez por sesión de tests)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def _sqlite_url(tmp_path_factory) -> str:
    """URL SQLite en fichero temporal compartida por ambos singletons."""
    db_path = tmp_path_factory.mktemp("seq_db") / "test.db"
    return f"sqlite:///{db_path.as_posix()}"


@pytest.fixture(scope="session")
def _initialized_db(_sqlite_url):
    """Crea un engine SQLite e inyecta el singleton de ``infrastructure.engine``.

    No se puede usar ``engine.initialize`` directamente porque fija
    ``isolation_level="READ COMMITTED"`` (válido en PostgreSQL, rechazado por
    SQLite). En su lugar construimos aquí un engine
    compatible con SQLite y lo asignamos a los globales de
    ``infrastructure.engine``; como su función de init es idempotente
    (``if ENGINE is None``), después reutilizará este engine.
    """
    # Importar run arrastra todos los blueprints y, con ellos, TODOS los modelos
    # de cada módulo a Base.metadata. Debe ocurrir antes del shim para que se
    # parcheen también las tablas de iris/themis/aegis.
    import run  # noqa: F401

    _patch_postgres_types()

    engine = sa.create_engine(
        _sqlite_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
        echo=False,
    )
    session_factory = scoped_session(
        sessionmaker(
            bind=engine,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
    )

    # The engine/session-factory singletons live in infrastructure.engine now,
    # and get_session()/close_all() read them from *that* module's namespace, so
    # the injection must target engine_module — reassigning unit_of_work.* (a
    # re-exported copy) would have no effect on what those functions see.
    engine_module.ENGINE = engine
    engine_module.SESSION_FACTORY = session_factory

    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    session_factory.remove()


# ---------------------------------------------------------------------------
# 4. Aplicación Flask + cliente de test
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app(_initialized_db):
    """Crea la app Ellysia apuntando a SQLite, sin scheduler ni Redis real."""
    import run  # import diferido: ya hay entorno y engines listos

    # ``redis.Redis(...).ping()`` se ejecuta dentro de create_app; lo
    # neutralizamos para no depender de un Redis real ni pagar su timeout.
    with mock.patch("redis.Redis.ping", return_value=True), \
         mock.patch("redis.Redis.close", return_value=None):
        application = run.create_app(fresh_db_init=False, start_scheduler=False, run_migrations=False)

    application.config.update(TESTING=True)

    # Desactiva el rate limiting para que los límites no contaminen tests.
    from src.modules.shared import limiter
    limiter.enabled = False

    return application


@pytest.fixture()
def client(app):
    """Cliente HTTP de pruebas de Flask."""
    return app.test_client()


@pytest.fixture()
def rate_limiting_enabled(app):
    """T4: reactiva el rate limiting real (storage en memoria, ver env
    RATELIMIT_STORAGE_URI) solo para el test que pida este fixture.

    El resto de la suite sigue con el limiter desactivado (ver fixture
    `app`) para que los límites no contaminen tests no relacionados — `app`
    es session-scoped, así que un límite global dejaría "quemadas" las
    peticiones de tests posteriores que compartan endpoint. Este fixture
    resetea el storage antes y después para no dejar rastro.
    """
    from src.modules.shared import limiter

    limiter.storage.reset()
    limiter.enabled = True
    try:
        yield
    finally:
        limiter.enabled = False
        limiter.storage.reset()


# ---------------------------------------------------------------------------
# 5. Aislamiento entre tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_db(_initialized_db):
    """Vacía todas las tablas tras cada test para garantizar independencia."""
    yield
    engine = _initialized_db
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    unit_of_work.close_all()


# ---------------------------------------------------------------------------
# 6. Factories de usuarios y cabeceras de autenticación
# ---------------------------------------------------------------------------

class UserHandle:
    """Datos planos de un usuario de prueba (evita objetos ORM desligados)."""

    def __init__(self, user_id: int, username: str, password: str, role: str):
        self.id = user_id
        self.username = username
        self.password = password
        self.role = role


@pytest.fixture()
def make_user(app):
    """Factory que crea un usuario con rol y atributos ABAC dados.

    Devuelve un ``UserHandle`` con id/username/password/role. El usuario se
    persiste con una contraseña hasheada real, de modo que sirve tanto para
    flujos de login como para minar tokens.

    T5: por defecto hashea con Argon2 (``hash_password``), igual que
    ``sign_in_user`` hashea a cualquier usuario real desde el alta — antes
    todo usuario de test se creaba por la ruta legacy SHA-256
    (``hash_password_with_salt``), así que ningún test de login por HTTP
    ejercitaba de verdad la rama Argon2 de ``verify_password`` (la que usa el
    100% de los usuarios reales). ``legacy_hash=True`` sigue disponible para
    los tests que verifican explícitamente la migración SHA-256→Argon2.
    """
    counter = {"n": 0}

    def _make(role: str = "role_user", attributes=None, password: str = "Secret123!", legacy_hash: bool = False):
        counter["n"] += 1
        suffix = counter["n"]
        username = f"user{suffix}"
        email = f"user{suffix}@ellysia.test"

        with app.app_context():
            if legacy_hash:
                salt = generate_salt()
                password_hash = hash_password_with_salt(password, salt)
            else:
                salt = ""
                password_hash = hash_password(password)

            user = User(
                username=username,
                email=email,
                first_name="Test",
                last_name=f"User{suffix}",
                password_hash=password_hash,
                password_salt=salt,
                role=role,
            )
            with unit_of_work.UnitOfWork() as uow:
                UserRepository(uow).save(user)
                user_id = user.id
                for attr in attributes or []:
                    AttributeRepository(uow).add_attribute(user_id, attr)

        return UserHandle(user_id, username, password, role)

    return _make


@pytest.fixture()
def auth_headers(app):
    """Factory que genera cabeceras Bearer para un ``UserHandle``."""

    def _headers(user: UserHandle) -> dict:
        with app.app_context():
            token = OAuthTokenManager().create_access_token(
                user.id, user.username, user.role
            )
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture()
def root_user(make_user):
    return make_user(role="role_root")


@pytest.fixture()
def admin_user(make_user):
    return make_user(role="role_admin")


@pytest.fixture()
def regular_user(make_user):
    return make_user(role="role_user")


@pytest.fixture()
def root_headers(root_user, auth_headers):
    return auth_headers(root_user)


@pytest.fixture()
def admin_headers(admin_user, auth_headers):
    return auth_headers(admin_user)


@pytest.fixture()
def user_headers(regular_user, auth_headers):
    return auth_headers(regular_user)
