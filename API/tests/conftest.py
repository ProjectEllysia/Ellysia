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

4.  **Servicios externos mockeados.** Redis se corta de raíz para toda la
    sesión (``_redis_always_unavailable``); el ``ping`` de ``create_app`` se
    parchea; el scheduler se desactiva con ``start_scheduler=False``; el rate
    limiter se desactiva para no contaminar tests entre sí.
"""

from __future__ import annotations

import ipaddress
import os
import socket
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
# users.services.secrets.encrypt_totp_secret / config_reading.MfaConfig.
os.environ.setdefault("MFA_ENCRYPTION_KEY", "oZrC9aq99vdSaSW5nk55KNJFr9flChUBjs16fNhpfuU=")
# Clave Fernet distinta de MFA_ENCRYPTION_KEY (purposes no intercambiables,
# ver shared._crypto) para el refresh token del conector de buzón de Iris.
os.environ.setdefault("IRIS_MAILBOX_ENCRYPTION_KEY", "wMNiTz_4azXsQb3lJg8Fvv0hpRbPz50TV1ZivCMvx_E=")
# Idem para el raw MIME/cabeceras de IrisAnalysis, separado en su propia
# fila cifrada (IrisRawMessage) por M09/B19.
os.environ.setdefault("IRIS_RAW_MESSAGE_ENCRYPTION_KEY", "PttUWa9N_8cdsC4t113HiqFmxjCYYTIoplsFkz5U71Y=")
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

# T5: aislar Redis del de desarrollo. Segunda línea de defensa por debajo del
# fixture `_redis_always_unavailable` (que ya corta cualquier conexión): si
# alguien lo desactiva a propósito para depurar, los tests siguen escribiendo
# en la base 15 y no en la del servidor de desarrollo. Sin ninguna de las dos,
# un TaskQueue.submit() no mockeado encola jobs reales en la MISMA base Redis
# que usa dev (REDIS_HOST/DB comparten valor con .env), dejando jobs huérfanos
# que un worker real recoge más tarde y fallan con FK violation contra una
# fila que solo existió en el SQLite efímero del test. Redis soporta 16 bases
# lógicas (0-15). Asignación incondicional (no `setdefault`): tiene que ganar
# aunque `.env` ya fije REDIS_DB.
os.environ["REDIS_DB"] = "15"

# Redis/Ollama: valores inertes; los servicios se mockean.
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")

# Credenciales de IA: vacías siempre, en cualquier máquina.
#
# ``config_reading`` llama a ``load_dotenv()`` sin ruta, y esa función sube por
# el árbol de directorios hasta encontrar un ``.env``. En un checkout de
# desarrollo eso encuentra el ``.env`` de la raíz —el de docker-compose, que
# CLAUDE.md describe como "la API no lo lee"— y de ahí saca una OPENAI_API_KEY
# de verdad. En CI no hay ningún ``.env``, porque está en .gitignore.
#
# Resultado: un test que construya un writer de IA (``build_generator`` monta
# la estrategia con credenciales en el constructor) pasaba en local y fallaba en
# CI, sin que nada en el test dijera que dependía de eso. Es la misma clase de
# fuga que ya sellan Redis y los sockets salientes: algo del entorno de la
# máquina decidiendo el resultado.
#
# Asignación incondicional, no ``setdefault``: tiene que ganar a lo que traiga
# el ``.env``. Y basta con dejarlas vacías porque ``load_dotenv`` no sobrescribe
# una variable que ya existe, aunque su valor sea la cadena vacía.
os.environ["OPENAI_API_KEY"] = ""
os.environ["GOOGLE_API_KEY"] = ""

from importlib.util import module_from_spec, spec_from_file_location  # noqa: E402
from unittest import mock  # noqa: E402

import pytest  # noqa: E402
import redis as redis_lib  # noqa: E402
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
from src.modules.users.services.permissions import DEFAULT_USER_ATTRIBUTES  # noqa: E402
from src.modules.shared import utcnow_naive  # noqa: E402


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
# 3-bis. Redis: siempre caído, siempre al instante
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _redis_always_unavailable():
    """Hace que cualquier operación contra Redis falle *al instante*.

    La suite no necesita un Redis: los tests que ejercitan el encolado mockean
    ``TaskQueue.get_instance`` con un doble. Pero basta con olvidarlo en un
    test para que la operación salga a la red de verdad, y ahí el coste no es
    un error rápido sino una espera larguísima: en Windows un ECONNREFUSED
    contra ``localhost`` tarda ~4 s (resolución dual-stack, ~2 s por ``::1`` y
    otros ~2 s por ``127.0.0.1``) y redis-py reintenta varias veces, así que un
    único comando se comía ~48 s. Tres tests despistados sumaban 220 s de los
    375 s de la suite entera. En el runner Linux de CI el rechazo es inmediato,
    por eso el pipeline nunca lo delató.

    Se parchea ``ConnectionPool.get_connection`` en vez de la fachada
    ``Redis``: es el único punto por el que pasan tanto los comandos sueltos
    como los pipelines, y deja intactos los objetos ``Redis`` reales, de modo
    que el código bajo test sigue viendo un ``redis.ConnectionError`` (lo que
    ya captura hoy) y no un doble con otra forma.

    Efecto secundario buscado: el resultado deja de depender de si la máquina
    tiene o no el Redis de desarrollo levantado.
    """
    def _unavailable(*_args, **_kwargs):
        raise redis_lib.ConnectionError("Redis deshabilitado en la suite de tests")

    with mock.patch.object(redis_lib.connection.ConnectionPool, "get_connection", _unavailable):
        yield


# ---------------------------------------------------------------------------
# 3-ter. Ningún socket sale de loopback
# ---------------------------------------------------------------------------

# Los objetivos reales declarados los comparten este sello y el banco de
# paridad. Se cargan por ruta y no por nombre porque ``conftest`` es ambiguo:
# hay más de uno en el árbol (``tests/postgres/conftest.py``) y cuál gana
# depende del orden de recolección.
_REAL_TARGETS_SPEC = spec_from_file_location(
    "lybra_real_targets", Path(__file__).resolve().parent / "oracle" / "_real_targets.py"
)
_real_targets = module_from_spec(_REAL_TARGETS_SPEC)
_REAL_TARGETS_SPEC.loader.exec_module(_real_targets)


def _is_loopback(address) -> bool:
    """¿Apunta ``address`` (el argumento de ``socket.connect``) a loopback?

    Sockets Unix (dirección = ruta) y familias exóticas se dejan pasar: aquí
    solo interesa el tráfico IP. Una dirección sin resolver (nombre en vez de
    IP) se considera externa, que es el lado conservador.
    """
    if not isinstance(address, tuple) or not address:
        return True
    try:
        return ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        return address[0] in ("localhost", "")


@pytest.fixture(scope="session", autouse=True)
def _no_outbound_sockets():
    """Corta cualquier conexión que no sea a loopback, al instante.

    Varios tests de Lybra ejecutan el motor completo contra ``10.0.0.5`` (una
    IP privada que no enruta a ninguna parte). Cada check activo abría un
    socket de verdad y esperaba su timeout completo — ``HttpProbe`` usa 8 s, y
    un solo test se comía 10 checks × 8 s = 80 s. Los tests ya mockean las
    sondas que recuerdan (``HttpProbe.fetch`` y compañía), pero basta con
    olvidar una para que el escaneo salga a la red.

    Se corta en ``socket.connect``, no sonda a sonda, porque es el único punto
    por el que pasan todas: urllib (``HttpProbe``), TLS, las sesiones TCP
    crudas del descubrimiento de puertos. Un ``ConnectionRefused``
    instantáneo es indistinguible de un host inalcanzable para el código bajo
    test — que trata cualquier ``OSError`` como "no hay servicio" — solo que
    sin la espera.

    Loopback sí se permite: los tests de herald levantan un servidor SMTP real
    (aiosmtpd) en 127.0.0.1 y tienen que poder hablar con él.

    También se permiten las direcciones que el operador haya declarado en
    ``LYBRA_REAL_TARGETS`` (ver :func:`declared_real_targets`). Es una lista
    blanca de direcciones concretas, resueltas antes de instalar el sello, no
    un interruptor que lo apague: sin esa variable —el caso por defecto, y el
    de CI— no sale de aquí ni un paquete.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_gethostbyaddr = socket.gethostbyaddr
    allowed = _real_targets.allowed_outbound_addresses()

    def _is_permitted(address) -> bool:
        return _is_loopback(address) or (
            isinstance(address, tuple) and bool(address) and address[0] in allowed
        )

    def guarded_connect(self, address):
        if not _is_permitted(address):
            raise ConnectionRefusedError(
                f"La suite de tests no permite conexiones fuera de loopback: {address!r}"
            )
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        if not _is_permitted(address):
            return 111  # ECONNREFUSED, la convención de connect_ex
        return real_connect_ex(self, address)

    def guarded_gethostbyaddr(ip):
        # El DNS inverso es la otra forma de irse a la red sin abrir un socket
        # propio: resolver 10.0.0.5 colgaba 16 s en un test de Lybra. El único
        # caller (shared._endpoints) ya trata socket.herror como "no resuelve".
        if not _is_permitted((ip,)):
            raise socket.herror(f"DNS inverso bloqueado en tests: {ip!r}")
        return real_gethostbyaddr(ip)

    with (
        mock.patch.object(socket.socket, "connect", guarded_connect),
        mock.patch.object(socket.socket, "connect_ex", guarded_connect_ex),
        mock.patch.object(socket, "gethostbyaddr", guarded_gethostbyaddr),
    ):
        yield


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

    Semántica de ``attributes``, que cambió al vaciarse el baseline de
    ``Role.USER``: omitirlo concede ``DEFAULT_USER_ATTRIBUTES``, que es lo que
    ``sign_in_user`` escribe en el alta real; pasarlo concede **exactamente**
    esos, ni uno más — es la forma de construir el caso "el administrador le ha
    retirado este permiso". ``attributes=[]`` deja al usuario sin ninguno (ver
    el atajo ``stripped_user``).
    """
    counter = {"n": 0}

    def _make(role: str = "role_user", attributes=None, password: str = "Secret123!",
              legacy_hash: bool = False, unverified: bool = False):
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
                # Verificado salvo que el test pida lo contrario, igual que un
                # alta hecha por un administrador: sin esto, el motor de cuotas
                # cortaría a todos los usuarios de la suite.
                email_verified_at=None if unverified else utcnow_naive(),
            )
            granted = (
                [attribute.db_name for attribute in DEFAULT_USER_ATTRIBUTES]
                if attributes is None
                else attributes
            )
            with unit_of_work.UnitOfWork() as uow:
                UserRepository(uow).save(user)
                user_id = user.id
                for attr in granted:
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
def stripped_user(make_user):
    """Usuario al que un administrador le ha retirado todos los atributos.

    Es el caso que prueban los tests ``*_requires_*_attribute``: desde que el
    baseline de ``Role.USER`` está vacío, un usuario normal tiene todos los
    atributos por defecto, así que el 403 solo puede venir de una retirada
    explícita. Antes ese 403 lo daba la ausencia de baseline.
    """
    return make_user(role="role_user", attributes=[])


@pytest.fixture()
def root_headers(root_user, auth_headers):
    return auth_headers(root_user)


@pytest.fixture()
def admin_headers(admin_user, auth_headers):
    return auth_headers(admin_user)


@pytest.fixture()
def user_headers(regular_user, auth_headers):
    return auth_headers(regular_user)


# ---------------------------------------------------------------------------
# 7. Catálogo de planes (módulo accounts)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _unlimited_default_plan(app):
    """Siembra un plan por defecto sin topes, para toda la suite.

    Desde que el motor de cuotas corta de verdad, una base de datos sin
    catálogo no es un estado realista: en producción siempre hay planes, los
    siembra la migración. Sin esto, cualquier test que lance un escaneo o dé de
    alta un activo recibiría un 500 por ``DefaultPlanMissingError``.

    Todos los topes van a ``NULL`` (ilimitado) por el mismo motivo que
    ``limiter.enabled = False``: el resto de la suite no está probando cuotas y
    no debe pelearse con ellas. El motor sigue ejecutándose en cada llamada —
    así que una excepción dentro de él sale a la luz igual—, simplemente nunca
    corta. Los tests que sí prueban el corte se traen su propio catálogo.
    """
    from src.modules.accounts.model import Plan, PlanLimit
    from src.modules.accounts.services.limits import PERIODS, LimitKey

    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            plan = Plan(
                code="test-unlimited", name="Test", rank=0,
                monthly_price_cents=0, org_addon_price_cents=0, currency="EUR",
                is_public=False, is_default=True,
            )
            uow.session.add(plan)
            uow.session.flush()
            for key in LimitKey:
                uow.session.add(PlanLimit(
                    plan_id=plan.id, limit_key=key.value, scope="holder",
                    value=None, period=PERIODS[key].value,
                ))
            uow.session.flush()
    yield


@pytest.fixture()
def seeded_plans(app, _unlimited_default_plan):
    """Siembra un catálogo mínimo de planes y devuelve {code: plan_id}.

    Retira antes el plan sin topes de ``_unlimited_default_plan``: solo puede
    haber un ``is_default``, y lo impone un índice único de la base de datos.

    **Function-scoped a propósito**: ``_clean_db`` vacía todas las tablas al
    terminar cada test, así que un fixture de sesión dejaría el catálogo
    sembrado solo para el primero que lo pidiera.

    No replica el catálogo comercial real (4 planes × 15 claves × 2 ámbitos):
    duplicarlo aquí obligaría a editar los números en dos sitios y un cambio de
    precio rompería tests. Lo que estos necesitan ejercitar son las formas —
    un límite mensual, uno de existencias, un cero, un ilimitado, un plan
    oculto y el plan por defecto. La fidelidad del catálogo real la vigila
    ``tests/unit/test_accounts_seed.py``, sobre el literal de la migración.
    """
    from src.modules.accounts.model import Plan, PlanLimit

    # (code, name, rank, price, is_public, is_default)
    plans = [
        ("freemium", "Freemium", 0,     0, True,  True),
        ("bronze",   "Bronze",   1,  2900, True,  False),
        ("gold",     "Gold",     2, 19900, True,  False),
        ("custom",   "A medida", 9, 50000, False, False),
    ]
    # code -> [(limit_key, scope, value, period)]
    limits = {
        "freemium": [
            ("iris.analyses",           "holder",   10, "month"),
            ("acheron.vaults",          "holder",    1, "stock"),
            ("themis.thirdparty.scans", "holder",    0, "month"),
        ],
        "bronze": [
            ("iris.analyses",           "holder",  100, "month"),
            ("acheron.vaults",          "holder",    3, "stock"),
            ("themis.thirdparty.scans", "holder",   10, "month"),
            ("organization.members",    "holder",    2, "stock"),
            ("acheron.vaults",          "member",    3, "stock"),
            ("iris.analyses",           "member",   50, "month"),
        ],
        "gold": [
            ("iris.analyses",           "holder", None, "month"),
            ("acheron.vaults",          "holder", None, "stock"),
            ("themis.thirdparty.scans", "holder",  200, "month"),
            ("organization.members",    "holder",    5, "stock"),
            ("acheron.vaults",          "member", None, "stock"),
            ("iris.analyses",           "member",  200, "month"),
        ],
        "custom": [
            ("iris.analyses",           "holder", None, "month"),
        ],
    }

    ids = {}
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            placeholder = uow.session.query(Plan).filter(
                Plan.code == "test-unlimited"
            ).one_or_none()
            if placeholder is not None:
                uow.session.delete(placeholder)
                uow.session.flush()

            for code, name, rank, price, is_public, is_default in plans:
                plan = Plan(
                    code=code, name=name, tagline=f"Plan {name}", rank=rank,
                    monthly_price_cents=price, org_addon_price_cents=0,
                    currency="EUR", is_public=is_public, is_default=is_default,
                )
                uow.session.add(plan)
                uow.session.flush()
                ids[code] = plan.id
                for limit_key, scope, value, period in limits[code]:
                    uow.session.add(PlanLimit(
                        plan_id=plan.id, limit_key=limit_key,
                        scope=scope, value=value, period=period,
                    ))
            uow.session.flush()
    return ids


@pytest.fixture()
def set_plan_limits(app, _unlimited_default_plan):
    """Aprieta los topes del plan por defecto de la suite.

    Es la forma más corta de poner a un usuario contra el límite: no hace falta
    crear un plan nuevo ni darle una suscripción, porque quien no tiene
    suscripción ya recibe el plan por defecto.

    Uso: ``set_plan_limits({LimitKey.HYGEIA_ASSETS: 1})``.
    """
    from src.modules.accounts.model import Plan, PlanLimit

    def _set(limits: dict) -> None:
        with app.app_context():
            with unit_of_work.UnitOfWork() as uow:
                plan = uow.session.query(Plan).filter(Plan.is_default.is_(True)).one()
                for key, value in limits.items():
                    row = uow.session.query(PlanLimit).filter(
                        PlanLimit.plan_id == plan.id,
                        PlanLimit.limit_key == key.value,
                        PlanLimit.scope == "holder",
                    ).one()
                    row.value = value
                uow.session.flush()

    return _set


@pytest.fixture()
def make_subscription(app, seeded_plans):
    """Factory que da de alta una suscripción para un usuario.

    Sin llamar a ``SubscriptionManager``: escribe la fila directamente para
    dejar el test libre de tener que pasar por las seis operaciones del ciclo
    de vida cuando lo único que le importa es partir de un estado ya dado.
    """
    from src.modules.accounts.model import Subscription

    def _make(user, plan_code="gold", status="active", **overrides):
        with app.app_context():
            with unit_of_work.UnitOfWork() as uow:
                subscription = Subscription(
                    user_id=user.id,
                    plan_id=seeded_plans[plan_code],
                    status=status,
                    organization_enabled=overrides.pop("organization_enabled", False),
                    cancel_at_period_end=overrides.pop("cancel_at_period_end", False),
                    **overrides,
                )
                uow.session.add(subscription)
                uow.session.flush()
                return subscription.id

    return _make
