# Convenciones de código — Ellysia

Este documento responde a una sola pregunta: **si tengo que crear esto, ¿dónde lo creo, cómo lo creo
y qué entidad le doy?** Cubre el backend (`API/`), que es donde vive casi todo el código.

Lo operativo —comandos, arquitectura, configuración, «cosas que muerden»— sigue en
[`CLAUDE.md`](CLAUDE.md). La regla de docstrings también vive allí (§ *Documentación de funciones,
clases y métodos*) y aplica a todo lo que se describe aquí.

**Alcance.** Rige para todo código nuevo y para todo código que se toque. Lo que hoy no lo cumple
está inventariado en [§ 11](#11-estado-actual-y-cumplimiento): cuando se toca un fichero de esa
lista, se adapta en el mismo cambio.

---

## Índice

1. [Chuleta: ¿dónde va esto?](#1-chuleta-dónde-va-esto)
2. [Árbol del proyecto](#2-árbol-del-proyecto)
3. [Capas, módulos y fronteras](#3-capas-módulos-y-fronteras)
4. [Repositorios](#4-repositorios)
5. [Managers](#5-managers)
6. [Servicios y funciones compartidas](#6-servicios-y-funciones-compartidas)
7. [Trabajo en segundo plano: TaskQueue, outbox y Dispatcher](#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher)
8. [Tareas periódicas: schedulers](#8-tareas-periódicas-schedulers)
9. [Constantes y configuración](#9-constantes-y-configuración)
10. [Nombres](#10-nombres)
11. [Estado actual y cumplimiento](#11-estado-actual-y-cumplimiento)

---

## 1. Chuleta: ¿dónde va esto?

| Quiero… | Entidad | Dónde |
|---|---|---|
| Leer, guardar, modificar o borrar filas | método de `<Modelo>Repository` | `<módulo>/repositories.py` |
| Una tabla nueva | modelo SQLAlchemy + migración | `<módulo>/model.py` + `alembic revision --autogenerate` |
| Una operación que llaman los endpoints, otro módulo, el worker o un scheduler | método público de `<Algo>Manager` | `<módulo>/managers.py` o `<módulo>/managers/<tema>.py` |
| Un helper que solo usa un fichero | función de módulo `_nombre` | ese mismo fichero |
| Un helper que usan varios ficheros del mismo módulo | función pública de un servicio | `<módulo>/services/<tema>.py` |
| Un helper puro (sin BD, sin red) que usan varios módulos | función pública | `shared/_<tema>.py`, reexportada en `shared/__init__.py` |
| Lógica de negocio de un módulo que necesita otro módulo | método público del manager dueño | el manager del módulo dueño, exportado en su `__init__.py` |
| Un trabajo largo (escaneo, PDF, IA, correo) | `execute_*` + `_run_*` + outbox | manager del módulo + categoría en su `__init__.py` ([§ 7](#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher)) |
| Algo que se repite cada X tiempo | scheduler del módulo | `<módulo>/services/scheduling.py` ([§ 8](#8-tareas-periódicas-schedulers)) |
| Un endpoint | método del Blueprint + schema | `<módulo>/endpoints.py` + `<módulo>/schemas.py` |
| Un valor que un operador podría querer cambiar | campo de un `@config_block` | `SecOpsConfig.json` + `config_reading.py` ([§ 9](#9-constantes-y-configuración)) |
| Un valor fijo que solo cambia cambiando código | constante `_NOMBRE` | cabecera del fichero que la usa |
| Un conjunto cerrado de valores | `StrEnum` | `model.py` si se persiste; si no, el servicio dueño del concepto |
| Una excepción de dominio | clase `<Algo>Error` | `<módulo>/exceptions.py` |
| Hablar con un proveedor de IA o de correo | estrategia | `tools/scribe/` o `tools/herald/` |
| Un módulo de feature nuevo | paquete completo ([§ 3.1](#31-anatomía-de-un-módulo)) | `features/<nombre>/` + blueprint en `run.py` + `web/Caddyfile` + `web/app/vite.config.js` |

---

## 2. Árbol del proyecto

```
EllysiaServer/
├── CLAUDE.md                 guía maestra: operativa y arquitectura
├── CONVENCIONES.md           este documento: dónde y cómo se crea cada cosa
├── AGENTS.md                 puntero a CLAUDE.md (convención AGENTS.md)
├── README.md                 contrato público: endpoints, categorías de cola, puertos, config
├── docker-compose*.yml       perfiles dev / container y variantes de GPU
├── .env                      credenciales solo para docker-compose; la API no lo lee
├── .github/workflows/        CI: tests, tests-postgres, lybra-bench, deploy, landing
├── plans/                    intenciones y auditorías fechadas; NO describen el estado actual
├── landing/                  web estática de marketing, sin build ni acoplamiento
├── web/
│   ├── Caddyfile             sirve el SPA, proxya la API y gestiona TLS
│   └── app/src/
│       ├── views/            una vista por pantalla (IrisHubView.vue, ConfigView.vue…)
│       ├── components/       piezas reutilizables entre vistas
│       ├── stores/           estado Pinia, uno por dominio (irisStore.js…)
│       ├── composables/      lógica reactiva reutilizable (usePolling…)
│       ├── router/           rutas del SPA; deben seguir a los matchers de web/Caddyfile
│       ├── constants/        constantes del frontend
│       ├── acheron/          cliente de bóveda (cripto + sync)
│       └── assets/images/    fuente de verdad de los assets de marca
└── API/
    ├── run.py                create_app(): blueprints, BD, schedulers, apagado ordenado
    ├── SecOpsConfig.json     configuración base no secreta (§ 9)
    ├── .env                  secretos y overrides de la config; nunca se commitea
    ├── alembic/versions/     migraciones, una por cambio de model.py
    ├── resources/            datos que la API lee en ejecución (semilla de Topic, recursos de Iris)
    ├── scripts/              scripts de mantenimiento que se lanzan a mano; src/ no los importa
    ├── tools/                utilidades de análisis para desarrollo; src/ no las importa
    │                         (no confundir con src/modules/tools/, que sí es runtime)
    ├── tests/
    │   ├── conftest.py       sella la red y Redis; adapta a SQLite
    │   ├── unit/             sin app ni BD; aquí viven también los tests de arquitectura
    │   ├── integration/      create_app() + cliente HTTP de test
    │   ├── postgres/         lo que SQLite no puede probar: concurrencia, migraciones, invariantes
    │   └── oracle/           benchmarks de Lybra contra objetivos y KB reales (fuera de la suite normal)
    └── src/
        ├── data/             salida en disco (informes, CSV); en .gitignore
        └── modules/
            ├── infrastructure/   mecanismo de persistencia y scheduling; no sabe nada del dominio
            │   ├── unit_of_work.py       UnitOfWork: frontera transaccional
            │   ├── base_repository.py    BaseRepository[T]: CRUD genérico
            │   ├── document_repository.py
            │   ├── session.py            get_db_session, build_repository, hooks de request
            │   ├── engine.py             singletons de engine y sesión
            │   ├── scheduling.py         make_background_scheduler, @scheduler_job
            │   └── retry.py
            ├── shared/           código puro y clases base que usan todos los módulos
            │   ├── __init__.py           superficie pública (reexporta los _*.py)
            │   ├── _model.py             Base, Document
            │   ├── _exposure.py          is_private_target, classify_exposure
            │   ├── _crypto.py            EncryptedText
            │   └── _*.py                 un tema por fichero; se consumen vía shared/__init__
            ├── system/           /system: config, TaskQueue, logging
            │   ├── config_reading.py     CR: bloques de config (§ 9)
            │   ├── taskqueue/            cola RQ + outbox + worker (§ 7)
            │   └── services/
            ├── tools/            capacidades técnicas enchufables que no saben quién las usa
            │   ├── scribe/               generación IA (Ollama / OpenAI / Google)
            │   └── herald/               envío de correo (SMTP)
            ├── users/            transversal: usuarios, auth, permisos, MFA
            ├── accounts/         transversal: planes, organizaciones, suscripciones, cuotas
            └── features/         un paquete por producto
                ├── themis/       escaneo (Nmap, Nikto, Nuclei, Lybra)
                │   └── lybra/    motor propio: capa pura, sin ORM ni red (§ 6.4)
                ├── iris/         análisis de correo y phishing
                ├── aegis/        concienciación: píldoras, quiz, campañas
                ├── hygeia/       monitorización de activos
                └── acheron/      bóveda de secretos
```

---

## 3. Capas, módulos y fronteras

Un **módulo** es cada paquete directo de `src/modules/` (`users`, `accounts`, `system`…) y cada
paquete de `src/modules/features/` (`themis`, `iris`…). `infrastructure`, `shared` y `tools/*`
también son módulos, pero de soporte.

### 3.1 Anatomía de un módulo

```
features/<módulo>/
├── __init__.py        superficie pública del módulo (__all__) + QueueRegistry.register(...)
├── endpoints.py       Blueprint: auth, validación de schema y una llamada a un manager. Nada más.
├── schemas.py         schemas Marshmallow; claves JSON en camelCase
├── model.py           modelos SQLAlchemy (y los StrEnum que se persisten)
├── repositories.py    un <Modelo>Repository por modelo: el único sitio con SQL
├── managers.py        clases <Algo>Manager: lo que el módulo ofrece a los demás
│   (o managers/)      paquete cuando crece: un fichero por manager, __init__.py reexporta
├── exceptions.py      excepciones de dominio (<Algo>Error)
├── resources/         (opcional) ficheros binarios que el módulo usa en ejecución
└── services/          lógica interna con entidad propia (§ 6)
    ├── <tema>.py      un tema por fichero: scoring.py, retention.py, parsers.py…
    ├── scheduling.py  (opcional) el scheduler del módulo (§ 8)
    └── <tema>/        paquete cuando un servicio crece: rules/, reports/, mailbox/
```

### 3.2 Quién puede importar a quién, dentro de un módulo

Las dependencias van en una sola dirección: **endpoints → managers → servicios → repositorios →
modelos**.

| Desde ↓ / hacia → | `model` | `repositories` | `services` | `managers` |
|---|---|---|---|---|
| `endpoints.py` | solo para tipos | ✗ | ✗ | ✓ |
| `managers` | ✓ | ✓ | ✓ | ✓ (otro manager del módulo) |
| `services` | ✓ | ✓ | ✓ | ✗ — salvo `services/scheduling.py`, que es un borde (§ 8) |
| `repositories.py` | ✓ | ✗ | ✗ | ✗ |

Un **borde** es el código por el que entra el trabajo en la aplicación: los endpoints (HTTP), el
worker (jobs) y los schedulers (tiempo). Los bordes consumen managers; nada consume a un borde.

### 3.3 La frontera entre módulos: el `__init__.py`

**Un módulo solo puede usar de otro lo que ese otro exporta en su `__init__.py` (`__all__`).** Esa
lista es su superficie pública: managers, modelos (para relaciones del ORM y tipos), excepciones,
enums, schemas compartidos y, en los transversales, los decoradores de permisos.

```python
# Bien
from src.modules.users import User, UserManager, require_oauth_token
from src.modules.accounts import LimitKey, QuotaManager

# Mal: entra en las tripas de otro módulo
from src.modules.users.services.secrets import hash_password
from src.modules.accounts.services.entitlements import resolve_entitlement
from src.modules.features.themis.repositories import ScanRepository
```

- **Nunca** se importan los `services/` ni los `repositories.py` de otro módulo, ni un nombre con
  `_` de otro fichero (salvo desde `tests/`, [§ 5.4](#54-tests-de-funciones-privadas)).
- Si lo que necesitas no está exportado, la solución es **exportarlo** desde el módulo dueño —
  normalmente como método de su manager—, no importarlo por dentro.
- Si importar el paquete completo provoca un import circular, se puede importar el **mismo nombre
  público** desde el fichero de superficie que lo define (`<módulo>.model`, `<módulo>.managers`,
  `<módulo>.exceptions`, `<módulo>.schemas`). Nunca desde `services/` ni `repositories`.
- **Excepción autorizada:** `TaskDispatchRepository` (outbox de la TaskQueue). Es parte del
  mecanismo de encolado y tiene que escribir en la misma transacción que la fila del módulo que
  encola ([§ 7](#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher)).

### 3.4 La dirección entre módulos

```
features/*  ──►  users, accounts  ──►  tools/*, system  ──►  shared, infrastructure
```

- Una capa puede usar las de su derecha, nunca las de su izquierda. `shared/` e `infrastructure/`
  no importan nada del dominio; `users` y `accounts` no importan features.
- Una feature puede usar a otra feature, siempre por su `__init__.py` (Aegis usa a Themis y a
  Hygeia así).
- **Excepciones autorizadas:**
  - `system/config_reading.py` importa `ScanType` de Themis, porque `CR.THEMIS_SCANNERS` se
    deriva del enum a propósito (ver CLAUDE.md § Configuración). El import ocurre la primera vez
    que se pide la lista, nunca al cargar el módulo: cargar `themis/model.py` ejecuta antes
    `features/themis/__init__.py`, que arrastra media aplicación.
  - Cualquier módulo, también `shared/` e `infrastructure/`, puede leer `system/config_reading.py`.
    Es una hoja: solo depende de la biblioteca estándar y de `shared._exceptions`.
  - Un `endpoints.py` puede usar la superficie pública de `users` (los decoradores de permisos y
    `Role`) aunque su módulo tenga un rango menor. Es un borde HTTP (§ 3.2) y la autenticación la
    necesitan todos.
- **Nada se importa en `src/__init__.py`.** Python lo ejecuta antes que cualquier
  `src.modules.x.y`, así que lo que se importe ahí se carga en todos los imports del proyecto y
  esconde los ciclos de imports. Por el mismo motivo, un `__init__.py` de mecanismo (`system`,
  `shared`, `infrastructure`) no carga endpoints ni nada que dependa de `users`. Lo vigila
  `tests/unit/test_system_import_isolation.py`, que importa esos módulos en un proceso limpio.
- Cuando un módulo transversal necesita algo de todas las features —contar recursos para la
  cuota de un plan, borrar los datos de un usuario—, la dependencia se invierte con un registro:
  cada feature se da de alta en el transversal desde su propio `__init__.py`, igual que hace hoy
  con `QueueRegistry.register(...)`. El transversal recorre el registro sin conocer a nadie.

---

## 4. Repositorios

**Qué son.** Las únicas clases que hablan con la base de datos. **Ningún SQL se ejecuta fuera de
una clase `<Algo>Repository`**: ni `session.query`, ni `session.execute`, ni `session.add`/`delete`/
`flush`, ni `select()`/`update()`/`text()`.

Excepciones: `infrastructure/` (es el propio mecanismo), `alembic/versions/` y `tests/` (cuando una
consulta directa hace el test más claro).

### 4.1 Cómo se declara

```python
from sqlalchemy import and_, update

from src.modules.infrastructure import BaseRepository

from .model import IrisAnalysis


class IrisAnalysisRepository(BaseRepository[IrisAnalysis]):
    """Acceso a datos de ``IrisAnalysis``."""

    _MODEL = IrisAnalysis

    def count_by_user(self, user_id: int) -> int:
        """Cuenta los análisis de un usuario, en cualquier estado.

        Args:
            user_id: Primary key del usuario.

        Returns:
            int: Número de análisis; ``0`` si no tiene ninguno.
        """
        return self._session.query(IrisAnalysis).filter(IrisAnalysis.user_id == user_id).count()
```

- Un repositorio por modelo, en el `repositories.py` del módulo dueño del modelo, con nombre
  `<Modelo>Repository` y `_MODEL = <Modelo>`. No hace falta `__init__` propio.
- `BaseRepository` ya trae `get_by_id`, `get_by_field`, `get_all_by_field`, `get_all`, `exists`,
  `get_children`, `paginate`, `save`, `update` y `delete`. Una consulta nueva es un **método nuevo
  del repositorio**, con nombre y docstring; nunca una consulta montada en el manager.
- Se accede a la sesión con `self._session`, que resuelve la del `UnitOfWork` o la de lectura.

### 4.2 Qué hace y qué no hace

- **Hace:** consultar, insertar, actualizar y borrar. Devuelve instancias del modelo, escalares
  (`int`, `bool`) o listas de ellos.
- **No confirma** la transacción: `save`/`update`/`delete` hacen `flush`, no `commit`. El commit
  pertenece al `UnitOfWork` y a los bordes (§ 4.3).
- **No decide nada del negocio:** no comprueba permisos, no valida reglas, no lanza excepciones de
  dominio y no devuelve diccionarios para la API. Todo eso es del manager.
- **No consulta modelos de otro módulo.** Eso se le pide al manager de ese módulo.

### 4.3 Cómo se usa

```python
from src.modules.infrastructure import UnitOfWork, build_repository

# Lectura: sin transacción propia
analysis = build_repository(IrisAnalysisRepository).get_by_id(analysis_id)

# Escritura: siempre dentro de un UnitOfWork
with UnitOfWork() as uow:
    IrisAnalysisRepository(uow).save(analysis)
    IrisRuleResultRepository(uow).save(rule_result)   # misma transacción
```

Qué hace el `with` depende de dónde corre, y no hay que pensar en ello en cada llamada:

| Contexto | Al salir del `with` |
|---|---|
| Dentro de una request HTTP | nada: el `teardown_request` confirma toda la request de una vez (o hace rollback si hubo error) |
| En el worker o en un scheduler | confirma si todo fue bien; hace rollback si hubo excepción |

**`uow.commit_for_handoff()`** confirma *ya*, también dentro de una request. Se usa justo antes de
encolar un job: el worker es otro proceso con otra sesión, y si la fila no está confirmada cuando
la busca, no la ve ([§ 7](#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher)).

### 4.4 Actualizaciones que compiten entre sí

Si dos actores pueden cambiar la misma fila a la vez (el usuario cancela mientras el worker
termina), no se lee, se decide y se escribe: la condición va **dentro del propio `UPDATE`**, y el
método devuelve si ganó. Así es `IrisAnalysisRepository.transition_if_state`:

```python
def transition_if_state(self, analysis_id: int, from_states: list[str], **fields) -> bool:
    result = self._session.execute(
        update(IrisAnalysis)
        .where(and_(IrisAnalysis.id == analysis_id, IrisAnalysis.status.in_(from_states)))
        .values(**fields)
    )
    return result.rowcount == 1
```

Nombres habituales: `get_by_<campo>`, `get_<qué>`, `count_<qué>`, `exists_<qué>`/`has_<qué>`,
`delete_<qué>`, `purge_<qué>_older_than`, `transition_if_state`, `claim_<qué>`.

---

## 5. Managers

**Qué son.** Las clases con la lógica de negocio de un módulo. **Los métodos de una clase manager
son, exactamente, lo que el módulo ofrece a quien no es ese fichero**: nada más.

«Quien no es ese fichero» incluye:
- los `endpoints.py` del propio módulo;
- otros módulos, a través del `__init__.py`;
- el **worker**, que ejecuta los `execute_*`;
- los **schedulers**.

### 5.1 La regla

- **Todos los métodos de la clase son públicos** (sin `_`).
- Todo lo que no se publica es una **función de módulo privada** (`_nombre`) en el mismo fichero,
  fuera de la clase.
- Si una función privada necesita estado de la instancia (`self._task_queue`, el usuario…), lo
  recibe **por parámetro**. Tocar `self` no justifica un método privado.
- Atributos de clase e instancia sí pueden ser privados (`self._task_queue`); la regla habla de
  métodos.
- Las constantes de la clase que forman parte de su contrato (`EXTERNAL_ID_PREFIX`,
  `TASK_CATEGORY`, `SCAN_TYPE`) son atributos de clase públicos.

**Única excepción: los ganchos que se sobrescriben.** Cuando una clase base define un método que
cada subclase redefine —`ScanManager` y sus escáneres Nmap, Nikto, Nuclei y Lybra—, ese método no
puede ser una función de módulo, porque la subclase necesita sustituirlo. Se permite `_nombre` si
es `@abstractmethod` en la base **o** lo redefine al menos una subclase, y su docstring lo dice:

```python
    @abstractmethod
    def _build_command(self, target: str) -> list[str]:
        """Gancho: construye la línea de comandos del escáner.

        Lo redefinen ``NmapScanManager``, ``NiktoScanManager`` y ``NucleiScanManager``.
        ...
        """
```

Un `_método` que ninguna subclase redefine no es un gancho: es un helper, y sale de la clase.

**Esta regla vale para toda clase de `src/`**, no solo para los managers: los métodos de una clase
son su contrato. Además de los ganchos, se permiten los métodos especiales (`__init__`,
`__enter__`…) y los que implementan un gancho de una librería externa, por ejemplo
`_install_signal_handlers` de `rq.SimpleWorker`.

### 5.2 Orden de un fichero de manager

```python
"""Ciclo de vida del análisis de Iris."""

# 1. imports
from src.modules.system.taskqueue import TaskTrackingMixin, job_context

# 2. constantes privadas del fichero
_VERDICT_ORDER = ("Legitimate", "Suspicious", "Phishing")


# 3. funciones privadas
def _run_analysis(analysis_id: int, raw_input: str) -> None:
    """Cuerpo del job de análisis; lo invoca ``IrisManager.execute_iris_analysis``."""
    with job_context() as job:
        ...


def _enqueue_phishing_notification(task_queue: ITaskQueue, analysis_id: int, verdict: str) -> None:
    """La cola llega por parámetro: una función privada no lee ``self``."""
    ...


# 4. la clase: solo superficie pública
class IrisManager(TaskTrackingMixin):
    """Análisis de cabeceras y contenido de correo."""

    EXTERNAL_ID_PREFIX = "iris-analysis:"
    TASK_CATEGORY = "iris.analyze"

    def get_analysis_status(self, analysis_id: int) -> Optional[str]:   # lo llama endpoints.py
        ...

    @staticmethod
    def execute_iris_analysis(analysis_id: int, raw_input: str) -> None:  # lo llama el worker
        _run_analysis(analysis_id, raw_input)
```

### 5.3 Tamaño y reparto

- Un manager por agregado o caso de uso (`IrisManager`, `IrisMailboxManager`,
  `IrisReportManager`…), con nombre `<Dominio>Manager`.
- Cuando `managers.py` crece, pasa a paquete `managers/`, un fichero por manager, y su
  `__init__.py` reexporta las clases. Así ningún import externo cambia, y RQ sigue resolviendo los
  `execute_*` ya encolados.
- Si los helpers privados de un manager empiezan a tener entidad propia —se pueden nombrar como un
  tema, o los necesita otro fichero—, suben a `services/` ([§ 6](#6-servicios-y-funciones-compartidas)).

### 5.4 Tests de funciones privadas

Un test que necesita una función privada la **importa explícitamente** del fichero que la define:

```python
from src.modules.features.iris.managers.analysis import IrisManager, _evaluate_gates
```

Nunca se reexporta un `_nombre` en un `__init__.py`, y nunca se hace pública una función solo para
poder testearla.

---

## 6. Servicios y funciones compartidas

### 6.1 Qué es un servicio

Código **con entidad propia que no es superficie pública del módulo**: parsers, motores de reglas,
scoring, renderizado de informes, adaptadores a proveedores (Gmail, Microsoft), retención,
scheduling. Tiene entidad propia si se puede nombrar como un tema del dominio (`scoring`,
`retention`), si lo usan varios ficheros del módulo, o si tiene tests propios.

- Vive en `<módulo>/services/<tema>.py`, con el fichero nombrado por el tema (`scoring.py`,
  `parsers.py`, `retention.py`). Cuando crece, pasa a paquete (`services/rules/`,
  `services/reports/`, `services/mailbox/`).
- Sus nombres **públicos** (sin `_`) son lo que el resto del módulo usa. Sus nombres con `_` son
  privados de ese fichero.
- **Solo lo consume su propio módulo.** Si otro módulo lo necesita, se publica a través del
  manager o se sube a `shared/` (§ 6.2).
- Puede usar los repositorios de su módulo. No importa los managers de su módulo (la dependencia va
  de manager a servicio), salvo `services/scheduling.py`, que es un borde (§ 8).
- Se prefieren servicios **puros** (sin BD ni red): se testean sin fixtures. Si un paquete entero
  es puro, su docstring lo dice y un test lo fija (el patrón de `themis/lybra/`).
- Sus clases siguen la regla de clases de § 5.1.

### 6.2 La escalera: dónde vive una función según quién la use

| Quién la usa | Dónde vive | Cómo se llama |
|---|---|---|
| Un solo fichero | ese fichero, fuera de toda clase | `_nombre` |
| Varios ficheros del mismo módulo | `<módulo>/services/<tema>.py` | `nombre` (público dentro del módulo) |
| Varios módulos, y es puro (sin BD, sin red, sin dominio) | `shared/_<tema>.py`, reexportado en `shared/__init__.py` | `nombre` |
| Varios módulos, y es lógica de negocio de uno de ellos | método del manager dueño, exportado en su `__init__.py` | `nombre` |
| Varios módulos, y es mecanismo (BD, scheduling, reintentos) | `infrastructure/` | `nombre` |

Reglas de la escalera:

- **Se sube un peldaño en el mismo cambio en que aparece el segundo consumidor.** Nunca se importa
  un `_nombre` desde otro fichero para ahorrarse la subida.
- **Antes de crear un helper, busca en `shared/` y en los `services/` de tu módulo.** El ejemplo de
  lo que pasa si no: `iris/services/parsers.py` define `_is_private_ip`, que duplica
  `shared.is_private_target` (`shared/_exposure.py`). Dos implementaciones de la misma regla acaban
  divergiendo sin que nada falle.
- Si al subir a `shared/` descubres que la función necesita BD o conceptos de un módulo, no es de
  `shared/`: es de un manager.

### 6.3 `shared/`: cómo se añade algo

1. Crea `shared/_<tema>.py`. El `_` del fichero significa que no se importa directamente.
2. Reexporta sus nombres públicos en `shared/__init__.py` y añádelos a `__all__`.
3. Los consumidores importan `from src.modules.shared import nombre`.

### 6.4 Subpaquetes de motor en la raíz de una feature

Una feature puede tener en su raíz un paquete de motor puro cuando es grande y tiene invariantes
propias. Es el caso de `themis/lybra/` (sin ORM ni red; lo fija
`tests/unit/test_lybra_package_invariants.py`). La parte que sí toca ORM y red va en
`managers/` o `services/`, como hace `themis/managers/lybra/`. No es un sitio para helpers sueltos:
si no tiene una invariante que un test pueda fijar, va a `services/`.

---

## 7. Trabajo en segundo plano: TaskQueue, outbox y Dispatcher

### 7.1 Cómo funciona

La API no ejecuta el trabajo largo: lo **describe** —qué función, con qué argumentos— y lo deja en
una cola de Redis. Un **proceso worker**, separado de la API, lo recoge y lo ejecuta. Dentro de ese
proceso hay `max_workers` hilos (`infrastructure.taskqueue.max_workers`), cada uno con su propia
app Flask y su propia sesión de BD.

La función viaja **por referencia** (`modulo:Clase.metodo`), no por valor. Por eso tiene que ser un
`@staticmethod` de un manager, y sus argumentos tienen que ser datos simples (ids, texto, listas y
dicts). Nunca objetos del ORM, lambdas ni closures.

**Sin un worker levantado no falla nada:** los jobs se quedan en la cola para siempre, en
silencio.

### 7.2 Dos formas de encolar

**El problema que resuelve la outbox.** Si guardas una fila en estado `pending` (un escaneo) y
*después* encolas su job, entre los dos pasos hay una ventana. Si la API muere o Redis falla justo
ahí, la fila existe y ningún job la procesará nunca. La **outbox** guarda la *intención* de encolar
—una fila `TaskDispatch`— en la **misma transacción** que tu fila: o existen las dos o ninguna.

Después, `OutboxDispatcher.dispatch()` la publica en Redis. Si falla, la fila se queda `pending` y
la reintentan:
- el barrido periódico (`TaskDispatchScheduler`, cada `outbox_sweep_interval_seconds`);
- la reconciliación de arranque.

| Situación | Usa |
|---|---|
| Guardas una fila cuyo estado depende de que el job llegue a correr: escaneo, análisis, campaña, píldora, aviso con guardia anti-duplicado | **outbox** (`build_dispatch` + `OutboxDispatcher.dispatch`) |
| No hay fila previa que pueda quedarse huérfana, o relanzar el job no tiene consecuencias: traceroute, sincronización de buzón | **`submit()` directo**, con un comentario junto a la llamada que diga por qué |

La outbox garantiza **al menos una vez**, no *exactamente una vez*: en una rendija muy estrecha, un
job ya terminado puede volver a publicarse. Por eso todo job debe poder repetirse sin crear datos
duplicados: recalcula y sobrescribe por id, nunca inserta a ciegas.

### 7.3 Receta paso a paso

**1. Registra la categoría** en el `__init__.py` de la feature. Formato `<módulo>.<acción>`:

```python
from src.modules.system.taskqueue import QueueRegistry

QueueRegistry.register("example.report")
```

Añádela a la lista de categorías de CLAUDE.md y del README.

**2. Prepara el manager.** Hereda de `TaskTrackingMixin`, que recibe la cola por el constructor
(`task_queue: Optional[ITaskQueue] = None`, y en tests un doble) y la guarda en
`self._task_queue`:

```python
class ExampleReportManager(TaskTrackingMixin):
    """Generación asíncrona de informes de ejemplo."""

    EXTERNAL_ID_PREFIX = "example-report:"
    TASK_CATEGORY = "example.report"
```

**3. Escribe el punto de entrada y el cuerpo.** El `execute_*` es superficie pública (lo consume el
worker) y va en la clase. El cuerpo es una función privada de módulo que usa `job_context()`:

```python
def _run_report(report_id: int) -> None:
    """Cuerpo del job: genera el informe y marca su estado."""
    with job_context() as job:
        sections = ...
        for position, section in enumerate(sections, start=1):
            if job.cancelled():          # cancelación cooperativa
                return
            ...
            job.progress(position * 100 // len(sections))


class ExampleReportManager(TaskTrackingMixin):
    ...

    @staticmethod
    def execute_report(report_id: int) -> None:
        """Punto de entrada que ejecuta el worker de la TaskQueue."""
        _run_report(report_id)
```

`job_context()` expone `job.progress(porcentaje)` y `job.cancelled()`. Al salir limpia la señal de
cancelación y libera la sesión de BD del hilo. Fuera de un worker (en un test) todo es un no-op.

**4a. Encola con la outbox** (el caso por defecto):

```python
from src.modules.system.taskqueue import OutboxDispatcher, build_dispatch
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

    def create_report(self, user_id: int) -> ExampleReport:
        """Crea el informe y encola su generación en la misma transacción."""
        report = ExampleReport(user_id=user_id, status="pending")
        with UnitOfWork() as uow:
            ExampleReportRepository(uow).save(report)
            dispatch = TaskDispatchRepository(uow).save(build_dispatch(
                func=ExampleReportManager.execute_report,
                name=f"ExampleReport-{report.id}",          # id del job en RQ: determinista
                category=self.TASK_CATEGORY,
                args=(report.id,),                          # JSON-serializable
                external_id=self.external_id_for(report.id),
                timeout=600,                                # segundos
            ))
            dispatch_id = dispatch.id
            uow.commit_for_handoff()     # el worker es otro proceso: la fila debe verse ya

        OutboxDispatcher.dispatch(dispatch_id, task_queue=self._task_queue)
        return report
```

`ScanManager._create_scan_and_dispatch` (Themis) es el ejemplo real más completo.

**4b. O encola directamente**, solo si se cumple el criterio de § 7.2:

```python
        # Sin fila previa que pueda quedarse huérfana: si el submit falla, el usuario reintenta.
        self._task_queue.submit(
            func=ExampleReportManager.execute_report,
            name=f"ExampleReport-{report_id}",
            category=self.TASK_CATEGORY,
            args=(report_id,),
            external_id=self.external_id_for(report_id),
            timeout=600,
        )
```

**5. Estado, progreso y cancelación.** El mixin ya lo resuelve por `external_id`:

```python
    def get_report_status(self, report_id: int) -> Optional[str]:
        """Estado del job: pending, running, completed, failed, cancelled o timeout."""
        return self.task_status_of(report_id)

    def cancel_report(self, report_id: int) -> bool:
        """Pide la cancelación; el job para en su siguiente ``job.cancelled()``."""
        task = self.find_task(report_id)
        return task is not None and self._task_queue.cancel(task.id)
```

**6. Huérfanos.** Si la fila tiene estados no terminales (`pending`, `running`), añade un
`reconcile_orphaned_<qué>()` en el manager: marca como fallidas las filas cuyo job ya no existe. Se
llama desde `run.py::_configure_scheduling()` (ejemplo: `IrisManager.reconcile_orphaned_analyses`).

### 7.4 Reglas

- Argumentos **JSON-serializables**: la outbox los guarda en JSONB. Un dataclass se convierte a
  dict antes.
- `name` determinista y apto para RQ (`f"{Tipo}-{id}"`: letras, números, `_`, `-`). Es lo que hace
  idempotente volver a publicar.
- `external_id` siempre con `self.external_id_for(id)`; el prefijo lo declara
  `EXTERNAL_ID_PREFIX`. Nunca a mano.
- `commit_for_handoff()` antes de publicar, siempre.
- El worker relee `SecOpsConfig.json` antes de cada job si cambió en disco; `max_workers` solo se
  lee al arrancar.
- `TaskDispatchRepository` se importa hoy de `system.taskqueue.outbox_repository` porque
  `system/taskqueue/__init__.py` no lo exporta todavía ([§ 11](#11-estado-actual-y-cumplimiento)).

### 7.5 Cuándo usar la cola y cuándo no

**Sí:**
- escaneos (`themis.scan`);
- informes PDF (`themis.report`, `iris.report`);
- generación con IA (`aegis.generate`, `iris.ai_summary`);
- envío de correo (`aegis.campaign`, `iris.notify`, `hygeia.notify`);
- ingesta de buzones (`iris.ingest`);
- traceroute (`themis.traceroute`).

Todo lo que dependa de la red, de un binario externo o de un LLM, o que pueda tardar más de un par
de segundos.

**No:** lo que la request tiene que devolver ya, o lo que es trivialmente rápido. Encolar tiene su
coste: una fila, un viaje a Redis y un estado que el cliente tiene que sondear.

---

## 8. Tareas periódicas: schedulers

Lo que se repite cada X tiempo (sincronizar buzones, purgar por retención, avisos de resumen) va
en **un scheduler por módulo**, nunca en uno compartido.

- Clase `<Módulo>Scheduler` en `<módulo>/services/scheduling.py`, con `start()` y `stop()`
  idempotentes.
- La construye `make_background_scheduler()` (UTC y margen de retraso de 60 s) y se arranca desde
  `run.py::_configure_scheduling()`: solo en la API, nunca en el worker.
- Cada job es una función de módulo privada decorada con `@scheduler_job(logger, "mensaje")`, que
  registra y se traga la excepción (una ejecución fallida no mata el hilo del scheduler) y libera
  la sesión al terminar.
- El scheduler corre en un hilo del proceso de la API. Si la tarea es pesada (red, IA, PDF), su job
  **se limita a encolar** un trabajo en la TaskQueue ([§ 7](#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher)).
- `system/taskqueue/scheduling.py` (`TaskDispatchScheduler`) es el ejemplo mínimo.

---

## 9. Constantes y configuración

### 9.1 ¿Config, entorno o código?

Hazte estas preguntas **en orden**; la primera que se cumpla decide:

1. **¿Es secreto o depende del despliegue** (credenciales, hosts, URL pública)? → **`API/.env`**.
   Se lee con `CR.get_*_environment()` o con una `@property` sobre un campo `configured_*`.
2. **¿Querría cambiarlo quien opera un despliegue, sin tocar código?** Umbrales, timeouts, TTL,
   reintentos, límites de tamaño, URLs de feeds externos, flags de activación, prompts, listas de
   palabras, branding. → **`SecOpsConfig.json`**, leído con un `@config_block`.
3. **Si no:** cambiarlo exige cambiar código de todas formas, o es parte de un protocolo, un
   formato o una invariante. Prefijos de claves Redis, regex, versiones de esquema, bytes de un
   protocolo, valores de un enum, rutas dentro del paquete. → **constante en el código**.

Dos matices:

- **Una garantía de seguridad no se deja rebajar por config.** El tiempo de vida del `state` de
  OAuth (`_STATE_MAX_AGE_SECONDS` en `iris/managers/mailbox.py`) es código a propósito. Si algo de
  seguridad tiene que ser ajustable, el bloque de config valida su rango al leerlo.
- **Nunca en los dos sitios.** Si un valor está en la config, el código no lleva una constante con
  el mismo valor «por si acaso»: el default vive solo en el campo del `@config_block`.

### 9.2 Dónde va una constante de código

La misma escalera que las funciones ([§ 6.2](#62-la-escalera-dónde-vive-una-función-según-quién-la-use)):

| Quién la usa | Dónde | Nombre |
|---|---|---|
| Un fichero | cabecera del fichero, tras los imports | `_UPPER_SNAKE` |
| Varios ficheros del módulo | el servicio dueño del concepto (las constantes de scoring en `scoring.py`) | `UPPER_SNAKE` |
| Varios módulos | `shared/_<tema>.py` | `UPPER_SNAKE` |

- **No se crean ficheros `constants.py`**: agrupan por tipo («son constantes») en vez de por
  concepto, y acaban siendo un cajón de sastre. Una constante vive con el código que le da sentido.
- **Un conjunto cerrado de valores es un `StrEnum`**, no varias constantes de texto sueltas. Se
  declara en `model.py` si se guarda en una columna; si no, en el servicio dueño.
- **Nada de números mágicos** dentro de las funciones cuyo significado no sea evidente: se nombran.
- Una constante que no sea obvia lleva un comentario `#:` encima que diga **por qué** tiene ese
  valor (el patrón de `PRIVATE_HOST_SUFFIXES` en `shared/_exposure.py`).

### 9.3 Cómo se añade una clave a la config

El procedimiento completo está en CLAUDE.md (§ *Leer config: bloques, no getters*). En resumen:

1. Colócala bajo la rama raíz que le toca (`general`, `infrastructure`, `tools`, `features`),
   nunca en la raíz.
2. Nombre en `camelCase`, salvo que se pase tal cual como kwarg a una librería (argon2,
   SQLAlchemy, redis-py).
3. Añade el campo al `@config_block` y el default, solo ahí.
4. Registra el bloque en `CONFIG_BLOCKS` de `tests/unit/test_config_shape.py`.
5. Si se edita desde el SPA, añade la ruta en `web/app/src/views/ConfigView.vue` (lo vigila
   `test_config_view_paths.py`).

---

## 10. Nombres

### 10.1 Palabras completas

Nunca abreviaturas ni letras sueltas: `message` no `msg`, `count` no `cnt`, `manager` no `mgr`,
`document` no `doc`, `task_queue` no `tq`, `configuration`… salvo las autorizadas:

- **Abreviaturas autorizadas:** `repo`, `config`, `uow`, `pk`, `CR`, `e` en `except … as e`.
- **Índices y descartes:** `_`, `i`, `j`, `n`, `x`, `y`.
- **Siglas que son el nombre estándar de la cosa:** `ip`, `url`, `id`, `cve`, `jwt`, `pdf`,
  `smtp`, `oauth`, `json`, `csv`. Una sigla no es una abreviatura cuando nadie usa la forma larga.
- **Sufijo `_RE`** para regex compiladas (`_LOG_LINE_RE`).

### 10.2 Funciones y métodos: verbos

Toda función o método se nombra con un **verbo**. Hay cinco excepciones:
- las **propiedades** (`@property`), que se leen como un dato y se nombran como tal
  (`public_url`, `is_expired`);
- las conversiones `to_*` / `from_*` / `as_*`;
- los métodos especiales (`__init__`…);
- los tests `test_*`, que describen el comportamiento;
- las fixtures de pytest, que representan un valor y por eso son sustantivos.

Cada prefijo tiene un significado fijo, para que el nombre diga qué esperar:

| Prefijo | Significa | Devuelve |
|---|---|---|
| `get_` | obtiene algo que puede no existir | el valor, o `None` |
| `assert_` | obtiene algo que **debe** existir o ser accesible | el valor; si no, lanza una excepción de dominio |
| `validate_` | comprueba datos de entrada | nada; lanza si no son válidos |
| `check_` | consulta un estado externo (red, cuota) | un resultado; si solo es sí/no, usa `is_`/`has_` |
| `is_` / `has_` / `can_` | predicado | `bool` |
| `count_` | cuenta | `int` |
| `build_` | construye un objeto **sin** persistirlo | el objeto |
| `create_` | construye **y** persiste | la entidad creada |
| `save_` / `update_` / `delete_` | persistencia (repositorios) | la entidad o nada |
| `parse_` / `render_` | texto → estructura / estructura → salida | la estructura / la salida |
| `submit_` / `dispatch_` | encolar | lo que devuelva la cola |
| `execute_` | punto de entrada del worker (`@staticmethod`) | nada |
| `_run_` | cuerpo del job (función privada) | nada |
| `reconcile_` | repara estado incoherente tras una caída | cuántas filas tocó |

### 10.3 Variables: sustantivos que dicen qué guardan y de qué tipo

- **El nombre aclara el tipo.** `critical_threshold` no `critical` (`critical` se lee como
  booleano; `critical_threshold` dice que es un número).
- **Colecciones en plural** (`scans`, `open_ports`). **Diccionarios `<valor>_by_<clave>`**
  (`findings_by_host`). **Contadores `<cosa>_count`**. **Identificadores `<cosa>_id`**.
- **Magnitudes con la unidad en el nombre:** `timeout_seconds`, `retention_days`, `max_body_bytes`.
- **Booleanos con `is_`, `are_`, `was_`, `did_`, `has_`, `can_` o `should_`:** `is_finished`,
  `was_cancelled`, `has_pending`, `should_notify`.
- **Y al revés:** lo que no es booleano no puede sonar a booleano. `active_scans` (una lista) no
  `active`; `matched_phrases` no `found`; `empty_payload` no `empty`.

### 10.4 Clases, constantes y ficheros

- **Clases:** sustantivos en `PascalCase`, con el sufijo de su papel: `…Repository`, `…Manager`,
  `…Scheduler`, `…Strategy`, `…Schema`, `…Error` (excepciones). Los modelos son el sustantivo
  solo: `Scan`, `IrisAnalysis`.
- **Constantes:** `UPPER_SNAKE`, con `_` delante si son privadas del fichero.
- **Ficheros:** sustantivos en `snake_case` que nombran el tema (`scoring.py`, `retention.py`).
  Tests: `test_<módulo>_<tema>.py`.

---

## 11. Estado actual y cumplimiento

### 11.1 Lo que hoy no cumple el convenio

**SQL fuera de un repositorio** (§ 4):
- `accounts/managers/{plans,organizations,invitations,subscriptions}.py` y
  `features/acheron/managers.py` usan `uow.session.add/query/flush` directamente.
- `accounts/services/{limits,notices,quotas}.py` y `users/services/account_deletion.py` consultan
  la sesión directamente.
- `features/iris/managers/mailbox.py` tiene un `uow.session.execute`.

**Métodos privados en managers** (§ 5): 140 en 41 clases. Los más cargados son
`LybraEngineManager` (22), `IrisMailboxManager` (19) y `AegisManager` (10). Parte de los de
`ScanManager` y sus subclases son ganchos legítimos.

**Imports que entran por dentro de otro módulo** (§ 3.3):
- Hygeia importa `users.services.secrets`.
- Una feature importa `accounts.services.entitlements`.
- Las features importan `system.taskqueue.outbox_repository`, `.dispatcher` y `.outbox`.
  `TaskDispatchRepository` debería reexportarse en `system/taskqueue/__init__.py`.

**Dependencias en sentido contrario** (§ 3.4):
- `accounts/services/limits.py` y `users/services/account_deletion.py` importan modelos de todas
  las features.
- `users/__init__.py` importa Acheron.
- `shared/_documents.py` importa la TaskQueue de `system`. Además usa la BD, así que no es código
  puro y no le corresponde estar en `shared/` (§ 6.2).

**Duplicados** (§ 6.2, § 9.1):
- `iris/services/parsers.py::_is_private_ip` duplica `shared.is_private_target`.
- El par reintentos `3` / backoff `1.5` aparece en `aegis/services/pills.py` y en
  `themis/lybra/kb.py`, además de en `tools.scribe.resilience`.

**Conjuntos cerrados como cadenas sueltas** (§ 9.2): `PROFILE_*` en `iris/services/scoring.py`,
y `QUALITY_*` / `CONFIDENCE_*` / `COVERAGE_*` en `iris/services/quality.py`.

**Ficheros fuera de sitio** (§ 3.1): `acheron/password_generator.py` y `acheron/storable_specs.py`
viven en la raíz del módulo; son candidatos a `services/`.

### 11.2 Cómo se hace cumplir

Una norma que nada comprueba se degrada. Esta sección es la especificación del test que la
comprueba, `API/tests/unit/test_code_conventions.py`. El inventario exacto de lo que hoy no cumple
es su `KNOWN_VIOLATIONS`; la lista de § 11.1 es el resumen legible.

**Dónde y cómo.** Un fichero, `API/tests/unit/test_code_conventions.py`, marcado `unit` (no arranca
la app ni toca la BD), en la línea de `test_caddy_api_routes.py` y `test_config_shape.py`. Recorre
todos los `.py` de `API/src/` y los analiza con el módulo `ast` de la librería estándar.

No usa expresiones regulares sobre el texto: una regex confunde `item.findtext(...)` con una
llamada a `text(...)` de SQLAlchemy, y no distingue un import de un comentario que lo menciona.

#### A qué módulo pertenece un fichero

Las reglas 3 y 5 necesitan saber si dos ficheros están en el mismo módulo. El módulo se deduce de
la ruta:

| Ruta | Módulo |
|---|---|
| `src/modules/features/<nombre>/…` | `features.<nombre>` |
| `src/modules/tools/<nombre>/…` | `tools.<nombre>` |
| `src/modules/<nombre>/…` (cualquier otro) | `<nombre>` |
| `src/` fuera de `src/modules/` (hoy solo `src/__init__.py`) | ninguno; cuenta como rango 0 en la regla 5 |

Los imports relativos (`from .x import y`) se resuelven a ruta absoluta antes de comparar.

#### Las reglas

**Regla 1 — SQL solo en repositorios.** Es violación toda llamada, fuera de una clase cuyo nombre
acabe en `Repository`, a:
- un atributo `query`, `execute`, `add`, `add_all`, `delete`, `merge`, `flush` o `get` de un objeto
  cuyo nombre sea `session` o acabe en `.session` (cubre `session.query(...)` y
  `uow.session.add(...)`);
- las funciones de SQLAlchemy `select`, `update`, `delete`, `insert` o `text`, solo si se
  importaron de `sqlalchemy` en ese fichero.

Quedan exentos `src/modules/infrastructure/` (es el propio mecanismo), los `model.py` (su SQL
declara el esquema —el `where` de un índice parcial—, no ejecuta consultas) y `alembic/`, que está
fuera de `src/`.

**Regla 2 — métodos privados solo si son ganchos.** Para cada clase de `src/`, es violación todo
método cuyo nombre empiece por un solo `_` (los especiales `__x__` no cuentan), salvo que cumpla
alguna de estas condiciones:
- está decorado con `@abstractmethod`;
- es una propiedad (`@property`, `@cached_property` o su `.setter`): se lee como un atributo, y los
  atributos sí pueden ser privados (§ 5.1). Es el caso de `BaseRepository._session`;
- un ancestro de la clase, definido en `src/`, declara un método con el mismo nombre (esta clase lo
  está sobrescribiendo);
- una subclase, definida en `src/`, declara un método con el mismo nombre (esta clase es la base de
  un gancho).

Para las condiciones segunda y tercera, el test construye primero un grafo de herencia de todas las
clases de `src/`, resolviendo las bases por nombre importado.

Los ganchos de librerías externas no se pueden ver en ese grafo, como
`_ThreadSafeWorker._install_signal_handlers`, que sobrescribe un método de `rq.SimpleWorker`. Van a
una lista aparte, `EXTERNAL_HOOKS`, cada uno con la librería que lo exige.

**Regla 3 — no entrar por dentro de otro módulo.** Es violación que un fichero del módulo A
importe algo de otro módulo B cuya ruta contenga `.services` o `.repositories`. Se usa la tabla de
módulos de arriba para saber si A y B son distintos.

Única excepción: `src.modules.system.taskqueue.outbox_repository` (§ 3.3).

**Regla 4 — los `_nombres` no salen de su fichero.** Es violación todo `from X import _nombre`
dentro de `src/`, sea X del mismo módulo o no. Los tests están fuera de `src/` y por eso pueden
hacerlo (§ 5.4).

**Regla 5 — dirección entre módulos.** Cada módulo tiene un rango:

| Módulo | Rango |
|---|---|
| `shared`, `infrastructure` | 0 |
| `system`, `tools.*` | 1 |
| `users`, `accounts` | 2 |
| `features.*` | 3 |

Es violación importar un módulo de rango **mayor** que el propio. Los ficheros de `src/` que no
están en ningún módulo cuentan como rango 0. Las tres excepciones autorizadas de § 3.4 no son
violación: `system/config_reading.py` → `ScanType` de Themis, cualquier fichero →
`system/config_reading.py`, y un `endpoints.py` → la superficie pública de `users`.

#### La lista de excepciones que solo encoge

El código de hoy incumple estas reglas (§ 11.1), así que el test nace con una lista de las
violaciones existentes. Es un diccionario en el propio fichero de test:

```python
KNOWN_VIOLATIONS: dict[tuple[str, str, str], str] = {
    # (regla, ruta relativa a API/, símbolo): motivo o plan.
    # Las dos entradas son ILUSTRATIVAS: muestran la forma, no son violaciones reales.
    ("sql-outside-repository", "src/modules/accounts/managers/plans.py", "PlanManager.ejemplo"):
        "pendiente de mover a PlanRepository",
    ("private-method", "src/modules/features/iris/managers/mailbox.py", "IrisMailboxManager._ejemplo"):
        "pendiente de sacar a función de módulo",
}
```

La clave identifica la violación por **símbolo** —la función o `Clase.método` donde aparece—,
nunca por número de línea. Así la lista no se rompe cada vez que alguien añade una línea encima.

Por cada regla hay un test que compara lo encontrado con la lista y falla en dos casos:

1. **Aparece una violación que no está en la lista.** El mensaje enumera cada una con su regla,
   ruta y símbolo, y remite a la sección de este documento que la explica.
2. **Una violación de la lista ya no aparece.** Alguien la arregló; el test pide borrar esa entrada
   para que la lista siga diciendo la verdad. Es la misma idea que `xfail(strict=True)`.

La lista inicial **no se escribe a mano**: se genera ejecutando el detector sobre el código actual.
Los recuentos de § 11.1 salieron de búsquedas aproximadas y serán algo distintos del resultado del
detector, que es el que manda.

#### Tests del propio detector

Un detector que no detecta pasa en verde para siempre sin que nadie lo note. Por cada regla hay
además un test sobre código de ejemplo escrito como cadena y analizado con `ast.parse`, que
comprueba los dos sentidos:
- que detecta un caso que debe detectar, como un `uow.session.add(x)` dentro de un manager;
- que no detecta uno que no debe, como la misma llamada dentro de un `FooRepository`, o un
  `_método` abstracto.
