# Refactor de la capa de datos y la estructura de módulos de la API

## Contexto

Tras la auditoría de antipatrones sobre el uso de `Queues` e `infrastructure/`, se
corrigieron los cuatro hallazgos de mayor impacto (carrera *enqueue-antes-de-commit*,
entry points sin `job_context()`, workers que registraban éxito pese a fallar, y la
honestidad de la semántica de `UnitOfWork`). Este documento recoge las mejoras
**estructurales** restantes: son correctas pero de alcance amplio y **no se pueden
validar de forma fiable sin arrancar el servidor**, que asume Linux (Nmap/Nikto/OpenVAS
son nativos de Linux; en Windows solo corren `pytest` y el build web). Por eso se
plantean como un refactor por fases con su propia estrategia de verificación, en lugar
de aplicarse a ciegas.

El objetivo transversal: que **cómo y cuándo se persiste algo** sea evidente leyendo el
código, sin depender del contexto de ejecución (request vs. worker), y que los ficheros
de `managers.py` dejen de ser "god files" de ~1.000–2.000 líneas.

## Estado actual verificado

- **`UnitOfWork` tiene tres semánticas** según dónde corre (`API/src/modules/infrastructure/unit_of_work.py`):
  no-op en request (el commit lo hace `teardown_request`), commit/rollback por bloque en
  contexto background, y no-op con sesión inyectada (tests). Está bien documentado, pero
  obliga al lector a saber en qué contexto está para razonar sobre la durabilidad.
  La operación `commit_for_handoff()` (añadida al corregir el hallazgo #1) ya da un nombre
  explícito al caso "hacer durable antes de ceder trabajo a otro proceso".
- **Dualidad `Repository(uow=…)` vs `Repository(session=get_db_session())`**: convención
  implícita "lecturas con `session=`, escrituras con `uow`", no reforzada por ningún tipo
  ni helper. Se mezclan dentro de un mismo método (p. ej. `aegis/managers.py` `launch_campaign`).
- **Import circular en `infrastructure/`**: `unit_of_work.py` mezcla los singletons de
  engine/session-factory (`initialize`, `get_session`, `warmup`, `close_all`) con la clase
  `UnitOfWork`; el ciclo con `session.py` se resuelve con un import diferido dentro de
  `UnitOfWork.__init__` (`from .session import get_db_session`). Además `unit_of_work.py`
  tiene imports a media altura de fichero.
- **`conftest.py:175-176`** reasigna directamente `unit_of_work.ENGINE` /
  `unit_of_work.SESSION_FACTORY`, y `get_session()` lee esos globales del módulo. Cualquier
  extracción de un `engine.py` debe actualizar `conftest` en el mismo cambio, o el
  monkeypatch de tests dejará de tener efecto (semántica de reasignación de globales entre
  módulos).
- **God files**: `sentinel/managers.py` (~2.000 líneas, 5+ clases: `ScanManager` base,
  `Nmap/Nikto/OpenVASScanManager`, `TracerouteManager`, `SentinelReportManager`,
  `ProgramedScanManager`), `users/managers.py`, `iris/managers.py`, `aegis/managers.py`
  (~1.000 cada uno).
- **Timestamps mezclados**: `datetime.utcnow()` (naive, deprecado en 3.12+) conviven con
  `datetime.now(timezone.utc)` (aware). Los modelos y el scheduler comparan **naive**, por
  lo que un reemplazo global a *aware* rompería comparaciones si no se audita a fondo.
- **Repetición de "assert ownership"**: `assert_document_ownership`, `_assert_list_ownership`,
  `_assert_campaign_ownership`, `assert_analysis_ownership` repiten el patrón "get + comparar
  `user_id` + misma excepción anti-enumeración" en cuatro módulos.

## Diseño propuesto

### 1. Separar el engine/session-factory de `UnitOfWork` (rompe el ciclo)

Extraer a `API/src/modules/infrastructure/engine.py`: `ENGINE`, `SESSION_FACTORY`,
`initialize`, `get_session`, `warmup`, `close_all`. Quedaría la cadena de dependencias
lineal y sin ciclo:

```
engine.py            (sin dependencias internas)
  └── session.py     (get_db_session; importa de engine)
        └── unit_of_work.py  (UnitOfWork; ya puede importar session en el top)
```

Para no tocar los ~20 importadores existentes (`from …unit_of_work import close_all/get_session/…`),
`unit_of_work.py` re-exporta desde `engine.py`. **Riesgo real**: los globales `ENGINE`/
`SESSION_FACTORY` se reasignan en `initialize()` y en `conftest.py`; con la extracción,
`get_session()` debe leerlos desde `engine.py` y `conftest.py` debe monkeypatchear
`engine.ENGINE`/`engine.SESSION_FACTORY` (no `unit_of_work.*`). Este cambio debe hacerse en
un solo commit junto con `conftest`. De paso: subir los imports a media altura al top y
eliminar el cálculo muerto de `elapsed` en `initialize()`.

### 2. Convención única de acceso a datos (elimina la dualidad uow/session)

Hacer explícita y verificable la separación lectura/escritura. Opción recomendada:

- **Escrituras**: siempre `with UnitOfWork() as uow: Repo(uow)…` (+ `commit_for_handoff()`
  cuando sigue un `submit`). Sin cambios respecto a hoy.
- **Lecturas**: sustituir el `Repo(session=get_db_session())` disperso por un helper
  explícito (p. ej. `read_repo(RepoCls)` o un `@contextmanager reading()`), de modo que el
  intento de escribir por esa vía sea obvio en la revisión. El helper documenta que la
  sesión es la ambiental (request o thread-local) y que **no** demarca transacción.

Es un cambio mecánico pero disperso por todos los managers, de ahí que vaya por fases
(módulo a módulo) con la suite como red.

### 3. Descomponer los god files

Convertir cada `managers.py` grande en un paquete `managers/` con un fichero por manager,
manteniendo `managers/__init__.py` re-exportando los nombres públicos para no romper
imports ni el registro de entry points de la cola. Prioridad por tamaño:
`sentinel/managers.py` → `managers/{scan,nmap,nikto,openvas,traceroute,reports,programed}.py`;
luego `iris`, `aegis`, `users`.

### 4. Unificar "assert ownership"

Un helper genérico (en `shared/`) que reciba repo/entidad, `user_id` y la excepción a
lanzar, preservando la respuesta idéntica para "no encontrado" y "no es tuyo"
(anti-enumeración). Sustituir las cuatro implementaciones.

### 5. Normalizar timestamps

Auditar todas las comparaciones de fechas (scheduler, `next_run_at`, cachés de traceroute)
y migrar de forma consistente a *aware* UTC (`datetime.now(timezone.utc)`), o dejar
explícitamente todo *naive* con un helper `utcnow_naive()`. **No** hacerlo como reemplazo
ciego: el riesgo es mezclar naive/aware en un `>` y provocar `TypeError` en runtime.

## Fases

- **Fase 1 — infraestructura (bajo riesgo, alto valor):** extracción de `engine.py` +
  actualización de `conftest` + limpieza de imports/código muerto. Verificable 100% con
  `pytest` (SQLite).
- **Fase 2 — convención de acceso a datos:** introducir el helper de lectura y migrar
  módulo a módulo (`acheron` → `iris` → `aegis` → `sentinel` → `users`), un commit por
  módulo, corriendo la suite entre cada uno.
- **Fase 3 — descomposición de god files:** empezar por `sentinel/managers.py`; validar que
  el registro de `QueueRegistry` y los entry points `execute_*` siguen siendo picklables
  por referencia tras el movimiento.
- **Fase 4 — assert ownership + timestamps:** cambios pequeños pero transversales, al final
  para no entorpecer los anteriores.

## Archivos clave

- `API/src/modules/infrastructure/{unit_of_work.py,session.py,retry.py}` + nuevo `engine.py`
- `API/tests/conftest.py:175-176` (monkeypatch de los globales del engine)
- `API/src/modules/{sentinel,iris,aegis,users}/managers.py` (dualidad + descomposición)
- `API/src/modules/shared/` (helper de ownership; posible hogar del helper de lectura)

## Fuera de alcance / no-objetivos

- No se toca la API pública de `UnitOfWork` (`with UnitOfWork() as uow` y `uow.session`
  siguen funcionando).
- No se cambia el modelo de ejecución de la cola (RQ + threads) ni el contrato `ITaskQueue`.
- El servidor sigue asumiendo Linux; la verificación de este refactor se apoya en `pytest`
  (SQLite) y no en ejecución real de escaneos.

## Verificación (por fase)

- **Fase 1:** suite completa verde; test específico de que `conftest` sigue inyectando el
  engine de SQLite (los tests de integración arrancan) y de que `close_all()` entre jobs
  resetea la sesión (ya cubierto por `tests/integration/test_infrastructure_sessions.py`).
- **Fase 2:** por cada módulo migrado, sus tests de integración (`test_<módulo>.py`) siguen
  pasando; revisión de que ninguna lectura quedó capaz de escribir accidentalmente.
- **Fase 3:** import smoke test (`create_app()` arranca y registra todos los blueprints) +
  un job encolado y ejecutado de forma síncrona por cada categoría.
- **Fase 4:** tests de propiedad/autorización existentes por módulo (mismo 404 para "no
  encontrado" y "no es tuyo").
