# La Guía del Proyecto — Ellysia

Documento maestro del repositorio. Es la **única** fuente de verdad operativa y arquitectónica:
`AGENTS.md` apunta aquí, `README.md` cubre solo la superficie pública (referencia de endpoints) y
`CONVENCIONES.md` fija dónde y cómo se crea cada pieza de código.
Si algo de aquí contradice a un documento de `plans/`, manda el código; `plans/` describe
intenciones y auditorías fechadas, no el estado actual.

Verificado contra el código el **2026-08-29** (rama `v0.5.11`, `appVersion` 0.5.10).

Comentarios y docstrings del codebase están en **castellano**; al editar, sigue el idioma del
fichero que tocas.

---

## Plataforma

La API asume **Linux**: Nmap, Nikto y Nuclei son nativos de Linux y no hay puente para Windows en
el código. El checkout vive en Windows y ahí funcionan los tests y el build del SPA, pero **no**
levantar el servidor: usa **WSL** (`wsl` → `cd API && python run.py`) o `docker compose`.

Los subprocesos de escaneo se lanzan con `start_new_session=True`, de modo que la cancelación mata
el árbol completo de descendientes vía `psutil`.

---

## Comandos

### API (Python / Flask) — desde `API/`
```bash
pip install -r requirements.txt -r requirements-dev.txt

python run.py                                    # API en 0.0.0.0:5000 (Linux/WSL/Docker)
python run.py --with-worker                      # + worker RQ como subproceso
python -m src.modules.system.taskqueue.worker    # worker RQ suelto — OBLIGATORIO para tareas async

pytest                                           # suite completa + cobertura (SQLite, servicios externos mockeados)
pytest -n auto --no-cov                          # en paralelo (pytest-xdist) y sin cobertura, como la CI
pytest -m unit                                   # solo unitarios (sin app, sin BD)
pytest -m integration                            # integración (arranca create_app + cliente HTTP de test)
pytest tests/integration/test_oauth.py -q
pytest tests/integration/test_oauth.py::TestX::test_y

pylint src                                        # config en API/.pylintrc
```
CI: `.github/workflows/tests.yml` ejecuta `python -m pytest -q -m "not oracle" -n auto --no-cov`
y las suites del SPA en los PR hacia `main`, las `vX.Y` y `proyecto/**`, y en el push a `main`
(la puerta del despliegue). En un PR, cada job se salta si no cambia nada de lo que lee.
También hay `tests-postgres.yml` (solo en PR que tocan `API/`), `lybra-bench.yml` (de noche, solo
si el motor cambió), `deploy.yml` y `landing.yml`.

Algunos tests usan `xfail(strict=True)` para documentar bugs reales: cuando el bug se arregla el
test pasa a XPASS y **hay que quitar el marcador**. La adaptación a SQLite y los mocks viven
**solo** en `tests/`; nunca modifiques `src/` para acomodar un test.

### Migraciones (Alembic) — desde `API/`
```bash
alembic revision --autogenerate -m "describe change"   # tras editar un model.py
alembic upgrade head        # se aplica también sola en cada arranque de run.py
alembic downgrade -1
alembic current / history
```

### SPA (Vue 3 + Vite) — desde `web/app/`
```bash
npm install
npm run dev            # :5173, proxya /oauth,/themis,/aegis,... a Flask :5000
npm run build

npm run test:acheron   # interop cripto + CRUD + sync del cliente de bóveda
npm run test:hygeia    # formato + matemática de gráficas
npm run test:polling   # composable usePolling
npm run test:toast     # store de toasts
npm run test:quiz      # barajado del quiz de Aegis
npm run test:logs      # transporte de logs
```

### Docker (desde la raíz)
```bash
docker compose --profile dev up -d        # infra: postgres(15432), redis(6379), ollama
docker compose --profile container up -d  # stack completo: API, worker, web
# GPU: añade -f docker-compose.gpu-nvidia.yml (o .gpu-intel.yml / .gpu-amd.yml)
```
`ollama` está **fuera** del perfil `container` a propósito: por defecto `scribe` usa OpenAI, y
Ollama es opcional.

---

## Arquitectura

Monorepo con tres entregables:

- **`API/`** — backend REST Flask (área principal de trabajo). Entrada: `run.py` → `create_app()`.
- **`web/`** — SPA Vue 3 en `web/app/` (Vite + Pinia + Vue Router), más el **Caddy** que la sirve,
  proxya la API y gestiona TLS por su cuenta (`web/Caddyfile`).
- **`landing/`** — sitio estático de marketing, publicado a `gh-pages` por `.github/workflows/landing.yml`.
  Sin build, sin acoplamiento con los otros dos.

El cliente Android y su motor Java `AcheronCore` viven en un repositorio aparte
([SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile)) y consumen `/acheron` por HTTP.

**`API/` y `web/` están juntos a propósito.** Comparten un despliegue (un `docker-compose.yml`, un
Caddy que proxya a `Ellysia-API:5000` por nombre de contenedor) y un contrato que solo un repo
único puede verificar: los matchers `@api` y `@spa_bajo_prefijo_api` de `web/Caddyfile` tienen que
seguir a `run.py::_register_blueprints` y al router del SPA.
`API/tests/unit/test_caddy_api_routes.py` lo ata — un test en `API/` que lee ficheros de `web/`,
imposible si se separan. También fija el **orden** de los dos bloques `handle`, que en Caddy es
toda la regla de precedencia.

**Assets de marca: el SPA es la fuente de verdad** (`web/app/src/assets/images/`). Cuando un
informe de la API necesita una imagen, se copia ese fichero al módulo que lo usa
(`API/src/modules/features/hygeia/resources/hygeia-logo.png` es el patrón: reescalado para su uso
real, con un comentario que dice por qué). No se replica el árbol de assets en `API/`; esa copia
existió, pesaba 18 MB, era idéntica byte a byte, iba dentro de la imagen Docker y no la
referenciaba nada.

### Punto de entrada

`API/run.py` → `create_app(fresh_db_init, start_scheduler, run_migrations)`, en este orden:

1. `configure_logging()`, Flask + `ProxyFix`
2. CORS y rate limiter (backend Redis; cabeceras de cupo activadas)
3. Config de OpenAPI / Flask-Smorest (`API_VERSION` ← `CR.get_app_version()`)
4. `_register_blueprints`, error handlers, conditional GET, auditoría de request
5. `_init_db()` si `CREATE_DATABASE` (**destructivo**) — si no, `_run_migrations()`
6. `unit_of_work.initialize()` + `warmup()`
7. Sesión por request: `before_request(init_request_session)` / `teardown_request(shutdown_request_session)`
8. `_configure_scheduling()` — reconcilia trabajo huérfano y arranca los schedulers (solo API, no workers)
9. `ping_redis()` — health check
10. En `__main__`: handlers SIGTERM/SIGINT → apagado ordenado

### Blueprints registrados (`run.py`)

`/system` · `/oauth` · `/users` · `/plans` · `/organizations` · `/themis` · `/acheron` · `/aegis`
· `/iris` · `/hygeia`

Son **diez**. Añadir uno obliga a tocar también `web/Caddyfile` y `web/app/vite.config.js`
(el test de Caddy cubre el primero).

### Layout de un módulo (`API/src/modules/`)

Módulos de feature: `themis`, `iris`, `aegis`, `acheron`, `hygeia` (bajo `features/`).
Módulos transversales de dominio: `users`, `accounts` (planes, organizaciones, suscripciones,
cuotas), `system`.

```
endpoints.py      # Blueprint Flask-Smorest; auth + validación de schema, cero lógica de negocio
managers.py       # lógica de negocio; acceso a BD SOLO vía UnitOfWork + repositorio
repositories.py   # acceso a datos (extiende infrastructure/base_repository)
model.py          # modelos SQLAlchemy (base en shared/_model.py)
schemas.py        # schemas Marshmallow — las claves JSON son camelCase
services/         # helpers internos del módulo (escáneres, parsers, scheduling, informes)
```

Qué entidad le toca a cada pieza, qué puede importar a qué y dónde van los helpers compartidos:
[`CONVENCIONES.md`](CONVENCIONES.md) §3–§6.

Cuando `managers.py` se hace grande pasa a ser **paquete** `managers/` con un `__init__.py` que
reexporta la superficie pública (así ningún import externo cambia). Estado actual:

| Módulo | Managers |
|---|---|
| `themis` | paquete: `scan.py`, `nmap.py`, `nikto.py`, `nuclei.py`, `lybra/{engine,sources}.py`, `reports.py`, `traceroute.py`, `programed.py`, `scan_folder.py`, `scan_history.py`, `authorized_target.py`, `kb_sync.py` |
| `iris` | paquete: `analysis.py`, `reports.py`, `mailbox.py`, `notifications.py` |
| `aegis` | paquete: `pills.py`, `campaigns.py`, `org_profile.py` |
| `accounts` | paquete |
| `hygeia`, `acheron` | fichero único `managers.py` |

Lo mismo con `themis/services/reports/`, que es paquete (`base.py`, `creator.py`, `findings.py`,
`nmap.py`, `nikto.py`, `lybra.py`, `nuclei.py`).

### Módulos transversales

- **`infrastructure/`** — `UnitOfWork` (frontera transaccional), `base_repository`,
  `document_repository`, singletons de engine/sesión, helpers de scheduling y de reintento.
  UnitOfWork **no** posee la sesión: el ciclo de vida vive en los dos bordes —
  `teardown_request` para HTTP, `job_context`/`Scheduler.execute` para trabajo de fondo. En una
  request `__exit__` es un no-op (el teardown commitea, una sola transacción atómica); en un
  contexto de fondo commitea al salir limpio y hace rollback si hay error. Nunca gestiones
  sesiones fuera de los repositorios.
- **`shared/`** — modelo base, excepciones, `handle_exceptions`, rate limiter, `Document` base,
  `DocumentManager`, `assert_owned`, cripto, white-label.
  **Cifrado en reposo: siempre `EncryptedText`, nunca a mano.** Un secreto que la aplicación
  necesite poder leer se declara como `Column(EncryptedText(purpose="..."), ...)` y punto; en
  Python se lee y se escribe en claro, y lo cifrado es la fila. Llamar a `encrypt_at_rest`/
  `decrypt_at_rest` desde un manager es el patrón viejo: convivieron los dos y quien añadía un
  campo sensible no tenía forma de saber cuál imitar. `tests/unit/test_shared_crypto.py` ata las
  dos mitades — qué columnas están cifradas y con qué `purpose`, y que no reaparezca ninguna
  llamada manual en `src/`. Cada `purpose` tiene su clave (`<PURPOSE>_ENCRYPTION_KEY` en `.env`).
  Como el descifrado pasa a ocurrir al cargar la fila, los secretos que la mayoría de las
  consultas no miran se declaran además `deferred`.
- **`tools/scribe/`** — capa de estrategias enchufables de **generación IA** (Ollama / OpenAI /
  Google). El consumidor le pasa entradas; scribe no sabe nada de ellas. Estrategia elegida por
  módulo en `SecOpsConfig.json` → `tools.scribe.modules`.
- **`tools/herald/`** — capa de estrategias enchufables de **envío de correo** (relay SMTP), misma
  filosofía. Elegida por módulo en `tools.herald.modules`. La usan las campañas de Aegis.

Ambas factories despachan por registro (`ModelStrategy._registry` / `EmailStrategy._registry`), no
por cadenas de `if/elif`.

### TaskQueue (RQ + Redis) — `system/taskqueue/`

Sustituye a la cola en proceso legada. Los jobs persisten en Redis (sobreviven a reinicios de la
API) y corren en un **proceso worker separado de la API**; dentro de él, cada job ocupa uno de
los `max_workers` hilos (`SimpleWorker` de RQ, sin `fork` — `worker.py` explica por qué).

Ficheros clave: `task.py` (dataclass `Task` + enum `TaskStatus`), `queue.py` (singleton `TaskQueue`
con backend RQ+Redis), `worker.py` (entrada del worker), `tracking.py` (`TaskTrackingMixin`).

- Enviar: `TaskQueue.get_instance().submit(func, name=, category=, external_id=, args=, timeout=)`.
- Los puntos de entrada son `@staticmethod` en el manager de cada módulo (p. ej.
  `NmapScanManager.execute_nmap_scan`) — picklables por referencia, sin estado ligado; delegan en
  el cuerpo del job (patrón `execute_*` como costura → cuerpo en la función de módulo `_run_*`).
  Cuándo encolar por la outbox (`build_dispatch` + `OutboxDispatcher`) y cuándo con `submit()`
  directo, y la receta completa: [`CONVENCIONES.md`](CONVENCIONES.md) §7.
- **Categorías**: `themis.scan`, `themis.report`, `themis.traceroute`, `aegis.generate`,
  `aegis.campaign`, `iris.analyze`, `iris.ai_summary`, `iris.report`, `iris.ingest`,
  `iris.notify`, `hygeia.notify` (+ `default`). Cada módulo las da de alta en su `__init__.py` con `QueueRegistry.register(...)`;
  los workers escuchan en colas por categoría.
- **`external_id`**: el prefijo lo declara el manager en `EXTERNAL_ID_PREFIX` (`scan:`,
  `themis-doc:`, `themis-traceroute:`, `aegis-doc:`, `aegis-campaign:`, `iris-analysis:`,
  `iris-doc:`, `iris-mailbox-sync:`, `iris-phishing-notify:`) y `TaskTrackingMixin.external_id_for`
  lo compone. No lo escribas a mano.
- **Cancelación** cooperativa: pone la clave Redis `taskqueue:cancel:{job_id}`; los workers la
  sondean vía `_Task.wait(cancel_check=...)`. **Progreso** por `job.meta["progress"]`.
  **No hay** callbacks `on_cancel`/`on_complete`/`on_error` (se eliminaron).
- Los workers arrancan con el contexto de aplicación Flask empujado (las sesiones de BD funcionan).
- Superficie REST de administración en `/system/tasks/*`.

### Scheduling (APScheduler)

Cinco schedulers, uno por dominio, arrancados desde `run.py::_configure_scheduling()`:
`ThemisScheduler`, `HygeiaScheduler`, `IrisMailboxScheduler`, `AccountsScheduler`, `UsersScheduler`.
No comparten instancia a propósito (no acoplar módulos hermanos solo por compartir mecanismo),
pero todos usan el helper común `@scheduler_job` de `infrastructure/scheduling.py`, que aísla
excepciones y libera la sesión con `close_all()` en el `finally`.

En Themis, `_build_trigger` es la fuente **autoritativa** de "cuándo dispara";
`calculate_next_run` delega en ella (antes eran dos implementaciones —APScheduler y croniter—
que podían divergir en silencio). `tests/unit/test_scheduling_semantics.py` lo fija.

### Auth

OAuth 2.0 + JWT (PyJWT). `POST /oauth/token` con `{"grantType":"password", ...}`.
Los endpoints protegidos exigen `Authorization: Bearer <token>`; roles y atributos se aplican con
`require_oauth_token`, `require_role(minimum_role)` y `require_attributes(...)`
(`users/services/permissions.py`). **Las claves JSON son camelCase.** Contraseñas con Argon2id.

> Los **únicos** endpoints sin autenticar de toda la API son `GET/POST /aegis/quiz?t=<token>`
> (quiz público de concienciación). El token opaco es la identidad entera: no añadas auth ahí, y
> no filtres nada más allá del único destinatario al que pertenece el token.

### Themis — escaneo

- Cuatro escáneres: **Nmap**, **Nikto**, **Nuclei** y **Lybra** (motor propio).
- `ScanType` (`themis/model.py`) es **la** fuente de verdad del catálogo. Todo lo demás se deriva
  de ella o de un registro: `CR.THEMIS_SCANNERS`, los `validate.OneOf` de los schemas, los
  contadores de `repositories.py`, `ScanManager._registry`, `PrintingStrategy._registry`,
  `ScanLoggerFactory`. `tests/unit/test_config_shape.py::test_every_scan_type_is_fully_registered`
  comprueba que cada miembro del enum está dado de alta en los cuatro sitios que lo hacen
  funcionar. **Lybra no tiene logger CSV a propósito** (no pasa por `_log_to_csv`).
- Los escaneos programados despachan por ese mismo registro: cada manager declara
  `SCHEDULED_REQUIRED_ARGS` / `SCHEDULED_OPTIONAL_ARGS` junto a su `run_scan`, y el scheduler los
  usa. No hay tabla de despacho paralela.
- `themis/lybra/` es la capa pura del motor: **libre de ORM y de efectos de red**
  (L0 transport / L1 fingerprinting / L2 engine+checks / L3 kb+correlation).
  `tests/unit/test_lybra_package_invariants.py` congela esa invariante. La parte que sí toca ORM y
  red vive en `themis/managers/lybra/`.

### Aegis

- `AegisManager` (píldoras) genera con `scribe`; cada píldora lleva 2–3 preguntas de quiz
  (`AegisQuizQuestion`), editables por `PUT /aegis/document`.
- **Campañas** (`aegis/managers/campaigns.py`): envían píldora+quiz a una `DistributionList` por
  correo. `launch_campaign()` congela el quiz en `Campaign.questions_snapshot` (para que editar la
  píldora después no afecte a una campaña en curso) y acuña un `secrets.token_urlsafe(32)` por
  destinatario (`CampaignRecipient.token`) — **nunca derivado del email**, y no reutilizable una
  vez `status="completed"` (lo garantizan tanto el chequeo de estado como el
  `UniqueConstraint(campaign_recipient_id, question_position)` de `CampaignAnswer`, para la carrera
  de peticiones concurrentes). El envío va en segundo plano con `herald`, no con `scribe`.

### Puertos

| Servicio | Puerto | Nota |
|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | el contenedor publica `127.0.0.1:15432` → `5432` interno |
| Redis | 6379 | |
| Ollama | 11434 | opcional |
| SPA (dev) | 5173 | Vite |

---

## Configuración

Por capas, leída con `system/config_reading.py` (importado como `CR`):

1. **`API/SecOpsConfig.json`** — base: prompts, directorios, defaults de taskqueue, selección de
   estrategia `tools.scribe`/`tools.herald`, tuning no secreto de JWT (`general.security.jwt`),
   `appVersion` (→ `CR.get_app_version()`, hoy `0.5.10`).
2. **`API/.env`** — variables de entorno que **sobrescriben** el JSON. Obligatorio para secretos:
   `JWT_SECRET_KEY`, credenciales de BD / Redis / SMTP / OpenAI, `PUBLIC_WEB_URL`.
3. **`.env` de la raíz** — solo para docker-compose (credenciales Postgres/Redis); la API no lo lee.

Los cambios en `SecOpsConfig.json` requieren reiniciar la app (los valores se cachean) salvo que se
apliquen con `PUT /system`, que refresca el proceso de la API en caliente. El **worker** es un
proceso aparte y se quedaría con su config de arranque, así que relee el fichero antes de cada job
cuando cambia el mtime (`CR.reload_if_changed()` en `_ThreadSafeWorker.perform_job`) — una edición
guardada desde ConfigView llega al siguiente job de fondo sin reiniciar nada. `max_workers` es la
excepción: solo se lee al arrancar el worker.

`SecOpsConfig.json` tiene exactamente cinco entradas raíz; mete las claves nuevas bajo la que
corresponda, no en la raíz:

```
appVersion                       # obligatoria en la raíz; la lee create_app()
general/         publicUrl, directories (tempdir/logdir), security (argon2/jwt/mfa)
infrastructure/  database, redis, taskqueue
tools/           scribe (IA), herald (correo)   # los nombres coinciden con src/modules/tools/
features/        themis, aegis, iris, hygeia    # uno por módulo de feature
```

Cada escáner de Themis tiene su bloque en `features.themis.scanners.<tool>` (`nmap`, `nikto`,
`lybra`, `nuclei`), todos con `prompts` + `colorPalette`. `CR.THEMIS_SCANNERS` se deriva de
`ScanType`, así que no puede desincronizarse por olvido; `tests/unit/test_config_shape.py` ata el
enum al JSON.

### Leer config: bloques, no getters

Los valores se leen con **dataclasses congeladas atadas a una rama del árbol** vía `@config_block`,
no con un getter por valor:

```python
CR.nuclei_config().rate_limit          # features.themis.scanners.nuclei.rateLimit
CR.hygeia_limits().max_body_bytes      # features.hygeia.limits.maxBodyBytes
```

- Los nombres de campo van en `snake_case` y mapean solos al `camelCase` del JSON
  (`max_body_bytes` → `maxBodyBytes`). Para las claves que deben conservar otra forma —las que se
  pasan tal cual como kwargs a argon2/SQLAlchemy/redis-py— hay que declararlo:
  `field(default=10, metadata={"key": "pool_size"})`.
- **Los defaults viven solo en el campo.** Antes estaban escritos dos veces (getter + JSON) y
  derivaban.
- Los valores con override por entorno o con resolución propia son una `@property` sobre un campo
  `configured_*`: `CR.general_config().public_url` prefiere `PUBLIC_WEB_URL`;
  `CR.jwt_config().secret` lanza si falta `JWT_SECRET_KEY` (de forma perezosa, para que un
  despliegue sin credenciales de OpenAI siga arrancando).
- Los bloques se cachean y se reconstruyen solos cuando cambia `_configs` (`reload()`,
  `PUT /system`, una config monkeypatcheada en tests) — no hay que invalidar nada a mano.
- Para añadir un bloque: defínelo, añade el accesor y regístralo en `CONFIG_BLOCKS` de
  `tests/unit/test_config_shape.py`.

Siguen siendo funciones planas a propósito: las credenciales solo-entorno (`get_*_environment`) y
las búsquedas parametrizadas por clave en vez de por campo (`get_iris_data`,
`get_iris_scoring_weight`, `get_tool_prompts`) — declararlas como campos obligaría a editar
`config_reading.py` cada vez que se añade una regla.

**Cuidado con el fallo silencioso**: `_cfg()` devuelve el *default* cuando una ruta no resuelve, así
que un prefijo mal escrito desactiva un bloque entero sin lanzar. Cualquier clave que muevas hay
que actualizarla en tres sitios — la ruta del `@config_block` (o la llamada a `_cfg()`) en
`config_reading.py`, la ruta literal en `web/app/src/views/ConfigView.vue`, y
`test_config_shape.py`. `tests/unit/test_config_view_paths.py` convierte la divergencia con el
`.vue` en un fallo de CI (verifica que cada ruta existe **y** que apunta a una hoja).

---

## Convenciones de código

Dónde va cada pieza, qué entidad darle (repositorio, manager, servicio, scheduler, constante o
clave de config), qué puede importar a qué y cómo se nombra todo está en
**[`CONVENCIONES.md`](CONVENCIONES.md)**. Eso incluye la regla de nombres: palabras completas,
funciones con verbo y booleanos con `is_`/`has_`… No se duplica aquí.

---

## Documentación de funciones, clases y métodos

Toda función, clase o método que se genere o modifique lleva **docstring en castellano**, sin
excepción — esto es una extensión de la regla de idioma de la cabecera de este documento, no una
regla nueva y separada. Un docstring incompleto es peor que ninguno: promete una referencia y
luego obliga a leer el cuerpo igualmente.

Estructura obligatoria:

- **Qué hace.** Una explicación clara del propósito, en prosa — no una repetición del nombre
  (`"""Calcula el umbral crítico."""` sobre una función `calculate_critical_threshold` no dice
  nada nuevo; explica *qué* umbral, *a partir de qué* y *por qué* hace falta).
- **Todos los parámetros** (o, en una clase, todos los atributos), cada uno con:
  - su propósito,
  - qué valores acepta (tipo, y si es un conjunto cerrado — enum, `Literal`, cadena con formato
    concreto — cuáles son los valores válidos),
  - el valor por defecto, si lo tiene.
- **El tipo devuelto**, y si puede tomar más de un valor con distinto significado (`None` frente a
  una instancia, un enum con varios miembros, una tupla con estados distintos), qué significa cada
  uno.

Formato (estilo Google, adaptado al castellano):

```python
def calculate_critical_threshold(base_score: float, scan_type: ScanType, multiplier: float = 1.5) -> float:
    """Calcula el umbral crítico de una vulnerabilidad a partir de su puntuación base.

    El umbral resultante decide si un hallazgo dispara notificación inmediata
    (ver `NotificationManager.should_notify`).

    Args:
        base_score: Puntuación CVSS base del hallazgo, en el rango [0.0, 10.0].
        scan_type: Tipo de escaneo que originó el hallazgo (`ScanType.NMAP`,
            `ScanType.NIKTO`, `ScanType.NUCLEI` o `ScanType.LYBRA`); determina qué
            tabla de pesos se aplica.
        multiplier: Factor de ajuste sobre `base_score`. Por defecto `1.5`.

    Returns:
        float: El umbral crítico ya ajustado. Nunca es negativo; si `base_score`
            es `0.0` el resultado es `0.0`.
    """
```

**El docstring describe lo que la función es hoy, no lo que fue.** Frases como «antes esto se
tragaba la excepción», «hasta el cambio X devolvía una lista» o «se reescribió para…» cuentan la
historia del cuerpo, no su contrato: obligan a quien lee a reconstruir una versión que ya no existe
para entender la que tiene delante, y se quedan viejas en cuanto el código vuelve a cambiar. Esa
historia ya está en el mensaje de commit y en la descripción del PR, que es donde se busca.

Lo que sí cabe es el *porqué* de una decisión que hoy no es obvia, escrito en presente: «se captura
aquí y se vuelve a lanzar porque la cola debe ver el trabajo como fallido» explica el código actual;
«antes no se capturaba y la fila se quedaba en `running`» explica el código anterior. Si el pasado
importa de verdad a quien usa la función —datos antiguos que siguen en la base de datos, un formato
que se sigue aceptando por compatibilidad—, va en un bloque aparte y marcado como aviso, no mezclado
con la descripción:

```python
    Warning:
        Los jobs encolados antes de pasar a la outbox traen ``Service`` ya
        construidos en vez de dicts; se aceptan los dos.
```

Esto rige para código nuevo y para funciones/clases/métodos que se toquen al pasar; no obliga a
reescribir en masa lo que ya existe y no se está editando.

---

## Cosas que muerden

- Los `.env` llevan credenciales — nunca los commitees. `API/.env`, `API/src/data/` y `docs/` están
  en `.gitignore`.
- **Solo en el primer despliegue**: `CREATE_DATABASE=True` ejecuta el destructivo `_init_db()`
  (borra y recrea la BD, siembra el usuario root y las filas de Topic). Vuélvelo a `False` después
  o perderás los datos en el siguiente arranque. Los cambios de esquema posteriores van por Alembic
  (se aplican solos al arrancar, sin destruir nada).
- **No ejecutes `CREATE_DATABASE=True` ni reinicies la BD local de desarrollo.** Desde 2026-07-29
  contiene un backfill real de la base de conocimiento NVD/KEV/EPSS (`CveEntry`/`CpeMatch`/
  `KevEntry`/`EpssScore`, ~350k CVEs: el catálogo histórico completo, no una ventana) que costó más
  de una hora bajo el rate limit sin autenticar de NVD. Rehacerlo es tiempo perdido, no un problema
  de corrección — pero no hay motivo para pagarlo dos veces.
- PostgreSQL está en el **15432** en local (el contenedor publica 15432→5432), no en el 5432.
- Las tareas asíncronas **no se ejecutan nunca, en silencio**, si no hay un worker RQ levantado.
- La suite está sellada contra la red: `tests/conftest.py` hace fallar al instante toda operación
  de Redis (`_redis_always_unavailable`) y rechaza cualquier `socket.connect`/DNS inverso fuera de
  loopback (`_no_outbound_sockets`). Un test que intente alcanzar algo real recibe un
  `ConnectionRefusedError` inmediato, no un timeout — mockea la costura, o bindea a `127.0.0.1`
  (loopback sí se permite, que es como funcionan los tests de aiosmtpd). Esto es lo que mantiene la
  suite en ~1 min 50 s; antes, diez tests esperando timeouts eran el 75 % del tiempo.
- La versión de la API sale de la config: `create_app()` la lee con `CR.get_app_version()` desde
  `appVersion` en `SecOpsConfig.json` (hoy `0.5.10`). **No está hardcodeada** — y ojo, la rama
  puede ir por delante del `appVersion` del fichero.
- `features.themis.areLocalIpsAllowed` viaja en `false`, y hay un test que lo ata
  (`test_the_anti_ssrf_defence_ships_enabled` en `tests/unit/test_config_shape.py`). Estuvo en
  `true` hasta 2026-09-01 —y por tanto la defensa anti-SSRF, apagada en producción— sin que la
  suite dijera nada: los tests de SSRF fuerzan el valor a `false` con una fixture autouse, así que
  pasaban en verde diga lo que diga el fichero. Comprobar el *comportamiento* y atar el *valor que
  se despliega* son dos cosas distintas, y hacían falta las dos. Para desarrollo local contra IPs
  privadas, ponlo a `true` en tu copia sin commitearlo.
- **SSRF: cada escáner se autovalida.** Nmap, Nikto, Nuclei y Lybra rechazan IPs privadas dentro de
  su propio `run_scan()`, no solo en el endpoint HTTP, así que el flujo programado
  (`scheduling.py` llamando a `run_scan()` directo) también está cubierto. Los cuatro tests
  `test_*_scheduled_flow_rejects_private_ip` (`tests/integration/test_themis.py`) lo mantienen
  cierto. El único modo que **no** valida, por diseño, es `ExternalPayload` de Lybra
  (`managers/lybra/sources.py`, `probes_target_network = False`): analiza una lista de servicios que
  el llamante ya resolvió sin tocar la red, así que no hay objetivo que rechazar — los corroboradores
  profundos desde ese modo exigen en su lugar una entrada explícita de objetivo autorizado
  (`deep_requires_authorization = True`).
- OpenVAS se retiró del producto. Si encuentras referencias en `plans/`, están caducadas.
- Hay **un solo** `TaskStatus` en el repo (`system/taskqueue/task.py`). El enum duplicado que
  Themis tenía en `services/tasks.py` desapareció; ese fichero lo importa del canónico.

### Mantenimiento del README

El `README.md` de la raíz es el contrato público del repositorio (superficie de la API, categorías
de TaskQueue, perfiles de Docker, puertos, config, inventario de módulos) y se desactualiza solo si
nada lo obliga a estar fresco. Dos reglas:

- **Revisa `README.md` al terminar cualquier tarea.** Si la sesión cambió algo visible para el
  usuario —endpoints nuevos o modificados, categorías o `external_id` de TaskQueue, capacidades de
  un módulo, migraciones, claves de config, variables de entorno, perfiles/puertos de Docker,
  versiones— actualiza el README antes de dar la tarea por terminada. La revisión es parte de
  terminar, no una tarea aparte.
- **Todos los cambios del README van en un único commit.** Nunca los mezcles con commits de
  feature/fix ni los repartas entre varios: haz `git add README.md` por separado y commitéalo solo
  (`docs(readme): keep in sync with ...`), aunque la sesión abarque varios commits. Si ya hay un
  commit de README en la sesión, mete ahí las actualizaciones posteriores en vez de abrir otro.
- **Ninguna referencia a issues ni a PRs, ni en el README ni en el código.** Una frase como
  «decisión tomada por el issue #N», «ver `plans/x.md`» o un `(#N)` al final de un docstring dice
  *de dónde salió* una decisión, no la decisión — y un número de issue envejece peor que el código:
  quien lo lee lo hereda para siempre aunque el issue se cierre, se renumere en otro repo o deje de
  ser accesible. La prohibición cubre el README, los docstrings, los comentarios y los tests.
  El *porqué* de una decisión va **en el código**, lo más cerca posible de lo que decide — un
  comentario junto a la línea, o el docstring de la función/clase si la decisión afecta a toda su
  lógica —, pero **explicado con sus propias palabras y sin el número**: tiene que entenderse sin
  abrir el issue. El sitio de las referencias a issues y PRs es el mensaje de commit (`Refs #N`) y
  la descripción del PR. Quedan referencias antiguas en el código (`# ... (#118)` en
  `themis/services/analyzers.py`, `(Issue #118)` en `tools/scribe/inputs.py`, varias `#551`):
  no son un patrón a imitar, y se quitan al tocar la función que las lleva.

---

## Ramas y versiones

- **`main`** — producción. Solo recibe una rama de versión cuando esa versión sale. Es la rama
  por defecto del repositorio y la única desde la que despliega `deploy.yml`.
- **`vX.Y`** (`v0.5`, luego `v0.6`, …) — la línea de trabajo de una versión. Es la rama de
  integración: el trabajo del día a día sale de aquí y vuelve aquí por PR.
- **Ramas de trabajo** — `<tipo>/<módulo>/<descripción>` (`refactor/themis/deep-flag-naming`).
  Salen de la `vX.Y` vigente, vuelven a ella por PR, y se borran al mergear.

**No hay rama `develop`/`develope`.** Existió, y se retiró: no aportaba ningún commit propio
(estaba contenida entera en la rama de versión), se rodeaba en 9 de cada 12 merges, y duplicaba
el papel que la `vX.Y` ya cumple. Si ves una referencia a ella en algún sitio, está caducada.

El CI (`tests.yml`) corre en los PR hacia `main` y hacia las `vX.Y`, y en el push a `main`. Un
push a una rama de versión no lo dispara: el PR ya probó el merge de su rama con la base, y
repetirlo al mergear solo gastaba minutos de Actions. `deploy.yml` solo despliega tras el push
a `main`.

> Ojo al desfase: la `vX.Y` puede ir por delante de `main` con cosas sin publicar, y el
> `appVersion` de `SecOpsConfig.json` puede ir por detrás del nombre de la rama. Ninguna de las
> dos cosas es un error, pero conviene mirarlas antes de afirmar «esto ya está en producción».

## Cómo se escriben los PR, los issues y sus comentarios

Se escriben para **alguien que no conoce el módulo que se está tocando**. Quien abre un PR de
Themis puede no saber qué es Lybra, qué hace el runtime de checks o qué significa `feed_version`, y
una descripción comprimida sólo la entiende quien ya sabía la respuesta: no informa a nadie, es un
recordatorio para el autor disfrazado de documentación.

Tres reglas concretas:

- **Primero el problema en lenguaje llano, después el símbolo.** Antes de nombrar
  `xfail(strict=True)`, `NetworkSession.exchange` o «bulk string RESP», di qué es y por qué importa
  aquí. «Un *bulk string* de Redis es una respuesta que empieza por una línea con la longitud del
  contenido, así que la primera línea no trae datos» cuesta una frase y ahorra el viaje al código.
- **Nada de taquigrafía ni de explicaciones planas.** Una tabla o una lista siguen valiendo, pero
  cada fila necesita su frase de contexto; una fila que sólo repite el nombre del test no explica
  por qué falla.
- **Vale alargarse; no vale dar por supuesto.** El coste de leer un párrafo de más es mucho menor
  que el de reconstruir el contexto entrando al código.

Esto aplica a los cuerpos de PR, a los issues que se abran y a los comentarios de seguimiento. No
aplica al **código**: ahí manda la concisión de siempre (nombres completos, comentarios que
explican el *por qué*, no el *qué*).

## Deuda técnica

`plans/deuda-tecnica-y-calidad.md` es la auditoría de origen (fechada 2026-08-03) y `plans/` en
general describe intenciones, no estado. **El estado vivo está en el proyecto de GitHub
["Deuda técnica y calidad"](https://github.com/orgs/ProjectEllysia/projects/2)**, un issue por
punto. A 2026-08-29, 38 de los 41 puntos están cerrados; quedan `A11` (endpoint
`GET /system/config-schema`, aparcado con argumentos en el propio documento), `C1` (residuo de
variables de comprensión de una letra) y `C2` (falta renombrar `deep` → `is_deep_analysis`).

---

## Herramientas

### Exploración de código
- Prefiere **Serena** para navegación semántica, búsqueda de símbolos, referencias y refactor
  estructural cuando aporte ventaja clara.
- Usa las herramientas nativas de búsqueda/lectura/git cuando encajen mejor: texto exacto,
  configuración, logs, ficheros que no son código, historia del repositorio.
- Evita leer ficheros enteros cuando basta una búsqueda dirigida.

### Documentación externa
- Usa **Context7** al implementar o depurar contra librerías, frameworks o APIs externas.
- Comprueba antes la versión real de la dependencia en el proyecto.
- Úsalo con criterio: no consultes documentación cuando el código del proyecto ya da la respuesta.
