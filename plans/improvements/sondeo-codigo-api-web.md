# Sondeo de código — Ellysia (API Flask + SPA Vue)

> Auditoría técnica realizada el 2026-07-10. Alcance: backend `API/` y SPA `web/app/` (módulo móvil fuera de alcance). El documento original era solo informativo; desde el 2026-07-11 se está ejecutando por fases (ver Progreso abajo) — cada ítem se reverifica contra el código actual antes de tocarlo, porque el código se ha seguido moviendo desde el sondeo.

## Progreso de ejecución

**Fase 1 — Quick wins críticos: hecha (2026-07-11), sin commitear.** Los 6 hallazgos se reverificaron contra el código actual (todos seguían presentes tal cual el sondeo los describía) y se corrigieron:

- **B1** (`nmap.py`) — ahora `raise`a en el except en vez de devolver `scan_id` sin asignar, igual que Nikto/OpenVAS.
- **B2** (`toastStore.js`) — el parámetro de `show()` ya no hace *shadowing* del ref `type`; se renombró a `variant` y se asigna `type.value`. Verificado con un script Node aislado (Pinia sin navegador): la variante cambia en cada llamada.
- **B5** (`IrisView.vue`) — `onBeforeUnmount` ahora llama también a `store.stopPolling()`, no solo limpia `rejectTimer`.
- **S1** (SSRF Nikto) — nuevo `validate_nikto_target()` en `endpoints.py`: resuelve el target a IP (`normalize_target`) y rechaza IPs privadas/loopback/metadata antes de encolar el escaneo. Nikto sigue aceptando hostname/URL (lo necesita para escanear por dominio); solo se valida la IP resuelta.
- **S2** (`SecOpsConfig.json`) — `themis.areLocalIpsAllowed` pasó de `true` a `false`, alineado con el default en código.
- **C3** (OpenVAS un host por escaneo) — la validación (resolución + rechazo de IP privada) se movió de "solo en el endpoint HTTP" a dentro de `OpenVASScanManager.run_scan()`, así que el flujo programado (`scheduling.py::_run_openvas_scan`) también queda cubierto sin duplicar lógica.

Pieza compartida nueva: `parsing.reject_private_ip()` / `ScanManager.reject_private_ip()` — wrapper de una sola IP sobre el guard ya existente (`_reject_private_ips`), para callers que resuelven su propio hostname (Nikto, OpenVAS) en vez de expandir un rango vía `validate_ip`.

**Tests:** suite completa de `API` verde (`pytest --no-cov -q`, WSL). Se ajustó `tests/unit/test_themis_parsing.py` (las pruebas de expansión de formato usaban IPs privadas como fixture y dependían implícitamente del `areLocalIpsAllowed: true` que S2 acaba de quitar; ahora mockean la política explícitamente) y se añadió cobertura nueva: `TestPrivateIpPolicy` (rechazo/permiso por defecto) y, en `tests/integration/test_themis.py`, regresión SSRF para Nikto (loopback + metadata cloud), Nmap (IP privada) y el flujo programado de OpenVAS. Esto cierra parcialmente **T1** para esta zona concreta (SSRF/IP privada); Themis en general ya tenía `test_themis.py` con cobertura de auth/carpetas — el sondeo original decía "sin tests de integración para Themis", lo cual ya no es exacto.

**Fase 2 — Robustez operativa: hecha (2026-07-11), sin commitear.** Los 6 hallazgos se reverificaron (todos vigentes) y se corrigieron:

- **B3** (`tasks.py::OpenVASTask.wait`) — el timeout ahora llama a `self.cancel()` antes de devolver `False`, así que `_wait_for_completion` (hilo aparte) ve `_cancel_event` en su próximo ciclo (≤60s) y llama `stop_task` en OpenVAS, en vez de sondear para siempre. El estado final reportado sigue siendo `TIMEOUT` (no `CANCELLED`), para no confundirlo con una cancelación pedida por el usuario.
- **B4** (race `cancel_scan` vs worker) — nuevo `ScanRepository.update_status_if(scan_id, expected, status)`: UPDATE atómico con `WHERE status IN (...)`, devuelve si la transición ocurrió. `cancel_scan` y el path de finalización en `_execute_scan` ahora usan este CAS en vez de una escritura incondicional — quien pierde la carrera no sobrescribe al otro. Cubierto con tests nuevos (`test_update_status_if_*` en `test_themis.py`).
- **B6** (`irisStore.js` timers de documentos huérfanos) — nueva `stopDocumentPolling()` (limpia todo `documentPollTimers`), llamada desde `onBeforeUnmount` de `IrisView.vue` (junto a B5) y desde `selectAnalysis()` al cambiar de análisis.
- **C1** (sin reconciliación para Iris/Aegis) — nuevo `IrisManager.reconcile_orphaned_analyses()` (+ `IrisAnalysisRepository.get_active_analyses()`), espejo exacto de `ScanManager.reconcile_orphaned_scans`, llamado en `run.py` junto a la de Themis. **Aegis queda deliberadamente fuera de esta pasada**: no usa `TaskTrackingMixin` (construye su `external_id` a mano) y su modelo de campañas es más complejo que un simple pending/running — necesita su propio análisis, no una extensión mecánica de este patrón.
- **C2** (Themis sin polling de estado) — mismo idioma que el polling de traceroute ya existente (`setTimeout` re-encadenado, no `setInterval`): `loadScans(type)` se reprograma a sí misma cada 4s mientras la pestaña activa tenga escaneos pending/running y siga visible (`_isTypeVisible`, cubre los 4 tipos incl. Lybra). `stopScanPolling()` nuevo, llamado desde `onBeforeUnmount` de `ThemisView.vue`. Verificado end-to-end en el navegador real (fetch mockeado): auto-poll mientras hay running, se auto-detiene al llegar a finished, y `stopScanPolling()` cancela el timer pendiente. **No cubre la vista de carpetas** (`ScanFolderView`, otra fuente de datos) — solo la vista 'full', que es donde se lanza y observa un escaneo recién creado.
- **S3** (root/root hardcodeado) — `_init_db()` ahora genera una contraseña aleatoria (`secrets.token_urlsafe(18)`) para el usuario root en vez de `"root"` fijo, y la loguea una única vez (WARNING) al terminar el seed. No se implementó un flujo de "forzar cambio en primer login" (columna nueva + migración + gate en frontend) — se evaluó como una feature aparte, más grande que este fix puntual; la contraseña aleatoria ya cierra el riesgo real (credencial pública/adivinable). No verificable por tests (el path `fresh_db_init=True` solo corre contra Postgres real, la suite usa SQLite con `fresh_db_init=False`) — revisado por lectura + syntax-check.

**Tests Fase 2:** suite completa verde. Nuevos: `test_update_status_if_*` (CAS de B4) y `tests/integration/test_iris_reconciliation.py` (3 tests para C1: huérfano sin tarea → failed, tarea aún pending → se deja, ya terminado → no se toca).

**Pendiente:** Fase 3 (seguridad S4–S9/S11, correctness B7–B12, DRY D1–D3, Q1, T1) y el resto del documento.

## Contexto

El objetivo es una **auditoría técnica completa** del código activo (backend `API/` y SPA `web/app/`) para detectar bugs, incoherencias con situaciones reales de operación (escaneos largos, sin worker, concurrencia, tokens caducados…) y oportunidades de mejora, antes de dar el proyecto por terminado. El resultado se cataloga por **impacto** y por **esfuerzo/tiempo**, evaluado contra **SOLID**, **LEAN** (eliminar desperdicio: código muerto, duplicación, complejidad accidental) y **DRY**.

La auditoría se realizó con 3 exploraciones paralelas (backend, SPA, seguridad/tests). Los 3 hallazgos de mayor impacto se verificaron manualmente sobre el código y están confirmados.

### Leyenda
- **Impacto:** 🔴 Alto · 🟠 Medio · 🟡 Bajo
- **Esfuerzo:** ⚡ Rápido (<2 h) · 🔧 Medio (½–1 día) · 🏗️ Largo (>2 días / refactor)
- **Principio:** Correctness · SOLID · DRY · LEAN · Security

---

## 1. Bugs funcionales (correctness)

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **B1** | `NmapScanManager.run_scan` traga `OSError/RuntimeError` y hace `return scan_id` con la variable **sin asignar** → `UnboundLocalError` que enmascara el error; endpoint devuelve `201` con escaneo huérfano en PENDING. Incoherente con Nikto/OpenVAS que sí `raise`. **(Verificado)** | `themis/managers/nmap.py:66-88` | 🔴 | ⚡ |
| **B2** | Toast: el parámetro `type` hace *shadowing* del `ref` del store; `type = type \|\| ''` reasigna el local y `type.value` **nunca** se actualiza → **todos los toasts se renderizan sin variante** (error/success/​warn idénticos en toda la app). **(Verificado)** | `web/.../stores/toastStore.js:39-47` | 🔴 | ⚡ |
| **B3** | `OpenVASTask.wait`: en timeout marca estado pero **no** dispara `_cancel_event` ni `stop_task` → el hilo de polling sigue consultando OpenVAS indefinidamente y la tarea GMP remota queda viva (fuga de hilo + recurso remoto). | `themis/services/tasks.py:435-472` | 🔴 | 🔧 |
| **B4** | Race `cancel_scan` vs finalización del worker: `cancel_scan` escribe `CANCELLED` tras la señal cooperativa; si el worker marca `FINISHED` en la ventana, se sobrescribe (last-writer-wins entre 2 procesos) → escaneo con resultados mostrado como cancelado, o viceversa. | `themis/managers/scan.py:318-364,473` | 🔴 | 🔧 |
| **B5** | Memory leak: `IrisView` no llama `store.stopPolling()` en `onBeforeUnmount`; el `setInterval(…,2000)` del store (singleton) sobrevive a la navegación → `GET /iris/status` cada 2 s **para siempre**. | `web/.../views/IrisView.vue:184`; `stores/irisStore.js:187` | 🔴 | ⚡ |
| **B6** | Intervalos `documentPollTimers` solo se limpian si el documento llega a `done/error`; documento colgado, análisis borrado o navegación → intervalos huérfanos. No hay `onUnmounted` que recorra el `Map`. | `web/.../stores/irisStore.js:28,364-376` | 🔴 | 🔧 |
| **B7** | `_execute_scan` lee atributos de una instancia ORM **detached** (funciona solo por `expire_on_commit=False`); en el `except` llama `_log_to_csv(fresh_scan=None)` → posible `AttributeError`. Parámetro `scan` muerto (se recarga dentro). | `themis/managers/scan.py:425-486,517` | 🟠 | 🔧 |
| **B8** | Vocabulario de estado incoherente hacia el cliente: `get_scan_status` devuelve `"completed"` mientras `Scan.status` persiste `"finished"`; la misma respuesta expone ambos. | `themis/managers/scan.py:162-167`; `themis/endpoints.py:135-147` | 🟠 | ⚡ |
| **B9** | Race del preview PDF: `handlePreviewPdf` espera **600 ms mágicos** y refresca; la generación es asíncrona (encolada) y suele tardar más → el documento no aparece. Ya existe `pollDocumentStatus` que debería usarse. | `web/.../views/ThemisView.vue:236` | 🟠 | 🔧 |
| **B10** | `setInterval` con callback `async` no esperado (Iris): si `getStatus/getReport` tardan >2 s, se solapan peticiones y puede dispararse `getReport`+`fetchResults` varias veces. El patrón correcto (`setTimeout` re-encadenado) ya existe en traceroute. | `web/.../stores/irisStore.js:187-205,364-375` | 🟠 | ⚡ |
| **B11** | Manejo de error frágil: cuando `apiFetch` devuelve `null`, `res?.json()` corta la cadena y `data` queda `undefined`; la línea siguiente accede a `data.error_description` → `TypeError` (atrapado por `try/catch`, "funciona" por accidente, oculta el error real). | `web/.../stores/themisStore.js:249-251` (patrón repetido) | 🟠 | ⚡ |
| **B12** | `require_attributes` captura `Exception` genérica y responde **500 en vez de 404** ante recurso inexistente (`GET /aegis/status?id=<inexistente>`). Es el único `xfail(strict=True)` abierto de la suite. | `users/services/permissions.py:386-393`; test: `tests/integration/test_aegis.py:25-32` | 🟠 | ⚡ |
| **B13** | Inconsistencia de orden de la pseudo-carpeta "Sin carpeta": `loadFolders` la añade al final, `_getUnfoldered` la pone primera; la inserción de carpetas nuevas depende de esa posición ambigua. | `web/.../stores/themisStore.js:94-101,613-615,683` | 🟡 | ⚡ |

---

## 2. Seguridad

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **S1** | **SSRF:** `start_nikto_scan` pasa `data["target"]` directo a `run_scan` **sin `validate_targets()`** (Nmap/OpenVAS/Lybra sí validan). Nikto acepta hostnames → alcanza `127.0.0.1`, `169.254.169.254` (metadata cloud), hosts internos, y evade por DNS. **(Verificado)** | `themis/endpoints.py:249-264`; `themis/managers/nikto.py:49-78` | 🔴 | ⚡ |
| **S2** | `areLocalIpsAllowed: true` en el JSON **versionado** anula el único guard anti-SSRF (`_reject_private_ips`) del resto de scanners. El default en código es `False`. | `SecOpsConfig.json:1158-1160`; `themis/services/parsing.py:172-180` | 🔴 | ⚡ |
| **S3** | Credencial por defecto **root/root** con `role_root` + **todos** los atributos, sin forzar cambio en el primer login. Activa con `CREATE_DATABASE=True`. | `run.py:493-509` | 🔴 | 🔧 |
| **S4** | Rate limiter con `storage_uri="memory://"` (por-proceso): con varios workers/gunicorn cada proceso tiene su contador → protección de fuerza bruta multiplicada y reseteada en cada reinicio (afecta `/oauth/token`, `/oauth/mfa/verify`). | `shared/_endpoints.py:120-124` | 🟠 | 🔧 |
| **S5** | Sin `ProxyFix`: tras Nginx, rate-limit por IP y logs de auditoría ven la IP del proxy, no la real (todos comparten cubo / IP falseada). | `run.py` (ausente) | 🟠 | ⚡ |
| **S6** | Endpoints públicos **adicionales** al invariante ("solo `/aegis/quiz`"): `GET /acheron/generate-password` y `GET /system/say-hello` sin `@require_oauth_token`. | `acheron/endpoints.py:127-144`; `system/endpoints.py:40-50` | 🟠 | ⚡ |
| **S7** | `PUT /system` (solo `require_role(ADMIN)`, no root) reescribe **toda** la config: un admin puede bajar `security.argon2`, activar `areLocalIpsAllowed`, etc. `GET /system` expone toda la config. | `system/endpoints.py:118-138` | 🟠 | 🔧 |
| **S8** | `JWT_ALGORITHM` es override por entorno **sin allowlist** → configurar `none`/asimétrico por error rompe la verificación. Falta fijar HS* válido (defensa en profundidad). | `config_reading.py:206`; `users/managers.py:637` | 🟠 | ⚡ |
| **S9** | El `role` se toma del claim JWT y no se revalida contra BD en `require_role`; un cambio de rol no revocaría tokens (privilegio obsoleto ≤30 min). Hoy no explotable (no hay endpoint de cambio de rol). | `users/services/permissions.py:233-290` | 🟠 | 🔧 |
| **S10** | `update_storable` no comprueba ownership (IDOR latente); hoy no explotable porque el endpoint va por `bulk_update_storables` (que sí acota por `vault_id`). | `acheron/managers.py:331-385` | 🟡 | ⚡ |
| **S11** | Cambio de contraseña: `currentPassword` se recoge y solo se compara en cliente; **nunca se envía** ni se re-verifica en servidor (operación sensible autorizada solo por JWT). Falsa sensación de seguridad. | `web/.../views/ProfileView.vue:128,150-158`; `stores/profileStore.js:102-105` | 🟠 | 🔧 |
| **S12** | Router web sin guard de rol: `/users` y `/config` solo `requiresAuth`; cualquier autenticado navega y hace fetch (la API rechaza, pero falta defensa en profundidad en cliente, ya hay `isAdmin`/`isRoot`). | `web/.../router/index.js:52-101` | 🟡 | ⚡ |

> **Verificado sin hallazgo (puntos fuertes):** quiz público no filtra datos (nunca expone `correctIndex` ni otros destinatarios); cripto correcta (Argon2id, Fernet para TOTP, CSPRNG `secrets`, Acheron zero-knowledge); sin SQLi ni path traversal; cadena de migraciones Alembic lineal, single-head, sin destructivas en `upgrade`; secretos fuera de control de versiones.

---

## 3. Concurrencia / situaciones reales

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **C1** | Sin worker RQ / Redis caído: `create_app` solo emite WARNING; todos los `submit()` commitean y la fila queda **`pending` para siempre**. La reconciliación (`reconcile_orphaned_scans`) corre solo al arrancar y **solo para Themis** — Iris/Aegis no tienen equivalente. | `run.py:252-283`; `themis/managers/scan.py` | 🔴 | 🔧 |
| **C2** | Themis (Web) **no tiene polling** de estado de escaneos (a diferencia de Iris): un escaneo lanzado queda "running" en la UI hasta refresco manual. Afecta Nmap/Nikto/OpenVAS/Lybra. | `web/.../stores/themisStore.js`; `views/ThemisView.vue:177` | 🔴 | 🔧 |
| **C3** | Regla "un host por escaneo" de OpenVAS solo se impone en el **endpoint HTTP**; `OpenVASScanManager.run_scan` y el flujo **programado** (`scheduling.py`) no la validan → un escaneo OpenVAS programado puede recibir un CIDR/multi-host. | `themis/endpoints.py:285-289` vs `managers/openvas.py:67-105`; `services/scheduling.py:81-94` | 🟠 | ⚡ |
| **C4** | `submit`: cancelar-y-reencolar con el mismo `job_id` cuando el job está `started` es racy (la cancelación es cooperativa, no elimina el job) → posible choque de id en RQ al re-lanzar. | `system/taskqueue/queue.py:378-408` | 🟠 | 🔧 |
| **C5** | Cancelación de OpenVAS con granularidad de **60 s** (el bucle revisa `_cancel_event` una vez por iteración) → cancelar tarda hasta ~60 s. | `themis/services/tasks.py:685` | 🟡 | ⚡ |
| **C6** | `max_workers` reportado por la API (proceso API) puede no coincidir con el del worker real → panel "aliveWorkers/maxWorkers" engañoso tras `PUT /system/tasks/config`. | `system/taskqueue/queue.py:587` | 🟡 | ⚡ |
| **C7** | `ExternalIdStore.remove_by_job_id` hace `return` tras la primera coincidencia → si 2 external_ids apuntan al mismo job, el segundo mapping queda huérfano. | `system/taskqueue/stores.py:37-46` | 🟡 | ⚡ |
| **C8** | `Task.from_rq_job` usa estado cacheado (`refresh=False`) → historial/listado puede reportar estado obsoleto, mientras el duplicate-check de `submit` sí usa `refresh=True` (inconsistencia). | `system/taskqueue/task.py:59` | 🟡 | ⚡ |
| **C9** | `configStore.saveConfig` / `PUT /system` es last-write-wins sin ETag/versión: cambios server-side entre carga y guardado se pierden. | `web/.../stores/configStore.js:53-70`; `system/endpoints.py:118-138` | 🟠 | 🔧 |

---

## 4. Arquitectura / SOLID

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **A1** | God-class `ScanManager` (741 líneas): queries + ownership + ciclo de vida + orquestación + logging CSV + **utilidades de red** (`is_host_reachable`/`_ping_host` con `socket`/`subprocess`) + validación IP/puerto + formateo. Viola SRP; las utils de red no pertenecen a un manager de persistencia. | `themis/managers/scan.py` | 🔴 | 🏗️ |
| **A2** | God-store `themisStore` (864 líneas): escaneos, stats, tabs, 2 modales, carpetas, programados, histórico+cache, polling traceroute, objetivos, documentos, Lybra y "mundo". Debe dividirse (folders/history/scheduled). | `web/.../stores/themisStore.js` | 🔴 | 🏗️ |
| **A3** | God-component `IrisReportViewer.vue` (1197 líneas): mezcla presentación + orquestación de fetching + lógica de negocio (`defang`, export CSV, veredicto, PDF) y **accede a caches internos del store** (`pathCache`, `iocsCache`) rompiendo encapsulamiento. | `web/.../components/iris/IrisReportViewer.vue` | 🔴 | 🏗️ |
| **A4** | Acceso a BD **fuera de repositorio** en el manager: `session.query(Document)…` cuando ya existe `AegisDocumentRepository.get_documents_by_user`. | `aegis/managers.py:296-319` | 🟠 | ⚡ |
| **A5** | Manipulación de sesión **cruda** en `VaultManager` (`session.delete/flush/add`); la lógica de storables debería vivir en `VaultRepository`. | `acheron/managers.py:118-137` | 🟠 | 🔧 |
| **A6** | `Scheduler._has_active_run` hace `session.query(Scan)` directo en un *service* y **duplica** `ScanRepository.get_active_scans`. | `themis/services/scheduling.py:261-271` | 🟠 | ⚡ |
| **A7** | Lógica de negocio/formateo en endpoints: `severityBreakdown` y reconstrucción de `openPorts`, y `TYPE_MGR_MAP` que instancia 4 managers por request (incl. `OpenVASScanManager()` que lee config en `__init__`). | `themis/endpoints.py:403-441,516-530` | 🟠 | 🔧 |
| **A8** | Efectos secundarios de config en **import-time**: `SCAN_CONFIGS`/`PORT_LISTS` se leen al definir la clase (obliga a reiniciar para recoger cambios). | `themis/managers/openvas.py:49-50` | 🟠 | ⚡ |
| **A9** | DIP: dependencias concretas no inyectables (`AegisAlertFetcher`, `AegisAIWriter`, mailer, `result_processor`) → difícil de testear/sustituir; solo `task_queue` es inyectable. | `aegis/managers.py:84,401` | 🟠 | 🔧 |
| **A10** | `assert_scan_ownership` **no** usa el helper compartido `assert_owned` y reimplementa la lógica con una verificación extra → comportamiento divergente. | `themis/managers/scan.py:272-298` vs `shared/_ownership.py` | 🟠 | ⚡ |
| **A11** | Acoplamiento de Nikto en la clase **base** `_Task` (`_read_output` conoce strings de Nikto y loguea "Nikto rechazó el comando"). | `themis/services/tasks.py:120-122` | 🟡 | ⚡ |

---

## 5. DRY (duplicación)

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **D1** | `_generate_pdf_async` + `_update_document_status` duplicados casi literalmente (mismos strings, mismo comentario) entre Themis e Iris → base común de "report manager". | `themis/managers/reports.py:163-205` ≈ `iris/managers.py:1066-1107` | 🟠 | 🔧 |
| **D2** | `delete_document` (get→exists→remove→delete fila) reimplementado **3×**. | `themis/managers/reports.py:84-109`; `iris/managers.py:1000-1019`; `scan.py:207-214` | 🟠 | ⚡ |
| **D3** | Patrón error de API repetido **decenas de veces** en la SPA (`await res?.json().catch(()=>({}))` + `toast.show(data.error_description \|\| …,'error')`) → extraer `apiError(res)` a `useApi`. | `web/.../stores/*` (themis/aegis/iris/queue) | 🟠 | 🔧 |
| **D4** | Patrón `create_pending → commit_for_handoff → submit → execute_* → status update` replicado en Themis/Iris/Aegis sin base común. | `nmap.py`, `reports.py`, `iris/managers.py`, `aegis/managers.py` | 🟠 | 🏗️ |
| **D5** | `CANCELLABLE_STATES = {"pending","running"}` redefinido en 4+ sitios con representaciones distintas (frozenset/tupla). | `themis/endpoints.py:100`; `scan.py:251,337`; `iris/managers.py:47`; `iris/endpoints.py:68` | 🟡 | ⚡ |
| **D6** | `triggerDownload` (helper existente en `useUtils.js:102`) reimplementado a mano **3-4×**. | `irisStore.js:386-392`; `IrisReportViewer.vue:425-431`; `ProfileView.vue:187-194` | 🟡 | ⚡ |
| **D7** | Regex de `Content-Disposition` copiado literal **3×**. | `themisStore.js:529`; `aegisStore.js:270`; `irisStore.js:385` | 🟡 | ⚡ |
| **D8** | `formatDate` ad-hoc reimplementado en cada componente (formatos inconsistentes) pese a `useUtils.formatDate`. | `LybraResults.vue:142`; `TracerouteGraph.vue:64`; `ScanPreviewModal.vue:120`; `ScanTable.vue:87` | 🟡 | ⚡ |
| **D9** | `categoryLabel`/`statusLabel` inline en `QueueView` duplican la lógica de etiquetas que ya vive en `StatusBadge`. | `web/.../views/QueueView.vue:97-98` | 🟡 | ⚡ |

---

## 6. Calidad / legibilidad / UX / LEAN (desperdicio)

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **Q1** | Ausencia total de **estado de error** en la UI: en fallo/500 las listas se vacían y se muestra el empty-state feliz ("¡Lanza el primero!"); muchos `catch { /* noop */ }`. El usuario no distingue "vacío" de "falló". | Stores web (themis/aegis/iris/queue) | 🟠 | 🔧 |
| **Q2** | `_Task` timeout por defecto **200000 s (~55 h)** + números mágicos de timeout dispersos (`28800`, `14400`). Default peligroso si una subclase olvida pasar timeout. | `themis/services/tasks.py:66,438`; `openvas.py:101` | 🟠 | ⚡ |
| **Q3** | Proliferación de `# type: ignore` / `# pyright: ignore` que **enmascaran** varias de las inseguridades None de arriba (`scan_id`, `scan.status`, `user`). | managers/endpoints de Themis | 🟠 | 🔧 |
| **Q4** | `TaskStatus` duplicado: `themis/services/tasks.py` define uno propio distinto de `system.taskqueue.task.TaskStatus` (fuente de la confusión `completed`/`finished`). | ambos módulos | 🟠 | 🔧 |
| **Q5** | `console.log` de depuración olvidados + clave `'profile:me'` hardcodeada que duplica `keyPrefix + CACHE_KEY`. | `web/.../stores/profileStore.js:57,61,69` | 🟡 | ⚡ |
| **Q6** | `window.location.href = '/login'` para logout (recarga dura, pierde estado, re-descarga bundle) en vez de `router.push`; se invoca desde `apiFetch` a mitad de petición. | `web/.../stores/authStore.js:241,261` | 🟡 | ⚡ |
| **Q7** | `confirm()` nativos bloqueantes para cancelar/borrar, incoherentes con los modales propios (`BatchActionModal`) ya existentes. | `ThemisView.vue:191,233`; `ScanTable.vue:85-86` | 🟡 | 🔧 |
| **Q8** | Badges de estado que no se resetean (`launched` queda `true` para siempre → "Motor en marcha" permanente). | `LybraLaunchPanel.vue:148,193`; `ScanForm.vue:63,96` | 🟡 | ⚡ |
| **Q9** | Inconsistencia `'warn'` vs `'warning'`: `LoginView` usa `'warning'` mientras el resto del sistema usa `'warn'` (el estilo de aviso no se aplica). | `web/.../views/LoginView.vue:335` | 🟡 | ⚡ |
| **Q10** | Parámetro **muerto** `is_recovery` en `get_vault_for_user` (se ignora), pero se usa como clave de caché aguas arriba asumiendo que distingue vaults → confusión funcional. | `acheron/managers.py:74-77` | 🟡 | ⚡ |
| **Q11** | N+1 innecesario: `find_task(analysis_id)` (round-trip a Redis) por cada regla, cuando `job` ya está disponible desde `job_context`. | `iris/managers.py:651-654` | 🟡 | ⚡ |
| **Q12** | `MAX_PDF_SIZE_BYTES` declarado pero **sin uso** (código muerto; `download_document` no comprueba tamaño). | `themis/endpoints.py:101` | 🟡 | ⚡ |
| **Q13** | Typo persistente `frecuent` → `frequent` en el modelo; docstring que menciona "Windows Firewall" pese a plataforma Linux-only. | `themis/model.py:271`; `scan.py:665-669` | 🟡 | ⚡ |
| **Q14** | Detección de arranque de subproceso frágil (`time.sleep(0.1)` + `poll()` + `wait(5)`): un proceso que termina en <0.1 s puede perder salida. | `themis/services/tasks.py:178-193` | 🟡 | 🔧 |
| **Q15** | Números mágicos / strings hardcodeados varios (`600` ms del PDF, `2000` ms del logout, timeouts `900/6000/600`); sin i18n (todo el texto en español embebido). | `ThemisView.vue:236`; `ProfileView.vue:158`; `ScanForm.vue:66-68` | 🟡 | 🔧 |

---

## 7. Testing / Documentación

| ID | Hallazgo | Ubicación | Impacto | Esfuerzo |
|----|----------|-----------|---------|----------|
| **T1** | Sin tests de integración para **Themis** — justo el módulo con superficie SSRF (S1/S2/S3) y los bugs B1/B3/B4. | `tests/integration/` (ausente) | 🟠 | 🔧 |
| **T2** | `IMPROVEMENTS.md` referenciado repetidamente pero **inexistente** → los bugs "documentados" no tienen respaldo. | `tests/README.md:38`; `conftest.py:52,94` | 🟡 | ⚡ |
| **T3** | Docs desactualizadas: README/CLAUDE afirman "varios `xfail(strict=True)`"; solo existe **uno** (B12). | `tests/README.md:35`; `CLAUDE.md` | 🟡 | ⚡ |
| **T4** | Rate limiting deshabilitado globalmente en tests (`limiter.enabled = False`) → los `@limiter.limit` no tienen cobertura (login/MFA/quiz). | `tests/conftest.py:207-208` | 🟡 | 🔧 |
| **T5** | Usuarios de test creados por el camino **legacy SHA-256**, no Argon2 → el login de tests no ejercita la ruta principal. | `tests/conftest.py:271` | 🟡 | 🔧 |
| **T6** | Mock/nota de `jti` en `conftest` ya **obsoleto** (el bug está resuelto en `src`: `create_access_token` ya incluye `jti`). Código muerto. | `tests/conftest.py:105-111` | 🟡 | ⚡ |

---

## 8. Matriz de priorización (Impacto × Esfuerzo)

Cuadrantes para decidir orden de ataque. Prioridad de arriba-izquierda (alto impacto / bajo esfuerzo) hacia abajo-derecha.

| | ⚡ Rápido (<2 h) | 🔧 Medio (½–1 día) | 🏗️ Largo (>2 días) |
|---|---|---|---|
| **🔴 Alto** | **B1** Nmap UnboundLocalError · **B2** toast sin variante · **B5** leak polling Iris · **S1** SSRF Nikto · **S2** localIps=true · **C3** OpenVAS scheduled | **B3** OpenVAS timeout no para · **B4** race cancel/finish · **B6** timers huérfanos · **S3** root/root · **C1** sin worker/reconciliación · **C2** Themis sin polling | **A1** ScanManager god-class · **A2** themisStore god-store · **A3** IrisReportViewer god-component |
| **🟠 Medio** | **B8** completed/finished · **B10** setInterval async · **B11** TypeError null · **B12** 500→404 · **S5** ProxyFix · **S6** endpoints públicos · **S8** JWT allowlist · **A4** query fuera de repo · **A6/A8/A10** · **D2** delete_document · **Q2** timeout 55 h | **B7** detached ORM · **B9** race PDF 600 ms · **S4** rate-limit memory · **S7** config mutable admin · **S9** rol sin revalidar · **S11** currentPassword · **C4** reencolar racy · **C9** config last-write · **A5/A7/A9** · **D1** report dup · **D3** apiError · **Q1** estado error UI · **Q3/Q4** · **T1** tests Themis | **D4** pipeline submit común |
| **🟡 Bajo** | **B13** orden carpeta · **S10** IDOR latente · **S12** guard rol web · **C5–C8** taskqueue menores · **A11** Nikto en base · **D5–D9** DRY web · **Q5/Q6/Q8–Q13** · **T2/T3/T6** | **Q7** confirm() · **Q14** arranque frágil · **Q15** magic/i18n · **T4/T5** tests | — |

---

## 9. Roadmap recomendado (secuencia sugerida)

1. ✅ **Fase 1 — Quick wins críticos (⚡🔴, <1 día total):** B1, B2, B5, S1, S2, C3. Máximo retorno: cierran un SSRF, un bug que anula todo el feedback visual y dos fugas/enmascaramientos de error, casi todos de una línea a un puñado. **Hecha 2026-07-11** (ver Progreso de ejecución arriba).
2. ✅ **Fase 2 — Robustez operativa (🔧🔴):** B3, B4, B6, C1, C2 + S3. Aquí está la "coherencia con situaciones reales": escaneos que no se cuelgan, estado consistente entre procesos, reconciliación sin worker y feedback vivo en la UI. **Hecha 2026-07-11** (C1 cubre Themis+Iris; Aegis queda fuera, ver Progreso de ejecución).
3. **Fase 3 — Endurecimiento medio (🟠):** seguridad (S4–S9, S11), correctness restante (B7–B12), DRY de alto valor (D1–D3), estado de error en UI (Q1) y tests de Themis (T1).
4. **Fase 4 — Refactors estructurales (🏗️):** A1/A2/A3 (dividir las tres "god-*"), D4 (pipeline común de tareas), Q3/Q4 (unificar `TaskStatus` y retirar `type: ignore`). Mayor esfuerzo, mejor hacerlo con tests de regresión ya en su sitio (Fase 3).
5. **Fase 5 — Limpieza LEAN (🟡):** código muerto (Q12, T6, Q10), typos/docs (Q13, T2, T3), DRY menor del front (D5–D9) y unificaciones de UX (Q6–Q9).

---

## 10. Cómo se mapean a SOLID / LEAN / DRY

- **SRP (S de SOLID):** A1, A2, A3, A7, A11 — clases/stores/componentes que hacen demasiado. Dividir por responsabilidad reduce el riesgo de regresión y facilita testear.
- **OCP/DIP:** A8 (config en import-time), A9 (dependencias concretas no inyectables) — abstraer AI/alert/mailer detrás de interfaces inyectables (ya existe el patrón `scribe`/`herald` como referencia).
- **DRY:** todo el bloque §5 (D1–D9) + A4/A6/A10 (repos y ownership divergentes/duplicados). Una fuente única de verdad para descargas, parseo de cabeceras, manejo de error, estados cancelables y borrado de documentos.
- **LEAN (eliminar desperdicio):** Q10, Q12, T6 (código muerto), B11/Q3 (complejidad accidental que "funciona por accidente"), Q5 (logs de depuración), T2/T3 (docs que mienten). Menos superficie = menos donde esconder bugs.
- **Correctness/seguridad transversal:** §1 y §2 — el fin "código de calidad" empieza por que no filtre (S1/S2), no mienta al usuario (B2, B8, Q1) y no deje recursos colgados (B3, B5, B6, C1).

---

## 11. Verificación de futuras correcciones

Este documento es solo informe. Los tres hallazgos de mayor impacto (B1, B2, S1) se confirmaron leyendo el código fuente citado. Para cualquier corrección futura, la vía de verificación end-to-end sería:

- **Backend:** `cd API && pytest -m integration` (y añadir `tests/integration/test_themis.py`, hoy inexistente, para B1/B3/B4/S1). Lint con `pylint src`.
- **SPA:** reproducir en `npm run dev` (proxy a Flask :5000) — p. ej. B2 se valida viendo que un `toast.show(...,'error')` ya aplica la variante roja; B5 comprobando en DevTools que el `setInterval` de `/iris/status` cesa al navegar fuera.
- **Async:** todo lo de TaskQueue requiere el worker RQ activo (`python -m src.modules.system.taskqueue.worker`) además de Redis.
