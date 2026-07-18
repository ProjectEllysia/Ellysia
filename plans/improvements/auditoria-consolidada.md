# Auditoría consolidada — código, despliegue y viabilidad (2026-07-18)

> Este documento **sustituye** a `sondeo-codigo-api-web.md` (2026-07-10) y `calidad-codigo-segunda-pasada.md` (2026-07-14), ambos eliminados. Consolida: (1) el estado real de todos los hallazgos anteriores reverificado contra la rama `refactor/fix-general-issues` a fecha de hoy, (2) una pasada nueva sobre las zonas nunca auditadas — **despliegue Docker, nginx, certificados, dependencias, `landing/`** — con prefijo `E`, (3) los requisitos funcionales y no funcionales observados durante el escaneo, y (4) el contraste de todo ello con `saas-viability-plan.md`.
>
> Criterios de evaluación: **Correctness · Security · SOLID · DRY · LEAN**. Cada hallazgo abierto se clasifica por **impacto en el resultado final** (🔴 Alto · 🟠 Medio · 🟡 Bajo) y **tiempo de implementación** (⚡ <2 h · 🔧 ½–1 día · 🏗️ >2 días).

---

## 1. Cerrado desde las pasadas anteriores (verificado hoy, no reabrir)

La rama actual ha absorbido la gran mayoría de los dos documentos anteriores. Verificado por lectura/grep del código citado:

- **Sondeo, Fases 1–3 completas:** B1–B12, S1–S6, S8, C1–C3, D1, D3. Además `xfail(strict=True)` restantes: **cero** — la deuda documentada vía xfail está saldada.
- **Segunda pasada, casi íntegra:**
  - **N1** ownership Themis — `resolve_owned_scan`/`assert_document_ownership` en todos los endpoints de documentos.
  - **N2/D1** — `run_report_generation` de `shared/_documents.py` ya cableado en Themis e Iris; **D2** cerrado con `delete_document_with_file`.
  - **N3** (`strategy_class` muerto), **N4** (`_serialize_document` extraído), **N5** (excepciones de documentos movidas a `shared/_exceptions.py`), **N6** (`format_scan(id, _scan=item)` elimina el N+1), **N7** (config OAuth leída lazy vía `CR.get_oauth_config()` en el punto de uso), **N8** (`waitForDocument` en `generateLybraPdf`), **N10** (CLAUDE.md del SPA sin "sentinel"), **N11+A10** (`assert_scan_ownership` delega en `assert_owned`, sin query extra de User).
  - **Q4** — solo queda un `TaskStatus` (`taskqueue`); el de `themis/services/tasks.py` desapareció.
  - **Q11** (`find_task` solo en cancel/delete, no por regla), **Q12** (`MAX_PDF_SIZE_BYTES` eliminado), **D6** (`triggerDownload` solo en `useUtils`), **D8** (formatDate ad-hoc eliminados de los componentes citados), **A7** parcial (`severityBreakdown`/`TYPE_MGR_MAP` ya no están en endpoints).
- **nginx** — el hallazgo "enruta `/sentinel/` y falta `/iris/`" quedó resuelto (commit d6d5a80): `web/nginx.conf` proxya `/themis/`, `/iris/` y el resto de blueprints, con cabeceras `X-Forwarded-*` correctas para `ProxyFix`.
- **T1** — Themis tiene ahora suite de integración amplia (`test_themis.py`, `test_lybra*.py`, `test_scheduling.py`, `test_traceroute.py`, `test_scanner_finding_adapters.py`).

---

## 2. Hallazgos nuevos de esta pasada — despliegue, infraestructura y dependencias (E1–E11)

### E1 — Servidor de desarrollo Flask como servidor de producción — 🔴 🔧 · Correctness/Performance

`run.py` termina en `app.run(...)` (Werkzeug, servidor de desarrollo) y el `Dockerfile` de la API hace `CMD ["python", "run.py"]`. No hay **ningún** servidor WSGI de producción en `requirements.txt` (ni gunicorn, ni waitress, ni uwsgi). Consecuencias directas en UX/rendimiento:

- Concurrencia mínima: el SPA sondea `/themis/results` cada 4 s por pestaña activa y descarga PDFs; con 2–3 usuarios simultáneos las peticiones se encolan unas detrás de otras.
- El propio Werkzeug lo avisa en el arranque ("do not use it in a production deployment").
- Toda la corrección de S4 (rate limiter multi-worker en Redis) presupone un despliegue multi-worker que hoy no existe.

**Fix:** añadir `gunicorn` a requirements y cambiar el CMD del Dockerfile a `gunicorn -w <N> -b 0.0.0.0:5000 "run:create_app()"` (ajustando el factory/entrypoint; el modo `python run.py` puede quedarse para desarrollo). Es **bloqueante de Fase 0** del plan SaaS — ver §5.

### E2 — `docker-compose` hace a Ollama obligatorio y bloqueante para arrancar la API — 🔴 ⚡ · LEAN/Despliegue

El servicio `ellysia` declara `depends_on: ollama: condition: service_healthy`. Pero el plan de viabilidad (§5) dice explícitamente que **Ollama es opcional/no crítico** (`scribe` usa OpenAI por defecto) y presupuesto de VPS <50 €/mes — mientras que Ollama reserva **4 GB y limita a 8 GB** de RAM en compose. Hoy: sin Ollama sano, la API ni arranca; y el stack completo no cabe en el VPS objetivo.

**Fix:** sacar Ollama del `depends_on` de `ellysia`/`ellysia-worker` y moverlo a un profile propio (p. ej. `gpu`/`local-ai`), de modo que el despliegue SaaS por defecto sea postgres + redis + api + worker + web.

### E3 — `.env` completo inyectado en todos los contenedores — 🟠 ⚡ · Security (mínimo privilegio)

Todos los servicios del compose llevan `env_file: .env`, así que `JWT_SECRET_KEY`, `MFA_ENCRYPTION_KEY`, credenciales SMTP y la API key de OpenAI acaban también en el entorno de **ollama, openvas y postgres**, que no los necesitan. Cualquier RCE o imagen comprometida de esos contenedores expone todos los secretos de la plataforma.

**Fix:** quitar `env_file` de los servicios de infraestructura y pasarles solo sus variables (`POSTGRES_*`, `REDIS_PASSWORD`, `OPENVAS_*`) vía `environment`.

### E4 — Healthcheck de Redis que nunca puede fallar por auth — 🟡 ⚡ · Correctness

`redis-cli -a $${REDIS_PASSWORD} ping || redis-cli ping`: si la contraseña está mal, el fallback sin auth responde igualmente (y `redis-cli` devuelve exit 0 incluso con error NOAUTH en algunos modos), con lo que el healthcheck da verde y el fallo aparece después, en la API. Quitar el fallback.

### E5 — Dockerfile de la API: root, sin healthcheck, y residuos — 🟡 🔧 · Security/LEAN

- El proceso corre como **root** dentro del contenedor (no hay `USER`); para un contenedor que ejecuta nmap/nikto contra input de usuario, un usuario sin privilegios + `cap_add` puntual es defensa en profundidad barata.
- Ni `ellysia` ni `ellysia-worker` tienen healthcheck (el resto de servicios sí) — `restart: unless-stopped` no puede reaccionar a una API colgada.
- `mkdir -p /app/data/sentinel/output` — nombre viejo del módulo ("sentinel"), directorio que ya nadie usa.
- Imagen single-stage sobre `python:3.11-bookworm` con `git` instalado permanentemente (solo se usa en build para clonar Nikto).

### E6 — Clave privada TLS copiada dentro de la imagen web — 🟡 ⚡ · Security

`web/Dockerfile` hace `COPY ssl/ /etc/nginx/ssl/`: la clave privada queda horneada en una capa de la imagen (y en cualquier registry al que se suba), aunque el compose ya monta `./web/ssl` como volumen read-only que la tapa. Con el volumen basta — eliminar el `COPY ssl/`. (Lo bueno: `web/ssl/*.key|crt` están correctamente gitignorados; solo `generate.ps1` está versionado.)

### E7 — nginx sin gzip, sin cache de assets y con config triplicada — 🟡 🔧 · Performance/DRY

`web/nginx.conf`: no hay `gzip on`, ni `expires`/`Cache-Control` para los assets con hash de Vite (cada visita re-descarga el bundle completo → lentitud percibida real), ni `client_max_body_size`, ni HSTS en los bloques TLS. Además el bloque de 8 `location` proxy está copiado 2–3 veces (localhost:80, dominio:443) con las mismas 5 cabeceras repetidas por línea — un `include proxy_common.conf;` lo deja en una sola fuente. El `location /aegis/quiz` de `api.ellysia.es` es redundante (`location /` ya lo cubre).

### E8 — Certificados: autofirmados, 365 días, regeneración manual — 🟡 ⚡ · Despliegue

`web/ssl/generate.ps1` genera un autofirmado anual (SAN correcto: dominio, wildcard, api, localhost). Válido para desarrollo; para producción el plan de viabilidad ya decidió **Caddy con Let's Encrypt** (§5), lo que dejaría este nginx+certs como camino solo-dev. Decisión pendiente de ejecutar: o Caddy delante (y nginx interno solo sirve el SPA), o certbot en este nginx. No dejar que el autofirmado caduque en silencio si se sigue usando.

### E9 — Dependencias: muertas, duplicadas y sin lockfile — 🟡 ⚡ · LEAN

En `API/requirements.txt`, verificado con grep sobre `src/`:

- `flask-jwt-extended` — **ningún import** en el código (se usa PyJWT directo). Muerta.
- `ipaddress==1.0.23` — backport de Python 2; `ipaddress` es stdlib desde 3.3. Muerta.
- `duckduckgo-search` **y** `ddgs` a la vez — `ddgs` es el renombre del mismo paquete; sobra uno.
- Pinning mixto (`==` en unas, `>=` sin techo en la mayoría, `flask_limiter`/`PyJWT`/`requests` sin versión) y sin lockfile → dos builds de la misma imagen pueden llevar versiones distintas. Congelar con `pip-compile` o al menos acotar mayores.

### E10 — CORS con residuos de desarrollo en producción — 🟡 ⚡ · Security/LEAN

`create_app()` añade **incondicionalmente** `http://127.0.0.1:3000` a los orígenes CORS, y el default de `ALLOWED_ORIGINS` es `http://localhost:8080` (el dev server real de Vite es :5173 — el default no sirve a nadie). En producción tras nginx el SPA es same-origin y CORS apenas aplica, pero el origen extra viaja igualmente. Limpiar: el default correcto y el origen de dev solo si `is_development()`.

### E11 — `landing/` estática: duplicada, desalineada y sin desplegar — 🟡 🔧 · LEAN/DRY

El directorio `landing/` (804 líneas de HTML/CSS/JS) es una landing estática que: (1) **duplica** la función de los hubs públicos del SPA (`LandingView` + hubs por módulo, que el plan de viabilidad da por hechos el 2026-07-11); (2) muestra **"v3.2"** hardcodeado cuando `appVersion` es 4.2 y en la app es config-driven; (3) carga Google Fonts desde el CDN de Google — para un SaaS vendido en España/UE eso es un problema GDPR conocido (transferencia de IP a Google; hay sentencias); (4) **no está referenciada** ni en docker-compose ni en nginx — no se despliega con nada. Decidir: o se elimina (los hubs del SPA son la landing) o se le da un destino real y se alinea versión/fuentes. El SPA (`web/app/index.html`) también debería autoalojar las fuentes si aplica.

---

## 3. Pendientes vigentes de las pasadas anteriores (reverificados hoy)

Siguen abiertos, con su ID original. Nada de esta tabla se ha vuelto a cerrar desde el 2026-07-14:

| ID | Resumen | Impacto | Tiempo | Nota de hoy |
|---|---|---|---|---|
| **A1** | God-class `ScanManager` — sigue en **801 líneas** (queries + ownership + red + CSV + formateo) | 🔴 | 🏗️ | Hacer con la suite verde; último gran refactor backend |
| **A2** | God-store `themisStore` — **987 líneas** (creció desde 864) | 🔴 | 🏗️ | Dividir folders/history/scheduled/lybra |
| **A3** | God-component `IrisReportViewer.vue` — **1200 líneas** | 🔴 | 🏗️ | Sigue accediendo a caches internos del store |
| **Q1** | Sin estado de error en la UI: fetch fallido → empty-state feliz; sin `loadError` en ningún store | 🟠 | 🔧 | El usuario no distingue "vacío" de "falló" — impacto directo en UX |
| **S7** | `PUT /system` reescribe toda la config con solo `require_role(ADMIN)` | 🟠 | 🔧 | Decisión de producto pendiente |
| **S9** | Rol leído del claim JWT sin revalidar contra BD (ventana ≤30 min) | 🟠 | 🔧 | Decisión de producto pendiente |
| **S11** | `currentPassword` solo se valida en cliente (`ProfileView.vue:154`); nunca se envía ni verifica en servidor | 🟠 | 🔧 | Cambio de contraseña autorizado solo por JWT |
| **S12** | Router SPA sin guard de rol: `/users` y `/config` solo `requiresAuth` | 🟡 | ⚡ | Defensa en profundidad en cliente |
| **D4** | Pipeline `create→commit_for_handoff→submit→execute` sin base común (Themis/Iris/Aegis) | 🟠 | 🏗️ | N2/D2 lo dejaron más cerca |
| **D5** | `CANCELLABLE_STATES` redefinido en 3 sitios (iris×2, themis) | 🟡 | ⚡ | Ya son frozensets consistentes; moverlo a `shared` |
| **D7** | Parseo de `Content-Disposition` copiado en 3 stores | 🟡 | ⚡ | Extraer a `useApi`/`useUtils` |
| **A4** | `session.query(Document)` directo en `aegis/managers.py:318` | 🟠 | ⚡ | Ya existe repo con el método |
| **A6** | `session.query(Scan)` directo en `scheduling.py:286`, duplica `ScanRepository` | 🟠 | ⚡ | — |
| **A8** | `SCAN_CONFIGS`/`PORT_LISTS` leídos en class-definition-time (`openvas.py:50`) | 🟠 | ⚡ | Cambios de config exigen reinicio |
| **A9** | Dependencias concretas no inyectables en Aegis (`AegisAlertFetcher`, `AegisAIWriter`) | 🟠 | 🔧 | Solo `task_queue` es inyectable |
| **A11** | Strings de Nikto en la clase base `_Task` (`tasks.py:121`) | 🟡 | ⚡ | — |
| **C4** | Cancelar-y-reencolar con mismo `job_id` racy en `submit` | 🟠 | 🔧 | — |
| **C5** | Cancelación OpenVAS con granularidad 60 s | 🟡 | ⚡ | — |
| **C6** | `max_workers` reportado por la API puede no coincidir con el worker real | 🟡 | ⚡ | — |
| **C7** | `remove_by_job_id` sale tras la primera coincidencia → mapping huérfano | 🟡 | ⚡ | — |
| **C8** | `Task.from_rq_job` con estado cacheado (`refresh=False`) | 🟡 | ⚡ | — |
| **C9** | `PUT /system` last-write-wins sin ETag/versión | 🟠 | 🔧 | Agravado si hay >1 admin (SaaS) |
| **Q2** | Timeout default de `_Task` = 200000 s (~55 h) + números mágicos (`28800`, `14400`) | 🟠 | ⚡ | Mover a `SecOpsConfig.json` (regla del repo) |
| **Q3** | `# type: ignore` dispersos enmascarando None-inseguridades (endpoints Themis) | 🟠 | 🔧 | — |
| **Q5** | `console.log` de depuración en `profileStore.js:57,61,69` + clave `'profile:me'` hardcodeada | 🟡 | ⚡ | — |
| **Q6** | Logout con `window.location.href = '/login'` (recarga dura) en `authStore.js:241,261` | 🟡 | ⚡ | — |
| **Q7** | `confirm()` nativos incoherentes con los modales propios | 🟡 | 🔧 | — |
| **Q8** | Badge `launched` nunca se resetea ("Motor en marcha" permanente) — `LybraLaunchPanel.vue:148` | 🟡 | ⚡ | — |
| **Q13** | Typo `frecuent` en columna del modelo Themis | 🟡 | 🔧 | Requiere migración Alembic; hacerlo aprovechando otra migración |
| **Q14** | Detección de arranque de subproceso frágil (`sleep(0.1)` + `poll()`) | 🟡 | 🔧 | — |
| **Q15** | Números mágicos / sin i18n (texto español embebido) | 🟡 | 🔧 | i18n solo si el plan comercial sale de España/LatAm |
| **T2** | `IMPROVEMENTS.md` referenciado en `tests/README.md:38` y `conftest.py:52,94` pero inexistente | 🟡 | ⚡ | Docs que mienten |
| **T4** | Rate limiting deshabilitado globalmente en tests | 🟡 | 🔧 | — |
| **T5** | Usuarios de test por camino legacy SHA-256, no Argon2 | 🟡 | 🔧 | — |
| **N12** | Pila de ~8 decoradores × ~30 endpoints Themis (`endpoints.py`: 1253 líneas) | 🟡 | 🏗️ | Solo junto al resto de A7; no como cambio aislado |

---

## 4. Matriz consolidada (impacto × tiempo de implementación)

| | ⚡ Rápido (<2 h) | 🔧 Medio (½–1 día) | 🏗️ Largo (>2 días) |
|---|---|---|---|
| **🔴 Alto** | **E2** Ollama obligatorio en compose | **E1** WSGI de producción | **A1/A2/A3** god-* |
| **🟠 Medio** | **E3** secretos en todos los contenedores · **A4/A6/A8** queries/config · **Q2** timeouts | **Q1** estado de error UI · **S7/S9/S11** decisiones seguridad · **C4/C9** · **A9** DIP Aegis · **Q3** type-ignores | **D4** pipeline común |
| **🟡 Bajo** | **E4** healthcheck Redis · **E6** COPY ssl · **E8** certs · **E9** deps muertas · **E10** CORS · **S12** guard rol web · **D5/D7** · **A11** · **C5–C8** · **Q5/Q6/Q8** · **T2** | **E5** Dockerfile API · **E7** nginx gzip/cache · **E11** landing/ · **Q7/Q13/Q14/Q15** · **T4/T5** | **N12** factory decoradores |

### Secuencia recomendada

1. **Bloque despliegue (antes de cualquier usuario real):** E1 → E2 → E3 (+ E4/E6/E10 de paso, son minutos). Es el bloque con mejor ratio impacto/esfuerzo de toda la auditoría y prerequisito de la Fase 0 SaaS.
2. **Bloque UX:** Q1 (estado de error) + E7 (gzip/cache) — los dos hallazgos abiertos que un usuario final nota directamente.
3. **Bloque decisiones de seguridad:** S7, S9, S11, S12 — requieren decisión de producto explícita; en modelo SaaS multiusuario dejan de ser teóricos (ver §6).
4. **Bloque LEAN corto:** E5, E8, E9, E11, D5, D7, A4, A6, A8, A11, Q5/Q6/Q8, T2 — PRs pequeños y sin riesgo.
5. **Refactors largos (solo con suite verde):** A1 → A2 → A3 → D4; reevaluar N12 dentro de A1/A7.

### Verificación

- Backend: `cd API && pytest` (SQLite + mocks, sin Postgres/Redis) y `pylint src`. E1 exige además prueba real del contenedor (`docker compose --profile container up`) con carga concurrente mínima (dos descargas de PDF simultáneas).
- SPA: `npm run build` + verificación en navegador para Q1/Q6/Q8.
- Regla del repo: nada de adaptar `src/` a los tests; `xfail(strict=True)` que pase a XPASS pierde el marcador.

---

## 5. Requisitos funcionales y no funcionales observados

Derivados del escaneo (lo que el sistema **hace** hoy y lo que le **falta** según su propio plan). Sirven como base contractual para tests y para el pricing por módulos.

### Requisitos funcionales

**Implementados (verificados en código/tests):**

- **RF1 — Autenticación:** OAuth2 password grant + JWT (access 30 min / refresh 7 d), Argon2id, MFA TOTP con códigos de recuperación, revocación por `jti`.
- **RF2 — Autorización:** roles jerárquicos (user/admin/root) + atributos ABAC por módulo (`THEMIS_READ`, etc.); ownership por `user_id` en todos los recursos (Themis, Iris, Aegis, Acheron).
- **RF3 — Themis:** escaneos Nmap/Nikto/OpenVAS/Lybra con validación anti-SSRF, un host por escaneo OpenVAS, carpetas, escaneos programados (APScheduler), traceroute, informes PDF (con IA opcional), targets autorizados.
- **RF4 — Iris:** análisis de cabeceras (37 reglas, scoring sustractivo 0–100), quishing (QR), documentos PDF, reconciliación de análisis huérfanos.
- **RF5 — Aegis:** píldoras de concienciación generadas por IA (scribe: OpenAI/Ollama/Gemini), campañas con listas de distribución, envío por `herald` (SMTP), quiz público por token opaco (único endpoint sin auth), perfil de organización.
- **RF6 — Acheron:** vault zero-knowledge (cripto en cliente, interop web/móvil verificada por vectores compartidos), 7 tipos de storable, generador de contraseñas (autenticado).
- **RF7 — Sistema:** cola de tareas persistente (RQ+Redis) con categorías, cancelación cooperativa, progreso, reconciliación al arranque; administración de tareas y config en runtime (`/system/tasks/*`, `PUT /system`).

**Faltantes confirmados (grep negativo hoy — todos previstos por el plan SaaS):**

- **RF8 — Registro público de usuarios** (no existe ruta ni vista).
- **RF9 — Recuperación de contraseña** (ni endpoint ni email transaccional).
- **RF10 — Cuotas por usuario** (scans/día, píldoras/día, tamaño vault, recipients).
- **RF11 — Pagos/suscripción** (Stripe/Paddle/Lemon: cero referencias) + página de pricing.
- **RF12 — Nudge/recordatorio de MFA** (toast post-login + job periódico).
- **RF13 — Ingesta IMAP en Iris** (convertir demo en hábito diario — Fase 2).
- **RF14 — Export GDPR y baja autoservicio** (Fase 3).

### Requisitos no funcionales

| # | Requisito | Estado observado |
|---|---|---|
| **RNF1** | **Seguridad:** hashing Argon2id, Fernet para TOTP, anti-SSRF en todos los scanners, rate limiting distribuido, mínimo endpoint público | ✅ sólido en código; ❌ en despliegue (E3 secretos, E5 root, S7/S9/S11 pendientes de decisión) |
| **RNF2** | **Rendimiento:** respuesta interactiva con polling de 4 s y varios usuarios | ❌ hoy imposible de garantizar: servidor de desarrollo Flask (E1), sin gzip/cache de assets (E7) |
| **RNF3** | **Disponibilidad/resiliencia:** tareas sobreviven reinicios (RQ persistente ✅), reconciliación de huérfanos ✅, `restart: unless-stopped` ✅; sin healthcheck de API (E5), sin monitoring ni backups (plan Fase 0) | parcial |
| **RNF4** | **Escalabilidad:** single VPS, single DB, aislamiento por `user_id`; colas por categoría ya existen; RLS y prioridades diferidas a Fase 3 | acorde al plan |
| **RNF5** | **Mantenibilidad:** capas endpoint→manager→repo respetadas, suite integración amplia, pylint, migraciones lineales | ✅ tras los refactors; deuda restante = A1/A2/A3/D4 |
| **RNF6** | **Reproducibilidad de build:** mismas fuentes → misma imagen | ❌ requirements sin lockfile (E9) |
| **RNF7** | **Cumplimiento (UE):** páginas legales preliminares ✅ (marcadas como pendientes), Google Fonts CDN en landing ❌ (E11), sin export GDPR (RF14) | pendiente antes de cobrar |
| **RNF8** | **Portabilidad:** API Linux-only (nmap/nikto/openvas) — asumido y documentado; web/tests corren en Windows | ✅ asumido |
| **RNF9** | **Observabilidad:** logs JSON rotados en compose ✅, `log_min_duration_statement=200` ✅; sin métricas ni uptime monitoring | parcial (plan: UptimeKuma) |
| **RNF10** | **i18n:** texto embebido en español | asumido mientras el mercado sea ES/LatAm (Q15) |

---

## 6. Contraste con el plan de viabilidad SaaS

Actualizaciones a la tabla "fuente de verdad" de `saas-viability-plan.md` §0 y consecuencias por fase:

### Correcciones de estado (el plan está desactualizado en esto)

| Afirmación del plan | Estado hoy | Evidencia |
|---|---|---|
| Rate limiter `memory://` ❌ | ✅ **resuelto** — Redis con fallback en memoria | `run.py` fija `RATELIMIT_STORAGE_URI` a Redis (fix S4) |
| — (no contemplado) | ❌ **nuevo bloqueante Fase 0: servidor WSGI** | E1 — `app.run` + `CMD python run.py`, sin gunicorn |
| "Ollama opcional/no crítico" (§5) | ❌ **el compose lo contradice** | E2 — `depends_on: ollama: service_healthy` + 4–8 GB RAM |
| "Caddy como reverse proxy" (§5, decidido) | ⏳ sin ejecutar — hoy nginx + autofirmado manual anual | E7/E8 |
| Resto de ❌ de la tabla (reset contraseña, pagos, pricing, registro, cuotas, nudge MFA) | ❌ siguen todos sin existir | grep negativo 2026-07-18 |

### Lecturas de viabilidad derivadas de esta auditoría

1. **El código de producto ya no es el cuello de botella; el despliegue sí.** Tras las fases ejecutadas de las dos pasadas anteriores, el backend está en un estado notablemente sano (capas respetadas, ownership consistente, cola persistente, suite amplia, cero xfails). Lo que separa el repo de "puede cobrar a un cliente" es casi todo infraestructura: E1 (WSGI), E2 (compose que no cabe en el VPS objetivo), backups, monitoring, y los RF8–RF11. Eso **refuerza** la estimación de 2–4 semanas de la Fase 0 — pero añadiendo E1/E2 a su checklist, o la primera demo con dos usuarios simultáneos irá lenta por diseño.

2. **La infra actual contradice el presupuesto del plan.** El plan asume <50 €/mes de VPS con Aegis como wedge (que no escanea nada y no necesita ni Ollama ni OpenVAS). El compose de hoy levanta Ollama (8 GB) y OpenVAS (shm 1 GB + feed) siempre. Para el lanzamiento Aegis-first sobra la mitad del stack: el "perfil SaaS" mínimo es postgres + redis + api + worker + web. E2 es el fix de una línea que alinea compose con plan.

3. **Las decisiones de seguridad aparcadas (S7/S9/S11) cambian de naturaleza con el SaaS.** En single-user eran teóricas; en multiusuario de pago: S7 significa que *cualquier* admin puede reescribir la config global de la plataforma (incluido `areLocalIpsAllowed` — reabriría el SSRF cerrado en Fase 1); C9 agrava esto con last-write-wins. Antes de aceptar el primer cliente, `PUT /system` debería ser solo-root (o partirse en config por-tenant vs global). S11 (verificación de contraseña actual en servidor) pasa de "nice to have" a estándar mínimo esperable en una plataforma de seguridad. Recomendación: resolver los tres dentro de Fase 0, son 🔧 cada uno.

4. **Q1 (estado de error en UI) es un riesgo comercial, no solo técnico.** El plan fija como umbral "1 consultora interesada en septiembre". En una demo, un fallo transitorio que se pinta como "no tienes nada, ¡lanza el primero!" es indistinguible de un producto vacío/roto. Es la mejora de UX pendiente con mayor retorno para la Fase 1.

5. **La landing estática (E11) compite con la estrategia de hubs ya hecha.** El plan da por hechos los hubs públicos del SPA como "carta de presentación" (Fase 1, punto 2). Mantener además `landing/` desalineada (v3.2, fuentes de Google, sin desplegar) es desperdicio LEAN y un riesgo de mensaje inconsistente. Decidir su eliminación o su rol (¿página de marketing en dominio raíz servida por Caddy?) dentro de Fase 1.

6. **Los refactors 🏗️ (A1/A2/A3/D4) no bloquean el lanzamiento.** Son deuda de mantenibilidad a largo plazo; con la suite actual verde se pueden hacer post-lanzamiento sin riesgo comercial. Lo coherente con el calendario 30/60/90 del plan es: Fase 0 + bloque despliegue ahora, god-* después de la validación de septiembre. Única excepción: si la validación exige tocar mucho `themisStore`/`ScanManager` para features nuevas (p. ej. cuotas RF10 tocan `ScanManager`), hacer el split **antes** de esa feature, no después.

7. **Checklist Fase 0 ampliado** (lo del plan + lo de esta auditoría):
   - [ ] ~~Rate limiter a Redis~~ ✅ hecho
   - [ ] **E1** gunicorn/WSGI en el contenedor API
   - [ ] **E2** perfil compose "SaaS" sin Ollama/OpenVAS obligatorios
   - [ ] **E3** secretos solo en los contenedores que los usan
   - [ ] Cuotas por usuario (RF10)
   - [ ] Reset de contraseña (RF9) + registro público (RF8)
   - [ ] Pasarela de pago + pricing (RF11)
   - [ ] Backups Postgres + UptimeKuma
   - [ ] SPF/DKIM/DMARC en dominio de envío
   - [ ] S7/S9/S11 resueltos (decisión + implementación)
   - [ ] Decisión Caddy vs nginx+certbot (E8) ejecutada
