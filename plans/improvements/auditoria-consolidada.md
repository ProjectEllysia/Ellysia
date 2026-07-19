# Auditoría — código, despliegue y viabilidad (2026-07-19)

> Consolida el estado real del código (`refactor/fix-general-issues`) frente a los criterios **Correctness · Security · SOLID · DRY · LEAN**, el estado del despliegue Docker/nginx, y el contraste con `saas-viability-plan.md`. Cada hallazgo abierto se clasifica por **impacto** (🔴 Alto · 🟠 Medio · 🟡 Bajo) y **tiempo de implementación** (⚡ <2 h · 🔧 ½–1 día · 🏗️ >2 días).

---

## 1. Resuelto (verificado en código — no reabrir)

**Backend — arquitectura:**
- Capas `endpoints → managers → repositories → model` respetadas en los 6 módulos; ownership por `user_id` consistente en Themis/Iris/Aegis/Acheron.
- `ScanManager` (760 líneas): las utilidades de red puras (`is_host_reachable`/`_ping_host`) viven en `services/reachability.py`, sin dependencias del framework. El registro polimórfico de subclases y el logging a CSV se quedan en la clase — son genuinamente cohesivos con el resto del manager.
- `TaskTrackingMixin` (`system/taskqueue/tracking.py`) usado de forma consistente en los 6 managers que respaldan una entidad con tarea en segundo plano: `ScanManager`, `IrisManager`, `IrisReportManager`, `AegisManager`, `CampaignManager` — todos derivan `external_id`/`category` de `EXTERNAL_ID_PREFIX`/`TASK_CATEGORY`, ninguno construye esas cadenas a mano.
- `TaskQueue.submit()` (`system/taskqueue/queue.py`) rechaza con `IllegalStateError` (409) reencolar un `job_id` cuyo job anterior sigue `started` — evita que dos ejecuciones lógicas compartan un mismo job_id de RQ mientras la cancelación cooperativa del anterior todavía no ha surtido efecto.
- Timeouts de escaneo (`_Task`, `OpenVASTask` en `themis/services/tasks.py`) configurables vía `SecOpsConfig.json` (`themis.taskDefaults.timeout`, `themis.openvas.timeout`, `themis.openvas.maxWaitTimeout`), no hardcodeados; el timeout del job de RQ en `openvas.py` y el timeout interno de `OpenVASTask` leen del mismo valor de config, para que no puedan divergir.
- Precedentes de extracción DRY ya cableados: `run_report_generation`/`delete_document_with_file` (`shared/_documents.py`) en Themis e Iris; `CANCELLABLE_STATES` centralizado en `shared/_task_states.py`; `filenameFromResponse`/`triggerDownload` en `useUtils` (frontend).

**Backend — seguridad:**
- `GET`/`PUT /system` exigen rol `ROOT` (antes `ADMIN`) — solo root puede leer/mutar la config global, incluida la política anti-SSRF y los parámetros de Argon2.
- `PUT /system` exige cabecera `If-Match` con el ETag de contenido de la config (`config_reading.get_config_version()`, hash SHA-256); responde 409 si la config cambió desde la última lectura del cliente, en vez de sobrescribir sin avisar. `GET /system` devuelve el ETag actual en la cabecera de respuesta.
- `require_role` revalida el rol contra BD en los endpoints de baja frecuencia (`/system`, `/users`); `require_attributes` no revalida (hot path de Themis, ya hace una query por llamada).
- Cambio de contraseña valida `currentPassword` en el servidor (`verify_credentials`), no solo en el formulario del cliente.
- Router del SPA con guards de rol (`/config` exige root, `/users` exige admin) como defensa en profundidad — la API ya rechaza igualmente.
- Rate limiter con storage Redis (fallback en memoria documentado y testeado); handler de error 429 con firma correcta (antes lanzaba `TypeError` en vez de devolver el JSON esperado).
- API corre como root dentro del contenedor — **decisión aceptada, no pendiente**: el nmap de Debian (7.93, sin `libcap-ng`) exige UID 0 real para escaneos SYN pase lo que pase con las capabilities; bajar a un usuario sin privilegios rompería el escaneo en silencio.

**Backend — despliegue:**
- Servidor WSGI de producción: `gunicorn --factory run:app_factory --workers 1 --threads 8` en el `Dockerfile` de la API (un solo proceso a propósito — el scheduler APScheduler y la reconciliación de huérfanos son en memoria por proceso; `python run.py` se conserva para desarrollo).
- `docker-compose`: Ollama fuera del `depends_on`/perfil `container` (vive en `dev` + `local-ai`); el stack SaaS por defecto es postgres + redis + api + worker + web. `env_file: .env` retirado de los servicios de infraestructura (postgres/redis/ollama/openvas) — cada uno recibe solo sus propias variables.
- Healthcheck de Redis corregido (sin fallback que enmascara contraseña mal puesta); healthcheck HTTP añadido al Dockerfile de la API.
- `requirements.txt` sin dependencias muertas (`flask-jwt-extended`, `ipaddress`) ni duplicadas (`duckduckgo-search`/`ddgs`).
- nginx: `gzip on`, cache inmutable de `/assets/` con hash de Vite, `client_max_body_size`, HSTS en los bloques TLS, cabeceras de proxy centralizadas en `web/proxy-common.conf` (antes repetidas 2–3 veces).
- CORS: el origen de desarrollo (`:5173`, el real de Vite) solo se añade si `is_development()`.
- `landing/` se mantiene (se despliega vía GitHub Pages); versión alineada a `4.2` (antes hardcodeaba `v3.2`).

**Frontend:**
- `themisStore.js` dividido en 4 stores por responsabilidad: núcleo (`themisStore.js`, 697 líneas — mundos, pestañas, stats, escaneos + polling, modales), `themisFoldersStore.js` (203, carpetas), `themisScheduledStore.js` (80, escaneos programados), `themisHistoryStore.js` (65, histórico + caché).
- `IrisReportViewer.vue` (994 líneas, de 1194 original): el store expone datos ya resueltos (`resolvedPathFor`/`isPathLoadingFor`/`resolvedIocsFor`/`isIocsLoadingFor`) en vez de exponer sus cachés internos (`pathCache`/`iocsCache`) a los componentes; el panel de IOCs (`IrisIocsPanel.vue`, 144 líneas) y el bloque hero/veredicto (`IrisVerdictHero.vue`, 113 líneas) son sub-componentes propios, reutilizables y probables por separado.
- Estado de error visible (distinto del empty-state) en Themis, Aegis, Iris y Queue, con botón "Reintentar".
- `ConfirmModal.vue` compartido sustituye los `confirm()` nativos del navegador.
- `configStore.js` captura el ETag de `/system` y lo reenvía como `If-Match`; un 409 se muestra como conflicto en vez de sobrescribir a ciegas.
- Badge "Motor en marcha"/"Escaneo iniciado" derivado del estado real de los escaneos, no un flag optimista permanente.
- `console.log` de depuración eliminados de `profileStore.js`.

**Tests:**
- Suite de integración amplia para Themis (`test_themis.py`, `test_lybra*.py`, `test_scheduling.py`, `test_traceroute.py`) e Iris/Aegis (documentos, campañas, reconciliación). Cero `xfail(strict=True)` pendientes.
- Rate limiting testeado con storage en memoria + fixture opt-in; usuarios de test con Argon2 por defecto (no SHA-256 legacy).

**Frontend (continuación):**
- Logout por navegación SPA (`router.push('/login')`), sin recarga dura de página. Cada uno de los 11 stores con datos de sesión (`profile`, `users`, `themis` + sus 3 satélites, `iris`, `aegis`, `config`, `mfa`, `queue`) implementa su propio `$reset()` — Pinia no lo genera automáticamente para "setup stores" — orquestado desde `authStore.logout()`/`endSession()` iterando la instancia activa de Pinia. Incluye limpiar cachés fuera de Pinia que también sobrevivían al logout (`profileCache` en sessionStorage, `docCache` de Aegis en memoria) y detener pollers activos (escaneos, traceroute, estado de Iris, documentos). `toast`/`theme` quedan fuera a propósito — son preferencias de UI/dispositivo, no datos de sesión.
- `landing/` y el SPA autoalojan sus fuentes (Sora, Syne, JetBrains Mono como `@font-face` locales en `landing/fonts/`) — cero peticiones a Google Fonts. El SPA también tenía dos `<link rel="preconnect">` muertos apuntando a Google sin usarlos; eliminados.

---

## 2. Hallazgos abiertos

### N12 — Pila de decoradores repetida en cada endpoint Themis — 🟡 🏗️ · DRY (opcional)

`themis/endpoints.py` (1252 líneas): cada uno de los ~30 endpoints repite el mismo "sándwich" de hasta 8 decoradores (`@blp.arguments`, `@blp.response`/`@blp.alt_response` ×varios, `@require_oauth_token`, `@require_attributes`, `@limiter.limit`, `@handle_exceptions`). Es verboso, pero también **explícito y `grep`-eable**: quien lee un endpoint ve exactamente qué protecciones tiene. Una factory (`@themis_endpoint(...)`) lo comprimiría a costa de indirección en la capa de seguridad — más fácil que un endpoint nuevo herede protecciones que no debía, o le falte una sin que se note.

**Recomendación: no abordarlo como cambio aislado.** Solo tiene sentido si en algún momento se decide extraer también la lógica de negocio que aún queda en algunos endpoints, y aun así con cautela.

### Q3 — `# type: ignore` dispersos enmascarando inseguridades de `None` — 🟠 🔧 · Correctness

43 ocurrencias en `themis/endpoints.py`, 12 en `scan.py`. Cada una es un punto donde el tipado real podría estar ocultando un `None` no manejado en tiempo de ejecución. Mejor abordarlo la próxima vez que se toque ese código de cerca, no como barrida aislada — una pasada dedicada sin motivo funcional arriesga cambios de comportamiento sin necesidad.

### E8 — Certificados autofirmados, sin renovación automática — 🟡 ⚡ · Despliegue

`web/ssl/generate.ps1` genera un certificado autofirmado válido un año. Suficiente para desarrollo; para producción sigue pendiente ejecutar la decisión ya tomada en el plan de viabilidad (Caddy + Let's Encrypt) frente a mantener nginx + certbot manual. **Decisión explícitamente pendiente del propietario** — requiere un dominio y DNS reales que no existen en el entorno de desarrollo, no es algo verificable en local. No dejar que el autofirmado caduque en silencio si se sigue usando mientras tanto.

### Recordatorio operacional — política anti-SSRF desactivada en config

`SecOpsConfig.json` tiene `themis.areLocalIpsAllowed` puesto a `true` a mano (para poder probar contra IPs privadas en desarrollo). Con ese valor, 4 tests SSRF de la suite no disparan por diseño (`test_nikto_rejects_loopback_target`, `test_nikto_rejects_cloud_metadata_target`, `test_nmap_rejects_private_ip_target`, `test_openvas_scheduled_flow_rejects_private_ip`) — no es una regresión, es este valor de config. **Debe volver a `false` antes de cualquier despliegue real**, o la defensa anti-SSRF queda desactivada en producción.

---

## 3. Matriz (impacto × tiempo de implementación)

| | ⚡ Rápido (<2 h) | 🔧 Medio (½–1 día) | 🏗️ Largo (>2 días) |
|---|---|---|---|
| **🔴 Alto** | — | — | — |
| **🟠 Medio** | — | **Q3** type-ignores | — |
| **🟡 Bajo** | **E8** certs (decisión del propietario) | — | **N12** factory decoradores (opcional) |

### Verificación

- Backend: `cd API && pytest` (SQLite + mocks, sin Postgres/Redis real) y `pylint src`.
- SPA: `npm run build` + verificación en navegador real para cualquier cambio de UI.
- Regla del repo: nada de adaptar `src/` a los tests; `xfail(strict=True)` que pase a XPASS pierde el marcador.

---

## 4. Requisitos funcionales y no funcionales observados

Derivados del estado actual del código. Sirven como base contractual para tests y para el pricing por módulos.

### Requisitos funcionales

**Implementados (verificados en código/tests):**

- **RF1 — Autenticación:** OAuth2 password grant + JWT (access 30 min / refresh 7 d), Argon2id, MFA TOTP con códigos de recuperación, revocación por `jti`.
- **RF2 — Autorización:** roles jerárquicos (user/admin/root) + atributos ABAC por módulo (`THEMIS_READ`, etc.); ownership por `user_id` en todos los recursos.
- **RF3 — Themis:** escaneos Nmap/Nikto/OpenVAS/Lybra con validación anti-SSRF, un host por escaneo OpenVAS, carpetas, escaneos programados (APScheduler), traceroute, informes PDF (con IA opcional), targets autorizados.
- **RF4 — Iris:** análisis de cabeceras (37 reglas, scoring sustractivo 0–100), quishing (QR), documentos PDF, reconciliación de análisis huérfanos.
- **RF5 — Aegis:** píldoras de concienciación generadas por IA (scribe: OpenAI/Ollama/Gemini), campañas con listas de distribución, envío por `herald` (SMTP), quiz público por token opaco (único endpoint sin auth), perfil de organización.
- **RF6 — Acheron:** vault zero-knowledge (cripto en cliente, interop web/móvil verificada por vectores compartidos), 7 tipos de storable, generador de contraseñas (autenticado).
- **RF7 — Sistema:** cola de tareas persistente (RQ+Redis) con categorías, cancelación cooperativa, progreso, reconciliación al arranque; administración de tareas y config en runtime (`/system/tasks/*`, `PUT /system` con control de concurrencia).

**Faltantes confirmados (grep negativo — todos previstos por el plan SaaS):**

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
| **RNF1** | **Seguridad:** hashing Argon2id, Fernet para TOTP, anti-SSRF en todos los scanners, rate limiting distribuido, mínimo endpoint público, config global solo-root con control de concurrencia | ✅ sólido en código y despliegue |
| **RNF2** | **Rendimiento:** servidor WSGI de producción, gzip + cache de assets | ✅ resuelto |
| **RNF3** | **Disponibilidad/resiliencia:** tareas sobreviven reinicios (RQ persistente), reconciliación de huérfanos, `restart: unless-stopped`, healthcheck de API; sin monitoring ni backups | parcial — falta plan de Fase 0 (backups, UptimeKuma) |
| **RNF4** | **Escalabilidad:** single VPS, single DB, aislamiento por `user_id`; colas por categoría; RLS y prioridades diferidas a Fase 3 | acorde al plan |
| **RNF5** | **Mantenibilidad:** capas endpoint→manager→repo respetadas, suite de integración amplia, pylint limpio, migraciones lineales | ✅ sólido; deuda restante = N12 (opcional) |
| **RNF6** | **Reproducibilidad de build:** mismas fuentes → misma imagen | ❌ `requirements.txt` sin lockfile |
| **RNF7** | **Cumplimiento (UE):** páginas legales preliminares ✅; fuentes autoalojadas (sin CDN de Google) ✅; sin export GDPR (RF14) | pendiente antes de cobrar (RF14) |
| **RNF8** | **Portabilidad:** API Linux-only (nmap/nikto/openvas) — asumido y documentado; web/tests corren en Windows | ✅ asumido |
| **RNF9** | **Observabilidad:** logs JSON rotados en compose, `log_min_duration_statement=200`; sin métricas ni uptime monitoring | parcial (plan: UptimeKuma) |
| **RNF10** | **i18n:** texto embebido en español | asumido mientras el mercado sea ES/LatAm |

---

## 5. Contraste con el plan de viabilidad SaaS

Estado de los bloqueantes de Fase 0 (`saas-viability-plan.md` §0 y §5) frente al código actual.

### Lecturas de viabilidad

1. **El código de producto ya no es el cuello de botella para lanzar.** Capas respetadas, ownership consistente, cola persistente, suite amplia, cero xfails, servidor WSGI de producción, decisiones de seguridad (S7/S9/S11 del histórico) resueltas. Lo que separa el repo de "puede cobrar a un cliente" es: RF8–RF11 (registro, reset de contraseña, pagos/pricing, cuotas), backups + monitoring, y SPF/DKIM/DMARC en el dominio de envío.

2. **El perfil de despliegue SaaS ya está alineado con el presupuesto del plan** (Ollama y OpenVAS fuera del arranque por defecto; stack mínimo = postgres + redis + api + worker + web).

3. **Checklist Fase 0 restante:**
   - [ ] Cuotas por usuario (RF10)
   - [ ] Reset de contraseña (RF9) + registro público (RF8)
   - [ ] Pasarela de pago + pricing (RF11)
   - [ ] Backups Postgres + UptimeKuma
   - [ ] SPF/DKIM/DMARC en dominio de envío
   - [ ] Decisión Caddy vs nginx+certbot (E8) ejecutada
   - [ ] Revertir `themis.areLocalIpsAllowed` a `false` antes de desplegar
