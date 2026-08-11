# Botón de reinicio del servidor Python desde ConfigView

> Plan de diseño para una funcionalidad que permite **reiniciar el proceso de la API
> (Flask)** desde la interfaz web de configuración. El botón vive en
> `web/app/src/views/ConfigView.vue` y solo es visible para administradores (rol
> `role_admin`) y, por extensión, para `root` (`role_root`), dado que la jerarquía
> de roles admite ambos al exigir `Role.ADMIN`.
>
> Documento de diseño. Describe el camino, **no código existente**. No se ha
> implementado nada todavía.

---

## 1. Qué es y qué NO es

**Es:** un botón de "zona de peligro" en la vista de Configuración que, tras una
confirmación, llama a un endpoint `POST /system/restart` (admin-only) y provoca
el reinicio **graceful** del proceso de la API, reutilizando la maquinaria de
apagado que ya existe en `run.py`.

**NO es (trampas de alcance):**

- No es un reinicio del **worker** RQ (contenedor/proceso separado). El worker
  tiene su propia señal de shutdown (`worker.py`) y, en el perfil `container`,
  vive en otro contenedor con su propia política `restart: unless-stopped`. Un
  reinicio del worker queda fuera de este plan (ver §10, trabajo futuro).
- No es un `os.execv` de auto-reemplazo in-place. El código base **no tiene
  precedente** de ese patrón (grep de `os.execv`/`os.execl` en `src/` devuelve
  cero) e introducirlo nuevo añadiría riesgo sin beneficio real, porque Docker
  ya auto-reinicia el contenedor al salir (ver §6).
- No es un reinicio de la base de datos, Redis ni Ollama. Solo la API.
- No expone `_init_db()` (destrucción de DB) por HTTP. Sigue sin haber endpoint
  para eso; este botón no lo añade.
- No es un reinicio "en caliente" que recargue `SecOpsConfig.json` sin parar el
  proceso. Para eso ya existe `PUT /system` + `CR.reload()`; el reinicio existe
  precisamente para los cambios que **sí** requieren proceso nuevo (pool de DB,
  credenciales `.env`, etc.).

**Encaje con la misión:** algunos ajustes de `ConfigView` (p. ej. los de la
sección "Base de datos" — `database.pool_size`, `isolation_level`) llevan la
nota explícita *"requiere reiniciar la API para aplicarse"*. Hoy ese reinicio es
manual (`docker compose restart` o matar/levantar `python run.py`). Este botón
cierra ese hueco de UX para el operador admin.

---

## 2. Decisión de arquitectura

### 2.1 Backend: endpoint nuevo en el blueprint `system`

No hay ningún endpoint de reinicio hoy. El sitio natural es
`API/src/modules/system/endpoints.py`, junto al resto de recursos admin-only del
blueprint `system_blp` (registrado en `run.py:218` con `url_prefix="/system"`).

Se modela sobre **`PUT /system/tasks/config`** (`endpoints.py:232-258`), que es
el análogo más cercano: muta estado del sistema, lleva `@limiter.limit` ajustado,
`@require_oauth_token` + `@require_role(minimum_role=Role.ADMIN)` y
`@handle_exceptions`. El nuevo endpoint hereda exactamente esa pila de
decoradores.

### 2.2 Estrategia de reinicio: `os._exit(0)` diferido, no `execv`

El proceso de la API ya tiene una **máquina de apagado robusta y probada** en
`run.py:63-177`:

- `_IS_SHUTTING_DOWN`, `_WORKER`, `_SHUTDOWN_DEADLINE_S = 6` (estado global).
- `_kill_worker_tree()` — mata el worker + descendencia (nmap, nikto…) vía
  `psutil` con timeout de 3 s.
- `_run_shutdown_cleanup()` — hilo daemon: cancela todas las tareas
  (`TaskQueue.get_instance().cancel_all()`), para APScheduler
  (`Scheduler.stop()`), cierra sesiones DB (`unit_of_work.close_all()`).
- `_graceful_shutdown(signum, *args)` — handler de SIGTERM/SIGINT que orquesta
  lo anterior y termina en `os._exit(0)` (`run.py:177`).

**El endpoint de reinicio es, literalmente, "_graceful_shutdown, pero disparado
por una petición HTTP y diferido hasta que la respuesta se haya enviado".**

Mecánica:

1. El handler valida (admin), programa en un **hilo daemon** un disparo diferido
   (sleep de ~1.5–2 s) que llama a la misma rutina de shutdown, y devuelve
   **inmediatamente** un `202 Accepted` con un cuerpo JSON
   `{"message": "Reiniciando…", "delaySeconds": <n>}`.
2. El sleep da tiempo a Werkzeug a vaciar el buffer de la respuesta al socket
   antes de que el proceso muera.
3. El hilo llama a `_run_shutdown_cleanup()` (reutilización directa, no copia) y
   termina en `os._exit(0)`.

**Por qué `os._exit(0)` y no `sys.exit`/`raise SystemExit`:** Werkzeug captura
excepciones en el dev server y puede convertir un `SystemExit` en un 500 en vez
de parar el proceso. El código base usa deliberadamente `os._exit(0)` tanto en
`run.py:177` como en `worker.py:240` para saltarse el manejo de excepciones de
Python. Seguir ese precedente es lo consistente y lo fiable.

**Por qué no `os.execv` (auto-reemplazo in-place):**

- No hay precedente en el repo (grep cero). Introducirlo sería novedad.
- `execv` reemplaza la imagen del proceso sin soltar recursos implícitamente;
  si no corre `_run_shutdown_cleanup()` **antes**, se huérfana el worker
  (`_WORKER["proc"]`), se orphanan hijos nmap/nikto y APScheduler queda corriendo.
- En el perfil `container`, `execv` es redundante: Docker ya reinicia al salir.
- En el perfil `dev` (lanzamiento manual `python run.py`), `execv` tras
  `app.run()` es incómodo porque el dev server no "vuelve" a un sitio donde
  llamar `execv` de forma natural.

### 2.3 Frontend: acción en `configStore`, botón en `ConfigView`

- Nueva acción `restartServer()` en `web/app/src/stores/configStore.js`, gemela
  de `saveConfig()` (`configStore.js:53-70`) en estructura: flag `restarting`,
  `apiFetch('/system/restart', { method: 'POST' })`, toasts info/error.
- Botón `type="button"` (¡no `submit`!) dentro del `.form-actions` de
  `ConfigView.vue:198-201`, gateado con `v-if="auth.isAdmin"`.
- Confirmación previa (ver §4) para evitar pulsaciones accidentales.

---

## 3. Detalles de diseño por capa

### 3.1 Backend — `API/src/modules/system/endpoints.py`

**Ruta:** `POST /system/restart` (sin body, sin query params).

**Pila de decoradores (outermost → innermost), idéntica a `PUT /system/tasks/config`:**

1. `@system_blp.post("/restart")`
2. `@system_blp.response(202, RestartAcceptedSchema, description="Restart scheduled")`
3. `@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")`
4. `@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")`
5. `@@limiter.limit("3 per hour; 10 per day")` — **muy estricto**, es un botón
   que tira el proceso.
6. `@require_oauth_token`
7. `@require_role(minimum_role=Role.ADMIN)` — admite `role_admin` y `role_root`.
8. `@handle_exceptions(default_exception=IllegalStateError, logger=logger)`

> Nota sobre el orden: `@require_oauth_token` va **detrás** (más interno que)
> `@require_role`, porque el primero inyecta `request.current_user_role` que el
> segundo lee. Es el orden que usa toda la vista (docstring en
> `permissions.py:256`).

**Cuerpo del handler (esquema, no código final):**

```
def system_restart():
    """Reinicia el proceso de la API de forma graceful.
    Reutiliza _run_shutdown_cleanup() de run.py: cancela tareas, para
    APScheduler, cierra sesiones DB y mata el árbol del worker. La salida
    final es os._exit(0), diferada en un hilo daemon para que esta respuesta
    202 llegue al cliente antes de que el proceso muera.
    En contenedor, Docker (restart: unless-stopped) relanza la API solo.
    En dev (python run.py sin supervisor), el proceso queda abajo y debe
    rearrancarse manualmente.
    """
    # 1. Idempotencia: si ya hay un reinicio en curso, no encolar otro.
    #    Usar una bandera module-level o un Lock en endpoints.py.
    # 2. Lanzar hilo daemon: threading.Thread(target=_deferred_restart,
    #    args=(delay,), daemon=True).start()
    # 3. Devolver RestartAcceptedSchema(message="Reiniciando…",
    #    delaySeconds=delay)
```

**`_deferred_restart(delay)` (función auxiliar en `endpoints.py` o, mejor, en
`run.py` reutilizando lo que ya existe):**

```
def _deferred_restart(delay):
    time.sleep(delay)            # da tiempo a flush de la respuesta
    # reutilizar la maquinaria existente de run.py:
    _run_shutdown_cleanup()      # cancela tareas, Scheduler.stop(), close DB
    os._exit(0)
```

> **Visibilidad de `_run_shutdown_cleanup` y `_IS_SHUTTING_DOWN`:** hoy viven en
> `run.py` como símbolos module-level "privados" (prefijo `_`). Hay dos opciones
> limpias para exponerlos al endpoint sin romper encapsulación:
>
> **(a) Mover la maquinaria de shutdown a un módulo `system/services/restart.py`
> (o `lifecycle.py`) y que `run.py` la importe.** Es lo más correcto
> arquitectónicamente: el ciclo de vida del proceso deja de ser приватно de
> `run.py` y se convierte en un servicio del módulo `system`, importable tanto
> por `run.py` (para los signal handlers) como por `endpoints.py` (para el
> endpoint de reinicio). `run.py` queda como mero pegamento de entry point.
>
> **(b) Importar desde `run.py` con un shim público:** `from run import
> _run_shutdown_cleanup`. Funciona pero acopla el endpoint al entry point (y
> `run.py` no es un paquete pensado para importarse desde `src/`).
>
> **Recomendación: (a).** Crea `API/src/modules/system/services/lifecycle.py`
> con `run_shutdown_cleanup()`, `is_shutting_down()`, `schedule_restart(delay)`
> y que `run.py:109-177` pase a consumirlo. Refactor mecánico, sin cambio de
> comportamiento. Deja el fallback (b) solo como nota si (a) se descarta por
> alcance.

**Schema nuevo en `API/src/modules/system/schemas.py`:**

```
class RestartAcceptedSchema(Schema):
    message = fields.String(required=True, dump_default="Reiniciando…")
    delaySeconds = fields.Integer(required=True, dump_default=2)
```

> Claves **camelCase** en JSON (`delaySeconds`), como manda la convención del
> API (ver `AGENTS.md` y los schemas existentes).

**Auditoría:** el middleware de auditoría de `run.py:366-409` loguea cada
petición con el actor tomado de `request.current_username` (inyectado por
`require_oauth_token`). El reinicio queda auditado "gratis": entrada con
`POST /system/restart`, usuario `root` (o el admin que lo pulse), timestamp.
No hace falta lógica extra de log.

**Rate limiting:** `3 per hour; 10 per day` es deliberadamente austero. Un
reinicio cuelga la API unos segundos y, en dev, la deja abajo. No queremos un
admin (o un script con su token robado) martilleando el botón. Si se necesita
más holgura, se sube; nunca bajar de esto.

### 3.2 Backend — refactoring de `run.py` (opcional pero recomendado)

Movimiento mecánico para soportar §3.1 opción (a):

- Crear `API/src/modules/system/services/lifecycle.py` con:
  - estado global: `_IS_SHUTTING_DOWN`, `_WORKER`, `_SHUTDOWN_DEADLINE_S`
    (movidos desde `run.py:63-68`).
  - `kill_worker_tree()` (desde `run.py:71-106`).
  - `run_shutdown_cleanup()` (desde `run.py:109-141`).
  - `graceful_shutdown(signum, *args)` (desde `run.py:144-177`) — ahora callable
    tanto desde signal handlers como desde el endpoint.
  - `is_shutting_down() -> bool`.
  - `schedule_restart(delay: float)` — el hilo daemon diferido.
- `run.py` pasa a `from src.modules.system.services.lifecycle import ...` y
  registra `graceful_shutdown` como handler de SIGTERM/SIGINT (líneas 528-535).
- `endpoints.py` importa `schedule_restart` y `is_shutting_down`.

**No cambia ningún comportamiento existente** (signals, worker, scheduler). Es
un movimiento de código para abrir la API pública que el endpoint necesita.

### 3.3 Frontend — `web/app/src/stores/configStore.js`

Nueva acción, gemela de `saveConfig()`:

```
const restarting = ref(false)

async function restartServer() {
  restarting.value = true
  toast.show('Reiniciando servidor…', 'info')
  try {
    const res = await apiFetch('/system/restart', { method: 'POST' })
    // El servidor morirá ~2s después de enviar el 202. Es normal que la
    // conexión se corte o que apiFetch devuelva null tras el reinicio.
    if (res?.ok) {
      // 202 recibido: el reinicio está en curso. No mostrar "éxito" todavía;
      // el usuario verá la reconexión cuando la API vuelva.
      toast.show('Reiniciando. La conexión se cortará unos segundos.', 'info', 6000)
    } else if (res === null) {
      // Redirección a login o caída de red — si fue justo tras pulsar,
      // asumimos reinicio en curso (no es un error real para el usuario).
      toast.show('Reiniciando. La API volverá en unos segundos.', 'info', 6000)
    } else {
      // HTTP 4xx/5xx real (403, 429, 500…)
      const data = await res?.json().catch(() => ({}))
      toast.show(data.message || 'No se pudo reiniciar el servidor.', 'error')
    }
  } finally {
    restarting.value = false
  }
}
```

**Idiomas a replicar del `saveConfig` existente:**

- Flag `restarting` toggled en `try`/`finally` para `:disabled` del botón.
- Guard `if (res?.ok)` / `res === null` / else (los tres casos, porque aquí el
  `null` de `apiFetch` es **esperado**, no excepcional).
- Extracción segura del cuerpo de error: `await res?.json().catch(() => ({}))`.
- Toast en cada rama.

**Devolver `restarting` desde el store** (junto a `saving`, `loading`, etc.).

### 3.4 Frontend — `web/app/src/views/ConfigView.vue`

**Imports a añadir (bloque `<script setup>`, líneas 210-218):**

- `import { useAuthStore } from '@/stores/authStore'`
- `const auth = useAuthStore()`

(Hoy `ConfigView.vue` **no** importa `authStore`; confirmado por grep.)

**Botón en `.form-actions` (líneas 198-201):**

```html
<div class="form-actions">
  <button type="button" class="btn btn--danger"
          v-if="auth.isAdmin"
          :disabled="store.restarting"
          @click="confirmRestart">
    {{ store.restarting ? 'Reiniciando…' : 'Reiniciar servidor' }}
  </button>
  <button type="button" class="btn btn--secondary" @click="store.resetForm()">Restablecer</button>
  <button type="submit" class="btn btn--primary" :disabled="store.saving">
    {{ store.saving ? 'Guardando…' : 'Guardar Configuración' }}
  </button>
</div>
```

**`type="button"` es obligatorio** (como en Restablecer) para que no envíe el
formulario `@submit.prevent="handleSave"`.

**Handler de confirmación en `<script setup>`** (junto a `handleSave:269`):

```
function confirmRestart() {
  // Confirmación nativa; suficiente para un botón de zona de peligro.
  // Si se quiere algo más bonito, mirar si ya existe un modal de confirmación
  // en components/shared (pendiente verificar; ver §9).
  if (!window.confirm('¿Reiniciar el servidor Python? La API se caerá unos segundos.')) return
  store.restartServer()
}
function handleSave() { store.saveConfig() }   // ya existe
```

**Clase `btn--danger`:** verificar si ya existe en los estilos globales. Si no,
añadir una regla (fondo rojo / borde rojo) al `<style scoped>` de ConfigView o
al CSS global de botones. El sistema ya tiene `btn--primary` y `btn--secondary`
usados en este mismo archivo, así que `btn--danger` encaja como convención.

**No hace falta tocar `AppToast`:** ya está montado en `ConfigView.vue:206`, y
`configStore` ya inyecta `useToastStore()`.

---

## 4. Confirmación y UX

- **Confirmación previa obligatoria.** El botón tira el proceso; un clic
  accidental es caro. `window.confirm(…)` basta para la v1. Si el design system
  ya tuviera un `ConfirmModal` reusable, mejor ese (pendiente verificar en
  §9).
- **Mensaje honesto sobre dev vs. container:**
  - En `container` (Docker, `restart: unless-stopped`): "La API volverá en unos
    segundos." — Docker la rearranca solo.
  - En `dev` (`python run.py` manual, sin supervisor): "El proceso se detendrá.
    Rearranca `python run.py` manualmente." — aquí el botón **detiene**, no
    reinicia solo.
  - Dado que el frontend no sabe a ciencia cierta cómo se lanzó la API, el
    toast debe ser genérico y cubrir ambos casos: "Reiniciando. La conexión se
    cortará unos segundos." (el caso peor —dev— queda implícito).
- **Deshabilitar el botón durante `store.restarting`** para evitar dobles
  envíos. Como el proceso muere, el flag nunca se resetea por la vía feliz; el
  `finally` lo resetea solo en la rama de error HTTP. Es aceptable: tras un
  reinicio exitoso, el usuario recarga la página al reconectar.

---

## 5. Seguridad

- **Rol:** `@require_role(minimum_role=Role.ADMIN)` admite `role_admin` y
  `role_root`. El usuario `root` sembrado por `_init_db()` (`run.py:499`) tiene
  `role='role_root'` y pasa el corte. Cumple el requisito del plan ("solo
  administradores y, por ende, root").
- **Frontend:** `v-if="auth.isAdmin"` oculta el botón a usuarios `role_user`.
  (`authStore.js:49`: `isAdmin = role === 'role_admin' || role === 'role_root'`.)
  El ocultamiento en UI es cosmético; el gate real es el backend.
- **JWT:** `apiFetch` inyecta `Authorization: Bearer <token>` automáticamente
  (`useApi.js:37-41`). No hace falta nada manual.
- **Rate limit:** `3 per hour; 10 per day` limita el abuso incluso si el token
  de un admin se compromete.
- **Auditoría:** el middleware de `run.py` registra la petición con el actor.
  Trazabilidad "gratis".
- **CSRF:** el API usa Bearer tokens (no cookies), así que no hay superficie
  CSRF relevante.
- **Idempotencia:** si el endpoint se llama dos veces rápido (doble clic antes
  de que `restarting` se asiente, o retry de `apiFetch` tras 401), el segundo
  call debe ser no-op. Una bandera `is_shutting_down()` (o un `threading.Lock`)
  en `lifecycle.py` lo garantiza: el segundo call devuelve 202 inmediatamente
  sin programar otro `os._exit`.

---

## 6. Entornos y reinicio real

| Entorno | Lanzamiento | ¿Se rearranca solo al `os._exit(0)`? | UX esperada |
|---|---|---|---|
| `container` (docker compose) | `python run.py` en contenedor `Ellysia-API` | **Sí** — `restart: unless-stopped` (`docker-compose.yml:142`) | La API vuelve sola en ~2-5 s |
| `dev` (manual) | `python run.py` en terminal | **No** — no hay supervisor | El proceso queda abajo; rearranque manual |
| `dev` con `--with-worker` | API + worker en mismo proceso | No (API muere, worker huérfano muerto por `_kill_worker_tree`) | Igual que dev; además el worker se mata limpio |

**Worker RQ:** en `container`, el worker vive en `ellysia-worker` (contenedor
distinto, `restart: unless-stopped`, `docker-compose.yml:188`) y **no** se ve
afectado por el reinicio de la API. Sus jobs persisten en Redis y sobreviven.
En `dev` con `--with-worker`, `_kill_worker_tree()` mata el worker hijo limpio.

**APScheduler:** `Scheduler.stop()` corre en `_run_shutdown_cleanup()`, así que
no queda zombi. Al rearrancar (container) o al levantar de nuevo (dev),
`Scheduler.start()` se ejecuta otra vez en `create_app()` (`run.py:263`) y
re-sincroniza los schedules desde DB.

---

## 7. Schemas y contratos

### Request

```
POST /system/restart
Authorization: Bearer <access_token>
Content-Type: application/json
(cuerpo vacío)
```

### Response 202

```json
{ "message": "Reiniciando…", "delaySeconds": 2 }
```

### Response 401 (no autenticado)

```json
{ "message": "Not authenticated" }
```

### Response 403 (rol insuficiente)

```json
{ "message": "Insufficient role" }
```

### Response 429 (rate limit excedido)

Estándar de `flask-limiter`.

### Response 409 (ya hay reinicio en curso) — opcional

Si se implementa la idempotencia con error en vez de 202 silencioso:

```json
{ "message": "Ya hay un reinicio en curso" }
```

---

## 8. Archivos a tocar (resumen)

**Backend:**

- `API/src/modules/system/services/lifecycle.py` — **NUEVO**. Maquinaria de
  shutdown movida desde `run.py` (estado global, `kill_worker_tree`,
  `run_shutdown_cleanup`, `graceful_shutdown`, `schedule_restart`,
  `is_shutting_down`).
- `API/run.py` — refactor mecánico: importa de `lifecycle.py` en vez de tener
  las funciones inline (líneas 63-177, 528-535). Sin cambio de comportamiento.
- `API/src/modules/system/endpoints.py` — **NUEVO** endpoint `POST /system/restart`
  + import de `schedule_restart`/`is_shutting_down` desde `lifecycle.py`.
- `API/src/modules/system/schemas.py` — **NUEVO** `RestartAcceptedSchema`.
- `API/src/modules/system/__init__.py` — exportar `lifecycle` si hace falta.

**Frontend:**

- `web/app/src/stores/configStore.js` — **NUEVA** acción `restartServer()` +
  flag `restarting` (exportado).
- `web/app/src/views/ConfigView.vue` — import `useAuthStore`, botón
  `btn--danger` con `v-if="auth.isAdmin"` en `.form-actions`, handler
  `confirmRestart()`.
- CSS global o `<style scoped>` de ConfigView — clase `.btn--danger` (si no
  existe ya).

**Tests (si hay suite de API):** verificar cómo se testea el blueprint `system`
hoy y añadir caso para `/system/restart` (mockeando `schedule_restart` para que
no mate el proceso de test). Pendiente de revisar en fase de implementación.

---

## 9. Verificaciones pendientes antes de implementar

1. **¿Existe `btn--danger` en los estilos globales?** Grep de `btn--danger` en
   `web/app/src`. Si no existe, definirla o reutilizar `btn--secondary` con
   tono rojo.
2. **¿Hay un `ConfirmModal` reusable en `components/shared`?** Si sí, usarlo en
   vez de `window.confirm` para el diálogo de confirmación. Si no, `window.confirm`
   es aceptable para v1.
3. **¿Cómo se testean los endpoints de `system`?** Buscar tests existentes de
   `endpoints.py` (probablemente bajo `API/tests/` o similar) para replicar el
   patrón con `schedule_restart` mockeado.
4. **¿`time` ya importado en `endpoints.py`?** Si no, añadir import para el
   sleep del hilo diferido (o que `schedule_restart` encapsule el sleep en
   `lifecycle.py` y no necesite importarlo en el endpoint).
5. **¿El middleware de auditoría loguea correctamente tras el `os._exit`?**
   Verificar que el log de la petición se flushea antes de que el hilo daemon
   mate el proceso (si la auditoría es síncrona en el `after_request`, sí; si
   es asíncrona, puede perderse — aclarar).

---

## 10. Trabajo futuro (fuera de alcance de este plan)

- **Reiniciar el worker RQ** desde la UI (endpoint `POST /system/worker/restart`
  o similar). Hoy el worker es proceso/contenedor separado; su reinicio es
  independiente.
- **Reiniciar contenedores de infra** (postgres, redis, ollama) desde
  la UI — requeriría Docker socket o un sidecar, y eleva mucho el riesgo.
- **Auto-restart en dev** sin supervisor: un script `run_supervised.sh` que
  envuelva `python run.py` y lo rearranque al salir con código 0, para que el
  botón "reinicie" de verdad también en dev.
- **Polling de salud tras reinicio:** tras pulsar el botón, la UI podría hacer
  `GET /system/say-hello` (endpoint público, `endpoints.py:40-50) en bucle
  hasta que vuelva 200, y entonces mostrar un toast "Servidor de vuelta". Mejor
  UX que dejar al usuario recargar a mano. Apto para v2.

---

## 11. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| El proceso muere antes de que la respuesta 202 llegue al cliente | Hilo daemon con `sleep(delay)` (1.5–2 s) antes de `os._exit`. Si aun así se corta, el frontend trata `res === null` como "reinicio en curso" (§3.3). |
| Doble clic / doble envío | Flag `restarting` (UI) + `is_shutting_down()`/Lock (backend). Segundo call → 202 silencioso o 409. |
| Token de admin comprometido martillea el botón | `@limiter.limit("3 per hour; 10 per day")`. |
| `run.py` refactor (§3.2) rompe el shutdown existente | Refactor mecánico puro (mover, no reescribir). Mismas funciones, mismo comportamiento. Verificar con un `docker compose down && up` y un SIGTERM manual antes/después. |
| Worker huérfano tras reinicio en `dev --with-worker` | `_kill_worker_tree()` ya corre en `_run_shutdown_cleanup()`. En container, el worker es contenedor aparte e imperturbable. |
| APScheduler zombi | `Scheduler.stop()` ya corre en `_run_shutdown_cleanup()`. |
| Cola de tareas perdida | Las jobs RQ persisten en Redis; `cancel_all()` cancela las en vuelo, pero las pendientes se retoman al rearrancar el worker. Documentar si se quiere "no cancelar, solo reiniciar". |
| Sesiones DB abiertas | `unit_of_work.close_all()` ya corre en `_run_shutdown_cleanup()`. |

---

## 12. Orden de implementación propuesto (cuando se ejecute)

1. Backend refactor §3.2: crear `lifecycle.py`, mover funciones de `run.py`,
   verificar que `docker compose restart` y SIGTERM siguen funcionando igual.
2. Backend endpoint §3.1: `RestartAcceptedSchema` en `schemas.py`, endpoint en
   `endpoints.py`, import de `schedule_restart`/`is_shutting_down`.
3. Backend test: caso `POST /system/restart` con `schedule_restart` mockeado
   (no queremos que el test mate el runner).
4. Frontend store §3.3: `restartServer()` + `restarting` en `configStore.js`.
5. Frontend UI §3.4: import `authStore`, botón `btn--danger` con `v-if`, handler
   `confirmRestart`.
6. CSS: definir `btn--danger` si no existe.
7. Verificación §9: grep `btn--danger`, buscar `ConfirmModal`, revisar tests de
   `system`.
8. Prueba manual en `container` (Docker) y en `dev` (manual).

---

*Documento de diseño. No se ha escrito código de implementación; este plan es
la guía para ejecutarla.*
