# Hygeia — Backend del agente de monitorización de activos

> Plan de diseño para el módulo **Hygeia**: la parte de Ellysia que **recibe, almacena,
> evalúa y alerta** sobre la telemetría de hardware que envían agentes instalados en los
> activos monitorizados (picos de CPU, memoria alta, disco lleno, host caído…).
>
> El nombre es Hygeia (Ὑγίεια), diosa griega de la salud: el módulo vigila los **signos
> vitales** de cada activo y avisa cuando algo se sale de lo sano.
>
> El **agente** que recolecta las métricas vive en **otro repositorio** (`Ellysia - Hygeia`,
> ver su propio plan/README). Este documento cubre solo lo que Ellysia (este repo) necesita
> para acogerlo. El punto de contacto entre ambos repos es el **contrato de ingesta** (§11).
>
> Documento de diseño. Describe el camino, no código existente. Nombre del módulo: `hygeia`.

---

## 1. Qué es Hygeia y qué NO es

**Es:** un módulo de ingesta de telemetría + detección de anomalías + alertado.
Un flujo *push*: agentes ligeros en los hosts empujan snapshots de métricas cada N
segundos; el backend los persiste, evalúa reglas de umbral/baseline y abre incidencias.

**NO es** (trampas de alcance, estilo `lybra-engine-roadmap.md`):

- No es un Prometheus/Grafana/Datadog. No construyas un TSDB propio, ni un lenguaje de
  consulta tipo PromQL, ni dashboards de gráficas arbitrarias. Postgres + JSONB basta
  para el beta; el techo está documentado en §3.
- No es APM (trazas, spans, instrumentación de aplicación). Solo métricas de host.
- No es *pull*: el backend no sondea a los agentes. Son ellos los que empujan. Esto
  evita abrir puertos en los activos y encaja con hosts detrás de NAT.
- No reimplementa el sistema de tareas ni el de scheduling: reutiliza RQ y APScheduler.

**Encaje con la misión de Ellysia:** la monitorización de hardware es la puerta de entrada
a señales de *seguridad* (un pico sostenido de CPU por un proceso desconocido huele a
cryptominer; un puerto nuevo a la escucha, a persistencia). El agente puede recolectar
esas señales "de seguridad" además de las de rendimiento — ver el plan del agente.

---

## 2. Decisión de arquitectura: **módulo nuevo**, no un `ScanType` de Sentinel

Hygeia **no** encaja en la abstracción polimórfica de Sentinel (`ScanType → Task →
Processor → Manager`). Esa abstracción modela *"lanzar una herramienta contra un objetivo
y procesar su salida una vez"*. Hygeia es lo contrario: **flujo continuo entrante**, sin
"lanzar" nada. Meterlo en Sentinel deformaría ambos.

Por tanto, un módulo hermano nuevo con la **misma estratificación** que el resto
(`endpoints → managers → repositories → model/schemas`, helpers en `services/`):

```
API/src/modules/hygeia/
  endpoints.py      # Blueprint; auth (usuario + agente) y validación de schema
  managers.py       # HygeiaAssetManager, HygeiaIngestManager, HygeiaAlertManager
  repositories.py   # acceso a datos vía UnitOfWork
  model.py          # MonitoredAsset, AssetSnapshot, Anomaly
  schemas.py        # Marshmallow, claves JSON camelCase
  exceptions.py
  services/
    detection.py    # evaluación de reglas de umbral/baseline
    enrollment.py   # emisión/verificación de claves de agente
    retention.py    # poda/agregación de snapshots antiguos (job programado)
```

Se registra en `run.py` junto al resto:

```python
flask_smorest_api.register_blueprint(hygeia_blp, url_prefix="/hygeia")
```

### Lo que reutilizas (no partes de cero)

| Pieza que necesita Hygeia | Dónde ya existe |
|---|---|
| Frontera transaccional + repos | `infrastructure` (`UnitOfWork`, `base_repository`) |
| Cierre de sesión por request/job | `teardown_request` / `job_context` (ya cableado) |
| Cola de trabajos aislada | `system/taskqueue` (RQ + Redis) |
| Programación de jobs recurrentes | `sentinel/services/scheduling.py` (APScheduler) |
| Hashing fuerte (para claves de agente) | Argon2id, ya usado para contraseñas (`users`) |
| Auth de usuario + roles | `require_oauth_token` / `require_attributes` (`users`) |
| Envío de correo (alertas) | `herald` (SMTP relay, estrategia por módulo) |
| Narrativa IA opcional de incidencias | `scribe` (estrategia Ollama/OpenAI) |
| Config por capas cacheada | `system/config_reading.py` (`CR`) + `SecOpsConfig.json` |
| Modelo base + `Document` + `handle_exceptions` | `shared/` |

El trabajo real es: **modelo de datos + endpoint de ingesta + auth de agente + reglas de
detección**. Todo lo demás se enchufa a infraestructura existente.

---

## 3. Modelo de datos

Tres tablas. Estilo idéntico al resto (`Base` de `shared`, `JSONB` de Postgres, docstrings
en español).

### 3.1 `MonitoredAsset` — el activo vigilado

```python
class MonitoredAsset(Base):
    """Activo (host/máquina) monitorizado por un agente Hygeia."""
    __tablename__ = "MonitoredAsset"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    hostname      = Column(String(255), nullable=False)
    os            = Column(String(64))            # "linux" | "windows" | "darwin"
    labels        = Column(JSONB)                 # etiquetas libres: env, rol, ubicación…

    # Identidad del agente (ver §4)
    agent_key_id   = Column(String(32), unique=True, index=True, nullable=False)  # prefijo público; permite el lookup O(1)
    agent_key_hash = Column(String(255), nullable=False)   # Argon2id del secreto (nunca el secreto en claro)
    agent_version  = Column(String(32))

    # Estado de presencia
    status        = Column(String(16), default="pending")  # pending|online|stale|offline
    last_seen_at  = Column(DateTime)              # último heartbeat recibido

    user_id       = Column(Integer, ForeignKey("User.id"), nullable=False)  # dueño
    created_at    = Column(DateTime, default=datetime.utcnow)

    snapshots     = relationship("AssetSnapshot", back_populates="asset",
                                 cascade="all, delete-orphan")
    anomalies     = relationship("Anomaly", back_populates="asset",
                                 cascade="all, delete-orphan")
```

### 3.2 `AssetSnapshot` — un heartbeat con todas las métricas

**Decisión clave (ponytail):** **una fila por heartbeat**, con todas las métricas en un
`JSONB`, en lugar de una fila por (métrica, timestamp). El agente empuja un payload
completo por intervalo, así que una fila por payload es el mapeo natural y minimiza
volumen de filas y complejidad de escritura.

```python
class AssetSnapshot(Base):
    """Instantánea de métricas de un activo en un instante (un heartbeat)."""
    __tablename__ = "AssetSnapshot"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    asset_id   = Column(Integer, ForeignKey("MonitoredAsset.id", ondelete="CASCADE"),
                        index=True, nullable=False)
    collected_at = Column(DateTime, index=True, nullable=False)  # reloj del agente
    received_at  = Column(DateTime, default=datetime.utcnow)     # reloj del servidor

    # Métricas completas del heartbeat (esquema en §11). Se guarda tal cual llega,
    # ya validado por el schema Marshmallow de ingesta.
    metrics    = Column(JSONB, nullable=False)

    # Desnormalizados para filtrar/ordenar sin abrir el JSONB (los 2-3 que más se
    # consultan). El resto vive dentro de `metrics`.
    cpu_pct    = Column(Float)
    mem_pct    = Column(Float)

    asset = relationship("MonitoredAsset", back_populates="snapshots")

    __table_args__ = (Index("ix_snapshot_asset_time", "asset_id", "collected_at"),)
```

> **ponytail: JSONB + índice compuesto, no un TSDB.** A 15 s de intervalo son ~5.760
> filas/activo/día. Con 100 activos, ~0,5 M filas/día: Postgres lo digiere sin problema
> **si hay poda** (§7). Techo y ruta de subida: cuando el volumen o las consultas por
> métrica individual a lo largo del tiempo aprieten, migrar `AssetSnapshot` a un
> *hypertable* de **TimescaleDB** (misma tabla, extensión) o a una tabla `MetricSample`
> normalizada. No antes: es un cambio localizado, no un rediseño.

### 3.3 `Anomaly` — incidencia abierta por la detección

```python
class Anomaly(Base):
    """Anomalía detectada sobre las métricas de un activo (ciclo de vida propio)."""
    __tablename__ = "Anomaly"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    asset_id    = Column(Integer, ForeignKey("MonitoredAsset.id", ondelete="CASCADE"),
                         index=True, nullable=False)

    kind        = Column(String(48), nullable=False)  # cpu_spike|mem_high|disk_full|host_down|...
    severity    = Column(String(16), nullable=False)  # info|warning|critical
    metric      = Column(String(64))                  # "cpu.usagePct", "disk./"
    value       = Column(Float)                        # valor que disparó
    threshold   = Column(Float)                        # umbral cruzado
    details     = Column(JSONB)                         # contexto: proceso culpable, etc.

    state       = Column(String(16), default="open")  # open|acknowledged|resolved
    opened_at   = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime)

    asset = relationship("MonitoredAsset", back_populates="anomalies")
```

> **Ciclo de vida, no spam.** Una anomalía no se crea en cada heartbeat que cruza el
> umbral: se **abre** al primer cruce sostenido y se **resuelve** cuando la métrica vuelve
> por debajo (con histéresis). La lógica vive en `services/detection.py`. Esto es el mismo
> principio "estado a lo largo del tiempo, no listas inconexas" del roadmap del motor.

---

## 4. Autenticación del agente — la pieza transversal nueva

El único mecanismo de auth hoy es OAuth de **usuario** (Bearer JWT, `grantType=password`).
Los agentes son máquinas no interactivas: necesitan su propia identidad. Decisión (la más
simple que es correcta):

**Clave de agente por activo (bearer opaco), emitida en el alta y hasheada con Argon2id**
(el mismo hashing que ya usáis para contraseñas — cero dependencias nuevas). La clave tiene
**dos partes**, `<keyId>.<secreto>` (estilo token de GitHub/Stripe):

- `keyId` — prefijo corto, **público**, indexado en claro (`agent_key_id`). No es secreto:
  su único trabajo es localizar por índice qué activo intenta autenticarse.
- `secreto` — la parte de alta entropía (`secrets.token_urlsafe(32)`); de esto se guarda
  **solo** el hash Argon2id (`agent_key_hash`). Nunca se persiste en claro.

Flujo de alta (*enrollment*):

1. Un **usuario autenticado** da de alta un activo: `POST /hygeia/assets`. El backend genera
   `keyId` + `secreto`, guarda `keyId` en claro y **solo el hash Argon2id del secreto**, y
   **devuelve la clave completa (`keyId.secreto`) en claro una sola vez** (patrón "recovery
   codes" de MFA, que ya existe en el repo).
2. El operador configura esa clave en el agente (fichero de config del otro repo).
3. Cada heartbeat viaja con `Authorization: Bearer <keyId.secreto>` (o cabecera `X-Agent-Key`).

Verificación en el endpoint de ingesta (`require_agent_key`, en `services/enrollment.py`):
parte la clave por el separador, **localiza el activo por `keyId`** (índice → O(1), una sola
fila) y verifica el `secreto` contra su `agent_key_hash` con Argon2. Deja el `MonitoredAsset`
en el contexto de la request. **No emite JWT** — el agente no necesita sesión, solo probar su
clave en cada push.

> **Por qué el `keyId` no es opcional:** con un bearer opaco "de una sola pieza" no hay forma
> de saber **qué** activo lo emitió sin verificar el Argon2 de *todos* los activos uno a uno
> — cada hash tiene su propia sal, así que no se puede indexar por el secreto. Eso sería
> O(nº activos) verificaciones Argon2 (caras a propósito) **por cada heartbeat**: inviable y,
> de paso, un vector de DoS. El `keyId` reduce el lookup a una fila y una sola verificación.
> La respuesta uniforme ante un `keyId` inexistente se detalla en §16.6.

> **ponytail: bearer + Argon2, no mTLS ni client_credentials.** mTLS y un grant OAuth
> `client_credentials` son más robustos pero triplican el trabajo (PKI / rotación / nuevo
> flujo OAuth) y no aportan nada en beta. Techo: la **revocación** ya sale gratis (borra o
> marca la fila del activo por su `keyId`, y `POST /hygeia/assets/{id}/rotate-key` reemite);
> si más adelante quieres **rotación con solape** o expiración, añade una columna
> `agent_key_expires_at` y admite dos `keyId` vivos por activo durante la ventana de rotación
> — sigue siendo un par de columnas, no un rediseño. TLS lo aporta el reverse proxy, como el
> resto de la API.

**Aislamiento de datos:** un agente solo puede escribir sobre **su** activo (el que
resuelve su clave). Nunca aceptar `assetId` del payload como fuente de identidad — la
identidad es la clave, igual que en el quiz público de Aegis el token es la única
identidad.

---

## 5. Endpoints

Dos superficies separadas: **usuario** (OAuth) y **agente** (clave de agente).

### Superficie de usuario (`require_oauth_token`)

| Método | Ruta | Qué hace |
|---|---|---|
| `POST`   | `/hygeia/assets`               | Alta de activo → devuelve clave de agente (una vez) |
| `GET`    | `/hygeia/assets`               | Lista de activos + estado de presencia |
| `GET`    | `/hygeia/assets/{id}`          | Detalle + último snapshot |
| `GET`    | `/hygeia/assets/{id}/metrics`  | Serie temporal (`?from=&to=&metric=`) |
| `DELETE` | `/hygeia/assets/{id}`          | Baja del activo (revoca la clave) |
| `PUT`    | `/hygeia/assets/{id}/thresholds` | Umbrales por activo (override de los globales) |
| `POST`   | `/hygeia/assets/{id}/rotate-key` | Regenera la clave de agente |
| `GET`    | `/hygeia/alerts`               | Lista de anomalías (`?state=&severity=&assetId=`) |
| `POST`   | `/hygeia/alerts/{id}/ack`      | Reconocer una anomalía |
| `POST`   | `/hygeia/alerts/{id}/resolve`  | Resolver manualmente |

### Superficie de agente (`require_agent_key`)

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/hygeia/ingest` | **Ruta caliente.** Recibe un heartbeat (esquema §11) |

`endpoints.py` solo hace auth + validación de schema; toda la lógica en managers, y el
acceso a DB **solo** vía `UnitOfWork` + repositorio (regla del repo).

---

## 6. Detección de anomalías — dónde y cómo

**Dónde:** **síncrono en la ingesta**, dentro de `HygeiaIngestManager`. Evaluar unos
umbrales es comparar números — microsegundos. No merece una tarea RQ (que añadiría
latencia y complejidad). Persistir snapshot + evaluar + abrir/cerrar anomalías, todo en la
misma transacción del request.

**Cómo (beta):** reglas de **umbral estático con histéresis**, configurables por activo o
globales:

```python
# services/detection.py — esquema conceptual
def evaluate(asset, snapshot, open_anomalies, thresholds) -> list[AnomalyChange]:
    # cpu_spike: abre si cpu_pct > umbral N heartbeats seguidos; resuelve al bajar.
    # mem_high, disk_full: idem por métrica.
    # Devuelve altas/bajas de Anomaly; el manager las persiste.
```

Reglas mínimas del beta: `cpu_spike`, `mem_high`, `swap_thrash`, `disk_full`, `host_down`
(esta última la levanta el job de presencia, §7, no la ingesta).

> **ponytail: umbrales estáticos ahora, baseline estadístico después.** Un umbral fijo
> (CPU > 90 % durante 3 heartbeats) resuelve el 80 % del valor y se entiende de un vistazo.
> Techo y ruta de subida: cuando genere falsos positivos (una máquina que vive al 85 % no
> es una anomalía), pasar a *baseline* móvil (media/desv. de las últimas H horas, o EWMA).
> Se calcula como job programado que rellena `thresholds` dinámicos por activo — se enchufa
> en el mismo `evaluate`, sin tocar la ingesta. No lo construyas hasta tener datos reales
> que calibren qué es "normal" para cada host.

**Config de umbrales:** por la regla del repo (datos → `SecOpsConfig.json` vía
`config_reading.py`), los umbrales por defecto van en un bloque `hygeia` del JSON (§9); los
overrides por activo, en la columna/tabla de thresholds vía `PUT /hygeia/assets/{id}/thresholds`.

> **ponytail: síncrono ahora, pero con techo definido — no lo dejes crecer sin límite.**
> Comparar umbrales estáticos contra un único snapshot son microsegundos: no justifica RQ.
> Pero hay tres señales concretas de que la evaluación se ha vuelto demasiado pesada para
> vivir dentro de la transacción de ingesta: **(1)** una regla necesita I/O externo (consulta
> a un feed de reputación, inferencia de un modelo) — nunca bloquees la respuesta al agente
> por una llamada de red que no controlas; **(2)** una regla necesita una consulta histórica
> (el *baseline* móvil ya mencionado arriba) cuyo coste deja de ser despreciable frente al
> presupuesto de latencia del endpoint caliente; **(3)** aparece correlación entre varios
> activos (una campaña de anomalías simultáneas), que por definición no cabe en "evaluar un
> snapshot aislado". Cuando aparezca cualquiera de las tres, **no conviertas sin más cada
> heartbeat en un job de RQ**: el estado de histéresis de una `Anomaly` (abrir al N-ésimo
> cruce sostenido, resolver al volver por debajo) depende de que las evaluaciones de un mismo
> activo se procesen **en orden**, y una cola genérica no lo garantiza si dos heartbeats del
> mismo activo caen en workers distintos. La vía segura: mantener el chequeo de umbral ligero
> y síncrono (barato, con orden garantizado por vivir en la misma request) y mover solo el
> trabajo pesado — el que dispara (1)/(2)/(3) — a una tarea de enriquecimiento asíncrona
> **posterior al commit** (mismo patrón que ya usa el correo de §8: encolar tras confirmar la
> transacción, no dentro de ella). Si de verdad hace falta que la detección en sí sea
> asíncrona, serializa por activo (lock de Redis por `asset_id`, o un job keyed que RQ no
> empiece el siguiente heartbeat de ese activo hasta que el anterior termine) — no lo dejes
> a la suerte del orden de llegada a la cola.

---

## 7. Tareas de fondo (RQ + APScheduler)

Dos jobs recurrentes, con el patrón de `sentinel/services/scheduling.py`. Categorías RQ
nuevas: `hygeia.maintenance`.

### 7.1 Detector de presencia (host caído)

Job periódico (cada minuto, vía APScheduler). Su única entrada es el reloj — no evalúa
métricas, solo silencio:

1. **Selecciona candidatos.** Consulta `MonitoredAsset` cuyo `status` sea `online` o `stale`
   (nunca reprocesa uno que ya está `offline`) y cuyo `last_seen_at` sea anterior a
   `now - offlineAfterMissed × heartbeatIntervalSec` — o al intervalo específico de ese
   activo si el agente se auto-ajustó a un `nextIntervalSec` distinto del global (§11): el
   umbral de "lleva demasiado callado" debe compararse contra lo que el propio activo tiene
   configurado, no contra el valor por defecto de `SecOpsConfig.json`.
2. **Transición en dos escalones, no en uno.** `online → stale` en el primer corte (dejar
   ver "algo va mal" en el listado de activos antes de declarar la caída); `stale → offline`
   en un segundo corte, más permisivo. **Solo** la transición a `offline` abre
   `Anomaly(kind="host_down")` — `stale` es una señal visual (`GET /hygeia/assets`, §5), no
   una incidencia.
3. **Apertura idempotente.** Antes de crear la `Anomaly`, comprobar que no exista ya una
   `open` del mismo `kind="host_down"` para ese activo. Un job que corre cada minuto no debe
   abrir una anomalía nueva cada vez que se ejecuta mientras el activo sigue caído.
4. **A salvo de la carrera con un heartbeat que llega a la vez.** No hagas "leer
   `last_seen_at`, decidir en Python, escribir" en dos pasos: si un heartbeat entra justo
   cuando el job está evaluando, esa lectura pudo quedar obsoleta un instante después. Haz el
   corte con una escritura condicional atómica (`UPDATE ... WHERE last_seen_at < :umbral AND
   status != 'offline'`, vía el repositorio) para que sea Postgres, no el job, quien decida
   si el activo seguía realmente inactivo **en el momento de escribir**.

### 7.2 Resolución — no la hace el job, la hace la ingesta

Aquí vale la pena dejar explícita una asimetría: **`host_down` es la única `Anomaly` cuya
apertura y cierre viven en sitios distintos del código.** Las demás (`cpu_spike`,
`mem_high`...) se abren y se cierran ambas dentro de `HygeiaIngestManager.evaluate()` porque
ambas transiciones dependen de examinar un snapshot que llegó. `host_down` es lo contrario:
se abre por **ausencia** de snapshot (solo el job periódico puede detectar eso — la ingesta
nunca "ve" un silencio, porque si no llega nada, no hay request que dispare nada) y se cierra
por **presencia** de uno (recibir un heartbeat).

Por tanto, en `HygeiaIngestManager`, el primer paso al recibir un heartbeat — antes incluso
de evaluar los umbrales de métricas del propio snapshot (§6) — es:

1. Actualizar `MonitoredAsset.last_seen_at` y `status = "online"`, sea cual sea el estado
   previo (`stale` u `offline`): el heartbeat que acaba de llegar ya es la prueba de que el
   activo volvió.
2. Buscar una `Anomaly(asset_id=this, kind="host_down", state="open")`. Si existe, resolverla
   (`state="resolved"`, `resolved_at=now`) — no hace falta ninguna otra condición: recibir el
   heartbeat **es** la condición de resolución para este tipo concreto de anomalía.
3. Solo entonces, evaluar los umbrales de CPU/memoria/disco sobre los datos que trae el
   payload (§6), igual que en cualquier otro heartbeat.

El job de presencia (§7.1) solo abre; la ingesta (§7.2) solo cierra. Ambos actúan sobre el
mismo `asset_id` pero en transacciones separadas — no hace falta coordinarlos más allá de la
escritura condicional del punto 7.1.4, que ya evita que se pisen.

### 7.3 Poda/retención

Diaria: borra `AssetSnapshot` más antiguos que `retentionDays` (config). Opcional:
**downsampling** — antes de borrar, agregar a resolución horaria en una tabla
`AssetSnapshotHourly`. Para el beta, borrar basta; el downsampling es el techo.

> **ponytail:** el detector de presencia es el único job imprescindible del beta. La
> retención es imprescindible en cuanto haya tráfico real (si no, la tabla crece sin
> límite), pero el downsampling es opcional hasta que quieras histórico largo.

---

## 8. Notificaciones (reutiliza `herald` y `scribe`)

- **Correo en anomalía nueva (crítica):** al abrir una `Anomaly` de severidad `critical`,
  encolar (`hygeia.notify`) un correo al dueño vía **`herald`** — mismo mecanismo que las
  campañas de Aegis. No en la transacción de ingesta (no bloquear el push por SMTP): tarea
  RQ disparada tras el commit.
- **Resumen IA de incidencia (opcional):** `scribe` puede generar una narrativa breve
  ("CPU al 98 % sostenido 10 min, proceso `xmrig`, probable minado") a partir del snapshot
  + histórico. Estrategia elegida en `SecOpsConfig.json → ai.modules.hygeia`, como el resto.

> **ponytail:** el correo es el MVP de notificación. La narrativa IA es un *nice-to-have*;
> no la construyas hasta que el flujo de detección esté estable.

---

## 9. Configuración (`SecOpsConfig.json`)

Bloque nuevo `hygeia`, leído vía `CR` (regla del repo: nada de constantes mágicas en código):

```jsonc
"hygeia": {
  "heartbeatIntervalSec": 15,      // esperado del agente; el detector de presencia lo usa
  "offlineAfterMissed": 4,         // N heartbeats perdidos → offline
  "retentionDays": 30,
  "thresholds": {                  // por defecto; override por activo en DB
    "cpuPct":  { "warning": 85, "critical": 95, "sustainedHeartbeats": 3 },
    "memPct":  { "warning": 85, "critical": 95, "sustainedHeartbeats": 3 },
    "diskPct": { "warning": 85, "critical": 95 },
    "swapPct": { "warning": 40, "critical": 70 }
  },
  "limits": {                      // guardas anti-abuso (§16); nada hardcodeado en código
    "maxBodyBytes":         262144,  // 256 KB comprimido → 413 si se supera
    "maxDecompressedBytes": 1048576, // 1 MB tras gunzip → corta el gzip-bomb
    "maxProcesses":         20,      // tope de topCpu/topMem por snapshot
    "maxDiskMounts":        64,
    "maxNetInterfaces":     64,
    "minIntervalSec":       5,       // suelo de cadencia por clave (anti-flood) → 429
    "clockSkewSec":         300,     // ventana de cordura de collectedAt (±5 min)
    "maxAssetsPerUser":     500      // cuota de alta por usuario
  }
}
```

Y en `ai.modules` / `email.modules`, la selección de estrategia para `hygeia` (como
`sentinel`, `iris`, `aegis`).

---

## 10. Migraciones

Tres modelos nuevos → una migración Alembic autogenerada:

```bash
alembic revision --autogenerate -m "hygeia: MonitoredAsset, AssetSnapshot, Anomaly"
alembic upgrade head    # también corre solo al arrancar run.py
```

Sin cambios destructivos: son tablas nuevas, no tocan nada existente.

---

## 11. Contrato de ingesta — la costura entre los dos repos

**Este es el único acoplamiento entre el repo del backend y el del agente (`Ellysia -
Hygeia`).** Congélalo pronto y versiónalo (`agentVersion`). Claves **camelCase**
(convención de la API). El agente empuja `POST /hygeia/ingest` con
`Authorization: Bearer <agentKey>`, cuerpo JSON (idealmente gzip):

```jsonc
{
  "agentVersion": "1.0.0",
  "collectedAt": "2026-07-07T10:00:00Z",   // ISO-8601 UTC, reloj del agente
  "host": {
    "hostname": "web-01",
    "os": "linux",
    "kernel": "6.1.0",
    "uptimeSec": 123456
  },
  "metrics": {
    "cpu":    { "usagePct": 87.5, "loadAvg": [2.1, 1.8, 1.5], "ctxSwitches": 12345,
                "perCorePct": [88, 91, 80, 90] },
    "memory": { "totalBytes": 8589934592, "usedBytes": 7300000000, "usagePct": 85.0,
                "swapUsedPct": 12.0 },
    "disk":   [ { "mount": "/", "usagePct": 91.2, "freeBytes": 5000000000 } ],
    "network":[ { "iface": "eth0", "rxBytesPerSec": 120000, "txBytesPerSec": 45000,
                  "errIn": 0, "errOut": 0 } ],
    "processes": { "total": 210, "zombie": 1,
                   "topCpu": [ { "pid": 8123, "name": "xmrig", "cpuPct": 96.0 } ],
                   "topMem": [ { "pid": 990, "name": "java", "memPct": 22.0 } ] }
  },
  "localAlerts": []   // opcional: anomalías que el agente pre-marcó (autoridad = servidor)
}
```

Respuesta del backend (permite al agente auto-ajustarse sin re-desplegar):

```jsonc
{ "ok": true, "nextIntervalSec": 15, "serverTime": "2026-07-07T10:00:01Z" }
```

Reglas del contrato:
- El schema Marshmallow de ingesta **valida y descarta** lo desconocido (defensa en la
  frontera de confianza — no relajar esto aunque el agente sea "de confianza").
- La identidad del activo **sale de la clave**, nunca del payload.
- `metrics` se persiste tal cual en `AssetSnapshot.metrics`; solo `cpu.usagePct` y
  `memory.usagePct` se desnormalizan a columnas.

---

## 12. Fases de entrega

Cada fase es útil por sí sola (como el roadmap del motor).

| Fase | Entregable | Estado que habilita |
|---|---|---|
| **0** | Módulo `hygeia`, 3 modelos + migración, alta de activo (`POST/GET/DELETE /hygeia/assets`) con clave de agente (§4) | Puedes registrar activos y emitir claves |
| **1** | `POST /hygeia/ingest` con `require_agent_key`, persistencia de `AssetSnapshot`, `last_seen_at` | Un agente ya puede empujar y ves datos entrando |
| **2** | Detección síncrona de umbrales + modelo `Anomaly` con ciclo de vida; `GET /hygeia/alerts` + ack/resolve | Alertas reales de CPU/mem/disco |
| **3** | Job de presencia (`host_down`) + job de retención | Detecta caídas y no crece sin límite |
| **4** | Notificación por correo (`herald`) en anomalía crítica | Aviso proactivo al dueño |
| **5** | Consulta de series (`/assets/{id}/metrics`) para el dashboard de la SPA | Visualización histórica |
| **6** (opcional) | Baseline estadístico, resumen IA (`scribe`), downsampling, señales de seguridad | Menos falsos positivos, valor diferencial |
| **H0-H3** (opcional, ver §14) | Inventario de software del agente como entrada del matcher CPE→CVE de Lybra | Cobertura de CVE por host, sin fingerprinting remoto ni SSH |
| **D0** (opcional, ver §15) | Sección de descargas del agente Hygeia (binarios precompilados por SO/arquitectura) | Alta de un activo termina en "descarga el agente" sin salir de Ellysia |

**Rebanada mínima para esta semana:** Fases 0+1 → un activo empujando métricas que se ven
en la DB. A partir de ahí, Fase 2 es la que convierte "datos" en "alertas".

---

## 13. Aspectos transversales

- **Frontera de confianza.** Validar y limitar tamaño del payload de ingesta (un agente
  comprometido no debe poder tumbar la DB con snapshots gigantes). Rate-limit por clave de
  agente (reutiliza `limiter` de `shared`).
- **Aislamiento por dueño.** Toda consulta de usuario filtra por `user_id`; un usuario solo
  ve sus activos y sus anomalías.
- **Idempotencia/reloj.** Guardar `collected_at` (agente) y `received_at` (servidor) por
  separado; no fiarse del reloj del agente para el detector de presencia.
- **Frontend (fuera de este plan):** una página nueva en la SPA (Vue) con lista de activos,
  estado y gráficas — se apoya en `/hygeia/assets` y `/hygeia/*`. El proxy de Vite ya
  reenvía rutas al Flask; añadir `/hygeia` a esa lista.
- **Tests:** unit para `detection.evaluate` (histéresis, apertura/cierre) e integration para
  el flujo ingesta→anomalía, con el patrón SQLite+mocks de `tests/` (nunca tocar `src/`
  para acomodar tests).

---

## 14. Integración con Themis/Lybra — el inventario de software como entrada del matcher CPE→CVE

> Sección añadida a partir de una conversación de diseño (2026-07-13): Hygeia y Themis miran
> el mismo activo desde ángulos opuestos — Themis desde la red (lo que un atacante ve desde
> fuera: puertos, banners, fingerprinting inferido); Hygeia desde dentro del host (lo que hay
> realmente instalado). Esta sección explora la sinergia: que el **descubrimiento** de uno
> alimente el **análisis** del otro.

### 14.1 Por qué es viable — no es una capacidad nueva de Lybra, es un origen nuevo del dato

Lybra ya separa "de dónde sale la lista de servicios" de "qué hace con ella". Su Fase 1 —
el matcher CPE→CVE (`normalize_product_to_cpe` + `cves_for_cpe`, `lybra-engine-roadmap.md`
§Fase 1, **ya implementada**) — toma como entrada una lista de `(host, puerto, producto,
versión)` y no le importa si esa lista la generó Nmap, un `LybraEngineTask` manual, o —lo
que proponemos aquí— el propio agente Hygeia leyendo paquetes instalados.

Más aún: el roadmap del motor **ya había anticipado exactamente este problema**, solo que
por otra vía. Su **Fase 4 — "el escaneo autenticado"** (`lybra-engine-roadmap.md` §Fase 4,
*avanzada y opcional, planificada*) propone entrar por SSH con una credencial del vault de
Acheron para leer `dpkg -l`/`rpm -qa` y así resolver de raíz el problema de los backports
(un banner de versión no siempre coincide con el paquete real instalado — la causa nº 1 de
falsos positivos del matcher). Si el activo ya tiene un agente Hygeia corriendo, **ese
problema está resuelto de antemano**: el agente ya vive dentro del host, ya lee el sistema
de paquetes localmente, y no necesita abrir una sesión SSH ni que Acheron guarde una
credencial de acceso remoto. Para hosts *con* agente Hygeia, esta integración vuelve
innecesaria la Fase 4; para hosts *sin* agente, la Fase 4 sigue siendo el camino (siguen
siendo dos vías al mismo destino, no una que sustituye a la otra en todos los casos).

> **ponytail: no dupliques el motor de detección.** Lo único nuevo de verdad aquí es (a) un
> colector de paquetes en el agente y (b) un adaptador que traduce ese inventario a la forma
> `(host, producto, versión)` que Lybra ya consume. El matcher CPE→CVE, la correlación, el
> dedup y el scoring — todo eso ya existe y no se toca.

### 14.2 Qué hay que construir

**En el agente (`Ellysia - Hygeia`, repo hermano):** un colector más, en la línea de los que
ya describe su README (§3): lista de paquetes instalados vía el gestor nativo de cada SO
(`dpkg -l` / `rpm -qa` en Linux, `winget list` / registro en Windows, `brew list` en macOS),
más versión de kernel/SO que ya se recolecta como parte de `host` en el contrato de ingesta
(§11). A diferencia de CPU/memoria, esto **no cambia cada 15 s** — no tiene sentido mandarlo
en cada heartbeat.

**En el backend (este módulo):**

1. **Endpoint y cadencia propios.** `POST /hygeia/inventory` (misma auth `require_agent_key`
   que `/hygeia/ingest`, §5), disparado por el agente con mucha menor frecuencia (p. ej. una
   vez al día, o al detectar que el listado de paquetes cambió desde el último envío — un
   hash del listado basta para decidirlo del lado del agente). Reutiliza la misma frontera de
   confianza del §13: valida y limita tamaño, rate-limit por clave de agente.
2. **Identidad de activo compartida con Themis.** El roadmap del motor ya resolvió este
   mismo problema para el caso Nmap-vs-Nmap: `ScanRepository.get_host_by_ip` evita que un
   mismo dispositivo físico se duplique en dos filas de `Host` cuando se le ve por IP y por
   hostname (`lybra-engine-roadmap.md`, decisión de diseño del 2026-07-11, §Fase 5). Al dar de
   alta un `MonitoredAsset` (§5, `POST /hygeia/assets`), hay que resolver o crear el `Host`
   de Themis correspondiente (por IP conocida o por hostname) y guardar esa referencia
   (`MonitoredAsset.host_id`, nullable — no todo activo Hygeia tiene por qué tener un `Host`
   de Themis todavía). Sin este vínculo, el inventario de Hygeia y los hallazgos de red de
   Themis viven en dos árboles separados y no se benefician de nada de la Fase 5 del motor.
3. **Adaptador inventario → servicios.** Una función de traducción, simétrica a los
   adaptadores que ya existen para Nikto/OpenVAS (`themis/lybra/adapters.py`), que convierte
   cada paquete del inventario en la forma `Service` que consume `LybraEngineTask`. Diferencia
   clave frente al caso de red: aquí el **puerto es opcional** — una librería vulnerable no
   tiene por qué escuchar en ningún puerto. El modelo de `Finding` ya lo contempla en la
   práctica: la categoría `outdated_software` (`lybra-engine-roadmap.md` §Modelo de datos, línea
   139) no depende conceptualmente de un puerto, solo de un CPE resuelto y una versión.
4. **Disparo del análisis.** Tras persistir un inventario nuevo (o distinto del anterior),
   encolar una tarea en `system/taskqueue` que invoque
   `LybraEngineManager.run_scan(..., services=...)` pasándole como entrada la lista de
   servicios ya traducida. **Corrección respecto a una versión anterior de esta sección:**
   ese punto de entrada no existe todavía — hoy `run_scan` solo sabe construir la lista de
   servicios leyendo un escaneo Nmap previo o descubriendo puertos por su cuenta. El modo por
   payload que esta fase necesita es una **pre-fase propia del roadmap del motor**, la
   **Fase 0.9** (`lybra-engine-roadmap.md` §Fase 0.9), que además define `Service.origin` para
   que un hallazgo de inventario nazca `confirmed=true`/`qod=95` en vez de compartir el
   `qod=70` genérico de una hipótesis por banner. Esta Fase H2 depende de que la 0.9 esté
   construida primero; el adaptador de este punto solo tiene que marcar `origin="inventory"`
   al traducir cada paquete. Los `Finding` resultantes caen en el mismo `Host` que Themis, así
   que heredan gratis dedup multi-fuente, ciclo de vida (`open`/`fixed`/`regressed`) y scoring
   contextual — no hay que reimplementar nada de la Fase 5.

### 14.3 Qué gana cada lado

- **Themis/Lybra** deja de depender solo de fingerprinting remoto (inferido, sujeto a
  backports) para los hosts que además corren Hygeia: obtiene la versión real del paquete sin
  SSH ni credenciales nuevas en Acheron. También gana cobertura donde el fingerprinting de red
  no llega — un host detrás de NAT sin puertos expuestos, que Themis nunca podría escanear,
  igual reporta su inventario vía Hygeia (push saliente, sin abrir nada).
- **Hygeia** gana valor de seguridad real más allá de la monitorización de salud: hoy solo
  detecta anomalías de rendimiento (CPU, memoria, disco); con esto, el mismo agente que ya
  está instalado empieza a alimentar hallazgos de CVE con severidad y CVSS, sin construir un
  motor de detección propio — se apoya en el que ya existe en Lybra.
- **Lo que ninguno gana del otro:** Hygeia nunca podrá ver la superficie de ataque *externa*
  (qué expone el host a Internet, TLS mal configurado, un path expuesto) — eso sigue siendo
  terreno exclusivo de Themis. Son complementarios, no intercambiables; no colapsar ambas
  señales en un único score sin distinguir "vulnerable por inventario" de "vulnerable y
  expuesto en red" (ver la advertencia ya hecha sobre este mismo punto en la conversación de
  diseño que originó esta sección).

### 14.4 Fases (opcionales, posteriores a la Fase 2 de este documento)

| Fase | Entregable | Estado que habilita |
|---|---|---|
| **H0** | Colector de paquetes instalados en el agente + `POST /hygeia/inventory` | El backend recibe listados de software por activo |
| **H1** | `MonitoredAsset.host_id` — resolución/creación del `Host` de Themis al dar de alta el activo | Un `MonitoredAsset` y un `Host` de Themis son la misma entidad de identidad |
| **H2** | Adaptador inventario→servicios (marca `origin="inventory"`) + disparo de `LybraEngineManager.run_scan(services=...)` — requiere la Fase 0.9 de `lybra-engine-roadmap.md` ya construida | Hallazgos CVE por inventario, visibles en el mismo árbol Host→Service→Finding que Themis, con `confirmed=true`/`qod=95` |
| **H3** (opcional) | Envío diferencial (solo cuando el hash del inventario cambia) | Menos tráfico/ruido; no reprocesar un inventario idéntico |

> **ponytail: no antes de que Hygeia y Lybra estén ambos estables por separado.** Esta
> integración acopla dos módulos que hoy son independientes; hacerlo antes de que cada uno
> tenga su Fase 0-2 asentada multiplicaría la superficie de debugging sin necesidad. Es la
> extensión natural una vez ambos lados existen, no un prerrequisito de ninguno de los dos.

---

## 15. Descarga del agente desde Ellysia (opcional, interesante)

> Requisito opcional surgido de una conversación de diseño (2026-07-14). No bloquea ninguna
> fase anterior — es una comodidad de distribución, no una pieza del contrato de ingesta.

**La idea:** que dar de alta un activo (`POST /hygeia/assets`, §4) no termine en "aquí tienes
tu clave, ve a buscar el binario a otro sitio", sino en una sección de Ellysia
(`/hygeia/agent/download` o una página en la SPA) donde el usuario elige su SO/arquitectura y
descarga el agente ya listo para instalar.

### 15.1 Dos formas de resolverlo, y cuál conviene

**A) Binarios precompilados, servidos tal cual (recomendado).** El repo del agente
(`Ellysia - Hygeia`) ya cross-compila trivialmente con Go (`GOOS`/`GOARCH`, sin toolchains
por plataforma — §2/§6 del plan del agente). En su CI se genera, en cada release, una matriz
de binarios (linux/amd64, linux/arm64, windows/amd64, darwin/amd64, darwin/arm64), **firmados
una sola vez** en ese pipeline (§5 del plan del agente, "releases firmadas"). El backend de
Ellysia no compila nada: solo expone `GET /hygeia/agent/download?os=&arch=` que sirve (o
redirige a) el artefacto correspondiente de la última release. Es un endpoint más, del mismo
tipo que servir cualquier fichero estático — cero cambios de arquitectura en la API Python.

**B) Compilación dinámica bajo demanda.** Técnicamente viable — se podría encolar un `go
build` como un job más de `system/taskqueue` (categoría nueva, p. ej. `hygeia.build`) — pero
introduce complejidad y riesgo que no compensan para lo que se gana:

- Requiere el toolchain de Go desplegado junto a la API o en un worker dedicado; la API es
  Python/Flask, así que es una dependencia de infraestructura enteramente nueva.
- Si la razón de compilar por petición es **personalizar** el binario (embeber `serverUrl`
  o `agentKey` en tiempo de build), entonces cada descarga necesita firmarse en caliente, lo
  que obliga a exponer la clave de firma al servicio que atiende descargas — exactamente lo
  que el plan del agente quiere evitar (§5: "releases firmadas", no firma-por-petición).
- Tiempos de build (segundos a ~1 min) y limpieza de artefactos temporales por descarga,
  para un problema que la opción A resuelve sin ninguno de estos costes.

### 15.2 Recomendación

Opción A. La personalización por activo (URL del servidor, `agentKey`) no necesita hornear
secretos en el binario en cada descarga: se resuelve con el fichero de config que ya describe
el agente (§4 de su plan) más el flujo de enrollment de la interfaz de bandeja
(`hygeia-tray`, §11 del plan del agente) — el usuario descarga el binario genérico firmado en
release, y pega la clave que Ellysia le mostró al dar de alta el activo (§4) en la mini UI de
enrollment, o en el fichero de config a mano. Menos superficie de confianza, cero
infraestructura de build nueva.

### 15.3 Qué construir si se decide seguir adelante (Fase D0)

- Página en la SPA (o sección de la pantalla de alta de activo) con selector de SO/arquitectura.
- Endpoint `GET /hygeia/agent/download?os=&arch=` — sirve el binario de la última release
  publicada (storage estático o proxy a los assets de la release en el repo del agente).
- Idealmente, junto al botón de descarga, mostrar la clave de agente recién emitida y un
  fragmento de config ya rellenado (`serverUrl` conocido, `agentKey` de la respuesta de
  `POST /hygeia/assets`) para copiar-pegar — cierra el círculo alta→descarga→config sin que
  el usuario tenga que ensamblar nada a mano.
- No requiere cambios en el modelo de datos ni en el contrato de ingesta (§11): es una
  superficie de distribución, no una pieza del flujo de auth/telemetría.

---

## 16. Guardas de seguridad y anti-abuso

> Modelo de amenaza: el agente corre en hosts que Ellysia **no** controla y empuja datos sin
> sesión interactiva. Los vectores de abuso realistas son tres — (a) una **clave de agente
> robada** de un host comprometido, (b) un cliente que manda **payloads malformados o
> gigantes** para tumbar la DB o el worker, y (c) un **usuario legítimo** que agota recursos
> dando de alta activos sin fin. Todo lo de esta sección es barato y **no toca la usabilidad
> del caso honesto** — el agente normal ni se entera. Complementa §4 (auth de agente) y §13
> (transversales); no los repite.

### 16.1 Límites de forma del payload (frontera de confianza dura)

El schema Marshmallow de ingesta (§11) ya **valida y descarta lo desconocido**; encima de
eso, límites de tamaño **antes** de tocar la DB (todos en el bloque `hygeia.limits`, §9 —
nada hardcodeado):

- **Cuerpo acotado.** Rechazar (`413`) cualquier request cuyo cuerpo supere `maxBodyBytes`.
  Un heartbeat honesto pesa unos pocos KB.
- **Gzip con tope de descompresión.** Como se acepta gzip (§11), descomprimir con un límite
  duro (`maxDecompressedBytes`) y **abortar** si lo excede — nunca `gunzip` a un buffer sin
  límite (un *gzip bomb* de pocos KB descomprime a GB).
- **Arrays acotados.** `topCpu`/`topMem` ≤ `maxProcesses`, `disk` ≤ `maxDiskMounts`,
  `network` ≤ `maxNetInterfaces`, `perCorePct` a un tope razonable. Un agente comprometido no
  debe poder inflar una fila con 10⁶ procesos.
- **Cadenas acotadas** (hostname, nombre de proceso, mount, iface) por longitud en el propio
  schema. Cortar en la frontera, no confiar en que el agente se porte bien.

> **ponytail: rechazar, no truncar.** Un payload que viola un límite es un heartbeat que se
> descarta con un `4xx` claro, no algo que el backend intenta "arreglar" quedándose con una
> parte — sanear datos hostiles a medias es justo cómo entran los bugs.

### 16.2 Cadencia y rate-limit por clave

- **Rate-limit por clave de agente** (reutiliza `limiter` de `shared`, §13): un tope de
  requests/min por `keyId`. Una clave robada no puede martillear la ingesta.
- **Suelo de intervalo.** El backend responde `nextIntervalSec` (§11); si una clave empuja
  mucho más rápido que `minIntervalSec`, responder `429` en vez de persistir. Protege la DB
  de un agente en bucle cerrado (con un bug, o comprometido).
- **Las notificaciones ya van amortiguadas de serie.** El ciclo de vida de `Anomaly`
  (§3.3/§8) abre **una** incidencia por condición sostenida y manda **un** correo; una métrica
  que oscila alrededor del umbral no genera un correo por heartbeat. Es decir: una clave
  robada tampoco sirve para *spamear* por correo al dueño. La histéresis, que estaba por
  precisión, hace aquí de anti-abuso gratis.

### 16.3 Ventana de cordura del reloj

El `collectedAt` lo pone el agente (§11) y **no es de fiar**. Ya se guarda `received_at` del
servidor aparte y el detector de presencia usa ese (§7.1/§13). Encima:

- Rechazar (o marcar y **no** usar para ordenar) un `collectedAt` fuera de `±clockSkewSec`
  respecto al reloj del servidor. Así una clave robada no puede inyectar snapshots fechados
  en 2099 que envenenen el orden de la serie temporal o tapen un hueco de presencia.
- El histórico y la detección se ordenan/particionan por `received_at`, nunca por el reloj
  del agente.

### 16.4 Cuota de activos por usuario

`POST /hygeia/assets` está autenticado (OAuth de usuario), pero un usuario podría dar de alta
activos sin fin y agotar filas/espacio. Un tope `maxAssetsPerUser` (config) cortado en el
manager de alta, con un `4xx` explicativo. Número generoso (cientos): topa el abuso, no
estorba al uso real.

### 16.5 Todo lo que trae el agente es dato no confiable (UI y logs)

Hostnames, nombres de proceso, mounts… los controla quien controla el agente. Al mostrarlos
o registrarlos:

- **En la SPA:** interpolación normal de Vue (que **escapa** por defecto); nunca `v-html` con
  contenido de un snapshot. Si no, un proceso llamado `<img src=x onerror=…>` es un XSS
  almacenado servido a quien mire el dashboard.
- **En logs:** no volcar cadenas del agente crudas en una línea de log (evita *log injection*
  con saltos de línea/escapes). Tratar esos campos como valores, no como formato.

### 16.6 Respuesta de auth uniforme (sin oráculos de enumeración ni de *timing*)

`require_agent_key` (§4) debe responder **igual** ante "`keyId` no existe" y "secreto
incorrecto": un único `401` genérico, sin distinguir en cuerpo ni en código. Y para no filtrar
por *timing* qué `keyId` existe, cuando el `keyId` no se encuentra hacer igualmente una
verificación Argon2 *dummy* (contra un hash fijo) antes de responder — así el coste de un
`keyId` inexistente y el de un secreto erróneo son indistinguibles. Barato, y cierra el
oráculo que dejaría a un atacante enumerar `keyId` válidos.

### 16.7 Endurecimiento de la descarga del agente (§15)

Si se implementa la sección de descargas (`GET /hygeia/agent/download?os=&arch=`, §15):

- **`os`/`arch` son un allowlist enum, nunca un trozo de ruta.** Mapear `(os, arch)` contra un
  conjunto cerrado de artefactos conocidos; jamás interpolar el valor recibido dentro de una
  ruta de fichero (`agents/{os}/{arch}/…`) — eso es *path traversal* (`?os=../../etc`).
- **Sin *open redirect* ni SSRF.** Si el endpoint redirige a un storage, que sea a una URL de
  un allowlist fijo, no a nada derivado del input del usuario.
- **Publicar checksum + firma** junto al binario, para que el instalador verifique integridad
  antes de ejecutar (contraparte de §5 del plan del agente, "releases firmadas").

### 16.8 Lo que se deja fuera a propósito (para no estorbar la usabilidad)

- **mTLS / certificados de cliente por agente:** más robusto, pero mete PKI y rotación de
  certs en cada host — coste operativo alto para un beta. La clave bearer + TLS del proxy
  cubre el grueso. Techo documentado en el ponytail de §4.
- **Protección de *replay* con nonce/firma por petición:** sobre TLS, reenviar un heartbeat
  capturado solo reinyecta una métrica vieja (impacto bajo), y la ventana de reloj (§16.3) ya
  acota cuánto vale un payload viejo. No compensa la complejidad en beta.
- **Firmar cada payload:** ídem — TLS ya da integridad y confidencialidad en tránsito.

> **ponytail:** ninguna de estas guardas añade un paso al operador que instala un agente:
> siguen siendo "pega la clave y arranca". La seguridad que **sí** costaría usabilidad (mTLS,
> certs por host) es justo la que se deja como techo, no como requisito de beta.

---

*Documento vivo. El acoplamiento con el otro repo se limita a §11: si el contrato de
ingesta se mantiene estable, agente y backend evolucionan por separado. El acoplamiento con
Themis/Lybra (§14) es opcional y unidireccional: Hygeia puede vivir sin él. La sección de
descargas (§15) es igualmente opcional: Ellysia funciona sin ella, el agente se puede
distribuir a mano igual que hoy. Las **guardas de seguridad (§16)**, en cambio, no son
opcionales: se tejen en las Fases 0-1 (auth, límites de payload, rate-limit), no son una fase
aparte ni un añadido posterior.*
