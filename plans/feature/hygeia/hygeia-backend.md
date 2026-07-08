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

**NO es** (trampas de alcance, estilo `vulnengineroadmap.md`):

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
    agent_key_hash = Column(String(255), nullable=False)   # Argon2id de la clave de agente
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
(el mismo hashing que ya usáis para contraseñas — cero dependencias nuevas).

Flujo de alta (*enrollment*):

1. Un **usuario autenticado** da de alta un activo: `POST /hygeia/assets`. El backend
   genera una clave aleatoria de alta entropía (`secrets.token_urlsafe`), guarda **solo su
   hash Argon2id** en `MonitoredAsset.agent_key_hash`, y **devuelve la clave en claro una
   sola vez** (patrón "recovery codes" de MFA, que ya existe en el repo).
2. El operador configura esa clave en el agente (fichero de config del otro repo).
3. Cada heartbeat viaja con `Authorization: Bearer <agentKey>` (o cabecera `X-Agent-Key`).

Verificación en el endpoint de ingesta: un decorador nuevo `require_agent_key` (en
`services/enrollment.py`) resuelve el activo, verifica el hash Argon2 y deja el
`MonitoredAsset` en el contexto de la request. **No emite JWT** — el agente no necesita
sesión, solo probar su clave en cada push.

> **ponytail: bearer + Argon2, no mTLS ni client_credentials.** mTLS y un grant OAuth
> `client_credentials` son más robustos pero triplican el trabajo (PKI / rotación / nuevo
> flujo OAuth) y no aportan nada en beta. Techo: si más adelante quieres rotación
> automática o revocación fina, añade `agent_key_id` + expiración a `MonitoredAsset` — un
> par de columnas, no un rediseño. TLS lo aporta el reverse proxy, como el resto de la API.

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

---

## 7. Tareas de fondo (RQ + APScheduler)

Dos jobs recurrentes, con el patrón de `sentinel/services/scheduling.py`. Categorías RQ
nuevas: `hygeia.maintenance`.

- **Detector de presencia (host caído).** Cada minuto: marca `stale`/`offline` los activos
  cuyo `last_seen_at` supere `N × intervalo`, y abre una `Anomaly(kind="host_down")`. Al
  volver un heartbeat, la ingesta la resuelve. Esto cubre "el activo dejó de responder",
  que la ingesta por sí sola no puede detectar (no llega nada que evaluar).
- **Poda/retención.** Diaria: borra `AssetSnapshot` más antiguos que `retentionDays`
  (config). Opcional: **downsampling** — antes de borrar, agregar a resolución horaria en
  una tabla `AssetSnapshotHourly`. Para el beta, borrar basta; el downsampling es el techo.

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

*Documento vivo. El acoplamiento con el otro repo se limita a §11: si el contrato de
ingesta se mantiene estable, agente y backend evolucionan por separado.*
