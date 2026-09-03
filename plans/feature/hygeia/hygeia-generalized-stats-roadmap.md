# Hygeia — Estadísticas generalizadas del parque monitorizado

Este documento describe el plan para construir una capa de **estadísticas agregadas** sobre los
datos que Hygeia ya recolecta. Hoy Hygeia sabe responder "¿cómo está *este* activo *ahora mismo*":
`GET /hygeia/assets/{id}/metrics` y `.../metrics/latest` son consultas por-activo, y no existe
ningún endpoint que cruce datos entre activos. No sabe responder "¿cuál es el máximo histórico de
CPU de este equipo?", "¿cuánta memoria consume en total la etiqueta `producción`?" ni "¿qué activo
del parque está peor?". Este plan cierra esa brecha.

No es un documento de lluvia de ideas: es un plan de ejecución, con una tabla maestra de
necesidades que se traduce 1:1 en issues de GitHub, agrupadas en fases con un issue padre cada una.

---

## 1. Lo que ya existe, verificado contra el código

**El dato crudo.** Cada activo (`MonitoredAsset`, `API/src/modules/features/hygeia/model.py`) manda
heartbeats periódicos que se guardan uno-a-uno en `AssetSnapshot`: `received_at` (reloj del
servidor, la referencia real para ordenar y filtrar), `cpu_pct`, `mem_pct`, `swap_pct`, `load1`,
`disk_max_pct` + `disk_max_mount`, `net_rx_bps`, `net_tx_bps` — desnormalizados a columna por
`services/aggregation.py::denormalize()` en el momento de la ingesta, para que sean graficables sin
tocar JSON. Todo lo que tiene cardinalidad por entidad — disco por punto de montaje, red por
interfaz, CPU por núcleo, procesos — vive **solo** en el JSONB `metrics`, sin desnormalizar.

**La retención.** `AssetSnapshot` se poda a 30 días (`HygeiaConfig.retention_days`, job diario). No
hay tabla de rollup a más largo plazo. Esto es una restricción de diseño, no un detalle: ningún
endpoint de este plan puede prometer "máximo histórico" más allá de la ventana de retención
configurada, y cada uno debe decirlo en su respuesta.

**Las etiquetas.** Hygeia tiene su propio esquema de etiquetado, autocontenido: `HygeiaTag`
(single-table, discriminada por `tag_type`) con subclases `SystemTag` (catálogo común) y `UserTag`
(personal), y la tabla de asociación `AssetTag` (M:N con `MonitoredAsset`). No hay un modelo
`Tag` genérico compartido con otro módulo.

**Lo que ya existe y no hay que reconstruir.** `GET /hygeia/assets/{id}/metrics` ya soporta
agregación por cubos temporales con el **máximo** por cubo
(`AssetSnapshotRepository.get_series_bucketed`, agrupación portable Postgres/SQLite por
`floor(epoch/bucket)`), acotada por `HygeiaLimits.max_series_points`. Este plan lo generaliza en
vez de duplicarlo.

**Lo que este plan explícitamente no toca.** No añade ninguna capacidad nueva al agente — el agente
ya manda todo lo necesario en cada heartbeat. Todo el trabajo es de agregación sobre datos que ya
están en la base de datos. Tampoco compite con el análisis de vulnerabilidades de Lybra sobre el
inventario (`POST /hygeia/assets/{id}/analyze`): esto es rendimiento y consumo, no seguridad.

---

## 2. Los principios de diseño

**Multi-función, no un endpoint por métrica.** La tentación obvia es `GET
/hygeia/assets/{id}/cpu-max`, `GET /hygeia/assets/{id}/mem-max`, uno por cada cruce de
métrica×agregación×alcance. Es exactamente el patrón que el resto del código evita: un
`if`/`elif` por protocolo era el error que la Fase N de Lybra corrigió con un registro de
`Dissector`. Aquí el equivalente es un **registro de métricas** (nombre → columna o extractor
JSONB) y un pequeño vocabulario de query params —`metric(s)`, `agg`, `period`, `scope`— que un
puñado de endpoints combinan. Añadir una métrica nueva es una entrada en el registro, no un
endpoint nuevo.

**El alcance (`scope`) es el eje que falta hoy.** Todo lo que existe es `scope=asset` implícito.
Este plan añade `scope=tag` (todos los activos de una etiqueta) y `scope=fleet` (todo el parque del
usuario) al mismo vocabulario, en vez de tratarlos como features separadas.

**Cálculo en servidor, no en el navegador.** El volumen por usuario es modesto —
`HygeiaLimits.max_assets_per_user` es 500, y cada consulta ya está acotada por la retención de 30
días—, así que centralizar el cálculo en Python/SQL es más simple que mandar series completas al
cliente y sumarlas allí. El navegador recibe agregados ya resueltos; como mucho formatea o calcula
un delta trivial entre dos números que ya tiene.

**Cada endpoint declara su ventana de confianza.** Un "máximo" sobre 30 días de datos no es un
máximo histórico, y la respuesta debe decir el periodo real cubierto (`from`/`to`), no solo el
número.

---

## 3. Las fases

| Fase | Título | Qué entrega |
|---|---|---|
| 0 | Los cimientos del servicio de estadísticas | Capa pura de agregación, registro de métricas, límites de consulta, repositorio multi-activo |
| 1 | El resumen por activo | "Cuál es el máximo de CPU/memoria/disco de este equipo" |
| 2 | La agregación por etiqueta | "Consumo total de memoria de la etiqueta X" |
| 3 | El panorama del parque | Rankings y vista global multi-activo |
| 4 | Las series multi-activo | Gráficas apiladas/comparativas por etiqueta o entre activos |
| 5 | El detalle que vive en el JSONB | Disco por montaje, red por interfaz, núcleos |
| 6 | El análisis derivado | Tendencias, patrones horarios, incumplimientos de umbral |
| 7 | La vista en el panel | Superficie SPA que consume todo lo anterior |

El orden es normativo dentro de la pista de correlación (0→3 desbloquean el resto), pero las Fases
5 y 6 son en gran parte independientes entre sí y pueden intercalarse según lo que resulte más
interesante de implementar.

---

## 4. La tabla maestra

`I` = Impacto (1–5) · `F` = Facilidad (1–5) · `I×F` = Prioridad · `R` = Realismo.

| Orden | Id | Necesidad | Fase | Categoría | I | F | I×F | R |
|---|---|---|---|---|---|---|---|---|
| 1 | E01 | Servicio puro de agregación (`HygeiaStatsService`) | 0 | Arquitectura | 5 | 4 | 20 | R1 |
| 2 | E05 | Resumen estadístico por activo (`/stats/summary`) | 1 | Funcionalidad | 5 | 4 | 20 | R1 |
| 3 | E02 | Registro de métricas (columna vs. JSONB) | 0 | Arquitectura | 4 | 4 | 16 | R1 |
| 4 | E06 | Bucketing con agregación configurable (min/avg/p95/max) | 1 | Mejora | 4 | 4 | 16 | R1 |
| 5 | E11 | Ranking de activos por métrica | 3 | Funcionalidad | 4 | 4 | 16 | R1 |
| 6 | E12 | Panorama global del parque (`/stats/overview`) | 3 | Funcionalidad | 4 | 4 | 16 | R1 |
| 7 | E03 | Límite configurable de periodo de consulta | 0 | Hardening | 3 | 5 | 15 | R1 |
| 8 | E04 | Repositorio de snapshots multi-activo | 0 | Arquitectura | 5 | 3 | 15 | R1 |
| 9 | E08 | Agregación cruzada por etiqueta (`/stats/by-tag`) | 2 | Funcionalidad | 5 | 3 | 15 | R1 |
| 10 | E09 | Catálogo de etiquetas con recuento de activos | 2 | Funcionalidad | 3 | 5 | 15 | R1 |
| 11 | E07 | Momento del pico (`timestampOfMax`/`Min`) | 1 | Funcionalidad | 3 | 4 | 12 | R1 |
| 12 | E14 | Series bucketed multi-activo/etiqueta | 4 | Mejora | 4 | 3 | 12 | R1 |
| 13 | E16 | Histórico de disco por punto de montaje | 5 | Funcionalidad | 4 | 3 | 12 | R1 |
| 14 | E22 | Ranking de activos por incumplimientos de umbral | 6 | Funcionalidad | 3 | 4 | 12 | R1 |
| 15 | E24 | Vista "Estadísticas" en el panel de Hygeia | 7 | Funcionalidad | 5 | 2 | 10 | R2 |
| 16 | E10 | Comparativa entre etiquetas | 2 | Funcionalidad | 3 | 3 | 9 | R2 |
| 17 | E13 | Histograma de distribución por métrica | 3 | Funcionalidad | 3 | 3 | 9 | R2 |
| 18 | E15 | Series comparativas entre dos activos/etiquetas | 4 | Mejora | 3 | 3 | 9 | R2 |
| 19 | E17 | Montajes más llenos del parque (último snapshot) | 5 | Funcionalidad | 3 | 3 | 9 | R2 |
| 20 | E18 | Red por interfaz agregada del parque | 5 | Funcionalidad | 3 | 3 | 9 | R2 |
| 21 | E21 | Patrón horario de carga (heatmap hora del día) | 6 | Funcionalidad | 3 | 3 | 9 | R2 |
| 22 | E20 | Tendencia de disco y estimación de días hasta llenarse | 6 | Funcionalidad | 4 | 2 | 8 | R2 |
| 23 | E26 | Exportar estadísticas (CSV/JSON) desde el panel | 7 | Mejora | 2 | 4 | 8 | R1 |
| 24 | E19 | Desequilibrio de CPU entre núcleos | 5 | Funcionalidad | 2 | 3 | 6 | R2 |
| 25 | E25 | Gráficas comparativas configurables por el usuario | 7 | Mejora | 3 | 2 | 6 | R2 |
| 26 | E23 | Correlación simple entre picos de red y CPU | 6 | Estratégica | 2 | 2 | 4 | R3 |

Un `I×F` alto no significa "primero": manda la fase. E01/E05 encabezan la tabla porque además son
fundacionales, pero E08 (Fase 2) no puede empezar sin E04 (Fase 0), por mucho que su prioridad
individual sea alta.

---

## 5. Las fases en detalle

### Fase 0 — Los cimientos del servicio de estadísticas

Ningún endpoint público todavía: es la capa que hace baratas a todas las demás fases. Vive en
`hygeia/services/stats.py` (nuevo), sin ORM en su núcleo — igual que la filosofía de Lybra L0-L2 —
para que sea trivial de testear con listas de snapshots en memoria.

- **E01 — Servicio puro de agregación.** Funciones `min`/`max`/`avg`/`p95`/`current` sobre una
  secuencia de valores con su timestamp, sin depender de SQLAlchemy. Es la pieza que reutilizan
  todos los endpoints posteriores.
- **E02 — Registro de métricas.** Un diccionario cerrado `nombre → (columna | extractor_jsonb)`
  para las siete métricas desnormalizadas (`cpuPct`, `memPct`, `swapPct`, `load1`, `diskMaxPct`,
  `netRxBps`, `netTxBps`), con un punto de extensión explícito para las métricas del JSONB que
  llegan en la Fase 5.
- **E03 — Límite configurable de periodo.** `HygeiaLimits` gana `max_stats_period_days`, acotado
  por diseño a `retention_days`: pedir un periodo mayor no debe devolver un error confuso, sino
  recortarse al máximo disponible y decirlo en la respuesta.
- **E04 — Repositorio multi-activo.** `AssetSnapshotRepository` gana una consulta que acepta una
  **lista** de `asset_id` (no uno), reutilizando el mismo bucketing portable Postgres/SQLite que ya
  existe. Es el bloque que hace posible `scope=tag` y `scope=fleet` sin reescribir SQL en cada
  endpoint.

### Fase 1 — El resumen por activo

Responde directamente la pregunta que abre este documento.

- **E05 — `GET /hygeia/assets/{id}/stats/summary`.** Multi-métrica: `metrics=cpuPct,memPct,...` y
  `period=24h|7d|30d` devuelven `{min, max, avg, p95, current}` por métrica solicitada en una sola
  llamada, en vez de un roundtrip por métrica.
- **E06 — Bucketing con agregación elegible.** El endpoint de series existente solo agrega por
  **máximo** por cubo. Se generaliza a `agg=min|avg|p95|max`, mismo parámetro que el resto del
  plan, sin duplicar la función de bucketing.
- **E07 — Momento del pico.** El resumen de E05 gana `timestampOfMax`/`timestampOfMin` por
  métrica, para poder correlacionar un máximo con lo que pasaba en ese instante (una anomalía, un
  despliegue).

### Fase 2 — La agregación por etiqueta

- **E08 — `GET /hygeia/stats/by-tag/{tagId}`.** Agregación cruzada (`agg=sum|avg|max`) de todos los
  activos con esa etiqueta. Para "memoria total" hace falta convertir porcentaje a bytes absolutos
  — a verificar contra el payload real del agente si el total de memoria viaja en el JSONB
  (`mem_total_bytes` o equivalente); si no viaja, esta necesidad se reduce a promedio/máximo de
  porcentaje y una nota lo dice explícitamente en la respuesta, en vez de inventar una cifra.
- **E09 — `GET /hygeia/stats/tags`.** Catálogo de etiquetas del usuario con recuento de activos y
  última actividad — el listado que alimenta el selector de etiqueta del panel.
- **E10 — Comparativa entre etiquetas.** Mismo endpoint de E08 generalizado a devolver el ranking
  de **todas** las etiquetas del usuario por una métrica, no solo una.

### Fase 3 — El panorama del parque

- **E11 — `GET /hygeia/stats/ranking`.** Top/bottom N activos por métrica
  (`agg=avg|max&limit=N&order=asc|desc`) — "qué equipo está peor" en una sola llamada.
- **E12 — `GET /hygeia/stats/overview`.** El dato de aterrizaje de una vista nueva: activos por
  estado (`online`/`stale`/`offline`/`pending`), anomalías abiertas por severidad, uptime medio del
  parque, actividad reciente.
- **E13 — Histograma de distribución.** Cuántos activos caen en cada franja (0–25 %, 25–50 %...)
  de una métrica — hace visible al activo atípico sin tener que mirar uno a uno.

### Fase 4 — Las series multi-activo

- **E14 — Series bucketed por etiqueta o lista de activos.** Generaliza el endpoint de series
  (ya extendido en E06) a `scope=tag|assetIds`, devolviendo una serie por activo o una serie
  agregada (`agg=sum|avg|max`) — la base de datos de una gráfica apilada de tráfico o CPU por
  etiqueta a lo largo del tiempo.
- **E15 — Series comparativas.** Dos activos o dos etiquetas en la misma respuesta, para
  superponer gráficas sin dos roundtrips.

### Fase 5 — El detalle que vive en el JSONB

Todo lo de esta fase lee la parte del payload que hoy solo existe en `metrics` (JSONB), sin
desnormalizar — cada necesidad decide si merece la pena desnormalizar o si extraer bajo demanda es
suficientemente barato.

- **E16 — `GET /hygeia/assets/{id}/stats/disks`.** Histórico por punto de montaje (no solo el
  máximo ya desnormalizado en `disk_max_pct`) — qué montaje concreto se llena más rápido.
- **E17 — `GET /hygeia/stats/disks/fleet`.** Montajes más llenos de todo el parque, deliberadamente
  acotado al **último** snapshot de cada activo (no histórico completo) para no convertir esto en
  un escaneo del JSONB de 30 días por activo.
- **E18 — Red por interfaz agregada.** Throughput total del parque o de una etiqueta, desglosado
  por interfaz.
- **E19 — Desequilibrio de CPU entre núcleos.** Si el JSONB trae CPU por núcleo, detectar un
  núcleo saturado mientras el resto está ocioso — señal que el promedio agregado (`cpuPct`)
  esconde.

### Fase 6 — El análisis derivado

Estas necesidades combinan lo anterior en algo que ninguna métrica cruda responde por sí sola.

- **E20 — Tendencia de disco.** Regresión lineal simple sobre `disk_max_pct` en la ventana
  disponible, con una estimación de "días hasta llenarse" que declara su propia confianza baja
  cuando la pendiente es casi plana o la ventana es corta — mejor no dar el número que dar uno
  falso.
- **E21 — Patrón horario de carga.** Promedio de una métrica agrupado por hora del día
  (0–23), para detectar la hora pico del parque o de un activo.
- **E22 — Ranking de incumplimientos de umbral.** `MonitoredAsset.breach_counters` ya cuenta
  cruces de umbral por métrica; esta necesidad solo lo expone ordenado: qué activo y qué métrica
  son los más conflictivos.
- **E23 — Correlación simple picos red/CPU.** Declarada explícitamente como apuesta de bajo
  compromiso (I+D): ¿los picos de una métrica coinciden en el tiempo con los de otra? Sin modelo
  estadístico sofisticado, solo coincidencia de ventana temporal.

### Fase 7 — La vista en el panel

- **E24 — Vista nueva "Estadísticas" en Hygeia (SPA).** Selector de alcance
  (activo/etiqueta/parque), métrica y periodo, consumiendo los endpoints de las fases 1–6.
- **E25 — Gráficas comparativas configurables.** El usuario elige 2–3 métricas a superponer; el
  cálculo pesado sigue en el backend, el cliente solo compone la vista.
- **E26 — Exportar CSV/JSON.** Reutiliza los endpoints existentes; no hay lógica de servidor nueva
  más allá del `content-type` de salida.

---

## 6. Fuera de alcance, a propósito

No se le pide nada nuevo al agente de Hygeia — todo este plan es agregación sobre lo que ya llega.
No se construye ninguna tabla de rollup de largo plazo (más allá de los 30 días de retención): si
en el futuro hace falta un "máximo del último año", es una fase aparte con una decisión de
retención distinta, no un efecto colateral de este plan. No se toca el árbol de vulnerabilidades de
Lybra ni el ciclo de vida de `Anomaly`: esto es rendimiento y consumo, un dominio distinto de la
seguridad.
