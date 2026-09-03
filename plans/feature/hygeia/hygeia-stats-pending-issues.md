# Hygeia — Estadísticas generalizadas: necesidades pendientes de subir a GitHub

Este documento conserva el contenido completo (diagnóstico, verificación contra el código, intervención, criterio de cierre) de las **necesidades que todavía no se subieron como issues** de GitHub, para no perder el trabajo hecho al diseñarlas. La creación se detuvo a mitad de camino por un límite de la API de GitHub compartido por el entorno ("5.000/h compartido entre todas las herramientas y agentes"), no por la cuenta personal de GitHub del usuario, cuya cuota mostraba 5000/5000 disponibles durante todo el bloqueo.

## Ya subido a GitHub

Proyecto: [Hygeia — Estadísticas generalizadas](https://github.com/orgs/ProjectEllysia/projects/5)

- Los 8 issues padre de fase: [#411](https://github.com/ProjectEllysia/EllysiaServer/issues/411)–[#418](https://github.com/ProjectEllysia/EllysiaServer/issues/418) (Fase 0 a Fase 7).
- Las necesidades **E01**–**E05**: [#419](https://github.com/ProjectEllysia/EllysiaServer/issues/419), [#420](https://github.com/ProjectEllysia/EllysiaServer/issues/420), [#421](https://github.com/ProjectEllysia/EllysiaServer/issues/421), [#422](https://github.com/ProjectEllysia/EllysiaServer/issues/422), [#423](https://github.com/ProjectEllysia/EllysiaServer/issues/423).

Los 8 issues padre de fase tienen en su tabla de necesidades el id (`E0N`) en vez del número de issue para las necesidades de este documento — no se llegó a reescribir esa tabla con los números reales (paso previsto para cuando todas las necesidades de la fase existan como issue).

## Necesidades pendientes

Contenido idéntico al que se habría usado como cuerpo de cada issue. Referencia completa del roadmap: [`plans/feature/hygeia/hygeia-generalized-stats-roadmap.md`](hygeia-generalized-stats-roadmap.md).

## Fase 1 — El resumen por activo

Issue padre ya creado: [#412](https://github.com/ProjectEllysia/EllysiaServer/issues/412).

### [E06] Bucketing con agregación configurable (min/avg/p95/max)

| | |
|---|---|
| **Categoría** | Mejora |
| **Fase** | 1 — El resumen por activo |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **16** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 4 de 26 |

**Diagnóstico**

El endpoint de series existente (`get_series_bucketed`) solo agrega por **máximo** dentro de cada cubo temporal. Una gráfica de "CPU media por hora" o "p95 de latencia de red por hora" no se puede pedir hoy sin traer los datos crudos y agregar en el cliente.

**Verificación contra el código**

`repositories.py::get_series_bucketed` construye la agrupación por `floor(epoch/bucket)` con `func.max(...)` fijo en la consulta SQL. El cambio es sustituir esa función fija por un parámetro, reutilizando la misma agrupación.

**Intervención**

El endpoint `GET /hygeia/assets/{id}/metrics` gana `agg=min|avg|p95|max` (default `max`, para no romper a ningún consumidor existente de la SPA). `avg`/`min`/`max` se resuelven en SQL (`func.avg`/`func.min`/`func.max`); `p95` no tiene una función portable simple entre Postgres y SQLite, así que se resuelve trayendo los valores del cubo y aplicando `stats.py` (E01) en Python — aceptable porque un cubo tiene, como mucho, unos pocos heartbeats.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/repositories.py`, `endpoints.py`, `schemas.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

`agg=avg` devuelve el promedio real por cubo (no el máximo); un consumidor que no manda `agg` sigue recibiendo exactamente el comportamiento actual, verificado por los tests existentes sin modificarlos.

**Dependencias**

Requiere E01 para el caso `p95`.

---

### [E07] Momento del pico (`timestampOfMax`/`Min`)

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 1 — El resumen por activo |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **12** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 11 de 26 |

**Diagnóstico**

Saber que la CPU llegó al 98 % no dice cuándo. Sin el instante del pico, correlacionar un máximo con una anomalía (`Anomaly`) o con un despliegue conocido exige ir a la serie cruda y buscarlo a mano.

**Verificación contra el código**

`stats.py` (E01) ya calcula `max`/`min` sobre la serie; el timestamp asociado es un subproducto casi gratis del mismo recorrido, no una consulta adicional.

**Intervención**

`StatSummary` (E01) gana `timestamp_of_max`/`timestamp_of_min`, y el endpoint de resumen (E05) los expone como `timestampOfMax`/`timestampOfMin` en camelCase por métrica.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/services/stats.py`, `schemas.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre una serie de fixture con un pico conocido en una posición concreta, el timestamp devuelto coincide exactamente con el del punto de fixture, no con un cubo aproximado.

**Dependencias**

Requiere E01 y E05.

---

## Fase 2 — La agregación por etiqueta

Issue padre ya creado: [#413](https://github.com/ProjectEllysia/EllysiaServer/issues/413).

### [E08] Agregación cruzada por etiqueta (`/stats/by-tag`)

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 2 — La agregación por etiqueta |
| **Impacto (I)** | 5 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **15** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 9 de 26 |

**Diagnóstico**

"Consumo de memoria total de la etiqueta producción" es la segunda pregunta del roadmap y hoy no tiene respuesta: una etiqueta es solo un filtro visual sobre la lista de activos, sin ninguna cifra agregada.

**Verificación contra el código**

`AssetTag` (M:N, `model.py`) asocia `MonitoredAsset` con `HygeiaTag`. No hay hoy ninguna consulta que agrupe `AssetSnapshot` por la etiqueta de su activo — hace falta un `JOIN` de tres tablas (`AssetSnapshot` → `MonitoredAsset` → `AssetTag` → `HygeiaTag`) antes de aplicar E04.

**Intervención**

`GET /hygeia/stats/by-tag/{tagId}?metrics=...&agg=sum|avg|max&period=...`. El manager resuelve primero los `asset_id` de la etiqueta (consulta simple sobre `AssetTag`), y delega en el repositorio multi-activo de E04. Para "memoria total": si el JSONB del agente trae un total de memoria en bytes, se deriva `mem_used_bytes = mem_total_bytes * mem_pct / 100`; si no lo trae — a verificar contra el payload real durante la implementación —, el endpoint degrada a agregar el porcentaje y lo declara explícitamente en la respuesta (`unit: "percent"` vs. `"bytes"`), en vez de inventar una cifra absoluta.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`, `repositories.py`.

**Nuevos artefactos**

Ninguno de base de datos.

**Criterio de cierre**

Sobre una etiqueta con 3 activos de fixture, `agg=sum` sobre una métrica en bytes devuelve la suma exacta de los tres; pedir una métrica que solo existe en porcentaje devuelve `unit: "percent"` sin fingir bytes.

**Dependencias**

Requiere E01, E02, E04.

---

### [E09] Catálogo de etiquetas con recuento de activos

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 2 — La agregación por etiqueta |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 5 / 5 |
| **Prioridad (I × F)** | **15** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 10 de 26 |

**Diagnóstico**

El selector de etiqueta que la Fase 7 necesita no tiene de dónde leer la lista de etiquetas del usuario con cuántos activos tiene cada una — hoy hay que pedir todos los activos y contar en el cliente.

**Verificación contra el código**

`HygeiaTag`/`SystemTag`/`UserTag` (`model.py`) ya distinguen catálogo común vs. personal; la relación `MonitoredAsset.tags` (`lazy="selectin"`) ya trae las etiquetas de un activo eficientemente.

**Intervención**

`GET /hygeia/stats/tags` — para cada etiqueta visible al usuario (sistema + propias), recuento de activos asociados y `lastActivityAt` (el `last_seen_at` más reciente entre sus activos).

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`, `repositories.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

El catálogo devuelve el recuento correcto de activos por etiqueta sobre datos de fixture, incluyendo etiquetas sin ningún activo (recuento 0, no ausentes de la lista).

**Dependencias**

Ninguna directa; comparte tablas con E08.

---

### [E10] Comparativa entre etiquetas

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 2 — La agregación por etiqueta |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 16 de 26 |

**Diagnóstico**

E08 responde sobre una etiqueta ya conocida. La pregunta "¿qué etiqueta consume más CPU en total?" exige compararlas todas, y hoy habría que llamar a E08 una vez por etiqueta desde el cliente.

**Verificación contra el código**

Se apoya enteramente en E08 y E09 — no añade acceso a datos nuevo, solo un modo de respuesta distinto del mismo cálculo.

**Intervención**

El mismo manager de E08 gana un modo `GET /hygeia/stats/by-tag?metric=...&agg=...&period=...` (sin `{tagId}`) que devuelve el ranking de **todas** las etiquetas del usuario por la métrica pedida, reutilizando la agregación de E08 en un bucle acotado por el número de etiquetas del usuario (normalmente bajo).

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre 3 etiquetas de fixture con consumos distintos, el ranking las ordena correctamente por la métrica pedida.

**Dependencias**

Requiere E08 y E09.

---

## Fase 3 — El panorama del parque

Issue padre ya creado: [#414](https://github.com/ProjectEllysia/EllysiaServer/issues/414).

### [E11] Ranking de activos por métrica

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 3 — El panorama del parque |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **16** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 5 de 26 |

**Diagnóstico**

"Qué activo del parque está peor" no tiene respuesta hoy sin abrir cada activo uno a uno y comparar a mano.

**Verificación contra el código**

Se apoya en E01 (agregación) y E04 (consulta multi-activo) sobre todos los activos del usuario (`MonitoredAsset.user_id`), sin necesitar tablas nuevas.

**Intervención**

`GET /hygeia/stats/ranking?metric=...&agg=avg|max&period=...&limit=N&order=asc|desc` — calcula la agregación pedida por activo (reutilizando E04 con la lista completa de activos del usuario) y devuelve los N extremos ordenados, con el `hostname` y el valor.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`, `repositories.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre 10 activos de fixture con valores conocidos, `limit=3&order=desc` devuelve exactamente los 3 de mayor valor en el orden correcto.

**Dependencias**

Requiere E01 y E04.

---

### [E12] Panorama global del parque (`/stats/overview`)

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 3 — El panorama del parque |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **16** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 6 de 26 |

**Diagnóstico**

Una vista nueva de estadísticas necesita un endpoint de aterrizaje que resuma el estado del parque sin que el cliente tenga que orquestar cinco llamadas distintas para pintar la primera pantalla.

**Verificación contra el código**

`MonitoredAsset.status` (`pending|online|stale|offline`) y `Anomaly` (`state`, `severity`) ya existen con exactamente los campos que un resumen global necesita; no hay hoy ningún endpoint que los cuente agregados.

**Intervención**

`GET /hygeia/stats/overview` — recuento de activos por `status`, recuento de `Anomaly` abiertas por `severity`, uptime medio del parque (`avg(uptime_sec)` sobre activos online), y total de activos. Sin parámetros de periodo: es una foto del instante actual, no una serie.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre un parque de fixture con activos en los cuatro estados y anomalías de severidades distintas, el resumen cuenta cada categoría correctamente.

**Dependencias**

Ninguna directa de otras necesidades del roadmap.

---

### [E13] Histograma de distribución por métrica

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 3 — El panorama del parque |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 17 de 26 |

**Diagnóstico**

El ranking de E11 muestra los extremos; no muestra la forma de la distribución — cuántos activos están cómodos y cuántos empiezan a apretar. Sin esto, un activo al 60 % de memoria en un parque donde todos están al 20 % pasa desapercibido si no está entre los 5 primeros del ranking.

**Verificación contra el código**

Se apoya en la misma consulta multi-activo de E04/E11; el histograma es una forma distinta de presentar los mismos valores agregados por activo.

**Intervención**

`GET /hygeia/stats/histogram?metric=...&agg=avg&period=...&buckets=4` — reparte el valor agregado de cada activo en franjas configurables (por defecto 0–25/25–50/50–75/75–100 %) y devuelve el recuento de activos por franja.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre activos de fixture con valores conocidos repartidos en las cuatro franjas por defecto, el recuento por franja es exacto.

**Dependencias**

Requiere E01, E04, y reutiliza la lógica de E11.

---

## Fase 4 — Las series multi-activo

Issue padre ya creado: [#415](https://github.com/ProjectEllysia/EllysiaServer/issues/415).

### [E14] Series bucketed multi-activo/etiqueta

| | |
|---|---|
| **Categoría** | Mejora |
| **Fase** | 4 — Las series multi-activo |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **12** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 12 de 26 |

**Diagnóstico**

Una gráfica de "tráfico total de la etiqueta producción en las últimas 24 horas" necesita una serie temporal ya agregada entre activos, no un número único (eso ya lo resuelve E08) ni una serie por activo que el cliente tenga que sumar punto a punto.

**Verificación contra el código**

Depende directamente de E06 (bucketing con agregación configurable) y E04 (consulta multi-activo) — es la combinación de ambas, no una pieza nueva de bajo nivel.

**Intervención**

El endpoint de series bucketed de E06 gana `scope=tag&tagId=...` o `scope=assetIds&assetIds=1,2,3` junto a `agg=sum|avg|max`. Con `agg=sum`/`avg`/`max` sobre `scope`, devuelve una única serie ya combinada; sin `agg` explícito, devuelve una serie por activo (comportamiento por defecto, útil para comparar activos lado a lado en la Fase 7).

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`, `repositories.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre 3 activos de fixture con series conocidas, `scope=assetIds&agg=sum` devuelve, en cada cubo, la suma exacta de los tres.

**Dependencias**

Requiere E04 y E06.

---

### [E15] Series comparativas entre dos activos/etiquetas

| | |
|---|---|
| **Categoría** | Mejora |
| **Fase** | 4 — Las series multi-activo |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 18 de 26 |

**Diagnóstico**

Superponer dos series (dos activos, o un activo contra el promedio de su etiqueta) hoy exige dos llamadas y alinear los cubos en el cliente.

**Verificación contra el código**

Se apoya enteramente en E14 — es un modo de respuesta que empaqueta dos llamadas equivalentes a E14 en una, con los cubos ya alineados por el mismo `bucket_seconds`.

**Intervención**

El mismo endpoint de E14 acepta una segunda fuente (`compareTo=assetId:5` o `compareTo=tag:3`) y devuelve ambas series con los mismos límites de cubo, para que el cliente las dibuje superpuestas sin reconciliar timestamps.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Las dos series devueltas comparten exactamente los mismos límites de cubo, verificado comparando los timestamps de ambos arrays.

**Dependencias**

Requiere E14.

---

## Fase 5 — El detalle que vive en el JSONB

Issue padre ya creado: [#416](https://github.com/ProjectEllysia/EllysiaServer/issues/416).

### [E16] Histórico de disco por punto de montaje

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 5 — El detalle que vive en el JSONB |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **12** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 13 de 26 |

**Diagnóstico**

`disk_max_pct`/`disk_max_mount` dicen cuál es el montaje más lleno **en el último heartbeat**, pero no su histórico: si `/var` se llena rápido y `/` está siempre ligero, hoy no se puede aislar esa señal porque solo el máximo del conjunto se desnormalizó a columna.

**Verificación contra el código**

El detalle por montaje vive únicamente en el JSONB `metrics` de cada `AssetSnapshot` (nunca desnormalizado). Extraerlo de 30 días de snapshots de un solo activo es razonable en coste (decenas a cientos de filas, no miles); extraerlo de todo el parque no lo es (ver E17).

**Intervención**

`GET /hygeia/assets/{id}/stats/disks?mount=/var&period=7d` — trae los snapshots del activo en el periodo, extrae el punto de montaje pedido del JSONB (o todos si no se especifica), y aplica `stats.py` (E01) por montaje.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre snapshots de fixture con dos montajes de evolución distinta, el histórico de cada uno se distingue correctamente del otro.

**Dependencias**

Requiere E01, E02 (extractor JSONB), E03.

---

### [E17] Montajes más llenos del parque (último snapshot)

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 5 — El detalle que vive en el JSONB |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 19 de 26 |

**Diagnóstico**

Sin este endpoint, encontrar el punto de montaje más lleno de todo el parque exige abrir cada activo y mirar su JSONB a mano.

**Verificación contra el código**

Deliberadamente acotado al último snapshot de cada activo, no a su historia: leer el JSONB de 30 días por cada uno de hasta 500 activos sería un escaneo caro para una consulta que se espera de baja frecuencia.

**Intervención**

`GET /hygeia/stats/disks/fleet?limit=10` — para cada activo, extrae del **último** snapshot el montaje más lleno (ya desnormalizado en `disk_max_pct`/`disk_max_mount`, sin tocar el JSONB), y devuelve los N activos con el montaje más lleno, ordenados.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Reutiliza las columnas ya desnormalizadas, no el JSONB — un test de integración lo confirma inspeccionando las consultas SQL emitidas.

**Dependencias**

Ninguna directa; usa columnas ya existentes, no depende de E16.

---

### [E18] Red por interfaz agregada del parque

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 5 — El detalle que vive en el JSONB |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 20 de 26 |

**Diagnóstico**

`net_rx_bps`/`net_tx_bps` son el total del activo; qué interfaz concreta genera ese tráfico solo vive en el JSONB, igual que el disco por montaje.

**Verificación contra el código**

Mismo patrón de E16: extracción del JSONB por activo, acotada por periodo y por `HygeiaLimits.max_net_interfaces` para no iterar interfaces sin límite.

**Intervención**

`GET /hygeia/assets/{id}/stats/network?interface=eth0&period=...` — histórico por interfaz, simétrico a E16 pero sobre la sección de red del JSONB.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre snapshots de fixture con dos interfaces, el histórico de cada una se distingue correctamente.

**Dependencias**

Requiere E01, E02, E03 — mismo patrón que E16.

---

### [E19] Desequilibrio de CPU entre núcleos

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 5 — El detalle que vive en el JSONB |
| **Impacto (I)** | 2 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **6** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 24 de 26 |

**Diagnóstico**

`cpu_pct` es el promedio de todos los núcleos. Un proceso mal repartido que satura un solo núcleo mientras el resto está ocioso queda invisible detrás de un promedio moderado — la señal más sutil de las que este roadmap puede exponer, y la más condicionada a lo que el agente realmente envía por núcleo.

**Verificación contra el código**

Depende de que el JSONB `metrics` traiga CPU por núcleo (a confirmar contra el payload real del agente durante la implementación; `HygeiaLimits` no declara hoy un límite de núcleos, a diferencia de `max_processes`/`max_disk_mounts`/`max_net_interfaces`, lo que sugiere que puede no estar modelado todavía).

**Intervención**

Si el dato existe: `GET /hygeia/assets/{id}/stats/cpu-cores?period=...` con la desviación entre núcleos del último snapshot o de un resumen del periodo. Si no existe, esta necesidad se cierra documentando la ausencia del dato en vez de construir sobre una suposición — no es una tarea de colección nueva del agente, que está fuera de alcance de este roadmap.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py` (condicionado a la verificación previa).

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

El endpoint devuelve la desviación entre núcleos cuando el dato existe, o el issue se cierra documentando por qué no aplica.

**Dependencias**

Requiere confirmar el payload real del agente antes de implementar.

---

## Fase 6 — El análisis derivado

Issue padre ya creado: [#417](https://github.com/ProjectEllysia/EllysiaServer/issues/417).

### [E20] Tendencia de disco y estimación de días hasta llenarse

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 6 — El análisis derivado |
| **Impacto (I)** | 4 / 5 |
| **Facilidad (F)** | 2 / 5 |
| **Prioridad (I × F)** | **8** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 22 de 26 |

**Diagnóstico**

Saber que un disco está al 80 % no dice si lleva ahí semanas o si va a llenarse mañana. Es la necesidad de mayor valor por cifra sola de la Fase 6, y la más fácil de hacer mal: una estimación confiada sobre poco dato es peor que no dar ninguna.

**Verificación contra el código**

Solo hay 30 días de `AssetSnapshot` (retención). Una regresión sobre una ventana tan corta puede ser ruidosa si el uso de disco es escalonado en vez de lineal — la intervención tiene que asumirlo explícitamente.

**Intervención**

`GET /hygeia/assets/{id}/stats/disk-trend` — regresión lineal simple (mínimos cuadrados, sin dependencia nueva) sobre `disk_max_pct` en la ventana disponible. La respuesta incluye `daysUntilFull` **solo** cuando la pendiente es positiva y por encima de un umbral mínimo de confianza (p. ej. R² o pendiente absoluta); si no, devuelve `null` con `reason: "insufficient_trend"` en vez de un número especulativo.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/services/stats.py` (regresión), `endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre una serie de fixture con pendiente clara, `daysUntilFull` es razonablemente correcto; sobre una serie plana o con datos insuficientes, devuelve `null` con la razón, nunca un número inventado.

**Dependencias**

Requiere E01, E03, E16.

---

### [E21] Patrón horario de carga (heatmap hora del día)

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 6 — El análisis derivado |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 3 / 5 |
| **Prioridad (I × F)** | **9** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 21 de 26 |

**Diagnóstico**

Detectar la hora pico del parque o de un activo (¿siempre a las 9h? ¿los findes de semana?) hoy exige exportar la serie cruda y agrupar a mano.

**Verificación contra el código**

`received_at` (reloj del servidor) es la referencia fiable para agrupar por hora del día — `collected_at` es el reloj del agente y no se usa para ordenar/filtrar, según ya establece el propio modelo.

**Intervención**

`GET /hygeia/stats/hourly-pattern?metric=...&agg=avg&scope=asset|tag|fleet&period=...` — agrupa los snapshots del periodo por hora del día (0–23, hora del servidor) y devuelve el promedio por hora, reutilizando el `scope` ya construido en E04/E08/E11.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre snapshots de fixture con un pico conocido a una hora concreta, el patrón devuelto lo refleja en la posición correcta del array de 24 horas.

**Dependencias**

Requiere E01 y el mismo mecanismo de `scope` de E04/E08.

---

### [E22] Ranking de activos por incumplimientos de umbral

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 6 — El análisis derivado |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **12** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 14 de 26 |

**Diagnóstico**

`MonitoredAsset.breach_counters` ya cuenta cruces de umbral por métrica, pero no hay ningún endpoint que lo exponga ordenado — el dato existe y está sin usar.

**Verificación contra el código**

`MonitoredAsset.breach_counters` y `thresholds` (`model.py`) ya existen: contadores de cruces de umbral por métrica y los umbrales propios del activo, que pisan los globales.

**Intervención**

`GET /hygeia/stats/breach-ranking?limit=N` — ordena los activos del usuario por la suma de sus `breach_counters`, y por separado expone qué métrica es la más conflictiva del parque (la de mayor recuento acumulado entre todos los activos).

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py`, `managers.py`.

**Nuevos artefactos**

Ninguno — es exposición pura de un campo ya persistido, sin cálculo nuevo de umbrales.

**Criterio de cierre**

Sobre activos de fixture con `breach_counters` conocidos, el ranking y la métrica más conflictiva son exactos.

**Dependencias**

Ninguna de otras necesidades del roadmap; usa un campo ya existente.

---

### [E23] Correlación simple entre picos de red y CPU

| | |
|---|---|
| **Categoría** | Estratégica |
| **Fase** | 6 — El análisis derivado |
| **Impacto (I)** | 2 / 5 |
| **Facilidad (F)** | 2 / 5 |
| **Prioridad (I × F)** | **4** |
| **Realismo (R)** | R3 |
| **Orden en la tabla maestra (§4)** | 26 de 26 |

**Diagnóstico**

Pregunta interesante pero de bajo compromiso deliberado: ¿coinciden en el tiempo los picos de CPU y de red de un activo? Puede indicar, por ejemplo, un proceso que satura CPU procesando tráfico entrante. Se marca explícitamente como apuesta de I+D para no comprometer más presupuesto del que el roadmap puede permitirse en algo especulativo.

**Verificación contra el código**

Se apoya en E07 (timestamps de pico) de dos métricas del mismo activo — no necesita ningún dato nuevo.

**Intervención**

Sin modelo estadístico: comparar si los timestamps de pico de `cpuPct` y `netRxBps`/`netTxBps` (de E07) caen dentro de una misma ventana corta (p. ej. 5 minutos) en el periodo pedido, y reportarlo como una señal booleana con los timestamps de ambos picos, no como una correlación estadística formal.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/managers.py` (extensión del endpoint de resumen de E05).

**Nuevos artefactos**

Ninguno.

**Criterio de cierre**

Sobre una serie de fixture con picos simultáneos conocidos, la señal se detecta; sobre una sin relación, no se fuerza una coincidencia falsa.

**Dependencias**

Requiere E07. Sin bloqueo de otras necesidades: puede posponerse sin afectar al resto del roadmap.

---

## Fase 7 — La vista en el panel

Issue padre ya creado: [#418](https://github.com/ProjectEllysia/EllysiaServer/issues/418).

### [E24] Vista "Estadísticas" en el panel de Hygeia

| | |
|---|---|
| **Categoría** | Funcionalidad |
| **Fase** | 7 — La vista en el panel |
| **Impacto (I)** | 5 / 5 |
| **Facilidad (F)** | 2 / 5 |
| **Prioridad (I × F)** | **10** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 15 de 26 |

**Diagnóstico**

Todas las fases anteriores son backend puro; sin esta necesidad, ningún usuario ve el resultado sin usar la API directamente.

**Verificación contra el código**

`web/app/src/views/` sigue el patrón por-módulo del resto de la SPA (Vue 3 + Pinia + Vue Router); una vista nueva de Hygeia se integra en la navegación existente del módulo siguiendo ese mismo patrón, sin inventar uno propio.

**Intervención**

Vista nueva con selector de alcance (activo/etiqueta/parque), métrica y periodo, que consume `/stats/summary` (E05), `/stats/by-tag` (E08), `/stats/ranking` (E11) y `/stats/overview` (E12) como pantalla de aterrizaje. Ningún cálculo de agregación en el cliente: solo formato de números y fechas.

**Puntos exactos de cambio**

`web/app/src/views/` (vista nueva), router del módulo Hygeia, store Pinia si el estado lo justifica.

**Nuevos artefactos**

Ninguno de backend.

**Criterio de cierre**

Un usuario puede cambiar de alcance/métrica/periodo desde la vista y ver los números correspondientes sin recargar la página.

**Dependencias**

Requiere E05, E08, E11, E12 ya construidos.

---

### [E25] Gráficas comparativas configurables por el usuario

| | |
|---|---|
| **Categoría** | Mejora |
| **Fase** | 7 — La vista en el panel |
| **Impacto (I)** | 3 / 5 |
| **Facilidad (F)** | 2 / 5 |
| **Prioridad (I × F)** | **6** |
| **Realismo (R)** | R2 |
| **Orden en la tabla maestra (§4)** | 25 de 26 |

**Diagnóstico**

Ver una sola métrica a la vez limita la utilidad de la vista de E24 — comparar CPU y memoria en la misma gráfica es la forma natural de detectar swap por falta de memoria, por ejemplo.

**Verificación contra el código**

Se apoya en E14/E15 (series multi-fuente ya alineadas por cubo) — el trabajo de alinear temporalmente ya está resuelto en el backend antes de llegar aquí.

**Intervención**

El usuario elige 2–3 métricas a superponer en la vista de E24; el backend (E14/E15) ya devuelve las series alineadas, el cliente solo las dibuja.

**Puntos exactos de cambio**

`web/app/src/views/` (extensión de la vista de E24).

**Nuevos artefactos**

Ninguno de backend.

**Criterio de cierre**

El usuario puede seleccionar y deseleccionar métricas superpuestas sin que la gráfica pierda la alineación temporal entre series.

**Dependencias**

Requiere E14, E15, E24.

---

### [E26] Exportar estadísticas (CSV/JSON) desde el panel

| | |
|---|---|
| **Categoría** | Mejora |
| **Fase** | 7 — La vista en el panel |
| **Impacto (I)** | 2 / 5 |
| **Facilidad (F)** | 4 / 5 |
| **Prioridad (I × F)** | **8** |
| **Realismo (R)** | R1 |
| **Orden en la tabla maestra (§4)** | 23 de 26 |

**Diagnóstico**

Un usuario que quiera analizar los números fuera del panel (una hoja de cálculo, un informe) hoy tendría que copiar valores a mano de la pantalla.

**Verificación contra el código**

Reutiliza exactamente los endpoints ya construidos en las fases 1–6 — no hay agregación nueva que escribir, solo un formato de salida distinto.

**Intervención**

Los endpoints de resumen/ranking/overview ganan un parámetro de `format=json|csv` (JSON ya es el default de toda la API), con un botón de descarga en la vista de E24 que apunta a la misma URL con `format=csv`.

**Puntos exactos de cambio**

`API/src/modules/features/hygeia/endpoints.py` (negociación de formato), `web/app/src/views/` (botón).

**Nuevos artefactos**

Ninguno de base de datos.

**Criterio de cierre**

El CSV descargado contiene exactamente los mismos valores que la respuesta JSON del mismo endpoint, verificado en un test de integración.

**Dependencias**

Requiere E24 y cualquiera de los endpoints de las fases 1–6 que se decida exponer primero.

---
