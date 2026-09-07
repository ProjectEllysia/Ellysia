# Plan de implementación — Monitorización de consumo energético en Hygeia

## Objetivo

Incorporar a Hygeia una nueva métrica de **consumo energético de la máquina** expresada en vatios (W), obtenida automáticamente por el agente según el sistema operativo y el hardware disponible.

La funcionalidad debe:

- funcionar de forma multiplataforma, como mínimo en **Linux y Windows**;
- proporcionar el **mejor dato disponible**, aunque en muchos equipos sea una estimación;
- diferenciar entre medición directa y estimación;
- informar al usuario de que la precisión no está garantizada;
- conservar histórico de consumo;
- mostrar una gráfica de potencia;
- permitir estimar energía consumida (kWh);
- permitir calcular el coste económico desde el servidor;
- integrarse en el pipeline existente de `HygeiaAgent` → `/hygeia/ingest` → `AssetSnapshot` → API → SPA;
- degradarse correctamente cuando un equipo no exponga ninguna fuente de potencia compatible.

> **Principio fundamental:** el agente recopila potencia. El servidor calcula energía y coste. No se debe presentar una estimación como si fuese una medición eléctrica exacta.

> **Principio de continuidad de datos:** los cálculos energéticos solo deben utilizar intervalos en los que exista una medición/estimación válida recibida del agente. Un equipo apagado, caído o sin comunicación no equivale a `0 W`; esos periodos deben tratarse como **datos ausentes** y no deben entrar en la media de potencia ni generar consumo/coste imputado.


---

# Fase 0 — Diseño del contrato y alcance

## Objetivos

Definir el contrato de la nueva métrica antes de implementar proveedores específicos por sistema operativo.

## Trabajo

### HygeiaAgent

Añadir una nueva familia de métricas:

```go
type PowerMetrics struct {
    Watts      float64 `json:"watts"`
    Estimated  bool    `json:"estimated"`
    Source     string  `json:"source"`
}
```

Añadirla a:

```go
type Metrics struct {
    CPU       *CPUMetrics      `json:"cpu,omitempty"`
    Memory    *MemoryMetrics   `json:"memory,omitempty"`
    Disk      []DiskMetrics    `json:"disk,omitempty"`
    Network   []NetworkMetrics `json:"network,omitempty"`
    Processes *ProcessMetrics  `json:"processes,omitempty"`
    Power     *PowerMetrics    `json:"power,omitempty"`
}
```

### Decisiones

`watts` representa potencia instantánea o una aproximación inmediata.

`estimated`:

- `false`: el valor procede de una fuente que realmente expone potencia;
- `true`: el valor se ha construido mediante estimación o agregación de sensores.

`source` identifica el origen, por ejemplo:

- `rapl`
- `hwmon`
- `nvidia`
- `amd_gpu`
- `psu`
- `windows_sensor`
- `aggregated`
- `unavailable`

Si no existe una fuente válida, `power` debe poder omitirse completamente.

---

# Fase 1 — Collector de potencia en HygeiaAgent

## Objetivos

Integrar potencia en el sistema de collectors existente sin modificar el flujo principal del agente.

La arquitectura actual ya utiliza `Collector`, `Registry` y ejecución paralela de collectors. La nueva métrica debe seguir exactamente este patrón.

## Trabajo

### 1.1 Crear el collector

Crear:

```text
internal/collector/power.go
```

El collector debe implementar:

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context, m *payload.Metrics) error
}
```

y registrarse como:

```go
r.Register("power", NewPower)
```

### 1.2 Diseñar una interfaz de proveedor

Separar el collector de la implementación específica del sistema operativo:

```go
type PowerProvider interface {
    Read(ctx context.Context) (*payload.PowerMetrics, error)
}
```

El collector será únicamente el adaptador:

```text
PowerCollector
      ↓
PowerProvider
      ↓
implementación del SO/hardware
```

### 1.3 Comportamiento ante errores

La ausencia de sensores no debe provocar que falle el heartbeat completo.

Ejemplo:

```text
sin sensor compatible
        ↓
warning en log
        ↓
power omitido
        ↓
heartbeat continúa normalmente
```

### 1.4 Tests

Añadir pruebas para:

- proveedor válido;
- valor cero;
- valor positivo;
- error del proveedor;
- ausencia de proveedor;
- valor estimado;
- serialización JSON;
- timeout/cancelación.

---

# Fase 2 — Implementación Linux

## Objetivo

Conseguir la mejor estimación disponible en Linux aprovechando las interfaces que exponga el kernel/hardware.

## Trabajo

Crear:

```text
internal/collector/power_linux.go
```

## Estrategia recomendada

Implementar proveedores por prioridad.

### 2.1 RAPL

Intentar aprovechar las interfaces de energía de CPU disponibles mediante RAPL cuando existan.

Ventajas:

- bajo coste de lectura;
- buen soporte en hardware compatible;
- especialmente útil para consumo de CPU/package.

Limitación:

- normalmente no representa por sí solo el consumo completo del equipo.

### 2.2 hwmon

Explorar:

```text
/sys/class/hwmon/
```

y localizar sensores de potencia disponibles.

No se debe asumir que cualquier `power*_input` representa el consumo total del equipo.

### 2.3 GPU

Añadir soporte específico cuando sea viable:

- NVIDIA;
- AMD.

El objetivo inicial puede limitarse a GPU si ya existe una fuente estable para esa plataforma.

### 2.4 Agregación

Crear una política clara para no realizar doble conteo.

Por ejemplo:

```text
PSU telemetry disponible
        ↓
usar PSU

si no:
agregar fuentes compatibles
        ↓
CPU + GPU + otros sensores
```

Las fuentes utilizadas deben quedar registradas en `source`.

### 2.5 Resultado

Ejemplos:

```json
{
  "watts": 286.4,
  "estimated": true,
  "source": "rapl+gpu+hwmon"
}
```

o:

```json
{
  "watts": 314.7,
  "estimated": false,
  "source": "psu"
}
```

## 2.6 Tests Linux

Cubrir:

- RAPL disponible;
- RAPL ausente;
- hwmon disponible;
- varios sensores;
- sensores no relevantes;
- GPU disponible/ausente;
- combinación de fuentes;
- detección de doble conteo;
- sistema sin fuentes compatibles.

---

# Fase 3 — Implementación Windows

## Objetivo

Proporcionar un proveedor específico de Windows con el mismo contrato público.

## Trabajo

Crear:

```text
internal/collector/power_windows.go
```

## Estrategia

Evaluar fuentes de telemetría accesibles desde Windows, priorizando una fuente capaz de ofrecer:

1. potencia de PSU/sistema completo;
2. potencia de CPU;
3. potencia de GPU;
4. combinación de sensores.

La implementación puede apoyarse en una capa de sensores externa o en APIs específicas cuando Windows por sí solo no exponga potencia total.

## Requisitos

Debe:

- devolver `PowerMetrics`;
- marcar `Estimated=true` cuando corresponda;
- indicar el proveedor real en `Source`;
- fallar de forma no destructiva;
- funcionar sin afectar al resto de collectors.

## Tests Windows

Cubrir:

- sensor disponible;
- sensor no disponible;
- WMI/telemetría inaccesible;
- GPU disponible/ausente;
- estimación;
- errores y timeouts.

---

# Fase 4 — Integración del payload y configuración del agente

## Objetivo

Hacer que `power` forme parte de los heartbeats normales.

## Trabajo

### 4.1 Payload

Actualizar:

```text
internal/payload/payload.go
```

### 4.2 Registry

Actualizar:

```text
internal/collector/collector.go
```

para registrar `power`.

### 4.3 Configuración

Determinar si `power` debe:

- venir habilitado por defecto;
- poder desactivarse mediante configuración de collectors.

Recomendación:

> habilitado por defecto, con posibilidad de desactivarlo.

### 4.4 Compatibilidad

Un heartbeat sin potencia debe seguir siendo válido.

Esto permite:

- agentes antiguos;
- hardware sin sensores;
- sistemas con permisos insuficientes.

---

# Fase 5 — Contrato de ingesta en EllysiaServer

## Objetivo

Aceptar y validar la nueva métrica desde `/hygeia/ingest`.

## Trabajo

Modificar:

```text
API/src/modules/features/hygeia/schemas.py
```

Añadir:

```python
class PowerMetricsSchema(_IngestSchema):
    watts = fields.Float(
        required=True,
        validate=validate.Range(min=0),
    )
    estimated = fields.Boolean(required=True)
    source = fields.String(
        required=True,
        validate=validate.Length(min=1, max=64),
    )
```

y:

```python
class MetricsSchema(_IngestSchema):
    ...
    power = fields.Nested(
        PowerMetricsSchema,
        load_default=None,
    )
```

## Validaciones

Rechazar:

- valores negativos;
- valores no numéricos;
- strings inválidos;
- fuentes vacías.

Permitir:

```json
"power": null
```

a nivel semántico mediante ausencia del campo.

No debe rechazarse un heartbeat simplemente porque no haya medición disponible.

---

# Fase 6 — Persistencia del histórico

## Objetivo

Persistir potencia de forma eficiente para poder graficarla.

## Trabajo

Modificar:

```text
API/src/modules/features/hygeia/model.py
```

Añadir a `AssetSnapshot`:

```text
power_watts
power_estimated
power_source
```

## Recomendación

Mantener:

- el payload completo en `metrics` (JSONB);
- `power_watts` desnormalizado para series temporales;
- metadatos (`estimated`, `source`) para explicar la procedencia.

## Migración

Crear una nueva migración Alembic.

Debe:

- añadir las nuevas columnas;
- mantener compatibilidad con snapshots existentes;
- dejar valores históricos anteriores como `NULL`.

---

# Fase 7 — Desnormalización

## Objetivo

Integrar potencia en el pipeline existente de agregación.

## Trabajo

Modificar:

```text
API/src/modules/features/hygeia/services/aggregation.py
```

Añadir:

```python
power = metrics.get("power") or {}

return {
    ...
    "power_watts": power.get("watts"),
    "power_estimated": power.get("estimated"),
    "power_source": power.get("source"),
}
```

Debe conservarse la distinción:

```text
NULL → dato no reportado
0    → dato reportado y consumo cero
```

No convertir automáticamente ausencia de sensores en `0 W`.

---

# Fase 8 — API y series temporales

## Objetivo

Exponer potencia usando la infraestructura de métricas existente.

## Trabajo

Aprovechar:

```text
GET /hygeia/assets/<asset_id>/metrics
GET /hygeia/assets/<asset_id>/metrics/latest
```

No crear endpoints específicos de potencia salvo que en el futuro exista una necesidad concreta.

## Serie temporal

Añadir:

```text
powerWatts
```

al punto temporal.

Ejemplo:

```json
{
  "collectedAt": "...",
  "receivedAt": "...",
  "cpuPct": 42.1,
  "memPct": 63.2,
  "powerWatts": 187.4
}
```

## Agregación

Mantener compatible la lógica existente de `bucket`.

Para ventanas largas se puede utilizar:

- promedio;
- máximo;
- mínimo;

según lo que tenga más sentido visual para potencia.

Recomendación:

> usar promedio como valor principal de cada bucket y conservar máximo si se quiere mostrar picos.

---

# Fase 9 — Frontend: gráfica de potencia

## Objetivo

Mostrar el consumo de la máquina junto al resto de métricas.

## Trabajo

Integrar `Power` en:

```text
MetricNav
MetricsChart
AssetDetail.vue
```

La navegación debería permitir:

```text
CPU
Memoria
...
Potencia
```

## Gráfico

Eje Y:

```text
W
```

Ejemplo:

```text
350 W ┤       ╭─╮
300 W ┤     ╭─╯ ╰──╮
250 W ┤─────╯      ╰──
200 W ┤
150 W ┤
      └────────────────
          tiempo
```

## Huecos de telemetría

La gráfica no debe dibujar los periodos sin datos como una línea que pase por `0 W`.

Debe existir un hueco visual o una representación equivalente de **datos no disponibles**.

Esto evita interpretar erróneamente:

```text
200 W → equipo apagado → 0 W → 200 W
```

cuando en realidad se tiene:

```text
200 W → sin datos → 200 W
```

## Estado de la métrica

La interfaz debe distinguir:

### Medición disponible

```text
287 W
Medición de sensor
```

### Estimación

```text
287 W
Estimación · precisión no garantizada
```

### No disponible

```text
Consumo no disponible
Este equipo no expone sensores de potencia compatibles.
```

## Aviso obligatorio

Debe existir una advertencia visible del tipo:

> El consumo mostrado es una estimación basada en los sensores disponibles del equipo. La precisión puede variar según el hardware y no equivale necesariamente al consumo medido en el enchufe.

El texto debe dejar claro que:

- no es necesariamente consumo de red;
- puede haber error;
- la precisión depende del hardware.

---

# Fase 10 — Coste energético a nivel de servidor

## Objetivo

Convertir potencia en energía y coste económico sin cargar esa lógica en el agente.

## Decisión arquitectónica

El agente envía:

```text
W
```

El servidor calcula:

```text
W → kWh → €
```

## Configuración

Crear una configuración para precio de electricidad.

Ejemplo:

```text
energyPrice = 0.15 €/kWh
```

Debe quedar asociada al ámbito adecuado del producto, preferentemente:

- usuario;
- organización;

y no al agente.

## Cálculo

Para un intervalo de duración `Δt`:

```text
kWh = (W / 1000) × horas
```

Ejemplo:

```text
250 W durante 4 horas
= 1 kWh
```

Con:

```text
0,15 €/kWh
```

el coste será:

```text
0,15 €
```

## Costes a mostrar

Como mínimo:

- €/hora;
- €/día;
- €/mes;
- €/año.

Los valores de día/mes/año deben poder basarse en histórico real o, cuando no exista suficiente histórico, marcarse como proyección.

---

# Fase 11 — Histórico energético y resumen

## Objetivo

Pasar de un dato instantáneo a una métrica accionable.

## Cálculo únicamente sobre tiempo observado

La **potencia media** debe calcularse únicamente a partir de muestras/intervalos realmente observados.

No se debe hacer:

```text
host apagado durante 12 h → 0 W
host medido durante 12 h   → 200 W

media = (0 + 200) / 2
```

sino:

```text
12 h con datos → 200 W
12 h sin datos → excluidas

potencia media observada = 200 W
```

Siempre que sea posible, la agregación debe ser **ponderada por duración**, teniendo en cuenta el tiempo transcurrido entre muestras válidas, en lugar de tratar todas las muestras como si representasen exactamente la misma duración.

Ejemplo:

```text
10:00 → 100 W
10:15 → 300 W
10:30 → sin datos
11:30 → 200 W
```

El intervalo sin datos no debe convertirse en cero. Para una media temporal, solo deben contribuir los intervalos cubiertos por mediciones válidas.

## Energía y coste

El cálculo de kWh y coste también debe basarse exclusivamente en intervalos observados.

No se debe imputar:

```text
host apagado
    ↓
0 W
    ↓
0 kWh
```

como si se hubiese medido su consumo.

Debe existir una distinción entre:

- **energía observada**: calculada sobre intervalos con datos;
- **energía estimada/proyectada**: cálculo futuro o extrapolación, claramente etiquetado.

Cuando existan huecos de telemetría, la interfaz debe poder indicar que el período contiene **datos incompletos**.


## Información recomendada

Para cada activo:

```text
Consumo actual       187 W
Media 24 h           204 W
Energía 24 h         4,90 kWh
Coste 24 h            0,74 €
```

Y para períodos mayores:

```text
Últimos 7 días
Energía               34,7 kWh
Coste                  5,21 €

Últimos 30 días
Energía              148,2 kWh
Coste                 22,23 €
```

## Proyecciones

Cuando proceda:

```text
Proyección mensual
≈ 24,80 €
```

Debe etiquetarse como proyección, no como coste ya consumido.

---

# Fase 12 — Calidad, procedencia y confianza

## Objetivo

Evitar que el usuario interprete todos los datos como igualmente precisos.

## Clasificación recomendada

### Alta

Telemetría directa del sistema/PSU.

```text
estimated = false
```

### Media

Combinación de sensores de componentes.

```text
estimated = true
```

### Baja

Estimación basada en utilización cuando no exista telemetría suficiente.

```text
estimated = true
```

## Campo futuro opcional

Si más adelante merece la pena, se puede ampliar:

```go
Confidence float64 `json:"confidence,omitempty"`
```

pero no es necesario para el MVP.

---

# Fase 13 — Tests de extremo a extremo

## Objetivo

Garantizar que la métrica atraviesa todo el pipeline.

## HygeiaAgent

Tests:

- payload con power;
- payload sin power;
- sensor Linux;
- sensor Windows;
- estimación;
- ausencia de sensor;
- errores del proveedor.

## EllysiaServer

Tests:

- schema acepta power;
- periodo sin heartbeat no se convierte en `0 W`;
- periodo sin heartbeat no entra en la media de potencia;
- media temporal ponderada por los intervalos realmente observados;
- energía y coste no imputan consumo durante huecos de telemetría;
- periodos con máquina offline/apagada quedan fuera de las métricas de potencia;
- schema rechaza valores inválidos;
- ingestión persiste power;
- `AssetSnapshot` conserva `NULL` cuando no existe;
- desnormalización correcta;
- serie temporal devuelve power;
- endpoint latest devuelve power;
- bucket temporal funciona.

## Frontend

Comprobar:

- métrica Power aparece en la navegación;
- gráfico renderiza;
- `NULL` no se dibuja como 0;
- aviso de estimación;
- estado sin sensor;
- coste calculado correctamente.

---

# Fase 14 — Documentación

## Objetivo

Documentar el comportamiento para usuarios y desarrolladores.

## HygeiaAgent

Actualizar documentación con:

- collector `power`;
- plataformas soportadas;
- sensores utilizados;
- limitaciones;
- configuración;
- ejemplos de payload.

## EllysiaServer

Documentar:

- contrato de ingesta;
- persistencia;
- significado de `estimated`;
- cálculo energético;
- precio de electricidad;
- diferencias entre consumo estimado y consumo real de enchufe.

## UI

Añadir texto contextual sobre:

- estimación;
- precisión;
- coste;
- proyección.

---

# Fase 15 — Optimización posterior

Esta fase no es necesaria para el MVP.

## Posibles mejoras

### 15.1 Más proveedores

Añadir soporte para:

- más hardware Linux;
- Intel/AMD específico;
- más APIs de GPU;
- PSU con telemetría;
- UPS/PDU.

### 15.2 Modelo de consumo más preciso

Separar:

```text
consumo base
+
consumo variable
```

y utilizar CPU/GPU/RAM/I/O para atribuir el componente variable.

### 15.3 Virtualización

En hosts físicos con VMs, añadir en el futuro:

```text
consumo total del host
        ↓
atribución estimada
        ↓
VM A
VM B
VM C
```

Importante:

> La potencia de una VM debe considerarse una **atribución estimada**, no una medición eléctrica independiente.

### 15.4 Contenedores

Aplicar un modelo equivalente para Docker/containers si se considera útil.

---

# Orden recomendado de ejecución

```text
Fase 0  → Contrato
   ↓
Fase 1  → Collector
   ↓
Fase 2  → Linux
   ↓
Fase 4  → Payload/configuración
   ↓
Fase 5  → Ingesta servidor
   ↓
Fase 6  → Persistencia
   ↓
Fase 7  → Desnormalización
   ↓
Fase 8  → API / histórico
   ↓
Fase 9  → Gráfica
   ↓
Fase 10 → Costes
   ↓
Fase 11 → Histórico/resúmenes
   ↓
Fase 12 → Calidad/procedencia
   ↓
Fase 13 → Tests E2E
   ↓
Fase 14 → Documentación
```

Después del MVP:

```text
Fase 3  → Windows
Fase 15 → Optimizaciones y nuevas fuentes
```

> **Nota:** aunque Windows forma parte de los requisitos finales, resulta razonable desarrollar primero Linux para validar todo el flujo de extremo a extremo con una implementación de proveedor más controlable. La interfaz de proveedor debe diseñarse desde el principio para que incorporar Windows no implique modificar el contrato de telemetría.

---

# Resultado final esperado

Un activo de Hygeia debería poder mostrar algo similar a:

```text
┌────────────────────────────────────────────┐
│ SERVIDOR-WEB-01                            │
│                                            │
│ Consumo actual                             │
│ 187 W                                      │
│                                            │
│ Estimación basada en sensores              │
│ ⚠ La precisión no es completa              │
│                                            │
│ Coste estimado                              │
│ 0,028 €/h                                  │
│ 0,67 €/día                                 │
│ 20,10 €/mes                                │
└────────────────────────────────────────────┘
```

Y una gráfica histórica:

```text
Potencia (W)

350 ┤           ╭──╮
300 ┤      ╭────╯  ╰────╮
250 ┤──────╯             ╰───╮
200 ┤                          ╰──
150 ┤
    └──────────────────────────────
      00   04   08   12   16   20
```

Con el mismo activo pudiendo exponer además:

```text
Consumo actual:       187 W
Media 24 h:           204 W
Energía 24 h:        4,90 kWh
Coste 24 h:           0,74 €
Proyección mensual:  22,10 €
```

## Principios que no deben romperse

1. **Nunca inventar `0 W` cuando no existe medición.**
2. **Nunca presentar una estimación como una medición exacta.**
3. **Los huecos sin datos no cuentan como consumo cero y quedan fuera de las medias y cálculos de consumo observado.**
4. **El agente mide/estima; el servidor calcula energía y coste.**
5. **La potencia es una métrica más del heartbeat existente, no un canal paralelo.**
6. **La ausencia de sensores no debe romper el heartbeat.**
7. **La serie temporal debe conservar `NULL` cuando el dato no exista.**
8. **La potencia de una VM debe tratarse como atribución, no como medición física.**
9. **La arquitectura debe permitir añadir nuevos proveedores sin modificar el contrato de Ellysia.**
