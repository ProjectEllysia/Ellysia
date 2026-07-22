<template>
  <div class="vitals">
    <div v-if="!vitals.length" class="vitals-empty">
      <p class="empty-title">Sin señal</p>
      <p class="empty-sub">En cuanto el agente envíe su primer heartbeat, el pulso del activo aparecerá aquí.</p>
    </div>

    <template v-else>
      <article
        v-for="v in vitals"
        :key="v.key"
        class="vital"
        :class="`vital--${v.key}`"
        :style="{ '--vital-color': v.color }"
      >
        <header class="vital-head">
          <h5 class="vital-name">{{ v.name }}</h5>
          <p class="vital-now">
            <span class="now-value">{{ v.current.text }}</span><span
              class="now-unit"
              :class="{ 'now-unit--wide': v.current.unit !== '%' }"
            >{{ v.current.unit }}</span>
          </p>
        </header>

        <div class="vital-plot">
          <svg class="spark" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true" focusable="false">
            <polygon :points="v.area" class="spark-area" />
            <polyline :points="v.line" class="spark-line" vector-effect="non-scaling-stroke" />
          </svg>
          <span class="axis-mark axis-mark--hi">{{ v.hiLabel }}</span>
          <span class="axis-mark axis-mark--lo">{{ v.loLabel }}</span>
        </div>

        <p class="vital-foot">
          <span class="stat"><b>{{ v.maxLabel }}</b> máx</span>
          <span class="stat"><b>{{ v.avgLabel }}</b> media</span>
          <span class="stat stat--reads">{{ v.reads }}</span>
        </p>

        <p class="sr-only">{{ v.srText }}</p>
      </article>

      <p class="vitals-window">{{ windowLabel }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtPct, fmtRate } from './format'

const props = defineProps({
  snapshots: { type: Array, default: () => [] },
  // La serie venía recortada al máximo de puntos: hay más histórico del que
  // se está pintando, y el rótulo de la ventana debe decirlo.
  truncated: { type: Boolean, default: false },
})

/**
 * Series que se trazan, y todo lo que las distingue entre sí.
 *
 * El componente no sabe nada de porcentajes: cada serie trae su unidad
 * (`fmt`), sus topes (`clamp`) y el rango mínimo que tiene sentido mostrar
 * (`minSpan`, en la unidad de la propia serie). Por eso la red puede
 * convivir con CPU y memoria en el mismo panel sin fingir que es un
 * porcentaje — no lo es, y no tiene techo natural.
 *
 * - `clamp`: `[min, max]`; `null` en cualquiera de los dos = sin tope por
 *   ese lado. Un porcentaje no pasa de 100; unos bytes/s pueden pasar de
 *   cualquier cosa.
 * - `minSpan`: amplitud mínima del eje Y aunque la serie sea plana. Sin este
 *   suelo, un host en reposo amplificaría el ruido de décimas hasta parecer
 *   un sismógrafo.
 * - `color`: se inyecta como custom property, no como clase CSS, para que
 *   añadir una serie no obligue a tocar la hoja de estilos.
 */
const PCT = (v) => ({ text: fmtPct(v), unit: '%' })

const SERIES = [
  { key: 'cpu',    name: 'CPU',       field: 'cpuPct',   color: 'var(--accent-bright)',
    clamp: [0, 100],  minSpan: 6,    fmt: PCT },
  { key: 'mem',    name: 'Memoria',   field: 'memPct',   color: 'var(--info)',
    clamp: [0, 100],  minSpan: 6,    fmt: PCT },
  { key: 'swap',   name: 'Swap',      field: 'swapPct',  color: 'var(--warn)',
    clamp: [0, 100],  minSpan: 6,    fmt: PCT },
  { key: 'disk',   name: 'Disco',     field: 'diskMaxPct', color: 'var(--danger)',
    clamp: [0, 100],  minSpan: 6,    fmt: PCT },
  // Entrada y salida comparten tono a propósito: son la misma magnitud en dos
  // sentidos, y la paleta no tiene seis matices distintos que repartir.
  { key: 'net-rx', name: 'Red · in',  field: 'netRxBps', color: 'var(--success)',
    clamp: [0, null], minSpan: 8192, fmt: fmtRate },
  { key: 'net-tx', name: 'Red · out', field: 'netTxBps',
    color: 'color-mix(in srgb, var(--success) 50%, var(--text-muted))',
    clamp: [0, null], minSpan: 8192, fmt: fmtRate },
]

/** Alto del viewBox y margen interno para que el trazo no se recorte arriba/abajo. */
const VB_H = 34
const INSET = 3

function round(v) { return Math.round(v * 100) / 100 }

/** Aplica los topes de la serie; `null` significa "sin tope por ese lado". */
function clampTo(value, [min, max]) {
  let v = value
  if (min !== null && min !== undefined) v = Math.max(min, v)
  if (max !== null && max !== undefined) v = Math.min(max, v)
  return v
}

/** Une número y unidad: pegados en porcentaje, separados en el resto. */
function label(formatted) {
  if (!formatted.unit) return formatted.text
  return formatted.unit === '%' ? `${formatted.text}%` : `${formatted.text} ${formatted.unit}`
}

/**
 * Construye una traza a partir de una serie del payload.
 *
 * El eje Y se ajusta a los datos, no al rango teórico: una máquina sana
 * reporta un 9 % de memoria, que en escala fija 0-100 queda pegado al eje e
 * indistinguible de la CPU. En las series sin techo (bytes/s) la escala
 * automática no es una mejora sino el único modo posible. El rango real se
 * rotula sobre el gráfico para que la escala variable no engañe.
 *
 * @returns {object|null} Traza lista para pintar, o null si la serie no tiene ni un dato.
 */
function buildVital({ key, name, field, color, clamp, minSpan, fmt }) {
  const total = props.snapshots.length
  let points = []
  props.snapshots.forEach((snapshot, i) => {
    const value = snapshot[field]
    if (value === null || value === undefined || Number.isNaN(value)) return
    points.push({
      x: total <= 1 ? 50 : (i / (total - 1)) * 100,
      v: clampTo(value, clamp),
    })
  })
  // Una serie que el agente no reporta (Windows no manda load1, un host sin
  // interfaces visibles no manda red) simplemente no se dibuja.
  if (!points.length) return null

  const reads = points.length

  // Con una sola lectura no hay trazo posible: se extiende a lo ancho como
  // línea plana en vez de dejar el gráfico vacío.
  if (points.length === 1) {
    points = [{ x: 0, v: points[0].v }, { x: 100, v: points[0].v }]
  }

  const values = points.map((p) => p.v)
  const max = Math.max(...values)
  const min = Math.min(...values)
  const avg = values.reduce((a, b) => a + b, 0) / values.length
  const current = values[values.length - 1]

  let lo = min
  let hi = max
  if (hi - lo < minSpan) {
    const mid = (hi + lo) / 2
    lo = mid - minSpan / 2
    hi = mid + minSpan / 2
  } else {
    const pad = (hi - lo) * 0.15
    lo -= pad
    hi += pad
  }
  lo = clampTo(lo, clamp)
  hi = clampTo(hi, clamp)
  // Tras recortar contra los topes el rango puede quedar degenerado, y una
  // división por cero en `yFor` dejaría el trazo en NaN. Se reabre con la
  // amplitud mínima de la propia serie — nunca con una constante, que solo
  // tendría sentido en porcentaje — y hacia abajo si estamos contra el techo.
  if (hi - lo <= 0) {
    const ceiling = clamp[1]
    if (ceiling !== null && ceiling !== undefined && hi >= ceiling) lo = hi - minSpan
    else hi = lo + minSpan
  }

  const yFor = (v) => VB_H - INSET - ((v - lo) / (hi - lo)) * (VB_H - INSET * 2)
  const line = points.map((p) => `${round(p.x)},${round(yFor(p.v))}`).join(' ')

  const currentFmt = fmt(current)
  const maxLabel = label(fmt(max))
  const avgLabel = label(fmt(avg))

  return {
    key,
    name,
    color,
    line,
    area: `${round(points[0].x)},${VB_H} ${line} ${round(points[points.length - 1].x)},${VB_H}`,
    current: currentFmt,
    maxLabel,
    avgLabel,
    hiLabel: label(fmt(hi)),
    loLabel: label(fmt(lo)),
    reads: reads === 1 ? '1 lectura' : `${reads} lecturas`,
    srText: `${name}: ${label(currentFmt)} ahora, ${maxLabel} máximo, ${avgLabel} de media, sobre ${reads} lecturas.`,
  }
}

const vitals = computed(() => SERIES.map(buildVital).filter(Boolean))

/**
 * Tramo temporal cubierto por la ventana.
 *
 * El recuento de lecturas vive en cada tarjeta, no aquí: tras añadir métricas
 * nuevas, las trazas no tienen por qué cubrir los mismos puntos (las filas
 * anteriores a la instrumentación llegan a null), así que un único total
 * mentiría sobre las series más cortas.
 */
const windowLabel = computed(() => {
  const total = props.snapshots.length
  if (!total) return ''

  const first = new Date(props.snapshots[0].receivedAt ?? props.snapshots[0].collectedAt).getTime()
  const last = new Date(props.snapshots[total - 1].receivedAt ?? props.snapshots[total - 1].collectedAt).getTime()
  const minutes = Math.round((last - first) / 60000)

  let span
  if (!Number.isFinite(minutes) || minutes < 1) span = 'último minuto'
  else if (minutes < 60) span = `${minutes} min`
  else span = `${Math.floor(minutes / 60)} h`

  // Sin este aviso, un recorte silencioso se presentaría como si fuera todo
  // el histórico disponible.
  return props.truncated ? `${span} · hay más histórico del que cabe aquí` : span
})
</script>

<style scoped>
.vitals { display: flex; flex-direction: column; gap: 0.85rem; }

.vitals-empty {
  padding: 2.2rem 1rem; text-align: center;
  border: 1px dashed var(--border-med); border-radius: 8px;
}
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0 auto; max-width: 42ch; font-size: var(--fs-sm); color: var(--text-muted); }

.vital {
  padding: 0.7rem 0.9rem 0.65rem;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 8px;
}

.vital-head { display: flex; align-items: baseline; justify-content: space-between; gap: 0.75rem; }
.vital-name {
  margin: 0;
  font-size: var(--fs-xs); font-weight: 700;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--text-muted);
}
.vital-now { margin: 0; line-height: 1; }
.now-value {
  font-family: var(--font-mono); font-size: 1.6rem; font-weight: 500;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.now-unit { margin-left: 0.1em; font-family: var(--font-mono); font-size: 0.95rem; color: var(--text-muted); }
/* El margen justo funciona para "%", pero pega el número a unidades de varias
   letras: "758KB/s" en lugar de "758 KB/s". */
.now-unit--wide { margin-left: 0.3em; }

.vital-plot { position: relative; margin: 0.6rem 0 0.45rem; }
.spark { display: block; width: 100%; height: 48px; }
.spark-line { fill: none; stroke-width: 1.75; stroke-linejoin: round; stroke-linecap: round; }
.spark-area { stroke: none; }

/* El color de cada traza llega como custom property desde el descriptor de la
   serie, no como una regla por clase: así añadir una métrica es una línea de
   JS y no obliga a tocar esta hoja. La clase .vital--{key} se conserva como
   gancho de estilo puntual y de test. */
.spark-line { stroke: var(--vital-color); }
.spark-area { fill: color-mix(in srgb, var(--vital-color) 15%, transparent); }

/* El rango real se rotula sobre el trazo: la escala es variable, así que
   ocultarla convertiría el gráfico en un adorno sin unidades. */
.axis-mark {
  position: absolute; right: 0;
  padding: 0 0.25rem;
  font-family: var(--font-mono); font-size: var(--fs-xs);
  color: var(--text-muted);
  background: color-mix(in srgb, var(--surface-2) 88%, transparent);
  pointer-events: none;
}
.axis-mark--hi { top: -0.3rem; }
.axis-mark--lo { bottom: -0.3rem; }

.vital-foot { display: flex; gap: 1.1rem; margin: 0; font-size: var(--fs-xs); color: var(--text-muted); }
.stat b {
  font-family: var(--font-mono); font-weight: 600;
  color: var(--text-dim); font-variant-numeric: tabular-nums;
}
/* Cada traza cubre sus propios puntos: una serie recién instrumentada tiene
   menos lecturas que CPU, y el recuento va por tarjeta para no mentir. */
.stat--reads { margin-left: auto; }

.vitals-window { margin: 0; text-align: right; font-size: var(--fs-xs); color: var(--text-muted); }

.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}
</style>
