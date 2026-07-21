<template>
  <div class="vitals">
    <div v-if="!vitals.length" class="vitals-empty">
      <p class="empty-title">Sin señal</p>
      <p class="empty-sub">En cuanto el agente envíe su primer heartbeat, el pulso del activo aparecerá aquí.</p>
    </div>

    <template v-else>
      <article v-for="v in vitals" :key="v.key" class="vital" :class="`vital--${v.key}`">
        <header class="vital-head">
          <h5 class="vital-name">{{ v.name }}</h5>
          <p class="vital-now">
            <span class="now-value">{{ v.currentLabel }}</span><span class="now-unit">%</span>
          </p>
        </header>

        <div class="vital-plot">
          <svg class="spark" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true" focusable="false">
            <polygon :points="v.area" class="spark-area" />
            <polyline :points="v.line" class="spark-line" vector-effect="non-scaling-stroke" />
          </svg>
          <span class="axis-mark axis-mark--hi">{{ v.hiLabel }}%</span>
          <span class="axis-mark axis-mark--lo">{{ v.loLabel }}%</span>
        </div>

        <p class="vital-foot">
          <span class="stat"><b>{{ v.maxLabel }}%</b> máx</span>
          <span class="stat"><b>{{ v.avgLabel }}%</b> media</span>
        </p>

        <p class="sr-only">{{ v.name }}: {{ v.currentLabel }} por ciento ahora, {{ v.maxLabel }} máximo, {{ v.avgLabel }} de media.</p>
      </article>

      <p class="vitals-window">{{ windowLabel }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtPct } from './format'

const props = defineProps({
  snapshots: { type: Array, default: () => [] }, // [{ collectedAt, cpuPct, memPct }]
})

const SERIES = [
  { key: 'cpu', name: 'CPU', field: 'cpuPct' },
  { key: 'mem', name: 'Memoria', field: 'memPct' },
]

/** Alto del viewBox y margen interno para que el trazo no se recorte arriba/abajo. */
const VB_H = 34
const INSET = 3

/**
 * Rango mínimo (en puntos porcentuales) que se muestra aunque la serie sea
 * plana. Sin este suelo, un host en reposo amplificaría el ruido de décimas
 * hasta parecer un sismógrafo: la escala automática resuelve la ilegibilidad
 * de un eje 0-100 fijo, pero no debe inventar drama donde no lo hay.
 */
const MIN_SPAN = 6

function round(v) { return Math.round(v * 100) / 100 }

/**
 * Construye una traza a partir de una serie del payload.
 *
 * El eje Y se ajusta a los datos, no a 0-100: una máquina sana reporta un 9 %
 * de memoria, que en escala fija queda pegado al eje e indistinguible de la
 * CPU. El rango real se rotula sobre el gráfico para que la escala variable
 * no engañe.
 *
 * @returns {object|null} Traza lista para pintar, o null si la serie no tiene ni un dato.
 */
function buildVital({ key, name, field }) {
  const total = props.snapshots.length
  let points = []
  props.snapshots.forEach((snapshot, i) => {
    const value = snapshot[field]
    if (value === null || value === undefined || Number.isNaN(value)) return
    points.push({
      x: total <= 1 ? 50 : (i / (total - 1)) * 100,
      v: Math.max(0, Math.min(100, value)),
    })
  })
  if (!points.length) return null

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
  if (hi - lo < MIN_SPAN) {
    const mid = (hi + lo) / 2
    lo = mid - MIN_SPAN / 2
    hi = mid + MIN_SPAN / 2
  } else {
    const pad = (hi - lo) * 0.15
    lo -= pad
    hi += pad
  }
  lo = Math.max(0, lo)
  hi = Math.min(100, hi)
  if (hi - lo < 1) hi = Math.min(100, lo + 1)

  const yFor = (v) => VB_H - INSET - ((v - lo) / (hi - lo)) * (VB_H - INSET * 2)
  const line = points.map((p) => `${round(p.x)},${round(yFor(p.v))}`).join(' ')

  return {
    key,
    name,
    line,
    area: `${round(points[0].x)},${VB_H} ${line} ${round(points[points.length - 1].x)},${VB_H}`,
    currentLabel: fmtPct(current),
    maxLabel: fmtPct(max),
    avgLabel: fmtPct(avg),
    hiLabel: fmtPct(hi),
    loLabel: fmtPct(lo),
  }
}

const vitals = computed(() => SERIES.map(buildVital).filter(Boolean))

/** Resumen del tramo cubierto: cuántas lecturas y cuánto tiempo abarcan. */
const windowLabel = computed(() => {
  const total = props.snapshots.length
  if (!total) return ''

  const reads = total === 1 ? '1 lectura' : `${total} lecturas`
  const first = new Date(props.snapshots[0].collectedAt).getTime()
  const last = new Date(props.snapshots[total - 1].collectedAt).getTime()
  const minutes = Math.round((last - first) / 60000)

  if (!Number.isFinite(minutes) || minutes < 1) return `${reads} · último minuto`
  if (minutes < 60) return `${reads} · ${minutes} min`
  return `${reads} · ${Math.floor(minutes / 60)} h`
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

.vital-plot { position: relative; margin: 0.6rem 0 0.45rem; }
.spark { display: block; width: 100%; height: 48px; }
.spark-line { fill: none; stroke-width: 1.75; stroke-linejoin: round; stroke-linecap: round; }
.spark-area { stroke: none; }

.vital--cpu .spark-line { stroke: var(--accent-bright); }
.vital--cpu .spark-area { fill: color-mix(in srgb, var(--accent-bright) 15%, transparent); }
.vital--mem .spark-line { stroke: var(--info); }
.vital--mem .spark-area { fill: color-mix(in srgb, var(--info) 15%, transparent); }

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

.vitals-window { margin: 0; text-align: right; font-size: var(--fs-xs); color: var(--text-muted); }

.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}
</style>
