<template>
  <article v-if="metric" class="metric-card" :class="`metric--${metric.key}`"
           :style="{ '--metric-color': metric.color }">
    <header class="metric-head">
      <h5 class="metric-name">{{ metric.name }}</h5>
      <p v-if="current" class="metric-now">
        <span class="now-value">{{ current.text }}</span><span
          v-if="current.unit"
          class="now-unit"
          :class="{ 'now-unit--wide': current.unit !== '%' }"
        >{{ current.unit }}</span>
      </p>
    </header>

    <!-- El gráfico manda sobre la tarjeta: el eje Y con techo natural (los
         porcentajes no escalan al máximo registrado), el eje X en tiempo
         real para localizar spikes, y las bandas de tiempo sin señal para
         que una caída se vea como caída y no como un salto entre puntos. -->
    <div ref="plotEl" class="metric-plot" @pointermove="onPointerMove" @pointerleave="onPointerLeave">
      <svg
        v-if="points.length"
        class="plot-svg"
        :width="plotW"
        :height="SVG_H"
        aria-hidden="true"
        focusable="false"
      >
        <g class="grid">
          <line
            v-for="t in yTickValues"
            :key="`y${t}`"
            :x1="0" :x2="plotW" :y1="yFor(t)" :y2="yFor(t)"
            class="grid-line"
          />
          <line
            v-for="(t, i) in xTickValues"
            :key="`x${i}`"
            :x1="xFor(t)" :x2="xFor(t)" :y1="PLOT_TOP" :y2="PLOT_BOTTOM"
            class="grid-line grid-line--x"
          />
        </g>

        <!-- Bandas de tiempo sin señal: huecos sin heartbeats por encima del
             umbral adaptativo, incluidos los bordes de la ventana. -->
        <g v-if="gaps.length" class="gaps">
          <rect
            v-for="(g, i) in gaps"
            :key="`g${i}`"
            :x="xFor(g.start)"
            :width="Math.max(1, xFor(g.end) - xFor(g.start))"
            :y="PLOT_TOP" :height="PLOT_H"
            class="gap-band"
          >
            <title>Sin señal: {{ fmtDuration(g.end - g.start) }}</title>
          </rect>
        </g>

        <!-- Incidencias registradas: host_down como banda (el tramo exacto
             que el servidor declaró caído), el resto como marca vertical en
             el instante de apertura. -->
        <g v-if="anomalyBands.length || anomalyMarks.length" class="anomaly-layer">
          <rect
            v-for="(a, i) in anomalyBands"
            :key="`ab${i}`"
            :x="xFor(a.start)"
            :width="Math.max(1, xFor(a.end) - xFor(a.start))"
            :y="PLOT_TOP" :height="PLOT_H"
            class="anomaly-band"
          >
            <title>{{ a.title }}</title>
          </rect>
          <line
            v-for="(m, i) in anomalyMarks"
            :key="`am${i}`"
            :x1="xFor(m.at)" :x2="xFor(m.at)" :y1="PLOT_TOP" :y2="PLOT_BOTTOM"
            class="anomaly-mark"
          >
            <title>{{ m.title }}</title>
          </line>
        </g>

        <template v-for="(segment, i) in plotSegments" :key="`segment${i}`">
          <polygon v-if="segment.area" :points="segment.area" class="spark-area" />
          <polyline
            v-if="segment.line"
            :key="`${drawKey}-${i}`"
            :points="segment.line"
            class="spark-line"
            :class="{ draw: drawKey > 0 }"
            pathLength="1"
            vector-effect="non-scaling-stroke"
          />
          <circle
            v-else-if="segment.points.length === 1"
            :cx="segment.points[0].x" :cy="segment.points[0].y" r="3.5"
            class="spark-dot"
          />
        </template>

        <g v-if="hover" class="crosshair">
          <line :x1="hover.x" :x2="hover.x" :y1="PLOT_TOP" :y2="PLOT_BOTTOM" class="crosshair-line" />
          <circle :cx="hover.x" :cy="hover.y" r="3.5" class="crosshair-dot" />
        </g>

        <g class="axis-y">
          <text
            v-for="t in yTickValues"
            :key="`l${t}`"
            :x="plotW - 4" :y="yFor(t) + 3"
            class="axis-y-label"
            text-anchor="end"
          >{{ formatTick(t) }}</text>
        </g>
      </svg>

      <div v-if="hover" class="tooltip" :style="{ left: tooltipLeft + 'px', top: tooltipTop + 'px' }">
        <span class="tooltip-time">{{ formatTooltipTime(hover.t) }}</span>
        <span class="tooltip-value">{{ hover.text }}</span>
      </div>
    </div>

    <div v-if="points.length" class="axis-x">
      <span
        v-for="(t, i) in xTickValues"
        :key="i"
        class="axis-x-label"
        :style="{ left: (xFor(t) / plotW) * 100 + '%' }"
      >{{ formatTimeTick(t, windowMs) }}</span>
    </div>

    <p v-if="gaps.length || anomalyBands.length" class="plot-legend">
      <span v-if="gaps.length" class="legend-item"><i class="swatch swatch--gap"></i>sin señal</span>
      <span v-if="anomalyBands.length" class="legend-item"><i class="swatch swatch--hostdown"></i>incidente host_down</span>
    </p>

    <footer class="metric-foot">
      <span class="stat"><b>{{ maxLabel }}</b> máx</span>
      <span class="stat"><b>{{ avgLabel }}</b> media</span>
      <span class="stat"><b>{{ minLabel }}</b> mín</span>
      <span class="stat stat--reads">{{ reads }}</span>
    </footer>

    <p class="metric-window-note">{{ windowNote }}</p>
    <p class="sr-only">{{ srText }}</p>
  </article>

  <div v-else class="metric-empty" role="status">
    <p class="empty-title">{{ emptyTitle }}</p>
    <p class="empty-sub">{{ emptySub }}</p>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  DEFAULT_WINDOW_MS, SERIES, detectGaps, fmtDuration, formatTimeTick, formatValue,
  gapThresholdMs, medianDeltaMs, seriesOf, splitAtRanges, timeTicks, yRange, yTicks,
} from './chartMath'

const props = defineProps({
  metricKey: { type: String, required: true },
  snapshots: { type: Array, default: () => [] },
  // Duración de la ventana: define el dominio del eje X (desde ahora-hacia
  // atrás hasta ahora). Una caída en curso se ve como banda hasta el borde.
  windowMs: { type: Number, default: DEFAULT_WINDOW_MS },
  // Segundos del cubo de agregación; null = serie cruda (un punto por heartbeat).
  bucketSec: { type: Number, default: null },
  truncated: { type: Boolean, default: false },
  // Anomalías del activo (ya filtradas por asset en la vista): host_down se
  // pinta como banda de incidente; el resto, como marca de apertura.
  anomalies: { type: Array, default: () => [] },
})

const PLOT_H = 190
const PLOT_PAD_Y = 12
const SVG_H = PLOT_H + PLOT_PAD_Y * 2
const PLOT_TOP = PLOT_PAD_Y
const PLOT_BOTTOM = PLOT_TOP + PLOT_H
const TOOLTIP_W = 130
const TOOLTIP_H = 48

const metric = computed(() => seriesOf(props.metricKey))

/* ── Geometría: eje X en tiempo real ── */

/** Instantes de TODOS los snapshots: la presencia manda, no la métrica. */
const times = computed(() =>
  props.snapshots
    .map((s) => new Date(s.receivedAt ?? s.collectedAt).getTime())
    .filter(Number.isFinite)
)

const t0 = computed(() => Date.now() - (props.windowMs || DEFAULT_WINDOW_MS))
const t1 = computed(() => Date.now())

const plotEl = ref(null)
const plotW = ref(600)
let resizeObserver = null

onMounted(() => {
  resizeObserver = new ResizeObserver(() => {
    plotW.value = plotEl.value?.clientWidth || 0
  })
  resizeObserver.observe(plotEl.value)
})
onUnmounted(() => resizeObserver?.disconnect())

const clampTime = (t) => Math.min(Math.max(t, t0.value), t1.value)
const xFor = (t) => ((clampTime(t) - t0.value) / Math.max(1, t1.value - t0.value)) * plotW.value

/* ── Puntos de la métrica seleccionada ── */

const points = computed(() => {
  const field = metric.value?.field
  if (!field) return []
  const pts = []
  for (const snapshot of props.snapshots) {
    const v = snapshot[field]
    if (v === null || v === undefined || Number.isNaN(v)) continue
    const t = new Date(snapshot.receivedAt ?? snapshot.collectedAt).getTime()
    if (!Number.isFinite(t)) continue
    pts.push({ t, v })
  }
  pts.sort((a, b) => a.t - b.t)
  return pts
})

const range = computed(() => {
  if (!points.value.length) return { lo: 0, hi: 1 }
  return yRange(metric.value, points.value.map((p) => p.v))
})

const yFor = (v) => PLOT_BOTTOM - ((v - range.value.lo) / (range.value.hi - range.value.lo)) * PLOT_H

/** Puntos ya proyectados a la geometría del SVG (x/y en px). */
const pts = computed(() => points.value.map((p) => ({ ...p, x: xFor(p.t), y: yFor(p.v) })))

const yTickValues = computed(() => yTicks(metric.value, range.value))

const xTickValues = computed(() => timeTicks(t0.value, t1.value))

function formatTick(value) {
  return formatValue(metric.value.fmt(value))
}

// La animación de trazado se dispara al cambiar de métrica o de ventana,
// nunca en el sondeo: un parpadeo cada 30 s sería ruido, no feedback.
const drawKey = ref(0)
watch(
  () => [props.metricKey, props.windowMs, props.bucketSec],
  () => { drawKey.value += 1 },
)

/* ── Tiempo sin señal ── */

const thresholdMs = computed(() =>
  gapThresholdMs(medianDeltaMs(times.value), props.bucketSec)
)

const gaps = computed(() =>
  times.value.length
    ? detectGaps(
      times.value, thresholdMs.value, t0.value, t1.value,
      (props.bucketSec || 0) * 1000,
    )
    : []
)

/* ── Incidencias ── */

const anomalyBands = computed(() =>
  props.anomalies
    .filter((a) => a.kind === 'host_down' && a.openedAt)
    .map((a) => {
      const start = Math.max(new Date(a.openedAt).getTime(), t0.value)
      const end = a.resolvedAt
        ? Math.min(new Date(a.resolvedAt).getTime(), t1.value)
        : t1.value
      if (!Number.isFinite(start) || end <= start) return null
      return { start, end, title: `host_down: ${fmtDuration(end - start)}` }
    })
    .filter(Boolean)
)

/* El trazo no debe saltar por encima de una zona sin señal o de un incidente. */
const plotSegments = computed(() =>
  splitAtRanges(pts.value, [...gaps.value, ...anomalyBands.value]).map((points) => {
    const line = points.length < 2
      ? ''
      : points.map((p) => `${Math.round(p.x)},${Math.round(p.y)}`).join(' ')
    if (!line) return { points, line: '', area: '' }
    const first = points[0]
    const last = points[points.length - 1]
    return {
      points,
      line,
      area: `${Math.round(first.x)},${PLOT_BOTTOM} ${line} ${Math.round(last.x)},${PLOT_BOTTOM}`,
    }
  })
)

const anomalyMarks = computed(() =>
  props.anomalies
    .filter((a) => a.kind !== 'host_down' && a.openedAt)
    .map((a) => {
      const at = new Date(a.openedAt).getTime()
      if (!Number.isFinite(at) || at < t0.value || at > t1.value) return null
      return { at, title: `${a.kind} · ${formatValue(metric.value.fmt(a.value))}` }
    })
    .filter(Boolean)
)

/* ── Lecturas ── */

const values = computed(() => points.value.map((p) => p.v))
const current = computed(() => {
  if (!values.value.length) return null
  return metric.value.fmt(values.value[values.value.length - 1])
})
const maxLabel = computed(() => formatValue(metric.value.fmt(Math.max(...values.value))))
const minLabel = computed(() => formatValue(metric.value.fmt(Math.min(...values.value))))
const avgLabel = computed(() => formatValue(metric.value.fmt(
  values.value.reduce((a, b) => a + b, 0) / values.value.length,
)))

const reads = computed(() => {
  const n = points.value.length
  if (props.bucketSec) return n === 1 ? '1 cubo' : `${n} cubos`
  return n === 1 ? '1 lectura' : `${n} lecturas`
})

const windowNote = computed(() => {
  const span = fmtDuration(props.windowMs || DEFAULT_WINDOW_MS)
  const bucket = props.bucketSec ? ` · cubos de ${fmtDuration(props.bucketSec * 1000)}` : ''
  const cut = props.truncated ? ' · hay más histórico del que cabe' : ''
  return `${span}${bucket}${cut}`
})

const srText = computed(() => {
  if (!metric.value || !points.value.length) return ''
  const gapsText = gaps.value.length ? `; ${gaps.value.length} tramo${gaps.value.length === 1 ? '' : 's'} sin señal` : ''
  return `${metric.value.name}: ${formatValue(current.value)} ahora, ${maxLabel.value} máximo, ${avgLabel.value} de media, ${minLabel.value} mínimo, sobre ${points.value.length} ${props.bucketSec ? 'cubos' : 'lecturas'}${gapsText}.`
})

/* ── Estados vacíos ── */

const emptyTitle = computed(() =>
  props.snapshots.length ? `Sin datos de ${metric.value?.name ?? 'esta métrica'}` : 'Sin señal en este tramo'
)

const emptySub = computed(() => {
  if (!props.snapshots.length) {
    return 'El agente no ha reportado ningún heartbeat en esta ventana.'
  }
  return `La métrica «${metric.value?.name ?? ''}» no aparece aquí — algunos agentes no la reportan (p. ej. la carga en Windows).`
})

/* ── Crosshair ── */

const hover = ref(null)

function onPointerMove(event) {
  if (!pts.value.length || !plotEl.value) return
  const rect = plotEl.value.getBoundingClientRect()
  const x = event.clientX - rect.left
  if (x < 0 || x > plotW.value) return

  // El punto más cercano en el eje X entre los que tienen valor.
  let nearest = pts.value[0]
  let best = Math.abs(nearest.x - x)
  for (const p of pts.value) {
    const d = Math.abs(p.x - x)
    if (d < best) { best = d; nearest = p }
  }
  hover.value = {
    x: nearest.x,
    y: nearest.y,
    t: nearest.t,
    text: formatValue(metric.value.fmt(nearest.v)),
  }
}

function onPointerLeave() { hover.value = null }

const tooltipLeft = computed(() => {
  if (!hover.value) return 0
  return Math.min(Math.max(hover.value.x + 12, 8), Math.max(8, plotW.value - TOOLTIP_W))
})

const tooltipTop = computed(() => {
  if (!hover.value) return 0
  return Math.min(Math.max(hover.value.y - 44, 8), PLOT_BOTTOM - TOOLTIP_H)
})

function formatTooltipTime(ts) {
  const d = new Date(ts)
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
</script>

<style scoped>
.metric-card {
  padding: 0.85rem 0.95rem 0.7rem;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 8px;
}

/* ── Cabecera ── */
.metric-head { display: flex; align-items: baseline; justify-content: space-between; gap: 0.75rem; }
.metric-name {
  margin: 0;
  font-size: var(--fs-sm); font-weight: 700;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--text-muted);
}
.metric-now { margin: 0; line-height: 1; }
.now-value {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: 1.6rem; font-weight: 500;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.now-unit { margin-left: 0.1em; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: 0.95rem; color: var(--text-muted); }
.now-unit--wide { margin-left: 0.3em; }

/* ── Zona del gráfico ── */
.metric-plot { position: relative; margin-top: 0.6rem; }
.plot-svg { display: block; width: 100%; }

.grid-line {
  stroke: var(--border);
  stroke-width: 1;
  stroke-dasharray: 3 5;
}
.grid-line--x { opacity: 0.6; }

/* Banda de ausencia: el silencio también es dato. Tono suave para no
   competir con el trazo; el rojo lo hereda de --danger translúcido. */
.gap-band { fill: color-mix(in srgb, var(--danger) 10%, transparent); }

/* Incidente host_down: más intenso que la ausencia (es un hecho declarado
   por el servidor, no un hueco inferido), con borde para que se recorte. */
.anomaly-band {
  fill: color-mix(in srgb, var(--danger) 22%, transparent);
  stroke: color-mix(in srgb, var(--danger) 45%, transparent);
  stroke-width: 1;
}
/* Cualquier otra anomalía: una marca vertical en su apertura. */
.anomaly-mark {
  stroke: var(--warn);
  stroke-width: 1.5;
  stroke-dasharray: 4 4;
  opacity: 0.85;
}

.spark-line { fill: none; stroke-width: 1.75; stroke-linejoin: round; stroke-linecap: round; }
.spark-area { stroke: none; }

/* El color de la traza llega como custom property desde el descriptor de la
   serie, no como una regla por clase: añadir una métrica es una línea de JS
   y no obliga a tocar esta hoja. La clase .metric--{key} se conserva como
   gancho de estilo puntual. */
.spark-line { stroke: var(--metric-color); }
.spark-area { fill: color-mix(in srgb, var(--metric-color) 15%, transparent); }
.spark-dot { fill: var(--metric-color); }

/* Trazado animado solo al cambiar de métrica/ventana (key sobre la polyline);
   con prefers-reduced-motion se dibuja de golpe. pathLength=1 hace que las
   unidades del dash sean fracciones del trazo, sea cual sea su longitud. */
.spark-line.draw {
  stroke-dasharray: 1;
  animation: draw-line 0.6s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}
@keyframes draw-line {
  from { stroke-dashoffset: 1; }
  to   { stroke-dashoffset: 0; }
}

/* Rejilla y etiquetas del eje Y, dentro del SVG: pintura con contorno del
   color de la tarjeta para que el texto se lea aunque pase un trazo por
   debajo. */
.axis-y-label {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-sm); fill: var(--text-muted);
  paint-order: stroke; stroke: var(--surface-2); stroke-width: 3px;
}

/* Eje X: etiquetas en HTML (no escalan con el SVG) sobre una fila propia. */
.axis-x { position: relative; height: 18px; margin-top: 2px; }
.axis-x-label {
  position: absolute; top: 0;
  transform: translateX(-50%);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm);
  color: var(--text-muted); white-space: nowrap;
}
.axis-x-label:first-child { transform: none; left: 0 !important; }
.axis-x-label:last-child { transform: translateX(-100%); }

/* En móvil las ventanas largas siguen teniendo seis instantes, pero sus
   fechas ya no caben sin pisarse: se conservan inicio, mitad y fin. */
@media (max-width: 520px) {
  .axis-x-label:nth-child(2),
  .axis-x-label:nth-child(3),
  .axis-x-label:nth-child(5) { display: none; }
}

/* Crosshair: línea vertical + punto sobre la traza. */
.crosshair-line { stroke: var(--text-dim); stroke-width: 1; stroke-dasharray: 2 3; }
.crosshair-dot { fill: var(--metric-color); stroke: var(--surface-2); stroke-width: 1.5; }

.tooltip {
  position: absolute; z-index: 2;
  display: flex; flex-direction: column; gap: 0.1rem;
  padding: 0.3rem 0.55rem;
  box-sizing: border-box; max-width: calc(100% - 16px);
  background: var(--surface-3); border: 1px solid var(--border-med); border-radius: 6px;
  box-shadow: 0 4px 14px rgb(0 0 0 / 0.35);
  pointer-events: none;
  animation: tooltip-in 0.15s ease;
}
@keyframes tooltip-in { from { opacity: 0; transform: translateY(2px); } }
.tooltip-time { font-size: var(--fs-sm); color: var(--text-muted); font-variant-numeric: tabular-nums; }
.tooltip-value {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md);
  font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums;
}

/* ── Leyenda ── */
.plot-legend {
  display: flex; flex-wrap: wrap; gap: 0.4rem 0.9rem; margin: 0.15rem 0 0;
  font-size: var(--fs-sm); color: var(--text-muted);
}
.legend-item { display: inline-flex; align-items: center; gap: 0.3rem; }
.swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.swatch--gap { background: color-mix(in srgb, var(--danger) 35%, transparent); }
.swatch--hostdown {
  background: color-mix(in srgb, var(--danger) 55%, transparent);
  border: 1px solid var(--danger);
}

/* ── Pie ── */
.metric-foot {
  display: flex; flex-wrap: wrap; gap: 0.4rem 0.85rem;
  margin: 0.5rem 0 0; font-size: var(--fs-sm); color: var(--text-muted);
}
.stat b {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-weight: 600;
  color: var(--text-dim); font-variant-numeric: tabular-nums;
}
.stat--reads { margin-left: auto; }

.metric-window-note { margin: 0.3rem 0 0; text-align: right; font-size: var(--fs-sm); color: var(--text-muted); }

/* ── Estados vacíos ── */
.metric-empty {
  padding: 2rem 1rem; text-align: center;
  border: 1px dashed var(--border-med); border-radius: 8px;
}
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0 auto; max-width: 44ch; font-size: var(--fs-sm); color: var(--text-muted); }

.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
}

@media (prefers-reduced-motion: reduce) {
  .spark-line.draw { animation: none; }
  .tooltip { animation: none; }
}
</style>
