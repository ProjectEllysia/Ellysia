<template>
  <div class="history-chart">
    <div v-if="!hasData" class="empty">
      <p>No hay datos históricos para este host todavía.</p>
    </div>

    <template v-else>
      <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="xMidYMid meet" class="chart-svg" role="img"
        :aria-label="`${metricLabel} en los últimos ${points.length} escaneos de ${chart.target}`">
        <!-- Y gridlines + labels -->
        <g class="grid">
          <g v-for="tick in yTicks" :key="`y${tick.value}`">
            <line :x1="M.left" :y1="tick.y" :x2="W - M.right" :y2="tick.y" class="gridline" />
            <text :x="M.left - 8" :y="tick.y + 3" text-anchor="end" class="axis-label">{{ tick.value }}</text>
          </g>
        </g>

        <!-- Axes -->
        <line :x1="M.left" :y1="M.top" :x2="M.left" :y2="H - M.bottom" class="axis" />
        <line :x1="M.left" :y1="H - M.bottom" :x2="W - M.right" :y2="H - M.bottom" class="axis" />

        <!-- Bars -->
        <g class="bars">
          <g v-for="(bar, i) in bars" :key="`b${i}`">
            <rect :x="bar.x" :y="bar.y" :width="bar.w" :height="bar.h" rx="2" class="bar" :fill="barColor" />
            <text :x="bar.cx" :y="bar.y - 5" text-anchor="middle" class="bar-value">{{ bar.value }}</text>
            <text :x="bar.cx" :y="H - M.bottom + 16" text-anchor="middle" class="x-label"
              :textLength="bar.w" lengthAdjust="spacingAndGlyphs">{{ bar.label }}</text>
          </g>
        </g>

        <!-- Axis titles -->
        <text :x="M.left + plotW / 2" :y="H - 4" text-anchor="middle" class="axis-title">{{ chart.axes.x.label }}</text>
        <text :x="14" :y="M.top + plotH / 2" text-anchor="middle" class="axis-title"
          :transform="`rotate(-90 14 ${M.top + plotH / 2})`">{{ chart.axes.y.label }}</text>
      </svg>

      <!-- Diff legend -->
      <div v-if="chart.scanCount >= 2" class="legend">
        <div v-for="item in chart.legend" :key="item.label" class="legend-item" :class="legendClass(item.label)">
          <span class="legend-value">{{ item.value }}</span>
          <span class="legend-label">{{ item.label }}</span>
        </div>
      </div>
      <p v-if="chart.scanCount >= 2" class="legend-caption">
        Comparativa del último escaneo frente al inmediatamente anterior.
      </p>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  chart: { type: Object, required: true },
})

const W = 640
const H = 360
const M = { top: 24, right: 18, bottom: 64, left: 52 }

const plotW = W - M.left - M.right
const plotH = H - M.top - M.bottom

const metricLabel = computed(() => props.chart?.metricLabel ?? 'Hallazgos')
const points = computed(() => props.chart?.series?.[0]?.points ?? [])
const hasData = computed(() => points.value.length > 0)

const barColor = computed(() => {
  const map = { nmap: 'var(--info)', nikto: 'var(--warn)', openvas: 'var(--danger)' }
  return map[props.chart?.scanType] ?? 'var(--accent)'
})

const step = computed(() => Math.max(1, props.chart?.axes?.y?.step ?? 1))
const niceMax = computed(() => {
  const max = props.chart?.axes?.y?.max ?? 0
  if (max <= 0) return step.value
  return Math.ceil(max / step.value) * step.value
})

const yTicks = computed(() => {
  const ticks = []
  for (let v = 0; v <= niceMax.value; v += step.value) {
    const y = M.top + plotH - (v / niceMax.value) * plotH
    ticks.push({ value: v, y })
  }
  return ticks
})

const bars = computed(() => {
  const n = points.value.length
  if (!n) return []
  const slot = plotW / n
  const w = Math.min(slot * 0.55, 64)
  return points.value.map((p, i) => {
    const cx = M.left + slot * i + slot / 2
    const h = niceMax.value > 0 ? (p.y / niceMax.value) * plotH : 0
    const y = M.top + plotH - h
    return { x: cx - w / 2, cx, y, w, h, value: p.y, label: p.x }
  })
})

function legendClass(label) {
  if (label === 'Nuevos') return 'new'
  if (label === 'Desaparecidos') return 'gone'
  return 'same'
}
</script>

<style scoped>
.history-chart { width: 100%; animation: history-chart-in 0.45s ease-in; }
.empty { padding: 2.5rem 1rem; text-align: center; color: var(--text-muted); font-size: 0.9rem; }

@keyframes history-chart-in {
  from { opacity: 0; transform: translateY(8px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.chart-svg { width: 100%; height: auto; display: block; }

.gridline { stroke: var(--border); stroke-width: 1; stroke-dasharray: 3 3; opacity: 0.5; }
.axis { stroke: var(--border-med); stroke-width: 1.5; }
.axis-label { fill: var(--text-muted); font-size: 11px; font-family: var(--font-mono); }
.axis-title { fill: var(--text-dim); font-size: 11px; font-weight: 600; }
.bar { transition: opacity 0.2s; }
.bar:hover { opacity: 0.82; }
.bar-value { fill: var(--text); font-size: 11px; font-weight: 700; font-family: var(--font-mono); }
.x-label { fill: var(--text-muted); font-size: 7.5px; }

.legend { display: flex; gap: 0.75rem; justify-content: center; margin-top: 1.1rem; flex-wrap: wrap; }
.legend-item { display: flex; flex-direction: column; align-items: center; min-width: 92px; padding: 0.6rem 0.9rem; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
.legend-value { font-size: 1.45rem; font-weight: 800; font-family: var(--font-mono); line-height: 1.1; }
.legend-label { font-size: 0.72rem; color: var(--text-dim); margin-top: 0.15rem; }
.legend-item.new .legend-value { color: var(--success); }
.legend-item.same .legend-value { color: var(--info); }
.legend-item.gone .legend-value { color: var(--danger); }
.legend-caption { text-align: center; font-size: 0.72rem; color: var(--text-muted); margin: 0.6rem 0 0; }
</style>
