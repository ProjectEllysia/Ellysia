<template>
  <div class="history-panel">
    <div class="panel-head">
      <div>
        <h2 class="panel-title">Estadísticas históricas</h2>
        <p class="panel-sub">Evolución de tus escaneos a lo largo del tiempo, por host.</p>
      </div>
      <button class="refresh-btn" :disabled="store.history.loading" @click="store.loadHistoryHosts({ force: true })">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        Actualizar
      </button>
    </div>

    <div v-if="store.history.loading" class="state">Cargando hosts…</div>

    <div v-else-if="!store.history.hosts.length" class="state">
      Todavía no has completado ningún escaneo. Lanza un escaneo para ver su historial aquí.
    </div>

    <template v-else>
      <div class="selector">
        <label for="history-host">Selecciona un host escaneado</label>
        <select id="history-host" :value="selectedKey" @change="onSelect">
          <option value="" disabled>-- Elige un host --</option>
          <optgroup v-for="group in groupedHosts" :key="group.type" :label="group.label">
            <option v-for="h in group.hosts" :key="`${h.scanType}|${h.target}`" :value="`${h.scanType}|${h.target}`">
              {{ h.target }} · {{ h.scanCount }} escaneo{{ h.scanCount === 1 ? '' : 's' }}
            </option>
          </optgroup>
        </select>
      </div>

      <div class="chart-area">
        <div v-if="store.history.chartLoading" class="state">Generando estadísticas…</div>
        <HistoryChart v-else-if="store.history.chart" :chart="store.history.chart" />
        <div v-else class="state hint">Selecciona un host para ver su gráfico.</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useThemisHistoryStore } from '@/stores/themisHistoryStore'
import HistoryChart from '@/components/themis/HistoryChart.vue'
import { SCAN_TYPES, SCAN_TYPE_ORDER } from '@/constants/scanTypes'

const store = useThemisHistoryStore()

const selectedKey = computed(() => {
  const s = store.history.selected
  return s ? `${s.scanType}|${s.target}` : ''
})

const groupedHosts = computed(() => {
  const byType = {}
  for (const h of store.history.hosts) {
    (byType[h.scanType] ??= []).push(h)
  }
  return SCAN_TYPE_ORDER
    .filter(type => byType[type]?.length)
    .map(type => ({ type, label: SCAN_TYPES[type]?.fullLabel ?? type, hosts: byType[type] }))
})

function onSelect(event) {
  const value = event.target.value
  if (!value) return
  const [type, target] = value.split('|')
  store.loadHistoryStats(target, type)
}
</script>

<style scoped>
.history-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }
.panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1.1rem; }
.panel-title { font-size: var(--fs-lg); font-weight: 700; color: var(--text); margin: 0; }
.panel-sub { font-size: var(--fs-lg); color: var(--text-muted); margin: 0.2rem 0 0; }

.refresh-btn { display: flex; align-items: center; gap: 0.35rem; padding: 0.45rem 0.8rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; color: var(--text-dim); font-size: var(--fs-lg); cursor: pointer; transition: all 0.2s; white-space: nowrap; }
.refresh-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--text); }
.refresh-btn:disabled { opacity: 0.5; cursor: default; }
.refresh-btn svg { width: 13px; height: 13px; }

.selector { margin-bottom: 1.25rem; }
.selector label { display: block; margin-bottom: 0.4rem; font-size: var(--fs-lg); color: var(--text-dim); }
.selector select { width: 100%; padding: 0.55rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: var(--fs-input); }
.selector select:focus { outline: none; border-color: var(--accent); }

.chart-area { min-height: 120px; }
.state { padding: 2rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-lg); }
.state.hint { color: var(--text-dim); }
</style>
