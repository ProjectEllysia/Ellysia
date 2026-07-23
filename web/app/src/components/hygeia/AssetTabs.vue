<template>
  <div class="tabs" role="tablist">
    <button v-for="tab in tabs" :key="tab.id"
      class="tab" :class="{ active: active === tab.id }"
      role="tab" :title="tab.hint" @click="$emit('switch', tab.id)">
      {{ tab.label }}
      <span v-if="tab.id === 'anomalias' && anomalyCount" class="tab-badge">{{ anomalyCount }}</span>
      <span
        v-else-if="tab.id === 'estadisticas' && statsWarning"
        class="tab-dot"
        title="Hay lecturas (disco o CPU) por encima del umbral"
      ></span>
    </button>
  </div>
</template>

<script setup>
defineProps({
  active: { type: String, required: true },
  anomalyCount: { type: Number, default: 0 },
  statsWarning: { type: Boolean, default: false },
})
defineEmits(['switch'])

const tabs = [
  { id: 'graficas', label: 'Gráficas', hint: 'Atajo: 1' },
  { id: 'estadisticas', label: 'Estadísticas', hint: 'Atajo: 2' },
  { id: 'anomalias', label: 'Anomalías', hint: 'Atajo: 3' },
]
</script>

<style scoped>
.tabs {
  display: flex; gap: 0.2rem;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 0.25rem;
}
.tab {
  flex: 1; padding: 0.5rem 0.85rem;
  background: none; border: none; border-radius: 6px;
  color: var(--text-muted); font-size: var(--fs-lg); font-weight: 500; cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 0.4rem;
  transition: all 0.2s ease;
}
.tab:hover { color: var(--text-dim); }
.tab.active { background: var(--surface-2); color: var(--text); font-weight: 600; }

.tab-badge {
  padding: 0.05rem 0.45rem; border-radius: 999px;
  background: var(--danger-dim); color: var(--danger);
  font-size: var(--fs-sm); font-weight: 700; letter-spacing: 0;
}

/* Aviso discreto (no es una anomalía registrada, solo una lectura puntual
   por encima del umbral) — por eso un punto en vez de una insignia roja. */
.tab-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--warn); flex-shrink: 0; }
</style>
