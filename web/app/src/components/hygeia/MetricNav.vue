<template>
  <!-- Barra secundaria de la pestaña Gráficas: una métrica a la vez, con el
       mismo patrón de tablist que AssetTabs (flechas, Inicio/Fin, tabindex
       dinámico). El catálogo viene de `SERIES`: una sola fuente de verdad
       para lo que se puede trazar. -->
  <div class="metric-nav" role="tablist" aria-label="Métrica a graficar" @keydown="onKeydown">
    <button
      v-for="(m, index) in options"
      :key="m.key"
      ref="tabButtons"
      class="metric-tab"
      :class="{ active: active === m.key }"
      role="tab"
      :id="`tab-metric-${m.key}`"
      :aria-controls="`panel-metric-${m.key}`"
      :aria-selected="active === m.key"
      :tabindex="active === m.key ? 0 : -1"
      @click="$emit('switch', m.key)"
    >
      {{ m.label }}
    </button>
  </div>
</template>

<script setup>
import { ref, nextTick } from 'vue'
import { SERIES } from './chartMath'

const props = defineProps({
  active: { type: String, required: true },
})
const emit = defineEmits(['switch'])

const options = SERIES.map(({ key, name }) => ({ key, label: name }))

const tabButtons = ref([])

/** Mueve el foco y la selección a la métrica de la posición dada. */
async function focusTab(index) {
  const destino = (index + options.length) % options.length
  emit('switch', options[destino].key)
  await nextTick()
  tabButtons.value[destino]?.focus()
}

function onKeydown(event) {
  const actual = options.findIndex((m) => m.key === props.active)
  const teclas = {
    ArrowRight: () => focusTab(actual + 1),
    ArrowLeft:  () => focusTab(actual - 1),
    Home:       () => focusTab(0),
    End:        () => focusTab(options.length - 1),
  }
  const accion = teclas[event.key]
  if (!accion) return
  event.preventDefault()
  accion()
}
</script>

<style scoped>
.metric-nav {
  display: flex; gap: 0.3rem;
  margin-bottom: 0.65rem;
  padding-bottom: 0.65rem;
  overflow-x: auto;
  border-bottom: 1px solid var(--border);
}
.metric-tab {
  flex-shrink: 0;
  padding: 0.32rem 0.75rem;
  background: none; border: 1px solid transparent; border-radius: 999px;
  color: var(--text-muted); font-size: var(--fs-sm); font-weight: 600; cursor: pointer;
  transition: all 0.2s ease;
}
.metric-tab:hover { color: var(--text-dim); border-color: var(--border-med); }
.metric-tab.active {
  background: var(--accent-dim); border-color: var(--accent);
  color: var(--accent-bright);
}
.metric-tab:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
</style>