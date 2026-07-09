<template>
  <div class="view-toggle" role="tablist">
    <button
      v-for="v in views" :key="v.id"
      class="view-btn" :class="{ active: modelValue === v.id }"
      role="tab" @click="$emit('update:modelValue', v.id)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path v-if="v.id === 'full'" d="M4 6h16M4 12h16M4 18h16"/>
        <path v-else-if="v.id === 'folders'" d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
        <path v-else d="M3 3v18h18M7 16l4-5 3 3 5-7"/>
      </svg>
      {{ v.label }}
    </button>
  </div>
</template>

<script setup>
defineProps({ modelValue: { type: String, required: true } })
defineEmits(['update:modelValue'])
const views = [
  { id: 'full', label: 'Vista completa' },
  { id: 'folders', label: 'Carpetas' },
  { id: 'history', label: 'Estadísticas' },
]
</script>

<style scoped>
.view-toggle { display: flex; gap: 0.5rem; margin-bottom: 1.1rem; }
.view-btn { flex: 1; display: flex; align-items: center; justify-content: center; gap: 0.4rem; padding: 0.55rem 0.85rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--text-muted); font-size: 0.82rem; font-weight: 500; cursor: pointer; transition: all 0.2s ease; }
.view-btn:hover { border-color: var(--accent); color: var(--text-dim); }
.view-btn.active { background: var(--surface-2); border-color: var(--accent); color: var(--text); font-weight: 600; }
.view-btn svg { width: 14px; height: 14px; }
</style>
