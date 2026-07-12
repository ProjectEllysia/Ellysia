<template>
  <div v-if="totalPages > 1" class="pagination">
    <button class="page-btn" :disabled="current <= 1" @click="$emit('go', current - 1)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>
    </button>
    <button
      v-for="p in visiblePages"
      :key="p"
      class="page-btn"
      :class="{ active: p === current }"
      @click="$emit('go', p)"
    >{{ p }}</button>
    <button class="page-btn" :disabled="current >= totalPages" @click="$emit('go', current + 1)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
    </button>
    <span class="page-count">{{ current }} / {{ totalPages }}</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  current: { type: Number, required: true },
  total: { type: Number, required: true },
  perPage: { type: Number, default: 15 },
})

defineEmits(['go'])

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.perPage)))

const visiblePages = computed(() => {
  const tp = totalPages.value
  const c = props.current
  const maxVisible = 5
  if (tp <= maxVisible) {
    return Array.from({ length: tp }, (_, i) => i + 1)
  }
  const half = Math.floor(maxVisible / 2)
  let start = c - half
  let end = c + half
  if (start < 1) { start = 1; end = maxVisible }
  if (end > tp) { end = tp; start = tp - maxVisible + 1 }
  return Array.from({ length: end - start + 1 }, (_, i) => start + i)
})
</script>

<style scoped>
.pagination {
  display: flex; align-items: center; gap: 0.3rem;
  margin-top: 1rem; justify-content: center;
}
.page-btn {
  width: 30px; height: 30px; display: flex; align-items: center;
  justify-content: center; border-radius: 6px;
  background: var(--surface-2); border: 1px solid var(--border);
  color: var(--text-dim); font-size: 1.37rem; font-weight: 500;
  cursor: pointer; transition: all 0.15s ease;
}
.page-btn:hover:not(:disabled):not(.active) {
  border-color: var(--accent); color: var(--accent);
}
.page-btn.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.page-btn:disabled { opacity: 0.3; cursor: default; }
.page-btn svg { width: 14px; height: 14px; }
.page-count {
  margin-left: 0.5rem; font-size: 1.26rem; color: var(--text-muted);
  font-family: var(--font-mono);
}
</style>
