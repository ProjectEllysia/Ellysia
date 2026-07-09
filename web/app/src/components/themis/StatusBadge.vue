<template>
  <span class="badge" :class="'badge--' + classMap">{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ status: { type: String, required: true } })
const MAP = {
  running: ['running', 'Ejecutando'],
  done: ['done', 'Completado'],
  finished: ['done', 'Completado'],
  pending: ['pending', 'Pendiente'],
  error: ['error', 'Error'],
  cancelled: ['cancelled', 'Cancelado'],
}
const classMap = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending'])[0])
const label = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending', props.status ?? '—'])[1])
</script>

<style scoped>
.badge { transition: background-color 0.3s ease, color 0.3s ease; }
@media (prefers-reduced-motion: reduce) {
  .badge { transition: none; }
}
</style>
