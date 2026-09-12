<template>
  <Transition name="batch-slide">
  <section v-if="batch" class="batch-panel" aria-live="polite">
    <header class="batch-header">
      <div>
        <p class="batch-eyebrow">Lote #{{ batch.batchId }}</p>
        <h3 class="batch-title">
          {{ batch.total }} {{ batch.total === 1 ? 'mensaje' : 'mensajes' }} ·
          {{ finishedCount }}/{{ trackedCount }} análisis terminados
        </h3>
      </div>
      <button type="button" class="batch-close" aria-label="Cerrar el lote" @click="$emit('close')">&times;</button>
    </header>

    <p class="batch-counts">
      <span v-for="(label, status) in STATUS_LABELS" :key="status" class="count" :class="`count--${status}`">
        {{ label }}: {{ batch.counts[status] ?? 0 }}
      </span>
    </p>

    <div class="batch-table-wrap">
      <table class="batch-table">
        <thead>
          <tr><th>Mensaje</th><th>Resultado</th><th>Análisis</th></tr>
        </thead>
        <tbody>
          <tr v-for="item in batch.items" :key="item.position">
            <td class="mono">{{ item.filename }}</td>
            <td>
              <span class="count" :class="`count--${item.status}`">{{ STATUS_LABELS[item.status] }}</span>
              <span v-if="item.error" class="item-error">{{ item.error }}</span>
            </td>
            <td>
              <button v-if="item.analysisId" type="button" class="link-btn" @click="$emit('open', item.analysisId)">
                #{{ item.analysisId }} · {{ item.verdict || ANALYSIS_LABELS[item.analysisStatus] || item.analysisStatus }}
              </button>
              <span v-else class="muted">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
  </Transition>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  // Respuesta de POST /iris/analyze/batch o de GET /iris/batches/<id>.
  batch: { type: Object, default: null },
})
defineEmits(['close', 'open'])

const STATUS_LABELS = { created: 'Creado', duplicate: 'Repetido', rejected: 'Rechazado', failed: 'Fallido' }
const ANALYSIS_LABELS = { pending: 'en cola', running: 'analizando', finished: 'terminado', failed: 'falló', cancelled: 'cancelado' }
const TERMINAL = ['finished', 'failed', 'cancelled']

const tracked = computed(() => (props.batch?.items ?? []).filter(item => item.analysisId))
const trackedCount = computed(() => tracked.value.length)
const finishedCount = computed(() => tracked.value.filter(item => TERMINAL.includes(item.analysisStatus)).length)
</script>

<style scoped>
.batch-panel {
  margin: 0.75rem 1rem 0; padding: 0.9rem 1.1rem;
  border: 1px solid var(--border-med); border-radius: 12px; background: var(--surface);
}
.batch-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; }
.batch-eyebrow { margin: 0; font-size: var(--fs-xs); letter-spacing: 0.2em; text-transform: uppercase; color: var(--accent); }
.batch-title { margin: 0.15rem 0 0; font-size: var(--fs-lg); color: var(--text); }
.batch-close { border: none; background: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; }
.batch-counts { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.6rem 0; }
.count { padding: 0 0.5rem; font-size: var(--fs-xs); font-weight: 600; border-radius: 999px; background: var(--surface-2); color: var(--text-dim); }
.count--created { background: var(--success-dim); color: var(--success); }
.count--duplicate { background: var(--info-dim); color: var(--info); }
.count--rejected, .count--failed { background: var(--danger-dim); color: var(--danger); }
.batch-table-wrap { overflow-x: auto; max-height: 40vh; overflow-y: auto; }
.batch-table { width: 100%; border-collapse: collapse; font-size: var(--fs-sm); }
.batch-table th, .batch-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
.batch-table th { color: var(--text-muted); font-weight: 600; }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); overflow-wrap: anywhere; }
.item-error { display: block; margin-top: 0.2rem; color: var(--text-muted); }
.link-btn { border: none; background: none; padding: 0; color: var(--accent-bright); cursor: pointer; font-size: var(--fs-sm); }
.muted { color: var(--text-muted); }

/* El panel empuja el informe hacia abajo: entra y sale deslizándose para que
   ese salto no ocurra de golpe. */
.batch-slide-enter-active { transition: opacity 0.25s ease, transform 0.25s cubic-bezier(0.22, 1, 0.36, 1); }
.batch-slide-leave-active { transition: opacity 0.15s ease, transform 0.15s ease; }
.batch-slide-enter-from, .batch-slide-leave-to { opacity: 0; transform: translateY(-6px); }

@media (prefers-reduced-motion: reduce) {
  .batch-slide-enter-active, .batch-slide-leave-active { transition: none; }
}
</style>
