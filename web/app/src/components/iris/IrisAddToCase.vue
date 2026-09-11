<template>
  <div class="add-to-case">
    <button v-if="!open" type="button" class="feedback-option" @click="openPicker">Añadir a un caso…</button>
    <form v-else class="case-picker" @submit.prevent="submit">
      <select v-model="target" class="case-select" aria-label="Caso de destino">
        <option value="new">Nuevo caso con este análisis</option>
        <option v-for="entry in openCases" :key="entry.caseId" :value="entry.caseId">
          #{{ entry.caseId }} · {{ entry.title }} ({{ STATUS_LABELS[entry.status] }})
        </option>
      </select>
      <button type="submit" class="case-save" :disabled="saving">{{ saving ? 'Guardando…' : 'Añadir' }}</button>
      <button type="button" class="case-cancel" @click="open = false">Cancelar</button>
      <router-link v-if="lastCaseId" to="/iris/casos" class="case-link">Ver el caso #{{ lastCaseId }}</router-link>
    </form>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useIrisStore } from '@/stores/irisStore'

const props = defineProps({
  analysisId: { type: Number, required: true },
  analysisTitle: { type: String, default: '' },
})

const store = useIrisStore()
const STATUS_LABELS = { new: 'nuevo', triage: 'en triaje', contained: 'contenido', resolved: 'resuelto', false_positive: 'falso positivo' }
const CLOSED = ['resolved', 'false_positive']

const open = ref(false)
const target = ref('new')
const saving = ref(false)
const lastCaseId = ref(null)

// Solo los casos abiertos: añadir evidencia a uno cerrado es reabrirlo, y eso
// se hace desde la vista de casos, con su razón.
const openCases = computed(() => store.cases.items.filter(entry => !CLOSED.includes(entry.status)))

watch(() => props.analysisId, () => { open.value = false; lastCaseId.value = null })

async function openPicker() {
  open.value = true
  target.value = 'new'
  await store.fetchCases()
}

async function submit() {
  saving.value = true
  const result = target.value === 'new'
    ? await store.createCase({ title: props.analysisTitle || `Análisis #${props.analysisId}`, analysisIds: [props.analysisId] })
    : await store.linkCaseAnalysis(target.value, props.analysisId)
  saving.value = false
  if (result) lastCaseId.value = result.caseId
}
</script>

<style scoped>
.add-to-case { margin-top: 0.6rem; }
.case-picker { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; }
.case-select {
  min-width: 14rem; padding: 0.35rem 0.5rem; font-size: var(--fs-sm);
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border-med); border-radius: 6px;
}
.case-save, .case-cancel { padding: 0.35rem 0.8rem; font-size: var(--fs-sm); font-weight: 600; border-radius: 6px; cursor: pointer; }
.case-save { border: none; background: var(--accent); color: var(--on-accent); }
.case-save:disabled { opacity: 0.5; cursor: not-allowed; }
.case-cancel { border: 1px solid var(--border-med); background: transparent; color: var(--text-dim); }
.case-link { font-size: var(--fs-sm); color: var(--accent-bright); text-decoration: underline; }
</style>
