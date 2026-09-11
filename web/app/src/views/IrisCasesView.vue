<template>
  <div class="cases-page" data-module="iris">
    <StarBackground />
    <Topbar title="Iris" badge="Casos" back-to="/iris/analisis" back-label="Análisis" />

    <div class="cases-layout">
      <!-- Cola de trabajo: cuántos casos hay en cada estado y cuáles. -->
      <section class="panel list-panel">
        <div class="status-pills" role="group" aria-label="Filtrar por estado">
          <button type="button" class="pill" :class="{ active: !store.cases.filters.status }" @click="setStatusFilter('')">
            Todos <span class="pill-count">{{ totalCases }}</span>
          </button>
          <button
            v-for="status in STATUSES"
            :key="status"
            type="button"
            class="pill"
            :class="{ active: store.cases.filters.status === status }"
            @click="setStatusFilter(status)"
          >
            {{ STATUS_LABELS[status] }} <span class="pill-count">{{ store.cases.countsByStatus[status] ?? 0 }}</span>
          </button>
        </div>
        <label class="mine-toggle">
          <input v-model="store.cases.filters.assignedToMe" type="checkbox" @change="store.fetchCases()" />
          Solo los asignados a mí
        </label>

        <form class="new-case" @submit.prevent="openCase">
          <input v-model="newTitle" type="text" maxlength="120" class="text-input" placeholder="Título del nuevo caso" aria-label="Título del nuevo caso" />
          <select v-model="newPriority" class="text-input" aria-label="Prioridad">
            <option v-for="priority in PRIORITIES" :key="priority" :value="priority">{{ PRIORITY_LABELS[priority] }}</option>
          </select>
          <button type="submit" class="primary-btn" :disabled="!newTitle.trim()">Abrir caso</button>
        </form>

        <p v-if="store.cases.loading && !store.cases.items.length" class="empty">Cargando…</p>
        <p v-else-if="!store.cases.items.length" class="empty">No hay casos con estos filtros.</p>
        <ul v-else class="case-list">
          <li
            v-for="entry in store.cases.items"
            :key="entry.caseId"
            class="case-row"
            :class="{ 'case-row--active': store.currentCase?.caseId === entry.caseId }"
            tabindex="0"
            @click="store.fetchCase(entry.caseId)"
            @keydown.enter="store.fetchCase(entry.caseId)"
          >
            <span class="case-title">#{{ entry.caseId }} · {{ entry.title }}</span>
            <span class="case-meta">
              <span class="chip" :class="`chip--${entry.status}`">{{ STATUS_LABELS[entry.status] }}</span>
              <span class="chip" :class="`priority--${entry.priority}`">{{ PRIORITY_LABELS[entry.priority] }}</span>
              {{ entry.analysisCount }} análisis · {{ formatDate(entry.updatedAt) }}
            </span>
          </li>
        </ul>
      </section>

      <!-- Detalle del caso seleccionado. -->
      <section class="panel detail-panel">
        <p v-if="!detail" class="empty">Elige un caso para ver sus análisis, su estado y su timeline.</p>
        <template v-else>
          <header class="detail-header">
            <h2 class="detail-title">#{{ detail.caseId }} · {{ detail.title }}</h2>
            <span class="chip" :class="`chip--${detail.status}`">{{ STATUS_LABELS[detail.status] }}</span>
          </header>
          <p v-if="detail.resolutionReason" class="resolution">Cerrado: «{{ detail.resolutionReason }}» · {{ formatDate(detail.closedAt) }}</p>

          <div class="controls">
            <label class="control">
              <span class="control-label">Prioridad</span>
              <select class="text-input" :value="detail.priority" @change="store.updateCase(detail.caseId, { priority: $event.target.value })">
                <option v-for="priority in PRIORITIES" :key="priority" :value="priority">{{ PRIORITY_LABELS[priority] }}</option>
              </select>
            </label>
            <div class="control">
              <span class="control-label">Asignado</span>
              <button v-if="detail.assigneeId" type="button" class="ghost-btn" @click="store.updateCase(detail.caseId, { assigneeId: null })">
                {{ detail.assignee }} · quitar
              </button>
              <!-- Solo el dueño ve el caso, así que asignárselo a uno mismo es
                   asignarlo a su dueño. -->
              <button v-else type="button" class="ghost-btn" @click="store.updateCase(detail.caseId, { assigneeId: detail.ownerId })">Asignármelo</button>
            </div>
            <label class="control control--grow">
              <span class="control-label">Etiquetas (separadas por comas)</span>
              <input
                class="text-input"
                :value="detail.tags.join(', ')"
                @change="store.updateCase(detail.caseId, { tags: $event.target.value.split(',') })"
              />
            </label>
          </div>

          <div class="transitions">
            <span class="control-label">Mover a</span>
            <button
              v-for="status in STATUSES.filter(candidate => candidate !== detail.status)"
              :key="status"
              type="button"
              class="ghost-btn"
              @click="requestStatus(status)"
            >{{ STATUS_LABELS[status] }}</button>
          </div>
          <form v-if="pendingClose" class="close-form" @submit.prevent="confirmClose">
            <textarea v-model="closeReason" class="text-input" rows="2" maxlength="4000"
              :placeholder="`Por qué se cierra como «${STATUS_LABELS[pendingClose]}» (obligatorio)`"></textarea>
            <button type="submit" class="primary-btn" :disabled="!closeReason.trim()">Cerrar caso</button>
            <button type="button" class="ghost-btn" @click="pendingClose = null">Cancelar</button>
          </form>

          <h3 class="section-title">Análisis ({{ detail.analyses.length }})</h3>
          <ul class="analysis-list">
            <li v-for="analysis in detail.analyses" :key="analysis.analysisId" class="analysis-row">
              <button type="button" class="link-btn" @click="openAnalysis(analysis.analysisId)">
                #{{ analysis.analysisId }} · {{ analysis.title || '(sin título)' }}
              </button>
              <span class="case-meta">{{ analysis.verdict || analysis.status }} · {{ analysis.totalScore ?? '—' }}</span>
              <button type="button" class="ghost-btn ghost-btn--small" @click="store.unlinkCaseAnalysis(detail.caseId, analysis.analysisId)">Quitar</button>
            </li>
          </ul>
          <form class="inline-form" @submit.prevent="linkAnalysis">
            <input v-model.number="analysisToLink" type="number" min="1" class="text-input" placeholder="Id de análisis" aria-label="Id del análisis a añadir" />
            <button type="submit" class="ghost-btn" :disabled="!analysisToLink">Añadir análisis</button>
          </form>

          <h3 class="section-title">Timeline</h3>
          <form class="inline-form" @submit.prevent="addNote">
            <textarea v-model="note" class="text-input" rows="2" maxlength="4000" placeholder="Añadir una nota"></textarea>
            <button type="submit" class="primary-btn" :disabled="!note.trim()">Anotar</button>
          </form>
          <ol class="timeline">
            <li v-for="event in [...detail.timeline].reverse()" :key="event.eventId" class="timeline-item">
              <span class="timeline-when">{{ formatDate(event.createdAt) }} · {{ event.actor || '—' }}</span>
              <span class="timeline-what">{{ describeEvent(event) }}</span>
            </li>
          </ol>
        </template>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useIrisStore } from '@/stores/irisStore'
import { useUtils } from '@/composables/useUtils'

const store = useIrisStore()
const router = useRouter()
const { formatDate } = useUtils()

const STATUSES = ['new', 'triage', 'contained', 'resolved', 'false_positive']
const CLOSED = ['resolved', 'false_positive']
const STATUS_LABELS = { new: 'Nuevo', triage: 'En triaje', contained: 'Contenido', resolved: 'Resuelto', false_positive: 'Falso positivo' }
const PRIORITIES = ['low', 'medium', 'high', 'critical']
const PRIORITY_LABELS = { low: 'Baja', medium: 'Media', high: 'Alta', critical: 'Crítica' }

const newTitle = ref('')
const newPriority = ref('medium')
const note = ref('')
const analysisToLink = ref(null)
const pendingClose = ref(null)
const closeReason = ref('')

const detail = computed(() => store.currentCase)
const totalCases = computed(() => Object.values(store.cases.countsByStatus).reduce((sum, count) => sum + count, 0))

function setStatusFilter(status) {
  store.cases.filters.status = status
  store.fetchCases()
}

async function openCase() {
  const created = await store.createCase({ title: newTitle.value.trim(), priority: newPriority.value })
  if (created) newTitle.value = ''
}

// Cerrar pide la razón antes de enviar; el resto de transiciones van directas
// y, si no están permitidas, el servidor explica por qué.
function requestStatus(status) {
  if (CLOSED.includes(status)) {
    pendingClose.value = status
    closeReason.value = ''
    return
  }
  pendingClose.value = null
  store.changeCaseStatus(detail.value.caseId, status)
}

async function confirmClose() {
  const updated = await store.changeCaseStatus(detail.value.caseId, pendingClose.value, closeReason.value.trim())
  if (updated) pendingClose.value = null
}

async function addNote() {
  const updated = await store.addCaseNote(detail.value.caseId, note.value.trim())
  if (updated) note.value = ''
}

async function linkAnalysis() {
  const updated = await store.linkCaseAnalysis(detail.value.caseId, analysisToLink.value)
  if (updated) analysisToLink.value = null
}

function openAnalysis(analysisId) {
  store.selectAnalysis(analysisId)
  router.push('/iris/analisis')
}

const EVENT_LABELS = {
  created: 'Caso abierto',
  status_changed: 'Cambio de estado',
  priority_changed: 'Cambio de prioridad',
  assigned: 'Cambio de asignación',
  title_changed: 'Cambio de título',
  tags_changed: 'Cambio de etiquetas',
  note: 'Nota',
  analysis_linked: 'Análisis añadido',
  analysis_unlinked: 'Análisis quitado',
}

/** Frase de una entrada de la timeline a partir de su tipo y su detalle. */
function describeEvent(event) {
  const detailData = event.detail ?? {}
  if (event.kind === 'note') return `Nota: ${event.note}`
  if (event.kind === 'status_changed') {
    const reason = detailData.reason ? ` — «${detailData.reason}»` : ''
    return `${STATUS_LABELS[detailData.from] ?? detailData.from} → ${STATUS_LABELS[detailData.to] ?? detailData.to}${reason}`
  }
  if (event.kind === 'priority_changed') return `Prioridad: ${PRIORITY_LABELS[detailData.from]} → ${PRIORITY_LABELS[detailData.to]}`
  if (event.kind === 'analysis_linked' || event.kind === 'analysis_unlinked') {
    return `${EVENT_LABELS[event.kind]}: #${detailData.analysisId}`
  }
  if (event.kind === 'created' && detailData.analysisIds?.length) {
    return `Caso abierto con ${detailData.analysisIds.length} análisis`
  }
  return EVENT_LABELS[event.kind] ?? event.kind
}

onMounted(() => store.fetchCases())
</script>

<style scoped>
.cases-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.cases-layout {
  position: relative; z-index: 1;
  max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem;
  display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 3fr); gap: 1.25rem; align-items: start;
}
.panel { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); padding: 1.1rem 1.25rem; min-width: 0; }
.status-pills { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.pill {
  padding: 0.25rem 0.65rem; font-size: var(--fs-sm); border-radius: 999px; cursor: pointer;
  border: 1px solid var(--border-med); background: transparent; color: var(--text-dim);
}
.pill.active { border-color: var(--accent); color: var(--accent-bright); background: var(--accent-dim); }
.pill-count { margin-left: 0.2rem; font-weight: 700; }
.mine-toggle { display: flex; align-items: center; gap: 0.4rem; margin: 0.7rem 0; font-size: var(--fs-sm); color: var(--text-dim); }
.new-case, .inline-form, .close-form { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.6rem 0; }
.new-case .text-input:first-child, .inline-form textarea, .close-form textarea { flex: 1; min-width: 10rem; }
.text-input {
  padding: 0.4rem 0.55rem; font-size: var(--fs-sm);
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border-med); border-radius: 6px;
}
.primary-btn, .ghost-btn { padding: 0.35rem 0.8rem; font-size: var(--fs-sm); font-weight: 600; border-radius: 6px; cursor: pointer; }
.primary-btn { border: none; background: var(--accent); color: var(--on-accent); }
.primary-btn:disabled, .ghost-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.ghost-btn { border: 1px solid var(--border-med); background: transparent; color: var(--text-dim); }
.ghost-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent-bright); }
.ghost-btn--small { padding: 0.15rem 0.5rem; font-weight: 500; }
.empty { color: var(--text-muted); font-size: var(--fs-md); }
.case-list, .analysis-list, .timeline { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
.case-row { padding: 0.55rem 0.7rem; border: 1px solid var(--border); border-radius: 8px; cursor: pointer; display: flex; flex-direction: column; gap: 0.2rem; }
.case-row:hover, .case-row:focus-visible { border-color: var(--border-med); background: var(--surface-2); outline: none; }
.case-row--active { border-color: var(--accent); background: var(--accent-dim); }
.case-title { font-weight: 600; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.case-meta { font-size: var(--fs-sm); color: var(--text-muted); display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; }
.chip { padding: 0 0.45rem; font-size: var(--fs-xs); font-weight: 600; border-radius: 999px; text-transform: uppercase; background: var(--surface-2); color: var(--text-dim); }
.chip--new { background: var(--info-dim); color: var(--info); }
.chip--triage { background: var(--warn-dim); color: var(--warn); }
.chip--contained { background: var(--accent-dim); color: var(--accent-bright); }
.chip--resolved { background: var(--success-dim); color: var(--success); }
.priority--high, .priority--critical { background: var(--danger-dim); color: var(--danger); }
.detail-header { display: flex; align-items: center; gap: 0.6rem; }
.detail-title { margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-xl); color: var(--text); }
.resolution { margin: 0.4rem 0 0; font-size: var(--fs-sm); color: var(--text-dim); }
.controls { display: flex; flex-wrap: wrap; gap: 0.8rem; margin: 0.9rem 0 0.6rem; }
.control { display: flex; flex-direction: column; gap: 0.25rem; }
.control--grow { flex: 1; min-width: 12rem; }
.control-label { font-size: var(--fs-xs); letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted); }
.transitions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; }
.section-title { margin: 1.1rem 0 0.5rem; font-size: var(--fs-md); color: var(--text); }
.analysis-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.link-btn { border: none; background: none; padding: 0; color: var(--accent-bright); cursor: pointer; font-size: var(--fs-md); text-align: left; }
.timeline-item { display: flex; flex-direction: column; padding-left: 0.7rem; border-left: 2px solid var(--border-med); }
.timeline-when { font-size: var(--fs-xs); color: var(--text-muted); }
.timeline-what { font-size: var(--fs-sm); color: var(--text-dim); overflow-wrap: anywhere; }
@media (max-width: 900px) { .cases-layout { grid-template-columns: 1fr; } }
</style>
