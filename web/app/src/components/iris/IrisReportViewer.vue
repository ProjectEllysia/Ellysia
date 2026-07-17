<template>
  <div class="report-viewer">

    <!-- EMPTY -- no selection, show form -->
    <div v-if="!reportId && !reportData && !reportLoading" class="rv-empty">
      <slot name="form" />
    </div>

    <!-- LOADING -->
    <div v-else-if="reportLoading" class="rv-loading">
      <div class="spinner"></div>
      <p>Cargando informe…</p>
    </div>

    <!-- RUNNING / PENDING -->
    <div v-else-if="status && (status === 'pending' || status === 'running')" class="rv-running">
      <div class="rv-running-header">
        <span class="badge badge--running">En análisis</span>
        <span class="analysis-id">#{{ reportId }}</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" :style="{ width: (progress ?? 0) + '%' }"></div>
      </div>
      <div class="progress-label">{{ progress ?? 0 }}% — ejecutando reglas de verificación</div>
      <button type="button" class="btn-cancel" @click="$emit('cancel')">
        Cancelar análisis
      </button>
    </div>

    <!-- FAILED -->
    <div v-else-if="reportData && reportData.status === 'failed'" class="rv-failed">
      <div class="rv-result-icon rv-result-icon--fail">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
      </div>
      <h3>Análisis fallido</h3>
      <p>El análisis #{{ reportId }} no pudo completarse. Intenta de nuevo.</p>
    </div>

    <!-- CANCELLED -->
    <div v-else-if="reportData && reportData.status === 'cancelled'" class="rv-cancelled">
      <div class="rv-result-icon rv-result-icon--warn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
      </div>
      <h3>Análisis cancelado</h3>
      <p>El análisis #{{ reportId }} fue cancelado por el usuario.</p>
    </div>

    <!-- FINISHED REPORT -->
    <div v-else-if="reportData && reportData.status === 'finished'" class="rv-report">
      <div class="rv-report-header">
        <div class="rv-report-id">
          <span v-if="reportData.title" class="report-title">{{ reportData.title }}</span>
          <span class="analysis-id">#{{ reportData.analysisId }}</span>
          <span class="report-date" v-if="reportData.finishedAt">{{ formatDate(reportData.finishedAt) }}</span>
        </div>
        <div class="rv-actions">
          <button type="button" class="action-btn" title="Informes PDF" @click="docsModalOpen = true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/><line x1="9" y1="11" x2="13" y2="11"/></svg>
            <span v-if="irisStore.documents.length" class="action-btn-badge">{{ irisStore.documents.length }}</span>
          </button>
          <button type="button" class="action-btn" title="Cancelar" @click="$emit('cancel')" v-if="status === 'running' || status === 'pending'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          </button>
          <button type="button" class="action-btn" title="Reanalizar con las reglas actuales" @click="irisStore.reanalyzeAnalysis(reportData.analysisId)" v-if="reportData && reportData.status === 'finished'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-3.51-7.14"/><polyline points="21 3 21 9 15 9"/></svg>
          </button>
          <button type="button" class="action-btn action-btn--danger" title="Eliminar" @click="$emit('delete', reportData.analysisId)" v-if="reportData && reportData.status !== 'running' && reportData.status !== 'pending'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
          </button>
        </div>
      </div>

      <!-- Aviso: el mensaje enviado era un reenvío que envolvía el correo -->
      <!-- original como adjunto .eml; se analizó el interno, no el envoltorio -->
      <div v-if="reportData.unwrappedFromForward" class="rv-unwrap-notice">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="unwrap-icon"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 7l-10 6L2 7"/></svg>
        <div class="unwrap-text">
          <strong>Correo reenviado como adjunto detectado.</strong>
          Se analizó el mensaje original adjunto (.eml), no el envoltorio del reenvío.
          <span v-if="reportData.wrapperFrom || reportData.wrapperSubject" class="unwrap-wrapper-info">
            Envoltorio: <template v-if="reportData.wrapperFrom">de {{ reportData.wrapperFrom }}</template>
            <template v-if="reportData.wrapperSubject">— «{{ reportData.wrapperSubject }}»</template>
          </span>
        </div>
      </div>

      <!-- Score + Verdict hero -->
      <div class="rv-hero" :class="`rv-hero--${verdictClass}`">
        <div class="rv-hero-score">
          <span class="score-num">{{ reportData.totalScore }}</span>
          <span class="score-unit">/ máx</span>
        </div>
        <div class="rv-hero-verdict">
          <span class="verdict-badge" :class="`verdict--${verdictClass}`">{{ reportData.verdict }}</span>
          <span class="verdict-status">{{ statusLabel }}</span>
        </div>
      </div>

      <!-- Gate reasons: señales de alta confianza que fijaron el veredicto -->
      <div v-if="reportData.gateReasons && reportData.gateReasons.length" class="rv-gates">
        <h3 class="section-title">Por qué este veredicto</h3>
        <ul class="gate-list">
          <li v-for="(reason, i) in reportData.gateReasons" :key="i" class="gate-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="gate-bullet"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {{ reason }}
          </li>
        </ul>
      </div>

      <!-- Top signals: reglas que más penalizaron el score -->
      <div v-if="reportData.topSignals && reportData.topSignals.length" class="rv-top-signals">
        <h3 class="section-title">Principales señales</h3>
        <div class="signal-list">
          <button
            type="button"
            v-for="signal in reportData.topSignals"
            :key="signal.index"
            class="signal-chip"
            @click="jumpToRule(signal.index)"
          >
            <span class="signal-name">{{ signal.ruleName }}</span>
            <span class="signal-score">{{ signal.score }}</span>
          </button>
        </div>
      </div>

      <!-- Resumen ejecutivo IA (IA1) -->
      <div v-if="reportData.status === 'finished'" class="rv-ai-summary">
        <h3 class="section-title">Resumen ejecutivo (IA)</h3>
        <div v-if="reportData.aiSummary" class="ai-summary-card">
          <p class="ai-summary-text">{{ reportData.aiSummary.executive_summary }}</p>
          <div class="ai-summary-row">
            <span class="ai-summary-label">Intención probable del atacante</span>
            <p class="ai-summary-text">{{ reportData.aiSummary.attacker_intent }}</p>
          </div>
          <ul v-if="reportData.aiSummary.recommendations && reportData.aiSummary.recommendations.length" class="ai-summary-recs">
            <li v-for="(rec, i) in reportData.aiSummary.recommendations" :key="i">{{ rec }}</li>
          </ul>
          <span class="ai-summary-confidence" :class="`confidence--${(reportData.aiSummary.confidence || '').toLowerCase()}`">
            Confianza: {{ reportData.aiSummary.confidence }}
          </span>
        </div>
        <div v-else-if="irisStore.aiSummaryLoading" class="rv-path-loading">
          <div class="spinner spinner--sm"></div>
          <span>Generando narrativa con IA…</span>
          <button type="button" class="btn-export-csv" @click="irisStore.checkAiSummary(reportData.analysisId)">
            Comprobar estado
          </button>
        </div>
        <button v-else type="button" class="btn-export-csv" @click="irisStore.generateAiSummary(reportData.analysisId)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l2.4 7.2H22l-6 4.4 2.4 7.2L12 16.4l-6.4 4.4 2.4-7.2-6-4.4h7.6z"/></svg>
          Generar resumen ejecutivo con IA
        </button>
      </div>

      <!-- Rule cards -->
      <div class="rv-rules" ref="rulesSection">
        <h3 class="section-title" v-if="flaggedRules.length">Reglas con hallazgos</h3>
        <IrisRuleCard
          v-for="entry in flaggedRules"
          :key="entry.i"
          :ref="el => setRuleCardRef(el, entry.i)"
          :rule="entry.rule"
          :expanded="expandedRule === entry.i"
          @toggle="toggleRule(entry.i)"
        />

        <!-- Reglas superadas (pass), plegadas por defecto para no alargar el scroll -->
        <div v-if="passedRules.length" class="rv-raw">
          <button type="button" class="raw-toggle" @click="passedRulesOpen = !passedRulesOpen">
            <svg :class="{ rotated: passedRulesOpen }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toggle-chevron"><polyline points="6 9 12 15 18 9"/></svg>
            Reglas superadas sin incidencias ({{ passedRules.length }})
          </button>
          <Transition name="raw-reveal">
            <div v-if="passedRulesOpen">
              <IrisRuleCard
                v-for="entry in passedRules"
                :key="entry.i"
                :ref="el => setRuleCardRef(el, entry.i)"
                :rule="entry.rule"
                :expanded="expandedRule === entry.i"
                @toggle="toggleRule(entry.i)"
              />
            </div>
          </Transition>
        </div>
      </div>

      <!-- Recommendations -->
      <div v-if="reportData.recommendations && reportData.recommendations.length" class="rv-recommendations">
        <h3 class="section-title">Recomendaciones</h3>
        <ul class="rec-list">
          <li v-for="(rec, i) in visibleRecommendations" :key="i" class="rec-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="rec-bullet"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            {{ rec }}
          </li>
        </ul>
        <button
          v-if="reportData.recommendations.length > RECS_PREVIEW_COUNT"
          type="button"
          class="raw-toggle"
          @click="recsExpanded = !recsExpanded"
        >
          <svg :class="{ rotated: recsExpanded }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toggle-chevron"><polyline points="6 9 12 15 18 9"/></svg>
          {{ recsExpanded ? 'Mostrar menos' : `Mostrar ${reportData.recommendations.length - RECS_PREVIEW_COUNT} más` }}
        </button>
      </div>

      <!-- Email path (Received chain) -->
      <div v-if="pathVisible" class="rv-path">
        <h3 class="section-title">Recorrido del correo</h3>
        <div v-if="pathLoading" class="rv-path-loading">
          <div class="spinner spinner--sm"></div>
          <span>Cargando recorrido…</span>
        </div>
        <IrisEmailPath
          v-else-if="pathData && pathData.available"
          :hops="pathData.hops"
          :transitions="pathData.transitions"
        />
        <p v-else class="rv-path-empty">
          {{ pathData?.reason || 'Recorrido no disponible para este análisis.' }}
        </p>
      </div>

      <!-- IOCs (collapsible, cargados bajo demanda) -->
      <div v-if="reportData.status === 'finished'" class="rv-raw">
        <button type="button" class="raw-toggle" @click="toggleIocs">
          <svg :class="{ rotated: iocsOpen }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toggle-chevron"><polyline points="6 9 12 15 18 9"/></svg>
          Indicadores de compromiso (IOCs)
        </button>
        <Transition name="raw-reveal">
          <div v-if="iocsOpen" class="ioc-panel">
            <div v-if="iocsLoading" class="rv-path-loading">
              <div class="spinner spinner--sm"></div>
              <span>Extrayendo IOCs…</span>
            </div>
            <template v-else-if="iocsData">
              <p class="ioc-hint">
                Valores <em>defanged</em> para pegar de forma segura sin activar enlaces.
              </p>
              <div v-for="cat in iocCategories" :key="cat.key" class="ioc-category">
                <div class="ioc-category-header">
                  <span class="ioc-category-title">{{ cat.label }} ({{ iocsData[cat.key].length }})</span>
                </div>
                <ul v-if="iocsData[cat.key].length" class="ioc-list">
                  <li v-for="(val, i) in iocsData[cat.key]" :key="i" class="ioc-item">{{ defang(val) }}</li>
                </ul>
                <p v-else class="ioc-empty">Ninguno detectado.</p>
              </div>
              <button type="button" class="btn-export-csv" @click="exportIocsCsv">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Exportar CSV
              </button>
            </template>
            <p v-else class="rv-path-empty">No se pudieron cargar los IOCs.</p>
          </div>
        </Transition>
      </div>

      <!-- Raw headers (collapsible) -->
      <div class="rv-raw">
        <button type="button" class="raw-toggle" @click="rawOpen = !rawOpen">
          <svg :class="{ rotated: rawOpen }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toggle-chevron"><polyline points="6 9 12 15 18 9"/></svg>
          Cabeceras originales
        </button>
        <Transition name="raw-reveal">
          <pre v-if="rawOpen" class="raw-block">{{ reportData.rawHeaders }}</pre>
        </Transition>
      </div>

    </div>

    <!-- Informes PDF (modal, fuera del flujo de scroll del informe) -->
    <IrisDocumentsModal
      :show="docsModalOpen"
      :documents="irisStore.documents"
      :loading="irisStore.documentsLoading"
      :generating="generatingDocument"
      :can-generate="reportData?.status === 'finished'"
      @close="docsModalOpen = false"
      @refresh="refreshDocuments"
      @generate="handleGenerateDocument"
      @download="handleDownloadDocument"
      @delete="handleDeleteDocument"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import { useUtils } from '@/composables/useUtils'
import { useIrisStore } from '@/stores/irisStore'
import IrisEmailPath from '@/components/iris/IrisEmailPath.vue'
import IrisDocumentsModal from '@/components/iris/IrisDocumentsModal.vue'
import IrisRuleCard from '@/components/iris/IrisRuleCard.vue'

const { formatDate } = useUtils()
const irisStore = useIrisStore()

const props = defineProps({
  reportId: { type: [Number, null], default: null },
  reportData: { type: [Object, null], default: null },
  reportLoading: { type: Boolean, default: false },
  status: { type: [String, null], default: null },
  progress: { type: [Number, null], default: null },
})

defineEmits(['cancel', 'delete'])

const expandedRule = ref(null)
const rawOpen = ref(false)
let ruleCardEls = []

function toggleRule(i) {
  expandedRule.value = expandedRule.value === i ? null : i
}

function setRuleCardRef(el, i) {
  if (el) ruleCardEls[i] = el.$el ?? el
}

// Agrupamos las reglas por veredicto para no obligar a un scroll larguísimo:
// las que dieron 'pass' (la mayoría en un análisis típico) se pliegan detrás
// de un desplegable y solo las que tienen hallazgos quedan siempre visibles.
// Conservamos el índice original porque topSignals[].index y jumpToRule(i)
// referencian la posición dentro de reportData.rules.
const rulesWithIndex = computed(() =>
  (props.reportData?.rules ?? []).map((rule, i) => ({ rule, i }))
)
const flaggedRules = computed(() => rulesWithIndex.value.filter(entry => entry.rule.verdict !== 'pass'))
const passedRules = computed(() => rulesWithIndex.value.filter(entry => entry.rule.verdict === 'pass'))
const passedRulesOpen = ref(false)

// Salta a la card de la regla señalada en "Principales señales", la expande
// y la desplaza a la vista (llamado desde los chips de topSignals). Si la
// regla vive en el grupo plegado de "superadas", lo abrimos primero.
async function jumpToRule(i) {
  expandedRule.value = i
  if (props.reportData?.rules?.[i]?.verdict === 'pass' && !passedRulesOpen.value) {
    passedRulesOpen.value = true
    await nextTick()
  }
  ruleCardEls[i]?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

const verdictClass = computed(() => {
  const v = props.reportData?.verdict?.toLowerCase() ?? ''
  if (v === 'legitimate') return 'legit'
  if (v === 'suspicious') return 'susp'
  if (v === 'phishing') return 'phish'
  return 'unknown'
})

const statusLabel = computed(() => {
  const v = props.reportData?.verdict?.toLowerCase() ?? ''
  if (v === 'legitimate') return 'Correo verificado'
  if (v === 'suspicious') return 'Posible amenaza'
  if (v === 'phishing') return 'Phishing detectado'
  return ''
})

const pathData = computed(() => {
  if (!props.reportId) return null
  const cached = irisStore.pathCache.get(props.reportId)
  if (cached) return cached
  return irisStore.currentPath?.data?.analysisId === props.reportId
    ? irisStore.currentPath.data
    : null
})
const pathLoading = computed(() => {
  if (!props.reportId) return false
  return irisStore.currentPath?.loading && irisStore.currentPath?.data?.analysisId !== props.reportId
})
const pathVisible = computed(() => {
  return props.reportData?.status === 'finished' && !!props.reportId && (
    pathData.value || pathLoading.value
  )
})

/* ── IOCs (O1: export, O2: defanged rendering) ── */
const iocsOpen = ref(false)
const iocCategories = [
  { key: 'domains', label: 'Dominios' },
  { key: 'urls', label: 'URLs' },
  { key: 'ips', label: 'IPs' },
  { key: 'emails', label: 'Emails' },
  { key: 'hashes', label: 'Hashes (SHA256)' },
]

const iocsData = computed(() => {
  if (!props.reportId) return null
  const cached = irisStore.iocsCache.get(props.reportId)
  if (cached) return cached
  return irisStore.currentIocs?.data?.analysisId === props.reportId
    ? irisStore.currentIocs.data
    : null
})
const iocsLoading = computed(() => {
  if (!props.reportId) return false
  return irisStore.currentIocs?.loading && irisStore.currentIocs?.data?.analysisId !== props.reportId
})

function toggleIocs() {
  iocsOpen.value = !iocsOpen.value
  if (iocsOpen.value && !iocsData.value) irisStore.iocsFor(props.reportId)
}

// Neutraliza dominios/URLs/IPs/emails para que no se conviertan en enlaces
// clicables ni resuelvan accidentalmente al pegarlos en otra herramienta.
function defang(value) {
  return String(value)
    .replace(/https?/gi, (m) => m.replace(/^http/i, 'hxxp'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]')
}

function exportIocsCsv() {
  if (!iocsData.value) return
  const rows = [['type', 'value']]
  for (const cat of iocCategories) {
    for (const val of iocsData.value[cat.key]) {
      rows.push([cat.key, val])
    }
  }
  const csv = rows.map(r => r.map(f => `"${String(f).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `iris_iocs_${props.reportId}.csv`
  document.body.appendChild(a)
  a.click()
  setTimeout(() => { URL.revokeObjectURL(url); a.remove() }, 1000)
}

/* ── Recomendaciones (recorte con "mostrar más") ── */
const RECS_PREVIEW_COUNT = 4
const recsExpanded = ref(false)
const visibleRecommendations = computed(() => {
  const all = props.reportData?.recommendations ?? []
  return recsExpanded.value ? all : all.slice(0, RECS_PREVIEW_COUNT)
})

/* ── Informes PDF ── */
const docsModalOpen = ref(false)
const generatingDocument = ref(false)

function refreshDocuments() {
  if (props.reportId) irisStore.fetchDocuments(props.reportId)
}

async function handleGenerateDocument() {
  if (!props.reportId) return
  generatingDocument.value = true
  try {
    await irisStore.generateDocument(props.reportId)
  } finally {
    generatingDocument.value = false
  }
}

async function handleDownloadDocument(documentId) {
  await irisStore.downloadDocument(documentId)
}

async function handleDeleteDocument(documentId) {
  await irisStore.deleteDocument(documentId, props.reportId)
}

watch(
  () => [props.reportId, props.reportData?.status],
  ([id, status]) => {
    if (id && status === 'finished') {
      irisStore.fetchDocuments(id)
    } else {
      irisStore.documents = []
    }
  },
  { immediate: true },
)
</script>

<style scoped>
.report-viewer {
  height: 100%;
  display: flex;
  flex-direction: column;
}

/* Empty */
.rv-empty {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2.5rem 3rem;
}

/* Loading */
.rv-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  padding: 5rem 0;
  color: var(--text-muted);
  font-size: var(--fs-md);
}

.spinner {
  width: 44px;
  height: 44px;
  border: 3px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: seq-spin 0.7s linear infinite;
}

/* Running */
.rv-running {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1.25rem;
  padding: 4rem 2rem;
  text-align: center;
}

.rv-running-header {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.progress-track {
  width: 100%;
  max-width: 400px;
  height: 10px;
  background: var(--surface-2);
  border-radius: 5px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--accent);
  border-radius: 5px;
  transition: width 0.4s ease;
}

.progress-label {
  font-size: var(--fs-xl);
  color: var(--text-dim);
  font-family: var(--font-mono);
}

.btn-cancel {
  padding: 0.6rem 1.3rem;
  font-size: var(--fs-xl);
  font-weight: 600;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-dim);
  cursor: pointer;
  transition: all 0.2s;
}

.btn-cancel:hover {
  border-color: var(--danger);
  color: var(--danger);
  background: var(--danger-dim);
}

/* Failed / Cancelled */
.rv-failed,
.rv-cancelled {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.8rem;
  padding: 5rem 2rem;
  text-align: center;
}

.rv-failed h3,
.rv-cancelled h3 {
  font-size: var(--fs-xl);
  font-weight: 700;
  color: var(--text);
  font-family: var(--font-display);
  margin: 0;
}

.rv-failed p,
.rv-cancelled p {
  font-size: var(--fs-xl);
  color: var(--text-dim);
  max-width: 380px;
  margin: 0;
  line-height: 1.5;
}

.rv-result-icon svg {
  width: 52px;
  height: 52px;
}

.rv-result-icon--fail svg { color: var(--danger); }
.rv-result-icon--warn svg { color: var(--warn); }

/* Finished report */
.rv-report {
  flex: 1;
  overflow-y: auto;
  padding: 1.5rem 2rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.rv-report-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.rv-report-id {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.analysis-id {
  font-family: var(--font-mono);
  font-size: var(--fs-xl);
  font-weight: 600;
  color: var(--text-dim);
  background: var(--surface-2);
  padding: 0.25rem 0.6rem;
  border-radius: 5px;
}

.report-title {
  font-family: var(--font-body);
  font-size: var(--fs-lg);
  font-weight: 700;
  color: var(--text);
  word-break: break-word;
}

.report-date {
  font-size: var(--fs-lg);
  color: var(--text-muted);
}

.rv-actions {
  display: flex;
  gap: 0.3rem;
}

.action-btn {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn svg {
  width: 18px;
  height: 18px;
}

.action-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-dim);
}

.action-btn--danger:hover {
  border-color: var(--danger);
  color: var(--danger);
  background: var(--danger-dim);
}

.action-btn-badge {
  position: absolute;
  top: -5px;
  right: -5px;
  min-width: 16px;
  height: 16px;
  padding: 0 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 999px;
  background: var(--accent);
  color: var(--bg);
  font-size: var(--fs-body);
  font-weight: 700;
  font-family: var(--font-mono);
  line-height: 1;
}

/* Hero */
.rv-hero {
  display: flex;
  align-items: center;
  gap: 2rem;
  padding: 1.5rem 2rem;
  border-radius: 12px;
  border: 1px solid var(--border-med);
  background: var(--surface);
}

.rv-hero--legit {
  border-color: rgba(76, 183, 130, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(76, 183, 130, 0.04) 100%);
}

.rv-hero--susp {
  border-color: rgba(212, 160, 74, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(212, 160, 74, 0.04) 100%);
}

.rv-hero--phish {
  border-color: rgba(217, 108, 108, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(217, 108, 108, 0.04) 100%);
}

.rv-hero-score {
  display: flex;
  align-items: baseline;
  gap: 0.25rem;
}

.score-num {
  font-size: var(--fs-stat-hero);
  font-weight: 800;
  font-family: var(--font-display);
  letter-spacing: -0.02em;
}

.rv-hero--legit .score-num { color: var(--success); }
.rv-hero--susp .score-num { color: var(--warn); }
.rv-hero--phish .score-num { color: var(--danger); }

.score-unit {
  font-size: var(--fs-lg);
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.rv-hero-verdict {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.verdict-badge {
  font-size: var(--fs-xl);
  font-weight: 700;
  font-family: var(--font-display);
}

.verdict--legit { color: var(--success); }
.verdict--susp { color: var(--warn); }
.verdict--phish { color: var(--danger); }

.verdict-status {
  font-size: var(--fs-lg);
  color: var(--text-dim);
}

/* Section title */
.section-title {
  font-size: var(--fs-xl);
  font-weight: 700;
  color: var(--text);
  font-family: var(--font-display);
  margin: 0 0 0.85rem;
  padding-bottom: 0.4rem;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* Top signals */
.rv-top-signals {
  display: flex;
  flex-direction: column;
}

/* AI executive summary (IA1) */
.rv-ai-summary {
  display: flex;
  flex-direction: column;
}

.ai-summary-card {
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
  padding: 1rem 1.1rem;
  border-radius: 10px;
  background: var(--surface);
  border: 1px solid var(--border-solid);
}

.ai-summary-text {
  margin: 0;
  font-size: var(--fs-xl);
  line-height: 1.6;
  color: var(--text);
}

.ai-summary-row {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.ai-summary-label {
  font-size: var(--fs-lg);
  font-weight: 700;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.ai-summary-recs {
  margin: 0;
  padding-left: 1.2rem;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-size: var(--fs-lg);
  color: var(--text-dim);
}

.ai-summary-confidence {
  align-self: flex-start;
  font-size: var(--fs-lg);
  font-weight: 700;
  padding: 0.25rem 0.6rem;
  border-radius: 999px;
  background: var(--border);
  color: var(--text-dim);
}

.ai-summary-confidence.confidence--alta {
  background: color-mix(in srgb, var(--danger) 15%, transparent);
  color: var(--danger);
}

.ai-summary-confidence.confidence--media {
  background: color-mix(in srgb, var(--warn) 15%, transparent);
  color: var(--warn);
}

.ai-summary-confidence.confidence--baja {
  background: color-mix(in srgb, var(--success) 15%, transparent);
  color: var(--success);
}

.signal-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.signal-chip {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.8rem;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  font-size: var(--fs-lg);
  cursor: pointer;
  transition: border-color 0.2s, transform 0.15s;
  font-family: var(--font-body);
}

.signal-chip:hover {
  border-color: var(--danger);
  transform: translateY(-1px);
}

.signal-name {
  font-weight: 600;
}

.signal-score {
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--danger);
}

/* Rule cards */
.rv-rules {
  display: flex;
  flex-direction: column;
  gap: 0;
}

/* Unwrapped-forward notice */
.rv-unwrap-notice {
  display: flex;
  align-items: flex-start;
  gap: 0.7rem;
  padding: 0.85rem 1rem;
  border-radius: 10px;
  background: color-mix(in srgb, var(--accent) 8%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
  font-size: var(--fs-lg);
  line-height: 1.5;
  color: var(--text);
}

.unwrap-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--accent);
}

.unwrap-text {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.unwrap-wrapper-info {
  font-size: var(--fs-lg);
  color: var(--text-dim);
}

/* Gate reasons (por qué este veredicto) */
.rv-gates {
  display: flex;
  flex-direction: column;
}

.gate-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.gate-item {
  display: flex;
  align-items: flex-start;
  gap: 0.55rem;
  padding: 0.75rem 0.9rem;
  border-radius: 10px;
  background: color-mix(in srgb, var(--danger) 6%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--danger) 30%, var(--border));
  font-size: var(--fs-xl);
  line-height: 1.6;
  color: var(--text);
}

.gate-bullet {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 3px;
  color: var(--danger);
}

/* Recommendations */
.rv-recommendations {
  display: flex;
  flex-direction: column;
}

.rec-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.rec-item {
  display: flex;
  align-items: flex-start;
  gap: 0.55rem;
  padding: 0.75rem 0.9rem;
  border-radius: 10px;
  background: var(--surface);
  border: 1px solid var(--border);
  font-size: var(--fs-xl);
  line-height: 1.6;
  color: var(--text-dim);
}

.rec-bullet {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 3px;
  color: var(--warn);
}

/* Raw headers */
.rv-raw {
  display: flex;
  flex-direction: column;
}

.raw-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.65rem 0;
  font-size: var(--fs-xl);
  font-weight: 600;
  color: var(--text-dim);
  background: none;
  border: none;
  cursor: pointer;
  transition: color 0.2s;
}

.raw-toggle:hover {
  color: var(--text);
}

.toggle-chevron {
  width: 18px;
  height: 18px;
  transition: transform 0.2s;
}

.toggle-chevron.rotated {
  transform: rotate(90deg);
}

.raw-block {
  padding: 1rem 1.2rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 8px;
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  line-height: 1.6;
  color: var(--text-dim);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow-y: auto;
}

/* Raw reveal transition */
.raw-reveal-enter-active,
.raw-reveal-leave-active {
  transition: all 0.25s ease;
}

.raw-reveal-enter-from,
.raw-reveal-leave-to {
  opacity: 0;
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
}

/* Email path */
.rv-path {
  display: flex;
  flex-direction: column;
}

.rv-path-loading {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 1rem 0;
  color: var(--text-muted);
  font-size: var(--fs-lg);
}

.spinner--sm {
  width: 18px;
  height: 18px;
  border-width: 2px;
}

.rv-path-empty {
  margin: 0;
  padding: 1rem 1.1rem;
  border: 1px dashed var(--border);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text-muted);
  font-size: var(--fs-lg);
  font-family: var(--font-mono);
  text-align: center;
}

/* IOCs */
.ioc-panel {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
  padding: 0.2rem 0 0.6rem;
}

.ioc-hint {
  margin: 0;
  font-size: var(--fs-lg);
  color: var(--text-muted);
}

.ioc-category-header {
  margin-bottom: 0.4rem;
}

.ioc-category-title {
  font-size: var(--fs-lg);
  font-weight: 700;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.ioc-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

.ioc-item {
  padding: 0.5rem 0.75rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  color: var(--text-dim);
  word-break: break-all;
}

.ioc-empty {
  margin: 0;
  font-size: var(--fs-lg);
  color: var(--text-muted);
  font-style: italic;
}

.btn-export-csv {
  align-self: flex-start;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 1rem;
  border-radius: 8px;
  background: var(--accent);
  color: var(--bg);
  border: none;
  font-size: var(--fs-lg);
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-export-csv:hover {
  opacity: 0.85;
}

.btn-export-csv svg {
  width: 16px;
  height: 16px;
}
</style>
