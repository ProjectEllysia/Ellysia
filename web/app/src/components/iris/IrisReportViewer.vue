<template>
  <div class="report-viewer">

    <!-- Un fundido entre estados: sin él, Vue cambia formulario, carga e
         informe en el mismo fotograma y todo aparece de golpe. -->
    <Transition name="rv-swap" mode="out-in">
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
    <!-- La key hace que pasar de un informe terminado a otro también se anime. -->
    <div v-else-if="reportData && reportData.status === 'finished'" :key="reportData.analysisId" class="rv-report">
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

      <!-- Etiquetas del analista: agrupan análisis en el archivo. No cambian
           el análisis, que sigue siendo lo que decidió Iris. -->
      <div class="rv-tags">
        <span v-for="tag in reportData.tags || []" :key="tag" class="rv-tag">
          {{ tag }}
          <button type="button" class="rv-tag-remove" :aria-label="`Quitar la etiqueta ${tag}`" @click="removeTag(tag)">&times;</button>
        </span>
        <form class="rv-tag-add" @submit.prevent="addTag">
          <input v-model="newTag" type="text" maxlength="40" class="rv-tag-input" placeholder="+ etiqueta" aria-label="Añadir etiqueta" list="iris-user-tags" />
          <datalist id="iris-user-tags"><option v-for="tag in irisStore.userTags" :key="tag.name" :value="tag.name" /></datalist>
        </form>
      </div>

      <!-- Aviso: el mensaje enviado era un reenvío que envolvía el correo -->
      <!-- original como adjunto .eml. Se evalúan los dos y el informe describe -->
      <!-- el que produjo el veredicto (winningContext); el otro queda como secundario -->
      <div v-if="reportData.unwrappedFromForward" class="rv-unwrap-notice">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="unwrap-icon"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 7l-10 6L2 7"/></svg>
        <div class="unwrap-text">
          <strong>Correo reenviado como adjunto detectado.</strong>
          <template v-if="reportData.winningContext === 'wrapper'">
            El veredicto sale del envoltorio del reenvío, no del mensaje original adjunto.
          </template>
          <template v-else>
            Se analizó el mensaje original adjunto (.eml), no el envoltorio del reenvío.
          </template>
          <span v-if="reportData.winningReason" class="unwrap-wrapper-info">{{ reportData.winningReason }}</span>
          <span v-if="reportData.secondaryContext" class="unwrap-wrapper-info">
            {{ reportData.secondaryContext.contextType === 'wrapper' ? 'Envoltorio' : 'Original' }}:
            {{ reportData.secondaryContext.verdict }} ({{ reportData.secondaryContext.totalScore }} puntos)
          </span>
          <span v-if="reportData.wrapperFrom || reportData.wrapperSubject" class="unwrap-wrapper-info">
            Envoltorio: <template v-if="reportData.wrapperFrom">de {{ reportData.wrapperFrom }}</template>
            <template v-if="reportData.wrapperSubject">— «{{ reportData.wrapperSubject }}»</template>
          </span>
        </div>
      </div>

      <!-- Score + Verdict hero -->
      <IrisVerdictHero
        :score="reportData.totalScore"
        :verdict="reportData.verdict"
        :confidence="reportData.confidence"
        :coverage-mode="reportData.coverage?.mode ?? null"
      />

      <!-- Incertidumbre: por qué la confianza no es alta. Va junto al veredicto
           porque lo matiza; en solo cabeceras lista además qué reglas no
           tuvieron cuerpo, enlaces ni adjuntos que inspeccionar. -->
      <div v-if="uncertaintyReasons.length || uncoveredRules.length" class="rv-uncertainty">
        <strong class="uncertainty-title">Qué limita este veredicto</strong>
        <ul v-if="uncertaintyReasons.length" class="uncertainty-list">
          <li v-for="(reason, i) in uncertaintyReasons" :key="i">{{ reason }}</li>
        </ul>
        <p v-if="uncoveredRules.length" class="uncertainty-rules">
          Sin contenido que inspeccionar: {{ uncoveredRules.join(' · ') }}
        </p>
      </div>

      <!-- Feedback del analista: corrige el resultado en dos clics (etiqueta y
           Guardar). Nunca cambia el veredicto de arriba; alimenta las métricas
           y la calibración del detector. -->
      <div class="rv-feedback">
        <div class="feedback-row">
          <span class="feedback-title">¿Es correcto este veredicto?</span>
          <div class="feedback-actions">
            <button
              v-for="option in FEEDBACK_OPTIONS"
              :key="option.value"
              type="button"
              class="feedback-option"
              :class="{ 'feedback-option--active': feedbackLabel === option.value }"
              @click="feedbackLabel = option.value"
            >{{ option.label }}</button>
          </div>
        </div>
        <div v-if="feedbackLabel" class="feedback-form">
          <textarea
            v-model="feedbackNote"
            class="feedback-note"
            maxlength="2000"
            rows="2"
            placeholder="Nota opcional (por qué)"
          ></textarea>
          <button type="button" class="feedback-save" :disabled="feedbackSaving" @click="saveFeedback">
            Guardar
          </button>
        </div>
        <p v-if="reportData.latestFeedback" class="feedback-current">
          Revisado como <strong>{{ FEEDBACK_LABELS[reportData.latestFeedback.label] }}</strong>
          por {{ reportData.latestFeedback.author }} · {{ formatDate(reportData.latestFeedback.createdAt) }}
          <template v-if="reportData.latestFeedback.note"> — «{{ reportData.latestFeedback.note }}»</template>
        </p>
        <!-- Falso positivo recurrente: confiar en el remitente para los
             próximos análisis. No toca este veredicto. -->
        <!-- Convertir el informe en trabajo: añadirlo a un caso de analista. -->
        <IrisAddToCase :analysis-id="reportData.analysisId" :analysis-title="reportData.title || ''" />
        <button v-if="!trustFormOpen" type="button" class="feedback-option trust-open" @click="trustFormOpen = true">
          Confiar en este remitente…
        </button>
        <IrisTrustForm
          v-else
          :from-header="reportData.previewHeaders?.from ?? ''"
          cancellable
          @saved="trustFormOpen = false"
          @cancel="trustFormOpen = false"
        />
      </div>

      <!-- Excepción de confianza que coincidió con el remitente: aplicada
           (qué reglas neutralizó) o ignorada (el mensaje no demostró venir de
           ahí). Es parte de la explicación del veredicto. -->
      <div v-if="reportData.trustApplied" class="rv-trust" :class="{ 'rv-trust--ignored': !reportData.trustApplied.applied }">
        <strong class="uncertainty-title">
          {{ reportData.trustApplied.applied ? 'Excepción de confianza aplicada' : 'Excepción de confianza no aplicada' }}
        </strong>
        <p class="trust-detail">
          {{ reportData.trustApplied.kind === 'domain' ? 'Dominio' : 'Remitente' }}
          <code>{{ reportData.trustApplied.value }}</code> — «{{ reportData.trustApplied.reason }}».
          <template v-if="reportData.trustApplied.applied">
            Reglas neutralizadas: {{ reportData.trustApplied.modulatedRules.join(' · ') || 'ninguna penalizaba' }}.
          </template>
          <template v-else>
            El mensaje no demuestra venir de ahí, así que se analizó sin la excepción.
          </template>
        </p>
      </div>

      <!-- Análisis degradado: alguna regla no llegó a ejecutarse, así que
           una parte del mensaje no se ha inspeccionado. Va inmediatamente
           debajo del veredicto porque lo matiza: quien lea el número grande
           tiene que saber que se calculó sin parte del examen. -->
      <div v-if="isDegraded" class="rv-degraded">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="degraded-icon"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div class="degraded-body">
          <strong class="degraded-title">Análisis incompleto</strong>
          <p class="degraded-text">
            No se pudieron ejecutar {{ failedRuleNames.length }}
            {{ failedRuleNames.length === 1 ? 'regla' : 'reglas' }}, así que la parte
            del mensaje que les correspondía no se ha inspeccionado.
          </p>
          <p v-if="failedRuleNames.length" class="degraded-rules">
            {{ failedRuleNames.join(' · ') }}
          </p>
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
          @jump-evidence="jumpToEvidence"
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
                @jump-evidence="jumpToEvidence"
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
            <IrisIocsPanel v-else-if="iocsData" :data="iocsData" :report-id="reportId" />
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
          <pre v-if="rawOpen" ref="rawBlock" class="raw-block"><span
            v-for="(line, n) in rawLines"
            :key="n"
            :class="['raw-line', { 'raw-line--hit': n === highlightedLine }]"
          >{{ line }}{{ '\n' }}</span></pre>
        </Transition>
      </div>

    </div>
    </Transition>

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
import IrisIocsPanel from '@/components/iris/IrisIocsPanel.vue'
import IrisVerdictHero from '@/components/iris/IrisVerdictHero.vue'
import IrisTrustForm from '@/components/iris/IrisTrustForm.vue'
import IrisAddToCase from '@/components/iris/IrisAddToCase.vue'

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

// Salto desde la evidencia de una regla a su línea en "Cabeceras originales".
const rawBlock = ref(null)
const highlightedLine = ref(null)
const rawLines = computed(() => (props.reportData?.rawHeaders ?? '').split(/\r?\n/))

/** Índice de línea de la aparición `occurrence` de la cabecera `header`, o
 * null si no está. En un reenvío cuyo veredicto sale del original adjunto,
 * sus cabeceras viven dentro de la parte message/rfc822: se busca a partir de
 * ahí para no caer en la cabecera homónima del envoltorio. */
function findHeaderLine(lines, header, occurrence) {
  let start = 0
  if (props.reportData?.unwrappedFromForward && props.reportData?.winningContext !== 'wrapper') {
    const nested = lines.findIndex(line => /^content-type:\s*message\/rfc822/i.test(line))
    if (nested >= 0) start = nested + 1
  }
  const escaped = header.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const prefix = new RegExp(`^${escaped}\\s*:`, 'i')
  let seen = 0
  for (let n = start; n < lines.length; n++) {
    if (!prefix.test(lines[n])) continue
    if (seen === occurrence) return n
    seen++
  }
  return null
}

async function jumpToEvidence(item) {
  const line = findHeaderLine(rawLines.value, item.locator?.header ?? '', item.locator?.occurrence ?? 0)
  rawOpen.value = true
  highlightedLine.value = line
  await nextTick()
  if (line !== null) {
    rawBlock.value?.querySelectorAll('.raw-line')[line]?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }
}

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

// Análisis degradado: alguna regla lanzó una excepción y no llegó a
// ejecutarse. No es lo mismo que una regla que encontró algo malo —esas
// aparecen en flaggedRules con su puntuación— sino una parte del mensaje que
// nadie miró, y por eso el aviso va arriba y no entre los hallazgos.
const failedRuleNames = computed(() =>
  (props.reportData?.failedRules ?? []).map(rule => rule.name).filter(Boolean)
)
const isDegraded = computed(() =>
  props.reportData?.analysisQuality === 'degraded' || failedRuleNames.value.length > 0
)
// Confianza ordinal y cobertura (ver IrisVerdictHero). Los motivos y las
// reglas sin contenido vienen ya calculados por la API: el componente no
// reinterpreta nada, para que UI, PDF y resumen de IA digan lo mismo.
const uncertaintyReasons = computed(() => props.reportData?.uncertaintyReasons ?? [])
const uncoveredRules = computed(() =>
  props.reportData?.coverage?.mode === 'headers_only'
    ? (props.reportData.coverage.uncoveredRules ?? [])
    : []
)
const passedRules = computed(() => rulesWithIndex.value.filter(entry => entry.rule.verdict === 'pass'))
const passedRulesOpen = ref(false)

// Feedback del analista (ver el bloque .rv-feedback de la plantilla).
const FEEDBACK_OPTIONS = [
  { value: 'malicious', label: 'Es malicioso' },
  { value: 'legitimate', label: 'Es legítimo' },
  { value: 'unknown', label: 'No se puede saber' },
]
const FEEDBACK_LABELS = { malicious: 'malicioso', legitimate: 'legítimo', unknown: 'indeterminado' }
const feedbackLabel = ref(null)
const feedbackNote = ref('')
const feedbackSaving = ref(false)
// Formulario «Confiar en este remitente» (excepción de confianza).
const trustFormOpen = ref(false)
// Etiqueta que se está escribiendo en la fila de etiquetas del informe.
const newTag = ref('')

/** Añade la etiqueta escrita al análisis abierto. */
async function addTag() {
  const tag = newTag.value.trim()
  if (!tag) return
  const saved = await irisStore.setAnalysisTags(props.reportData.analysisId, [...(props.reportData.tags ?? []), tag])
  if (saved) newTag.value = ''
}

/** Quita una etiqueta del análisis abierto. */
function removeTag(tag) {
  irisStore.setAnalysisTags(props.reportData.analysisId, (props.reportData.tags ?? []).filter(existing => existing !== tag))
}

watch(() => props.reportData?.analysisId, () => {
  feedbackLabel.value = null
  feedbackNote.value = ''
  trustFormOpen.value = false
  newTag.value = ''
})

async function saveFeedback() {
  feedbackSaving.value = true
  const saved = await irisStore.submitFeedback(props.reportData.analysisId, {
    label: feedbackLabel.value,
    note: feedbackNote.value.trim() || null,
  })
  feedbackSaving.value = false
  if (saved) {
    feedbackLabel.value = null
    feedbackNote.value = ''
  }
}

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

// Valor ya resuelto desde la API pública del store — antes se leían
// pathCache/currentPath (cachés internos de la estrategia de carga bajo
// demanda) directamente desde el componente.
const pathData = computed(() => irisStore.resolvedPathFor(props.reportId))
const pathLoading = computed(() => irisStore.isPathLoadingFor(props.reportId))
const pathVisible = computed(() => {
  return props.reportData?.status === 'finished' && !!props.reportId && (
    pathData.value || pathLoading.value
  )
})

/* ── IOCs (A3: contenido con datos vive en IrisIocsPanel.vue) ── */
const iocsOpen = ref(false)
const iocsData = computed(() => irisStore.resolvedIocsFor(props.reportId))
const iocsLoading = computed(() => irisStore.isIocsLoadingFor(props.reportId))

function toggleIocs() {
  iocsOpen.value = !iocsOpen.value
  if (iocsOpen.value && !iocsData.value) irisStore.iocsFor(props.reportId)
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
  font-size: var(--fs-lg);
  color: var(--text-dim);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
}

.btn-cancel {
  padding: 0.6rem 1.3rem;
  font-size: var(--fs-lg);
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
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
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
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  font-weight: 600;
  color: var(--text-dim);
  background: var(--surface-2);
  padding: 0.25rem 0.6rem;
  border-radius: 5px;
}

.report-title {
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
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
  font-size: var(--fs-sm);
  font-weight: 700;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  line-height: 1;
}

/* Section title */
.section-title {
  font-size: var(--fs-xl);
  font-weight: 700;
  color: var(--text);
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
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
  font-size: var(--fs-md);
  cursor: pointer;
  transition: border-color 0.2s, transform 0.15s;
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
}

.signal-chip:hover {
  border-color: var(--danger);
  transform: translateY(-1px);
}

.signal-name {
  font-weight: 600;
}

.signal-score {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
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
.rv-degraded {
  display: flex;
  align-items: flex-start;
  gap: 0.7rem;
  padding: 0.85rem 1rem;
  border-radius: 10px;
  background: color-mix(in srgb, var(--warn) 10%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--warn) 40%, var(--border));
  color: var(--text);
}

.degraded-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 0.1rem;
  color: var(--warn);
}

.degraded-body {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.degraded-title {
  font-size: var(--fs-md);
}

.degraded-text {
  margin: 0;
  font-size: var(--fs-md);
  line-height: 1.6;
}

.degraded-rules {
  margin: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
  word-break: break-word;
}

.rv-uncertainty {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  padding: 0.85rem 1rem;
  border-radius: 10px;
  background: var(--surface);
  border: 1px solid var(--border-med);
  color: var(--text);
}

.uncertainty-title {
  font-size: var(--fs-md);
}

.uncertainty-list {
  margin: 0;
  padding-left: 1.1rem;
  font-size: var(--fs-md);
  line-height: 1.6;
}

.uncertainty-rules {
  margin: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
  word-break: break-word;
}

.rv-feedback {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.85rem 1rem;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--surface);
}

.feedback-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.6rem;
}

.feedback-title {
  font-size: var(--fs-md);
  font-weight: 600;
}

.feedback-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.feedback-option,
.feedback-save {
  padding: 0.35rem 0.75rem;
  border-radius: 6px;
  border: 1px solid var(--border-med);
  background: var(--surface-2);
  color: var(--text);
  font: inherit;
  font-size: var(--fs-sm);
  cursor: pointer;
}

.feedback-option--active {
  border-color: var(--accent);
  color: var(--accent);
}

.feedback-form {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
}

.feedback-note {
  flex: 1;
  min-height: 2.4rem;
  padding: 0.4rem 0.55rem;
  border-radius: 6px;
  border: 1px solid var(--border-med);
  background: var(--surface);
  color: var(--text);
  font: inherit;
  font-size: var(--fs-sm);
  resize: vertical;
}

.feedback-current {
  margin: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.raw-line--hit {
  background: color-mix(in srgb, var(--accent) 22%, transparent);
  border-radius: 3px;
}

.rv-tags { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; margin: -0.25rem 0 0.25rem; }
.rv-tag {
  display: inline-flex; align-items: center; gap: 0.25rem;
  padding: 0.1rem 0.25rem 0.1rem 0.55rem; font-size: var(--fs-sm);
  background: var(--info-dim); color: var(--info); border-radius: 999px;
}
.rv-tag-remove { border: none; background: none; color: inherit; cursor: pointer; font-size: var(--fs-md); line-height: 1; }
.rv-tag-input {
  width: 8.5rem; padding: 0.15rem 0.5rem; font-size: var(--fs-sm);
  background: transparent; color: var(--text); border: 1px dashed var(--border-med); border-radius: 999px;
}
.rv-tag-input:focus { outline: none; border-color: var(--accent); }

.trust-open { margin-top: 0.6rem; }

.rv-trust {
  padding: 0.75rem 1rem;
  border: 1px solid rgba(96, 128, 224, 0.25);
  border-radius: 10px;
  background: var(--info-dim);
}
.rv-trust--ignored {
  border-color: rgba(212, 160, 74, 0.3);
  background: var(--warn-dim);
}
.trust-detail {
  margin: 0.35rem 0 0;
  font-size: var(--fs-md);
  line-height: 1.5;
  color: var(--text-dim);
}

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
  font-size: var(--fs-md);
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
  font-size: var(--fs-lg);
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
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
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
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  text-align: center;
}

/* IOCs — el contenido "con datos" (hint, categorías, lista, vacío) vive
   en IrisIocsPanel.vue; .ioc-panel es el contenedor del chrome colapsable,
   que se queda aquí (ver A3). */
.ioc-panel {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
  padding: 0.2rem 0 0.6rem;
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

/* Fundido entre estados del visor (formulario, carga, en curso, informe). */
.rv-swap-enter-active {
  transition: opacity 0.25s ease, transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
}
.rv-swap-leave-active {
  transition: opacity 0.15s ease;
}
.rv-swap-enter-from {
  opacity: 0;
  transform: translateY(6px);
}
.rv-swap-leave-to {
  opacity: 0;
}

/* Entrada escalonada de las secciones del informe, con la misma animación
   que la tira de historial. De la novena en adelante comparten retraso: al
   abrir quedan por debajo del pliegue y hacerlas esperar más no aporta. */
.rv-report > * {
  animation: seq-fade-up 0.35s cubic-bezier(0.22, 1, 0.36, 1) backwards;
}
.rv-report > :nth-child(2) { animation-delay: 0.04s; }
.rv-report > :nth-child(3) { animation-delay: 0.08s; }
.rv-report > :nth-child(4) { animation-delay: 0.12s; }
.rv-report > :nth-child(5) { animation-delay: 0.16s; }
.rv-report > :nth-child(6) { animation-delay: 0.2s; }
.rv-report > :nth-child(7) { animation-delay: 0.24s; }
.rv-report > :nth-child(8) { animation-delay: 0.28s; }
.rv-report > :nth-child(n+9) { animation-delay: 0.32s; }

@media (prefers-reduced-motion: reduce) {
  .rv-swap-enter-active, .rv-swap-leave-active { transition: none; }
  .rv-swap-enter-from { transform: none; }
  .rv-report > * { animation: none; }
}
</style>
