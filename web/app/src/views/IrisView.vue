<template>
  <div
    class="iris-page"
    data-module="iris"
    @dragenter="onDragEnter"
    @dragover="onDragOver"
    @dragleave="onDragLeave"
    @drop="onDrop"
  >
    <StarBackground />
    <Topbar title="Iris" badge="Análisis de Cabeceras" back-to="/iris" back-label="Volver" />

    <!-- Intake de evidencia: visor que aparece al arrastrar un .eml -->
    <Transition name="intake-fade">
      <div v-if="showOverlay" class="intake" :class="{ 'intake--reject': rejecting }" aria-hidden="true">
        <div class="intake-frame">
          <span class="tick tick--tl"></span>
          <span class="tick tick--tr"></span>
          <span class="tick tick--bl"></span>
          <span class="tick tick--br"></span>

          <div class="intake-specimen">
            <svg class="env" viewBox="0 0 64 48" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round">
              <rect x="2" y="4" width="60" height="40" rx="3" />
              <path d="M4 7l28 22L60 7" />
            </svg>
            <span class="scanline"></span>
          </div>

          <p class="intake-eyebrow">{{ rejecting ? 'Formato no válido' : 'Intake de evidencia' }}</p>
          <h2 class="intake-title">
            {{ rejecting ? 'Solo se admiten archivos .eml' : 'Suelta el correo para examinarlo' }}
          </h2>
          <span class="intake-chip">.eml</span>
        </div>
      </div>
    </Transition>

    <div class="iris-layout">
      <IrisHistoryStrip
        :items="sortedAnalyses"
        :active-id="store.currentId"
        :sort="sortMode"
        :has-more="store.hasMore"
        :loading-more="store.loadingMore"
        @select="store.selectAnalysis"
        @sort="handleSort"
        @delete="handleDelete"
        @load-more="handleLoadMore"
      />

      <main class="iris-main">
        <IrisReportViewer
          :report-id="store.currentId"
          :report-data="store.currentReport.data"
          :report-loading="store.currentReport.loading"
          :status="store.currentStatus.status"
          :progress="store.currentStatus.progress"
          @cancel="handleCancel"
          @delete="handleDelete"
        >
          <template #form>
            <IrisForm
              :key="formKey"
              :submitting="store.submitting"
              :prefill="prefill"
              @submit="handleSubmit"
            />
          </template>
        </IrisReportViewer>
      </main>
    </div>

    <AppToast />
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, computed, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import IrisHistoryStrip from '@/components/iris/IrisHistoryStrip.vue'
import IrisReportViewer from '@/components/iris/IrisReportViewer.vue'
import IrisForm from '@/components/iris/IrisForm.vue'
import { useIrisStore } from '@/stores/irisStore'
import { useToastStore } from '@/stores/toastStore'
import { parseEml } from '@/composables/useEml'

const store = useIrisStore()
const toast = useToastStore()
const formKey = ref(0)

// Relleno automático del formulario a partir de un .eml arrastrado.
const prefill = ref(null)

// Fase 2: enviamos el .eml completo (cuerpo, enlaces, adjuntos) para que las
// reglas de contenido puedan analizarlo. Tope generoso para correos con
// adjuntos grandes en base64, evitando cargar archivos descomunales.
const MESSAGE_READ_LIMIT = 20 * 1024 * 1024

// --- Intake por arrastre ---
// dragDepth cuenta enter/leave para no parpadear sobre los hijos; rejecting
// mantiene el visor en rojo un instante cuando el archivo no es válido.
const dragDepth = ref(0)
const rejecting = ref(false)
let rejectTimer = null

const showOverlay = computed(() => dragDepth.value > 0 || rejecting.value)

function hasFiles(e) {
  return Array.from(e.dataTransfer?.types ?? []).includes('Files')
}

function onDragEnter(e) {
  if (!hasFiles(e)) return
  e.preventDefault()
  dragDepth.value++
}

function onDragOver(e) {
  if (!hasFiles(e)) return
  e.preventDefault()
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'
}

function onDragLeave(e) {
  if (!hasFiles(e)) return
  e.preventDefault()
  dragDepth.value = Math.max(0, dragDepth.value - 1)
}

function flashReject() {
  rejecting.value = true
  clearTimeout(rejectTimer)
  rejectTimer = setTimeout(() => { rejecting.value = false }, 1500)
}

async function onDrop(e) {
  if (!hasFiles(e)) return
  e.preventDefault()
  dragDepth.value = 0

  const file = e.dataTransfer?.files?.[0]
  if (!file) return

  const isEml = /\.eml$/i.test(file.name) || file.type === 'message/rfc822'
  if (!isEml) {
    flashReject()
    toast.show('Solo se aceptan archivos .eml', 'error')
    return
  }

  try {
    const tooBig = file.size > MESSAGE_READ_LIMIT
    const text = await (tooBig ? file.slice(0, MESSAGE_READ_LIMIT) : file).text()
    const { rawHeaders, subject } = parseEml(text)
    if (!rawHeaders) {
      flashReject()
      toast.show('No se pudieron leer las cabeceras del correo.', 'error')
      return
    }
    // Conservamos el mensaje completo (cuerpo, enlaces, adjuntos) para que
    // Iris pueda aplicar las reglas de Fase 2; si el archivo se truncó por
    // tamaño, solo enviamos las cabeceras extraídas como respaldo.
    prefill.value = {
      headers: rawHeaders,
      message: tooBig ? null : text,
      title: subject || '',
      token: Date.now(),
    }
    if (store.currentId || store.currentReport.data) store.selectAnalysis(null)
    if (tooBig) {
      toast.show('Archivo muy grande: solo se cargaron las cabeceras.', 'info')
    } else {
      toast.show('Correo cargado.', 'success')
    }
  } catch {
    flashReject()
    toast.show('No se pudo leer el archivo.', 'error')
  }
}

onBeforeUnmount(() => {
  clearTimeout(rejectTimer)
  store.stopPolling()
  store.stopDocumentPolling()
})

const sortMode = computed({
  get: () => store.sortMode || 'date-desc',
  set: (v) => { store.sortMode = v },
})

const sortedAnalyses = computed(() => {
  const items = [...store.analyses]
  switch (sortMode.value) {
    case 'date-asc':
      return items.sort((a, b) => new Date(a.startedAt || 0) - new Date(b.startedAt || 0))
    case 'score-desc':
      return items.sort((a, b) => (b.totalScore ?? -999) - (a.totalScore ?? -999))
    case 'score-asc':
      return items.sort((a, b) => (a.totalScore ?? -999) - (b.totalScore ?? -999))
    default:
      return items.sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0))
  }
})

onMounted(async () => {
  await store.fetchResults()
  const last = store.analyses[0]
  if (last && (last.status === 'running' || last.status === 'pending')) {
    store.selectAnalysis(last.analysisId)
  }
})

async function handleSubmit({ headers, message, title }) {
  const id = await store.submitAnalysis({ headers, message, title })
  if (id) {
    prefill.value = null
    formKey.value++
  }
}

async function handleCancel() {
  if (store.currentId) {
    await store.cancelAnalysis(store.currentId)
  }
}

async function handleDelete(id) {
  await store.deleteAnalysis(id)
}

function handleLoadMore() {
  store.fetchMoreResults()
}

function handleSort(mode) {
  sortMode.value = mode
}
</script>

<style scoped>
.iris-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.iris-layout {
  display: flex;
  flex-direction: column;
  height: calc(100vh - var(--topbar-h));
  position: relative;
  z-index: 1;
}

.iris-main {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

/* ── Intake de evidencia (overlay de arrastre) ───────────────────────────── */
.intake {
  --intake-color: var(--accent);
  position: fixed;
  inset: 0;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: none; /* deja pasar los eventos de drag a .iris-page */
  background:
    radial-gradient(120% 80% at 50% 50%, rgba(11, 12, 16, 0.55) 0%, rgba(11, 12, 16, 0.88) 100%);
  backdrop-filter: blur(6px);
}

.intake--reject {
  --intake-color: var(--danger);
}

.intake-frame {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  width: min(440px, 78vw);
  padding: 3.25rem 2.5rem 2.75rem;
  border: 1px solid color-mix(in srgb, var(--intake-color) 22%, transparent);
  border-radius: 18px;
  background: color-mix(in srgb, var(--surface) 78%, transparent);
  box-shadow:
    0 24px 70px rgba(0, 0, 0, 0.5),
    inset 0 0 60px color-mix(in srgb, var(--intake-color) 5%, transparent),
    0 0 0 1px color-mix(in srgb, var(--intake-color) 14%, transparent),
    0 0 26px color-mix(in srgb, var(--intake-color) 22%, transparent);
  transition: border-color 0.3s, box-shadow 0.3s;
  animation: intake-glow 2.6s ease-in-out infinite;
}

/* Marcas de esquina del visor */
.tick {
  position: absolute;
  width: 22px;
  height: 22px;
  border: 2px solid var(--intake-color);
  filter: drop-shadow(0 0 4px color-mix(in srgb, var(--intake-color) 65%, transparent));
  transition: border-color 0.3s;
}
.tick--tl { top: 12px; left: 12px; border-right: 0; border-bottom: 0; border-top-left-radius: 6px; }
.tick--tr { top: 12px; right: 12px; border-left: 0; border-bottom: 0; border-top-right-radius: 6px; }
.tick--bl { bottom: 12px; left: 12px; border-right: 0; border-top: 0; border-bottom-left-radius: 6px; }
.tick--br { bottom: 12px; right: 12px; border-left: 0; border-top: 0; border-bottom-right-radius: 6px; }

/* Espécimen: sobre + línea de escaneo */
.intake-specimen {
  position: relative;
  width: 104px;
  height: 78px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 0.85rem;
  overflow: hidden;
}

.intake-specimen .env {
  width: 84px;
  height: 63px;
  color: var(--intake-color);
  opacity: 0.92;
  filter: drop-shadow(0 0 12px color-mix(in srgb, var(--intake-color) 30%, transparent));
}

.scanline {
  position: absolute;
  left: 6px;
  right: 6px;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--intake-color), transparent);
  box-shadow: 0 0 10px color-mix(in srgb, var(--intake-color) 70%, transparent);
  animation: intake-scan 1.9s ease-in-out infinite;
}

@keyframes intake-scan {
  0%, 100% { top: 8%; opacity: 0.2; }
  50%      { top: 88%; opacity: 1; }
}

.intake-eyebrow {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 1.26rem;
  letter-spacing: 0.28em;
  text-transform: uppercase;
  color: var(--intake-color);
  transition: color 0.25s;
}

.intake-title {
  margin: 0.1rem 0 0.6rem;
  font-family: var(--font-display);
  font-size: 1.76rem;
  font-weight: 700;
  line-height: 1.25;
  text-align: center;
  color: var(--text);
  letter-spacing: -0.01em;
}

.intake-chip {
  font-family: var(--font-mono);
  font-size: 1.37rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  padding: 0.25rem 0.7rem;
  border-radius: 999px;
  color: var(--intake-color);
  background: color-mix(in srgb, var(--intake-color) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--intake-color) 28%, transparent);
}

/* Entrada/salida del overlay */
.intake-fade-enter-active {
  transition: opacity 0.45s cubic-bezier(0.22, 1, 0.36, 1), backdrop-filter 0.45s ease;
}
.intake-fade-leave-active {
  transition: opacity 0.3s ease;
}
.intake-fade-enter-from,
.intake-fade-leave-to {
  opacity: 0;
}
.intake-fade-enter-from .intake-frame {
  opacity: 0;
  transform: scale(0.9) translateY(10px);
  filter: blur(6px);
}
.intake-frame {
  transition:
    border-color 0.3s,
    box-shadow 0.3s,
    transform 0.55s cubic-bezier(0.22, 1, 0.36, 1),
    opacity 0.5s cubic-bezier(0.22, 1, 0.36, 1),
    filter 0.5s ease;
}

/* Animación de brillo pulsante en el borde del visor */
@keyframes intake-glow {
  0%, 100% {
    box-shadow:
      0 24px 70px rgba(0, 0, 0, 0.5),
      inset 0 0 60px color-mix(in srgb, var(--intake-color) 5%, transparent),
      0 0 0 1px color-mix(in srgb, var(--intake-color) 14%, transparent),
      0 0 22px color-mix(in srgb, var(--intake-color) 18%, transparent);
  }
  50% {
    box-shadow:
      0 24px 70px rgba(0, 0, 0, 0.5),
      inset 0 0 60px color-mix(in srgb, var(--intake-color) 8%, transparent),
      0 0 0 1px color-mix(in srgb, var(--intake-color) 26%, transparent),
      0 0 38px color-mix(in srgb, var(--intake-color) 34%, transparent);
  }
}

@media (prefers-reduced-motion: reduce) {
  .scanline { animation: none; top: 48%; opacity: 0.9; }
  .intake-frame { animation: none; transition: border-color 0.2s, box-shadow 0.2s; }
  .intake-fade-enter-from .intake-frame { transform: none; filter: none; }
}

@media (max-width: 540px) {
  .intake-frame { padding: 2.5rem 1.5rem 2.25rem; }
  .intake-title { font-size: 1.49rem; }
}
</style>
