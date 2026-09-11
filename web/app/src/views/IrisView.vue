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
            {{ rejecting ? 'Solo se admiten archivos .eml, .msg o un ZIP' : 'Suelta el correo (o varios) para examinarlo' }}
          </h2>
          <span class="intake-chip">.eml · .msg · .zip</span>
        </div>
      </div>
    </Transition>

    <div class="iris-layout">
      <div v-if="store.listError" class="history-error-banner">
        {{ store.listError }}
        <button type="button" @click="store.fetchResults()">Reintentar</button>
      </div>
      <IrisHistoryStrip
        :items="store.analyses"
        :active-id="store.currentId"
        :total="store.totalCount"
        @select="store.selectAnalysis"
        @delete="handleDelete"
        @open-archive="archiveOpen = true"
      />

      <IrisBatchPanel :batch="store.currentBatch" @close="store.closeBatch()" @open="store.selectAnalysis" />

      <IrisArchiveModal
        :show="archiveOpen"
        @close="archiveOpen = false"
        @select="store.selectAnalysis"
      />

      <router-link to="/iris/conexiones" class="back-link connections-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <rect x="2" y="4" width="20" height="16" rx="2" />
          <path d="m2 7 10 6 10-6" />
        </svg>
        Conexiones de buzón
      </router-link>
      <router-link to="/iris/confianza" class="back-link connections-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        Remitentes de confianza
      </router-link>
      <router-link to="/iris/casos" class="back-link connections-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <rect x="3" y="7" width="18" height="13" rx="2" /><path d="M8 7V5a2 2 0 012-2h4a2 2 0 012 2v2" />
        </svg>
        Casos
      </router-link>

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
              @batch="handleBatch"
            />
          </template>
        </IrisReportViewer>
      </main>
    </div>
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, computed, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import IrisHistoryStrip from '@/components/iris/IrisHistoryStrip.vue'
import IrisArchiveModal from '@/components/iris/IrisArchiveModal.vue'
import IrisReportViewer from '@/components/iris/IrisReportViewer.vue'
import IrisForm from '@/components/iris/IrisForm.vue'
import IrisBatchPanel from '@/components/iris/IrisBatchPanel.vue'
import { useIrisStore } from '@/stores/irisStore'
import { useToastStore } from '@/stores/toastStore'
import { parseEml } from '@/composables/useEml'
import { classifyIntake, formatByteLimit, isBatchDrop } from '@/components/iris/intake.js'

const store = useIrisStore()
const toast = useToastStore()
const formKey = ref(0)
const archiveOpen = ref(false)

// Relleno automático del formulario a partir de un .eml arrastrado.
const prefill = ref(null)

// Enviamos el .eml completo (cuerpo, enlaces, adjuntos) para que las
// reglas de contenido puedan analizarlo.
//
// El tope ya no se escribe aquí. Era `20 * 1024 * 1024` mientras el
// backend aplicaba 10 MiB, así que la vista aceptaba ficheros que el API iba
// a rechazar — después de haberlos leído enteros en memoria. Ahora sale de
// `GET /iris/capabilities` y la decisión vive en `intake.js`, que es puro y
// está cubierto por `npm run test:iris`.

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

  const files = Array.from(e.dataTransfer?.files ?? [])
  // Varios ficheros, un ZIP o un .msg van a lote: el servidor decide qué entra.
  if (isBatchDrop(files)) {
    await handleBatch(files)
    return
  }
  const file = files[0]
  if (!file) return

  const capabilities = await store.fetchCapabilities()
  const intake = classifyIntake(file, capabilities)
  if (!intake.accepted) {
    flashReject()
    toast.show('Solo se aceptan archivos .eml, .msg o un ZIP', 'error')
    return
  }

  try {
    const tooBig = intake.headersOnly
    const text = await (tooBig ? file.slice(0, intake.limit) : file).text()
    const { rawHeaders, subject } = parseEml(text)
    if (!rawHeaders) {
      flashReject()
      toast.show('No se pudieron leer las cabeceras del correo.', 'error')
      return
    }
    // Conservamos el mensaje completo (cuerpo, enlaces, adjuntos) para que
    // Iris pueda aplicar las reglas de contenido; si el archivo se truncó por
    // tamaño, solo enviamos las cabeceras extraídas como respaldo.
    prefill.value = {
      headers: rawHeaders,
      message: tooBig ? null : text,
      title: subject || '',
      token: Date.now(),
    }
    if (store.currentId || store.currentReport.data) store.selectAnalysis(null)
    if (tooBig) {
      const readable = formatByteLimit(intake.limit)
      toast.show(
        `El archivo supera el máximo que admite el servidor${readable ? ` (${readable})` : ''}: `
        + 'solo se analizarán las cabeceras.',
        'info',
      )
    } else {
      toast.show('Correo cargado.', 'success')
    }
  } catch {
    flashReject()
    toast.show('No se pudo leer el archivo.', 'error')
  }
}

// Ctrl/Cmd+K abre el archivo desde cualquier punto de la vista — el resto
// de atajos (Esc, "/", flechas, Enter) viven dentro de IrisArchiveModal
// mismo, que solo escucha mientras está abierto.
function handleGlobalShortcut(e) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    archiveOpen.value = true
  }
}

onBeforeUnmount(() => {
  clearTimeout(rejectTimer)
  store.stopPolling()
  store.stopDocumentPolling()
  store.closeBatch()
  window.removeEventListener('keydown', handleGlobalShortcut)
})

onMounted(async () => {
  window.addEventListener('keydown', handleGlobalShortcut)
  // Los limites del servidor se piden al entrar, no al soltar un fichero: asi
  // el arrastre decide con el valor real desde el primer intento en vez de
  // caer al respaldo mientras la peticion esta en vuelo.
  store.fetchCapabilities()
  await store.fetchResults()
  const last = store.analyses[0]
  if (last && (last.status === 'running' || last.status === 'pending')) {
    store.selectAnalysis(last.analysisId)
  }
})

async function handleSubmit(submission) {
  const id = await store.submitAnalysis(submission)
  if (id) {
    prefill.value = null
    formKey.value++
  }
}

/** Envía un lote de .eml, .msg o ZIP y deja el panel del lote a la vista. */
async function handleBatch(files) {
  if (store.batchSubmitting) return
  await store.submitBatch(files)
}

async function handleCancel() {
  if (store.currentId) {
    await store.cancelAnalysis(store.currentId)
  }
}

async function handleDelete(id) {
  await store.deleteAnalysis(id)
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

/* .back-link ya trae tipografía/color/hover del sistema de diseño
   (assets/css/shared.css) — solo se ajusta la posición dentro del layout. */
.connections-link {
  align-self: flex-end;
  margin: 0.5rem 1rem 0;
  flex-shrink: 0;
}

.history-error-banner {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.5rem 1rem;
  color: var(--danger);
  background: var(--danger-dim);
  font-size: var(--fs-md);
  flex-shrink: 0;
}
.history-error-banner button {
  border: 1px solid var(--danger);
  background: transparent;
  color: var(--danger);
  border-radius: 6px;
  padding: 0.2rem 0.6rem;
  font-size: var(--fs-sm);
  font-weight: 600;
  cursor: pointer;
}
.history-error-banner button:hover { background: var(--danger); color: #fff; }

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
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  letter-spacing: 0.28em;
  text-transform: uppercase;
  color: var(--intake-color);
  transition: color 0.25s;
}

.intake-title {
  margin: 0.1rem 0 0.6rem;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-xl);
  font-weight: 700;
  line-height: 1.25;
  text-align: center;
  color: var(--text);
  letter-spacing: -0.01em;
}

.intake-chip {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-lg);
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
  .intake-title { font-size: var(--fs-lg); }
}
</style>
