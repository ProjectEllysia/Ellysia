<template>
  <div class="hygeia-page" data-module="hygeia">
    <StarBackground />
    <Topbar title="Hygeia" badge="Monitorización de Activos" back-to="/hygeia" back-label="Volver" />

    <main class="hygeia-layout" :data-pane="mobilePane">
      <section class="panel panel--list">
        <AssetList
          :assets="store.state.assets"
          :selected-id="store.state.selectedId"
          :loading="store.state.loading"
          :error="store.state.error"
          @select="handleSelect"
          @create="showCreateModal = true"
          @delete="handleDeleteRequest"
          @rotate="handleRotate"
          @toggle-persistent="handleTogglePersistent"
          @refresh="refreshNow"
        />
      </section>

      <section class="panel panel--detail">
        <button class="back-to-list" @click="mobilePane = 'list'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M15 18l-6-6 6-6"/></svg>
          Todos los activos
        </button>
        <AssetDetail
          :asset="selectedAsset"
          :metrics="store.state.metrics"
          :metrics-truncated="store.state.metricsTruncated"
          :metrics-loading="store.state.metricsLoading"
          :metrics-error="store.state.metricsError"
          :latest="store.state.latest"
          :latest-error="store.state.latestError"
          :inventory="store.state.inventory"
          :inventory-collected-at="store.state.inventoryCollectedAt"
          :inventory-loading="store.state.inventoryLoading"
          :inventory-error="store.state.inventoryError"
          :analysis="store.state.analysis"
          :analyzing="store.state.analyzing"
          :anomalies="assetAnomalies"
          @ack="handleAck"
          @resolve="handleResolve"
          @delete="handleDeleteAnomalyRequest"
          @analyze="handleAnalyze"
          @reanalyze="pendingReanalyze = true"
          @view-analysis="showAnalysisModal = true"
        />
      </section>
    </main>

    <CreateAssetModal
      :show="showCreateModal"
      :submitting="creating"
      @submit="handleCreate"
      @close="showCreateModal = false"
    />

    <AgentKeyModal
      :show="!!store.state.lastAgentKey"
      :agent-key="store.state.lastAgentKey || ''"
      @close="store.clearAgentKey()"
    />

    <ConfirmModal
      :show="!!pendingDeleteId"
      title="Eliminar activo"
      message="Se eliminará el activo y se revocará su clave de agente. Los heartbeats que llegue con esa clave dejarán de aceptarse."
      confirm-label="Eliminar"
      danger
      @confirm="handleDeleteConfirm"
      @cancel="pendingDeleteId = null"
    />

    <ConfirmModal
      :show="!!pendingRotateId"
      title="Rotar clave de agente"
      emphasis="¡Cuidado!"
      message="Esta acción revocará la clave de agente actual y deberá sustituirla manualmente (no se preocupe, le entregaremos una clave nueva si acepta). ¿Está seguro de que quiere continuar?"
      confirm-label="Continuar"
      danger
      swap-emphasis
      @confirm="handleRotateConfirm"
      @cancel="pendingRotateId = null"
    />

    <ConfirmModal
      :show="!!pendingDeleteAnomalyId"
      title="Borrar anomalía"
      message="Se eliminará el registro de esta anomalía. Esta acción no se puede deshacer."
      confirm-label="Borrar"
      danger
      @confirm="handleDeleteAnomalyConfirm"
      @cancel="pendingDeleteAnomalyId = null"
    />

    <!-- No advierte de un borrado: el análisis anterior se conserva, y es
         justamente eso lo que permite al motor marcar como corregido lo que
         ya no aparece (correlación de ciclo de vida). -->
    <ConfirmModal
      :show="pendingReanalyze"
      title="Volver a analizar"
      message="Se lanzará un análisis nuevo sobre el inventario actual. El resultado vigente pasará a ser el anterior, y los hallazgos que ya no aparezcan se marcarán como corregidos."
      confirm-label="Analizar"
      @confirm="handleReanalyzeConfirm"
      @cancel="pendingReanalyze = false"
    />

    <InventoryAnalysisModal
      :show="showAnalysisModal"
      :analysis="store.state.analysis"
      @close="showAnalysisModal = false"
      @open-in-themis="goToThemis"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import AssetList from '@/components/hygeia/AssetList.vue'
import AssetDetail from '@/components/hygeia/AssetDetail.vue'
import CreateAssetModal from '@/components/hygeia/CreateAssetModal.vue'
import AgentKeyModal from '@/components/hygeia/AgentKeyModal.vue'
import InventoryAnalysisModal from '@/components/hygeia/InventoryAnalysisModal.vue'
import { usePolling } from '@/composables/usePolling'
import { useHygeiaStore } from '@/stores/hygeiaStore'
import { useHygeiaAlertsStore } from '@/stores/hygeiaAlertsStore'
import { useToastStore } from '@/stores/toastStore'

const store = useHygeiaStore()
const alerts = useHygeiaAlertsStore()
const toast = useToastStore()
const router = useRouter()

const showCreateModal = ref(false)
const creating = ref(false)
const pendingDeleteId = ref(null)
const pendingRotateId = ref(null)
const pendingDeleteAnomalyId = ref(null)
const pendingReanalyze = ref(false)
const showAnalysisModal = ref(false)

const selectedAsset = computed(() =>
  store.state.assets.find((a) => a.id === store.state.selectedId) || null
)

const assetAnomalies = computed(() =>
  alerts.state.anomalies.filter((a) => a.assetId === store.state.selectedId)
)

/**
 * En pantalla estrecha las dos columnas se apilan, y el panel de detalle es
 * largo: al elegir un activo, la lista quedaba arriba del todo y no había
 * forma de volver a ella salvo desplazarse a ciegas. En estrecho se enseña una
 * cosa u otra, con un paso atrás explícito. En ancho no cambia nada: `panel`
 * solo se oculta dentro de la media query.
 */
const mobilePane = ref('list')

async function handleSelect(id) {
  store.selectAsset(id)
  mobilePane.value = 'detail'
  await alerts.fetchAlerts({ assetId: id })
}

async function handleCreate({ hostname, os, isPersistent }) {
  creating.value = true
  try {
    const asset = await store.createAsset({ hostname, os, isPersistent })
    if (asset) {
      showCreateModal.value = false
      toast.show(`Activo «${asset.hostname}» dado de alta.`, 'success')
    } else if (store.state.error) {
      toast.show(store.state.error, 'error')
    }
  } finally {
    creating.value = false
  }
}

/**
 * Alterna si un activo debería estar siempre encendido. Sin confirmación: es
 * reversible con el mismo botón y no destruye nada.
 */
async function handleTogglePersistent(id) {
  const asset = store.state.assets.find((a) => a.id === id)
  if (!asset) return
  const next = !asset.isPersistent
  const ok = await store.setPersistence(id, next)
  if (!ok) {
    toast.show(store.state.error || 'No se pudo actualizar el activo.', 'error')
    return
  }
  toast.show(
    next
      ? `Se volverá a avisar cuando «${asset.hostname}» esté caído.`
      : `«${asset.hostname}» se marca como host que se apaga a propósito: no se avisará de sus caídas.`,
    'success',
  )
}

function handleDeleteRequest(id) {
  pendingDeleteId.value = id
}

async function handleDeleteConfirm() {
  const id = pendingDeleteId.value
  pendingDeleteId.value = null
  if (!id) return
  const ok = await store.deleteAsset(id)
  toast.show(ok ? 'Activo eliminado.' : (store.state.error || 'No se pudo eliminar.'), ok ? 'success' : 'error')
}

function handleRotate(id) {
  pendingRotateId.value = id
}

async function handleRotateConfirm() {
  const id = pendingRotateId.value
  pendingRotateId.value = null
  if (!id) return
  const key = await store.rotateKey(id)
  if (!key) toast.show(store.state.error || 'No se pudo rotar la clave.', 'error')
}

async function handleAck(id) {
  const ok = await alerts.ackAlert(id)
  if (!ok) toast.show(alerts.state.error || 'No se pudo reconocer la anomalía.', 'error')
}

async function handleResolve(id) {
  const ok = await alerts.resolveAlert(id)
  if (!ok) toast.show(alerts.state.error || 'No se pudo resolver la anomalía.', 'error')
}

function handleDeleteAnomalyRequest(id) {
  pendingDeleteAnomalyId.value = id
}

async function handleDeleteAnomalyConfirm() {
  const id = pendingDeleteAnomalyId.value
  pendingDeleteAnomalyId.value = null
  if (!id) return
  const ok = await alerts.deleteAlert(id)
  toast.show(ok ? 'Anomalía eliminada.' : (alerts.state.error || 'No se pudo borrar la anomalía.'), ok ? 'success' : 'error')
}

/* ── Análisis del inventario con Lybra (Fase I) ── */

async function handleAnalyze() {
  const id = store.state.selectedId
  if (!id) return
  const scanId = await store.analyzeInventory(id)
  toast.show(
    scanId ? `Análisis iniciado (escaneo ${scanId}). El resumen se actualizará al terminar.`
           : (store.state.analysisError || 'No se pudo lanzar el análisis.'),
    scanId ? 'success' : 'error',
  )
}

async function handleReanalyzeConfirm() {
  pendingReanalyze.value = false
  await handleAnalyze()
}

/** Salta al desglose completo en Themis, en el mundo de agentes y con la
 *  tarjeta de este activo ya seleccionada. */
function goToThemis() {
  const id = store.state.selectedId
  showAnalysisModal.value = false
  // /themis es el hub, que ignora estos parámetros: quien los lee es
  // ThemisView, en /themis/escaneos (ver su onMounted). Apuntando al hub, el
  // enlace aterrizaba en la portada del módulo y perdía activo y mundo, justo
  // el contexto que este botón existe para llevar.
  router.push({ path: '/themis/escaneos', query: { world: 'agents', asset: id } })
}

/**
 * Cadencia del sondeo en vivo. El agente late cada 15 s por defecto
 * (`hygeia.heartbeatIntervalSec`), así que refrescar a ese ritmo mantiene la
 * vista al día sin pedir más de lo que hay: en una vista de monitorización,
 * un panel congelado es indistinguible de un host caído.
 */
const POLL_MS = 15000

/** Refresco manual (botón de recargar): sí muestra el estado de carga. */
async function refreshNow() {
  await store.fetchAssets()
  const id = store.state.selectedId
  if (!id) return
  await Promise.all([
    store.fetchMetrics(id),
    store.fetchLatest(id),
    store.fetchInventory(id),
    store.fetchAnalysis(id),
  ])
}

/** Refresco periódico: silencioso, para no parpadear cada 15 s.
 *
 * E8: el `if (document.hidden) return` que había aquí lo aporta ahora
 * `usePolling` con `pauseWhenHidden` — y además reanuda de inmediato al
 * volver a primer plano, en vez de esperar los 15 s completos. */
/**
 * Cada cosa se re-pide al ritmo al que de verdad cambia.
 *
 * Antes las cuatro lecturas iban en cada vuelta: 4 × 240 vueltas/hora = 960
 * peticiones/hora contra un límite de 600, así que la propia vista se dejaba
 * sin cupo en menos de 40 minutos. Bajar la cadencia no valía —el agente late
 * cada 15 s y un panel congelado no se distingue de un host caído—, así que lo
 * que se escalona es cada lectura por separado:
 *
 *   latest   cada vuelta (15 s) — es el pulso: los números en vivo
 *   metrics  cada 2 vueltas (30 s) — la serie del gráfico, que dibuja una
 *            tendencia; un punto de más o de menos no se aprecia
 *   alerts   cada 4 vueltas (60 s) — lo crítico ya avisa por correo aparte
 *   assets   cada 4 vueltas (60 s) — la lista cambia al dar de alta o de baja
 *
 * Total: 480 peticiones/hora en vez de 960, con el pulso igual de vivo.
 */
const METRICS_EVERY = 2
const SLOW_EVERY = 4
let pollTick = 0

async function poll() {
  const tick = pollTick++
  const tasks = []

  if (tick % SLOW_EVERY === 0) tasks.push(store.fetchAssets({ silent: true }))

  const id = store.state.selectedId
  if (id) {
    tasks.push(store.fetchLatest(id))
    if (tick % METRICS_EVERY === 0) tasks.push(store.fetchMetrics(id, { silent: true }))
    if (tick % SLOW_EVERY === 0) tasks.push(alerts.fetchAlerts({ assetId: id }))
    // El análisis solo se re-pide mientras hay uno corriendo: es un escaneo
    // puntual lanzado a mano, no un dato vivo como las métricas, así que
    // sondearlo siempre sería una petición de más cada 15 s por nada.
    if (['pending', 'running'].includes(store.state.analysis?.status)) {
      tasks.push(store.fetchAnalysis(id, { silent: true }))
    }
  }

  await Promise.all(tasks)
}

// usePolling se llama en el setup, no dentro de onMounted: así puede
// engancharse a onUnmounted él solo y no hace falta parar nada a mano.
const poller = usePolling(poll, { intervalMs: POLL_MS, immediate: false })

onMounted(async () => {
  await store.fetchAssets()
  if (store.state.assets.length) {
    await handleSelect(store.state.assets[0].id)
  }
  poller.start()
})
</script>

<style scoped>
.hygeia-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.hygeia-layout {
  position: relative;
  z-index: 1;
  display: grid;
  grid-template-columns: minmax(280px, 340px) minmax(0, 1fr);
  gap: 1.25rem;
  max-width: 1180px;
  margin: 0 auto;
  padding: 1.5rem 1.5rem 3rem;
  align-items: start;
}

.panel {
  background: var(--surface);
  border: 1px solid var(--border-med);
  border-radius: var(--radius, 10px);
  padding: 1.1rem 1.2rem;
}

/* En ancho no existe: las dos columnas se ven a la vez y no hay a dónde volver. */
.back-to-list { display: none; }

@media (max-width: 960px) {
  .hygeia-layout { grid-template-columns: 1fr; }

  /* Maestro-detalle: una cosa cada vez, con paso atrás explícito. */
  .hygeia-layout[data-pane="detail"] .panel--list { display: none; }
  .hygeia-layout[data-pane="list"]   .panel--detail { display: none; }

  .back-to-list {
    display: inline-flex; align-items: center; gap: 0.35rem;
    margin-bottom: 0.9rem; padding: 0.35rem 0.6rem 0.35rem 0.4rem;
    background: var(--surface-2);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    color: var(--text-dim); font-size: var(--fs-md); font-weight: 500;
    transition: color var(--transition), border-color var(--transition);
  }
  .back-to-list:hover { color: var(--text); border-color: var(--accent); }
  .back-to-list svg { width: 15px; height: 15px; }
}
</style>
