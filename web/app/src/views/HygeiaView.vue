<template>
  <div class="hygeia-page" data-module="hygeia">
    <StarBackground />
    <Topbar title="Hygeia" badge="Monitorización de Activos" back-to="/hygeia" back-label="Volver" />

    <main class="hygeia-layout">
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
          @refresh="refreshNow"
        />
      </section>

      <section class="panel panel--detail">
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

async function handleSelect(id) {
  store.selectAsset(id)
  await alerts.fetchAlerts({ assetId: id })
}

async function handleCreate({ hostname, os }) {
  creating.value = true
  try {
    const asset = await store.createAsset({ hostname, os })
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
  router.push({ path: '/themis', query: { world: 'agents', asset: id } })
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
async function poll() {
  await store.fetchAssets({ silent: true })
  const id = store.state.selectedId
  if (!id) return
  const tasks = [
    store.fetchMetrics(id, { silent: true }),
    store.fetchLatest(id),
    alerts.fetchAlerts({ assetId: id }),
  ]
  // El análisis solo se re-pide mientras hay uno corriendo: es un escaneo
  // puntual lanzado a mano, no un dato vivo como las métricas, así que
  // sondearlo siempre sería una petición de más cada 15 s por nada.
  if (['pending', 'running'].includes(store.state.analysis?.status)) {
    tasks.push(store.fetchAnalysis(id, { silent: true }))
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

@media (max-width: 900px) {
  .hygeia-layout { grid-template-columns: 1fr; }
}
</style>
