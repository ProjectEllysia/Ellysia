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
          :anomalies="assetAnomalies"
          @ack="handleAck"
          @resolve="handleResolve"
          @delete="handleDeleteAnomalyRequest"
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
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import AssetList from '@/components/hygeia/AssetList.vue'
import AssetDetail from '@/components/hygeia/AssetDetail.vue'
import CreateAssetModal from '@/components/hygeia/CreateAssetModal.vue'
import AgentKeyModal from '@/components/hygeia/AgentKeyModal.vue'
import { useHygeiaStore } from '@/stores/hygeiaStore'
import { useHygeiaAlertsStore } from '@/stores/hygeiaAlertsStore'
import { useToastStore } from '@/stores/toastStore'

const store = useHygeiaStore()
const alerts = useHygeiaAlertsStore()
const toast = useToastStore()

const showCreateModal = ref(false)
const creating = ref(false)
const pendingDeleteId = ref(null)
const pendingRotateId = ref(null)
const pendingDeleteAnomalyId = ref(null)

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

/**
 * Cadencia del sondeo en vivo. El agente late cada 15 s por defecto
 * (`hygeia.heartbeatIntervalSec`), así que refrescar a ese ritmo mantiene la
 * vista al día sin pedir más de lo que hay: en una vista de monitorización,
 * un panel congelado es indistinguible de un host caído.
 */
const POLL_MS = 15000
let pollId = null

/** Refresco manual (botón de recargar): sí muestra el estado de carga. */
async function refreshNow() {
  await store.fetchAssets()
  const id = store.state.selectedId
  if (!id) return
  await Promise.all([
    store.fetchMetrics(id),
    store.fetchLatest(id),
    store.fetchInventory(id),
  ])
}

/** Refresco periódico: silencioso, para no parpadear cada 15 s. */
async function poll() {
  if (document.hidden) return
  await store.fetchAssets({ silent: true })
  const id = store.state.selectedId
  if (!id) return
  await Promise.all([
    store.fetchMetrics(id, { silent: true }),
    store.fetchLatest(id),
    alerts.fetchAlerts({ assetId: id }),
  ])
}

onMounted(async () => {
  await store.fetchAssets()
  if (store.state.assets.length) {
    await handleSelect(store.state.assets[0].id)
  }
  pollId = setInterval(poll, POLL_MS)
})

onUnmounted(() => { if (pollId) clearInterval(pollId) })
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
