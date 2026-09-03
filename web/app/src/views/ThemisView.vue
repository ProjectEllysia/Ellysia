<template>
  <div class="themis-page" data-module="themis">
    <StarBackground />
    <Topbar title="Themis" badge="Escaneos de Vulnerabilidades" back-to="/themis" back-label="Volver" />

    <main class="main">
      <!-- Toggle de dos mundos: el motor propio vs los escáneres externos -->
      <div class="world-toggle" role="tablist" aria-label="Modo de Themis">
        <button class="world-opt" :class="{ active: store.world === 'lybra' }" role="tab" :aria-selected="store.world === 'lybra'" @click="store.setWorld('lybra')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3v18M7 21h10M5 7h14M5 7l-2.5 5a3 3 0 0 0 5 0L5 7zM19 7l-2.5 5a3 3 0 0 0 5 0L19 7z"/></svg>
          <span class="world-label">Motor Lybra</span>
        </button>
        <button class="world-opt" :class="{ active: store.world === 'external' }" role="tab" :aria-selected="store.world === 'external'" @click="store.setWorld('external')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
          <span class="world-label">Escáneres externos</span>
        </button>
        <button class="world-opt" :class="{ active: store.world === 'agents' }" role="tab" :aria-selected="store.world === 'agents'" @click="store.setWorld('agents')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          <span class="world-label">Agentes</span>
        </button>
      </div>

      <!-- Sin Transition envolvente aquí a propósito: es un cambio de "mundo"
           completo (motor propio vs. escáneres externos), árboles grandes y
           con formas muy distintas. mode="out-in" obligaba a esperar a que
           el mundo saliente terminara de desvanecerse (~120ms) antes si
           quiera de empezar a montar el entrante, sumando ambos tiempos y
           haciendo el cambio notablemente lento. Un swap instantáneo aquí
           se lee como cambiar de pestaña, no como una transición de
           contenido — la animación se reserva para cambios más pequeños
           dentro de un mismo mundo (view-block de abajo). -->
      <!-- ═══════════ MUNDO: MOTOR LYBRA ═══════════ -->
      <div v-if="store.world === 'lybra'" key="lybra" class="world-block">
        <button class="lybra-history-toggle" @click="store.setViewMode(store.viewMode === 'history' ? 'full' : 'history')">
          {{ store.viewMode === 'history' ? '← Volver al motor' : 'Ver historial' }}
        </button>
        <HistoryPanel v-if="store.viewMode === 'history'" />
        <template v-else>
          <!-- La detección por versión vale lo que valga la frescura del espejo
               local de NVD/KEV/EPSS. Si deja de refrescarse, los escaneos siguen
               saliendo en verde contra un catálogo congelado: el aviso existe
               para que eso deje de ser invisible. -->
          <div v-if="store.kbStatus.loaded && store.kbStatus.isStale" class="kb-stale">
            <strong>Base de conocimiento desactualizada.</strong>
            {{ staleSourcesLabel }} Los hallazgos por versión se resuelven contra ese catálogo,
            así que un CVE publicado después no aparecerá y la ausencia de hallazgos no es
            concluyente.
          </div>
          <LybraLaunchPanel
            :launching="store.launching"
            :launched="hasActiveLybraScan"
            :authorized-targets="store.authorizedTargets.items"
            :auth-targets-loading="store.authorizedTargets.loading"
            @launch="handleLaunchLybra"
            @add-authorized-target="handleAddAuthorizedTarget"
            @remove-authorized-target="store.removeAuthorizedTarget" />
          <LybraResults
            :scans="store.scans.lybra.results"
            :loading="store.scans.lybra.loading"
            :total-count="store.scans.lybra.totalCount"
            :docs-by-scan="store.lybraDocs"
            :groups-by-scan="store.lybraGroups"
            @refresh="store.loadLybraScans()"
            @load-more="store.loadMoreLybraScans()"
            @load-groups="store.loadLybraGroups"
            @delete="handleDeleteLybra"
            @load-docs="store.loadLybraDocs"
            @generate-pdf="handleLybraGeneratePdf"
            @download-doc="store.downloadDocument"
            @delete-doc="handleLybraDeleteDoc" />
          <ScheduledScansPanel :scheduled="scheduledStore.scheduled" :scheduling="scheduledStore.scheduling" active-tab="lybra"
            @create="handleCreateScheduled" @deactivate="handleDeactivateScheduled" @delete="handleDeleteScheduled" @toggle-form="scheduledStore.toggleScheduledForm()" />
        </template>
      </div>

      <!-- ═══════════ MUNDO: AGENTES (Fase I) ═══════════ -->
      <div v-else-if="store.world === 'agents'" key="agents" class="world-block">
        <AgentScansPanel
          :assets="hygeiaStore.state.assets"
          :assets-loading="hygeiaStore.state.loading"
          :selected-asset-id="store.selectedAssetId"
          :scans="store.scans.agentLybra.results"
          :loading="store.scans.agentLybra.loading"
          :total-count="store.scans.agentLybra.totalCount"
          :docs-by-scan="store.lybraDocs"
          :groups-by-scan="store.lybraGroups"
          @select="store.selectAgentAsset"
          @refresh-assets="hygeiaStore.fetchAssets()"
          @refresh-scans="store.loadAgentScans()"
          @load-more="store.loadMoreLybraScans('agentLybra')"
          @load-groups="store.loadLybraGroups"
          @delete="handleDeleteAgentScan"
          @load-docs="store.loadLybraDocs"
          @generate-pdf="handleLybraGeneratePdf"
          @download-doc="store.downloadDocument"
          @delete-doc="handleLybraDeleteDoc" />
      </div>

      <!-- ═══════════ MUNDO: ESCÁNERES EXTERNOS ═══════════ -->
      <div v-else key="external" class="world-block">
      <StatsRow :total="store.stats.total" :nmap="store.stats.nmap" :nikto="store.stats.nikto" :nuclei="store.stats.nuclei" />
      <ViewToggle :model-value="store.viewMode" @update:model-value="store.setViewMode" />
      <Transition name="fade-swap" mode="out-in" appear>
        <div v-if="store.viewMode === 'full'" key="full" class="view-block">
          <ScanTabs :active="store.activeTab" @switch="handleTabSwitch" />
          <ScanForm :type="store.activeTab" :launching="store.launching" :launched="hasActiveScan" @launch="handleLaunch" />
          <ScanTable :type="store.activeTab" :rows="currentData.results" :loading="currentData.loading" :error="currentData.error" :current-page="currentData.page" :total-count="currentData.totalCount" :per-page="currentData.perPage" :selected-ids="batchSelectedArray"
            @preview="(id, type) => store.openPreview(id, type)" @cancel="handleCancel" @delete="handleDelete" @refresh="store.refreshCurrent()" @page-change="page => store.goToPage(store.activeTab, page)"
            @toggle-select="batchToggle" @select-all="batchSelectAll">
            <template #batch-actions="{ selectedCount }">
              <button v-if="selectedCount > 0" class="batch-btn" @click="openBatchAction('add-to-folder')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                Añadir a carpeta ({{ selectedCount }})
              </button>
              <button v-if="selectedCount > 0" class="batch-btn danger" @click="openBatchAction('bulk-delete')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
                Eliminar ({{ selectedCount }})
              </button>
            </template>
          </ScanTable>
          <ScheduledScansPanel :scheduled="scheduledStore.scheduled" :scheduling="scheduledStore.scheduling" :active-tab="store.activeTab" @create="handleCreateScheduled" @deactivate="handleDeactivateScheduled" @delete="handleDeleteScheduled" @toggle-form="scheduledStore.toggleScheduledForm()" />
        </div>
        <ScanFolderView v-else-if="store.viewMode === 'folders'" key="folders"
          :folders="foldersStore.folders.items" :loading="foldersStore.folders.loading"
          @refresh="foldersStore.loadFolders()"
          @preview="(id, type) => store.openPreview(id, type)"
          @cancel="handleCancel"
          @delete="handleDelete"
          @create-folder="foldersStore.folderForms.create.show = true"
          @rename-folder="handleRenameFolder"
          @delete-folder="handleDeleteFolder"
          @move-scan="handleOpenMoveScan"
          @remove-scan="handleRemoveScan" />
        <HistoryPanel v-else-if="store.viewMode === 'history'" key="history" />
      </Transition>
      </div>
    </main>

    <ScanPreviewModal :show="store.preview.show" :scan="store.preview.scan" :type="store.preview.type" :docs="store.preview.docs" :docs-loading="store.preview.docsLoading"
      :traceroute="store.preview.traceroute" :traceroute-loading="store.preview.tracerouteLoading"
      @close="store.closePreview()" @refresh-docs="store.refreshPreviewDocs()" @download-doc="store.downloadDocument" @delete-doc="handleDeletePreviewDoc" @generate-pdf="handlePreviewPdf" @refresh-traceroute="store.loadPreviewTraceroute(true)" />

    <FolderFormModal
      :key="'create-folder'"
      :show="foldersStore.folderForms.create.show"
      title="Nueva carpeta"
      :submitting="foldersStore.folderForms.create.submitting"
      @close="foldersStore.folderForms.create.show = false"
      @submit="async name => { if (await foldersStore.createFolder(name)) foldersStore.folderForms.create.show = false }" />
    <FolderFormModal
      :key="'rename-folder'"
      :show="foldersStore.folderForms.rename.show"
      title="Renombrar carpeta"
      :initial-name="foldersStore.folderForms.rename.name"
      :submitting="foldersStore.folderForms.rename.submitting"
      @close="foldersStore.folderForms.rename.show = false"
      @submit="async name => { if (await foldersStore.renameFolder(foldersStore.folderForms.rename.folderId, name)) foldersStore.folderForms.rename.show = false }" />
    <MoveScanModal
      :key="'move-scan'"
      :show="foldersStore.moveScan.show"
      :scan-id="foldersStore.moveScan.scanId"
      :current-folder-id="foldersStore.moveScan.folderId"
      :folders="foldersStore.folders.items"
      :submitting="foldersStore.moveScan.submitting"
      @close="foldersStore.closeMoveScan()"
      @move="async folderId => { if (await foldersStore.moveScanToFolder(foldersStore.moveScan.scanId, folderId)) foldersStore.closeMoveScan() }" />

    <BatchActionModal
      :show="activeBatchAction === 'add-to-folder'"
      title="Añadir a carpeta"
      action-label="Añadir a carpeta"
      :selected-count="batchSelectedCount"
      :submitting="batchSubmitting"
      :can-submit="!!selectedFolderId"
      @close="closeBatchAction"
      @confirm="handleBatchAddToFolder">
      <template #content>
        <label for="target-folder">Selecciona una carpeta</label>
        <select id="target-folder" v-model="selectedFolderId" :disabled="batchSubmitting" required>
          <option value="" disabled>-- Elige carpeta --</option>
          <option v-for="folder in selectableFolders" :key="folder.id" :value="folder.id">{{ folder.name }}</option>
        </select>
      </template>
    </BatchActionModal>

    <BatchActionModal
      :show="activeBatchAction === 'bulk-delete'"
      title="Eliminar escaneos"
      action-label="Eliminar"
      :selected-count="batchSelectedCount"
      :submitting="batchSubmitting"
      :can-submit="true"
      @close="closeBatchAction"
      @confirm="handleBatchDelete">
      <template #content>
        <p class="batch-warning">Esta accion eliminara permanentemente los escaneos seleccionados y sus documentos PDF asociados.</p>
        <p class="batch-warning-sub">Los escaneos en ejecucion se cancelaran antes de ser eliminados.</p>
      </template>
    </BatchActionModal>
    <ConfirmModal
      :show="!!pendingConfirm"
      title="Eliminar"
      :message="pendingConfirm?.type === 'delete-lybra'
        ? '¿Eliminar este escaneo Lybra y sus hallazgos?'
        : pendingConfirm?.type === 'delete-agent-scan'
          ? '¿Eliminar este análisis de inventario y sus hallazgos? El activo de Hygeia no se borra.'
          : '¿Eliminar esta carpeta? Los escaneos no se borrarán, solo quedarán sin carpeta.'"
      confirm-label="Eliminar"
      danger
      @confirm="runPendingConfirm"
      @cancel="pendingConfirm = null" />
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, ref, computed, watch } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import StatsRow from '@/components/themis/StatsRow.vue'
import ViewToggle from '@/components/themis/ViewToggle.vue'
import ScanTabs from '@/components/themis/ScanTabs.vue'
import ScanForm from '@/components/themis/ScanForm.vue'
import ScanTable from '@/components/themis/ScanTable.vue'
import ScanFolderView from '@/components/themis/ScanFolderView.vue'
import HistoryPanel from '@/components/themis/HistoryPanel.vue'
import ScanPreviewModal from '@/components/themis/ScanPreviewModal.vue'
import FolderFormModal from '@/components/themis/FolderFormModal.vue'
import MoveScanModal from '@/components/themis/MoveScanModal.vue'
import BatchActionModal from '@/components/themis/BatchActionModal.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import ScheduledScansPanel from '@/components/themis/ScheduledScansPanel.vue'
import LybraLaunchPanel from '@/components/themis/lybra/LybraLaunchPanel.vue'
import LybraResults from '@/components/themis/lybra/LybraResults.vue'
import AgentScansPanel from '@/components/themis/lybra/AgentScansPanel.vue'
import { useRoute } from 'vue-router'
import { useThemisStore } from '@/stores/themisStore'
import { useThemisScheduledStore } from '@/stores/themisScheduledStore'
import { useThemisFoldersStore } from '@/stores/themisFoldersStore'
// Las tarjetas del mundo de agentes son los activos de Hygeia. La vista
// consume el store del otro módulo directamente: es una lectura que ya
// existe, y así el backend de Themis sigue sin saber que Hygeia existe.
import { useHygeiaStore } from '@/stores/hygeiaStore'
import { useBatchSelection } from '@/composables/useBatchSelection'

const route = useRoute()
const store = useThemisStore()
const scheduledStore = useThemisScheduledStore()
const foldersStore = useThemisFoldersStore()
const hygeiaStore = useHygeiaStore()
const { selectedIds: batchSelectedIds, selectedCount: batchSelectedCount, selectedArray: batchSelectedArray, toggle: batchToggle, selectAll: batchSelectAll, clear: batchClear } = useBatchSelection()
const currentData = computed(() => store.scans[store.activeTab])

// Q8: antes ScanForm/LybraLaunchPanel llevaban su propio `launched` local
// que se ponía a true al lanzar y nunca volvía a false (o solo al cambiar
// de pestaña) — el badge "Escaneo iniciado"/"Motor en marcha" quedaba fijo.
// Se deriva del estado real (¿hay algún escaneo pending/running?), que el
// polling de C2 ya mantiene fresco.
const hasActiveScan = computed(() =>
  currentData.value.results.some(s => s.status === 'pending' || s.status === 'running')
)
/** Las fuentes viejas, en una frase legible para el aviso. */
const staleSourcesLabel = computed(() => {
  const stale = store.kbStatus.sources.filter(s => s.isStale)
  const parts = stale.map(s => s.neverSynced
    ? `${s.source.toUpperCase()} nunca se ha sincronizado`
    : `${s.source.toUpperCase()} lleva ${s.ageDays} días sin actualizarse`)
  return parts.length ? `${parts.join('; ')}.` : ''
})

const hasActiveLybraScan = computed(() =>
  store.scans.lybra.results.some(s => s.status === 'pending' || s.status === 'running')
)

const activeBatchAction = ref(null)
const batchSubmitting = ref(false)
const selectedFolderId = ref('')

const selectableFolders = computed(() =>
  foldersStore.folders.items.filter(f => f.id !== null)
)

// El store es un singleton de Pinia que sobrevive a la navegación dentro de
// la SPA: si el usuario cambió a "escáneres externos" y vuelve a entrar a
// Themis después, sin esto vería el mundo que dejó seleccionado la vez
// anterior en vez de entrar siempre por Lybra (el motor propio, protagonista
// del roadmap). El hub de Themis puede forzar un mundo/vista concretos vía
// query params (?world=external&view=history) para sus atajos rápidos.
onMounted(() => {
  const world = ['external', 'agents'].includes(route.query.world) ? route.query.world : 'lybra'
  store.setWorld(world)
  if (route.query.view === 'history' || route.query.view === 'folders') store.setViewMode(route.query.view)
  // ?asset=N (el salto desde el modal de Hygeia) preselecciona esa tarjeta.
  const assetId = Number(route.query.asset)
  if (world === 'agents' && Number.isInteger(assetId) && assetId > 0) store.selectAgentAsset(assetId)
  store.loadStats(); store.loadScans(store.activeTab); scheduledStore.loadScheduledScans(); foldersStore.loadFolders()
})
onBeforeUnmount(() => store.stopScanPolling())

// Lybra (escaneos propios + objetivos autorizados) se carga la primera vez
// que se entra a su mundo; los agentes, en cambio, se refrescan a cada
// entrada: sus tarjetas muestran el contador de hallazgos del último
// análisis, un dato que nace en Hygeia al margen de Themis — un re-análisis
// cerrado mientras se estaba en otro mundo no llegaría nunca a la rejilla
// si la lista no se volviera a pedir.
let lybraLoaded = false
watch(() => store.world, (w) => {
  if (w === 'lybra' && !lybraLoaded) {
    lybraLoaded = true
    store.loadKbStatus()
    store.loadLybraScans()
    store.loadAuthorizedTargets()
  }
  if (w === 'agents') hygeiaStore.fetchAssets()
}, { immediate: true })

async function handleLaunchLybra(payload) { await store.launchLybra(payload) }
function handleDeleteLybra(id) { pendingConfirm.value = { type: 'delete-lybra', id } }
function handleDeleteAgentScan(id) { pendingConfirm.value = { type: 'delete-agent-scan', id } }
async function handleLybraGeneratePdf(scanId, useAi) { await store.generateLybraPdf(scanId, useAi) }
async function handleLybraDeleteDoc(scanId, docId) { await store.deleteLybraDoc(scanId, docId) }
async function handleAddAuthorizedTarget({ target, label }) { await store.addAuthorizedTarget(target, label) }

watch(activeBatchAction, (val) => {
  if (!val) { selectedFolderId.value = ''; batchSubmitting.value = false }
})

function openBatchAction(action) {
  if (action === 'add-to-folder') foldersStore.loadFolders()
  activeBatchAction.value = action
}

function closeBatchAction() {
  if (batchSubmitting.value) return
  activeBatchAction.value = null
}

async function handleBatchAddToFolder() {
  if (!selectedFolderId.value || batchSubmitting.value) return
  batchSubmitting.value = true
  const ok = await foldersStore.addScansToFolder(batchSelectedArray.value, Number(selectedFolderId.value))
  batchSubmitting.value = false
  if (ok) { batchClear(); closeBatchAction() }
}

async function handleBatchDelete() {
  if (batchSubmitting.value) return
  batchSubmitting.value = true
  const ok = await store.bulkDeleteScans(batchSelectedArray.value)
  batchSubmitting.value = false
  if (ok) { batchClear(); closeBatchAction() }
}

function handleTabSwitch(type) {
  batchClear()
  store.switchTab(type)
}

async function handleCancel(id) { await store.cancelScan(id) }
async function handleDelete(id) { await store.deleteScan(id) }
function handleLaunch(payload) { const fns = { nmap: store.launchNmap, nikto: store.launchNikto, nuclei: store.launchNuclei }; const fn = fns[store.activeTab]; if (fn) fn(payload) }
function handleRenameFolder(folder) { foldersStore.folderForms.rename = { show: true, folderId: folder.id, name: folder.name, submitting: false } }
function handleDeleteFolder(folderId) { pendingConfirm.value = { type: 'delete-folder', id: folderId } }

// Q7: modal propio en vez de confirm() nativo del navegador.
const pendingConfirm = ref(null) // { type: 'delete-lybra'|'delete-agent-scan'|'delete-folder', id }
async function runPendingConfirm() {
  const action = pendingConfirm.value
  pendingConfirm.value = null
  if (!action) return
  if (action.type === 'delete-lybra') await store.deleteLybraScan(action.id)
  else if (action.type === 'delete-agent-scan') await store.deleteLybraScan(action.id, 'agentLybra')
  else if (action.type === 'delete-folder') await foldersStore.deleteFolder(action.id)
}
function handleOpenMoveScan(scanId, folderId) { foldersStore.openMoveScan(scanId, folderId) }
async function handleRemoveScan(scanId, folderId) { await foldersStore.removeScanFromFolder(scanId, folderId) }
async function handlePreviewPdf(id, type, useAi) {
  const started = await store.generatePdf(id, useAi)
  if (started) await store.waitForDocument(id)
  await store.refreshCurrent()
  await store.refreshPreviewDocs()
}

async function handleDeletePreviewDoc(docId) { await store.deleteDocument(docId); await store.refreshPreviewDocs() }

async function handleCreateScheduled(payload) { await scheduledStore.createScheduledScan(payload) }
async function handleDeactivateScheduled(id) { await scheduledStore.deactivateScheduledScan(id) }
async function handleDeleteScheduled(id) { await scheduledStore.deleteScheduledScan(id) }
</script>

<style scoped>
.themis-page { min-height: 100vh; padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1100px; margin: 0 auto; padding: 1.25rem; position: relative; z-index: 1; }
@media (max-width: 768px) { .main { padding: 0.85rem; } }

/* ── Toggle de dos mundos ── */
.world-toggle { display: flex; gap: 0.3rem; margin-bottom: 1.1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.3rem; }
.world-opt {
  flex: 1; display: flex; align-items: center; justify-content: center; gap: 0.45rem;
  padding: 0.6rem 0.9rem; background: none; border: none; border-radius: 7px;
  color: var(--text-muted); font-size: var(--fs-lg); font-weight: 500; cursor: pointer;
  transition: all 0.2s ease;
}
.world-opt svg { width: 16px; height: 16px; }
.world-opt:hover { color: var(--text-dim); }
.world-opt.active { background: var(--accent-dim); color: var(--accent-bright); font-weight: 600; box-shadow: inset 0 0 0 1px var(--accent); }
.world-block { display: block; }

.kb-stale {
  margin-bottom: 0.8rem; padding: 0.6rem 0.8rem; border-radius: 8px;
  border: 1px solid var(--warn); background: var(--warn-dim);
  color: var(--text-dim); font-size: var(--fs-md); line-height: 1.45;
}
.kb-stale strong { color: var(--text); }

.lybra-history-toggle {
  display: block; margin: 0 0 0.85rem auto; padding: 0.45rem 0.8rem;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  color: var(--text-dim); font-size: var(--fs-lg); cursor: pointer; transition: all 0.2s;
}
.lybra-history-toggle:hover { border-color: var(--accent); color: var(--text); }

/* Staggered entrance on page load — mirrors the hub's fade-up language.
   Only the two static children get it; the switchable view-block below
   already gets its own motion from the fade-swap transition. */
.main > :nth-child(1) { animation: seq-fade-up 0.5s ease-out backwards; }
.main > :nth-child(2) { animation: seq-fade-up 0.5s ease-out 0.06s backwards; }

/* Crossfade between full / folders / history (and Lybra vs escáneres
   externos) so switching modes reads as one continuous view instead of a
   hard content swap. mode="out-in" makes this sequential (leave then
   enter), so total wait is roughly double this duration — kept short so
   toggling worlds doesn't feel sluggish. */
.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.12s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

@media (prefers-reduced-motion: reduce) {
  .main > :nth-child(1), .main > :nth-child(2) { animation: none !important; }
  /* No "none": con mode="out-in", Vue espera un transitionend real para
     montar el bloque entrante. "none" nunca lo dispara y el contenido
     saliente se queda pegado en pantalla. Una transición casi instantánea
     sigue sin animación perceptible pero deja que Vue detecte el final. */
  .fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.01s linear !important; }
}

.batch-btn { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.6rem; background: var(--accent); border: 1px solid var(--accent); border-radius: 6px; color: var(--on-accent); font-size: var(--fs-md); cursor: pointer; transition: all 0.2s; }
.batch-btn:hover { opacity: 0.9; }
.batch-btn svg { width: 11px; height: 11px; }
.batch-btn.danger { background: var(--danger); border-color: var(--danger); }
.batch-btn.danger:hover { opacity: 0.85; }

.batch-warning { font-size: var(--fs-lg); color: var(--text); margin: 0 0 0.5rem; }
.batch-warning-sub { font-size: var(--fs-md); color: var(--text-dim); margin: 0; }

label { display: block; margin-bottom: 0.4rem; font-size: var(--fs-lg); color: var(--text-dim); }
select { width: 100%; padding: 0.55rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: var(--fs-input); }
select:focus { outline: none; border-color: var(--accent); }
</style>
