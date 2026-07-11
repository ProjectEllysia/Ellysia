<template>
  <div class="themis-page">
    <StarBackground />
    <Topbar title="Themis" badge="Escaneos de Vulnerabilidades" />

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
      </div>

      <Transition name="fade-swap" mode="out-in">
      <!-- ═══════════ MUNDO: MOTOR LYBRA ═══════════ -->
      <div v-if="store.world === 'lybra'" key="lybra" class="world-block">
        <button class="lybra-history-toggle" @click="store.setViewMode(store.viewMode === 'history' ? 'full' : 'history')">
          {{ store.viewMode === 'history' ? '← Volver al motor' : 'Ver historial' }}
        </button>
        <HistoryPanel v-if="store.viewMode === 'history'" />
        <template v-else>
          <LybraLaunchPanel
            :launching="store.launching"
            :source-scans="store.sourceNmapScans.items"
            :source-loading="store.sourceNmapScans.loading"
            :authorized-targets="store.authorizedTargets.items"
            :auth-targets-loading="store.authorizedTargets.loading"
            @launch="handleLaunchLybra"
            @load-sources="store.loadSourceNmapScans()"
            @add-authorized-target="handleAddAuthorizedTarget"
            @remove-authorized-target="store.removeAuthorizedTarget" />
          <LybraResults
            :scans="store.scans.lybra.results"
            :loading="store.scans.lybra.loading"
            :docs-by-scan="store.lybraDocs"
            @refresh="store.loadLybraScans()"
            @delete="handleDeleteLybra"
            @load-docs="store.loadLybraDocs"
            @generate-pdf="handleLybraGeneratePdf"
            @download-doc="store.downloadDocument"
            @delete-doc="handleLybraDeleteDoc" />
          <ScheduledScansPanel :scheduled="store.scheduled" :scheduling="store.scheduling" active-tab="lybra"
            @create="handleCreateScheduled" @deactivate="handleDeactivateScheduled" @delete="handleDeleteScheduled" @toggle-form="store.toggleScheduledForm()" />
        </template>
      </div>

      <!-- ═══════════ MUNDO: ESCÁNERES EXTERNOS ═══════════ -->
      <div v-else key="external" class="world-block">
      <StatsRow :total="store.stats.total" :nmap="store.stats.nmap" :nikto="store.stats.nikto" :openvas="store.stats.openvas" />
      <ViewToggle :model-value="store.viewMode" @update:model-value="store.setViewMode" />
      <Transition name="fade-swap" mode="out-in" appear>
        <div v-if="store.viewMode === 'full'" key="full" class="view-block">
          <ScanTabs :active="store.activeTab" @switch="handleTabSwitch" />
          <ScanForm :type="store.activeTab" :launching="store.launching" @launch="handleLaunch" />
          <ScanTable :type="store.activeTab" :rows="currentData.results" :loading="currentData.loading" :current-page="currentData.page" :total-count="currentData.totalCount" :per-page="currentData.perPage" :selected-ids="batchSelectedArray"
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
          <ScheduledScansPanel :scheduled="store.scheduled" :scheduling="store.scheduling" :active-tab="store.activeTab" @create="handleCreateScheduled" @deactivate="handleDeactivateScheduled" @delete="handleDeleteScheduled" @toggle-form="store.toggleScheduledForm()" />
        </div>
        <ScanFolderView v-else-if="store.viewMode === 'folders'" key="folders"
          :folders="store.folders.items" :loading="store.folders.loading"
          @refresh="store.loadFolders()"
          @preview="(id, type) => store.openPreview(id, type)"
          @cancel="handleCancel"
          @delete="handleDelete"
          @create-folder="store.folderForms.create.show = true"
          @rename-folder="handleRenameFolder"
          @delete-folder="handleDeleteFolder"
          @move-scan="handleOpenMoveScan"
          @remove-scan="handleRemoveScan" />
        <HistoryPanel v-else-if="store.viewMode === 'history'" key="history" />
      </Transition>
      </div>
      </Transition>
    </main>

    <ScanPreviewModal :show="store.preview.show" :scan="store.preview.scan" :type="store.preview.type" :docs="store.preview.docs" :docs-loading="store.preview.docsLoading"
      :traceroute="store.preview.traceroute" :traceroute-loading="store.preview.tracerouteLoading"
      @close="store.closePreview()" @refresh-docs="store.refreshPreviewDocs()" @download-doc="store.downloadDocument" @delete-doc="handleDeletePreviewDoc" @generate-pdf="handlePreviewPdf" @refresh-traceroute="store.loadPreviewTraceroute(true)" />

    <FolderFormModal
      :key="'create-folder'"
      :show="store.folderForms.create.show"
      title="Nueva carpeta"
      :submitting="store.folderForms.create.submitting"
      @close="store.folderForms.create.show = false"
      @submit="async name => { if (await store.createFolder(name)) store.folderForms.create.show = false }" />
    <FolderFormModal
      :key="'rename-folder'"
      :show="store.folderForms.rename.show"
      title="Renombrar carpeta"
      :initial-name="store.folderForms.rename.name"
      :submitting="store.folderForms.rename.submitting"
      @close="store.folderForms.rename.show = false"
      @submit="async name => { if (await store.renameFolder(store.folderForms.rename.folderId, name)) store.folderForms.rename.show = false }" />
    <MoveScanModal
      :key="'move-scan'"
      :show="store.moveScan.show"
      :scan-id="store.moveScan.scanId"
      :current-folder-id="store.moveScan.folderId"
      :folders="store.folders.items"
      :submitting="store.moveScan.submitting"
      @close="store.closeMoveScan()"
      @move="async folderId => { if (await store.moveScanToFolder(store.moveScan.scanId, folderId)) store.closeMoveScan() }" />

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
import ScheduledScansPanel from '@/components/themis/ScheduledScansPanel.vue'
import LybraLaunchPanel from '@/components/themis/lybra/LybraLaunchPanel.vue'
import LybraResults from '@/components/themis/lybra/LybraResults.vue'
import { useThemisStore } from '@/stores/themisStore'
import { useBatchSelection } from '@/composables/useBatchSelection'

const store = useThemisStore()
const { selectedIds: batchSelectedIds, selectedCount: batchSelectedCount, selectedArray: batchSelectedArray, toggle: batchToggle, selectAll: batchSelectAll, clear: batchClear } = useBatchSelection()
const currentData = computed(() => store.scans[store.activeTab])

const activeBatchAction = ref(null)
const batchSubmitting = ref(false)
const selectedFolderId = ref('')

const selectableFolders = computed(() =>
  store.folders.items.filter(f => f.id !== null)
)

onMounted(() => { store.loadStats(); store.loadScans(store.activeTab); store.loadScheduledScans(); store.loadFolders() })
onBeforeUnmount(() => store.stopScanPolling())

// Carga la lista de Lybra y el registro de objetivos autorizados la primera
// vez que se entra a su mundo.
let lybraLoaded = false
watch(() => store.world, (w) => {
  if (w === 'lybra' && !lybraLoaded) {
    lybraLoaded = true
    store.loadLybraScans()
    store.loadAuthorizedTargets()
  }
}, { immediate: true })

async function handleLaunchLybra(payload) { await store.launchLybra(payload) }
async function handleDeleteLybra(id) { if (confirm('¿Eliminar este escaneo Lybra y sus hallazgos?')) await store.deleteLybraScan(id) }
async function handleLybraGeneratePdf(scanId, useAi) { await store.generateLybraPdf(scanId, useAi) }
async function handleLybraDeleteDoc(scanId, docId) { await store.deleteLybraDoc(scanId, docId) }
async function handleAddAuthorizedTarget({ target, label }) { await store.addAuthorizedTarget(target, label) }

watch(activeBatchAction, (val) => {
  if (!val) { selectedFolderId.value = ''; batchSubmitting.value = false }
})

function openBatchAction(action) {
  if (action === 'add-to-folder') store.loadFolders()
  activeBatchAction.value = action
}

function closeBatchAction() {
  if (batchSubmitting.value) return
  activeBatchAction.value = null
}

async function handleBatchAddToFolder() {
  if (!selectedFolderId.value || batchSubmitting.value) return
  batchSubmitting.value = true
  const ok = await store.addScansToFolder(batchSelectedArray.value, Number(selectedFolderId.value))
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
function handleLaunch(payload) { const fns = { nmap: store.launchNmap, nikto: store.launchNikto, openvas: store.launchOpenvas }; const fn = fns[store.activeTab]; if (fn) fn(payload) }
function handleRenameFolder(folder) { store.folderForms.rename = { show: true, folderId: folder.id, name: folder.name, submitting: false } }
async function handleDeleteFolder(folderId) { if (confirm('¿Eliminar esta carpeta? Los escaneos no se borraran, solo quedaran sin carpeta.')) await store.deleteFolder(folderId) }
function handleOpenMoveScan(scanId, folderId) { store.openMoveScan(scanId, folderId) }
async function handleRemoveScan(scanId, folderId) { await store.removeScanFromFolder(scanId, folderId) }
async function handlePreviewPdf(id, type, useAi) {
  const started = await store.generatePdf(id, useAi)
  if (started) await store.waitForDocument(id)
  await store.refreshCurrent()
  await store.refreshPreviewDocs()
}

async function handleDeletePreviewDoc(docId) { await store.deleteDocument(docId); await store.refreshPreviewDocs() }

async function handleCreateScheduled(payload) { await store.createScheduledScan(payload) }
async function handleDeactivateScheduled(id) { await store.deactivateScheduledScan(id) }
async function handleDeleteScheduled(id) { await store.deleteScheduledScan(id) }
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
  color: var(--text-muted); font-size: 0.85rem; font-weight: 500; cursor: pointer;
  transition: all 0.2s ease;
}
.world-opt svg { width: 16px; height: 16px; }
.world-opt:hover { color: var(--text-dim); }
.world-opt.active { background: var(--accent-dim); color: var(--accent-bright); font-weight: 600; box-shadow: inset 0 0 0 1px var(--accent); }
.world-block { display: block; }

.lybra-history-toggle {
  display: block; margin: 0 0 0.85rem auto; padding: 0.45rem 0.8rem;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  color: var(--text-dim); font-size: 0.78rem; cursor: pointer; transition: all 0.2s;
}
.lybra-history-toggle:hover { border-color: var(--accent); color: var(--text); }

/* Staggered entrance on page load — mirrors the hub's fade-up language.
   Only the two static children get it; the switchable view-block below
   already gets its own motion from the fade-swap transition. */
.main > :nth-child(1) { animation: seq-fade-up 0.5s ease-out backwards; }
.main > :nth-child(2) { animation: seq-fade-up 0.5s ease-out 0.06s backwards; }

/* Crossfade between full / folders / history so switching modes reads as
   one continuous view instead of a hard content swap. */
.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.2s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

@media (prefers-reduced-motion: reduce) {
  .main > :nth-child(1), .main > :nth-child(2) { animation: none !important; }
  .fade-swap-enter-active, .fade-swap-leave-active { transition: none !important; }
}

.batch-btn { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.6rem; background: var(--accent); border: 1px solid var(--accent); border-radius: 6px; color: var(--on-accent); font-size: 0.75rem; cursor: pointer; transition: all 0.2s; }
.batch-btn:hover { opacity: 0.9; }
.batch-btn svg { width: 11px; height: 11px; }
.batch-btn.danger { background: var(--danger); border-color: var(--danger); }
.batch-btn.danger:hover { opacity: 0.85; }

.batch-warning { font-size: 0.82rem; color: var(--text); margin: 0 0 0.5rem; }
.batch-warning-sub { font-size: 0.75rem; color: var(--text-dim); margin: 0; }

label { display: block; margin-bottom: 0.4rem; font-size: 0.78rem; color: var(--text-dim); }
select { width: 100%; padding: 0.55rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem; }
select:focus { outline: none; border-color: var(--accent); }
</style>
