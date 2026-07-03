<template>
  <div class="aegis-page" data-module="aegis">
    <StarBackground />
    <Topbar title="Aegis" badge="Generación de Píldoras" />

    <div class="app-layout">
      <aside class="panel panel--left">
        <TweaksForm />
      </aside>

      <section class="panel panel--center">
        <DocumentEditor
          v-if="store.editing && store.viewerDoc.data"
          :doc="store.viewerDoc.data"
          :saving="store.saving"
          @save="(pill) => store.savePill(store.currentDocId, pill)"
          @cancel="store.cancelEdit()"
        />
        <DocumentViewer
          v-else
          :viewer-doc="store.viewerDoc"
          @close="store.closeViewer()"
          @export="(fmt) => store.downloadExport(store.currentDocId, fmt)"
          @preview="() => store.previewMarkdown(store.currentDocId)"
          @edit="store.startEdit()"
          @campaign="store.openCampaignModal()"
        />
      </section>

      <aside class="panel panel--right">
        <HistoryPanel
          :documents="store.sortedDocuments()"
          :current-doc-id="store.currentDocId"
          :sort-mode="store.sortMode"
          @view="store.loadDocument($event)"
          @delete="store.deleteDocument($event)"
          @export="(docId, fmt) => store.downloadExport(docId, fmt)"
          @preview="store.previewMarkdown($event)"
          @sort="store.sortMode = $event"
          @refresh="store.loadHistory()"
        />
      </aside>
    </div>

    <CampaignModal
      v-if="store.campaignModalOpen && store.viewerDoc.data"
      :doc="store.viewerDoc.data"
      @close="store.closeCampaignModal()"
    />

    <AppToast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useAegisStore } from '@/stores/aegisStore'
import TweaksForm from '@/components/aegis/TweaksForm.vue'
import DocumentViewer from '@/components/aegis/DocumentViewer.vue'
import DocumentEditor from '@/components/aegis/DocumentEditor.vue'
import HistoryPanel from '@/components/aegis/HistoryPanel.vue'
import CampaignModal from '@/components/aegis/CampaignModal.vue'

const store = useAegisStore()
onMounted(async () => { await Promise.all([store.loadTopics(), store.loadBrands()]); await store.loadHistory() })
</script>

<style scoped>
.aegis-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.app-layout { display: grid; grid-template-columns: 340px 1fr 320px; gap: 0; height: calc(100vh - var(--topbar-h)); overflow: hidden; position: relative; z-index: 1; }
.panel { overflow-y: auto; display: flex; flex-direction: column; position: relative; }
.panel--left   { background: var(--surface); border-right: 1px solid var(--border); }
.panel--center { background: var(--surface); }
.panel--right  { background: var(--surface); border-left: 1px solid var(--border); }
@media (max-width: 1100px) { .app-layout { grid-template-columns: 1fr; grid-template-rows: auto 1fr auto; } .panel--left, .panel--right { border: none; border-bottom: 1px solid var(--border); max-height: 40vh; } }
</style>
