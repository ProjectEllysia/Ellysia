<template>
  <div class="aegis-page" data-module="aegis">
    <StarBackground />
    <Topbar title="Aegis" badge="Generación de Píldoras" back-to="/aegis" back-label="Volver" />

    <div class="app-layout">
      <aside class="panel panel--left" :class="{ 'panel--collapsed': leftCollapsed }" :style="{ width: leftWidth }">
        <button
          type="button"
          class="panel-toggle panel-toggle--left"
          :aria-label="leftCollapsed ? 'Expandir panel de perfil y generación' : 'Contraer panel de perfil y generación'"
          @click="toggleLeft"
        >
          <span :class="{ 'chevron--flipped': leftCollapsed }">‹</span>
        </button>
        <div class="panel-content" v-show="!leftCollapsed">
          <OrgProfilePanel />
          <TweaksForm />
        </div>
      </aside>

      <section class="panel panel--center">
        <Transition name="fade-swap" mode="out-in">
          <DocumentEditor
            v-if="store.editing && store.viewerDoc.data"
            key="editor"
            :doc="store.viewerDoc.data"
            :saving="store.saving"
            @save="(pill) => store.savePill(store.currentDocId, pill)"
            @cancel="store.cancelEdit()"
          />
          <DocumentViewer
            v-else
            key="viewer"
            :viewer-doc="store.viewerDoc"
            :generating="store.generating"
            @close="store.closeViewer()"
            @export="(fmt) => store.downloadExport(store.currentDocId, fmt)"
            @preview="() => store.previewMarkdown(store.currentDocId)"
            @edit="store.startEdit()"
            @campaign="store.openCampaignModal()"
          />
        </Transition>
      </section>

      <aside class="panel panel--right" :class="{ 'panel--collapsed': rightCollapsed }" :style="{ width: rightWidth }">
        <button
          type="button"
          class="panel-toggle panel-toggle--right"
          :aria-label="rightCollapsed ? 'Expandir historial' : 'Contraer historial'"
          @click="toggleRight"
        >
          <span :class="{ 'chevron--flipped': rightCollapsed }">›</span>
        </button>
        <div class="panel-content" v-show="!rightCollapsed">
          <HistoryPanel
            :documents="store.sortedDocuments()"
            :error="store.listError"
            :current-doc-id="store.currentDocId"
            :sort-mode="store.sortMode"
            @view="store.loadDocument($event)"
            @delete="store.deleteDocument($event)"
            @export="(docId, fmt) => store.downloadExport(docId, fmt)"
            @preview="store.previewMarkdown($event)"
            @sort="store.sortMode = $event"
            @refresh="store.loadHistory()"
          />
        </div>
      </aside>
    </div>

    <CampaignModal
      v-if="store.campaignModalOpen && store.viewerDoc.data"
      :doc="store.viewerDoc.data"
      @close="store.closeCampaignModal()"
    />
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useAegisStore } from '@/stores/aegisStore'
import { usePanelCollapse } from '@/composables/usePanelCollapse'
import OrgProfilePanel from '@/components/aegis/OrgProfilePanel.vue'
import TweaksForm from '@/components/aegis/TweaksForm.vue'
import DocumentViewer from '@/components/aegis/DocumentViewer.vue'
import DocumentEditor from '@/components/aegis/DocumentEditor.vue'
import HistoryPanel from '@/components/aegis/HistoryPanel.vue'
import CampaignModal from '@/components/aegis/CampaignModal.vue'

const store = useAegisStore()

const { collapsed: leftCollapsed, toggle: toggleLeft } = usePanelCollapse('aegis-left')
const { collapsed: rightCollapsed, toggle: toggleRight } = usePanelCollapse('aegis-right')
const leftWidth = computed(() => (leftCollapsed.value ? '48px' : '400px'))
const rightWidth = computed(() => (rightCollapsed.value ? '48px' : '320px'))

onMounted(async () => { await store.loadTopics(); await store.loadHistory() })
</script>

<style scoped>
.aegis-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }

/* Flex, no grid: el ancho de cada barra llega por :style inline (calculado
   en leftWidth/rightWidth) y se anima con "transition: width". */
.app-layout { display: flex; height: calc(100vh - var(--topbar-h)); overflow: hidden; position: relative; z-index: 1; }
.panel { display: flex; flex-direction: column; position: relative; min-height: 0; }
.panel--left, .panel--right { flex: 0 0 auto; transition: width 0.28s ease; }
.panel--left   { background: var(--surface); border-right: 1px solid var(--border-med); }
.panel--right  { background: var(--surface); border-left: 1px solid var(--border-med); }
/* El escenario central respira en un tono propio (surface-2) para que se
   distinga de las barras laterales (surface) — antes las tres compartían
   el mismo fondo y solo un hairline casi invisible las separaba. */
.panel--center { flex: 1 1 0%; min-width: 0; background: var(--surface-2); overflow-y: auto; }
.panel-content { flex: 1; overflow-y: auto; overflow-x: hidden; min-height: 0; }

/* ── Entrada escalonada al cargar — mismo lenguaje que ThemisView ── */
.panel--left   { animation: seq-fade-up 0.45s ease-out backwards; }
.panel--center { animation: seq-fade-up 0.45s ease-out 0.07s backwards; }
.panel--right  { animation: seq-fade-up 0.45s ease-out 0.14s backwards; }

/* ── Tirador de contraer/expandir ──
   Vive fuera de .panel-content (que es lo único con scroll) para no quedar
   recortado, y va a MEDIA ALTURA de la costura, sobresaliendo hacia el panel
   central. Así no pelea con los controles de cabecera de cada barra (chevron
   del acordeón de perfil, ordenar/refrescar del historial), que están arriba,
   ni tapa el formulario de la barra: queda sobre el margen libre del visor. */
.panel-toggle {
  position: absolute; top: 50%; transform: translateY(-50%); z-index: 4;
  width: 26px; height: 72px;
  display: grid; place-items: center;
  background: var(--surface-2); border: 1px solid var(--border-med);
  color: var(--text-dim); cursor: pointer; font-size: var(--fs-xl); line-height: 1;
  box-shadow: 0 2px 10px rgba(0,0,0,0.28);
  transition: background var(--transition), color var(--transition), border-color var(--transition);
}
.panel-toggle:hover { background: var(--surface-3); border-color: var(--accent); color: var(--accent); }
.panel-toggle:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
.panel-toggle--left  { left: 100%; border-radius: 0 10px 10px 0; border-left: none; }
.panel-toggle--right { right: 100%; border-radius: 10px 0 0 10px; border-right: none; }
.panel-toggle span { display: inline-block; transition: transform 0.25s ease; }
.chevron--flipped { transform: rotate(180deg); }

/* Crossfade entre el editor y el visor de la píldora — mismo patrón que el
   fade-swap de ThemisView entre mundos/vistas. */
.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.15s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

@media (max-width: 1200px) {
  .app-layout { flex-direction: column; }
  /* !important necesario: pisa el width inline calculado por leftWidth/rightWidth. */
  .panel--left, .panel--right { flex: 0 1 auto !important; width: auto !important; transition: none; border: none; border-bottom: 1px solid var(--border-med); }
  /* El `max-height: 40vh` que había aquí iba acompañado de ocultar el botón de
     plegar, así que el perfil de organización —un formulario largo— quedaba
     encerrado en una caja de 40vh con scroll y sin forma de agrandarla.
     Apilados, los paneles pueden ocupar lo que necesiten: la página ya se
     desplaza. El botón de plegar se queda, que es lo que da el control. */
  .panel--collapsed { max-height: 3rem; overflow: hidden; }
}

@media (prefers-reduced-motion: reduce) {
  .panel--left, .panel--center, .panel--right { animation: none !important; }
  .panel--left, .panel--right { transition: none !important; }
  .panel-toggle span { transition: none !important; }
  /* No "none": con mode="out-in" Vue espera un transitionend real para
     montar el bloque entrante; "none" nunca lo dispara y el contenido
     saliente se queda pegado en pantalla (mismo gotcha que en ThemisView). */
  .fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.01s linear !important; }
}
</style>
