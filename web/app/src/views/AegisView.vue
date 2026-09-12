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
          <!-- Mantenimiento de listas: hasta ahora solo se podían crear desde
               el modal de campaña, y no había forma de editarlas después. -->
          <button type="button" class="lists-btn" @click="store.openListsModal()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
            Editar listas de distribución
          </button>
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
        <div class="panel-content panel-content--history" v-show="!rightCollapsed">
          <!-- Acceso a la vista de campañas: lanzar se hace desde el visor de
               cada píldora, pero consultar lo enviado tiene su propia vista. -->
          <router-link to="/aegis/campanas" class="campaigns-cta">
            <span class="campaigns-cta-icon" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            </span>
            <span class="campaigns-cta-text">
              <span class="campaigns-cta-title">Campañas</span>
              <span class="campaigns-cta-sub">Resultados de lo que ya has enviado</span>
            </span>
            <span class="campaigns-cta-arrow" aria-hidden="true">›</span>
          </router-link>
          <div class="history-slot">
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
        </div>
      </aside>
    </div>

    <CampaignModal
      v-if="store.campaignModalOpen && store.viewerDoc.data"
      :doc="store.viewerDoc.data"
      @close="store.closeCampaignModal()"
    />

    <DistributionListsModal
      v-if="store.listsModalOpen"
      @close="store.closeListsModal()"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount } from 'vue'
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
import DistributionListsModal from '@/components/aegis/DistributionListsModal.vue'

const store = useAegisStore()

const { collapsed: leftCollapsed, toggle: toggleLeft } = usePanelCollapse('aegis-left')
const { collapsed: rightCollapsed, toggle: toggleRight } = usePanelCollapse('aegis-right')
const leftWidth = computed(() => (leftCollapsed.value ? '48px' : '400px'))
const rightWidth = computed(() => (rightCollapsed.value ? '48px' : '320px'))

// El layout de escritorio es de una sola pantalla (.app-layout mide
// calc(100vh - topbar) con overflow:hidden) y cada panel scrollea por su
// cuenta en .panel-content. Pero `html` sí puede desplazarse (overflow-x
// hidden fuerza overflow-y:auto, ver comentario en shared.css) y Chromium,
// al devolver el foco al <input type="file"> oculto de WhiteLabelFields tras
// cerrar el diálogo nativo, se salta `.app-layout` (overflow:hidden no cuenta
// como contenedor de scroll) y desplaza `html` en su lugar — aunque el input
// ya era visible. Como la página mide justo 100vh, ese scroll no revela más
// contenido: revela hueco, con el fondo fijo de StarBackground asomando.
// Bloquear el scroll de html en este rango de anchura (el mismo en el que
// .app-layout es de una sola pantalla) impide que ese salto tenga adónde ir,
// sin tocar el modo apilado por debajo de 1200px, donde sí debe desplazarse.
onMounted(async () => {
  document.documentElement.classList.add('aegis-scroll-lock')
  await store.loadTopics()
  await store.loadHistory()
})
onBeforeUnmount(() => {
  document.documentElement.classList.remove('aegis-scroll-lock')
  // El modal de campaña se abre con un flag del store, que sobrevive a la
  // vista: si se sale con él abierto (su enlace a la vista de campañas, o
  // el botón de atrás), al volver al generador reaparecería solo.
  store.closeCampaignModal()
})
</script>

<style scoped>
.aegis-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }

/* Ver el porqué en el onMounted de <script setup>. Acotado al mismo ancho en
   el que .app-layout es de una sola pantalla (media query de más abajo
   apila los paneles y necesita que la página SÍ pueda desplazarse). */
@media (min-width: 1201px) {
  :global(html.aegis-scroll-lock) { overflow-y: hidden; }
}

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

.lists-btn {
  display: flex; align-items: center; justify-content: center; gap: 0.45rem;
  width: calc(100% - 2rem); margin: 0 1rem 1rem;
  padding: 0.5rem 0.75rem; border-radius: 7px;
  background: var(--bg); border: 1px solid var(--border-solid);
  color: var(--text-dim); font-family: inherit; font-size: var(--fs-md); font-weight: 600;
  cursor: pointer; transition: all 0.15s;
}
.lists-btn:hover { border-color: var(--accent); color: var(--accent-bright); }
.lists-btn:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }

/* La barra del historial apila el acceso a campañas y el historial; este
   último ocupa el resto y scrollea por dentro (HistoryPanel mide 100%). */
.panel-content--history { display: flex; flex-direction: column; }
.history-slot { flex: 1; min-height: 0; }
.campaigns-cta {
  display: flex; align-items: center; gap: 0.7rem; flex-shrink: 0;
  margin: 0.75rem 0.75rem 0.6rem; padding: 0.75rem 0.85rem;
  border-radius: 10px; border: 1px solid var(--accent);
  background: var(--accent-dim); color: var(--text); text-decoration: none;
  transition: background var(--transition), box-shadow var(--transition), transform var(--transition);
}
.campaigns-cta:hover { background: var(--surface-3); box-shadow: 0 4px 14px rgba(0,0,0,0.25); transform: translateY(-1px); }
.campaigns-cta:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
.campaigns-cta-icon { width: 34px; height: 34px; border-radius: 9px; display: grid; place-items: center; background: var(--accent); color: var(--on-accent); flex-shrink: 0; }
.campaigns-cta-text { display: flex; flex-direction: column; flex: 1; min-width: 0; }
.campaigns-cta-title { font-size: var(--fs-lg); font-weight: 700; color: var(--accent-bright); font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.campaigns-cta-sub { font-size: var(--fs-md); color: var(--text-dim); }
.campaigns-cta-arrow { color: var(--accent-bright); font-size: var(--fs-xl); line-height: 1; }

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
  .campaigns-cta { transition: none !important; }
  .campaigns-cta:hover { transform: none; }
  /* No "none": con mode="out-in" Vue espera un transitionend real para
     montar el bloque entrante; "none" nunca lo dispara y el contenido
     saliente se queda pegado en pantalla (mismo gotcha que en ThemisView). */
  .fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.01s linear !important; }
}
</style>
