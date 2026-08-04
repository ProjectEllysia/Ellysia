<template>
  <div class="viewer">
    <div v-if="!viewerDoc.data && !viewerDoc.loading" class="viewer-empty">
      <h3>Visor de Documentos</h3>
      <p>Selecciona un documento del historial o genera una nueva píldora para ver su contenido aquí.</p>
    </div>

    <div v-else-if="viewerDoc.loading" class="viewer-loading">
      <div class="spinner-lg"></div>
      <p>Cargando documento…</p>
    </div>

    <Transition name="pill-reveal" mode="out-in">
      <div v-if="viewerDoc.data && !viewerDoc.loading" class="viewer-content">
        <div class="viewer-toolbar">
          <span class="doc-id">Doc #{{ viewerDoc.data.id }}</span>
          <span v-if="viewerDoc.data.topicId" class="doc-topic">Tema #{{ viewerDoc.data.topicId }}</span>
          <span class="doc-date">{{ formatDate(viewerDoc.data.generatedAt) }}</span>
          <div class="toolbar-spacer"></div>
          <div class="export-dropdown">
            <button type="button" class="toolbar-btn" @click="exportOpen = !exportOpen">Exportar</button>
            <div v-if="exportOpen" class="export-menu">
              <button @click="emitExport('md')">Markdown</button>
              <button @click="emitExport('html')">HTML</button>
              <button @click="emitExport('json')">JSON</button>
            </div>
          </div>
          <button type="button" class="toolbar-btn" @click="emit('preview')">Vista previa</button>
          <button
            v-if="viewerDoc.data.status === 'done'"
            type="button"
            class="toolbar-btn"
            @click="emit('edit')"
          >Editar</button>
          <button
            v-if="viewerDoc.data.status === 'done'"
            type="button"
            class="toolbar-btn toolbar-btn--campaign"
            :disabled="!hasQuestions"
            :title="hasQuestions ? 'Lanzar una campaña con esta píldora' : 'Añade preguntas al test desde el editor para poder lanzar una campaña'"
            @click="emit('campaign')"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            Lanzar campaña
          </button>
          <button type="button" class="toolbar-btn toolbar-close" @click="emit('close')">&times;</button>
        </div>

        <div class="pill-body">
          <h2 class="pill-title">{{ viewerDoc.data.title }}</h2>
          <p class="pill-subtitle" v-if="viewerDoc.data.subtitle">{{ viewerDoc.data.subtitle }}</p>

          <section v-if="viewerDoc.data.pill?.intro" class="pill-section">
            <p class="pill-intro">{{ viewerDoc.data.pill.intro }}</p>
          </section>

          <section v-if="viewerDoc.data.pill?.tips?.length" class="pill-section">
            <h3>Recomendaciones</h3>
            <div v-for="(tip, i) in viewerDoc.data.pill.tips" :key="i" class="pill-tip">
              <span class="tip-num">{{ i + 1 }}</span>
              <div class="tip-body">
                <h4>{{ tip.headline }}</h4>
                <p>{{ tip.body }}</p>
                <div v-if="tip.links?.length" class="tip-links">
                  <a v-for="(link, j) in tip.links" :key="j" :href="link.url" target="_blank" rel="noopener" class="tip-link">{{ link.text }}</a>
                </div>
              </div>
            </div>
          </section>

          <section v-if="viewerDoc.data.pill?.closing" class="pill-section">
            <p class="pill-closing">{{ viewerDoc.data.pill.closing }}</p>
          </section>

          <section v-if="viewerDoc.data.alerts?.length" class="pill-section">
            <h3>Alertas de Seguridad</h3>
            <div v-for="(alert, i) in viewerDoc.data.alerts" :key="i" class="pill-alert" :class="`pill-alert--${alert.severity || 'informativa'}`">
              <div class="alert-header">
                <span class="alert-severity">{{ sevIcon(alert.severity) }}</span>
                <a v-if="alert.url" :href="alert.url" target="_blank" rel="noopener" class="alert-title">{{ alert.title }}</a>
                <span v-else class="alert-title">{{ alert.title }}</span>
              </div>
              <p class="alert-desc" v-if="alert.description">{{ alert.description }}</p>
              <div class="alert-meta" v-if="alert.source || alert.sourceLabel">
                <span class="alert-source">{{ alert.sourceLabel || alert.source }}</span>
                <span v-if="alert.published" class="alert-published">{{ formatDate(alert.published) }}</span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate } = useUtils()
const props = defineProps({ viewerDoc: { type: Object, default: () => ({ loading: false, data: null }) } })

// Sin preguntas el backend rechaza el lanzamiento (CampaignNoQuestionsError);
// mejor decirlo aquí que dejar al usuario rellenar el modal para nada.
const hasQuestions = computed(() => (props.viewerDoc?.data?.pill?.questions?.length || 0) > 0)
const emit = defineEmits(['close', 'export', 'preview', 'edit', 'campaign'])
const exportOpen = ref(false)

const sevIcons = { critica: '🔴', alta: '🟠', media: '🟡', baja: '🟢', informativa: '🔵' }
function sevIcon(sev) { return sevIcons[sev] || sevIcons.informativa }
function emitExport(fmt) { exportOpen.value = false; emit('export', fmt) }
</script>

<style scoped>
.viewer { height: 100%; display: flex; flex-direction: column; }
.viewer-empty { text-align: center; padding: 2.5rem 1.25rem; color: var(--text-muted); }
.viewer-empty h3 { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); margin: 0 0 0.4rem; }
.viewer-empty p { font-size: var(--fs-lg); line-height: 1.5; max-width: 300px; margin: 0 auto; }
.viewer-loading { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.85rem; padding: 3.5rem 0; color: var(--text-muted); font-size: var(--fs-lg); }
.spinner-lg { width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: seq-spin .7s linear infinite; }
.viewer-content { flex: 1; display: flex; flex-direction: column; }
.viewer-toolbar { display: flex; align-items: center; gap: 0.4rem; padding: 0.5rem 0.85rem; background: var(--surface); border-bottom: 1px solid var(--border); font-size: var(--fs-md); color: var(--text-muted); flex-wrap: wrap; }
.doc-id, .doc-topic { font-weight: 600; color: var(--text-dim); font-family: var(--font-mono); font-size: var(--fs-md); }
.toolbar-spacer { flex: 1; }
.toolbar-btn { padding: 0.25rem 0.6rem; font-size: var(--fs-md); font-weight: 600; border-radius: 5px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; transition: all 0.2s; }
.toolbar-btn:hover:not(:disabled) { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
.toolbar-btn--campaign { display: inline-flex; align-items: center; gap: 0.3rem; background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.toolbar-btn--campaign:hover:not(:disabled) { background: var(--accent); color: var(--on-accent); border-color: var(--accent); box-shadow: 0 0 14px var(--accent-dim); }
.toolbar-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.toolbar-close { border: none; background: none; font-size: var(--fs-lg); padding: 0 0.25rem; line-height: 1; }
.toolbar-close:hover { background: none; color: var(--danger); }
.export-dropdown { position: relative; }
.export-menu { position: absolute; right: 0; top: 100%; margin-top: 3px; z-index: 20; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; overflow: hidden; min-width: 100px; }
.export-menu button { display: block; width: 100%; text-align: left; padding: 0.35rem 0.6rem; font-size: var(--fs-md); background: none; border: none; color: var(--text-dim); cursor: pointer; transition: background 0.15s; }
.export-menu button:hover { background: var(--accent); color: var(--on-accent); }
.pill-body { padding: 1.25rem 4rem; overflow-y: auto; flex: 1; }
.pill-title { font-size: var(--fs-3xl); font-weight: 800; color: var(--text); margin: 0 0 0.8rem; font-family: var(--font-epic); text-align: center; }
.pill-subtitle { font-size: var(--fs-lg); color: var(--text-dim); margin: 0 0 1.25rem; }
.pill-section { margin-bottom: 1.25rem; }
.pill-section h3 { font-size: var(--fs-xl); font-weight: 700; color: var(--accent); margin: 0 0 0.65rem; padding-bottom: 0.3rem; border-bottom: 1px solid var(--border); font-family: var(--font-display); }
.pill-intro, .pill-closing { font-size: var(--fs-lg); line-height: 1.6; color: var(--text); white-space: pre-wrap; }
.pill-tip { display: flex; gap: 0.65rem; margin-bottom: 0.85rem; }
.tip-num { width: 24px; height: 24px; border-radius: 50%; flex-shrink: 0; background: var(--accent); color: var(--on-accent); font-size: var(--fs-md); font-weight: 700; display: flex; align-items: center; justify-content: center; }
.tip-body { flex: 1; min-width: 0; }
.tip-body h4 { font-size: var(--fs-lg); font-weight: 700; color: var(--text); margin: 0 0 0.15rem; }
.tip-body p { font-size: var(--fs-lg); line-height: 1.5; color: var(--text-dim); margin: 0 0 0.3rem; white-space: pre-wrap; }
.tip-links { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.tip-link { font-size: var(--fs-md); color: var(--accent); text-decoration: none; font-weight: 600; }
.tip-link:hover { text-decoration: underline; }
.pill-alert { padding: 0.65rem; border-radius: 7px; margin-bottom: 0.5rem; border: 1px solid var(--border); background: var(--bg); }
.pill-alert--critica     { border-color: rgba(217,108,108,0.25); border-left: 3px solid var(--danger); }
.pill-alert--alta        { border-color: rgba(251,146,60,0.2); border-left: 3px solid #fb923c; }
.pill-alert--media       { border-color: rgba(212,160,74,0.2); border-left: 3px solid var(--warn); }
.pill-alert--baja        { border-color: rgba(76,183,130,0.2); border-left: 3px solid var(--success); }
.pill-alert--informativa { border-color: rgba(96,128,224,0.2); border-left: 3px solid var(--info); }
.alert-header { display: flex; align-items: center; gap: 0.35rem; margin-bottom: 0.2rem; }
.alert-severity { font-size: var(--fs-lg); }
.alert-title { font-size: var(--fs-lg); font-weight: 700; color: var(--text); text-decoration: none; }
a.alert-title:hover { color: var(--accent); text-decoration: underline; }
.alert-desc { font-size: var(--fs-md); color: var(--text-dim); margin: 0.2rem 0; line-height: 1.45; }
.alert-meta { display: flex; gap: 0.65rem; font-size: var(--fs-md); color: var(--text-muted); margin-top: 0.3rem; }
.pill-reveal-enter-active { transition: opacity 0.35s ease-out, transform 0.35s ease-out; }
.pill-reveal-leave-active { transition: opacity 0.15s ease-in; }
.pill-reveal-enter-from { opacity: 0; transform: scale(0.97); }
.pill-reveal-leave-to { opacity: 0; }
</style>
