<template>
  <div class="history-panel">
    <div class="history-header">
      <h2>Historial</h2>
      <span class="history-count">{{ documents.length }} doc(s)</span>
    </div>

    <div class="history-controls">
      <select class="input select sort" v-model="sortModeLocal" @change="$emit('sort', sortModeLocal)">
        <option value="date-desc">Más recientes</option>
        <option value="date-asc">Más antiguos</option>
        <option value="name-asc">Nombre A–Z</option>
        <option value="status">Estado</option>
      </select>
      <button type="button" class="btn-icon" :class="{ spinning }" @click="handleRefresh" title="Refrescar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
      </button>
    </div>

    <div class="history-list">
      <div v-if="documents.length === 0" class="history-empty">Sin documentos aún</div>

      <div v-for="doc in documents" :key="doc.id"
        class="history-item" :class="{ active: doc.id === currentDocId }">
        <div class="item-info" @click="$emit('view', doc.id)">
          <div class="item-title">{{ doc.title || `Documento #${doc.id}` }}</div>
          <div class="item-meta">
            <span class="item-status" :class="`status--${doc.status || 'pending'}`">{{ statusLabel(doc.status) }}</span>
            <span class="item-topic">Tema #{{ doc.topicId }}</span>
            <span class="item-date">{{ formatDate(doc.generatedAt) }}</span>
          </div>
        </div>
        <div class="item-actions">
          <button type="button" class="action-btn" title="Exportar" @click="exportOpen = exportOpen === doc.id ? null : doc.id">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
          <div v-if="exportOpen === doc.id" class="export-mini-menu">
            <button @click="emitExport(doc.id, 'md')">MD</button>
            <button @click="emitExport(doc.id, 'html')">HTML</button>
            <button @click="emitExport(doc.id, 'json')">JSON</button>
          </div>
          <button type="button" class="action-btn action-btn--danger" title="Eliminar" @click="confirmDelete(doc.id)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
          </button>
        </div>
      </div>
    </div>
  </div>

  <Teleport to="body">
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal--confirm">
        <p>¿Eliminar el documento <strong>#{{ deleteTarget }}</strong>?</p>
        <div class="modal-actions">
          <button type="button" class="btn btn--secondary" @click="deleteTarget = null">Cancelar</button>
          <button type="button" class="btn btn--danger" @click="doDelete">Eliminar</button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate } = useUtils()
const props = defineProps({ documents: { type: Array, default: () => [] }, currentDocId: { type: [Number, null], default: null }, sortMode: { type: String, default: 'date-desc' } })
const emit = defineEmits(['view', 'delete', 'export', 'preview', 'sort', 'refresh'])

const sortModeLocal = ref(props.sortMode)
const spinning = ref(false)
const exportOpen = ref(null)
const deleteTarget = ref(null)
const statusLabels = { done: 'Listo', pending: 'Generando', error: 'Error' }
function statusLabel(s) { return statusLabels[s] || s || '—' }
function emitExport(docId, fmt) { exportOpen.value = null; emit('export', docId, fmt) }
async function handleRefresh() { spinning.value = true; emit('refresh'); setTimeout(() => { spinning.value = false }, 800) }
function confirmDelete(id) { deleteTarget.value = id }
function doDelete() { emit('delete', deleteTarget.value); deleteTarget.value = null }
</script>

<style scoped>
.history-panel { display: flex; flex-direction: column; height: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.history-header { display: flex; align-items: baseline; justify-content: space-between; padding: 0.85rem 1.1rem 0.4rem; }
.history-header h2 { font-size: var(--fs-md); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); }
.history-count { font-size: var(--fs-md); color: var(--text-muted); font-family: var(--font-mono); }
.history-controls { display: flex; align-items: center; gap: 0.4rem; padding: 0 1.1rem 0.65rem; border-bottom: 1px solid var(--border); }
.sort { flex: 1; padding: 0.3rem 0.45rem; font-size: var(--fs-md); }
.input { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 5px; color: var(--text); outline: none; }
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; }
.btn-icon { width: 28px; height: 28px; border-radius: 5px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0; }
.btn-icon:hover { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
.btn-icon.spinning svg { animation: seq-spin 0.7s linear infinite; }
.history-list { flex: 1; overflow-y: auto; padding: 0.4rem; }
.history-empty { text-align: center; padding: 2rem 1rem; color: var(--text-muted); font-size: var(--fs-lg); }
.history-item { display: flex; align-items: center; gap: 0.4rem; padding: 0.55rem 0.65rem; border-radius: 7px; cursor: default; transition: background 0.15s; margin-bottom: 2px; position: relative; }
.history-item:hover { background: var(--bg); }
.history-item.active { background: var(--bg); border: 1px solid var(--accent); padding: calc(0.55rem - 1px) calc(0.65rem - 1px); }
.item-info { flex: 1; min-width: 0; cursor: pointer; }
.item-title { font-size: var(--fs-lg); font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.item-meta { display: flex; align-items: center; gap: 0.35rem; margin-top: 0.1rem; font-size: var(--fs-md); color: var(--text-muted); }
.item-status { padding: 0.1rem 0.3rem; border-radius: 3px; font-weight: 600; font-size: var(--fs-body); text-transform: uppercase; }
.status--done    { background: rgba(76,183,130,0.15); color: var(--success); }
.status--pending { background: rgba(212,160,74,0.15); color: var(--warn); }
.status--error   { background: rgba(217,108,108,0.15); color: var(--danger); }
.item-actions { display: flex; gap: 0.15rem; flex-shrink: 0; align-items: center; }
.action-btn { width: 24px; height: 24px; border-radius: 4px; border: 1px solid transparent; background: none; color: var(--text-muted); cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.15s; }
.action-btn:hover { background: var(--bg); border-color: var(--border); color: var(--text); }
.action-btn--danger:hover { color: var(--danger); border-color: rgba(217,108,108,0.3); }
.export-mini-menu { position: absolute; right: 2.2rem; z-index: 25; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; overflow: hidden; display: flex; }
.export-mini-menu button { padding: 0.2rem 0.4rem; font-size: var(--fs-body); font-weight: 600; background: none; border: none; color: var(--text-dim); cursor: pointer; }
.export-mini-menu button:hover { background: var(--accent); color: var(--on-accent); }
</style>

<style>
.modal-overlay { position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,.6); display: flex; align-items: center; justify-content: center; padding: 1.5rem; backdrop-filter: blur(4px); }
.modal--confirm { background: var(--surface); border: 1px solid var(--border-solid); border-radius: 10px; padding: 1.25rem; max-width: 340px; width: 100%; }
.modal--confirm p { font-size: var(--fs-lg); color: var(--text); margin: 0 0 0.85rem; }
.modal-actions { display: flex; gap: 0.45rem; justify-content: flex-end; }
.btn { padding: 0.45rem 1.1rem; border-radius: 6px; font-size: var(--fs-lg); font-weight: 600; border: 1px solid transparent; cursor: pointer; transition: background 0.2s; }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--surface-2); color: var(--text); }
.btn--danger { background: var(--danger); color: #fff; }
.btn--danger:hover { filter: brightness(1.1); }
</style>
