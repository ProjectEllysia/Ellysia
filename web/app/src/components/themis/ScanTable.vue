<template>
  <div class="table-wrap">
    <div class="table-toolbar">
      <span class="toolbar-title">Resultados {{ type.toUpperCase() }}</span>
      <div class="toolbar-actions">
        <slot name="batch-actions" :selected-count="selectedIds.length" :selected-ids="selectedIds" />
        <button class="btn-refresh" :disabled="loading" @click="$emit('refresh')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: loading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Actualizar
        </button>
      </div>
    </div>
    <Transition name="fade-swap" mode="out-in">
      <div v-if="showLoading" key="loading" class="empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        <span>Cargando…</span>
      </div>
      <div v-else-if="error" key="error" class="empty-state error-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>{{ error }}</span>
        <button class="btn-refresh" @click="$emit('refresh')">Reintentar</button>
      </div>
      <div v-else-if="!rows.length" key="empty" class="empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        <span>No hay escaneos todavía. ¡Lanza el primero!</span>
      </div>
      <table v-else key="table">
        <thead><tr>
          <th class="chk-col"><input type="checkbox" :checked="allSelected" :indeterminate="someSelected" @change="$emit('select-all', rows.map(r => r.id))" /></th>
          <th>ID</th><th>Target</th><th>Estado</th>
          <th v-if="type === 'nmap'">Puertos</th>
          <th v-if="type === 'nikto'">Incidencias</th>
          <template v-if="type === 'nuclei'"><th>Hallazgos</th><th>Críticos</th><th>Altos</th></template>
          <th>Fecha</th><th>Acciones</th>
        </tr></thead>
        <TransitionGroup name="row" tag="tbody">
          <tr v-for="row in rows" :key="row.id" :class="{ selected: _selectedSet.has(row.id) }">
            <td class="chk-col"><input type="checkbox" :checked="_selectedSet.has(row.id)" @change="$emit('toggle-select', row.id)" /></td>
            <td class="mono">#{{ row.id }}</td>
            <td class="target">{{ row.target }}</td>
            <td><StatusBadge :status="row.status" /></td>
            <td v-if="type === 'nmap'" class="mono">{{ row.totalOpenPorts ?? 0 }} <span class="muted">puertos</span></td>
            <td v-if="type === 'nikto'" class="mono">{{ row.totalIncidents ?? 0 }} <span class="muted">hallazgos</span></td>
            <template v-if="type === 'nuclei'">
              <td class="mono">{{ row.totalFindings ?? 0 }}</td>
              <td class="sev-critical"><span v-if="row.criticalCount">{{ row.criticalCount }}</span><span v-else class="muted">0</span></td>
              <td class="sev-high"><span v-if="row.highCount">{{ row.highCount }}</span><span v-else class="muted">0</span></td>
            </template>
            <td class="date">{{ formatDate(row.startedAt) }}</td>
            <td class="actions">
              <div class="actions-row">
                <button class="act-btn" title="Vista previa" @click="$emit('preview', row.id, type)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                </button>
                <button v-if="isActive(row.status)" class="act-btn warn" title="Cancelar" @click="confirmCancel(row.id)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                </button>
                <button class="act-btn danger" title="Eliminar" @click="confirmDelete(row.id)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
                </button>
              </div>
            </td>
          </tr>
        </TransitionGroup>
      </table>
    </Transition>
    <div class="table-footer">
      <AppPagination v-if="totalCount > perPage" :current="currentPage" :total="totalCount" :per-page="perPage" @go="page => $emit('page-change', page)" />
    </div>
    <ConfirmModal
      :show="!!pendingAction"
      :title="pendingAction?.type === 'delete' ? 'Eliminar escaneo' : 'Cancelar escaneo'"
      :message="pendingAction?.type === 'delete' ? `¿Eliminar el escaneo #${pendingAction.id}?` : `¿Cancelar el escaneo #${pendingAction?.id}?`"
      :confirm-label="pendingAction?.type === 'delete' ? 'Eliminar' : 'Cancelar escaneo'"
      :danger="pendingAction?.type === 'delete'"
      @confirm="runPendingAction"
      @cancel="pendingAction = null" />
  </div>
</template>

<script setup>
import { ref, computed, watch, onUnmounted } from 'vue'
import StatusBadge from './StatusBadge.vue'
import AppPagination from '@/components/shared/AppPagination.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'

const props = defineProps({ type: { type: String, required: true }, rows: { type: Array, default: () => [] }, loading: { type: Boolean, default: false }, error: { type: String, default: null }, currentPage: { type: Number, default: 1 }, totalCount: { type: Number, default: 0 }, perPage: { type: Number, default: 10 }, selectedIds: { type: Array, default: () => [] } })
const emit = defineEmits(['preview', 'cancel', 'delete', 'refresh', 'page-change', 'toggle-select', 'select-all'])

const _selectedSet = computed(() => new Set(props.selectedIds))

const showLoading = ref(false)
let loadingTimer = null
watch(() => props.loading, (val) => { clearTimeout(loadingTimer); if (val) loadingTimer = setTimeout(() => { showLoading.value = true }, 200); else showLoading.value = false })
onUnmounted(() => clearTimeout(loadingTimer))

const allSelected = computed(() => props.rows.length > 0 && props.rows.every(r => _selectedSet.value.has(r.id)))
const someSelected = computed(() => props.rows.some(r => _selectedSet.value.has(r.id)) && !allSelected.value)

function isActive(s) { const st = (s ?? '').toLowerCase(); return st === 'running' || st === 'pending' }

// Q7: modal propio en vez de confirm() nativo del navegador.
const pendingAction = ref(null) // { type: 'cancel'|'delete', id }
function confirmCancel(id) { pendingAction.value = { type: 'cancel', id } }
function confirmDelete(id) { pendingAction.value = { type: 'delete', id } }
function runPendingAction() {
  if (pendingAction.value) emit(pendingAction.value.type, pendingAction.value.id)
  pendingAction.value = null
}
function formatDate(iso) { if (!iso) return '—'; return new Date(iso).toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.table-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1.1rem; border-bottom: 1px solid var(--border); }
.toolbar-title { font-size: var(--fs-lg); font-weight: 600; color: var(--text-dim); }
.btn-refresh { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.6rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text-muted); font-size: var(--fs-md); cursor: pointer; transition: all 0.2s; }
.btn-refresh:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-refresh:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-refresh svg { width: 11px; height: 11px; }
.toolbar-actions { display: flex; gap: 0.5rem; align-items: center; }
table { width: 100%; border-collapse: collapse; }
th { padding: 0.55rem 0.85rem; text-align: left; font-size: var(--fs-md); font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; background: var(--surface-2); }
td { padding: 0.55rem 0.85rem; font-size: var(--fs-lg); border-top: 1px solid var(--border); color: var(--text); }
tr:hover td { background: var(--surface-2); }
tr.selected td { background: rgba(99,102,241,0.06); }
.chk-col { width: 32px; text-align: center; vertical-align: middle; }
.chk-col input {
  appearance: none; -webkit-appearance: none;
  width: 12px; height: 12px;
  display: block; margin: 0 auto;
  cursor: pointer;
  border: 1.5px solid var(--border-med);
  border-radius: 3px;
  background: var(--surface-2);
  transition: all 0.15s;
}
.chk-col input:hover { border-color: var(--accent); }
.chk-col input:checked {
  background: var(--accent) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath fill='none' stroke='%230b0c10' stroke-width='2' d='M3 6l2 2 4-4'/%3E%3C/svg%3E") center/8px no-repeat;
  border-color: var(--accent);
}
.chk-col input:indeterminate {
  background: var(--accent-dim) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cline x1='3' y1='6' x2='9' y2='6' stroke='%23d4a04a' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E") center/8px no-repeat;
  border-color: var(--border-med);
}
.mono { font-family: var(--font-mono); font-size: var(--fs-lg); }
.muted { color: var(--text-muted); font-family: var(--font-body); font-size: var(--fs-md); }
.date { font-size: var(--fs-md); color: var(--text-dim); white-space: nowrap; }
.target { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sev-critical { color: var(--danger); font-weight: 600; }
.sev-high { color: var(--warn); font-weight: 600; }
.actions { vertical-align: middle; }
.actions-row { display: flex; gap: 0.25rem; }
.act-btn { width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px; color: var(--text-muted); cursor: pointer; transition: all 0.15s; }
.act-btn:hover { border-color: var(--accent); color: var(--accent); }
.act-btn svg { width: 13px; height: 13px; }
.act-btn.warn:hover { border-color: var(--warn); color: var(--warn); }
.act-btn.danger:hover { border-color: var(--danger); color: var(--danger); }
.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.4rem; padding: 2.5rem 1rem; color: var(--text-muted); font-size: var(--fs-lg); text-align: center; }
.empty-state svg { opacity: 0.2; }
.error-state { color: var(--danger); }
.error-state svg { opacity: 0.6; }
.error-state .btn-refresh { margin-top: 0.4rem; }
.spin { animation: seq-spin 0.8s linear infinite; }
.table-footer { border-top: 1px solid var(--border); padding: 0.5rem; }
@media (max-width: 768px) { .target { max-width: 100px; } }

.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.18s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

.row-move { transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.row-enter-active { transition: opacity 0.25s ease; }
.row-leave-active { transition: opacity 0.18s ease; }
.row-enter-from, .row-leave-to { opacity: 0; }

@media (prefers-reduced-motion: reduce) {
  .fade-swap-enter-active, .fade-swap-leave-active,
  .row-move, .row-enter-active, .row-leave-active { transition: none !important; }
}
</style>
