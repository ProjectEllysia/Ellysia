<template>
  <div class="accordion" :class="{ expanded: isExpanded, 'is-default': isDefault }">
    <button class="accordion-header" @click="isExpanded = !isExpanded">
      <span class="folder-icon">
        <svg v-if="isDefault" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      </span>
      <span class="folder-name">{{ folder.name }}</span>
      <span class="folder-count">{{ folder.scanCount }}</span>
      <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
    </button>

    <div class="accordion-collapse" :class="{ expanded: isExpanded }">
      <div class="accordion-collapse-inner">
        <div class="accordion-body">
          <div v-if="!folder.scans?.length" class="empty-folder">No hay escaneos en esta carpeta.</div>
          <table v-else>
            <thead><tr><th>ID</th><th>Tipo</th><th>Target</th><th>Estado</th><th>Fecha</th><th>Acciones</th></tr></thead>
            <tbody>
              <tr v-for="scan in visibleScans" :key="scan.id">
                <td class="mono">#{{ scan.id }}</td>
                <td class="mono type">{{ scan.scanType }}</td>
                <td class="target">{{ scan.target }}</td>
                <td><StatusBadge :status="scan.status" /></td>
                <td class="date">{{ formatDate(scan.startedAt) }}</td>
                <td class="actions">
                  <button class="act-btn" title="Vista previa" @click="$emit('preview', scan.id, scan.scanType)">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  </button>
                  <button class="act-btn" title="Mover a otra carpeta" @click="$emit('move-scan', { scanId: scan.id })">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 9l7-7 7 7M12 2v14"/></svg>
                  </button>
                  <button v-if="!isDefault" class="act-btn" title="Quitar de la carpeta" @click="$emit('remove-scan', { scanId: scan.id })">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                  </button>
                  <button v-if="isActive(scan.status)" class="act-btn warn" title="Cancelar" @click="$emit('cancel', scan.id)">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  </button>
                  <button class="act-btn danger" title="Eliminar escaneo" @click="$emit('delete', scan.id)">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
          <button v-if="hasMore" class="load-more" @click="visibleCount += step">
            Ver más ({{ remaining }} restantes)
          </button>
        </div>

        <div v-if="!isDefault" class="accordion-footer">
          <button class="footer-btn" @click="$emit('rename', folder)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Renombrar
          </button>
          <button class="footer-btn danger" @click="$emit('delete-folder', folder.id)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
            Eliminar carpeta
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import StatusBadge from './StatusBadge.vue'

const props = defineProps({
  folder: { type: Object, required: true },
  isDefault: { type: Boolean, default: false },
})
const emit = defineEmits(['preview', 'cancel', 'delete', 'rename', 'delete-folder', 'move-scan', 'remove-scan'])

const step = 5
const visibleCount = ref(step)
const isExpanded = ref(false)

const scans = computed(() => props.folder.scans ?? [])
const visibleScans = computed(() => scans.value.slice(0, visibleCount.value))
const hasMore = computed(() => scans.value.length > visibleCount.value)
const remaining = computed(() => scans.value.length - visibleCount.value)

function isActive(status) {
  const st = (status ?? '').toLowerCase()
  return st === 'running' || st === 'pending'
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
</script>

<style scoped>
.accordion { border-bottom: 1px solid var(--border); }
.accordion:last-child { border-bottom: none; }
.accordion-header { width: 100%; display: flex; align-items: center; gap: 0.6rem; padding: 0.75rem 1.1rem; background: none; border: none; color: var(--text); font-size: var(--fs-lg); cursor: pointer; text-align: left; }
.accordion-header:hover { background: var(--surface-2); }
.folder-icon { width: 18px; height: 18px; color: var(--accent); flex-shrink: 0; }
.is-default .folder-icon { color: var(--text-muted); }
.folder-name { flex: 1; font-weight: 500; }
.folder-count { font-size: var(--fs-md); color: var(--text-muted); background: var(--surface-2); padding: 0.15rem 0.45rem; border-radius: 10px; }
.chevron { width: 16px; height: 16px; color: var(--text-muted); transition: transform 0.2s ease; flex-shrink: 0; }
.expanded .chevron { transform: rotate(180deg); }
.accordion-collapse { display: grid; grid-template-rows: 0fr; transition: grid-template-rows 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.accordion-collapse.expanded { grid-template-rows: 1fr; }
.accordion-collapse-inner { overflow: hidden; min-height: 0; }
.accordion-body { padding: 0 1.1rem 0.75rem; }
.empty-folder { padding: 1rem 0; text-align: center; color: var(--text-muted); font-size: var(--fs-lg); }
table { width: 100%; border-collapse: collapse; }
th { padding: 0.5rem 0.7rem; text-align: left; font-size: var(--fs-body); font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; background: var(--surface-2); }
td { padding: 0.5rem 0.7rem; font-size: var(--fs-lg); border-top: 1px solid var(--border); color: var(--text); }
tr:hover td { background: var(--surface-2); }
.type { text-transform: uppercase; font-size: var(--fs-md); }
.target { max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.date { font-size: var(--fs-md); color: var(--text-dim); white-space: nowrap; }
.actions { display: flex; gap: 0.25rem; }
.act-btn { width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px; color: var(--text-muted); cursor: pointer; transition: all 0.15s; }
.act-btn:hover { border-color: var(--accent); color: var(--accent); }
.act-btn svg { width: 11px; height: 11px; }
.act-btn.warn:hover { border-color: var(--warn); color: var(--warn); }
.act-btn.danger:hover { border-color: var(--danger); color: var(--danger); }
.load-more { width: 100%; margin-top: 0.5rem; padding: 0.45rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text-dim); font-size: var(--fs-md); cursor: pointer; transition: all 0.2s; }
.load-more:hover { border-color: var(--accent); color: var(--accent); }
.accordion-footer { display: flex; gap: 0.5rem; padding: 0 1.1rem 0.75rem; }
.footer-btn { display: flex; align-items: center; gap: 0.3rem; padding: 0.35rem 0.6rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text-muted); font-size: var(--fs-md); cursor: pointer; transition: all 0.2s; }
.footer-btn:hover { border-color: var(--accent); color: var(--accent); }
.footer-btn.danger:hover { border-color: var(--danger); color: var(--danger); }
.footer-btn svg { width: 11px; height: 11px; }
@media (max-width: 768px) { .target { max-width: 80px; } }
@media (prefers-reduced-motion: reduce) {
  .accordion-collapse { transition: none; }
  .chevron { transition: none; }
}
</style>
