<template>
  <div class="folder-view">
    <div class="folder-toolbar">
      <span class="toolbar-title">Carpetas de escaneos</span>
      <div class="toolbar-actions">
        <button type="button" class="btn-new" @click="$emit('create-folder')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Nueva carpeta
        </button>
        <button class="btn-refresh" :disabled="loading" @click="$emit('refresh')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: loading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Actualizar
        </button>
      </div>
    </div>

    <div v-if="loading && !folders.length" class="empty-state">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
      <span>Cargando carpetas…</span>
    </div>
    <div v-else-if="!folders.length" class="empty-state">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      <span>No hay carpetas todavía. ¡Crea la primera!</span>
    </div>
    <div v-else class="folder-list">
      <FolderAccordion
        v-for="folder in folders" :key="folder.id ?? 'unfoldered'"
        :folder="folder"
        :is-default="folder.id === null"
        @preview="(id, type) => $emit('preview', id, type)"
        @cancel="$emit('cancel', $event)"
        @delete="$emit('delete', $event)"
        @rename="$emit('rename-folder', $event)"
        @delete-folder="$emit('delete-folder', $event)"
        @move-scan="$emit('move-scan', $event.scanId, folder.id)"
        @remove-scan="$emit('remove-scan', $event.scanId, folder.id)" />
    </div>
  </div>
</template>

<script setup>
import FolderAccordion from './FolderAccordion.vue'

defineProps({
  folders: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
})
defineEmits(['refresh', 'create-folder', 'preview', 'cancel', 'delete', 'rename-folder', 'delete-folder', 'move-scan', 'remove-scan'])
</script>

<style scoped>
.folder-view { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 1.1rem; }
.folder-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1.1rem; border-bottom: 1px solid var(--border); }
.toolbar-title { font-size: 0.82rem; font-weight: 600; color: var(--text-dim); }
.toolbar-actions { display: flex; gap: 0.5rem; }
.btn-new, .btn-refresh { display: flex; align-items: center; gap: 0.3rem; padding: 0.35rem 0.7rem; border-radius: 6px; font-size: 0.75rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
.btn-new { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-new:hover { opacity: 0.9; }
.btn-refresh { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-muted); }
.btn-refresh:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-refresh:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-new svg, .btn-refresh svg { width: 12px; height: 12px; }
.folder-list { display: flex; flex-direction: column; }
.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.4rem; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.82rem; text-align: center; }
.empty-state svg { opacity: 0.2; }
.spin { animation: seq-spin 0.8s linear infinite; }
</style>
