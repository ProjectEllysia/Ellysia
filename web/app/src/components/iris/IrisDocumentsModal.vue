<template>
  <Transition name="modal">
    <div v-if="show" class="modal visible" role="dialog" aria-modal="true">
      <div class="modal-backdrop" @click="$emit('close')"></div>
      <div class="modal-content docs-modal-content">
        <div class="modal-header">
          <h2>Informes PDF</h2>
          <button class="modal-close" @click="$emit('close')" aria-label="Cerrar">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>

        <div class="modal-body">
          <div class="docs-actions">
            <button
              type="button"
              class="icon-btn"
              title="Refrescar"
              :disabled="loading"
              @click="$emit('refresh')"
            >
              <svg class="refresh-icon" :class="{ spinning: loading }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="23 4 23 10 17 10"/>
                <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
              </svg>
            </button>
            <button
              type="button"
              class="generate-btn"
              :disabled="!canGenerate || generating"
              @click="$emit('generate')"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/><line x1="9" y1="11" x2="13" y2="11"/></svg>
              {{ generating ? 'Generando…' : 'Generar informe' }}
            </button>
          </div>

          <p v-if="!canGenerate" class="docs-hint">
            El informe PDF solo puede generarse cuando el análisis ha finalizado.
          </p>

          <div v-if="!documents.length" class="docs-empty">
            Aún no se ha generado ningún informe para este análisis.
          </div>

          <ul v-else class="docs-list">
            <li v-for="doc in documents" :key="doc.documentId" class="doc-item">
              <div class="doc-info">
                <span class="doc-status" :class="`status--${doc.status}`">{{ statusLabel(doc.status) }}</span>
                <span class="doc-id">#{{ doc.documentId }}</span>
                <span v-if="doc.verdict" class="doc-verdict" :class="`verdict--${verdictClass(doc.verdict)}`">{{ doc.verdict }}</span>
                <span class="doc-date">{{ formatDate(doc.generatedAt || doc.createdAt) }}</span>
              </div>
              <div class="doc-buttons">
                <button
                  type="button"
                  class="icon-btn"
                  title="Descargar"
                  :disabled="doc.status !== 'done'"
                  @click="$emit('download', doc.documentId)"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                </button>
                <button
                  type="button"
                  class="icon-btn icon-btn--danger"
                  title="Eliminar"
                  @click="$emit('delete', doc.documentId)"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                </button>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </Transition>
</template>

<script setup>
import { useUtils } from '@/composables/useUtils'

const { formatDate } = useUtils()

defineProps({
  show: { type: Boolean, default: false },
  documents: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  generating: { type: Boolean, default: false },
  canGenerate: { type: Boolean, default: false },
})

defineEmits(['close', 'refresh', 'generate', 'download', 'delete'])

function statusLabel(status) {
  if (status === 'running') return 'Generando'
  if (status === 'done') return 'Listo'
  if (status === 'error') return 'Error'
  return status
}

function verdictClass(v) {
  const value = v?.toLowerCase() ?? ''
  if (value === 'legitimate') return 'legit'
  if (value === 'suspicious') return 'susp'
  if (value === 'phishing') return 'phish'
  return 'unknown'
}
</script>

<style scoped>
/* Antes heredado de la regla global `.modal`/`.modal.visible` de shared.css
   (legacy pre-Vue): posición, capa y centrado propios, ahora que ese bloque
   se borra (#131). */
.modal {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}
.modal.visible {
  display: flex;
}

.docs-modal-content {
  max-width: 560px;
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.2s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
.modal-enter-active .modal-content,
.modal-leave-active .modal-content {
  transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease;
}
.modal-enter-from .modal-content,
.modal-leave-to .modal-content {
  opacity: 0;
  transform: scale(0.96) translateY(10px);
}
@media (prefers-reduced-motion: reduce) {
  .modal-enter-active,
  .modal-leave-active,
  .modal-enter-active .modal-content,
  .modal-leave-active .modal-content {
    transition: none !important;
  }
}

.docs-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.9rem;
}

.icon-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.2s;
}

.icon-btn svg {
  width: 17px;
  height: 17px;
}

.icon-btn:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-dim);
}

.icon-btn--danger:hover:not(:disabled) {
  border-color: var(--danger);
  color: var(--danger);
  background: var(--danger-dim);
}

.icon-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.refresh-icon.spinning {
  animation: docs-spin 0.9s linear infinite;
}

@keyframes docs-spin {
  to { transform: rotate(360deg); }
}

.generate-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 1.1rem;
  font-size: var(--fs-lg);
  font-weight: 600;
  border-radius: 8px;
  border: 1px solid var(--accent);
  background: var(--accent-dim);
  color: var(--accent);
  cursor: pointer;
  transition: all 0.2s;
}

.generate-btn svg {
  width: 16px;
  height: 16px;
}

.generate-btn:hover:not(:disabled) {
  background: var(--accent);
  color: var(--bg);
}

.generate-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.docs-hint {
  margin: 0 0 0.9rem;
  font-size: var(--fs-lg);
  color: var(--text-muted);
}

.docs-empty {
  padding: 1rem;
  text-align: center;
  font-size: var(--fs-lg);
  color: var(--text-muted);
  border: 1px dashed var(--border);
  border-radius: 8px;
}

.docs-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.doc-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
  padding: 0.65rem 0.9rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}

.doc-info {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  min-width: 0;
}

.doc-status {
  font-size: var(--fs-md);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 3px 8px;
  border-radius: 5px;
}

.status--running {
  background: var(--warn-dim);
  color: var(--warn);
}

.status--done {
  background: var(--success-dim);
  color: var(--success);
}

.status--error {
  background: var(--danger-dim);
  color: var(--danger);
}

.doc-id {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  color: var(--text-dim);
}

.doc-verdict {
  font-size: var(--fs-md);
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 5px;
}

.verdict--legit { color: var(--success); background: var(--success-dim); }
.verdict--susp { color: var(--warn); background: var(--warn-dim); }
.verdict--phish { color: var(--danger); background: var(--danger-dim); }

.doc-date {
  font-size: var(--fs-lg);
  color: var(--text-muted);
}

.doc-buttons {
  display: flex;
  gap: 0.3rem;
  flex-shrink: 0;
}
</style>
