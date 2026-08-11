<template>
  <div class="prompt-field">
    <div class="pf-head">
      <label>{{ label }}</label>
      <button type="button" class="btn btn--ghost btn--sm" @click="openEditor">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
        </svg>
        Editar prompt
      </button>
    </div>
    <p v-if="hint" class="pf-hint">{{ hint }}</p>
    <div class="pf-preview" :class="{ 'pf-preview--empty': !modelValue }" @click="openEditor">
      {{ modelValue || 'Sin contenido' }}
    </div>
    <span class="pf-count">{{ stats(modelValue) }}</span>

    <Teleport to="body">
      <Transition name="modal">
        <!-- El clic en el overlay NO cierra: esto es un editor de textos de miles
             de caracteres, no un diálogo. Un clic despistado fuera no puede tirar
             la edición. Se sale por Cancelar, la × o Esc. -->
        <div v-if="open" class="modal-overlay">
          <div class="modal-box" role="dialog" aria-modal="true" :aria-label="title || label">
            <div class="modal-header">
              <h3>{{ title || label }}</h3>
              <button type="button" class="close-btn" @click="close">&times;</button>
            </div>
            <p v-if="hint" class="modal-hint">{{ hint }}</p>
            <textarea
              ref="editor"
              v-model="draft"
              class="pf-editor"
              spellcheck="false"
              @keydown.ctrl.enter.prevent="apply"
              @keydown.meta.enter.prevent="apply"
            ></textarea>
            <div class="modal-footer">
              <span class="pf-count">{{ stats(draft) }}</span>
              <div class="footer-actions">
                <button type="button" class="btn btn--secondary" @click="close">Cancelar</button>
                <button type="button" class="btn btn--primary" @click="apply">Aplicar</button>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup>
/**
 * Campo de texto largo con minieditor en modal.
 *
 * Los prompts del sistema son textos de dos a ocho mil caracteres; metidos en un
 * `<textarea>` de seis filas dentro de una tarjeta estrecha no se pueden ni leer
 * ni revisar. Aquí el campo solo enseña una vista previa y el botón, y el texto
 * se edita a pantalla casi completa.
 *
 * Es genérico a propósito (`v-model` sobre un string) — sirve para cualquier
 * texto largo, no solo para la vista de configuración.
 */
import { ref, nextTick, onBeforeUnmount } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, required: true },
  /** Texto explicativo bajo la etiqueta y dentro del modal */
  hint: { type: String, default: '' },
  /** Título del modal; por defecto, la etiqueta */
  title: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue'])

const open = ref(false)
const draft = ref('')
const editor = ref(null)

/** «N caracteres · M líneas» — el proxy barato del presupuesto de tokens */
function stats(text) {
  const value = text || ''
  return `${value.length} caracteres · ${value ? value.split('\n').length : 0} líneas`
}

async function openEditor() {
  draft.value = props.modelValue || ''
  open.value = true
  // El `keydown.esc` sobre un div no dispara si nada tiene el foco: listener global.
  window.addEventListener('keydown', onGlobalKeydown)
  document.body.style.overflow = 'hidden'
  await nextTick()
  editor.value?.focus()
}

function close() {
  open.value = false
  window.removeEventListener('keydown', onGlobalKeydown)
  document.body.style.overflow = ''
}

function apply() {
  emit('update:modelValue', draft.value)
  close()
}

function onGlobalKeydown(event) {
  if (event.key === 'Escape') close()
}

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onGlobalKeydown)
  document.body.style.overflow = ''
})
</script>

<style scoped>
.prompt-field { display: flex; flex-direction: column; gap: 0.3rem; }
.pf-head { display: flex; align-items: center; justify-content: space-between; gap: 0.6rem; }
.pf-head label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.pf-head svg { width: 13px; height: 13px; }
.pf-hint { font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; margin: 0; }
.pf-preview {
  background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px;
  padding: 0.45rem 0.6rem; color: var(--text-dim);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-body);
  line-height: 1.5; cursor: pointer; white-space: pre-wrap; overflow: hidden;
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-clamp: 2;
  transition: border-color var(--transition);
}
.pf-preview:hover { border-color: var(--accent); }
.pf-preview--empty { color: var(--text-muted); font-style: italic; }
.pf-count { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-body); color: var(--text-muted); }

/* Mismo idioma visual que ConfirmModal, con la caja dimensionada para escribir. */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  width: 100%; max-width: min(920px, 92vw); height: min(78vh, 720px);
  box-shadow: 0 10px 30px rgba(0,0,0,0.5);
  display: flex; flex-direction: column;
}
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-hint { font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; margin: 0; padding: 0.7rem 1.1rem 0; flex-shrink: 0; }
.pf-editor {
  flex: 1; min-height: 0; margin: 0.7rem 1.1rem; box-sizing: border-box;
  background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px;
  padding: 0.6rem 0.75rem; color: var(--text);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-input);
  line-height: 1.6; resize: none; outline: none; transition: border-color var(--transition);
}
.pf-editor:focus { border-color: var(--accent); box-shadow: none; }
.modal-footer { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.75rem 1.1rem; border-top: 1px solid var(--border); flex-shrink: 0; }
.footer-actions { display: flex; gap: 0.5rem; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-active .modal-box, .modal-leave-active .modal-box { transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease; }
.modal-enter-from .modal-box, .modal-leave-to .modal-box { opacity: 0; transform: scale(0.95) translateY(10px); }
@media (prefers-reduced-motion: reduce) {
  .modal-enter-active, .modal-leave-active,
  .modal-enter-active .modal-box, .modal-leave-active .modal-box { transition: none !important; }
}
</style>
