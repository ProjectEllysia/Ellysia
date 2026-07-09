<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="modal-overlay" @click.self="close">
        <div class="modal">
            <div class="modal-header">
              <h3>{{ title }}</h3>
              <button class="close-btn" @click="close">&times;</button>
            </div>
            <form @submit.prevent="submit">
              <div class="modal-body">
                <label for="folder-name">Nombre de la carpeta</label>
                <input
                  id="folder-name"
                  v-model="name"
                  type="text"
                  placeholder="Ej. Producción"
                  maxlength="255"
                  :disabled="submitting"
                  required
                />
                <p class="hint">Solo letras, números, espacios, guiones y guiones bajos.</p>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn-secondary" :disabled="submitting" @click="close">Cancelar</button>
                <button type="submit" class="btn-primary" :disabled="submitting || !isValid">
                  <span v-if="submitting">Guardando…</span>
                  <span v-else>Guardar</span>
                </button>
              </div>
            </form>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref, watch, computed } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  title: { type: String, default: 'Carpeta' },
  initialName: { type: String, default: '' },
  submitting: { type: Boolean, default: false },
})
const emit = defineEmits(['close', 'submit'])

const name = ref('')
const validRe = /^[a-zA-Z0-9\s_-]+$/
const isValid = computed(() => name.value.trim().length > 0 && validRe.test(name.value.trim()))

watch(() => props.show, (val) => {
  if (val) name.value = props.initialName
})

function close() {
  if (props.submitting) return
  emit('close')
}

function submit() {
  if (!isValid.value || props.submitting) return
  emit('submit', name.value.trim())
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal { display: block; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); pointer-events: auto; opacity: 1; visibility: visible; transform: translateZ(0); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: 0.95rem; color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: 1.4rem; cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }
.modal-body label { display: block; margin-bottom: 0.4rem; font-size: 0.78rem; color: var(--text-dim); }
.modal-body input { width: 100%; padding: 0.55rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem; }
.modal-body input:focus { outline: none; border-color: var(--accent); }
.hint { margin: 0.4rem 0 0; font-size: 0.7rem; color: var(--text-muted); }
.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0.75rem 1.1rem; border-top: 1px solid var(--border); }
.btn-secondary, .btn-primary { padding: 0.45rem 0.9rem; border-radius: 6px; font-size: 0.78rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover:not(:disabled) { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover:not(:disabled) { opacity: 0.9; }
button:disabled { opacity: 0.5; cursor: not-allowed; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-active .modal, .modal-leave-active .modal { transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease; }
.modal-enter-from .modal, .modal-leave-to .modal { opacity: 0; transform: scale(0.95) translateY(10px); }
@media (prefers-reduced-motion: reduce) {
  .modal-enter-active, .modal-leave-active,
  .modal-enter-active .modal, .modal-leave-active .modal { transition: none !important; }
}
</style>
