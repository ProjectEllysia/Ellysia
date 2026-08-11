<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>Nuevo activo</h3>
            <button class="close-btn" @click="$emit('close')">&times;</button>
          </div>
          <form class="modal-body" @submit.prevent="submit">
            <label class="field">
              <span class="field-label">Hostname</span>
              <input v-model.trim="hostname" type="text" placeholder="web-01" required maxlength="255" />
            </label>
            <label class="field">
              <span class="field-label">Sistema operativo (opcional)</span>
              <select v-model="os">
                <option :value="null">Desconocido</option>
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="darwin">macOS</option>
              </select>
            </label>

            <label class="check">
              <input v-model="powersOff" type="checkbox" />
              <span class="check-text">
                Este host se apaga a propósito
                <small>Un portátil o un equipo que se suspende. No se avisará cuando esté caído.</small>
              </span>
            </label>

            <p v-if="localError" class="error">{{ localError }}</p>

            <div class="modal-footer">
              <button type="button" class="btn-secondary" @click="$emit('close')">Cancelar</button>
              <button type="submit" class="btn-primary" :disabled="submitting">
                {{ submitting ? 'Creando…' : 'Dar de alta' }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  submitting: { type: Boolean, default: false },
  serverError: { type: String, default: '' },
})
const emit = defineEmits(['submit', 'close'])

const hostname = ref('')
const os = ref(null)
// Se pregunta en positivo ("se apaga") porque es la excepción; la API lo
// recibe en negativo (`isPersistent`), que es lo que el detector consulta.
const powersOff = ref(false)
const localError = ref('')

watch(() => props.show, (v) => {
  if (v) { hostname.value = ''; os.value = null; powersOff.value = false; localError.value = '' }
})

function submit() {
  if (!hostname.value) { localError.value = 'El hostname es obligatorio.'; return }
  localError.value = ''
  emit('submit', { hostname: hostname.value, os: os.value, isPersistent: !powersOff.value })
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }

.field { display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 0.85rem; }
.field-label { font-size: var(--fs-sm); color: var(--text-muted); }
.field input, .field select {
  padding: 0.45rem 0.6rem; border-radius: 6px; border: 1px solid var(--border-med);
  background: var(--bg); color: var(--text); font-size: var(--fs-md);
}
.field input:focus, .field select:focus { outline: none; border-color: var(--accent); }

.check { display: flex; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.85rem; cursor: pointer; }
.check input { margin-top: 0.15rem; accent-color: var(--accent); }
.check-text { display: flex; flex-direction: column; gap: 0.15rem; font-size: var(--fs-md); color: var(--text); }
.check-text small { font-size: var(--fs-sm); color: var(--text-muted); }

.error { color: var(--danger); font-size: var(--fs-sm); margin: 0 0 0.6rem; }

.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 0.4rem; }
.btn-secondary, .btn-primary { padding: 0.45rem 0.9rem; border-radius: 6px; font-size: var(--fs-md); font-weight: 600; cursor: pointer; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover:not(:disabled) { background: var(--accent-bright); }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
