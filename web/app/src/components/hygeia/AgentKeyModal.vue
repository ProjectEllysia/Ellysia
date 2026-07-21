<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>Clave de agente</h3>
            <button class="close-btn" @click="$emit('close')">&times;</button>
          </div>
          <div class="modal-body">
            <p class="warning">
              Esta clave se muestra <strong>una única vez</strong>. Cópiala y configúrala en el
              agente ahora — no podrás volver a verla.
            </p>

            <div class="key-box">
              <code>{{ agentKey }}</code>
              <button class="copy-btn" @click="copyKey">{{ copied ? 'Copiado ✓' : 'Copiar' }}</button>
            </div>

            <p class="snippet-label">Configuración del agente:</p>
            <pre class="snippet">serverUrl: {{ serverUrl }}
agentKey: {{ agentKey }}</pre>

            <div class="modal-footer">
              <button type="button" class="btn-primary" @click="$emit('close')">Ya la he guardado</button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  agentKey: { type: String, default: '' },
})
defineEmits(['close'])

const copied = ref(false)
const serverUrl = typeof window !== 'undefined' ? window.location.origin : ''

async function copyKey() {
  try {
    await navigator.clipboard.writeText(props.agentKey)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    /* Clipboard API no disponible — el usuario puede seleccionar el texto a mano. */
  }
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 520px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }

.warning {
  font-size: var(--fs-md); color: var(--warn); background: rgba(212,160,74,0.1);
  border: 1px solid rgba(212,160,74,0.3); border-radius: 6px; padding: 0.6rem 0.8rem; margin: 0 0 0.9rem;
}

.key-box {
  display: flex; align-items: center; gap: 0.5rem;
  background: var(--bg); border: 1px solid var(--border-med); border-radius: 6px;
  padding: 0.6rem 0.7rem; margin-bottom: 0.9rem;
}
.key-box code {
  flex: 1; font-family: var(--font-mono); font-size: var(--fs-sm); color: var(--text);
  word-break: break-all;
}
.copy-btn {
  flex-shrink: 0; font-size: var(--fs-sm); padding: 0.3rem 0.65rem; border-radius: 6px;
  background: var(--accent-dim); border: 1px solid var(--accent); color: var(--accent-bright); cursor: pointer;
}
.copy-btn:hover { background: var(--accent); color: var(--on-accent); }

.snippet-label { font-size: var(--fs-sm); color: var(--text-muted); margin: 0 0 0.3rem; }
.snippet {
  font-family: var(--font-mono); font-size: var(--fs-sm); color: var(--text-dim);
  background: var(--bg); border: 1px solid var(--border-med); border-radius: 6px;
  padding: 0.6rem 0.7rem; margin: 0; white-space: pre-wrap; word-break: break-all;
}

.modal-footer { display: flex; justify-content: flex-end; margin-top: 1rem; }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); padding: 0.45rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
.btn-primary:hover { background: var(--accent-bright); }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
