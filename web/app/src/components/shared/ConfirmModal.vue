<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="modal-overlay" @click.self="$emit('cancel')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>{{ title }}</h3>
            <button class="close-btn" @click="$emit('cancel')">&times;</button>
          </div>
          <div class="modal-body">
            <p v-if="emphasis" class="emphasis">{{ emphasis }}</p>
            <p class="message">{{ message }}</p>
            <div class="modal-footer">
              <button type="button" :class="swapEmphasis ? (danger ? 'btn-danger' : 'btn-primary') : 'btn-secondary'" @click="$emit('cancel')">Cancelar</button>
              <button type="button" :class="swapEmphasis ? 'btn-secondary' : (danger ? 'btn-danger' : 'btn-primary')" @click="$emit('confirm')">
                {{ confirmLabel }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
/**
 * Modal de confirmación genérico (Q7) — sustituye a los `confirm()` nativos
 * del navegador (bloqueantes, sin estilo propio, incoherentes con el resto
 * de la UI) por el mismo idioma visual que BatchActionModal.
 */
defineProps({
  show: { type: Boolean, default: false },
  title: { type: String, default: 'Confirmar' },
  message: { type: String, required: true },
  confirmLabel: { type: String, default: 'Confirmar' },
  danger: { type: Boolean, default: false },
  swapEmphasis: { type: Boolean, default: false },
  emphasis: { type: String, default: '' },
})
defineEmits(['confirm', 'cancel'])
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }
.emphasis { font-size: var(--fs-xl); font-weight: 700; color: var(--danger); margin: 0 0 0.4rem; }
.message { font-size: var(--fs-lg); color: var(--text-dim); margin: 0 0 0.8rem; text-align: justify; }
.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0.75rem 0 0; }
.btn-secondary, .btn-primary, .btn-danger { padding: 0.45rem 0.9rem; border-radius: 6px; font-size: var(--fs-lg); font-weight: 500; cursor: pointer; transition: all 0.2s; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover { opacity: 0.9; }
.btn-danger { background: var(--danger-dim); border: 1px solid var(--danger); color: var(--danger); }
.btn-danger:hover { background: var(--danger); color: #fff; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-active .modal-box, .modal-leave-active .modal-box { transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease; }
.modal-enter-from .modal-box, .modal-leave-to .modal-box { opacity: 0; transform: scale(0.95) translateY(10px); }
@media (prefers-reduced-motion: reduce) {
  .modal-enter-active, .modal-leave-active,
  .modal-enter-active .modal-box, .modal-leave-active .modal-box { transition: none !important; }
}
</style>
