<template>
  <Transition name="modal-fade">
    <div v-if="open" class="modal-backdrop" @click.self="$emit('cancel')">
      <div class="modal-card" role="dialog" aria-modal="true">
        <header class="modal-head">
          <h2 class="modal-title">Activar verificación en dos pasos</h2>
          <button class="modal-close" aria-label="Cerrar" @click="$emit('cancel')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>

        <form class="modal-form" @submit.prevent="submit">
          <p class="modal-intro">Escanea este código con tu app autenticadora (Google Authenticator, Authy, 1Password…):</p>

          <div class="qr-wrap">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="Código QR de activación MFA" class="qr-img" />
            <div v-else class="qr-placeholder skeleton"></div>
          </div>

          <button type="button" class="secret-toggle" @click="showSecret = !showSecret">
            {{ showSecret ? 'Ocultar clave manual' : '¿No puedes escanear? Introducir clave manualmente' }}
          </button>
          <Transition name="collapse">
            <code v-if="showSecret" class="mfa-secret">{{ secret }}</code>
          </Transition>

          <label class="form-field">
            <span class="form-label">Código de la app</span>
            <input
              ref="codeInput"
              v-model="code"
              type="text" inputmode="numeric" autocomplete="one-time-code"
              placeholder="123456" :disabled="confirming"
            />
          </label>

          <div class="modal-actions">
            <span class="spacer"></span>
            <button type="button" class="btn-ghost" :disabled="confirming" @click="$emit('cancel')">Cancelar</button>
            <button type="submit" class="btn-primary" :disabled="confirming || !code.trim()">
              <span v-if="confirming" class="spinner" aria-hidden="true"></span>
              {{ confirming ? 'Confirmando…' : 'Confirmar' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </Transition>
</template>

<script setup>
import { ref, watch, nextTick } from 'vue'
import QRCode from 'qrcode'

const props = defineProps({
  open: { type: Boolean, default: false },
  secret: { type: String, default: '' },
  provisioningUri: { type: String, default: '' },
  confirming: { type: Boolean, default: false },
})
const emit = defineEmits(['confirm', 'cancel'])

const code = ref('')
const showSecret = ref(false)
const qrDataUrl = ref('')
const codeInput = ref(null)

watch(() => props.provisioningUri, async (uri) => {
  qrDataUrl.value = uri ? await QRCode.toDataURL(uri, { width: 220, margin: 1 }) : ''
}, { immediate: true })

watch(() => props.open, (open) => {
  if (open) {
    code.value = ''
    showSecret.value = false
    nextTick(() => codeInput.value?.focus())
  }
})

function submit() {
  if (!code.value.trim()) return
  emit('confirm', code.value.trim())
}
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 100;
  display: flex; align-items: center; justify-content: center; padding: 1.5rem;
  background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(4px);
}
.modal-card {
  width: 100%; max-width: 400px; max-height: 88vh; overflow-y: auto;
  background: var(--surface); border: 1px solid var(--border-solid);
  border-radius: 16px; box-shadow: 0 30px 70px rgba(0, 0, 0, 0.6);
}
.modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border);
}
.modal-title { font-family: var(--font-display); font-size: 1.93rem; color: var(--text); }
.modal-close {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  padding: 0.25rem; display: grid; place-items: center;
}
.modal-close:hover { color: var(--text); }
.modal-close svg { width: 20px; height: 20px; }

.modal-form { padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
.modal-intro { font-size: 1.44rem; color: var(--text-dim); line-height: 1.5; margin: 0; }

.qr-wrap { display: flex; justify-content: center; }
.qr-img { width: 220px; height: 220px; border-radius: 10px; background: #fff; padding: 10px; }
.qr-placeholder { width: 220px; height: 220px; border-radius: 10px; }
.skeleton { background: var(--surface); animation: pulse 1.4s ease-in-out infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }

.secret-toggle {
  align-self: center; background: none; border: none; cursor: pointer;
  color: #c4a0e0; font-size: 1.37rem; text-decoration: underline; padding: 0;
}
.secret-toggle:hover { color: #d8bce8; }
.mfa-secret {
  display: block; padding: 0.6rem 0.75rem;
  background: rgba(0, 0, 0, 0.25); border: 1px solid var(--border-med); border-radius: 8px;
  font-family: monospace; font-size: 1.49rem; letter-spacing: 0.05em; word-break: break-all;
  color: var(--text); overflow: hidden;
}
.collapse-enter-active, .collapse-leave-active { transition: all 0.2s ease; }
.collapse-enter-from, .collapse-leave-to { opacity: 0; max-height: 0; padding-top: 0; padding-bottom: 0; margin: 0; }

.form-field { display: flex; flex-direction: column; gap: 0.35rem; }
.form-label {
  font-family: var(--font-mono); font-size: 1.16rem; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--text-muted);
}
.modal-form input {
  width: 100%; padding: 0.65rem 0.8rem; background: rgba(0, 0, 0, 0.25);
  border: 1px solid var(--border-med); border-radius: 9px; color: var(--text);
  font-size: 1.58rem; font-family: var(--font-mono); letter-spacing: 0.1em;
  transition: border-color 0.2s ease;
}
.modal-form input:focus { outline: none; border-color: rgba(160, 122, 192, 0.55); }

.modal-actions { display: flex; align-items: center; gap: 0.6rem; margin-top: 0.3rem; }
.spacer { flex: 1; }
.btn-ghost {
  padding: 0.6rem 0.9rem; border-radius: 9px; cursor: pointer;
  background: none; border: 1px solid var(--border-med); color: var(--text-dim);
  font-size: 1.49rem; transition: all 0.18s ease;
}
.btn-ghost:hover:not(:disabled) { color: var(--text); border-color: var(--border-solid); }
.btn-primary {
  padding: 0.6rem 1.2rem; border: none; border-radius: 9px; cursor: pointer;
  background: linear-gradient(135deg, #a07ac0, #7d5aa0); color: #fff;
  font-size: 1.49rem; font-weight: 600;
  display: inline-flex; align-items: center; gap: 0.5rem;
  transition: filter 0.18s ease;
}
.btn-primary:hover:not(:disabled) { filter: brightness(1.1); }
.btn-primary:disabled, .btn-ghost:disabled { opacity: 0.5; cursor: not-allowed; }
.spinner {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.35); border-top-color: #fff;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.modal-fade-enter-active, .modal-fade-leave-active { transition: opacity 0.2s ease; }
.modal-fade-enter-from, .modal-fade-leave-to { opacity: 0; }
.modal-fade-enter-active .modal-card, .modal-fade-leave-active .modal-card { transition: transform 0.2s ease; }
.modal-fade-enter-from .modal-card, .modal-fade-leave-to .modal-card { transform: scale(0.95) translateY(8px); }
</style>
