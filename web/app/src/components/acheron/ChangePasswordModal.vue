<template>
  <Transition name="modal-fade">
    <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-card" role="dialog" aria-modal="true">
        <header class="modal-head">
          <h2 class="modal-title">Cambiar contraseña maestra</h2>
          <button class="modal-close" aria-label="Cerrar" @click="$emit('close')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>

        <form class="modal-form" @submit.prevent="submit">
          <p class="modal-intro">
            La nueva contraseña se aplica <strong>en tu navegador</strong>: se vuelve a
            cifrar la clave de la bóveda con ella. Tus elementos no se modifican.
          </p>

          <label
            v-for="f in fields" :key="f.key"
            class="form-field"
          >
            <span class="form-label">{{ f.label }}</span>
            <div class="form-input" :class="{ 'form-input--with-generate': f.key === 'next' }">
              <input
                :ref="(el) => { if (f.key === 'current') firstInput = el }"
                v-model="form[f.key]"
                :type="revealed.has(f.key) ? 'text' : 'password'"
                :disabled="saving"
                autocomplete="off" spellcheck="false"
                :placeholder="f.label"
              />
              <button
                v-if="f.key === 'next'"
                type="button" class="gen-btn" tabindex="-1"
                aria-label="Generar contraseña"
                :disabled="saving"
                @click="generateNext"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
              </button>
              <button
                type="button" class="reveal-btn" tabindex="-1"
                :aria-label="revealed.has(f.key) ? 'Ocultar' : 'Mostrar'"
                @click="toggleReveal(f.key)"
              >
                <svg v-if="revealed.has(f.key)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
            <PasswordStrengthMeter v-if="f.key === 'next'" :password="form.next" />
          </label>

          <p v-if="displayError" class="form-error">{{ displayError }}</p>

          <div class="modal-actions">
            <span class="spacer"></span>
            <button type="button" class="btn-ghost" :disabled="saving" @click="$emit('close')">
              Cancelar
            </button>
            <button type="submit" class="btn-primary" :disabled="saving">
              <span v-if="saving" class="spinner" aria-hidden="true"></span>
              {{ saving ? 'Aplicando…' : 'Cambiar contraseña' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </Transition>
</template>

<script setup>
import { reactive, ref, computed, watch, nextTick } from 'vue'
import PasswordStrengthMeter from './PasswordStrengthMeter.vue'
import { generatePassword } from '@/acheron/passwordGenerator.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  saving: { type: Boolean, default: false },
  serverError: { type: String, default: '' },
})
const emit = defineEmits(['save', 'close'])

const MIN_LENGTH = 8

const fields = [
  { key: 'current', label: 'Contraseña actual' },
  { key: 'next', label: 'Nueva contraseña' },
  { key: 'confirm', label: 'Repite la nueva contraseña' },
]

const form = reactive({ current: '', next: '', confirm: '' })
const revealed = reactive(new Set())
const localError = ref('')
let firstInput = null

const displayError = computed(() => localError.value || props.serverError)

watch(
  () => props.open,
  (open) => {
    if (open) {
      form.current = ''
      form.next = ''
      form.confirm = ''
      revealed.clear()
      localError.value = ''
      nextTick(() => firstInput?.focus())
    }
  },
)

function toggleReveal(key) {
  if (revealed.has(key)) revealed.delete(key)
  else revealed.add(key)
}

function generateNext() {
  const generated = generatePassword()
  form.next = generated
  form.confirm = generated
  revealed.add('next')
  revealed.add('confirm')
}

function validate() {
  if (!form.current) return 'Introduce tu contraseña actual.'
  if (!form.next) return 'Introduce la nueva contraseña.'
  if (form.next.length < MIN_LENGTH) {
    return `La nueva contraseña debe tener al menos ${MIN_LENGTH} caracteres.`
  }
  if (form.next !== form.confirm) return 'Las contraseñas nuevas no coinciden.'
  if (form.next === form.current) return 'La nueva contraseña debe ser distinta de la actual.'
  return ''
}

function submit() {
  const err = validate()
  if (err) {
    localError.value = err
    return
  }
  localError.value = ''
  emit('save', { current: form.current, next: form.next })
}
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 100;
  display: flex; align-items: center; justify-content: center; padding: 1.5rem;
  background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(4px);
}
.modal-card {
  width: 100%; max-width: 440px; max-height: 88vh; overflow-y: auto;
  background: var(--surface); border: 1px solid rgba(160, 122, 192, 0.28);
  border-radius: 16px; box-shadow: 0 30px 70px rgba(0, 0, 0, 0.6);
}
.modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border);
}
.modal-title { font-family: var(--font-display); font-size: var(--fs-lg); color: var(--text); }
.modal-close {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  padding: 0.25rem; display: grid; place-items: center;
}
.modal-close:hover { color: var(--text); }
.modal-close svg { width: 20px; height: 20px; }

.modal-form { padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
.modal-intro { font-size: var(--fs-md); color: var(--text-dim); line-height: 1.5; margin: 0; }
.modal-intro strong { color: #c4a0e0; font-weight: 600; }

.form-field { display: flex; flex-direction: column; gap: 0.35rem; }
.form-label {
  font-family: var(--font-mono); font-size: var(--fs-body); text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--text-muted);
}
.form-input { position: relative; display: flex; align-items: center; }
.modal-form input {
  width: 100%; padding: 0.65rem 2.4rem 0.65rem 0.8rem; background: var(--surface-2);
  border: 1px solid var(--border-med); border-radius: 9px; color: var(--text);
  font-size: var(--fs-md); font-family: var(--font-mono); transition: border-color 0.2s ease;
}
.modal-form input:focus { outline: none; border-color: rgba(160, 122, 192, 0.55); }
.form-input--with-generate input { padding-right: 4.4rem; }
.reveal-btn {
  position: absolute; right: 0.5rem; background: none; border: none;
  color: var(--text-muted); cursor: pointer; padding: 0.3rem; display: grid; place-items: center;
}
.reveal-btn:hover { color: #c4a0e0; }
.reveal-btn svg { width: 17px; height: 17px; }
.gen-btn {
  position: absolute; right: 2.4rem; background: none; border: none;
  color: var(--text-muted); cursor: pointer; padding: 0.3rem; display: grid; place-items: center;
  transition: color 0.15s ease;
}
.gen-btn:hover:not(:disabled) { color: #c4a0e0; }
.gen-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.gen-btn svg { width: 16px; height: 16px; }

.form-error {
  color: var(--danger); font-size: var(--fs-md);
  background: var(--danger-dim); border: 1px solid rgba(217, 108, 108, 0.25);
  border-radius: 8px; padding: 0.5rem 0.7rem;
}

.modal-actions { display: flex; align-items: center; gap: 0.6rem; margin-top: 0.3rem; }
.spacer { flex: 1; }
.btn-ghost {
  padding: 0.6rem 0.9rem; border-radius: 9px; cursor: pointer;
  background: none; border: 1px solid var(--border-med); color: var(--text-dim);
  font-size: var(--fs-md); transition: all 0.18s ease;
}
.btn-ghost:hover:not(:disabled) { color: var(--text); border-color: var(--border-solid); }
.btn-primary {
  padding: 0.6rem 1.2rem; border: none; border-radius: 9px; cursor: pointer;
  background: linear-gradient(135deg, #a07ac0, #7d5aa0); color: #fff;
  font-size: var(--fs-md); font-weight: 600;
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
</style>
