<template>
  <Transition name="modal-fade">
    <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-card" role="dialog" aria-modal="true">
        <header class="modal-head">
          <h2 class="modal-title">{{ headerTitle }}</h2>
          <button class="modal-close" aria-label="Cerrar" @click="$emit('close')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>

        <!-- Selector de tipo (solo al añadir, antes de elegir) -->
        <div v-if="mode === 'add' && !selectedCategory" class="type-grid">
          <button
            v-for="t in STORABLE_TYPES" :key="t.kind"
            type="button" class="type-btn"
            @click="pickType(t.category)"
          >
            <span class="type-btn-label">{{ t.label }}</span>
            <span class="type-btn-sub">{{ t.newLabel }}</span>
          </button>
        </div>

        <!-- Formulario de campos -->
        <form v-else class="modal-form" @submit.prevent="submit">
          <label class="form-field">
            <span class="form-label">Título</span>
            <input
              ref="firstInput" v-model.trim="form.title" type="text"
              :disabled="saving" placeholder="Nombre para reconocerlo"
            />
          </label>

          <label v-for="f in type.fields" :key="f.key" class="form-field">
            <span class="form-label">
              {{ f.label }}
              <span v-if="mode === 'edit' && f.prefill === false" class="form-hint">(en blanco = sin cambios)</span>
            </span>

            <textarea
              v-if="f.multiline"
              v-model="form[f.key]" :disabled="saving" rows="4"
              :placeholder="f.label"
            ></textarea>

            <div v-else class="form-input">
              <input
                v-model="form[f.key]"
                :type="f.secret && !revealed.has(f.key) ? 'password' : 'text'"
                :inputmode="f.numeric ? 'numeric' : 'text'"
                :disabled="saving"
                autocomplete="off" spellcheck="false"
                :placeholder="f.label"
              />
              <button
                v-if="f.secret" type="button" class="reveal-btn" tabindex="-1"
                :aria-label="revealed.has(f.key) ? 'Ocultar' : 'Mostrar'"
                @click="toggleReveal(f.key)"
              >
                <svg v-if="revealed.has(f.key)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
          </label>

          <p v-if="displayError" class="form-error">{{ displayError }}</p>

          <div class="modal-actions">
            <button
              v-if="mode === 'add'" type="button" class="btn-ghost"
              :disabled="saving" @click="selectedCategory = null"
            >
              ← Tipo
            </button>
            <span class="spacer"></span>
            <button type="button" class="btn-ghost" :disabled="saving" @click="$emit('close')">
              Cancelar
            </button>
            <button type="submit" class="btn-primary" :disabled="saving">
              <span v-if="saving" class="spinner" aria-hidden="true"></span>
              {{ saving ? 'Guardando…' : 'Guardar' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </Transition>
</template>

<script setup>
import { ref, reactive, computed, watch, nextTick } from 'vue'
import { STORABLE_TYPES, TYPE_BY_CATEGORY } from '@/acheron/storableTypes.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  mode: { type: String, default: 'add' }, // 'add' | 'edit'
  category: { type: String, default: null },
  item: { type: Object, default: null },
  saving: { type: Boolean, default: false },
  serverError: { type: String, default: '' },
})
const emit = defineEmits(['save', 'close'])

const selectedCategory = ref(null)
const form = reactive({ title: '' })
const revealed = reactive(new Set())
const localError = ref('')
const firstInput = ref(null)

const type = computed(() =>
  selectedCategory.value ? TYPE_BY_CATEGORY[selectedCategory.value] : null,
)
const headerTitle = computed(() => {
  if (props.mode === 'edit') return `Editar ${type.value?.label ?? 'elemento'}`
  return selectedCategory.value ? type.value.newLabel : 'Nuevo elemento'
})
const displayError = computed(() => localError.value || props.serverError)

watch(
  () => props.open,
  (open) => {
    if (open) init()
  },
)

function init() {
  localError.value = ''
  revealed.clear()
  selectedCategory.value = props.mode === 'edit' ? props.category : null
  if (selectedCategory.value) setupFields()
}

function pickType(category) {
  selectedCategory.value = category
  setupFields()
  nextTick(() => firstInput.value?.focus())
}

function setupFields() {
  form.title = props.mode === 'edit' ? props.item?.title ?? '' : ''
  for (const f of type.value.fields) {
    // En edición, los secretos no-prefill (contraseña, PAN, CVV) van vacíos.
    const usePrefill = props.mode === 'edit' && f.prefill !== false
    form[f.key] = usePrefill ? props.item?.[f.key] ?? '' : ''
  }
  nextTick(() => firstInput.value?.focus())
}

function toggleReveal(key) {
  if (revealed.has(key)) revealed.delete(key)
  else revealed.add(key)
}

function validate() {
  if (!form.title?.trim()) return 'El título es obligatorio.'
  for (const f of type.value.fields) {
    const v = (form[f.key] ?? '').toString().trim()
    const optionalOnEdit = props.mode === 'edit' && f.prefill === false
    if (!v) {
      if (!optionalOnEdit) return `El campo «${f.label}» es obligatorio.`
      continue // secreto no-prefill vacío en edición = sin cambios
    }
    if (f.minLength && v.length < f.minLength) {
      return `«${f.label}» debe tener al menos ${f.minLength} caracteres.`
    }
  }
  return ''
}

function collectFields() {
  const out = {}
  for (const f of type.value.fields) {
    const v = (form[f.key] ?? '').toString()
    // En edición, omitir secretos no-prefill vacíos (no se tocan).
    if (props.mode === 'edit' && f.prefill === false && v.trim() === '') continue
    out[f.key] = v
  }
  return out
}

function submit() {
  const err = validate()
  if (err) {
    localError.value = err
    return
  }
  localError.value = ''
  emit('save', {
    mode: props.mode,
    category: selectedCategory.value,
    title: form.title.trim(),
    fields: collectFields(),
    item: props.item,
  })
}
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 100;
  display: flex; align-items: center; justify-content: center; padding: 1.5rem;
  background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(4px);
}
.modal-card {
  width: 100%; max-width: 480px; max-height: 88vh; overflow-y: auto;
  background: #15161d; border: 1px solid rgba(160, 122, 192, 0.28);
  border-radius: 16px; box-shadow: 0 30px 70px rgba(0, 0, 0, 0.6);
}
.modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border);
}
.modal-title { font-family: var(--font-display); font-size: 1.62rem; color: var(--text); }
.modal-close {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  padding: 0.25rem; display: grid; place-items: center;
}
.modal-close:hover { color: var(--text); }
.modal-close svg { width: 20px; height: 20px; }

/* Selector de tipo */
.type-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; padding: 1.5rem;
}
.type-btn {
  display: flex; flex-direction: column; gap: 0.2rem; text-align: left;
  padding: 0.85rem 1rem; cursor: pointer;
  background: rgba(160, 122, 192, 0.06); border: 1px solid rgba(160, 122, 192, 0.2);
  border-radius: 10px; transition: all 0.18s ease;
}
.type-btn:hover { background: rgba(160, 122, 192, 0.14); border-color: rgba(160, 122, 192, 0.45); }
.type-btn-label { color: var(--text); font-weight: 600; font-size: 1.66rem; }
.type-btn-sub { color: var(--text-muted); font-size: 1.26rem; }

/* Formulario */
.modal-form { padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
.form-field { display: flex; flex-direction: column; gap: 0.35rem; }
.form-label {
  font-family: var(--font-mono); font-size: 1.16rem; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--text-muted);
}
.form-hint { text-transform: none; letter-spacing: 0; color: var(--text-muted); opacity: 0.8; }
.form-input { position: relative; display: flex; align-items: center; }
.modal-form input,
.modal-form textarea {
  width: 100%; padding: 0.65rem 0.8rem; background: rgba(0, 0, 0, 0.25);
  border: 1px solid var(--border-med); border-radius: 9px; color: var(--text);
  font-size: 1.58rem; font-family: var(--font-mono); transition: border-color 0.2s ease;
}
.modal-form input { padding-right: 2.4rem; }
.modal-form textarea { resize: vertical; line-height: 1.5; }
.modal-form input:focus,
.modal-form textarea:focus { outline: none; border-color: rgba(160, 122, 192, 0.55); }
.reveal-btn {
  position: absolute; right: 0.5rem; background: none; border: none;
  color: var(--text-muted); cursor: pointer; padding: 0.3rem; display: grid; place-items: center;
}
.reveal-btn:hover { color: #c4a0e0; }
.reveal-btn svg { width: 17px; height: 17px; }

.form-error {
  color: var(--danger); font-size: 1.4rem;
  background: var(--danger-dim); border: 1px solid rgba(217, 108, 108, 0.25);
  border-radius: 8px; padding: 0.5rem 0.7rem;
}

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

@media (max-width: 520px) {
  .type-grid { grid-template-columns: 1fr; }
}
</style>
