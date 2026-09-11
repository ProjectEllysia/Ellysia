<template>
  <div class="iris-form">
    <div class="form-header">
      <h2>Nuevo Análisis</h2>
      <p class="form-hint">
        Arrastra un archivo .eml o pega las cabeceras, y elige qué parte del correo quieres que Iris examine.
        Para varios correos a la vez, suelta varios .eml o un ZIP, o
        <label class="batch-link">
          elige un lote
          <input type="file" accept=".eml,.zip,message/rfc822,application/zip" multiple class="batch-input" @change="pickBatch" />
        </label>.
      </p>
    </div>

    <div class="form-body">
      <input
        v-model="title"
        type="text"
        class="form-title"
        maxlength="120"
        placeholder="Título opcional para identificar el análisis (ej: Correo sospechoso)"
      />

      <!-- El modo es una elección explícita y reversible, no algo que se deduce
           de si el usuario tocó el textarea. -->
      <div class="mode-switch" role="radiogroup" aria-label="Qué se analiza">
        <button
          type="button"
          role="radio"
          class="mode-option"
          :class="{ 'mode-option--active': mode === MODE_HEADERS }"
          :aria-checked="mode === MODE_HEADERS"
          @click="mode = MODE_HEADERS"
        >
          <span class="mode-name">Solo cabeceras</span>
          <span class="mode-sub">Autenticación, remitente y ruta de entrega</span>
        </button>
        <button
          type="button"
          role="radio"
          class="mode-option"
          :class="{ 'mode-option--active': mode === MODE_MESSAGE }"
          :aria-checked="mode === MODE_MESSAGE"
          :disabled="!message"
          @click="mode = MODE_MESSAGE"
        >
          <span class="mode-name">Mensaje completo (.eml)</span>
          <span class="mode-sub">{{ message ? 'Añade cuerpo, enlaces y adjuntos' : 'Arrastra un .eml para activarlo' }}</span>
        </button>
      </div>

      <p v-if="mode === MODE_MESSAGE" class="mode-notice mode-notice--warn">{{ fullMessageNotice }}</p>
      <details v-else-if="uncoveredRules.length" class="mode-notice">
        <summary>{{ uncoveredRules.length }} reglas no se evaluarán en este modo (necesitan cuerpo, enlaces o adjuntos)</summary>
        <p class="mode-rules">{{ uncoveredRules.join(' · ') }}</p>
      </details>

      <textarea
        v-model="shownHeaders"
        class="form-textarea"
        :readonly="mode === MODE_MESSAGE"
        placeholder="Received: from mail.example.com (209.85.220.41)&#10;DKIM-Signature: v=1; a=rsa-sha256; d=example.com;&#10;From: &quot;Usuario&quot; &lt;user@example.com&gt;&#10;Reply-To: user@example.com&#10;Return-Path: &lt;user@example.com&gt;&#10;Message-ID: &lt;20260607120000.abc123@mail.example.com&gt;&#10;Authentication-Results: mx.google.com;&#10;  spf=pass smtp.mailfrom=example.com;&#10;  dkim=pass header.i=@example.com;&#10;  dmarc=pass action=none;"
        rows="14"
        spellcheck="false"
      ></textarea>
      <p v-if="mode === MODE_MESSAGE" class="form-subhint">
        Se analiza el .eml tal como se cargó. Para editar las cabeceras, cambia a «Solo cabeceras».
      </p>
    </div>

    <div class="form-footer">
      <div class="char-count">{{ shownHeaders.length }} caracteres</div>
      <button
        type="button"
        class="btn-analyze"
        :disabled="!canSubmit || submitting"
        @click="handleSubmit"
      >
        <span v-if="submitting" class="btn-spinner"></span>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          <polyline points="12 8 12 16"/>
          <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
        {{ submitting ? 'Analizando…' : (mode === MODE_MESSAGE ? 'Analizar mensaje completo' : 'Analizar cabeceras') }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useIrisStore } from '@/stores/irisStore'
import { MODE_HEADERS, MODE_MESSAGE } from '@/components/iris/intake.js'

const emit = defineEmits(['submit', 'batch'])
const props = defineProps({
  submitting: { type: Boolean, default: false },
  // Relleno automático al arrastrar un .eml: { headers, message, title, token }
  prefill: { type: Object, default: null },
})

const store = useIrisStore()

// Respaldo mientras `/iris/capabilities` no ha respondido: el texto de verdad
// lo publica el servidor, para que la UI y la API avisen de lo mismo.
const FALLBACK_NOTICE = 'El mensaje completo incluye cuerpo y adjuntos, que pueden contener datos personales o confidenciales.'

const title = ref('')
// Cabeceras editables (modo solo cabeceras).
const headers = ref('')
// Mensaje .eml completo, si el archivo arrastrado se cargó entero.
const message = ref(null)
// Cabeceras tal como llegaron con el .eml: es lo que se ve en modo completo.
const loadedHeaders = ref('')
const mode = ref(MODE_HEADERS)

function applyPrefill() {
  headers.value = props.prefill?.headers ?? ''
  title.value = props.prefill?.title ?? ''
  message.value = props.prefill?.message ?? null
  loadedHeaders.value = headers.value
  mode.value = message.value ? MODE_MESSAGE : MODE_HEADERS
}

applyPrefill()
// Cuando llega un nuevo .eml (token distinto), reemplaza el contenido del formulario.
watch(() => props.prefill?.token, () => { if (props.prefill) applyPrefill() })

const shownHeaders = computed({
  get: () => (mode.value === MODE_MESSAGE ? loadedHeaders.value : headers.value),
  set: (value) => { headers.value = value },
})

const uncoveredRules = computed(() => store.capabilities?.headersOnlyUncoveredRules ?? [])
const fullMessageNotice = computed(() => store.capabilities?.fullMessageNotice || FALLBACK_NOTICE)

const canSubmit = computed(() =>
  mode.value === MODE_MESSAGE ? !!message.value : headers.value.length >= 10
)

/** Ficheros elegidos con el selector de lote: los analiza IrisView como lote. */
function pickBatch(event) {
  const files = Array.from(event.target.files ?? [])
  event.target.value = ''
  if (files.length) emit('batch', files)
}

function handleSubmit() {
  if (!canSubmit.value || props.submitting) return
  emit('submit', {
    mode: mode.value,
    headers: headers.value,
    message: message.value,
    title: title.value || undefined,
  })
}
</script>

<style scoped>
.iris-form {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  max-width: 820px;
  width: 100%;
  margin: 0 auto;
}

.form-header h2 {
  font-size: var(--fs-2xl);
  font-weight: 700;
  color: var(--text);
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  margin: 0 0 0.35rem;
}

.form-hint {
  font-size: var(--fs-lg);
  color: var(--text-dim);
  line-height: 1.5;
  margin: 0;
}

.batch-link { color: var(--accent-bright); text-decoration: underline; cursor: pointer; }
.batch-input { display: none; }

.form-body {
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
  position: relative;
}

.form-title {
  width: 100%;
  padding: 0.7rem 0.85rem;
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
  font-size: var(--fs-lg);
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 8px;
  color: var(--text);
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.form-title:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-dim);
}

.form-title::placeholder {
  color: var(--text-muted);
  opacity: 0.4;
}

.mode-switch {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.6rem;
}

.mode-option {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  padding: 0.65rem 0.85rem;
  text-align: left;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 8px;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
}

.mode-option--active {
  border-color: var(--accent);
  background: var(--accent-dim);
}

.mode-option:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.mode-name {
  font-size: var(--fs-md);
  font-weight: 700;
  color: var(--text);
}

.mode-sub {
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.mode-notice {
  margin: 0;
  padding: 0.55rem 0.8rem;
  font-size: var(--fs-sm);
  line-height: 1.5;
  color: var(--text-dim);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 8px;
}

.mode-notice summary { cursor: pointer; }

.mode-notice--warn {
  color: var(--warn);
  background: var(--warn-dim);
  border-color: rgba(212, 160, 74, 0.25);
}

.mode-rules { margin: 0.4rem 0 0; color: var(--text-muted); }

.form-textarea {
  width: 100%;
  min-height: 320px;
  resize: vertical;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  line-height: 1.7;
  padding: 1.1rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 8px;
  color: var(--text);
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.form-textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-dim);
}

.form-textarea[readonly] {
  color: var(--text-dim);
}

.form-textarea::placeholder {
  color: var(--text-muted);
  font-size: var(--fs-md);
  opacity: 0.35;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
}

.form-subhint {
  margin: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.form-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.25rem;
}

.char-count {
  font-size: var(--fs-md);
  color: var(--text-muted);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
}

.btn-analyze {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0.75rem 1.5rem;
  font-size: var(--fs-md);
  font-weight: 700;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  background: var(--accent);
  color: var(--on-accent);
  transition: opacity 0.2s, transform 0.15s;
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
}

.btn-analyze:hover:not(:disabled) {
  opacity: 0.85;
  transform: translateY(-1px);
}

.btn-analyze:disabled {
  opacity: 0.35;
  cursor: not-allowed;
  transform: none;
}

.btn-analyze .btn-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.btn-spinner {
  width: 18px;
  height: 18px;
  border: 2px solid rgba(0, 0, 0, 0.15);
  border-top-color: var(--on-accent);
  border-radius: 50%;
  animation: seq-spin 0.6s linear infinite;
}

@media (max-width: 540px) {
  .mode-switch { grid-template-columns: 1fr; }
}
</style>
