<template>
  <div class="iris-form">
    <div class="form-header">
      <h2>Nuevo Análisis</h2>
      <p class="form-hint">
        Arrastra un archivo .eml para analizar el correo completo (cuerpo, enlaces y adjuntos),
        o pega aquí solo las cabeceras.
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
      <textarea
        v-model="headers"
        class="form-textarea"
        placeholder="Received: from mail.example.com (209.85.220.41)&#10;DKIM-Signature: v=1; a=rsa-sha256; d=example.com;&#10;From: &quot;Usuario&quot; &lt;user@example.com&gt;&#10;Reply-To: user@example.com&#10;Return-Path: &lt;user@example.com&gt;&#10;Message-ID: &lt;20260607120000.abc123@mail.example.com&gt;&#10;Authentication-Results: mx.google.com;&#10;  spf=pass smtp.mailfrom=example.com;&#10;  dkim=pass header.i=@example.com;&#10;  dmarc=pass action=none;"
        rows="14"
        spellcheck="false"
      ></textarea>
    </div>

    <div class="form-footer">
      <div class="char-count">{{ headers.length }} caracteres</div>
      <button
        type="button"
        class="btn-analyze"
        :disabled="headers.length < 10 || submitting"
        @click="handleSubmit"
      >
        <span v-if="submitting" class="btn-spinner"></span>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          <polyline points="12 8 12 16"/>
          <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
        {{ submitting ? 'Analizando…' : 'Analizar Cabeceras' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

const emit = defineEmits(['submit'])
const props = defineProps({
  submitting: { type: Boolean, default: false },
  // Relleno automático al arrastrar un .eml: { headers, message, title, token }
  prefill: { type: Object, default: null },
})

const headers = ref(props.prefill?.headers ?? '')
const title = ref(props.prefill?.title ?? '')
// Mensaje .eml completo (Fase 2), si el archivo arrastrado se cargó entero.
const message = ref(props.prefill?.message ?? null)
// Cabeceras tal como llegaron del prefill: si el usuario las edita, ya no
// podemos garantizar que sigan correspondiendo al mensaje completo cargado,
// así que dejamos de enviarlo y caemos de vuelta a solo-cabeceras.
const loadedHeaders = ref(headers.value)

// Cuando llega un nuevo .eml (token distinto), reemplaza el contenido del formulario.
watch(
  () => props.prefill?.token,
  () => {
    if (!props.prefill) return
    headers.value = props.prefill.headers ?? ''
    title.value = props.prefill.title ?? ''
    message.value = props.prefill.message ?? null
    loadedHeaders.value = headers.value
  },
)

function handleSubmit() {
  if (headers.value.length < 10 || props.submitting) return
  const useFullMessage = message.value && headers.value === loadedHeaders.value
  emit('submit', {
    headers: headers.value,
    message: useFullMessage ? message.value : undefined,
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
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text);
  font-family: var(--font-display);
  margin: 0 0 0.35rem;
}

.form-hint {
  font-size: 0.92rem;
  color: var(--text-dim);
  line-height: 1.5;
  margin: 0;
}

.form-body {
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
  position: relative;
}

.form-title {
  width: 100%;
  padding: 0.7rem 0.85rem;
  font-family: var(--font-body);
  font-size: 0.9rem;
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

.form-textarea {
  width: 100%;
  min-height: 320px;
  resize: vertical;
  font-family: var(--font-mono);
  font-size: 0.88rem;
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

.form-textarea::placeholder {
  color: var(--text-muted);
  opacity: 0.35;
  font-family: var(--font-mono);
  font-size: 0.82rem;
}

.form-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.25rem;
}

.char-count {
  font-size: 0.85rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.btn-analyze {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0.75rem 1.5rem;
  font-size: 0.95rem;
  font-weight: 700;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  background: var(--accent);
  color: var(--on-accent);
  transition: opacity 0.2s, transform 0.15s;
  font-family: var(--font-body);
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
</style>
