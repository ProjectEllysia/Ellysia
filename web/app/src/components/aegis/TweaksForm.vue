<template>
  <div class="tweaks-form">
    <h2>Nueva Píldora</h2>

    <div class="form-group">
      <label for="tw-audience">Audiencia</label>
      <select
        id="tw-audience"
        v-model="store.tweaks.audienceLevel"
        class="input select"
      >
        <option value="mixed">Mixta</option>
        <option value="technical">Técnica</option>
        <option value="non-technical">No técnica</option>
      </select>
    </div>

    <div class="form-group">
      <label for="tw-focus">Foco del tema</label>
      <input
        id="tw-focus"
        v-model="store.tweaks.topicFocus"
        type="text"
        maxlength="120"
        class="input"
        placeholder="Ej: phishing por QR"
      />
    </div>

    <div class="form-group">
      <label for="tw-incident">Incidente reciente</label>
      <textarea
        id="tw-incident"
        v-model="store.tweaks.recentIncident"
        maxlength="500"
        rows="2"
        class="input textarea"
        placeholder="Opcional — ej: intento de phishing a Contabilidad la semana pasada"
      ></textarea>
    </div>

    <TopicGrid
      :topics="store.topics"
      :selected-topic-id="store.selectedTopicId"
      @select="store.selectedTopicId = $event"
    />

    <button
      type="button"
      class="btn-generate"
      :disabled="!store.selectedTopicId || store.generating"
      @click="store.generate()"
    >
      <span v-if="store.generating" class="spinner"></span>
      {{ store.generating ? "Generando…" : "Generar Píldora" }}
    </button>

    <!-- El fallo se anunciaba solo con un toast, que desaparece a los pocos
         segundos: si no estabas mirando, la generación había fallado y la vista
         quedaba idéntica a antes de pulsar. Aquí se queda hasta el siguiente
         intento, junto al botón que lo provocó. -->
    <p v-if="store.generateError && !store.generating" class="generate-error" role="alert">
      {{ store.generateError }}
    </p>
  </div>
</template>

<script setup>
import { useAegisStore } from "@/stores/aegisStore";
import TopicGrid from "./TopicGrid.vue";

const store = useAegisStore();
</script>

<style scoped>
.tweaks-form {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
  padding: 1.1rem;
}
.tweaks-form h2 {
  font-size: var(--fs-xl);
  font-weight: 700;
  color: var(--text);
  margin: 0 0 0.2rem;
  flex-shrink: 0;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.form-group label {
  font-size: var(--fs-md);
  font-weight: 600;
  color: var(--text-dim);
}
.input {
  background: var(--bg);
  border: 1px solid var(--border-solid);
  border-radius: 6px;
  padding: 0.4rem 0.55rem;
  color: var(--text);
  font-size: var(--fs-input);
  outline: none;
  width: 100%;
  box-sizing: border-box;
  transition: border-color 0.2s;
  font-family: inherit;
}
.input:focus {
  border-color: var(--accent);
}
.select {
  cursor: pointer;
  appearance: auto;
}
.textarea {
  resize: vertical;
  min-height: 2.4rem;
  line-height: 1.4;
}
.btn-generate {
  margin-top: 0.4rem;
  padding: 0.6rem;
  font-size: var(--fs-lg);
  font-weight: 700;
  border-radius: 7px;
  border: none;
  cursor: pointer;
  background: var(--accent);
  color: var(--on-accent);
  transition: opacity 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
}
.btn-generate:hover:not(:disabled) {
  opacity: 0.85;
}
.btn-generate:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(0, 0, 0, 0.15);
  border-top-color: var(--on-accent);
  border-radius: 50%;
  animation: seq-spin 0.6s linear infinite;
}

.generate-error {
  margin: 0.6rem 0 0;
  padding: 0.55rem 0.7rem;
  background: var(--danger-dim);
  border: 1px solid var(--danger);
  border-radius: var(--radius-sm);
  color: var(--danger);
  font-size: var(--fs-sm);
}
</style>
