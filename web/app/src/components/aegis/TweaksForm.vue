<template>
  <div class="tweaks-form">
    <h2>Nueva Píldora</h2>

    <div class="form-group">
      <label for="tw-company">Empresa</label>
      <input id="tw-company" v-model="store.tweaks.company" type="text" maxlength="60" class="input" placeholder="Nombre de la empresa" />
    </div>

    <div class="form-row">
      <div class="form-group">
        <label for="tw-lang">Idioma</label>
        <select id="tw-lang" v-model="store.tweaks.language" class="input select">
          <option value="es">Español</option><option value="en">English</option><option value="fr">Français</option><option value="de">Deutsch</option>
        </select>
      </div>
      <div class="form-group">
        <label for="tw-tone">Tono</label>
        <select id="tw-tone" v-model="store.tweaks.tone" class="input select">
          <option value="profesional">Profesional</option><option value="formal">Formal</option><option value="cercano">Cercano</option><option value="tecnico">Técnico</option>
        </select>
      </div>
    </div>

    <div class="form-row">
      <div class="form-group">
        <label for="tw-audience">Audiencia</label>
        <select id="tw-audience" v-model="store.tweaks.audienceLevel" class="input select">
          <option value="mixed">Mixta</option><option value="technical">Técnica</option><option value="non-technical">No técnica</option>
        </select>
      </div>
      <div class="form-group">
        <label for="tw-sector">Sector</label>
        <input id="tw-sector" v-model="store.tweaks.sector" type="text" maxlength="40" class="input" placeholder="Ej: banca" />
      </div>
    </div>

    <div class="form-group">
      <label for="tw-contact">Email de contacto</label>
      <input id="tw-contact" v-model="store.tweaks.mentionContact" type="email" maxlength="100" class="input" placeholder="contacto@empresa.com" />
    </div>

    <div class="form-group">
      <label>Marcas asociadas</label>
      <div class="selected-brands" v-if="store.selectedBrands.length">
        <span v-for="b in store.selectedBrands" :key="b" class="brand-tag">
          {{ b }}
          <button type="button" class="brand-remove" @click="removeBrand(b)">&times;</button>
        </span>
      </div>
      <select class="input select" :value="''" @change="addBrand($event.target.value); $event.target.value = ''">
        <option value="">+ Añadir marca</option>
        <option v-for="b in availableBrands" :key="b" :value="b">{{ b }}</option>
      </select>
    </div>

    <div class="form-group">
      <label for="tw-focus">Foco del tema</label>
      <input id="tw-focus" v-model="store.tweaks.topicFocus" type="text" maxlength="120" class="input" placeholder="Ej: phishing por QR" />
    </div>

    <div class="form-divider">Contexto adicional</div>

    <div class="form-row">
      <div class="form-group">
        <label for="tw-size">Tamaño de empresa</label>
        <select id="tw-size" v-model="store.tweaks.companySize" class="input select">
          <option value="">Sin especificar</option>
          <option value="micro">Micro (&lt;10)</option>
          <option value="pequeña">Pequeña (10-50)</option>
          <option value="mediana">Mediana (50-250)</option>
        </select>
      </div>
      <div class="form-group">
        <label for="tw-employees">Nº empleados</label>
        <input id="tw-employees" v-model.number="store.tweaks.employeeCount" type="number" min="1" class="input" placeholder="Opcional" />
      </div>
    </div>

    <div class="form-row">
      <div class="form-group">
        <label for="tw-jurisdiction">Jurisdicción</label>
        <input id="tw-jurisdiction" v-model="store.tweaks.jurisdiction" type="text" maxlength="256" class="input" placeholder="Ej: España (RGPD)" />
      </div>
      <div class="form-group">
        <label for="tw-workmodel">Modelo de trabajo</label>
        <select id="tw-workmodel" v-model="store.tweaks.workModel" class="input select">
          <option value="">Sin especificar</option>
          <option value="remoto">Remoto</option>
          <option value="híbrido">Híbrido</option>
          <option value="presencial">Presencial</option>
        </select>
      </div>
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

    <TopicGrid :topics="store.topics" :selected-topic-id="store.selectedTopicId" @select="store.selectedTopicId = $event" />

    <button type="button" class="btn-generate" :disabled="!store.selectedTopicId || store.generating" @click="store.generate()">
      <span v-if="store.generating" class="spinner"></span>
      {{ store.generating ? 'Generando…' : 'Generar Píldora' }}
    </button>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useAegisStore } from '@/stores/aegisStore'
import TopicGrid from './TopicGrid.vue'

const store = useAegisStore()
const availableBrands = computed(() => (store.brands || []).filter(b => !store.selectedBrands.includes(b)))
function addBrand(brand) { if (brand) store.selectedBrands.push(brand) }
function removeBrand(brand) { store.selectedBrands = store.selectedBrands.filter(b => b !== brand) }
</script>

<style scoped>
.tweaks-form { display: flex; flex-direction: column; gap: 0.65rem; padding: 1.1rem; }
.tweaks-form h2 { font-size: 1rem; font-weight: 700; color: var(--text); margin: 0 0 0.2rem; flex-shrink: 0; font-family: var(--font-display); }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: 0.72rem; font-weight: 600; color: var(--text-dim); }
.input { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.4rem 0.55rem; color: var(--text); font-size: 0.8rem; outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s; font-family: inherit; }
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; appearance: auto; }
.input[type=number]::-webkit-inner-spin-button,
.input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
.input[type=number] { -moz-appearance: textfield; }
.textarea { resize: vertical; min-height: 2.4rem; line-height: 1.4; }
.form-divider { margin: 0.3rem 0 -0.15rem; padding-top: 0.6rem; border-top: 1px solid var(--border); font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
.selected-brands { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.3rem; }
.brand-tag { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.15rem 0.4rem; font-size: 0.7rem; font-weight: 600; background: var(--accent); color: var(--on-accent); border-radius: 4px; }
.brand-remove { background: none; border: none; color: inherit; cursor: pointer; font-size: 0.9rem; padding: 0; line-height: 1; opacity: 0.7; }
.brand-remove:hover { opacity: 1; }
.btn-generate { margin-top: 0.4rem; padding: 0.6rem; font-size: 0.85rem; font-weight: 700; border-radius: 7px; border: none; cursor: pointer; background: var(--accent); color: var(--on-accent); transition: opacity 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; }
.btn-generate:hover:not(:disabled) { opacity: 0.85; }
.btn-generate:disabled { opacity: 0.4; cursor: not-allowed; }
.spinner { width: 14px; height: 14px; border: 2px solid rgba(0,0,0,0.15); border-top-color: var(--on-accent); border-radius: 50%; animation: seq-spin .6s linear infinite; }
</style>
