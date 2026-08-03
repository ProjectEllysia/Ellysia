<template>
  <div class="launch-card">
    <div class="launch-header">
      <span class="launch-title">Nuevo escaneo {{ type.toUpperCase() }}</span>
      <Transition name="pop"><span v-if="launched" class="launch-success">Escaneo iniciado</span></Transition>
    </div>
    <div class="launch-fields">
      <div class="field-row">
        <template v-if="type === 'nmap'">
          <div class="field"><label>Target (IP / CIDR)</label>
            <input v-model="form.target" placeholder="192.168.1.0/24" /></div>
          <div class="field field-sm"><label>Timeout (s)</label>
            <input v-model.number="form.timeout" type="number" min="30" max="86400" class="no-spin" /></div>
        </template>
        <template v-if="type === 'nikto'">
          <div class="field field-lg"><label>Target URL</label>
            <input v-model="form.target" placeholder="http://example.com" /></div>
          <div class="field field-sm"><label>Timeout (s)</label>
            <input v-model.number="form.timeout" type="number" min="10" max="86400" class="no-spin" /></div>
        </template>
        <template v-if="type === 'nuclei'">
          <div class="field field-lg"><label>Target URL</label>
            <input v-model="form.target" placeholder="https://example.com" /></div>
        </template>
        <button class="btn-launch" :class="launching ? 'loading' : ''" :disabled="launching" @click="handleLaunch">
          <span class="btn-label">Lanzar</span>
          <span class="btn-spin"></span>
        </button>
      </div>
      <div v-if="type === 'nmap'" class="ports-row">
        <div class="field field-lg">
          <label>Estrategia de puertos</label>
          <div class="strategy-picker" role="radiogroup" aria-label="Estrategia de puertos">
            <button v-for="opt in PORT_STRATEGIES" :key="opt.id" type="button"
              class="strategy-chip" :class="[opt.id, { active: portMode === opt.id }]"
              role="radio" :aria-checked="portMode === opt.id" :title="opt.hint"
              @click="selectPortMode(opt.id)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path :d="opt.icon"/></svg>
              <span class="strategy-label">{{ opt.label }}</span>
            </button>
          </div>
        </div>
        <div class="field" :class="{ hidden: portMode !== 'custom' }"><label>Rango de puertos</label>
          <input v-model="form.ports" placeholder="80,443 o 1-1000" /></div>
      </div>
      <div v-if="type === 'nuclei'" class="nuclei-row">
        <div class="field field-lg">
          <!-- "info" queda fuera por defecto (roadmap Fase U1, punto 1): son
               miles de plantillas de tech-detect que, al ser confirmed=true
               sin CVSS, el suelo de score_finding subiría todas a MEDIO. -->
          <label>Severidades</label>
          <div class="strategy-picker" role="group" aria-label="Severidades de Nuclei">
            <button v-for="sev in NUCLEI_SEVERITIES" :key="sev.id" type="button"
              class="strategy-chip" :class="[sev.id, { active: form.severities.includes(sev.id) }]"
              :aria-pressed="form.severities.includes(sev.id)" :title="sev.hint"
              @click="toggleSeverity(sev.id)">
              <span class="strategy-label">{{ sev.label }}</span>
            </button>
          </div>
        </div>
        <div class="field field-md"><label>Tags (opcional)</label>
          <input v-model="form.tags" placeholder="cve,exposure" /></div>
        <div class="field field-sm"><label>Rate limit</label>
          <input v-model.number="form.rateLimit" type="number" min="1" max="1000" class="no-spin" /></div>
        <div class="field field-sm"><label>Timeout petición (s)</label>
          <input v-model.number="form.requestTimeout" type="number" min="1" max="120" class="no-spin" /></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  type: { type: String, required: true },
  launching: { type: Boolean, default: false },
  // Q8: viene del padre (deriva del estado real de los escaneos), no de un
  // flag local que solo se limpiaba al cambiar de pestaña.
  launched: { type: Boolean, default: false },
})
const emit = defineEmits(['launch'])

const DEFAULTS = {
  nmap:    { target: '', ports: '1-1000', timeout: 900,  config: 'full_fast' },
  nikto:   { target: '', ports: '',        timeout: 6000, config: 'full_fast' },
  nuclei:  { target: '', severities: ['critical', 'high', 'medium'], tags: '', rateLimit: 150, requestTimeout: 10 },
}
const form = ref({ ...DEFAULTS.nmap })

const NUCLEI_SEVERITIES = [
  { id: 'critical', label: 'Crítica', hint: 'Severidad crítica' },
  { id: 'high', label: 'Alta', hint: 'Severidad alta' },
  { id: 'medium', label: 'Media', hint: 'Severidad media' },
  { id: 'low', label: 'Baja', hint: 'Severidad baja' },
  { id: 'info', label: 'Info', hint: 'Plantillas de tech-detect — miles de peticiones, sin CVSS propio' },
]
function toggleSeverity(id) {
  form.value.severities = form.value.severities.includes(id)
    ? form.value.severities.filter(s => s !== id)
    : [...form.value.severities, id]
}

// Rangos IANA: bien conocidos (0–1023), registrados (1024–49151), privados/dinámicos (49152–65535), y completo (0–65535).
const PORT_PRESETS = { wellknown: '1-1023', registered: '1024-49151', private: '49152-65535', complete: '1-65535' }
const PORT_STRATEGIES = [
  { id: 'wellknown', label: 'Conocidos', hint: 'Puertos 1-1023 · servicios estándar del sistema', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
  { id: 'registered', label: 'Registrados', hint: 'Puertos 1024-49151 · aplicaciones registradas', icon: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01' },
  { id: 'private', label: 'Privados', hint: 'Puertos 49152-65535 · uso dinámico/privado', icon: 'M22 12h-4l-3 9L9 3l-3 9H2' },
  { id: 'complete', label: 'Completo', hint: 'Rango 0-65535 · escaneo exhaustivo', icon: 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20M12 2a15.3 15.3 0 010 20 15.3 15.3 0 010-20z' },
  { id: 'custom', label: 'Personalizado', hint: 'Define tu propio rango de puertos', icon: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6' },
]
const portMode = ref('custom')
function selectPortMode(id) {
  portMode.value = id
  if (id !== 'custom') form.value.ports = PORT_PRESETS[id]
}

function resetForm(type) { form.value = { ...DEFAULTS[type] }; portMode.value = 'custom' }
watch(() => props.type, resetForm, { immediate: true })

function handleLaunch() {
  if (!form.value.target.trim()) return
  const payload = { target: form.value.target.trim() }
  if (props.type === 'nmap') { payload.ports = form.value.ports; payload.timeout = form.value.timeout }
  if (props.type === 'nikto') { payload.timeout = form.value.timeout }
  if (props.type === 'nuclei') {
    if (form.value.severities.length) payload.severities = form.value.severities
    const tags = (form.value.tags || '').split(',').map(t => t.trim()).filter(Boolean)
    if (tags.length) payload.tags = tags
    if (form.value.rateLimit) payload.rateLimit = form.value.rateLimit
    if (form.value.requestTimeout) payload.requestTimeout = form.value.requestTimeout
  }
  emit('launch', payload)
}
</script>

<style scoped>
.launch-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.25rem; margin-bottom: 1.1rem; }
.launch-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.85rem; }
.launch-title { font-weight: 600; color: var(--text); font-size: var(--fs-xl); font-family: var(--font-display); }
.launch-success { font-size: var(--fs-md); color: var(--success); background: var(--success-dim); padding: 0.15rem 0.5rem; border-radius: 6px; }
.pop-enter-active { transition: opacity 0.2s ease, transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1); }
.pop-enter-from { opacity: 0; transform: scale(0.8); }
.pop-leave-active { transition: opacity 0.15s ease; }
.pop-leave-to { opacity: 0; }
@media (prefers-reduced-motion: reduce) {
  .pop-enter-active, .pop-leave-active { transition: none !important; }
}
.launch-fields { display: flex; flex-direction: column; gap: 0.6rem; }
.field-row { display: flex; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.ports-row { display: grid; grid-template-columns: 1fr; gap: 0.6rem; }
.nuclei-row { display: flex; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; min-width: 130px; }
.ports-row .field:nth-child(2) { max-height: 70px; overflow: hidden; transition: max-height 0.2s ease, opacity 0.2s ease; opacity: 1; }
.ports-row .field.hidden { max-height: 0; opacity: 0; pointer-events: none; }
.field label { font-size: var(--fs-md); color: var(--text-muted); font-weight: 500; }
.field input, .field select { padding: 0.5rem 0.65rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; }
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-sm { flex: 0 0 100px; min-width: 90px; }
.field-md { flex: 0 0 160px; }
.field-lg { flex: 2; min-width: 190px; }

.strategy-picker { display: flex; gap: 0.3rem; flex-wrap: wrap; }
.strategy-chip { display: flex; align-items: center; gap: 0.32rem; padding: 0.5rem 0.6rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text-muted); font-size: var(--fs-md); font-weight: 500; cursor: pointer; transition: all 0.2s ease; white-space: nowrap; }
.strategy-chip:hover { color: var(--text-dim); border-color: var(--accent); }
.strategy-chip svg { width: 13px; height: 13px; flex-shrink: 0; }
.strategy-chip.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); font-weight: 600; }
@media (max-width: 640px) { .strategy-label { display: none; } .strategy-chip { padding: 0.5rem; } }
.no-spin::-webkit-outer-spin-button, .no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }
.btn-launch { height: 34px; padding: 0 1.15rem; margin-bottom: 0; background: var(--accent-dim); border: 1px solid var(--accent); color: var(--accent-bright); font-weight: 600; font-size: var(--fs-lg); border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.35rem; transition: all 0.2s; white-space: nowrap; position: relative; }
.btn-launch:hover:not(:disabled) { background: var(--accent); color: var(--on-accent); }
.btn-launch:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-launch.loading .btn-label { opacity: 0; }
.btn-launch.loading .btn-spin { display: block; }
.btn-spin { display: none; position: absolute; width: 13px; height: 13px; border: 2px solid rgba(0,0,0,0.2); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }
</style>
