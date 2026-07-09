<template>
  <div class="engine-card">
    <!-- Cabecera con identidad de motor -->
    <div class="engine-head">
      <div class="engine-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
          <path d="M12 3v18M7 21h10M5 7h14M5 7l-2.5 5a3 3 0 0 0 5 0L5 7zM19 7l-2.5 5a3 3 0 0 0 5 0L19 7z"/>
        </svg>
      </div>
      <div class="engine-title-wrap">
        <span class="engine-title">Motor Lybra</span>
        <span class="engine-sub">Pesa cada amenaza antes de que golpee</span>
      </div>
      <Transition name="pop"><span v-if="launched" class="engine-launched">Motor en marcha</span></Transition>
    </div>

    <!-- Selector de modo -->
    <div class="mode-picker" role="radiogroup" aria-label="Modo de escaneo">
      <button type="button" class="mode-opt" :class="{ active: mode === 'discover' }"
        role="radio" :aria-checked="mode === 'discover'" @click="mode = 'discover'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg>
        <span class="mode-label">Que Lybra descubra</span>
        <span class="mode-hint">Transporte propio: descubre los puertos por su cuenta</span>
      </button>
      <button type="button" class="mode-opt" :class="{ active: mode === 'source' }"
        role="radio" :aria-checked="mode === 'source'" @click="onPickSourceMode">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M4 7h16M4 12h16M4 17h10"/></svg>
        <span class="mode-label">Analizar un Nmap</span>
        <span class="mode-hint">Reutiliza los servicios de un escaneo Nmap ya hecho</span>
      </button>
    </div>

    <!-- Campos según modo -->
    <div class="engine-fields">
      <div v-if="mode === 'discover'" class="field-row">
        <div class="field field-lg"><label>Target (IP única)</label>
          <input v-model="target" placeholder="192.168.1.1" @keyup.enter="handleLaunch" /></div>
        <div class="field"><label>Puertos (opcional)</label>
          <input v-model="ports" placeholder="80,443 o 1-1000" /></div>
      </div>

      <div v-else class="field-row">
        <div class="field field-lg">
          <label>Escaneo Nmap de origen</label>
          <select v-model="sourceScanId">
            <option value="" disabled>{{ sourceLoading ? 'Cargando…' : (sourceScans.length ? '-- Elige un Nmap terminado --' : 'No hay escaneos Nmap terminados') }}</option>
            <option v-for="s in sourceScans" :key="s.id" :value="s.id">
              #{{ s.id }} · {{ s.target }} · {{ s.totalOpenPorts ?? 0 }} puertos
            </option>
          </select>
        </div>
      </div>

      <!-- Segunda opinión + profundidad -->
      <div class="engine-row">
        <label class="deep-toggle" :title="'Lanza Nmap, Nikto y OpenVAS en paralelo y funde sus hallazgos con los de Lybra'">
          <input type="checkbox" v-model="deep" />
          <span class="deep-track"><span class="deep-thumb"></span></span>
          <span class="deep-copy">
            <span class="deep-label">Pedir una segunda opinión</span>
            <span class="deep-sub">Corrobora con Nmap · Nikto · OpenVAS</span>
          </span>
        </label>

        <div class="field field-sm"><label>Timeout (s)</label>
          <input v-model.number="timeout" type="number" min="1" max="86400" class="no-spin" /></div>

        <button class="btn-launch" :class="launching ? 'loading' : ''" :disabled="launching || !canLaunch" @click="handleLaunch">
          <span class="btn-label">Emitir veredicto</span>
          <span class="btn-spin"></span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  launching: { type: Boolean, default: false },
  sourceScans: { type: Array, default: () => [] },
  sourceLoading: { type: Boolean, default: false },
})
const emit = defineEmits(['launch', 'load-sources'])

const mode = ref('discover')       // 'discover' | 'source'
const target = ref('')
const ports = ref('')
const sourceScanId = ref('')
const deep = ref(false)
const timeout = ref(120)
const launched = ref(false)

const canLaunch = computed(() =>
  mode.value === 'discover' ? !!target.value.trim() : !!sourceScanId.value
)

function onPickSourceMode() {
  mode.value = 'source'
  emit('load-sources')
}

function handleLaunch() {
  if (!canLaunch.value || props.launching) return
  const payload = { deep: deep.value, timeout: timeout.value }
  if (mode.value === 'discover') {
    payload.target = target.value.trim()
    if (ports.value.trim()) payload.ports = ports.value.trim()
  } else {
    payload.sourceScanId = Number(sourceScanId.value)
  }
  launched.value = true
  emit('launch', payload)
}
</script>

<style scoped>
.engine-card {
  background: linear-gradient(180deg, var(--surface) 0%, var(--surface-2) 220%);
  border: 1px solid var(--accent);
  border-radius: 12px;
  padding: 1.2rem 1.35rem;
  margin-bottom: 1.1rem;
  box-shadow: 0 0 0 1px var(--accent-dim), 0 12px 34px rgba(0,0,0,0.16);
}

/* ── Cabecera ── */
.engine-head { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 1rem; }
.engine-mark {
  width: 40px; height: 40px; border-radius: 50%;
  display: grid; place-items: center; flex-shrink: 0;
  color: var(--accent-bright);
  background: var(--accent-dim);
  border: 1px solid var(--accent);
}
.engine-mark svg { width: 21px; height: 21px; }
.engine-title-wrap { display: flex; flex-direction: column; gap: 0.05rem; margin-right: auto; }
.engine-title { font-family: var(--font-display); font-weight: 600; font-size: 1.02rem; color: var(--text); }
.engine-sub { font-family: var(--font-display); font-style: italic; font-size: 0.82rem; color: var(--text-muted); }
.engine-launched { font-size: 0.72rem; color: var(--success); background: var(--success-dim); padding: 0.2rem 0.55rem; border-radius: 6px; }
.pop-enter-active { transition: opacity 0.2s ease, transform 0.25s cubic-bezier(0.34,1.56,0.64,1); }
.pop-enter-from { opacity: 0; transform: scale(0.8); }
.pop-leave-active { transition: opacity 0.15s ease; }
.pop-leave-to { opacity: 0; }

/* ── Selector de modo ── */
.mode-picker { display: grid; grid-template-columns: 1fr 1fr; gap: 0.55rem; margin-bottom: 0.9rem; }
.mode-opt {
  display: flex; flex-direction: column; align-items: flex-start; gap: 0.2rem;
  padding: 0.75rem 0.85rem; text-align: left;
  background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 9px;
  cursor: pointer; transition: all 0.2s ease; position: relative;
}
.mode-opt svg { width: 18px; height: 18px; color: var(--text-muted); transition: color 0.2s; }
.mode-opt:hover { border-color: var(--accent); }
.mode-opt.active { border-color: var(--accent); background: var(--accent-dim); box-shadow: inset 0 0 0 1px var(--accent); }
.mode-opt.active svg { color: var(--accent-bright); }
.mode-label { font-size: 0.86rem; font-weight: 600; color: var(--text); }
.mode-hint { font-size: 0.72rem; color: var(--text-muted); line-height: 1.25; }

/* ── Campos ── */
.engine-fields { display: flex; flex-direction: column; gap: 0.8rem; }
.field-row { display: flex; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; min-width: 130px; }
.field label { font-size: 0.72rem; color: var(--text-muted); font-weight: 500; }
.field input, .field select { padding: 0.5rem 0.65rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: 0.82rem; outline: none; transition: border-color 0.2s; }
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-lg { flex: 2; min-width: 200px; }
.field-sm { flex: 0 0 96px; min-width: 84px; }
.no-spin::-webkit-outer-spin-button, .no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }

/* ── Fila de segunda opinión ── */
.engine-row { display: flex; align-items: flex-end; gap: 0.9rem; flex-wrap: wrap; }
.deep-toggle { display: flex; align-items: center; gap: 0.6rem; cursor: pointer; margin-right: auto; user-select: none; }
.deep-toggle input { position: absolute; opacity: 0; width: 0; height: 0; }
.deep-track {
  position: relative; width: 40px; height: 22px; flex-shrink: 0;
  background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 999px;
  transition: background 0.2s, border-color 0.2s;
}
.deep-thumb {
  position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
  background: var(--text-muted); transition: transform 0.2s, background 0.2s;
}
.deep-toggle input:checked + .deep-track { background: var(--accent-dim); border-color: var(--accent); }
.deep-toggle input:checked + .deep-track .deep-thumb { transform: translateX(18px); background: var(--accent-bright); }
.deep-toggle input:focus-visible + .deep-track { box-shadow: 0 0 0 3px var(--accent-dim); }
.deep-copy { display: flex; flex-direction: column; gap: 0.05rem; }
.deep-label { font-size: 0.82rem; font-weight: 600; color: var(--text); }
.deep-sub { font-size: 0.72rem; color: var(--text-muted); }

.btn-launch { height: 36px; padding: 0 1.25rem; background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); font-weight: 600; font-size: 0.82rem; border-radius: 7px; cursor: pointer; display: flex; align-items: center; gap: 0.35rem; transition: all 0.2s; white-space: nowrap; position: relative; }
.btn-launch:hover:not(:disabled) { background: var(--accent-bright); border-color: var(--accent-bright); }
.btn-launch:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-launch.loading .btn-label { opacity: 0; }
.btn-launch.loading .btn-spin { display: block; }
.btn-spin { display: none; position: absolute; left: 50%; top: 50%; margin: -7px 0 0 -7px; width: 14px; height: 14px; border: 2px solid rgba(0,0,0,0.25); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }

@media (max-width: 600px) {
  .mode-picker { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  .pop-enter-active, .pop-leave-active, .deep-thumb, .deep-track, .btn-launch { transition: none !important; }
}
</style>
