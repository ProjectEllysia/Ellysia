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
      <Transition name="pop"><span v-if="props.launched" class="engine-launched">Motor en marcha</span></Transition>
    </div>

    <!-- Campos según modo -->
    <div class="engine-fields">
      <div class="field-row">
        <div class="field field-lg"><label>Target (IP única)</label>
          <input v-model="target" placeholder="192.168.1.1" @keyup.enter="handleLaunch" /></div>
        <div class="field"><label>Puertos (opcional)</label>
          <input v-model="ports" placeholder="80,443 o 1-1000" /></div>
      </div>
      <div v-if="target.trim()" class="auth-status" :class="{ ok: isTargetAuthorized(target) }">
        <template v-if="isTargetAuthorized(target)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          Objetivo autorizado
        </template>
        <template v-else>
          <span>Este objetivo no está en tu registro de objetivos autorizados — el autodescubrimiento se rechazará.</span>
          <button type="button" class="btn-authorize-inline" @click="$emit('add-authorized-target', { target: target.trim() })">
            Autorizar '{{ target.trim() }}'
          </button>
        </template>
      </div>

      <!-- Registro de objetivos autorizados -->
      <div class="auth-register">
        <button type="button" class="auth-register-toggle" @click="showAuthRegister = !showAuthRegister">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Objetivos autorizados ({{ authorizedTargets.length }})
          <span class="chevron" :class="{ rot: showAuthRegister }" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
          </span>
        </button>
        <div v-if="showAuthRegister" class="auth-register-body">
          <p class="auth-register-hint">
            Objetivos (IP o CIDR) que has declarado autorizados para el autodescubrimiento, el fingerprinting
            propio y las comprobaciones activas de Lybra (roadmap §6).
          </p>
          <div v-if="authTargetsLoading" class="auth-loading">Cargando…</div>
          <ul v-else-if="authorizedTargets.length" class="auth-chip-list">
            <li v-for="t in authorizedTargets" :key="t.id" class="auth-chip">
              <span class="mono">{{ t.target }}</span>
              <span v-if="t.label" class="auth-chip-label">{{ t.label }}</span>
              <button type="button" class="auth-chip-remove" title="Eliminar" @click="$emit('remove-authorized-target', t.id)">×</button>
            </li>
          </ul>
          <p v-else class="auth-empty">Aún no has autorizado ningún objetivo.</p>

          <div class="auth-add-row">
            <input v-model="newAuthTarget" placeholder="10.0.0.5 o 10.0.0.0/24" @keyup.enter="submitNewAuthTarget" />
            <input v-model="newAuthLabel" placeholder="Etiqueta (opcional)" @keyup.enter="submitNewAuthTarget" />
            <button type="button" class="btn-add-target" :disabled="!newAuthTarget.trim()" @click="submitNewAuthTarget">Añadir</button>
          </div>
        </div>
      </div>

      <div class="engine-row">
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
  // Q8: viene del padre (deriva del estado real de los escaneos), no de un
  // flag local que quedaba en true para siempre tras el primer lanzamiento.
  launched: { type: Boolean, default: false },
  authorizedTargets: { type: Array, default: () => [] },
  authTargetsLoading: { type: Boolean, default: false },
})
const emit = defineEmits(['launch', 'add-authorized-target', 'remove-authorized-target'])

// Un solo modo: Lybra descubre los puertos del objetivo con su propio
// transporte. Hubo un segundo modo —analizar los servicios de un escaneo Nmap
// ya hecho— retirado en L52 junto al interruptor de "segunda opinión" que
// lanzaba Nmap, Nikto y Nuclei como corroboradores.
const target = ref('')
const ports = ref('')
const timeout = ref(120)

const canLaunch = computed(() => !!target.value.trim())

/**
 * Heurística de coincidencia exacta contra el registro (el backend, que sí
 * entiende CIDR, es la fuente de verdad real). Las entradas de IP única se
 * normalizan a "x.x.x.x/32" en el servidor, así que se compara sin ese sufijo.
 */
function isTargetAuthorized(ip) {
  const needle = (ip || '').trim()
  if (!needle) return false
  return props.authorizedTargets.some(t => t.target.replace(/\/32$/, '') === needle)
}

const showAuthRegister = ref(false)
const newAuthTarget = ref('')
const newAuthLabel = ref('')
function submitNewAuthTarget() {
  if (!newAuthTarget.value.trim()) return
  emit('add-authorized-target', { target: newAuthTarget.value.trim(), label: newAuthLabel.value.trim() })
  newAuthTarget.value = ''
  newAuthLabel.value = ''
}

function handleLaunch() {
  if (!canLaunch.value || props.launching) return
  const payload = { target: target.value.trim(), timeout: timeout.value }
  if (ports.value.trim()) payload.ports = ports.value.trim()
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
.engine-title { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-weight: 600; font-size: var(--fs-lg); color: var(--text); }
.engine-sub { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-style: italic; font-size: var(--fs-lg); color: var(--text-muted); }
.engine-launched { font-size: var(--fs-md); color: var(--success); background: var(--success-dim); padding: 0.2rem 0.55rem; border-radius: 6px; }
.pop-enter-active { transition: opacity 0.2s ease, transform 0.25s cubic-bezier(0.34,1.56,0.64,1); }
.pop-enter-from { opacity: 0; transform: scale(0.8); }
.pop-leave-active { transition: opacity 0.15s ease; }
.pop-leave-to { opacity: 0; }

/* ── Campos ── */
.engine-fields { display: flex; flex-direction: column; gap: 0.8rem; }
.field-row { display: flex; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; min-width: 130px; }
.field label { font-size: var(--fs-md); color: var(--text-muted); font-weight: 500; }
.field input, .field select { padding: 0.5rem 0.65rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; }
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-lg { flex: 2; min-width: 200px; }
.field-sm { flex: 0 0 96px; min-width: 84px; }
.no-spin::-webkit-outer-spin-button, .no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }

/* ── Fila de lanzamiento ── */
.engine-row { display: flex; align-items: flex-end; gap: 0.9rem; flex-wrap: wrap; }
.engine-row .field-sm { margin-right: auto; }

.btn-launch { height: 36px; padding: 0 1.25rem; background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); font-weight: 600; font-size: var(--fs-lg); border-radius: 7px; cursor: pointer; display: flex; align-items: center; gap: 0.35rem; transition: all 0.2s; white-space: nowrap; position: relative; }
.btn-launch:hover:not(:disabled) { background: var(--accent-bright); border-color: var(--accent-bright); }
.btn-launch:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-launch.loading .btn-label { opacity: 0; }
.btn-launch.loading .btn-spin { display: block; }
.btn-spin { display: none; position: absolute; left: 50%; top: 50%; margin: -7px 0 0 -7px; width: 14px; height: 14px; border: 2px solid rgba(0,0,0,0.25); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }

/* ── Estado de autorización del objetivo (roadmap §6) ── */
.auth-status {
  display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
  padding: 0.5rem 0.7rem; margin-top: -0.15rem;
  font-size: var(--fs-md); color: var(--warn); background: var(--warn-dim);
  border: 1px dashed var(--warn); border-radius: 7px;
}
.auth-status.ok { color: var(--success); background: var(--success-dim); border-style: solid; border-color: var(--success); }
.auth-status svg { width: 14px; height: 14px; flex-shrink: 0; }
.btn-authorize-inline {
  padding: 0.25rem 0.6rem; background: var(--accent); border: 1px solid var(--accent);
  color: var(--on-accent); font-size: var(--fs-md); font-weight: 600; border-radius: 6px; cursor: pointer;
  white-space: nowrap; transition: all 0.2s;
}
.btn-authorize-inline:hover { background: var(--accent-bright); border-color: var(--accent-bright); }

/* ── Registro de objetivos autorizados ── */
.auth-register { border-top: 1px solid var(--border-solid); padding-top: 0.7rem; margin-top: 0.2rem; }
.auth-register-toggle {
  display: flex; align-items: center; gap: 0.45rem; width: 100%;
  background: none; border: none; color: var(--text-dim); font-size: var(--fs-lg); font-weight: 500;
  cursor: pointer; padding: 0.15rem 0;
}
.auth-register-toggle svg:first-child { width: 15px; height: 15px; color: var(--text-muted); }
.auth-register-toggle .chevron { margin-left: auto; display: grid; place-items: center; color: var(--text-muted); transition: transform 0.2s; }
.auth-register-toggle .chevron svg { width: 13px; height: 13px; }
.auth-register-toggle .chevron.rot { transform: rotate(90deg); }
.auth-register-body { padding-top: 0.6rem; display: flex; flex-direction: column; gap: 0.55rem; }
.auth-register-hint { margin: 0; font-size: var(--fs-md); color: var(--text-muted); line-height: 1.4; }
.auth-loading, .auth-empty { font-size: var(--fs-md); color: var(--text-muted); }

.auth-chip-list { list-style: none; display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0; padding: 0; }
.auth-chip {
  display: flex; align-items: center; gap: 0.4rem;
  padding: 0.25rem 0.3rem 0.25rem 0.6rem; background: var(--surface-2); border: 1px solid var(--border-solid);
  border-radius: 999px; font-size: var(--fs-md); color: var(--text);
}
.auth-chip-label { color: var(--text-muted); font-style: italic; }
.auth-chip-remove {
  width: 18px; height: 18px; display: grid; place-items: center; border-radius: 50%;
  background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: var(--fs-xl); line-height: 1;
  transition: all 0.2s;
}
.auth-chip-remove:hover { background: var(--danger-dim); color: var(--danger); }

.auth-add-row { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.auth-add-row input {
  flex: 1; min-width: 130px; padding: 0.4rem 0.6rem; background: var(--surface-2);
  border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: var(--fs-lg); outline: none;
}
.auth-add-row input:focus { border-color: var(--accent); }
.btn-add-target {
  padding: 0.4rem 0.8rem; background: var(--surface-2); border: 1px solid var(--accent); color: var(--accent-bright);
  font-size: var(--fs-md); font-weight: 600; border-radius: 6px; cursor: pointer; transition: all 0.2s; white-space: nowrap;
}
.btn-add-target:hover:not(:disabled) { background: var(--accent-dim); }
.btn-add-target:disabled { opacity: 0.4; cursor: not-allowed; }

@media (prefers-reduced-motion: reduce) {
  .pop-enter-active, .pop-leave-active, .btn-launch,
  .auth-register-toggle .chevron, .btn-authorize-inline, .btn-add-target, .auth-chip-remove { transition: none !important; }
}
</style>
