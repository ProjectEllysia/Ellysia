<template>
  <div class="admin-page">
    <StarBackground />
    <Topbar title="Simulador de reglas de Iris" backTo="/" />

    <main class="main">
      <p class="intro">
        Compara la política de puntuación vigente con una candidata sobre el corpus
        versionado de Iris antes de desplegarla: qué veredictos cambian, qué gates
        aparecen o desaparecen y cuántos falsos positivos y negativos tiene cada una.
        Nada de lo que se evalúa aquí se guarda.
      </p>

      <section class="section">
        <h2>Política candidata</h2>
        <p class="hint">Lo que dejes vacío se queda como en la política vigente.</p>

        <div class="form-grid">
          <label class="field">
            <span>Perfil de sensibilidad</span>
            <select v-model="candidate.profile" class="inp">
              <option value="">(el vigente)</option>
              <option value="strict">Estricto</option>
              <option value="balanced">Equilibrado</option>
              <option value="lenient">Permisivo</option>
            </select>
          </label>
          <label class="field">
            <span>Umbral legítimo</span>
            <input v-model="candidate.legitimateThreshold" type="number" min="0" max="100" class="inp" placeholder="(vigente)" />
          </label>
          <label class="field">
            <span>Umbral sospechoso</span>
            <input v-model="candidate.suspiciousThreshold" type="number" min="0" max="100" class="inp" placeholder="(vigente)" />
          </label>
        </div>

        <label class="field">
          <span>Pesos a sobreescribir (JSON, se suman a los vigentes)</span>
          <textarea v-model="weightOverridesText" class="inp mono" rows="3" placeholder='{"dmarc.fail": -20}'></textarea>
        </label>

        <label class="field">
          <span>Mensaje suelto (opcional: cabeceras o un .eml completo)</span>
          <textarea v-model="adHocRaw" class="inp mono" rows="5"></textarea>
        </label>
        <div class="form-row">
          <label v-if="adHocRaw.trim()" class="field field--inline">
            <span>Etiqueta del mensaje</span>
            <select v-model="adHocLabel" class="inp">
              <option value="">sin etiqueta</option>
              <option value="malicious">malicioso</option>
              <option value="legitimate">legítimo</option>
            </select>
          </label>
          <label class="field field--inline">
            <input v-model="includeCorpus" type="checkbox" />
            <span>Incluir el corpus versionado</span>
          </label>
        </div>

        <p v-if="formError" class="state state--error">{{ formError }}</p>
        <button type="button" class="btn btn--primary" :disabled="running" @click="run">
          {{ running ? 'Comparando…' : 'Comparar' }}
        </button>
      </section>

      <section v-if="report" class="section">
        <h2>Resultado</h2>
        <p class="hint">
          Corpus <span class="mono">{{ report.corpusVersion || '(no incluido)' }}</span> ·
          catálogo <span class="mono">{{ report.detectorVersion }}</span> ·
          {{ report.changedCount }} de {{ report.samples.length }} muestras cambian de veredicto.
        </p>

        <table class="table">
          <thead>
            <tr><th>Política</th><th>Versión</th><th>Falsos positivos</th><th>Falsos negativos</th><th>Precisión</th><th>Recall</th></tr>
          </thead>
          <tbody>
            <tr v-for="(policy, name) in report.policies" :key="name">
              <td>{{ POLICY_LABELS[name] || name }}</td>
              <td class="mono">{{ policy.scoringVersion }}</td>
              <td>
                <span class="mono">{{ policy.metrics.overall.falsePositives }}</span>
                <span v-if="policy.falsePositiveSamples.length" class="muted"> — {{ policy.falsePositiveSamples.join(', ') }}</span>
              </td>
              <td>
                <span class="mono">{{ policy.metrics.overall.falseNegatives }}</span>
                <span v-if="policy.falseNegativeSamples.length" class="muted"> — {{ policy.falseNegativeSamples.join(', ') }}</span>
              </td>
              <td class="mono">{{ percent(policy.metrics.overall.precision) }}</td>
              <td class="mono">{{ percent(policy.metrics.overall.recall) }}</td>
            </tr>
          </tbody>
        </table>

        <table class="table">
          <thead>
            <tr><th>Muestra</th><th>Etiqueta</th><th>Vigente</th><th>Candidata</th><th>Gates que cambian</th></tr>
          </thead>
          <tbody>
            <tr v-for="sample in report.samples" :key="sample.id" :class="{ 'row--changed': sample.verdictChanged }">
              <td class="mono">{{ sample.id }}</td>
              <td>{{ LABELS[sample.label] || '—' }}</td>
              <td>{{ sample.results.baseline.verdict }} <span class="muted">({{ sample.results.baseline.totalScore }})</span></td>
              <td>{{ sample.results.candidate.verdict }} <span class="muted">({{ sample.results.candidate.totalScore }})</span></td>
              <td class="gates">
                <span v-for="gate in sample.gateChanges.candidate.added" :key="`a-${gate}`" class="gate gate--added">+ {{ gate }}</span>
                <span v-for="gate in sample.gateChanges.candidate.removed" :key="`r-${gate}`" class="gate gate--removed">− {{ gate }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
  </div>
</template>

<script setup>
/**
 * Simulador de reglas de Iris (solo administradores): llama a
 * POST /iris/admin/replay con la política candidata y pinta el informe. La
 * política de referencia es siempre la vigente; el servidor no guarda nada.
 */
import { ref, reactive } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useIrisStore } from '@/stores/irisStore'

const irisStore = useIrisStore()

const POLICY_LABELS = { baseline: 'Vigente', candidate: 'Candidata' }
const LABELS = { malicious: 'malicioso', legitimate: 'legítimo', unknown: 'indeterminado' }

const candidate = reactive({ profile: '', legitimateThreshold: '', suspiciousThreshold: '' })
const weightOverridesText = ref('')
const adHocRaw = ref('')
const adHocLabel = ref('')
const includeCorpus = ref(true)
const running = ref(false)
const formError = ref('')
const report = ref(null)

/** Proporción 0–1 como porcentaje entero, o una raya si no hay datos. */
function percent(value) {
  return value === null || value === undefined ? '—' : `${Math.round(value * 100)} %`
}

/** Construye el cuerpo de la petición; lanza si los pesos no son un JSON válido. */
function buildPayload() {
  const spec = {}
  if (candidate.profile) spec.profile = candidate.profile
  if (candidate.legitimateThreshold !== '') spec.legitimateThreshold = Number(candidate.legitimateThreshold)
  if (candidate.suspiciousThreshold !== '') spec.suspiciousThreshold = Number(candidate.suspiciousThreshold)
  if (weightOverridesText.value.trim()) spec.weightOverrides = JSON.parse(weightOverridesText.value)

  const payload = { candidate: spec, includeCorpus: includeCorpus.value }
  if (adHocRaw.value.trim()) {
    payload.messages = [{ raw: adHocRaw.value, label: adHocLabel.value || null }]
  }
  return payload
}

async function run() {
  formError.value = ''
  let payload
  try {
    payload = buildPayload()
  } catch {
    formError.value = 'Los pesos no son un JSON válido.'
    return
  }
  running.value = true
  report.value = await irisStore.runReplay(payload)
  running.value = false
}
</script>

<style scoped>
.admin-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1080px; margin: 0 auto; padding: 2rem 1.5rem 4rem; display: flex; flex-direction: column; gap: 1.5rem; position: relative; z-index: 1; }
.intro { color: var(--text-muted); font-size: var(--fs-md); max-width: 70ch; margin: 0; }
.section {
  display: flex; flex-direction: column; gap: 0.9rem;
  padding: 1.25rem 1.5rem; border: 1px solid var(--border); border-radius: 12px; background: var(--surface);
}
.section h2 { margin: 0; font-size: var(--fs-lg); }
.hint { margin: 0; color: var(--text-muted); font-size: var(--fs-sm); }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.8rem; }
.form-row { display: flex; flex-wrap: wrap; gap: 1.2rem; align-items: center; }
.field { display: flex; flex-direction: column; gap: 0.3rem; font-size: var(--fs-sm); color: var(--text-muted); }
.field--inline { flex-direction: row; align-items: center; gap: 0.5rem; }
.inp {
  padding: 0.45rem 0.6rem; border: 1px solid var(--border-med); border-radius: 6px;
  background: var(--surface-2); color: var(--text); font: inherit; font-size: var(--fs-md);
}
textarea.inp { resize: vertical; }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.muted { color: var(--text-muted); }
.state { margin: 0; padding: 0.6rem 0.8rem; border: 1px solid var(--border); border-radius: 8px; font-size: var(--fs-md); }
.state--error { border-color: var(--danger); }
.btn {
  align-self: flex-start; padding: 0.5rem 1.1rem; border-radius: 8px; border: 1px solid var(--border-med);
  background: var(--surface-2); color: var(--text); font: inherit; cursor: pointer;
}
.btn--primary { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.btn:disabled { opacity: 0.6; cursor: default; }
.table { width: 100%; border-collapse: collapse; font-size: var(--fs-md); }
.table th, .table td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
.table th { color: var(--text-muted); font-weight: 600; font-size: var(--fs-sm); }
.row--changed { background: color-mix(in srgb, var(--warn) 10%, transparent); }
.gates { display: flex; flex-direction: column; gap: 0.2rem; }
.gate { font-size: var(--fs-sm); }
.gate--added { color: var(--danger); }
.gate--removed { color: var(--success); }
</style>
