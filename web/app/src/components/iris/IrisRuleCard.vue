<template>
  <div class="rule-card" :class="{ 'rule-card--expanded': expanded }">
    <button type="button" class="rule-header" @click="$emit('toggle')">
      <div class="rule-left">
        <span class="rule-name">{{ rule.ruleName }}</span>
        <span class="rule-category" v-if="rule.category">{{ ruleCategoryLabel(rule.category) }}</span>
        <span v-if="rule.severity" class="rule-severity" :class="`rule-severity--${rule.severity}`">{{ SEVERITY_LABELS[rule.severity] || rule.severity }}</span>
      </div>
      <div class="rule-right">
        <span class="rule-score" :class="scoreClass(rule.score, rule.verdict)">{{ sign(rule.score) }}{{ rule.score }}</span>
        <!-- El código exacto (`softfail`, `bestguess`…) es lo que busca un
             técnico: se queda en el tooltip, no en la primera lectura. -->
        <span class="rule-verdict" :class="`verdict-chip--${rule.verdict}`" :title="`Código: ${rule.verdict}`">{{ ruleVerdictLabel(rule.verdict) }}</span>
        <svg class="rule-chevron" :class="{ rotated: expanded }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
    </button>
    <Transition name="rule-detail">
      <div v-if="expanded" class="rule-detail">
        <!-- Referencia estable del hallazgo: el id no cambia aunque cambie el
             nombre visible, y las técnicas enlazan a MITRE ATT&CK. -->
        <p v-if="rule.ruleId" class="rule-reference">
          <code class="rule-id">{{ rule.ruleId }}</code>
          <a
            v-for="technique in rule.mitreTechniques || []"
            :key="technique"
            class="rule-technique"
            :href="attackUrl(technique)"
            target="_blank"
            rel="noopener noreferrer"
          >ATT&amp;CK {{ technique }}</a>
        </p>
        <div v-if="rule.details && Object.keys(rule.details).length" class="rule-details">
          <div v-for="(v, k) in rule.details" :key="k" class="detail-row">
            <span class="detail-key">{{ k }}</span>
            <span class="detail-val" :class="{ 'detail-val--empty': isEmptyValue(v) }">{{ formatDetailValue(v) }}</span>
          </div>
        </div>
        <!-- Evidencia anclada: dónde está lo que la regla encontró. Las
             cabeceras saltan a su línea en "Cabeceras originales"; enlaces y
             adjuntos muestran el extracto, ya desactivado (hxxp, [.], [@]). -->
        <div v-if="rule.evidence && rule.evidence.length" class="rule-evidence">
          <span class="evidence-title">Evidencia</span>
          <template v-for="(item, k) in rule.evidence" :key="k">
            <button
              v-if="item.kind === 'header'"
              type="button"
              class="evidence-item evidence-item--jump"
              title="Ver en las cabeceras originales"
              @click="$emit('jump-evidence', item)"
            >
              <span class="evidence-kind">{{ evidenceLabel(item) }}</span>
              <code class="evidence-excerpt">{{ item.excerpt }}</code>
            </button>
            <div v-else class="evidence-item">
              <span class="evidence-kind">{{ evidenceLabel(item) }}</span>
              <code class="evidence-excerpt">{{ item.excerpt }}</code>
            </div>
          </template>
        </div>
        <p v-else-if="rule.evidenceUnavailableReason" class="evidence-unavailable">
          Sin evidencia anclada: {{ rule.evidenceUnavailableReason }}
        </p>
        <div v-if="rule.recommendation" class="rule-recommendation">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="rec-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          {{ rule.recommendation }}
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ruleCategoryLabel, ruleVerdictLabel } from '@/components/iris/verdict'

defineProps({
  rule: { type: Object, required: true },
  expanded: { type: Boolean, default: false },
})

defineEmits(['toggle', 'jump-evidence'])

const SEVERITY_LABELS = { low: 'baja', medium: 'media', high: 'alta', critical: 'crítica' }

/** Página de MITRE ATT&CK de una técnica: T1566.002 -> /techniques/T1566/002/. */
function attackUrl(technique) {
  return `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`
}

/** Etiqueta corta de un elemento de evidencia (ver services/evidence.py en la API). */
function evidenceLabel(item) {
  const locator = item.locator ?? {}
  if (item.kind === 'header') {
    const occurrence = locator.occurrence ? ` #${locator.occurrence + 1}` : ''
    return `Cabecera ${locator.header}${occurrence}`
  }
  if (item.kind === 'url') return locator.source === 'qr_code' ? 'URL en QR' : 'Enlace'
  if (item.kind === 'attachment') return 'Adjunto'
  if (item.kind === 'body') return 'Cuerpo'
  if (item.kind === 'mime_part') return 'Parte MIME'
  return 'Evidencia'
}

function sign(s) {
  if (s > 0) return '+'
  return ''
}

function scoreClass(s, v) {
  if (s > 0) return 'score--pos'
  if (s < 0) return 'score--neg'
  if (v === 'pass') return 'score--pos'
  return 'score--neutral'
}

/** Un array vacío es una respuesta válida ("se buscó y no se encontró
 * nada"), no la ausencia de dato — antes se renderizaba como el literal
 * "[]", que a simple vista parece una celda sin valor. */
function isEmptyValue(v) {
  return Array.isArray(v) && v.length === 0
}

/** `Array.prototype.join` llama a `toString()` en cada elemento; para un
 * array de strings eso da el texto esperado, pero para un array de objetos
 * (p. ej. `findings`) da el literal "[object Object]" por cada uno — hay
 * que serializar los elementos que sean objeto en vez de dejar que `join`
 * los stringifique solo. */
function formatDetailValue(v) {
  if (Array.isArray(v)) {
    if (!v.length) return '—'
    return v.map((item) => (item && typeof item === 'object' ? JSON.stringify(item) : item)).join(', ')
  }
  if (v && typeof v === 'object') return JSON.stringify(v)
  return v
}
</script>

<style scoped>
.rule-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 0.4rem;
  overflow: hidden;
  transition: border-color 0.2s;
}

.rule-card:hover {
  border-color: var(--border-med);
}

.rule-evidence {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  margin-bottom: 0.6rem;
}

.evidence-title {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text-muted);
}

.evidence-item {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  padding: 0.35rem 0.55rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text);
  text-align: left;
  font: inherit;
}

.evidence-item--jump {
  cursor: pointer;
}

.evidence-item--jump:hover {
  border-color: var(--accent);
}

.evidence-kind {
  flex-shrink: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.evidence-excerpt {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-sm);
  word-break: break-all;
}

.evidence-unavailable {
  margin: 0 0 0.6rem;
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.rule-card--expanded {
  border-color: var(--accent);
}

.rule-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 0.85rem 1.1rem;
  background: var(--surface);
  border: none;
  color: var(--text);
  cursor: pointer;
  transition: background 0.15s;
  gap: 0.5rem;
}

.rule-header:hover {
  background: var(--surface-2);
}

.rule-left {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-width: 0;
}

.rule-name {
  font-size: var(--fs-lg);
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
}

.rule-category {
  font-size: var(--fs-md);
  font-weight: 500;
  color: var(--text-muted);
  background: var(--surface-2);
  padding: 3px 8px;
  border-radius: 5px;
  white-space: nowrap;
}

.rule-right {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  flex-shrink: 0;
}

.rule-score {
  font-size: var(--fs-lg);
  font-weight: 700;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  min-width: 3rem;
  text-align: right;
}

.score--pos { color: var(--success); }
.score--neg { color: var(--danger); }
.score--neutral { color: var(--text-muted); }

.rule-severity {
  font-size: var(--fs-xs);
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 999px;
  text-transform: uppercase;
  background: rgba(100, 116, 139, 0.12);
  color: var(--text-muted);
}
.rule-severity--high { background: var(--warn-dim); color: var(--warn); }
.rule-severity--critical { background: var(--danger-dim); color: var(--danger); }
.rule-reference { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; margin: 0 0 0.6rem; }
.rule-id { font-size: var(--fs-sm); color: var(--text-muted); }
.rule-technique { font-size: var(--fs-sm); color: var(--accent-bright); text-decoration: underline; }

.rule-verdict {
  font-size: var(--fs-md);
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 5px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.verdict-chip--pass {
  background: var(--success-dim);
  color: var(--success);
  border: 1px solid rgba(76, 183, 130, 0.15);
}

.verdict-chip--fail {
  background: var(--danger-dim);
  color: var(--danger);
  border: 1px solid rgba(217, 108, 108, 0.15);
}

.verdict-chip--suspicious {
  background: var(--warn-dim);
  color: var(--warn);
  border: 1px solid rgba(212, 160, 74, 0.15);
}

.verdict-chip--neutral,
.verdict-chip--missing,
.verdict-chip--softfail {
  background: rgba(100, 116, 139, 0.1);
  color: var(--text-muted);
  border: 1px solid var(--border);
}

.verdict-chip--error {
  background: var(--danger-dim);
  color: var(--danger);
  border: 1px solid rgba(217, 108, 108, 0.15);
}

/* Regla neutralizada por una excepción de confianza del usuario. */
.verdict-chip--trusted,
.verdict-chip--bestguess,
.verdict-chip--policy {
  background: var(--info-dim);
  color: var(--info);
  border: 1px solid rgba(96, 128, 224, 0.15);
}

.rule-chevron {
  width: 18px;
  height: 18px;
  color: var(--text-muted);
  transition: transform 0.2s;
  flex-shrink: 0;
}

.rule-chevron.rotated {
  transform: rotate(180deg);
}

.rule-detail {
  padding: 0 1.1rem 0.85rem;
  background: var(--surface);
  border-top: 1px solid var(--border);
}

/* Grid, no flex: con flex cada .detail-row calcula el ancho de su propia
   clave por separado, así que la columna de valores arranca en una
   posición distinta según lo larga que sea cada clave ("hidden_text" vs
   "phrases_found"). El grid comparte una sola pista de columna ("max-content")
   calculada sobre TODAS las filas a la vez, así que los valores quedan
   alineados sin importar la longitud de cada clave. */
.rule-details {
  display: grid;
  grid-template-columns: max-content 1fr;
  row-gap: 0.4rem;
  column-gap: 0.75rem;
  margin-bottom: 0.6rem;
}

.detail-row {
  display: contents;
}

.detail-key {
  color: var(--text-muted);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  line-height: 1.6;
}

.detail-val {
  color: var(--text-dim);
  font-size: var(--fs-lg);
  line-height: 1.6;
  word-break: break-word;
}

.detail-val--empty {
  color: var(--text-muted);
  font-style: italic;
}

.rule-recommendation {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.65rem 0.85rem;
  border-radius: 8px;
  background: var(--warn-dim);
  border: 1px solid rgba(212, 160, 74, 0.12);
  color: var(--warn);
  font-size: var(--fs-lg);
  line-height: 1.5;
}

.rec-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 2px;
}

/* Rule detail transition */
.rule-detail-enter-active,
.rule-detail-leave-active {
  transition: all 0.2s ease;
}

.rule-detail-enter-from,
.rule-detail-leave-to {
  opacity: 0;
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
}
</style>
