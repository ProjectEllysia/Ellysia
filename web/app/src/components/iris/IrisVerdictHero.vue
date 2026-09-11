<template>
  <div class="rv-hero" :class="`rv-hero--${verdictClass}`">
    <div class="rv-hero-score">
      <span class="score-num">{{ score }}</span>
      <span class="score-unit">/ máx</span>
    </div>
    <div class="rv-hero-verdict">
      <span class="verdict-badge" :class="`verdict--${verdictClass}`">{{ verdict }}</span>
      <span class="verdict-status">{{ statusLabel }}</span>
      <span v-if="confidenceLabel" class="verdict-confidence" :class="`confidence--${confidence}`">
        Confianza {{ confidenceLabel }} · {{ coverageLabel }}
      </span>
    </div>
  </div>
</template>

<script setup>
/**
 * Score + veredicto de IrisReportViewer. Bloque autónomo: sus clases
 * (.rv-hero*, .score-*, .verdict-*) no se comparten con ninguna otra
 * sección del informe, así que no hace falta duplicar nada en el padre.
 */
import { computed } from 'vue'

const props = defineProps({
  score: { type: [Number, null], default: null },
  verdict: { type: [String, null], default: null },
  // Confianza ordinal del análisis ('high' | 'medium' | 'low'). No es una
  // probabilidad: el score no está calibrado, así que nunca se muestra como %.
  confidence: { type: [String, null], default: null },
  // 'full_message' | 'headers_only'
  coverageMode: { type: [String, null], default: null },
})

const CONFIDENCE_LABELS = { high: 'alta', medium: 'media', low: 'baja' }
const confidenceLabel = computed(() => CONFIDENCE_LABELS[props.confidence] ?? '')
const coverageLabel = computed(() =>
  props.coverageMode === 'headers_only' ? 'solo cabeceras' : 'mensaje completo'
)

const verdictClass = computed(() => {
  const v = props.verdict?.toLowerCase() ?? ''
  if (v === 'legitimate') return 'legit'
  if (v === 'suspicious') return 'susp'
  if (v === 'phishing') return 'phish'
  return 'unknown'
})

const statusLabel = computed(() => {
  const v = props.verdict?.toLowerCase() ?? ''
  if (v === 'legitimate') return 'Correo verificado'
  if (v === 'suspicious') return 'Posible amenaza'
  if (v === 'phishing') return 'Phishing detectado'
  return ''
})
</script>

<style scoped>
.rv-hero {
  display: flex;
  align-items: center;
  gap: 2rem;
  padding: 1.5rem 2rem;
  border-radius: 12px;
  border: 1px solid var(--border-med);
  background: var(--surface);
}

.rv-hero--legit {
  border-color: rgba(76, 183, 130, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(76, 183, 130, 0.04) 100%);
}

.rv-hero--susp {
  border-color: rgba(212, 160, 74, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(212, 160, 74, 0.04) 100%);
}

.rv-hero--phish {
  border-color: rgba(217, 108, 108, 0.2);
  background: linear-gradient(135deg, var(--surface) 0%, rgba(217, 108, 108, 0.04) 100%);
}

.rv-hero-score {
  display: flex;
  align-items: baseline;
  gap: 0.25rem;
}

.score-num {
  font-size: var(--fs-stat-hero);
  font-weight: 800;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  letter-spacing: -0.02em;
}

.rv-hero--legit .score-num { color: var(--success); }
.rv-hero--susp .score-num { color: var(--warn); }
.rv-hero--phish .score-num { color: var(--danger); }

.score-unit {
  font-size: var(--fs-lg);
  color: var(--text-muted);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
}

.rv-hero-verdict {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.verdict-badge {
  font-size: var(--fs-xl);
  font-weight: 700;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
}

.verdict--legit { color: var(--success); }
.verdict--susp { color: var(--warn); }
.verdict--phish { color: var(--danger); }

.verdict-status {
  font-size: var(--fs-lg);
  color: var(--text-dim);
}

.verdict-confidence {
  font-size: var(--fs-sm);
  color: var(--text-muted);
}

.confidence--low { color: var(--warn); }
</style>
