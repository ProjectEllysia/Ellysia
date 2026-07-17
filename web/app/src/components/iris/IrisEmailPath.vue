<template>
  <div class="iep">
    <div class="iep-legend">
      <span class="legend-item legend-item--origin">Origen</span>
      <span class="legend-arrow">→</span>
      <span class="legend-item legend-item--dest">Destino</span>
      <span class="legend-sep">·</span>
      <span class="legend-item"><span class="legend-lock" aria-hidden="true">🔒</span> TLS</span>
      <span class="legend-item"><span class="legend-lock legend-lock--off" aria-hidden="true">🔓</span> clear</span>
      <span class="legend-sep">·</span>
      <span class="legend-item"><span class="legend-dot legend-dot--bad"></span> sospechoso</span>
    </div>

    <div v-if="!hops || hops.length === 0" class="iep-empty">
      Recorrido no disponible (envío sólo de cabeceras).
    </div>

    <div v-else class="iep-scroll">
      <div class="iep-chain">
        <template v-for="(hop, idx) in hops" :key="hop.hop">
          <button
            type="button"
            class="iep-node"
            :class="[
              hop.hop === 1 ? 'iep-node--origin' : '',
              hop.hop === hops.length ? 'iep-node--dest' : '',
              hasFlag(hop) ? 'iep-node--bad' : '',
            ]"
            @click="select(hop)"
            :aria-label="`Hop ${hop.hop}: ${hop.by || hop.fromAddress || 'desconocido'}`"
          >
            <span class="iep-node-num">#{{ hop.hop }}</span>
            <span class="iep-node-by">{{ hop.by || hop.fromAddress || 'desconocido' }}</span>
            <span v-if="hop.fromIp" class="iep-node-ip">{{ hop.fromIp }}</span>
            <span class="iep-node-tls" :class="hop.tls ? 'on' : 'off'" :title="hop.tls ? 'TLS' : 'clear'">
              {{ hop.tls ? '🔒' : '🔓' }}
            </span>
            <span v-if="hop.timestamp" class="iep-node-time">{{ formatTime(hop.timestamp) }}</span>
          </button>
          <div
            v-if="idx < hops.length - 1"
            class="iep-edge"
            :class="edgeClass(transitions[idx])"
            :title="edgeTitle(transitions[idx])"
          >
            <span class="iep-edge-arrow" aria-hidden="true">▶</span>
            <span v-if="delayLabel(transitions[idx])" class="iep-edge-delay">
              {{ delayLabel(transitions[idx]) }}
            </span>
          </div>
        </template>
      </div>
    </div>

    <Transition name="iep-detail">
      <div v-if="selected" class="iep-detail">
        <div class="iep-detail-head">
          <span class="iep-detail-title">Hop #{{ selected.hop }}</span>
          <button type="button" class="iep-detail-close" @click="selected = null" aria-label="Cerrar">×</button>
        </div>
        <dl class="iep-detail-grid">
          <dt>De</dt><dd>{{ selected.fromAddress || '—' }}</dd>
          <dt>IP</dt><dd>{{ selected.fromIp || '—' }}</dd>
          <dt>Por</dt><dd>{{ selected.by || '—' }}</dd>
          <dt>Con</dt><dd>{{ selected.withProtocol || '—' }}</dd>
          <dt>Protocolo</dt><dd>{{ selected.protocol || '—' }}</dd>
          <dt>Para</dt><dd>{{ selected.forAddress || '—' }}</dd>
          <dt>TLS</dt><dd>{{ selected.tls ? 'sí' : 'no' }}</dd>
          <dt>Timestamp</dt><dd>{{ selected.timestamp || '—' }}</dd>
          <template v-if="selected.flags && selected.flags.length">
            <dt>Flags</dt>
            <dd>
              <span v-for="f in selected.flags" :key="f" class="iep-flag">{{ f }}</span>
            </dd>
          </template>
        </dl>
        <details class="iep-detail-raw">
          <summary>Cabecera original</summary>
          <pre>{{ selected.raw }}</pre>
        </details>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const props = defineProps({
  hops: { type: Array, default: () => [] },
  transitions: { type: Array, default: () => [] },
})

const selected = ref(null)

function select(hop) {
  selected.value = selected.value && selected.value.hop === hop.hop ? null : hop
}

function hasFlag(hop) {
  return (hop.flags || []).length > 0
}

function edgeClass(t) {
  if (!t) return ''
  return t.suspicious ? 'iep-edge--bad' : 'iep-edge--ok'
}

function edgeTitle(t) {
  if (!t) return ''
  if (!t.reasons || t.reasons.length === 0) return 'tránsito normal'
  return `sospechoso: ${t.reasons.join(', ')}`
}

function delayLabel(t) {
  if (!t || t.delayMs == null) return ''
  const ms = t.delayMs
  if (ms < 0) return `${Math.abs(ms / 1000).toFixed(1)}s invertido`
  if (ms < 1000) return `${ms} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

function formatTime(iso) {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    return d.toISOString().slice(11, 16) + 'Z'
  } catch {
    return ''
  }
}
</script>

<style scoped>
.iep {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
  padding: 1rem 1.1rem 1.1rem;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface);
}

.iep-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem 0.7rem;
  font-size: var(--fs-lg);
  color: var(--text-muted);
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
}

.legend-sep {
  color: var(--text-muted);
  opacity: 0.5;
}

.legend-arrow {
  color: var(--accent);
  font-size: var(--fs-xl);
}

.legend-dot {
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 50%;
  display: inline-block;
}

.legend-dot--bad {
  background: var(--danger);
  box-shadow: 0 0 6px color-mix(in srgb, var(--danger) 60%, transparent);
}

.iep-empty {
  padding: 1.25rem 0.5rem;
  text-align: center;
  color: var(--text-muted);
  font-size: var(--fs-xl);
  border: 1px dashed var(--border);
  border-radius: 8px;
  font-family: var(--font-mono);
}

.iep-scroll {
  overflow-x: auto;
  padding: 0.25rem 0.1rem 0.5rem;
}

.iep-chain {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  min-width: max-content;
}

.iep-node {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.15rem;
  padding: 0.7rem 0.9rem;
  min-width: 160px;
  border: 1px solid var(--border-med);
  border-radius: 10px;
  background: var(--surface-2);
  color: var(--text);
  cursor: pointer;
  text-align: left;
  font: inherit;
  transition: border-color 0.18s, box-shadow 0.18s, transform 0.18s;
}

.iep-node:hover,
.iep-node:focus-visible {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 22%, transparent);
  transform: translateY(-1px);
  outline: none;
}

.iep-node--origin {
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 8%, var(--surface-2));
}

.iep-node--dest {
  border-color: var(--success);
  background: color-mix(in srgb, var(--success) 8%, var(--surface-2));
}

.iep-node--bad {
  border-color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface-2));
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--danger) 30%, transparent);
}

.iep-node-num {
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  color: var(--text-muted);
  letter-spacing: 0.06em;
}

.iep-node-by {
  font-size: var(--fs-xl);
  font-weight: 700;
  font-family: var(--font-mono);
  color: var(--text);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.iep-node-ip {
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  color: var(--text-dim);
}

.iep-node-tls {
  font-size: var(--fs-lg);
}

.iep-node-tls.off { opacity: 0.55; }

.iep-node-time {
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  color: var(--text-muted);
}

.iep-edge {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0 0.35rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  min-width: 64px;
  justify-content: center;
}

.iep-edge--ok .iep-edge-arrow { color: var(--accent); }
.iep-edge--bad .iep-edge-arrow { color: var(--danger); }
.iep-edge--bad { color: var(--danger); }

.iep-edge-arrow { font-size: var(--fs-xl); }
.iep-edge-delay { white-space: nowrap; }

.iep-detail {
  margin-top: 0.4rem;
  padding: 0.85rem 1rem 0.9rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-2);
}

.iep-detail-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.iep-detail-title {
  font-family: var(--font-display);
  font-weight: 700;
  color: var(--text);
}

.iep-detail-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: var(--fs-xl);
  line-height: 1;
  cursor: pointer;
  padding: 0 0.3rem;
}
.iep-detail-close:hover { color: var(--text); }

.iep-detail-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.25rem 0.85rem;
  margin: 0 0 0.4rem;
  font-size: var(--fs-lg);
}

.iep-detail-grid dt {
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
}

.iep-detail-grid dd {
  color: var(--text);
  margin: 0;
  word-break: break-word;
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
}

.iep-flag {
  display: inline-block;
  margin-right: 0.3rem;
  padding: 1px 6px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  background: color-mix(in srgb, var(--danger) 18%, transparent);
  color: var(--danger);
  border: 1px solid color-mix(in srgb, var(--danger) 30%, transparent);
}

.iep-detail-raw summary {
  cursor: pointer;
  color: var(--text-dim);
  font-size: var(--fs-lg);
  margin-top: 0.4rem;
}

.iep-detail-raw pre {
  margin: 0.45rem 0 0;
  padding: 0.6rem 0.75rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-dim);
  max-height: 180px;
  overflow: auto;
}

.iep-detail-enter-active,
.iep-detail-leave-active {
  transition: opacity 0.18s ease, transform 0.18s ease;
}
.iep-detail-enter-from,
.iep-detail-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
