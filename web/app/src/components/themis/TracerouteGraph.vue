<template>
  <div class="tr-wrap">
    <div class="tr-head">
      <div class="tr-title-wrap">
        <h3>Ruta de red (traceroute)</h3>
        <span v-if="computedAt && !loading" class="tr-meta">
          {{ cached ? 'Cacheado' : 'Calculado' }} {{ fmt(computedAt) }}
        </span>
      </div>
      <button class="tr-refresh" :disabled="loading" title="Recalcular ruta" @click="$emit('refresh')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: loading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
      </button>
    </div>

    <div v-if="loading" class="tr-state">
      <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
      <span>Calculando ruta hasta el objetivo…</span>
    </div>

    <div v-else-if="!hops.length" class="tr-state">
      <span>No se pudo trazar la ruta hasta el objetivo.</span>
    </div>

    <ol v-else class="tr-chain">
      <li class="tr-node origin">
        <span class="tr-ttl"></span>
        <span class="tr-dot"></span>
        <div class="tr-body">
          <span class="tr-host">Servidor Ellysia</span>
          <span class="tr-sub">Origen</span>
        </div>
      </li>
      <li
        v-for="(hop, idx) in hops"
        :key="hop.ttl + '-' + idx"
        class="tr-node"
        :class="{ timeout: !hop.ip, target: idx === hops.length - 1 }"
      >
        <span class="tr-ttl">{{ hop.ttl }}</span>
        <span class="tr-dot"></span>
        <div class="tr-body">
          <template v-if="hop.ip">
            <span class="tr-host mono">{{ hop.hostname || hop.ip }}</span>
            <span v-if="hop.hostname" class="tr-sub mono">{{ hop.ip }}</span>
          </template>
          <span v-else class="tr-host muted">Sin respuesta (*)</span>
        </div>
        <span v-if="hop.rtt_ms != null" class="tr-rtt">{{ hop.rtt_ms }} ms</span>
        <span v-if="idx === hops.length - 1 && hop.ip" class="tr-target-tag">Objetivo</span>
      </li>
    </ol>
  </div>
</template>

<script setup>
defineProps({
  hops: { type: Array, default: () => [] },
  loading: Boolean,
  computedAt: { type: String, default: null },
  cached: Boolean,
})
defineEmits(['refresh'])

function fmt(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString()
}
</script>

<style scoped>
.tr-wrap { width: 100%; }
.tr-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.65rem; }
.tr-title-wrap { display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.tr-head h3 { font-size: var(--fs-xl); font-weight: 600; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.tr-meta { font-size: var(--fs-md); color: var(--text-muted); }
.tr-refresh { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 3px; border-radius: 5px; display: flex; }
.tr-refresh:hover:not(:disabled) { color: var(--accent); }
.tr-refresh:disabled { opacity: 0.4; cursor: not-allowed; }
.tr-refresh svg { width: 14px; height: 14px; }

.tr-state { display: flex; align-items: center; gap: 0.5rem; justify-content: center; padding: 1.1rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; font-size: var(--fs-lg); color: var(--text-muted); }
.tr-state svg { width: 16px; height: 16px; }

.tr-chain { list-style: none; margin: 0; padding: 0; position: relative; }
/* Vertical connector running through the dots. */
.tr-chain::before { content: ''; position: absolute; left: 33px; top: 12px; bottom: 12px; width: 2px; background: var(--border); }

.tr-node { position: relative; display: flex; align-items: center; gap: 0.6rem; padding: 0.4rem 0.6rem 0.4rem 0; min-height: 38px; }
.tr-ttl { width: 18px; text-align: right; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); color: var(--text-muted); flex-shrink: 0; }
.tr-node.origin .tr-ttl { visibility: hidden; }
.tr-dot { width: 11px; height: 11px; border-radius: 50%; background: var(--surface); border: 2px solid var(--accent); margin-left: 3px; flex-shrink: 0; z-index: 1; }
.tr-node.origin .tr-dot { background: var(--accent); }
.tr-node.target .tr-dot { background: var(--accent-bright, var(--accent)); border-color: var(--accent-bright, var(--accent)); box-shadow: 0 0 0 3px var(--accent-dim); }
.tr-node.timeout .tr-dot { border-color: var(--border-med, var(--border)); border-style: dashed; }

.tr-body { display: flex; flex-direction: column; min-width: 0; flex: 1; }
.tr-host { font-size: var(--fs-lg); color: var(--text); font-weight: 500; word-break: break-all; }
.tr-host.muted { color: var(--text-muted); font-weight: 400; font-style: italic; }
.tr-sub { font-size: var(--fs-md); color: var(--text-muted); word-break: break-all; }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }

.tr-rtt { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); color: var(--info); background: var(--surface-2); padding: 2px 7px; border-radius: 8px; flex-shrink: 0; }
.tr-target-tag { font-size: var(--fs-body); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-bright, var(--accent)); background: var(--accent-dim); padding: 2px 7px; border-radius: 8px; flex-shrink: 0; }

.spin { animation: seq-spin 0.8s linear infinite; }
</style>
