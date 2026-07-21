<template>
  <div v-if="!asset" class="detail-empty">
    <p>Selecciona un activo para ver sus constantes.</p>
  </div>

  <div v-else class="detail">
    <header class="detail-head">
      <div class="head-id">
        <h3 class="detail-host">{{ asset.hostname }}</h3>
        <p class="detail-seen">Último heartbeat {{ timeAgo(asset.lastSeenAt) }}</p>
      </div>
      <span class="status" :class="`status--${asset.status}`">
        <span class="status-dot" aria-hidden="true"></span>{{ statusLabel(asset.status) }}
      </span>
    </header>

    <dl class="meta">
      <div class="meta-item">
        <dt>Sistema</dt>
        <dd>{{ asset.os || 'Desconocido' }}</dd>
      </div>
      <div class="meta-item">
        <dt>Agente</dt>
        <dd>{{ asset.agentVersion || 'Sin reportar' }}</dd>
      </div>
      <div class="meta-item">
        <dt>Alta</dt>
        <dd>{{ formatDate(asset.createdAt) }}</dd>
      </div>
    </dl>

    <section class="section">
      <h4 class="section-title">Constantes</h4>
      <p v-if="metricsLoading" class="state-msg">Cargando métricas…</p>
      <p v-else-if="metricsError" class="state-msg state-msg--error">{{ metricsError }}</p>
      <MetricsChart v-else :snapshots="metrics" />
    </section>

    <section class="section">
      <h4 class="section-title">
        Anomalías
        <span v-if="anomalies.length" class="count">{{ anomalies.length }}</span>
      </h4>

      <p v-if="!anomalies.length" class="state-msg">Ninguna anomalía registrada. El activo está sano.</p>

      <ul v-else class="anomalies">
        <li v-for="a in anomalies" :key="a.id" class="anomaly" :class="`anomaly--${a.severity}`">
          <div class="anomaly-top">
            <span class="anomaly-kind">{{ kindLabel(a.kind) }}</span>
            <span class="anomaly-state" :class="`anomaly-state--${a.state}`">{{ stateLabel(a.state) }}</span>
          </div>

          <p v-if="a.metric" class="anomaly-reading">
            <span class="reading-value">{{ a.value }}%</span>
            <span class="reading-ctx">{{ a.metric }} · umbral {{ a.threshold }}%</span>
          </p>

          <p class="anomaly-time">Abierta {{ timeAgo(a.openedAt) }}</p>

          <div v-if="a.state !== 'resolved'" class="anomaly-actions">
            <button v-if="a.state === 'open'" class="btn-sm" @click="$emit('ack', a.id)">Reconocer</button>
            <button class="btn-sm btn-sm--primary" @click="$emit('resolve', a.id)">Resolver</button>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup>
import MetricsChart from '@/components/hygeia/MetricsChart.vue'
import { useUtils } from '@/composables/useUtils'
import { timeAgo } from './format'

defineProps({
  asset: { type: Object, default: null },
  metrics: { type: Array, default: () => [] },
  metricsLoading: { type: Boolean, default: false },
  metricsError: { type: String, default: null },
  anomalies: { type: Array, default: () => [] },
})
defineEmits(['ack', 'resolve'])

const { formatDate } = useUtils()

const STATUS_LABELS = { pending: 'Pendiente', online: 'En línea', stale: 'Inestable', offline: 'Caído' }
function statusLabel(status) { return STATUS_LABELS[status] || status }

const KIND_LABELS = {
  cpu_spike: 'Pico de CPU', mem_high: 'Memoria alta', swap_thrash: 'Swap saturado',
  disk_full: 'Disco lleno', host_down: 'Host caído',
}
function kindLabel(kind) { return KIND_LABELS[kind] || kind }

const STATE_LABELS = { open: 'Abierta', acknowledged: 'Reconocida', resolved: 'Resuelta' }
function stateLabel(state) { return STATE_LABELS[state] || state }
</script>

<style scoped>
.detail-empty { padding: 3rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-lg); }

.detail { display: flex; flex-direction: column; gap: 1.3rem; }

/* ── Identidad ── */
.detail-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
.head-id { min-width: 0; }
.detail-host {
  margin: 0;
  font-family: var(--font-mono); font-size: 1.5rem; font-weight: 600;
  color: var(--text); word-break: break-all; line-height: 1.2;
}
.detail-seen { margin: 0.25rem 0 0; font-size: var(--fs-body); color: var(--text-muted); }

.status {
  display: inline-flex; align-items: center; gap: 0.4rem; flex-shrink: 0;
  padding: 0.25rem 0.7rem; border-radius: 999px;
  font-size: var(--fs-sm); font-weight: 600; white-space: nowrap;
  border: 1px solid currentColor;
}
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status--pending { color: var(--text-muted); }
.status--online  { color: var(--success); }
.status--stale   { color: var(--warn); }
.status--offline { color: var(--danger); }

/* ── Metadatos ── */
.meta {
  display: flex; flex-wrap: wrap; gap: 0 2rem; margin: 0;
  padding: 0.7rem 0; border-block: 1px solid var(--border);
}
.meta-item { display: flex; flex-direction: column; gap: 0.15rem; }
.meta dt {
  font-size: var(--fs-sm); text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-muted);
}
.meta dd { margin: 0; font-size: var(--fs-body); color: var(--text-dim); }

/* ── Secciones ── */
.section-title {
  display: flex; align-items: center; gap: 0.5rem;
  margin: 0 0 0.7rem;
  font-size: var(--fs-sm); font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.14em;
  color: var(--text-muted);
}
.count {
  padding: 0.05rem 0.4rem; border-radius: 999px;
  background: var(--surface-3); color: var(--text-dim);
  font-size: var(--fs-sm); letter-spacing: 0;
}

.state-msg { margin: 0; padding: 1.4rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-body); }
.state-msg--error { color: var(--danger); }

/* ── Anomalías ── */
.anomalies { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
.anomaly {
  padding: 0.65rem 0.85rem;
  background: var(--surface-2);
  border: 1px solid var(--border); border-left-width: 3px;
  border-radius: 8px;
}
.anomaly--info { border-left-color: var(--info); }
.anomaly--warning { border-left-color: var(--warn); }
.anomaly--critical { border-left-color: var(--danger); }

.anomaly-top { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
.anomaly-kind { font-size: var(--fs-md); font-weight: 600; color: var(--text); }
.anomaly-state { padding: 0.05rem 0.5rem; border-radius: 999px; font-size: var(--fs-sm); font-weight: 600; }
.anomaly-state--open { background: var(--danger-dim); color: var(--danger); }
.anomaly-state--acknowledged { background: var(--warn-dim); color: var(--warn); }
.anomaly-state--resolved { background: var(--success-dim); color: var(--success); }

.anomaly-reading { display: flex; align-items: baseline; gap: 0.5rem; margin: 0.4rem 0 0; }
.reading-value {
  font-family: var(--font-mono); font-size: var(--fs-xl); font-weight: 600;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.reading-ctx { font-size: var(--fs-sm); color: var(--text-muted); }
.anomaly-time { margin: 0.2rem 0 0; font-size: var(--fs-sm); color: var(--text-muted); }

.anomaly-actions { display: flex; gap: 0.4rem; margin-top: 0.6rem; }
.btn-sm {
  padding: 0.25rem 0.65rem; border-radius: 6px;
  background: transparent; border: 1px solid var(--border-med); color: var(--text-dim);
  font-size: var(--fs-sm); font-weight: 600; cursor: pointer;
  transition: border-color var(--transition), color var(--transition);
}
.btn-sm:hover { border-color: var(--text-muted); color: var(--text); }
.btn-sm--primary { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.btn-sm--primary:hover { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }

.btn-sm:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
</style>
