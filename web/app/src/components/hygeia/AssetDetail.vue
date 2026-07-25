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
      <div v-if="asset.kernel" class="meta-item">
        <dt>Kernel</dt>
        <dd>{{ asset.kernel }}</dd>
      </div>
      <div v-if="bootedAgo" class="meta-item">
        <dt>Arrancado</dt>
        <dd>{{ bootedAgo }}</dd>
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

    <AssetTabs
      :active="activeTab"
      :anomaly-count="openAnomalyCount"
      :stats-warning="statsWarning"
      @switch="activeTab = $event"
    />

    <div v-show="activeTab === 'graficas'" class="tab-panel">
      <section class="section">
        <h4 class="section-title">Constantes</h4>
        <p v-if="metricsLoading" class="state-msg">Cargando métricas…</p>
        <p v-else-if="metricsError" class="state-msg state-msg--error">{{ metricsError }}</p>
        <MetricsChart v-else :snapshots="metrics" :truncated="metricsTruncated" />
      </section>
    </div>

    <!-- Todo lo que sigue es el último heartbeat: tiene cardinalidad por
         entidad (montaje, interfaz, proceso, núcleo) y solo tiene sentido
         "ahora", así que no viaja en la serie temporal. -->
    <div v-show="activeTab === 'estadisticas'" class="tab-panel">
      <p v-if="latestError" class="state-msg state-msg--error">{{ latestError }}</p>

      <template v-if="m">
        <section v-if="memory" class="section">
          <h4 class="section-title">Memoria</h4>
          <dl class="readout">
            <div class="readout-item">
              <dt>En uso</dt>
              <dd>{{ used.text }}<small class="unit--wide">{{ used.unit }}</small></dd>
            </div>
            <div class="readout-item">
              <dt>Total</dt>
              <dd>{{ totalMem.text }}<small class="unit--wide">{{ totalMem.unit }}</small></dd>
            </div>
            <div v-if="memory.swapUsedPct !== null && memory.swapUsedPct !== undefined" class="readout-item">
              <dt>Swap</dt>
              <dd>{{ fmtPct(memory.swapUsedPct) }}<small>%</small></dd>
            </div>
          </dl>
        </section>

        <section v-if="disks.length" class="section">
          <h4 class="section-title">Almacenamiento</h4>
          <ul class="rows">
            <li v-for="d in disks" :key="d.mount" class="row row--disk">
              <span class="row-name" :title="d.mount">{{ d.mount }}</span>
              <span class="bar" :class="{ 'bar--hot': d.usagePct >= 85 }">
                <span class="bar-fill" :style="{ width: `${Math.min(100, d.usagePct)}%` }"></span>
              </span>
              <span class="row-value">{{ fmtPct(d.usagePct) }}%</span>
              <span class="row-note">{{ free(d).text }} {{ free(d).unit }} libres</span>
            </li>
          </ul>
        </section>

        <section v-if="nets.length" class="section">
          <h4 class="section-title">
            Red
            <span class="hint">el gráfico suma solo las no-loopback</span>
          </h4>
          <ul class="rows">
            <li v-for="n in nets" :key="n.iface" class="row row--net">
              <span class="row-name" :title="n.iface">{{ n.iface }}</span>
              <span class="row-value">↓ {{ rate(n.rxBytesPerSec).text }} <small>{{ rate(n.rxBytesPerSec).unit }}</small></span>
              <span class="row-value">↑ {{ rate(n.txBytesPerSec).text }} <small>{{ rate(n.txBytesPerSec).unit }}</small></span>
              <span v-if="errorsOf(n)" class="row-note row-note--bad">{{ errorsOf(n) }} err</span>
            </li>
          </ul>
        </section>

        <section v-if="topCpu.length || topMem.length || cores.length" class="section">
          <h4 class="section-title">
            Procesos
            <span v-if="procTotal !== null" class="count">{{ procTotal }}</span>
          </h4>

          <div v-if="cores.length" class="cores-block">
            <div class="cores">
              <span
                v-for="(pct, i) in cores"
                :key="i"
                class="core"
                :class="{ 'core--hot': pct >= 85 }"
                :title="`Núcleo ${i}: ${fmtPct(pct)} %`"
              >
                <span class="core-fill" :style="{ height: `${Math.min(100, pct)}%` }"></span>
              </span>
            </div>
            <p v-if="hiddenCores" class="hint hint--block">+{{ hiddenCores }} núcleos más sin representar</p>
          </div>

          <div class="proc-cols">
            <div v-if="topCpu.length" class="proc-col">
              <h5 class="proc-head">Por CPU</h5>
              <TransitionGroup tag="ul" name="proc-row" class="rows">
                <li v-for="p in topCpu" :key="`c${p.pid}`" class="row row--proc">
                  <span class="row-name" :title="p.name">{{ p.name }}</span>
                  <span class="row-pid">{{ p.pid }}</span>
                  <span class="row-value">{{ fmtPct(p.cpuPct) }}%</span>
                </li>
              </TransitionGroup>
            </div>

            <div v-if="topMem.length" class="proc-col">
              <h5 class="proc-head">Por memoria</h5>
              <TransitionGroup tag="ul" name="proc-row" class="rows">
                <li v-for="p in topMem" :key="`m${p.pid}`" class="row row--proc">
                  <span class="row-name" :title="p.name">{{ p.name }}</span>
                  <span class="row-pid">{{ p.pid }}</span>
                  <span class="row-value">{{ fmtPct(p.memPct) }}%</span>
                </li>
              </TransitionGroup>
            </div>
          </div>

          <p v-if="zombies" class="hint hint--block">{{ zombies }} en estado zombi</p>
        </section>
      </template>
    </div>

    <div v-show="activeTab === 'anomalias'" class="tab-panel">
      <section class="section">
        <h4 class="section-title">
          Anomalías
          <span v-if="anomalies.length" class="count">{{ anomalies.length }}</span>
        </h4>

        <p v-if="!anomalies.length" class="state-msg">Ninguna anomalía registrada. El activo está sano.</p>

        <TransitionGroup v-else tag="ul" name="anomaly-row" class="anomalies">
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

            <div class="anomaly-actions">
              <button v-if="a.state === 'open'" class="btn-sm" @click="$emit('ack', a.id)">Reconocer</button>
              <button v-if="a.state !== 'resolved'" class="btn-sm btn-sm--primary" @click="$emit('resolve', a.id)">Resolver</button>
              <button v-if="a.state !== 'open'" class="btn-sm btn-sm--danger" @click="$emit('delete', a.id)">Borrar</button>
            </div>
          </li>
        </TransitionGroup>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import MetricsChart from '@/components/hygeia/MetricsChart.vue'
import AssetTabs from '@/components/hygeia/AssetTabs.vue'
import { useUtils } from '@/composables/useUtils'
import { fmtBytes, fmtPct, fmtRate, timeAgo } from './format'

const props = defineProps({
  asset: { type: Object, default: null },
  metrics: { type: Array, default: () => [] },
  metricsTruncated: { type: Boolean, default: false },
  metricsLoading: { type: Boolean, default: false },
  metricsError: { type: String, default: null },
  // Último heartbeat completo: { collectedAt, receivedAt, metrics }. `metrics`
  // llega a null mientras el activo no haya reportado nunca.
  latest: { type: Object, default: null },
  latestError: { type: String, default: null },
  anomalies: { type: Array, default: () => [] },
})
defineEmits(['ack', 'resolve', 'delete'])

const { formatDate } = useUtils()

const TAB_IDS = ['graficas', 'estadisticas', 'anomalias']
const TAB_STORAGE_PREFIX = 'ellysia:hygeia:lastTab:'

const activeTab = ref('graficas')
/** Al cambiar de activo se recupera la última pestaña que se miró en ESE
 *  host (persistida por id), no la que quedó abierta en el anterior. */
watch(() => props.asset?.id, (id) => {
  const stored = id ? localStorage.getItem(TAB_STORAGE_PREFIX + id) : null
  activeTab.value = TAB_IDS.includes(stored) ? stored : 'graficas'
}, { immediate: true })

watch(activeTab, (tab) => {
  const id = props.asset?.id
  if (id) localStorage.setItem(TAB_STORAGE_PREFIX + id, tab)
})

const KEY_TO_TAB = { '1': 'graficas', '2': 'estadisticas', '3': 'anomalias' }

function isTypingTarget(el) {
  return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

/** Atajos 1/2/3 para saltar de pestaña sin ratón; se ignoran mientras se
 *  escribe en un campo o con teclas modificadoras (para no pisar otros
 *  atajos del navegador). */
function handleTabShortcut(event) {
  if (!props.asset || event.ctrlKey || event.metaKey || event.altKey) return
  if (isTypingTarget(event.target)) return
  const tab = KEY_TO_TAB[event.key]
  if (tab) activeTab.value = tab
}

onMounted(() => window.addEventListener('keydown', handleTabShortcut))
onUnmounted(() => window.removeEventListener('keydown', handleTabShortcut))

const openAnomalyCount = computed(() =>
  props.anomalies.filter((a) => a.state !== 'resolved').length
)

/**
 * Un host con muchos núcleos re-renderizaría cientos de barras cada 15 s. El
 * contrato de ingesta admite hasta 1024, así que se corta y se dice cuántos
 * quedan fuera en vez de pintarlos todos.
 */
const MAX_CORES = 128

/** Bloque `metrics` del último heartbeat, o null si el activo no ha reportado. */
const m = computed(() => props.latest?.metrics ?? null)

const memory = computed(() => m.value?.memory ?? null)
const used = computed(() => fmtBytes(memory.value?.usedBytes))
const totalMem = computed(() => fmtBytes(memory.value?.totalBytes))

/** Montajes de más lleno a más vacío: lo que está a punto de reventar, arriba. */
const disks = computed(() =>
  [...(m.value?.disk ?? [])].sort((a, b) => (b.usagePct ?? 0) - (a.usagePct ?? 0)),
)

/**
 * Interfaces tal como las reporta el agente, loopback incluida.
 *
 * El gráfico suma solo las no-loopback, así que aquí aparece una fila que no
 * cuenta para esa traza — de ahí la nota junto al título. Es intencionado:
 * ver el desglose completo es justamente para lo que sirve esta tabla.
 */
const nets = computed(() => m.value?.network ?? [])

const cores = computed(() => (m.value?.cpu?.perCorePct ?? []).slice(0, MAX_CORES))
const coreCount = computed(() => (m.value?.cpu?.perCorePct ?? []).length)

/** Mismo umbral que ya pinta discos y núcleos en rojo (`>= 85`) — el punto
 *  de la pestaña "Estadísticas" es solo un adelanto de que hay algo así
 *  dentro, sin duplicar el criterio. */
const statsWarning = computed(() =>
  disks.value.some((d) => d.usagePct >= 85) || cores.value.some((pct) => pct >= 85)
)
const hiddenCores = computed(() => Math.max(0, coreCount.value - MAX_CORES))

const topCpu = computed(() => m.value?.processes?.topCpu ?? [])
const topMem = computed(() => m.value?.processes?.topMem ?? [])
const procTotal = computed(() => m.value?.processes?.total ?? null)
const zombies = computed(() => m.value?.processes?.zombie ?? 0)

/**
 * Antigüedad del arranque del host.
 *
 * Se deriva de `lastSeenAt - uptimeSec` en lugar de mostrar el uptime crudo:
 * el uptime es un valor instantáneo que envejece entre sondeos, mientras que
 * el instante de arranque es fijo y `timeAgo` lo mantiene correcto solo.
 */
const bootedAgo = computed(() => {
  const uptime = props.asset?.uptimeSec
  const seen = props.asset?.lastSeenAt
  if (uptime === null || uptime === undefined || !seen) return null

  const bootedAt = new Date(seen).getTime() - uptime * 1000
  if (Number.isNaN(bootedAt)) return null
  return timeAgo(new Date(bootedAt).toISOString())
})

function free(disk) { return fmtBytes(disk.freeBytes) }
function rate(value) { return fmtRate(value) }
function errorsOf(iface) { return (iface.errIn ?? 0) + (iface.errOut ?? 0) }

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

.tab-panel { display: flex; flex-direction: column; gap: 1.3rem; }

.state-msg { margin: 0; padding: 1.4rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-body); }
.state-msg--error { color: var(--danger); }

.hint { font-size: var(--fs-xs); font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--text-muted); }
.hint--block { margin: 0.5rem 0 0; }

/* ── Lecturas puntuales (memoria) ── */
.readout { display: flex; flex-wrap: wrap; gap: 0 1.8rem; margin: 0; }
.readout-item { display: flex; flex-direction: column; gap: 0.15rem; }
.readout dt {
  font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: 0.12em;
  color: var(--text-muted);
}
.readout dd {
  margin: 0;
  font-family: var(--font-mono); font-size: var(--fs-lg); font-weight: 500;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.readout dd small { margin-left: 0.15em; font-size: 0.7em; color: var(--text-muted); }
/* Las unidades de varias letras necesitan más aire que un "%". */
.readout dd small.unit--wide { margin-left: 0.35em; }

/* ── Filas por entidad (montajes, interfaces, procesos) ── */
.rows { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.3rem; }
.row {
  display: flex; align-items: center; gap: 0.6rem;
  padding: 0.3rem 0.5rem; border-radius: 6px;
  background: var(--surface-2);
  font-size: var(--fs-sm);
}
.row-name {
  flex: 1 1 0; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: var(--font-mono); color: var(--text-dim);
}
.row-value {
  flex-shrink: 0;
  font-family: var(--font-mono); color: var(--text); font-variant-numeric: tabular-nums;
}
.row-value small { color: var(--text-muted); }
.row-pid { flex-shrink: 0; font-family: var(--font-mono); font-size: var(--fs-xs); color: var(--text-muted); }
.row-note { flex-shrink: 0; font-size: var(--fs-xs); color: var(--text-muted); }
.row-note--bad { color: var(--danger); }

.row--disk .row-name { flex: 0 1 8rem; }
.row--net .row-value { min-width: 5.5rem; text-align: right; }

.bar {
  flex: 1 1 0; min-width: 3rem; height: 6px;
  border-radius: 999px; background: var(--surface-3); overflow: hidden;
}
.bar-fill {
  display: block; height: 100%; background: var(--accent); border-radius: inherit;
  transition: width 0.5s cubic-bezier(0.22, 1, 0.36, 1), background-color 0.3s ease;
}
.bar--hot .bar-fill { background: var(--danger); }

/* ── Núcleos ──
   Viven dentro de la sección "Procesos", a ancho completo, justo debajo de
   su cabecera y antes de las columnas por CPU/memoria: son el contexto
   inmediato de esos rankings, no una sección aparte.
   Antes tan pequeños (8×26px) que la sección quedaba enana junto al resto de
   monitores; se agrandan a un tamaño comparable a las barras de disco. El
   relleno transiciona en vez de saltar entre heartbeats. */
.cores-block { margin-bottom: 0.9rem; }
.cores { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 4px; }
.core {
  display: flex; align-items: flex-end;
  width: 14px; height: 52px;
  border-radius: 3px; background: var(--surface-3); overflow: hidden;
}
.core-fill {
  width: 100%; background: var(--accent-bright); border-radius: inherit;
  transition: height 0.5s cubic-bezier(0.22, 1, 0.36, 1), background-color 0.3s ease;
}
.core--hot .core-fill { background: var(--danger); }

/* ── Procesos ── */
.proc-cols { display: flex; flex-wrap: wrap; gap: 0.9rem; }
.proc-col { flex: 1 1 14rem; min-width: 0; }
.proc-head {
  margin: 0 0 0.35rem;
  font-size: var(--fs-xs); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted);
}

/* Las cards de proceso cambian de orden en cada heartbeat según quién
   consuma más CPU/memoria; TransitionGroup anima ese reordenamiento (FLIP)
   en vez de que las filas salten de sitio de golpe.
   A propósito NO se usa `position: absolute` en `-leave-active` (el truco
   habitual para que una fila saliente no desplace al resto durante su
   fundido): con esa variante, al forzar reordenamientos rápidos con un
   mismo pid saliendo y volviendo a entrar al top-N, aparecían filas
   atascadas con opacidad 0 que nunca se retiraban del DOM. No se pudo
   aislar con certeza si la causa era la combinación de `transform`
   compartido entre `-move` y `-leave-active`, o una limitación del propio
   entorno de verificación (el pintado no llegó a confirmarse ahí). Se
   mantiene esta versión, más simple y sin ese riesgo, por precaución: es
   además la receta estándar de Vue para listas. El coste es un salto de
   layout mínimo mientras una fila se desvanece, imperceptible con filas de
   una sola línea. */
.proc-row-move {
  transition: transform 0.5s cubic-bezier(0.22, 1, 0.36, 1);
}
.proc-row-enter-active,
.proc-row-leave-active {
  transition: opacity 0.3s ease;
}
.proc-row-enter-from,
.proc-row-leave-to {
  opacity: 0;
}

/* ── Anomalías ── */
.anomalies { position: relative; list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }

/* Al borrar, la tarjeta se saca del flujo (`position: absolute`) para que el
   resto reacomode con `.anomaly-row-move` mientras ella se desvanece hacia
   la derecha en su sitio. A diferencia de `.proc-row-*` (que a propósito NO
   usa `position: absolute` por el bug de churn rápido documentado ahí
   arriba), aquí no hay reordenamiento continuo — solo un borrado puntual —
   así que la técnica estándar de Vue es segura. */
.anomaly-row-move {
  transition: transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
}
.anomaly-row-enter-active {
  transition: opacity 0.3s ease;
}
.anomaly-row-leave-active {
  transition: opacity 0.35s ease, transform 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  position: absolute;
  width: 100%;
}
.anomaly-row-enter-from {
  opacity: 0;
}
.anomaly-row-leave-to {
  opacity: 0;
  transform: translateX(28px);
}

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

.anomaly-reading { display: flex; flex-direction: column; margin: 0.4rem 0 0; }
.reading-value {
  font-family: var(--font-mono); font-size: var(--fs-xl); font-weight: 600;
  color: var(--text); font-variant-numeric: tabular-nums;
  margin: -0rem 0 -0.7rem 0;
}
.reading-ctx { font-size: var(--fs-sm); color: var(--text-muted); }
.anomaly-time { margin: 0.3rem 0 0; font-size: var(--fs-sm); color: var(--text-muted); }

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
.btn-sm--danger { border-color: var(--danger-dim); color: var(--danger); }
.btn-sm--danger:hover { background: var(--danger-dim); border-color: var(--danger); color: var(--danger); }

.btn-sm:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
</style>
