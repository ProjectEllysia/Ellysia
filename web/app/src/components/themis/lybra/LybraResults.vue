<template>
  <div class="results-wrap">
    <div class="results-toolbar">
      <span class="toolbar-title">Veredictos de Lybra</span>
      <button class="btn-refresh" :disabled="loading" @click="$emit('refresh')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: loading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        Actualizar
      </button>
    </div>

    <Transition name="fade-swap" mode="out-in">
      <div v-if="loading && !scans.length" key="loading" class="empty-state">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        <span>Cargando…</span>
      </div>
      <div v-else-if="!scans.length" key="empty" class="empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M12 3v18M7 21h10M5 7h14M5 7l-2.5 5a3 3 0 0 0 5 0L5 7zM19 7l-2.5 5a3 3 0 0 0 5 0L19 7z"/></svg>
        <span>El motor aún no ha emitido ningún veredicto. ¡Lanza el primero!</span>
      </div>

      <div v-else key="list" class="scan-list">
        <article v-for="scan in scans" :key="scan.id" class="scan-card" :class="{ open: expanded.has(scan.id) }">
          <!-- Cabecera de la tarjeta -->
          <button class="scan-head" @click="toggle(scan.id)">
            <span class="chevron" :class="{ rot: expanded.has(scan.id) }" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
            </span>
            <span class="scan-id mono">#{{ scan.id }}</span>
            <span class="scan-target">{{ scan.target }}</span>
            <StatusBadge :status="scan.status" />
            <span v-if="scan.exposure" class="exposure" :class="scan.exposure"
              :title="scan.exposure === 'public' ? 'IP pública — la prioridad se ajusta al alza' : 'LAN privada — la prioridad se modera'">
              {{ scan.exposure === 'public' ? 'Pública' : 'Privada' }}
            </span>
            <span v-if="scan.deep" class="deep-badge" title="Corroborado con escáneres externos">⚖ Corroborado</span>

            <!-- Resumen de prioridades -->
            <span class="prio-summary">
              <span v-for="lvl in LADDER" :key="lvl"
                v-show="summary(scan)[lvl]" class="prio-pill" :class="lvl.toLowerCase()"
                :title="`${summary(scan)[lvl]} ${PRIO_LABEL[lvl]}`">
                {{ summary(scan)[lvl] }}
              </span>
              <span v-if="scan.status === 'finished' && !scan.totalFindings" class="prio-clean">Sin hallazgos</span>
            </span>

            <span class="scan-date">{{ fmtDate(scan.finishedAt || scan.startedAt) }}</span>
          </button>

          <!-- Cuerpo expandible -->
          <Transition name="expand">
            <div v-if="expanded.has(scan.id)" class="scan-body">
              <div v-if="scan.status === 'running' || scan.status === 'pending'" class="body-pending">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                <span>El motor está pesando las pruebas…</span>
              </div>
              <div v-else-if="scan.status === 'failed'" class="body-failed">
                El escaneo falló. No se pudo emitir un veredicto.
              </div>
              <div v-else-if="!(scan.findings || []).length" class="body-clean">
                Ningún hallazgo. La superficie analizada está limpia.
              </div>

              <ul v-else class="findings">
                <li v-for="f in sortedFindings(scan)" :key="f.id" class="finding" :class="{ potential: !f.confirmed }">
                  <span class="f-prio" :class="(f.priority || 'INFO').toLowerCase()">{{ PRIO_LABEL[f.priority] || f.priority }}</span>
                  <div class="f-main">
                    <div class="f-title-row">
                      <span class="f-conf" :class="f.confirmed ? 'confirmed' : 'hypothesis'"
                        :title="f.confirmed ? `Comprobado activamente (QoD ${f.qod})` : `Deducido por versión (QoD ${f.qod}) — potencial, sin confirmar`">
                        {{ f.confirmed ? 'Comprobado' : 'Potencial' }}
                      </span>
                      <span class="f-title">{{ f.title }}</span>
                    </div>
                    <div class="f-meta">
                      <span v-if="f.port" class="f-tag mono">{{ f.service || 'svc' }}:{{ f.port }}</span>
                      <span v-for="cve in (f.cveIds || [])" :key="cve" class="f-tag cve">{{ cve }}</span>
                      <span v-if="f.inKev" class="f-tag kev" title="En la lista CISA de vulnerabilidades explotadas activamente">KEV · explotada</span>
                      <span v-if="f.epssScore != null" class="f-tag epss" :title="`Probabilidad de explotación en 30 días (EPSS)`">EPSS {{ Math.round(f.epssScore * 100) }}%</span>
                      <span v-if="f.cvssScore != null" class="f-tag cvss">CVSS {{ f.cvssScore }}</span>
                      <span v-if="f.state && f.state !== 'open'" class="f-tag state" :class="f.state">{{ STATE_LABEL[f.state] || f.state }}</span>
                      <span v-if="f.source && f.source !== 'lybra'" class="f-tag src" :title="`Corroborado por ${f.source}`">+{{ f.source }}</span>
                    </div>
                  </div>
                </li>
              </ul>

              <div v-if="scan.status === 'finished' && scan.targetAuthorized === false" class="body-unauth-hint">
                Objetivo no autorizado: el fingerprinting propio y las comprobaciones activas de Lybra no se
                ejecutaron sobre '{{ scan.target }}'. Autorízalo en el panel de lanzamiento para un análisis más completo.
              </div>

              <div class="body-actions">
                <button class="btn-del" @click="$emit('delete', scan.id)">Eliminar escaneo</button>
              </div>
            </div>
          </Transition>
        </article>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import StatusBadge from '@/components/themis/StatusBadge.vue'

defineProps({
  scans: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
})
defineEmits(['refresh', 'delete'])

const LADDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const PRIO_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const PRIO_LABEL = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja', INFO: 'Info' }
const STATE_LABEL = { fixed: 'Corregido', regressed: 'Regresado', accepted: 'Aceptado' }

const expanded = ref(new Set())
function toggle(id) {
  const s = new Set(expanded.value)
  s.has(id) ? s.delete(id) : s.add(id)
  expanded.value = s
}

/** Cuenta hallazgos por nivel de prioridad para el resumen de la cabecera. */
function summary(scan) {
  const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of scan.findings || []) out[f.priority] = (out[f.priority] || 0) + 1
  return out
}

/** Ordena los hallazgos por prioridad (crítico primero), luego confirmados antes. */
function sortedFindings(scan) {
  return [...(scan.findings || [])].sort((a, b) => {
    const pa = PRIO_RANK[a.priority] ?? 9, pb = PRIO_RANK[b.priority] ?? 9
    if (pa !== pb) return pa - pb
    return (b.confirmed === true) - (a.confirmed === true)
  })
}

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}
</script>

<style scoped>
.results-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.results-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); }
.toolbar-title { font-family: var(--font-display); font-weight: 600; font-size: 0.9rem; color: var(--text); }
.btn-refresh { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.7rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text-dim); font-size: 0.76rem; cursor: pointer; transition: all 0.2s; }
.btn-refresh:hover:not(:disabled) { border-color: var(--accent); color: var(--text); }
.btn-refresh svg { width: 12px; height: 12px; }
.spin { animation: seq-spin 0.8s linear infinite; }

.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.6rem; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.85rem; text-align: center; }
.empty-state svg { color: var(--text-muted); opacity: 0.7; }

.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.2s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

/* ── Tarjeta de escaneo ── */
.scan-list { display: flex; flex-direction: column; }
.scan-card { border-bottom: 1px solid var(--border); }
.scan-card:last-child { border-bottom: none; }
.scan-card.open { background: var(--surface-2); }

.scan-head {
  width: 100%; display: flex; align-items: center; gap: 0.65rem;
  padding: 0.7rem 1rem; background: none; border: none; cursor: pointer; text-align: left;
  transition: background 0.15s;
}
.scan-head:hover { background: var(--surface-2); }
.chevron { display: grid; place-items: center; color: var(--text-muted); transition: transform 0.2s; }
.chevron svg { width: 14px; height: 14px; }
.chevron.rot { transform: rotate(90deg); }
.scan-id { font-size: 0.78rem; color: var(--text-muted); flex-shrink: 0; }
.scan-target { font-size: 0.86rem; color: var(--text); font-weight: 500; }
.exposure { font-size: 0.68rem; padding: 0.12rem 0.45rem; border-radius: 5px; font-weight: 600; flex-shrink: 0; }
.exposure.public { color: var(--danger); background: var(--danger-dim); }
.exposure.private { color: var(--info); background: var(--info-dim); }
.deep-badge { font-size: 0.68rem; padding: 0.12rem 0.45rem; border-radius: 5px; color: var(--accent-bright); background: var(--accent-dim); flex-shrink: 0; }

.prio-summary { display: flex; align-items: center; gap: 0.25rem; margin-left: auto; flex-shrink: 0; }
.prio-pill { min-width: 20px; text-align: center; font-size: 0.72rem; font-weight: 700; padding: 0.1rem 0.35rem; border-radius: 5px; font-family: var(--font-mono); }
.prio-clean { font-size: 0.72rem; color: var(--success); }
.scan-date { font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); flex-shrink: 0; white-space: nowrap; }

/* Escala de severidad (compartida por pills de resumen y chips de finding) */
.critical { color: var(--danger); background: var(--danger-dim); }
.high     { color: var(--warn);   background: var(--warn-dim); }
.medium   { color: var(--info);   background: var(--info-dim); }
.low      { color: var(--success);background: var(--success-dim); }
.info     { color: var(--text-muted); background: var(--surface); }

/* ── Cuerpo ── */
.expand-enter-active, .expand-leave-active { transition: opacity 0.2s ease; overflow: hidden; }
.expand-enter-from, .expand-leave-to { opacity: 0; }
.scan-body { padding: 0.3rem 1rem 0.9rem 2.4rem; }
.body-pending, .body-failed, .body-clean { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 0; font-size: 0.82rem; }
.body-pending { color: var(--text-dim); }
.body-failed { color: var(--danger); }
.body-clean { color: var(--success); }

.findings { list-style: none; display: flex; flex-direction: column; gap: 0.35rem; margin: 0.3rem 0 0; }
.finding {
  display: flex; align-items: flex-start; gap: 0.6rem;
  padding: 0.55rem 0.7rem; background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--border-solid); border-radius: 7px;
}
.finding.potential { border-style: dashed; opacity: 0.92; }
.f-prio { flex-shrink: 0; font-size: 0.66rem; font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase; padding: 0.15rem 0.4rem; border-radius: 5px; min-width: 52px; text-align: center; }
.f-main { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; flex: 1; }
.f-title-row { display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.f-conf { font-size: 0.64rem; font-weight: 700; padding: 0.1rem 0.4rem; border-radius: 4px; flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.03em; }
.f-conf.confirmed { color: var(--success); background: var(--success-dim); }
.f-conf.hypothesis { color: var(--text-muted); background: var(--surface-2); border: 1px dashed var(--border-solid); }
.f-title { font-size: 0.83rem; color: var(--text); }
.f-meta { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }
.f-tag { font-size: 0.68rem; font-family: var(--font-mono); padding: 0.1rem 0.4rem; border-radius: 4px; background: var(--surface-2); color: var(--text-dim); }
.f-tag.cve { color: var(--accent-bright); background: var(--accent-dim); }
.f-tag.kev { color: var(--danger); background: var(--danger-dim); font-weight: 700; }
.f-tag.epss { color: var(--warn); background: var(--warn-dim); }
.f-tag.state.fixed { color: var(--success); background: var(--success-dim); }
.f-tag.state.regressed { color: var(--warn); background: var(--warn-dim); }
.f-tag.state.accepted { color: var(--text-muted); }
.f-tag.src { color: var(--info); background: var(--info-dim); }

.body-unauth-hint { margin-top: 0.6rem; padding: 0.55rem 0.7rem; font-size: 0.76rem; line-height: 1.4; color: var(--warn); background: var(--warn-dim); border: 1px dashed var(--warn); border-radius: 7px; }

.body-actions { margin-top: 0.7rem; display: flex; justify-content: flex-end; }
.btn-del { font-size: 0.72rem; color: var(--danger); background: none; border: 1px solid var(--danger-dim); padding: 0.3rem 0.7rem; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
.btn-del:hover { background: var(--danger-dim); }

@media (max-width: 700px) {
  .scan-head { flex-wrap: wrap; }
  .prio-summary { margin-left: 0; }
  .scan-body { padding-left: 1rem; }
}
@media (prefers-reduced-motion: reduce) {
  .spin { animation: none !important; }
  .chevron, .expand-enter-active, .expand-leave-active, .fade-swap-enter-active, .fade-swap-leave-active { transition: none !important; }
}
</style>
