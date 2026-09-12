<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>Análisis del inventario</h3>
            <button class="close-btn" @click="$emit('close')">&times;</button>
          </div>

          <div class="modal-body">
            <p v-if="!analysis || !analysis.scanId" class="state-msg">
              Este activo aún no se ha analizado.
            </p>

            <template v-else>
              <div class="summary-head">
                <span class="scan-status" :class="analysis.status">{{ STATUS_LABEL[analysis.status] || 'Desconocido' }}</span>
                <span class="scan-date">{{ fmtDate(analysis.finishedAt || analysis.startedAt) }}</span>
              </div>

              <p v-if="isRunning" class="state-msg">
                Analizando el software instalado… el resumen se actualizará solo al terminar.
              </p>

              <template v-else>
                <div class="totals">
                  <div class="total">
                    <span class="total-value">{{ analysis.vulnerableCount ?? 0 }}</span>
                    <span class="total-label">con vulnerabilidad conocida</span>
                  </div>
                  <div class="total">
                    <span class="total-value">{{ analysis.confirmedCount ?? 0 }}</span>
                    <span class="total-label">comprobados</span>
                  </div>
                  <div class="total">
                    <span class="total-value">{{ analysis.totalFindings ?? 0 }}</span>
                    <span class="total-label">hallazgos en total</span>
                  </div>
                </div>

                <p v-if="!analysis.totalFindings" class="state-msg state-msg--clean">
                  Ningún hallazgo. El software instalado está limpio.
                </p>

                <!-- Solo cuando el matcher no pudo identificar parte del inventario. -->
                <p v-else-if="analysis.unresolvedCount" class="coverage-note">
                  <strong>Nota de cobertura:</strong> {{ analysis.unresolvedCount }} de los
                  {{ analysis.packageCount }} paquetes inventariados no se pudieron identificar contra el
                  catálogo de vulnerabilidades, así que no se comprobaron. El resto sí se comprobó — su
                  ausencia de hallazgos es una verificación real.
                </p>

                <ul v-else class="prio-list">
                  <li v-for="lvl in LADDER" :key="lvl" v-show="byPriority[lvl]" class="prio-row">
                    <span class="prio-chip" :class="lvl.toLowerCase()">{{ PRIO_LABEL[lvl] }}</span>
                    <span class="prio-bar">
                      <span class="prio-fill" :class="lvl.toLowerCase()" :style="{ width: barWidth(byPriority[lvl]) }"></span>
                    </span>
                    <span class="prio-count mono">{{ byPriority[lvl] }}</span>
                  </li>
                </ul>

                <!-- La exposición es siempre "privada" en un análisis de
                     inventario: mirar los paquetes instalados no dice nada de
                     lo que el host expone a la red. Conviene decirlo, para que
                     nadie lea estas prioridades como una foto completa. -->
                <p class="scope-note">
                  Solo software instalado. La superficie expuesta a la red (puertos, TLS, rutas)
                  se analiza desde Themis, con un escaneo propio.
                </p>
              </template>
            </template>
          </div>

          <div class="modal-footer">
            <button type="button" class="btn-ghost" @click="$emit('close')">Cerrar</button>
            <button v-if="analysis && analysis.scanId" type="button" class="btn-primary" @click="$emit('open-in-themis')">
              Ver desglose en Themis
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  analysis: { type: Object, default: null },
})
defineEmits(['close', 'open-in-themis'])

// Misma escala que LybraResults.vue, para que un hallazgo se lea igual en
// los dos paneles.
const LADDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const PRIO_LABEL = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja', INFO: 'Info' }
const STATUS_LABEL = { pending: 'Pendiente', running: 'En curso', finished: 'Terminado', failed: 'Fallido' }

const isRunning = computed(() => ['pending', 'running'].includes(props.analysis?.status))
const byPriority = computed(() => props.analysis?.byPriority || {})

/** Barra proporcional al nivel más numeroso, no al total: con 1 crítica y 200
 *  informativas, escalar sobre el total dejaría la crítica invisible. */
function barWidth(count) {
  const max = Math.max(...Object.values(byPriority.value), 1)
  return `${Math.max((count / max) * 100, 6)}%`
}

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 520px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }

.state-msg { font-size: var(--fs-md); color: var(--text-muted); margin: 0.4rem 0; }
.state-msg--clean { color: var(--success); }

.summary-head { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.9rem; }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.scan-status { font-size: var(--fs-md); font-weight: 600; padding: 0.12rem 0.45rem; border-radius: 5px; }
.scan-status.finished { color: var(--success); background: var(--success-dim); }
.scan-status.running, .scan-status.pending { color: var(--info); background: var(--info-dim); }
.scan-status.failed { color: var(--danger); background: var(--danger-dim); }
.scan-date { margin-left: auto; font-size: var(--fs-md); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }

.totals { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-bottom: 0.9rem; }
.total { display: flex; flex-direction: column; align-items: center; gap: 0.15rem; padding: 0.6rem 0.4rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; }
.total-value { font-size: var(--fs-2xl, 1.4rem); font-weight: 700; color: var(--text); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.total-label { font-size: var(--fs-sm); color: var(--text-muted); text-align: center; }

.prio-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.35rem; }
.prio-row { display: flex; align-items: center; gap: 0.5rem; }
.prio-chip { flex-shrink: 0; min-width: 58px; text-align: center; font-size: var(--fs-md); font-weight: 700; padding: 0.12rem 0.4rem; border-radius: 5px; }
.prio-bar { flex: 1; height: 7px; background: var(--surface-2); border-radius: 4px; overflow: hidden; }
.prio-fill { display: block; height: 100%; border-radius: 4px; }
.prio-count { flex-shrink: 0; min-width: 2ch; text-align: right; font-size: var(--fs-md); color: var(--text-dim); }

/* Escala de severidad compartida con LybraResults.vue */
.critical { color: var(--danger); background: var(--danger-dim); }
.high     { color: var(--warn);   background: var(--warn-dim); }
.medium   { color: var(--info);   background: var(--info-dim); }
.low      { color: var(--success);background: var(--success-dim); }
.info     { color: var(--text-muted); background: var(--surface-2); }
.prio-fill.critical { background: var(--danger); }
.prio-fill.high     { background: var(--warn); }
.prio-fill.medium   { background: var(--info); }
.prio-fill.low      { background: var(--success); }
.prio-fill.info     { background: var(--text-muted); }

.scope-note { margin: 0.9rem 0 0; font-size: var(--fs-sm); line-height: 1.45; color: var(--text-muted); border-left: 2px solid var(--border-solid); padding-left: 0.6rem; }
.coverage-note { margin: 0 0 0.6rem; padding: 0.55rem 0.7rem; font-size: var(--fs-md); line-height: 1.45; color: var(--warn); background: var(--warn-dim); border: 1px dashed var(--warn); border-radius: 7px; }

.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0.85rem 1.1rem; border-top: 1px solid var(--border); }
.btn-ghost { background: none; border: 1px solid var(--border-solid); color: var(--text-dim); padding: 0.45rem 0.9rem; border-radius: 6px; cursor: pointer; }
.btn-ghost:hover { border-color: var(--accent); color: var(--text); }
.btn-primary { display: inline-flex; align-items: center; gap: 0.35rem; background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); padding: 0.45rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
.btn-primary:hover { background: var(--accent-bright); }
.btn-primary svg { width: 13px; height: 13px; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
@media (prefers-reduced-motion: reduce) {
  .modal-enter-active, .modal-leave-active { transition: none; }
}
</style>
