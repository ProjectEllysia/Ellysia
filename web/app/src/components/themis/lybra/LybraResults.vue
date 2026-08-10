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

              <template v-else>
                <!-- Acordeón anidado, colapsado por defecto: la cabecera de la tarjeta ya
                     resume la severidad (pills de arriba), así que abrir un escaneo para
                     generar su PDF o gestionar sus documentos no obliga a desplazarse
                     primero por una lista de hallazgos que puede ser muy larga. -->
                <button type="button" class="findings-toggle" @click="toggleFindings(scan.id)">
                  <span class="chevron findings-chevron" :class="{ rot: findingsOpen.has(scan.id) }" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                  </span>
                  {{ findingsOpen.has(scan.id) ? 'Ocultar hallazgos' : 'Mostrar hallazgos' }}
                  <span class="findings-count">{{ sortedFindings(scan).length }}</span>
                </button>

                <Transition name="findings-panel">
                <div v-if="findingsOpen.has(scan.id)" class="findings-panel">
                  <TransitionGroup tag="ul" name="finding-item" class="findings">
                    <li v-for="(f, idx) in visibleFindings(scan)" :key="f.id" class="finding" :class="{ potential: !f.confirmed }"
                      :style="{ '--enter-delay': (idx % FINDINGS_PAGE) * 22 + 'ms' }">
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
                  </TransitionGroup>

                  <button v-if="visibleFindings(scan).length < sortedFindings(scan).length" type="button" class="load-more-findings" @click="showMoreFindings(scan.id)">
                    Ver más ({{ visibleFindings(scan).length }} de {{ sortedFindings(scan).length }})
                  </button>
                </div>
                </Transition>
              </template>

              <!-- No se muestra para un escaneo de agente (Fase I, `assetId`): ahí el
                   fingerprinting y las comprobaciones activas están desactivados
                   siempre, por diseño (modo payload) — autorizar el objetivo no
                   cambiaría nada, así que sugerirlo sería un consejo sin efecto. -->
              <div v-if="scan.status === 'finished' && scan.targetAuthorized === false && !scan.assetId" class="body-unauth-hint">
                Objetivo no autorizado: el fingerprinting propio y las comprobaciones activas de Lybra no se
                ejecutaron sobre '{{ scan.target }}'. Autorízalo en el panel de lanzamiento para un análisis más completo.
              </div>

              <!-- Solo cuando hay paquetes que el matcher no pudo ni identificar. -->
              <div v-if="scan.status === 'finished' && coverageGap(scan)" class="body-coverage-hint">
                Nota de cobertura: {{ coverageGap(scan).unresolved }} de los {{ coverageGap(scan).packages }}
                paquetes inventariados no se pudieron identificar contra el catálogo de vulnerabilidades,
                así que no se comprobaron. El resto sí se comprobó — su ausencia de hallazgos es una
                verificación real.
              </div>

              <div v-if="scan.status === 'finished'" class="doc-section">
                <div class="doc-head">
                  <span class="doc-title">Documentos <span class="doc-count">{{ docsFor(scan.id).length }}</span></span>
                  <button class="doc-refresh-btn" @click="$emit('load-docs', scan.id)" :disabled="docsLoading(scan.id)" title="Refrescar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: docsLoading(scan.id) }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                  </button>
                </div>

                <div v-if="docsLoading(scan.id) && !docsFor(scan.id).length" class="doc-empty">Cargando documentos…</div>
                <div v-else-if="!docsFor(scan.id).length" class="doc-empty">Sin documentos generados</div>
                <div v-else class="doc-list">
                  <div v-for="doc in docsFor(scan.id)" :key="doc.documentId" class="doc-item">
                    <div class="doc-left">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="doc-icon"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                      <span class="doc-name">PDF Lybra <span v-if="doc.isAiGenerated" class="doc-ai-pill">IA</span></span>
                      <span v-if="doc.createdAt" class="doc-date">{{ fmtDate(doc.createdAt) }}</span>
                    </div>
                    <div class="doc-right">
                      <template v-if="doc.status === 'done'">
                        <button class="doc-icon-btn" @click="$emit('download-doc', doc.documentId)" title="Descargar">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        </button>
                        <button class="doc-icon-btn danger" @click="$emit('delete-doc', scan.id, doc.documentId)" title="Eliminar">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                        </button>
                      </template>
                      <span v-else-if="doc.status === 'running'" class="doc-status running">Generando…</span>
                      <span v-else-if="doc.status === 'pending'" class="doc-status pending">Pendiente</span>
                      <span v-else-if="doc.status === 'error'" class="doc-status error">Error</span>
                    </div>
                  </div>
                </div>

                <div class="doc-gen-bar">
                  <label class="doc-checkbox"><input type="checkbox" v-model="aiFlags[scan.id]" /><span>Análisis IA</span></label>
                  <button class="doc-gen-btn" @click="$emit('generate-pdf', scan.id, !!aiFlags[scan.id])">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                    Generar PDF
                  </button>
                </div>
              </div>

              <div class="body-actions">
                <button class="btn-del" @click="$emit('delete', scan.id)">Eliminar escaneo</button>
              </div>
            </div>
          </Transition>
        </article>

        <button v-if="scans.length < totalCount" class="load-more" :disabled="loading" @click="$emit('load-more')">
          {{ loading ? 'Cargando…' : `Ver más (${scans.length} de ${totalCount})` }}
        </button>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import StatusBadge from '@/components/themis/StatusBadge.vue'

const props = defineProps({
  scans: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  totalCount: { type: Number, default: 0 },
  docsByScan: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['refresh', 'delete', 'load-docs', 'generate-pdf', 'download-doc', 'delete-doc', 'load-more'])

const LADDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const PRIO_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const PRIO_LABEL = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja', INFO: 'Info' }
const STATE_LABEL = { fixed: 'Corregido', regressed: 'Regresado', accepted: 'Aceptado' }

/** Casilla "Análisis IA" del generador de PDF, por escaneo. */
const aiFlags = reactive({})

function docsFor(scanId) { return props.docsByScan[scanId]?.items || [] }
function docsLoading(scanId) { return !!props.docsByScan[scanId]?.loading }

const expanded = ref(new Set())
function toggle(id) {
  const s = new Set(expanded.value)
  if (s.has(id)) {
    s.delete(id)
  } else {
    s.add(id)
    if (!props.docsByScan[id]) emit('load-docs', id)
  }
  expanded.value = s
}

/** Acordeón anidado de hallazgos (colapsado por defecto) + "ver más" incremental. */
const FINDINGS_PAGE = 10
const findingsOpen = ref(new Set())
const findingsLimit = reactive({})

function toggleFindings(id) {
  const s = new Set(findingsOpen.value)
  if (s.has(id)) {
    s.delete(id)
    // Al comprimir, olvida cuánto se había revelado con "ver más": la
    // próxima vez que se abra empieza otra vez por la primera página.
    findingsLimit[id] = FINDINGS_PAGE
  } else {
    s.add(id)
    if (!findingsLimit[id]) findingsLimit[id] = FINDINGS_PAGE
  }
  findingsOpen.value = s
}

function visibleFindings(scan) {
  return sortedFindings(scan).slice(0, findingsLimit[scan.id] || FINDINGS_PAGE)
}

function showMoreFindings(id) {
  findingsLimit[id] = (findingsLimit[id] || FINDINGS_PAGE) + FINDINGS_PAGE
}

/** Cuenta hallazgos por nivel de prioridad para el resumen de la cabecera. */
function summary(scan) {
  const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of scan.findings || []) out[f.priority] = (out[f.priority] || 0) + 1
  return out
}

/**
 * Detecta un análisis de inventario (Fase I) con paquetes sin identificar.
 *
 * `cpeResolved` (Fase I-b, `Finding.cpe_resolved`) da el número exacto de
 * paquetes que el matcher no pudo ni resolver a un CPE — ya no es una
 * heurística sobre ausencia de detecciones, que mezclaba eso con "KB sin
 * sincronizar" o simplemente "comprobado y limpio".
 *
 * Devuelve `null` si no aplica (sin paquetes, o todos resueltos), o
 * `{ packages, unresolved }` cuando el aviso debe mostrarse.
 */
function coverageGap(scan) {
  const findings = scan.findings || []
  const packages = findings.filter(f => f.category === 'installed_package').length
  const unresolved = findings.filter(f => f.category === 'installed_package' && f.cpeResolved === false).length
  if (!packages || !unresolved) return null
  return { packages, unresolved }
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
.toolbar-title { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-weight: 600; font-size: var(--fs-xl); color: var(--text); }
.btn-refresh { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.7rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text-dim); font-size: var(--fs-md); cursor: pointer; transition: all 0.2s; }
.btn-refresh:hover:not(:disabled) { border-color: var(--accent); color: var(--text); }
.btn-refresh svg { width: 12px; height: 12px; }
.spin { animation: seq-spin 0.8s linear infinite; }

.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.6rem; padding: 2.5rem 1rem; color: var(--text-muted); font-size: var(--fs-lg); text-align: center; }
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
.scan-id { font-size: var(--fs-lg); color: var(--text-muted); flex-shrink: 0; }
.scan-target { font-size: var(--fs-lg); color: var(--text); font-weight: 500; }
.exposure { font-size: var(--fs-md); padding: 0.12rem 0.45rem; border-radius: 5px; font-weight: 600; flex-shrink: 0; }
.exposure.public { color: var(--danger); background: var(--danger-dim); }
.exposure.private { color: var(--info); background: var(--info-dim); }
.deep-badge { font-size: var(--fs-md); padding: 0.12rem 0.45rem; border-radius: 5px; color: var(--accent-bright); background: var(--accent-dim); flex-shrink: 0; }

.prio-summary { display: flex; align-items: center; gap: 0.25rem; margin-left: auto; flex-shrink: 0; }
.prio-pill { min-width: 20px; text-align: center; font-size: var(--fs-md); font-weight: 700; padding: 0.1rem 0.35rem; border-radius: 5px; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.prio-clean { font-size: var(--fs-md); color: var(--success); }
.scan-date { font-size: var(--fs-md); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); flex-shrink: 0; white-space: nowrap; }

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
.body-pending, .body-failed, .body-clean { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 0; font-size: var(--fs-lg); }
.body-pending { color: var(--text-dim); }
.body-failed { color: var(--danger); }
.body-clean { color: var(--success); }

/* Acordeón anidado de hallazgos: la sección entera se desliza al abrir/
   cerrar, y cada fila entra con un ligero cascadeo (retardo creciente por
   índice, --enter-delay) en vez de aparecer toda de golpe. */
.findings-panel-enter-active, .findings-panel-leave-active { transition: opacity 0.2s ease, transform 0.2s ease; overflow: hidden; }
.findings-panel-enter-from, .findings-panel-leave-to { opacity: 0; transform: translateY(-6px); }

.findings { position: relative; }
.finding-item-enter-active {
  transition: opacity 0.32s ease var(--enter-delay, 0ms), transform 0.32s ease var(--enter-delay, 0ms);
}
.finding-item-enter-from { opacity: 0; transform: translateY(-8px); }
.finding-item-leave-active { transition: opacity 0.15s ease; position: absolute; width: 100%; }
.finding-item-leave-to { opacity: 0; }
.finding-item-move { transition: transform 0.25s ease; }

.findings-toggle {
  display: inline-flex; align-items: center; gap: 0.4rem;
  padding: 0.4rem 0; margin-top: 0.2rem;
  background: none; border: none; cursor: pointer;
  font-size: var(--fs-md); font-weight: 600; color: var(--text-dim);
  transition: color 0.15s;
}
.findings-toggle:hover { color: var(--text); }
.findings-chevron { display: grid; place-items: center; color: var(--text-muted); transition: transform 0.2s; }
.findings-chevron svg { width: 12px; height: 12px; }
.findings-chevron.rot { transform: rotate(90deg); }
.findings-count { font-size: var(--fs-body); font-weight: 700; color: var(--text-muted); background: var(--surface-2); padding: 0.05rem 0.45rem; border-radius: 8px; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.load-more-findings {
  display: block; width: 100%; margin-top: 0.4rem; padding: 0.45rem;
  background: none; border: 1px dashed var(--border-solid); border-radius: 7px;
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 600; cursor: pointer;
  transition: all 0.15s;
}
.load-more-findings:hover { border-color: var(--accent); color: var(--text); background: var(--surface-2); }
.findings { list-style: none; display: flex; flex-direction: column; gap: 0.35rem; margin: 0.3rem 0 0; }
.finding {
  display: flex; align-items: flex-start; gap: 0.6rem;
  padding: 0.55rem 0.7rem; background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--border-solid); border-radius: 7px;
}
.finding.potential { border-style: dashed; opacity: 0.92; }
.f-prio { flex-shrink: 0; font-size: var(--fs-md); font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase; padding: 0.15rem 0.4rem; border-radius: 5px; min-width: 52px; text-align: center; }
.f-main { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; flex: 1; }
.f-title-row { display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.f-conf { font-size: var(--fs-body); font-weight: 700; padding: 0.1rem 0.4rem; border-radius: 4px; flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.03em; }
.f-conf.confirmed { color: var(--success); background: var(--success-dim); }
.f-conf.hypothesis { color: var(--text-muted); background: var(--surface-2); border: 1px dashed var(--border-solid); }
.f-title { font-size: var(--fs-lg); color: var(--text); }
.f-meta { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }
.f-tag { font-size: var(--fs-md); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); padding: 0.1rem 0.4rem; border-radius: 4px; background: var(--surface-2); color: var(--text-dim); }
.f-tag.cve { color: var(--accent-bright); background: var(--accent-dim); }
.f-tag.kev { color: var(--danger); background: var(--danger-dim); font-weight: 700; }
.f-tag.epss { color: var(--warn); background: var(--warn-dim); }
.f-tag.state.fixed { color: var(--success); background: var(--success-dim); }
.f-tag.state.regressed { color: var(--warn); background: var(--warn-dim); }
.f-tag.state.accepted { color: var(--text-muted); }
.f-tag.src { color: var(--info); background: var(--info-dim); }

.body-unauth-hint { margin-top: 0.6rem; padding: 0.55rem 0.7rem; font-size: var(--fs-md); line-height: 1.4; color: var(--warn); background: var(--warn-dim); border: 1px dashed var(--warn); border-radius: 7px; }
.body-coverage-hint { margin-top: 0.6rem; padding: 0.55rem 0.7rem; font-size: var(--fs-md); line-height: 1.4; color: var(--warn); background: var(--warn-dim); border: 1px dashed var(--warn); border-radius: 7px; }

/* ── Documentos PDF ── */
.doc-section { margin-top: 0.9rem; padding-top: 0.7rem; border-top: 1px solid var(--border); }
.doc-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }
.doc-title { font-size: var(--fs-lg); color: var(--text-dim); font-weight: 600; display: flex; align-items: center; gap: 0.35rem; }
.doc-count { font-size: var(--fs-body); font-weight: 500; color: var(--text-muted); background: var(--surface-2); padding: 1px 6px; border-radius: 8px; }
.doc-refresh-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 3px; border-radius: 5px; display: flex; }
.doc-refresh-btn:hover:not(:disabled) { color: var(--accent-bright); }
.doc-refresh-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.doc-refresh-btn svg { width: 12px; height: 12px; }
.doc-empty { font-size: var(--fs-md); color: var(--text-muted); padding: 0.5rem 0; }
.doc-list { display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 0.6rem; }
.doc-item { display: flex; align-items: center; justify-content: space-between; padding: 0.4rem 0.55rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }
.doc-item:hover { border-color: var(--accent); }
.doc-left { display: flex; align-items: center; gap: 0.4rem; min-width: 0; flex: 1; }
.doc-icon { width: 13px; height: 13px; color: var(--text-muted); flex-shrink: 0; }
.doc-name { font-size: var(--fs-md); color: var(--text); font-weight: 500; white-space: nowrap; }
.doc-ai-pill { font-size: var(--fs-body); color: var(--accent-bright); background: var(--accent-dim); padding: 1px 4px; border-radius: 3px; margin-left: 3px; font-weight: 700; }
.doc-date { font-size: var(--fs-md); color: var(--text-muted); white-space: nowrap; }
.doc-right { display: flex; gap: 0.2rem; align-items: center; flex-shrink: 0; }
.doc-icon-btn { width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 5px; color: var(--text-muted); cursor: pointer; transition: all 0.2s; }
.doc-icon-btn:hover { border-color: var(--accent); color: var(--accent-bright); }
.doc-icon-btn.danger:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }
.doc-icon-btn svg { width: 11px; height: 11px; }
.doc-status { font-size: var(--fs-body); padding: 2px 8px; border-radius: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; }
.doc-status.running { background: var(--info-dim); color: var(--info); }
.doc-status.pending { background: var(--warn-dim); color: var(--warn); }
.doc-status.error   { background: var(--danger-dim); color: var(--danger); }
.doc-gen-bar { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap; }
.doc-checkbox { display: flex; align-items: center; gap: 0.35rem; font-size: var(--fs-md); color: var(--text-dim); cursor: pointer; user-select: none; }
.doc-checkbox input[type="checkbox"] { appearance: none; -webkit-appearance: none; width: 14px; height: 14px; padding: 0; border: 1.5px solid var(--text-muted); border-radius: 3px; background: transparent; cursor: pointer; margin: 0; flex-shrink: 0; position: relative; }
.doc-checkbox input[type="checkbox"]:checked { background: var(--accent); border-color: var(--accent); }
.doc-checkbox input[type="checkbox"]:checked::after { content: ''; position: absolute; top: 1px; left: 2px; width: 3px; height: 6px; border: solid var(--on-accent); border-width: 0 1.5px 1.5px 0; transform: rotate(45deg); }
.doc-gen-btn { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.7rem; font-size: var(--fs-md); font-weight: 600; background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 6px; color: var(--accent-bright); cursor: pointer; transition: all 0.2s; }
.doc-gen-btn:hover { background: var(--accent); color: var(--on-accent); }
.doc-gen-btn svg { width: 12px; height: 12px; }

.body-actions { margin-top: 0.7rem; display: flex; justify-content: flex-end; }
.btn-del { font-size: var(--fs-md); color: var(--danger); background: none; border: 1px solid var(--danger-dim); padding: 0.3rem 0.7rem; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
.btn-del:hover { background: var(--danger-dim); }

.load-more {
  width: 100%; padding: 0.75rem; margin-top: -1px;
  background: none; border: none; border-top: 1px solid var(--border);
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 600; cursor: pointer;
  transition: background 0.15s, color 0.15s;
}
.load-more:hover:not(:disabled) { background: var(--surface-2); color: var(--text); }
.load-more:disabled { cursor: not-allowed; opacity: 0.6; }

@media (max-width: 700px) {
  .scan-head { flex-wrap: wrap; }
  .prio-summary { margin-left: 0; }
  .scan-body { padding-left: 1rem; }
}
@media (prefers-reduced-motion: reduce) {
  .spin { animation: none !important; }
  .chevron, .expand-enter-active, .expand-leave-active, .fade-swap-enter-active, .fade-swap-leave-active,
  .findings-panel-enter-active, .findings-panel-leave-active,
  .finding-item-enter-active, .finding-item-leave-active, .finding-item-move { transition: none !important; }
}
</style>
