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
      <div v-if="loading && !scans.length" key="loading" class="scan-list"
           aria-busy="true" aria-label="Cargando veredictos">
        <div v-for="n in SKELETON_ROWS" :key="n" class="scan-ghost" aria-hidden="true">
          <span class="skeleton skeleton--circle ghost-dot"></span>
          <span class="skeleton skeleton--line skeleton--w60"></span>
        </div>
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
            

            <!-- Resumen de prioridades -->
            <span class="prio-summary">
              <span v-for="lvl in LADDER" :key="lvl"
                v-show="summary(scan)[lvl]" class="prio-pill" :class="lvl.toLowerCase()"
                :title="`${summary(scan)[lvl]} ${PRIO_LABEL[lvl]}`">
                {{ summary(scan)[lvl] }}
              </span>
              <span v-if="scan.status === 'finished' && !scan.totalFindings && !scan.isPartial" class="prio-clean">Sin hallazgos</span>
              <span v-if="scan.isPartial" class="prio-partial"
                title="El descubrimiento se quedó sin tiempo: lo que se ve es cierto, pero no es toda la superficie">Parcial</span>
            </span>

            <span class="scan-date">{{ fmtDate(scan.finishedAt || scan.startedAt) }}</span>
          </button>

          <!-- Cuerpo expandible -->
          <Transition name="expand">
            <div v-if="expanded.has(scan.id)" class="scan-body">
              <!-- Un escaneo puede tardar minutos, y lo único que se veía en
                   todo ese rato era una frase con un reloj al lado. La barra no
                   finge saber cuánto queda —el porcentaje real vive en la cola y
                   no está expuesto por HTTP—: es indeterminada a propósito, y
                   dice lo único que aquí se puede afirmar, que sigue trabajando. -->
              <div v-if="scan.status === 'running' || scan.status === 'pending'"
                   class="state-panel state-panel--pending" aria-live="polite">
                <svg class="state-icon spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                  <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                </svg>
                <div class="state-text">
                  <p class="state-title">{{ scan.status === 'pending' ? 'En cola, a punto de empezar.' : 'El motor está pesando las pruebas…' }}</p>
                  <div class="state-progress" aria-hidden="true"><span></span></div>
                </div>
              </div>
              <!-- El fallo era una línea de texto suelta con la misma frase para
                   los cinco motivos posibles. Ahora ocupa el mismo recuadro que
                   el aviso de escaneo parcial de más abajo: son la misma clase
                   de mensaje —«esto no salió como debía, y esto es lo que pasa»—
                   y leerlos igual ahorra al usuario descifrar dos formatos. -->
              <div v-else-if="scan.status === 'failed'" class="state-panel state-panel--failed">
                <svg class="state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="7" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <div class="state-text">
                  <p class="state-title">{{ failureOf(scan).title }}</p>
                  <p class="state-hint">{{ failureOf(scan).hint }}</p>
                </div>
              </div>
              <div v-else-if="!scan.totalFindings && !scan.isPartial" class="body-clean">
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
                  <span class="findings-count">{{ scan.totalFindings }}</span>
                </button>

                <Transition name="findings-panel">
                <div v-if="findingsOpen.has(scan.id)" class="findings-panel">
                  <div v-if="groupsLoading(scan.id)" class="groups-loading">Cargando hallazgos…</div>
                  <div v-else-if="groupsError(scan.id)" class="groups-error">{{ groupsError(scan.id) }}</div>

                  <template v-else>
                    <!-- Dos secciones porque son dos clases de trabajo: subir un producto
                         de versión, y arreglar una configuración. Mezclarlas hacía que un
                         "falta la cabecera HSTS" pareciera un producto más del inventario. -->
                    <template v-for="section in sections(scan.id)" :key="section.key">
                      <p v-if="section.groups.length" class="group-section">{{ section.title }}</p>

                      <div v-for="group in section.groups" :key="section.key + groupKey(scan.id, group)" class="group">
                        <!-- La cabecera es el interruptor del grupo, y sigue visible al
                             plegarlo: lo que se esconde es la evidencia (los hallazgos
                             uno a uno), no la acción a tomar ni cuánto pesa. Así, con
                             todo plegado, el panel es un índice de trabajo pendiente. -->
                        <button type="button" class="group-head"
                          :aria-expanded="isGroupOpen(scan.id, group)"
                          @click="toggleGroup(scan.id, group)">
                          <span class="chevron group-chevron" :class="{ rot: isGroupOpen(scan.id, group) }" aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                          </span>
                          <span class="f-prio" :class="(group.priority || 'INFO').toLowerCase()">{{ PRIO_LABEL[group.priority] || group.priority }}</span>
                          <span class="group-label">{{ group.label }}</span>
                          <span v-if="group.port" class="f-tag mono">{{ group.service || 'svc' }}:{{ group.port }}</span>
                          <span class="group-count">{{ group.totalFindings }} {{ group.totalFindings === 1 ? 'hallazgo' : 'hallazgos' }}</span>
                        </button>

                        <div class="group-meta">
                          <span v-if="group.fixedVersion" class="f-tag fix" title="Actualizar hasta aquí cierra todo el grupo de una vez">
                            Corregido en {{ group.fixedVersion }} o superior
                          </span>
                          <span v-if="group.kevCveIds?.length" class="f-tag kev" title="En la lista CISA de vulnerabilidades explotadas activamente">
                            KEV · {{ group.kevCveIds.length }}
                          </span>
                          <span v-if="group.totalCves" class="f-tag cve">{{ group.totalCves }} CVE{{ group.totalCves === 1 ? '' : 's' }}</span>
                          <span v-if="group.maxCvss != null" class="f-tag cvss">CVSS máx. {{ group.maxCvss }}</span>
                          <span v-if="group.confirmedCount" class="f-tag conf">{{ group.confirmedCount }} comprobado{{ group.confirmedCount === 1 ? '' : 's' }}</span>
                        </div>

                        <Transition name="findings-panel">
                        <div v-if="isGroupOpen(scan.id, group)" class="group-body">
                        <TransitionGroup tag="ul" name="finding-item" class="findings">
                          <li v-for="(f, idx) in visibleGroupFindings(scan.id, group)" :key="f.id" class="finding" :class="{ potential: !f.confirmed }"
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
                                <span v-for="cve in (f.cveIds || [])" :key="cve" class="f-tag cve">{{ cve }}</span>
                                <span v-if="f.inKev" class="f-tag kev" title="En la lista CISA de vulnerabilidades explotadas activamente">KEV · explotada</span>
                                <span v-if="f.epssScore != null" class="f-tag epss" :title="`Probabilidad de explotación en 30 días (EPSS)`">EPSS {{ Math.round(f.epssScore * 100) }}%</span>
                                <span v-if="f.cvssScore != null" class="f-tag cvss">CVSS {{ f.cvssScore }}</span>
                                <span v-if="f.state && f.state !== 'open'" class="f-tag state" :class="f.state">{{ STATE_LABEL[f.state] || f.state }}</span>
                                <span v-if="f.source && f.source !== 'lybra'" class="f-tag src" :title="`Origen: ${f.source}`">+{{ f.source }}</span>
                              </div>

                              <!-- Desmentir un hallazgo y aceptar su riesgo son
                                   decisiones opuestas: la primera dice que el motor
                                   se equivocó, la segunda que el problema es real y
                                   se asume. Hasta L35 compartían casilla. -->
                              <div class="f-actions">
                                <template v-if="deciding === f.id">
                                  <input v-model="decisionReason" class="f-reason" type="text"
                                    :placeholder="decisionState === 'false_positive'
                                      ? '¿Por qué no es real? (p. ej. backport de Debian)'
                                      : '¿Por qué se asume? (p. ej. mitigado por el WAF)'"
                                    @keyup.enter="confirmDecision(scan.id)" />
                                  <button type="button" class="f-act primary" @click="confirmDecision(scan.id)">Confirmar</button>
                                  <button type="button" class="f-act" @click="cancelDecision">Cancelar</button>
                                </template>
                                <template v-else-if="f.state === 'accepted' || f.state === 'false_positive'">
                                  <span class="f-decided">{{ STATE_LABEL[f.state] }}<template v-if="f.stateReason">: {{ f.stateReason }}</template></span>
                                  <button type="button" class="f-act" @click="$emit('set-finding-state', scan.id, f.id, 'open', null)">Reabrir</button>
                                </template>
                                <template v-else>
                                  <button type="button" class="f-act" @click="startDecision(f.id, 'false_positive')">Desmentir</button>
                                  <button type="button" class="f-act" @click="startDecision(f.id, 'accepted')">Aceptar riesgo</button>
                                </template>
                              </div>
                            </div>
                          </li>
                        </TransitionGroup>

                        <button v-if="visibleGroupFindings(scan.id, group).length < group.findings.length" type="button"
                          class="load-more-findings" @click="showMoreFindings(groupKey(scan.id, group))">
                          Ver más ({{ visibleGroupFindings(scan.id, group).length }} de {{ group.findings.length }})
                        </button>
                        </div>
                        </Transition>
                      </div>
                    </template>
                  </template>
                </div>
                </Transition>
              </template>

              <!-- El descubrimiento no llegó a recorrer todo el objetivo. Va antes que
                   cualquier otra nota porque cambia cómo se leen todas las demás: la
                   ausencia de un hallazgo aquí no significa que no esté. -->
              <div v-if="scan.isPartial" class="body-partial-hint">
                Análisis incompleto: el descubrimiento de puertos agotó su tiempo antes de recorrer
                todo el objetivo. Lo que aparece es cierto, pero <strong>la ausencia de algo no
                significa que no esté</strong> — por eso este escaneo no ha dado por corregido ningún
                hallazgo anterior. Sube el tiempo límite o acota la lista de puertos para un análisis
                completo.
              </div>

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
                <!-- TransitionGroup: la tarjeta de un documento nuevo (recién generado) entra
                     con una animación en vez de aparecer de golpe, y el resto se desliza para
                     hacerle sitio. El estado (pendiente → generando → listo) es un cambio en el
                     mismo doc, no una entrada/salida de la lista, así que ese swap lo anima el
                     <Transition> interno de .doc-right, con key por estado. -->
                <TransitionGroup v-else tag="div" name="doc-item" class="doc-list">
                  <div v-for="doc in docsFor(scan.id)" :key="doc.documentId" class="doc-item">
                    <div class="doc-left">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="doc-icon"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                      <span class="doc-name">PDF Lybra <span v-if="doc.isAiGenerated" class="doc-ai-pill">IA</span></span>
                      <span v-if="doc.createdAt" class="doc-date">{{ fmtDate(doc.createdAt) }}</span>
                    </div>
                    <div class="doc-right">
                      <Transition name="fade-swap" mode="out-in">
                        <span v-if="doc.status === 'done'" key="done" class="doc-actions">
                          <button class="doc-icon-btn" @click="$emit('download-doc', doc.documentId)" title="Descargar">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                          </button>
                          <button class="doc-icon-btn danger" @click="$emit('delete-doc', scan.id, doc.documentId)" title="Eliminar">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                          </button>
                        </span>
                        <span v-else-if="doc.status === 'running'" key="running" class="doc-status running">Generando…</span>
                        <span v-else-if="doc.status === 'pending'" key="pending" class="doc-status pending">Pendiente</span>
                        <span v-else-if="doc.status === 'error'" key="error" class="doc-status error">Error</span>
                      </Transition>
                    </div>
                  </div>
                </TransitionGroup>

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

        <button v-if="canLoadMore" class="load-more" :disabled="loading" @click="$emit('load-more')">
          {{ loading ? 'Cargando…' : `Ver más (${scans.length} de ${totalCount})` }}
        </button>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import StatusBadge from '@/components/themis/StatusBadge.vue'
import { MAX_PER_PAGE } from '@/stores/scanWindow'

const props = defineProps({
  scans: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  totalCount: { type: Number, default: 0 },
  docsByScan: { type: Object, default: () => ({}) },
  groupsByScan: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['refresh', 'delete', 'load-docs', 'generate-pdf', 'download-doc', 'delete-doc', 'load-more', 'load-groups', 'set-finding-state'])

/** Veredictos fantasma mientras carga: los que caben sin alargar la caja. */
const SKELETON_ROWS = 4

/**
 * "Ver más" desaparece al llegar al tope de la ventana, no sólo al haberlos
 * cargado todos. El store pide la lista revelada en una sola petición, y
 * `per_page` está topado en el backend (`ResultsQuerySchema`), así que más allá
 * de ahí el botón seguiría ahí sin hacer nada — que es peor que no estar.
 */
const canLoadMore = computed(
  () => props.scans.length < props.totalCount && props.scans.length < MAX_PER_PAGE)

const LADDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const PRIO_LABEL = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja', INFO: 'Info' }
const STATE_LABEL = { fixed: 'Corregido', regressed: 'Regresado', accepted: 'Aceptado', false_positive: 'Falso positivo' }

/**
 * Por qué falló un escaneo, en prosa. El backend manda un código corto
 * (`failureReason`) y la redacción vive aquí, que es donde vive el resto del
 * castellano de cara al usuario.
 *
 * Cada entrada trae además un consejo, porque la diferencia que importa no es
 * cuál de los cinco motivos fue: es si el usuario puede hacer algo al respecto.
 * En «el host no respondía» —el caso más frecuente con diferencia— sí puede, y
 * el consejo enumera qué comprobar. En un error interno no puede hacer nada, y
 * decírselo evita que pierda el tiempo revisando su red.
 */
const FAILURE = {
  host_unreachable: {
    title: 'El objetivo no respondió.',
    hint: 'El motor no llegó a abrir ninguna conexión, así que no hay nada que analizar. '
        + 'Comprueba que la máquina esté encendida, que la dirección sea la correcta y que '
        + 'no haya un cortafuegos descartando el tráfico.',
  },
  port_discovery_failed: {
    title: 'El descubrimiento de puertos no pudo completarse.',
    hint: 'El objetivo respondía, pero el barrido no llegó a terminar. Suele ser un '
        + 'cortafuegos que corta el sondeo a mitad; prueba a acotar la lista de puertos.',
  },
  no_results: {
    title: 'El escáner terminó sin devolver resultados.',
    hint: 'La herramienta se ejecutó pero no produjo nada que procesar. Vuelve a lanzarlo; '
        + 'si se repite, el objetivo puede estar filtrando el escaneo.',
  },
  orphaned: {
    title: 'El escaneo se interrumpió al reiniciarse el servicio.',
    hint: 'No es un problema del objetivo: el trabajo se perdió a mitad y se cerró al '
        + 'arrancar de nuevo. Lánzalo otra vez.',
  },
  timeout: {
    title: 'Se acabó el tiempo antes de terminar.',
    hint: 'El trabajo pedido no cabía en el plazo pedido. Es lo que pasa al cruzar un '
        + 'rango de puertos muy ancho con un objetivo que tiene muchos abiertos: cada '
        + 'servicio encontrado se analiza después, y eso también cuesta tiempo. Acota '
        + 'los puertos o sube el plazo del panel de lanzamiento.',
  },
  internal_error: {
    title: 'El motor encontró un error inesperado.',
    hint: 'El fallo es del producto, no de tu red. El detalle queda en el registro del '
        + 'servidor; si se repite con el mismo objetivo, merece un aviso.',
  },
}
// Los escaneos que fallaron antes de que existiera la columna no traen código,
// y decir «no se registró» es más honesto que elegir un motivo por ellos.
const FAILURE_UNKNOWN = {
  title: 'El escaneo falló.',
  hint: 'No se registró el motivo — es un escaneo anterior a que el motor empezara a '
      + 'guardarlo.',
}
function failureOf(scan) { return FAILURE[scan.failureReason] || FAILURE_UNKNOWN }

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

/**
 * Hallazgo cuyo motivo se está escribiendo, y qué decisión.
 *
 * El motivo se pide siempre: un `accepted` sin justificación es deuda; con
 * justificación es una decisión. Y un desmentido sin motivo no sirve para
 * calibrar el motor, que es la mitad de su valor.
 */
const deciding = ref(null)
const decisionState = ref(null)
const decisionReason = ref('')

function startDecision(findingId, state) {
  deciding.value = findingId
  decisionState.value = state
  decisionReason.value = ''
}

function cancelDecision() {
  deciding.value = null
  decisionState.value = null
  decisionReason.value = ''
}

function confirmDecision(scanId) {
  emit('set-finding-state', scanId, deciding.value, decisionState.value,
       decisionReason.value.trim() || null)
  cancelDecision()
}

function groupsFor(scanId) { return props.groupsByScan[scanId]?.groups || [] }
function groupsLoading(scanId) { return !!props.groupsByScan[scanId]?.loading }
function groupsError(scanId) { return props.groupsByScan[scanId]?.error || null }

/**
 * Identidad de un grupo dentro de un escaneo. El backend no le da id porque no
 * es una fila: es una vista sobre los hallazgos, y su identidad es justo la
 * clave por la que se agrupó.
 *
 * El escaneo va delante porque la lista puede tener varias tarjetas abiertas a
 * la vez, y dos escaneos del mismo objetivo producen grupos con la misma
 * etiqueta, puerto y servicio. Sin él, ambos compartirían estado de plegado y
 * de "ver más": abrir uno abriría también a su homónimo de la tarjeta de al
 * lado.
 */
function groupKey(scanId, group) { return `${scanId}|${group.port ?? '-'}|${group.service ?? '-'}|${group.label}` }

/**
 * Las dos secciones en que se parten los grupos.
 *
 * Son dos clases de trabajo distintas: subir un producto de versión, y arreglar
 * una configuración. Mezclarlas hacía que "falta la cabecera HSTS" pareciera un
 * producto más del inventario, y que un producto con veinte CVEs pareciera
 * veinte problemas.
 */
function sections(scanId) {
  const groups = groupsFor(scanId)
  return [
    { key: 'prod', title: 'Productos afectados', groups: groups.filter(g => g.isProduct) },
    { key: 'conf', title: 'Configuración y exposición', groups: groups.filter(g => !g.isProduct) },
  ]
}

function toggleFindings(id) {
  const s = new Set(findingsOpen.value)
  if (s.has(id)) {
    s.delete(id)
  } else {
    s.add(id)
    // Los hallazgos no vienen con el listado: se piden al abrir, igual que los
    // documentos. Una lista de diez tarjetas colapsadas no debe pagar los
    // hallazgos de las nueve que nadie va a abrir.
    if (!props.groupsByScan[id]) emit('load-groups', id)
  }
  findingsOpen.value = s
}

function visibleGroupFindings(scanId, group) {
  return group.findings.slice(0, findingsLimit[groupKey(scanId, group)] || FINDINGS_PAGE)
}

/**
 * Plegado por grupo, independiente del bloque general y cerrado de entrada.
 *
 * Antes el único plegado era el de "Mostrar hallazgos", que abre los doce
 * grupos de golpe: para llegar al último había que atravesar los once
 * anteriores con toda su evidencia desplegada. El "ver más" incremental alivia
 * la lista *dentro* de un grupo, pero no ayuda a saltar de uno a otro.
 */
const groupsOpen = ref(new Set())

function isGroupOpen(scanId, group) { return groupsOpen.value.has(groupKey(scanId, group)) }

function toggleGroup(scanId, group) {
  const key = groupKey(scanId, group)
  const s = new Set(groupsOpen.value)
  if (s.has(key)) s.delete(key)
  else s.add(key)
  groupsOpen.value = s
}

function showMoreFindings(key) {
  findingsLimit[key] = (findingsLimit[key] || FINDINGS_PAGE) + FINDINGS_PAGE
}

/** Recuento por nivel de prioridad para el resumen de la cabecera.
 *
 * Lo calculaba aquí recorriendo la lista completa de hallazgos, que era la
 * razón por la que el listado tenía que mandarla entera. Ahora llega hecho. */
function summary(scan) {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, ...(scan.byPriority || {}) }
}

/**
 * Detecta un análisis de inventario (Fase I) con paquetes sin identificar.
 *
 * `cpeResolved` (Fase I-b, `Finding.cpe_resolved`) da el número exacto de
 * paquetes que el matcher no pudo ni resolver a un CPE — ya no es una
 * heurística sobre ausencia de detecciones, que mezclaba eso con "KB sin
 * sincronizar" o simplemente "comprobado y limpio". El recuento lo hace ahora
 * el servidor, que ya tenía las filas delante.
 *
 * Devuelve `null` si no aplica (sin paquetes, o todos resueltos), o
 * `{ packages, unresolved }` cuando el aviso debe mostrarse.
 */
function coverageGap(scan) {
  const packages = scan.installedPackages || 0
  const unresolved = scan.unresolvedPackages || 0
  if (!packages || !unresolved) return null
  return { packages, unresolved }
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
/* Mismo alto y mismo padding que .scan-head, para que al llegar los
   veredictos la lista no cambie de tamaño. */
.scan-ghost {
  display: flex; align-items: center; gap: 0.65rem;
  padding: 0.7rem 1rem;
  border-bottom: 1px solid var(--border);
}
.ghost-dot { width: 15px; flex-shrink: 0; }

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
.body-clean { display: flex; align-items: center; gap: 0.5rem; padding: 0.7rem 0; font-size: var(--fs-lg); color: var(--success); }

/* Recuadro de estado: el mismo molde que `.body-partial-hint` —borde, fondo
   tenue del color del estado, texto explicativo— porque son mensajes de la
   misma clase. Lo que cambia entre variantes es sólo el color. */
.state-panel {
  display: flex; align-items: flex-start; gap: 0.65rem;
  margin: 0.4rem 0; padding: 0.7rem 0.8rem; border-radius: 8px;
  border: 1px solid var(--state-color); background: var(--state-bg);
}
.state-panel--failed { --state-color: var(--danger); --state-bg: var(--danger-dim); }
.state-panel--pending { --state-color: var(--accent); --state-bg: var(--accent-dim); }
.state-panel--pending .state-title { color: var(--text-dim); }

/* Barra indeterminada: un tramo corto que recorre el carril de lado a lado.
   No representa progreso —el porcentaje real no llega hasta aquí—, sólo que el
   trabajo sigue vivo, que es justo lo que el usuario no podía saber. */
.state-progress {
  /* El carril lleva `--border-med` y no `--state-bg`: éste es el mismo color
     que el fondo del recuadro, así que la barra recorría un carril invisible y
     el movimiento se leía como un guion suelto. */
  position: relative; height: 3px; margin-top: 0.35rem; border-radius: 2px;
  background: var(--border-med); overflow: hidden;
}
.state-progress span {
  position: absolute; inset: 0 auto 0 0; width: 38%; border-radius: 2px;
  background: var(--state-color); opacity: 0.75;
  animation: state-progress-sweep 1.5s ease-in-out infinite;
}
@keyframes state-progress-sweep {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(265%); }
}
.state-icon { width: 20px; height: 20px; flex: none; margin-top: 0.1rem; color: var(--state-color); }
.state-text { display: flex; flex-direction: column; gap: 0.2rem; min-width: 0; }
.state-title { margin: 0; font-size: var(--fs-lg); color: var(--state-color); }
.state-hint { margin: 0; font-size: var(--fs-md); line-height: 1.45; color: var(--text-dim); }

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
.f-tag.state.false_positive { color: var(--text-muted); text-decoration: line-through; }

.f-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.35rem; }
.f-act {
  padding: 0.15rem 0.5rem; border-radius: 5px; cursor: pointer;
  border: 1px solid var(--border-solid); background: var(--surface-2);
  color: var(--text-dim); font-size: var(--fs-md);
}
.f-act:hover { border-color: var(--accent); color: var(--text); }
.f-act.primary { border-color: var(--accent); color: var(--text); }
.f-reason {
  flex: 1 1 16rem; min-width: 0; padding: 0.15rem 0.4rem; border-radius: 5px;
  border: 1px solid var(--border-solid); background: var(--surface);
  color: var(--text); font-size: var(--fs-md);
}
.f-decided { font-size: var(--fs-md); color: var(--text-muted); }
.f-tag.src { color: var(--info); background: var(--info-dim); }
.f-tag.fix { color: var(--success); background: var(--success-dim); font-weight: 600; }
.prio-partial {
  font-size: var(--fs-md); font-weight: 700; padding: 0.1rem 0.45rem; border-radius: 999px;
  color: var(--warn); background: var(--warn-dim); border: 1px solid var(--warn);
}
.body-partial-hint {
  margin-top: 0.6rem; padding: 0.55rem 0.7rem; border-radius: 8px;
  border: 1px solid var(--warn); background: var(--warn-dim);
  color: var(--text-dim); font-size: var(--fs-md); line-height: 1.45;
}
.body-partial-hint strong { color: var(--text); }
.f-tag.conf { color: var(--success); background: var(--success-dim); }

/* ── Grupos: la unidad sobre la que se actúa ── */
.groups-loading, .groups-error { padding: 0.6rem 0.2rem; font-size: var(--fs-md); color: var(--text-muted); }
.groups-error { color: var(--danger); }

.group-section {
  margin: 0.9rem 0 0.35rem; font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-md); font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-muted);
}
.group-section:first-child { margin-top: 0.2rem; }

.group { border: 1px solid var(--border); border-radius: 8px; padding: 0.55rem 0.7rem; margin-bottom: 0.5rem; background: var(--surface); }
.group-head {
  display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem;
  width: 100%; padding: 0; background: none; border: none;
  text-align: left; cursor: pointer; color: inherit; font: inherit;
}
.group-head:hover .group-label { color: var(--accent-bright); }
.group-head:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 4px; }
.group-chevron svg { width: 12px; height: 12px; }
.group-body { margin-top: 0.1rem; }
.group-label { font-weight: 600; color: var(--text); font-size: var(--fs-lg); }
.group-count { margin-left: auto; font-size: var(--fs-md); color: var(--text-muted); }
.group-meta { display: flex; flex-wrap: wrap; gap: 0.3rem; margin: 0.35rem 0 0.1rem; }
.group .findings { margin-top: 0.4rem; }

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
.doc-list { position: relative; display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 0.6rem; }
.doc-item { display: flex; align-items: center; justify-content: space-between; padding: 0.4rem 0.55rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }
.doc-item:hover { border-color: var(--accent); }
/* Mismo patrón que .finding-item: la tarjeta entra deslizándose, el resto de
   la lista se mueve para hacerle sitio, y una salida (eliminar documento) no
   deja un hueco brusco. */
.doc-item-enter-active { transition: opacity 0.3s ease, transform 0.3s ease; }
.doc-item-enter-from { opacity: 0; transform: translateY(-8px); }
.doc-item-leave-active { transition: opacity 0.15s ease; position: absolute; width: 100%; }
.doc-item-leave-to { opacity: 0; }
.doc-item-move { transition: transform 0.25s ease; }
.doc-actions { display: flex; gap: 0.2rem; align-items: center; }
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
/* align-items:center alinea la CAJA de la casilla con la caja de línea del
   texto, no con su tinta: Alegreya Sans reserva descendente aunque "Análisis
   IA" no tenga ninguna letra que baje de la línea base, así que esa caja
   queda descentrada respecto al texto visible. translateY corrige ese
   desfase óptico (medido con canvas measureText: ~1.5px a este tamaño). */
.doc-checkbox input[type="checkbox"] { appearance: none; -webkit-appearance: none; width: 14px; height: 14px; padding: 0; border: 1.5px solid var(--text-muted); border-radius: 3px; background: transparent; cursor: pointer; margin: 0; flex-shrink: 0; position: relative; transform: translateY(-1.5px); transition: background 0.15s ease, border-color 0.15s ease; }
.doc-checkbox input[type="checkbox"]:checked { background: var(--accent); border-color: var(--accent); }
/* Centrado por porcentaje + translate(-50%,-50%) en vez de top/left fijos en
   píxeles: esos quedaban descuadrados según el redondeo del borde y se veían
   corridos a la izquierda. El ::after existe siempre (no solo en :checked)
   para poder animar entre opacity/scale 0 y 1 en vez de aparecer de golpe. */
.doc-checkbox input[type="checkbox"]::after {
  content: ''; position: absolute; left: 50%; top: 45%; width: 28%; height: 55%;
  border: solid var(--on-accent); border-width: 0 1.5px 1.5px 0;
  transform: translate(-50%, -50%) rotate(45deg) scale(0); opacity: 0;
  transition: transform 0.18s cubic-bezier(0.34, 1.56, 0.64, 1), opacity 0.12s ease;
}
.doc-checkbox input[type="checkbox"]:checked::after { transform: translate(-50%, -50%) rotate(45deg) scale(1); opacity: 1; }
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
  /* La barra se queda quieta y llena: sin movimiento sigue diciendo «esto está
     en curso», que es lo único que representa. */
  .state-progress span { animation: none !important; width: 100%; }
  .chevron, .expand-enter-active, .expand-leave-active, .fade-swap-enter-active, .fade-swap-leave-active,
  .findings-panel-enter-active, .findings-panel-leave-active,
  .finding-item-enter-active, .finding-item-leave-active, .finding-item-move,
  .doc-checkbox input[type="checkbox"], .doc-checkbox input[type="checkbox"]::after,
  .doc-item-enter-active, .doc-item-leave-active, .doc-item-move { transition: none !important; }
}
</style>
