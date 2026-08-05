import { defineStore } from 'pinia'
import { ref, reactive } from 'vue'
import { useApi } from '@/composables/useApi'
import { usePolling } from '@/composables/usePolling'
import { useUtils } from '@/composables/useUtils'
import { useToastStore } from '@/stores/toastStore'
import { useThemisFoldersStore } from '@/stores/themisFoldersStore'
import { useThemisHistoryStore } from '@/stores/themisHistoryStore'

/**
 * Store de Themis — gestiona escaneos, estadísticas, modales y documentos.
 *
 * Sustituye al estado disperso en themis.js (1,198 líneas de manipulación DOM
 * directa). Centraliza las listas de resultados por tipo (nmap, nikto, nuclei),
 * la paginación, los modales de vista previa/detalle y los documentos asociados.
 */
export const useThemisStore = defineStore('themis', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()
  const { triggerDownload, filenameFromResponse } = useUtils()
  const foldersStore = useThemisFoldersStore()
  const historyStore = useThemisHistoryStore()

  /* ════════════════════════════════ MUNDOS ═════════════════════════════ */
  // Themis vive en tres mundos: el motor propio (Lybra), los escáneres
  // externos (Nmap/Nikto/Nuclei) y los agentes de Hygeia (Fase I: escaneos
  // Lybra nacidos del inventario de software de un activo, que se navegan por
  // agente en vez de mezclarse en la feed del motor). El toggle de ThemisView
  // conmuta entre ellos. Lybra es el mundo por defecto (roadmap Fase 6: el
  // motor propio es el protagonista, los externos son segunda opinión).
  const world = ref('lybra') // 'external' | 'lybra' | 'agents'
  function setWorld(w) { world.value = w }

  // Activo de Hygeia seleccionado en el mundo de agentes. Null = ninguna
  // tarjeta elegida todavía, así que no hay escaneos que pedir.
  const selectedAssetId = ref(null)

  /* ════════════════════════════════ TABS ═══════════════════════════════ */
  const activeTab = ref('nmap')

  /* ════════════════════════════════ STATS ══════════════════════════════ */
  const stats = reactive({ total: 0, nmap: 0, nikto: 0, lybra: 0, nuclei: 0 })
  const loadingStats = ref(false)
  const statsError = ref(null)

  /* ════════════════════════════════ SCANS POR TIPO ═════════════════════ */
  const scans = reactive({
    nmap:    { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null },
    nikto:   { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null },
    lybra:   { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null },
    nuclei:  { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null },
    // Fase I: los escaneos del activo Hygeia seleccionado. Mismo tipo de
    // escaneo que `lybra` y misma forma de estado —por eso `LybraResults` se
    // reutiliza tal cual—, pero su propia lista: el backend los sirve por
    // separado (`assetId`) y jamás los mezcla con los del panel.
    agentLybra: { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null },
  })

  // Escaneos Nmap terminados, para el modo "analizar un Nmap existente" de Lybra.
  const sourceNmapScans = reactive({ items: [], loading: false, error: null })

  // Registro de objetivos autorizados (roadmap §6): gate legal por-usuario que
  // desbloquea el autodescubrimiento, el fingerprinting propio y las
  // comprobaciones activas de Lybra sobre un objetivo concreto.
  const authorizedTargets = reactive({ items: [], loading: false, error: null })

  const launching = ref(false)

  /* ════════════════════════════════ MODALES ════════════════════════════ */
  const preview = reactive({ show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false, traceroute: null, tracerouteLoading: false })
  const details = reactive({ show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false })

  /* ════════════════════════════════ VISTA DE CARPETAS ══════════════════ */
  // Estado y CRUD de carpetas viven en themisFoldersStore; aquí solo queda el
  // modo de vista (que también conmuta a "history", no solo "folders").
  const viewMode = ref('full') // 'full' | 'folders' | 'history'

  /* ── HELPERS ── */
  /** @param {'nmap'|'nikto'|'nuclei'} type */
  function _scandata(type) { return scans[type] }

  /* ════════════════════════════════ STATS ══════════════════════════════ */
  /** Carga los contadores de escaneos desde el endpoint de stats. */
  async function loadStats() {
    loadingStats.value = true
    try {
      const res = await apiFetch('/themis/stats')
      if (!res?.ok) { statsError.value = 'No se pudieron cargar las estadísticas.'; return }
      const data = await res.json()
      stats.nmap    = data.nmap    ?? 0
      stats.nikto   = data.nikto   ?? 0
      stats.lybra   = data.lybra   ?? 0
      stats.nuclei  = data.nuclei  ?? 0
      stats.total   = data.total   ?? 0
      statsError.value = null
    } catch { statsError.value = 'Error de conexión al cargar las estadísticas.' }
    finally { loadingStats.value = false }
  }

  /* ════════════════════════════════ SCANS ═════════════════════════════ */
  // C2: a diferencia de Iris, Themis no sondeaba el estado de un escaneo
  // recién lanzado — se quedaba "running" en la UI hasta un refresco manual.
  // Mismo idioma que el polling de traceroute (setTimeout re-encadenado, no
  // setInterval): cada carga se reprograma a sí misma mientras la pestaña
  // siga visible y queden escaneos pending/running.
  const SCAN_POLL_INTERVAL_MS = 4000
  const _scanPollTimers = {}

  function _isTypeVisible(type) {
    if (type === 'lybra') return world.value === 'lybra' && viewMode.value !== 'history'
    if (type === 'agentLybra') return world.value === 'agents' && !!selectedAssetId.value
    return world.value === 'external' && activeTab.value === type && viewMode.value === 'full'
  }

  /**
   * Parámetros de consulta de una lista de escaneos.
   *
   * `agentLybra` no es un tipo de escaneo propio sino la misma lista de Lybra
   * acotada a un activo: el backend distingue ambas por `assetId` (omitirlo
   * devuelve los del panel), así que la diferencia vive aquí y no en una
   * segunda ruta.
   */
  function _scanQuery(type, page, perPage) {
    if (type === 'agentLybra') {
      return new URLSearchParams({ type: 'lybra', page, per_page: perPage, assetId: selectedAssetId.value })
    }
    return new URLSearchParams({ type, page, per_page: perPage })
  }

  // E8: este NO usa `usePolling` a propósito. No es un poller que posea una
  // tarea, sino un cargador que se reprograma a sí mismo: `loadScans` lo
  // llama en su `finally`, y a `loadScans` se entra también desde switchTab,
  // goToPage y refreshCurrent. Meterlo en el composable obligaría a arrancar
  // el poller desde esos cuatro sitios, o a que el poller se detuviera a sí
  // mismo a mitad de ciclo. Ya usa el idioma correcto (setTimeout
  // re-encadenado, sin solape), así que se queda.
  function _scheduleScanPoll(type) {
    clearTimeout(_scanPollTimers[type])
    delete _scanPollTimers[type]
    const hasActive = _scandata(type).results.some(s => s.status === 'pending' || s.status === 'running')
    if (!hasActive || !_isTypeVisible(type)) return
    _scanPollTimers[type] = setTimeout(() => loadScans(type), SCAN_POLL_INTERVAL_MS)
  }

  /** Detiene el polling de escaneos activos: de un tipo concreto, o de todos. */
  function stopScanPolling(type) {
    const types = type ? [type] : Object.keys(_scanPollTimers)
    for (const t of types) { clearTimeout(_scanPollTimers[t]); delete _scanPollTimers[t] }
  }

  /** Carga una pagina de resultados para un tipo de escaneo. */
  async function loadScans(type) {
    const d = _scandata(type)
    // Sin activo seleccionado no hay nada que pedir en el mundo de agentes.
    if (type === 'agentLybra' && !selectedAssetId.value) {
      d.results = []; d.totalCount = 0; d.error = null
      return
    }
    d.loading = true
    try {
      const params = _scanQuery(type, d.page, d.perPage)
      const res = await apiFetch(`/themis/results?${params}`)
      if (!res?.ok) {
        d.results = []
        d.error = await apiError(res, 'No se pudieron cargar los escaneos.')
        return
      }
      const data = await res.json()
      d.results = data.results ?? []
      d.totalCount = data.totalCount ?? 0
      d.error = null
    } catch (e) {
      d.results = []
      d.error = 'Error de conexión al cargar los escaneos.'
    } finally {
      d.loading = false
      _scheduleScanPoll(type)
    }
  }

  /** Cambia de pestana y carga los resultados desde pagina 1. */
  function switchTab(type) {
    activeTab.value = type
    const d = _scandata(type)
    d.page = 1
    loadScans(type)
  }

  /** Refresca la pestaña activa y las estadísticas. */
  async function refreshCurrent() {
    await loadScans(activeTab.value)
    await loadStats()
  }

  /** Navega a una pagina concreta para el tipo activo. */
  function goToPage(type, page) {
    const d = _scandata(type)
    d.page = page
    loadScans(type)
  }

  /* ════════════════════════════════ LANZAR ════════════════════════════ */
  /** Lanza un escaneo Nmap y refresca los datos.*/
  async function launchNmap(payload) {
    return _launch('/themis/nmap', payload, 'nmap')
  }
  /** Lanza un escaneo Nikto. */
  async function launchNikto(payload) {
    return _launch('/themis/nikto', payload, 'nikto')
  }
  /** Lanza un escaneo Nuclei (roadmap Fase U1). */
  async function launchNuclei(payload) {
    return _launch('/themis/nuclei', payload, 'nuclei')
  }

  /* ── LYBRA (el motor propio) ── */

  /** Carga la lista de escaneos Lybra (cada uno ya trae sus findings). */
  async function loadLybraScans() {
    return loadScans('lybra')
  }

  /**
   * "Ver más": añade la siguiente página de escaneos Lybra a la lista ya
   * cargada (en vez de reemplazarla, como hace loadScans/goToPage) — el
   * listado de veredictos crece hacia abajo sin perder el scroll ni el
   * estado expandido de las tarjetas ya visibles.
   */
  async function loadMoreLybraScans(type = 'lybra') {
    const d = _scandata(type)
    if (d.loading || d.results.length >= d.totalCount) return
    d.loading = true
    try {
      const nextPage = d.page + 1
      const res = await apiFetch(`/themis/results?${_scanQuery(type, nextPage, d.perPage)}`)
      if (!res?.ok) return
      const data = await res.json()
      d.results = [...d.results, ...(data.results ?? [])]
      d.totalCount = data.totalCount ?? d.totalCount
      d.page = nextPage
    } finally {
      d.loading = false
    }
  }

  /* ── AGENTES (Fase I: escaneos nacidos del inventario de Hygeia) ── */

  /**
   * Selecciona un activo de Hygeia y carga sus escaneos.
   *
   * @param {number|null} assetId - Id del activo, o null para deseleccionar.
   */
  function selectAgentAsset(assetId) {
    selectedAssetId.value = assetId
    const d = scans.agentLybra
    d.page = 1
    d.results = []
    d.totalCount = 0
    if (assetId) loadScans('agentLybra')
  }

  /** Recarga los escaneos del activo seleccionado desde la primera página. */
  function loadAgentScans() {
    scans.agentLybra.page = 1
    return loadScans('agentLybra')
  }

  /**
   * Carga los escaneos Nmap TERMINADOS del usuario, para poblar el desplegable
   * del modo "analizar un Nmap existente". Reutiliza el endpoint de resultados
   * y filtra por estado finished (solo un Nmap acabado tiene puertos que analizar).
   */
  async function loadSourceNmapScans() {
    sourceNmapScans.loading = true
    try {
      const params = new URLSearchParams({ type: 'nmap', page: 1, per_page: 100 })
      const res = await apiFetch(`/themis/results?${params}`)
      if (!res?.ok) { sourceNmapScans.items = []; sourceNmapScans.error = 'No se pudieron cargar los escaneos Nmap.'; return }
      const data = await res.json()
      sourceNmapScans.items = (data.results ?? []).filter(s => s.status === 'finished')
      sourceNmapScans.error = null
    } catch { sourceNmapScans.items = []; sourceNmapScans.error = 'Error de conexión.' }
    finally { sourceNmapScans.loading = false }
  }

  /** Carga el registro de objetivos autorizados del usuario. */
  async function loadAuthorizedTargets() {
    authorizedTargets.loading = true
    try {
      const res = await apiFetch('/themis/authorized-targets')
      if (!res?.ok) { authorizedTargets.items = []; authorizedTargets.error = 'No se pudieron cargar los objetivos.'; return }
      const data = await res.json()
      authorizedTargets.items = data.targets ?? []
      authorizedTargets.error = null
    } catch { authorizedTargets.items = []; authorizedTargets.error = 'Error de conexión.' }
    finally { authorizedTargets.loading = false }
  }

  /** Añade un objetivo (IP o CIDR) al registro de objetivos autorizados. */
  async function addAuthorizedTarget(target, label = '') {
    try {
      const res = await apiFetch('/themis/authorized-targets', {
        method: 'POST',
        body: JSON.stringify({ target, label: label || undefined }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo añadir el objetivo autorizado.'), 'error')
        return false
      }
      const data = await res.json()
      authorizedTargets.items.unshift({
        id: data.targetId, target: data.target, label: label || null, createdAt: new Date().toISOString(),
      })
      toast.show(`Objetivo '${data.target}' autorizado.`, 'success')
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    }
  }

  /** Elimina una entrada del registro de objetivos autorizados. */
  async function removeAuthorizedTarget(id) {
    const res = await apiFetch(`/themis/authorized-targets/${id}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el objetivo autorizado.', 'error'); return false }
    const idx = authorizedTargets.items.findIndex(t => t.id === id)
    if (idx !== -1) authorizedTargets.items.splice(idx, 1)
    toast.show('Objetivo autorizado eliminado.', 'success')
    return true
  }

  /**
   * Lanza un escaneo Lybra. El payload lleva UNO de los dos modos:
   *   - { sourceScanId }         → analizar un Nmap previo
   *   - { target, ports? }       → autodescubrimiento
   * más flags comunes: { deep, timeout }.
   */
  async function launchLybra(payload) {
    launching.value = true
    try {
      const res = await apiFetch('/themis/lybra', { method: 'POST', body: JSON.stringify(payload) })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al lanzar el escaneo Lybra.'), 'error')
        return false
      }
      const data = await res.json()
      toast.show(`Motor Lybra iniciado (ID: ${data.scanId})`, 'success')
      await loadLybraScans()
      await loadStats()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { launching.value = false }
  }

  async function _launch(endpoint, payload, type) {
    launching.value = true
    try {
      const res = await apiFetch(endpoint, { method: 'POST', body: JSON.stringify(payload) })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al lanzar el escaneo.'), 'error')
        return false
      }
      const data = await res.json()
      const id = data.scanIds ? data.scanIds.join(', ') : data.scanId
      toast.show(`Escaneo ${type.toUpperCase()} iniciado (ID: ${id})`, 'success')
      await refreshCurrent()
      await foldersStore.loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { launching.value = false }
  }

  /* ════════════════════════════════ ACCIONES DE FILA ══════════════════ */
  /** Elimina un escaneo por ID. Actualiza el estado local sin refetch completo. */
  async function deleteScan(id) {
    const res = await apiFetch(`/themis/${id}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el escaneo.', 'error'); return false }

    const hit = foldersStore.findScanInFolders(id)
    if (hit) {
      hit.folder.scans.splice(hit.idx, 1)
      hit.folder.scanCount = Math.max(0, (hit.folder.scanCount || 0) - 1)
    }

    const d = _scandata(activeTab.value)
    const tableIdx = d.results.findIndex(s => s.id === id)
    if (tableIdx !== -1) {
      d.results.splice(tableIdx, 1)
      d.totalCount = Math.max(0, d.totalCount - 1)

      if (d.results.length === 0 && d.totalCount > 0 && d.page > 1) {
        d.page--
        await loadScans(activeTab.value)
      } else if (d.results.length < d.perPage && d.totalCount > d.page * d.perPage) {
        await loadScans(activeTab.value)
      }
    }

    await loadStats()
    return true
  }

  /** Cancela un escaneo en ejecución. Actualiza el badge local sin refetch. */
  async function cancelScan(id) {
    const res = await apiFetch(`/themis/scans/${id}/cancel`, { method: 'POST' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo cancelar el escaneo.'), 'error')
      return false
    }

    const hit = foldersStore.findScanInFolders(id)
    if (hit) hit.folder.scans[hit.idx].status = 'cancelled'

    const d = _scandata(activeTab.value)
    const tableHit = d.results.find(s => s.id === id)
    if (tableHit) tableHit.status = 'cancelled'

    return true
  }

  /* ════════════════════════════════ VISTA PREVIA ══════════════════════ */

  // El traceroute se calcula en segundo plano (worker): el endpoint responde
  // "pending" al instante y aquí se hace polling hasta que esté "done"/"failed".
  // Cerrar o cambiar de modal invalida los ciclos en vuelo (E8: lo hace el
  // stop() de usePolling, antes era un token de generación a mano).
  const TRACE_POLL_INTERVAL_MS = 2000
  const TRACE_POLL_MAX_ATTEMPTS = 30
  let tracePoller = null

  function stopTracePoll() {
    tracePoller?.stop()
    tracePoller = null
  }

  /** Abre el modal de vista previa y carga scan + documentos. */
  async function openPreview(scanId, type) {
    preview.scanId = scanId
    preview.type = type
    preview.show = true
    preview.scan = null
    preview.docs = []
    preview.docsLoading = true
    preview.traceroute = null
    preview.tracerouteLoading = true

    try {
      const [scanRes, docsRes] = await Promise.all([
        apiFetch(`/themis/results/${scanId}`),
        apiFetch(`/themis/scan/${scanId}/documents`),
      ])
      if (scanRes?.ok) {
        const data = await scanRes.json()
        preview.scan = data.result ?? data
      }
      if (docsRes?.ok) {
        const data = await docsRes.json()
        preview.docs = data.documents ?? []
      }
    } catch { /* noop */ }
    finally { preview.docsLoading = false }

    // El traceroute se carga aparte: el worker lo calcula en segundo plano y
    // aquí se hace polling, así que no debe bloquear el resto del modal.
    loadPreviewTraceroute()
  }

  /**
   * Carga el traceroute del escaneo abierto en la vista previa.
   *
   * El cálculo es asíncrono (worker): si fuerza, primero dispara el recálculo
   * con POST /refresh; en ambos casos hace polling del GET hasta que el estado
   * deje de ser "pending".
   * @param {boolean} force - Si es true, fuerza el recálculo (ignora la caché).
   */
  async function loadPreviewTraceroute(force = false) {
    const scanId = preview.scanId
    if (!scanId) return

    stopTracePoll()
    if (!force) preview.traceroute = null
    preview.tracerouteLoading = true

    if (force) {
      try {
        const res = await apiFetch(`/themis/scan/${scanId}/traceroute/refresh`, { method: 'POST' })
        if (!res?.ok) toast.show('No se pudo recalcular el traceroute.', 'error')
      } catch {
        toast.show('Error al recalcular el traceroute.', 'error')
      }
    }

    // E8: el token de generación que llevaba a mano lo aporta ahora
    // `usePolling` (stop() invalida los ciclos en vuelo); aquí solo queda el
    // guard propio de esta vista — que el modal siga abierto sobre el MISMO
    // escaneo, que es una condición distinta de "se canceló el sondeo".
    tracePoller = usePolling(async (attempt) => {
      if (preview.scanId !== scanId) return false
      const res = await apiFetch(`/themis/scan/${scanId}/traceroute`)
      if (preview.scanId !== scanId) return false

      if (!res?.ok) { preview.tracerouteLoading = false; return false }

      const data = await res.json()
      // `attempt` es 0-based, así que el último ciclo permitido es
      // TRACE_POLL_MAX_ATTEMPTS - 1: ahí se acepta lo que haya como final.
      if (data.status === 'pending' && attempt < TRACE_POLL_MAX_ATTEMPTS - 1) return true

      // "done"/"failed" (o se agotaron los intentos): resultado final.
      preview.traceroute = data
      preview.tracerouteLoading = false
      return false
    }, { intervalMs: TRACE_POLL_INTERVAL_MS, maxAttempts: TRACE_POLL_MAX_ATTEMPTS })
    tracePoller.start()
  }

  /** Cierra el modal de vista previa. */
  function closePreview() {
    stopTracePoll()
    preview.show = false
    preview.scanId = null
    preview.scan = null
    preview.docs = []
    preview.traceroute = null
    preview.tracerouteLoading = false
  }

  /** Refresca los documentos dentro del modal de vista previa. */
  async function refreshPreviewDocs() {
    if (!preview.scanId) return
    preview.docsLoading = true
    try {
      const res = await apiFetch(`/themis/scan/${preview.scanId}/documents`)
      if (res?.ok) {
        const data = await res.json()
        preview.docs = data.documents ?? []
      }
    } finally { preview.docsLoading = false }
  }

  /* ════════════════════════════════ DETALLES ══════════════════════════ */
  /** Abre el modal de detalles completos. */
  async function openDetails(scanId, type) {
    details.scanId = scanId
    details.type = type
    details.show = true
    details.scan = null
    details.docs = []
    details.docsLoading = true

    try {
      const [scanRes, docsRes] = await Promise.all([
        apiFetch(`/themis/results/${scanId}`),
        apiFetch(`/themis/scan/${scanId}/documents`),
      ])
      if (scanRes?.ok) {
        const data = await scanRes.json()
        details.scan = data.result ?? data
      }
      if (docsRes?.ok) {
        const data = await docsRes.json()
        details.docs = data.documents ?? []
      }
    } finally { details.docsLoading = false }
  }

  /** Cierra el modal de detalles. */
  function closeDetails() {
    details.show = false
    details.scanId = null
    details.scan = null
    details.docs = []
  }

  /** Refresca documentos en el modal de detalles. */
  async function refreshDetailsDocs() {
    if (!details.scanId) return
    details.docsLoading = true
    try {
      const res = await apiFetch(`/themis/scan/${details.scanId}/documents`)
      if (res?.ok) {
        const data = await res.json()
        details.docs = data.documents ?? []
      }
    } finally { details.docsLoading = false }
  }

  /* ════════════════════════════════ DOCUMENTOS PDF ════════════════════ */
  /** Solicita la generación de un PDF para un escaneo (opcionalmente con IA). */
  async function generatePdf(scanId, useAi = false) {
    const res = await apiFetch('/themis/generate-pdf', {
      method: 'POST',
      body: JSON.stringify({ id: scanId, aiReport: useAi }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'Error al generar documento'), 'error')
      return false
    }
    toast.show('Documento en generación...', 'success')
    return true
  }

  /**
   * Sondea /themis/document-status hasta que el último documento del escaneo
   * termine (done/error) o se agoten los intentos (B9: reemplaza un
   * `setTimeout` fijo de 600ms, que asumía que la generación —encolada,
   * asíncrona— siempre terminaba antes de ese plazo).
   */
  // E8: tampoco usa `usePolling`. Esto no es un sondeo en segundo plano sino
  // una espera bloqueante — el llamante hace `await` hasta que el documento
  // esté listo. El bucle secuencial ya es correcto (nunca solapa) y no hay
  // nada que cancelar desde fuera.
  async function waitForDocument(scanId, { intervalMs = 1500, maxAttempts = 20 } = {}) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const res = await apiFetch(`/themis/document-status?scan_id=${scanId}`)
      if (res?.ok) {
        const data = await res.json()
        if (data.status === 'done' || data.status === 'error') return
      }
      await new Promise(r => setTimeout(r, intervalMs))
    }
  }

  /** Descarga un documento PDF por ID. */
  async function downloadDocument(docId) {
    try {
      const res = await apiFetch(`/themis/document/${docId}/download`)
      if (!res?.ok) { toast.show('No se pudo descargar el documento.', 'error'); return false }
      const blob = await res.blob()
      const name = filenameFromResponse(res, `scan_${docId}.pdf`)
      triggerDownload(blob, name)
      toast.show('Documento descargado.', 'success')
      return true
    } catch (e) {
      toast.show('Error al descargar: ' + e.message, 'error')
      return false
    }
  }

  /** Elimina un documento por ID. */
  async function deleteDocument(docId) {
    const res = await apiFetch(`/themis/document/${docId}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo eliminar el documento.'), 'error')
      return false
    }
    toast.show('Documento eliminado.', 'success')
    return true
  }

  function setViewMode(mode) {
    viewMode.value = mode
    if (mode === 'folders') {
      if (!foldersStore.folders.items.length) foldersStore.loadFolders()
    } else if (mode === 'history') {
      if (!historyStore.history.hosts.length) historyStore.loadHistoryHosts()
    } else {
      refreshCurrent()
    }
  }

  /** Elimina multiples escaneos de forma masiva. */
  async function bulkDeleteScans(scanIds) {
    try {
      const res = await apiFetch('/themis/scans', {
        method: 'DELETE',
        body: JSON.stringify({ scanIds }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al eliminar escaneos.'), 'error')
        return false
      }
      const data = await res.json()
      toast.show(`${data.deletedCount ?? scanIds.length} escaneo(s) eliminado(s).`, 'success')
      await refreshCurrent()
      await foldersStore.loadFolders()
      await loadStats()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    }
  }

  /**
   * Documentos PDF por escaneo Lybra, indexados por scanId. A diferencia del
   * modal de vista previa (un solo escaneo "seleccionado" a la vez), varias
   * tarjetas de Lybra pueden estar expandidas simultáneamente, así que aquí
   * cada una lleva su propia entrada `{ items, loading }`.
   */
  const lybraDocs = reactive({})

  /** Carga (o refresca) los documentos de un escaneo Lybra concreto. */
  async function loadLybraDocs(scanId) {
    if (!lybraDocs[scanId]) lybraDocs[scanId] = reactive({ items: [], loading: false })
    const d = lybraDocs[scanId]
    d.loading = true
    try {
      const res = await apiFetch(`/themis/scan/${scanId}/documents`)
      if (!res?.ok) { d.items = []; return }
      const data = await res.json()
      d.items = data.documents ?? []
    } catch { d.items = [] }
    finally { d.loading = false }
  }

  /**
   * Genera un PDF para un escaneo Lybra y refresca su lista de documentos.
   *
   * Refresca dos veces a propósito: nada más lanzar la generación, para que
   * el documento aparezca de inmediato con estado "pending"/"running" (antes
   * la lista no se tocaba hasta que `waitForDocument` ya había terminado, así
   * que el usuario nunca llegaba a ver el documento en curso); y otra vez al
   * terminar el sondeo, para reflejar el estado final ("done"/"error").
   */
  async function generateLybraPdf(scanId, useAi = false) {
    const ok = await generatePdf(scanId, useAi)
    if (ok) {
      await loadLybraDocs(scanId)
      await waitForDocument(scanId)
      await loadLybraDocs(scanId)
    }
    return ok
  }

  /** Elimina un documento de un escaneo Lybra y refresca su lista. */
  async function deleteLybraDoc(scanId, docId) {
    const ok = await deleteDocument(docId)
    if (ok) await loadLybraDocs(scanId)
    return ok
  }

  /**
   * Elimina un escaneo Lybra por ID y refresca la lista.
   *
   * @param {number} id - Id del escaneo.
   * @param {'lybra'|'agentLybra'} [type] - Lista de la que quitarlo.
   */
  async function deleteLybraScan(id, type = 'lybra') {
    const res = await apiFetch(`/themis/${id}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el escaneo.', 'error'); return false }
    const d = _scandata(type)
    const idx = d.results.findIndex(s => s.id === id)
    if (idx !== -1) { d.results.splice(idx, 1); d.totalCount = Math.max(0, d.totalCount - 1) }
    await loadStats()
    return true
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura) — detiene también el
   * polling de escaneos y de traceroute en curso, que si no seguirían
   * disparando peticiones (con el token ya revocado) tras el logout. */
  function $reset() {
    stopScanPolling()
    stopTracePoll()

    world.value = 'lybra'
    activeTab.value = 'nmap'
    viewMode.value = 'full'
    launching.value = false
    selectedAssetId.value = null

    Object.assign(stats, { total: 0, nmap: 0, nikto: 0, lybra: 0, nuclei: 0 })
    loadingStats.value = false
    statsError.value = null

    for (const type of ['nmap', 'nikto', 'lybra', 'nuclei', 'agentLybra']) {
      Object.assign(scans[type], { results: [], loading: false, page: 1, totalCount: 0, perPage: 10, error: null })
    }

    Object.assign(sourceNmapScans, { items: [], loading: false, error: null })
    Object.assign(authorizedTargets, { items: [], loading: false, error: null })

    Object.assign(preview, { show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false, traceroute: null, tracerouteLoading: false })
    Object.assign(details, { show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false })

    for (const key of Object.keys(lybraDocs)) delete lybraDocs[key]
  }

  return {
    world, setWorld, sourceNmapScans,
    authorizedTargets, loadAuthorizedTargets, addAuthorizedTarget, removeAuthorizedTarget,
    activeTab, stats, loadingStats, statsError, scans, launching,
    preview, details,
    viewMode,
    loadStats, loadScans, switchTab, refreshCurrent, goToPage, stopScanPolling,
    launchNmap, launchNikto, launchNuclei,
    launchLybra, loadLybraScans, loadMoreLybraScans, loadSourceNmapScans, deleteLybraScan,
    selectedAssetId, selectAgentAsset, loadAgentScans,
    lybraDocs, loadLybraDocs, generateLybraPdf, deleteLybraDoc,
    deleteScan, cancelScan,
    openPreview, closePreview, refreshPreviewDocs, loadPreviewTraceroute,
    openDetails, closeDetails, refreshDetailsDocs,
    generatePdf, waitForDocument, downloadDocument, deleteDocument,
    setViewMode,
    bulkDeleteScans,
    $reset,
  }
})
