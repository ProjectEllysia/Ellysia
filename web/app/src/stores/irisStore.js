import { defineStore } from 'pinia'
import { ref, reactive, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { usePolling } from '@/composables/usePolling'
import { useUtils } from '@/composables/useUtils'
import { useToastStore } from '@/stores/toastStore'

export const useIrisStore = defineStore('iris', () => {
  const { apiFetch, apiError } = useApi()
  const { triggerDownload, filenameFromResponse } = useUtils()
  const toast = useToastStore()

  // "Banco de trabajo": los BENCH_SIZE análisis más recientes, siempre por
  // fecha — es lo que muestra IrisHistoryStrip. El histórico completo con
  // filtros/orden vive aparte, en `archive` (ver más abajo), paginado en
  // servidor para no cargar miles de análisis en el navegador.
  const BENCH_SIZE = 5

  const analyses = ref([])
  const loading = ref(false)
  const listError = ref(null)
  const submitting = ref(false)
  const totalCount = ref(0)

  // Umbrales de veredicto (iris.legitimate_threshold/suspicious_threshold),
  // servidos junto a la lista para que el raíl de score del archivo no los
  // hardcodee. Los valores por defecto solo se usan hasta el primer fetch.
  const thresholds = reactive({ legitimate: 80, suspicious: 55 })

  // B13: límites que aplica el servidor (`GET /iris/capabilities`). La vista
  // los necesita para decidir igual que el API en vez de replicar constantes:
  // el tope de tamaño estaba escrito a mano allí y había derivado al doble
  // del real, así que el usuario cargaba en memoria ficheros que el backend
  // iba a rechazar. Se pide una vez y se cachea; si falla, `intake.js` cae a
  // su respaldo y la interfaz sigue siendo usable.
  const capabilities = ref(null)

  const currentId = ref(null)
  const currentReport = reactive({ loading: false, data: null })
  const currentStatus = reactive({ polling: false, status: null, progress: null })
  const pathCache = reactive(new Map())
  const currentPath = reactive({ loading: false, data: null })
  const iocsCache = reactive(new Map())
  const currentIocs = reactive({ loading: false, data: null })
  const aiSummaryLoading = ref(false)

  const documents = ref([])
  const documentsLoading = ref(false)
  // Map de documentId -> poller de usePolling (E8). No reactive: nadie
  // renderiza a partir de él, solo se arranca y se para.
  const documentPollers = new Map()

  let statusPoller = null

  // Fase 2: si hay un mensaje completo (.eml arrastrado) se envía en
  // "message" para que el backend analice cuerpo, enlaces y adjuntos
  // reales; "headers" se mantiene como respaldo cuando solo se pegaron
  // cabeceras a mano.
  async function fetchCapabilities() {
    if (capabilities.value) return capabilities.value
    try {
      capabilities.value = await apiFetch('/iris/capabilities')
    } catch {
      // Silencioso a propósito: no poder leer los límites no impide analizar
      // nada, solo hace que la interfaz use su respaldo. Un toast de error
      // aquí sería ruido por algo que el usuario no puede arreglar.
      capabilities.value = null
    }
    return capabilities.value
  }

  async function submitAnalysis({ headers, message, title } = {}) {
    submitting.value = true
    try {
      const body = message ? { message } : { headers }
      if (title) body.title = title

      const res = await apiFetch('/iris/analyze', {
        method: 'POST',
        body: JSON.stringify(body),
      })
      if (!res) return null
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        toast.show(data.error_description || data.message || 'Error al iniciar el an\u00e1lisis.', 'error')
        return null
      }
      toast.show(`An\u00e1lisis iniciado (ID: ${data.analysisId})`, 'success')
      currentId.value = data.analysisId
      currentReport.data = null
      await fetchResults()
      startPolling(data.analysisId)
      return data.analysisId
    } finally {
      submitting.value = false
    }
  }

  // Siempre página 1, siempre BENCH_SIZE, siempre fecha desc: el bench no
  // pagina ni ordena — eso es el archivo. Antes esta función tomaba
  // `page.value` como valor por defecto, así que cualquier mutación
  // (borrar, cancelar, el polling…) que llamara a `fetchResults()` sin
  // argumentos colapsaba la lista completa a la última página cargada por
  // `fetchMoreResults`. Al no existir ya paginación acumulada en el bench,
  // ese bug queda cerrado por construcción.
  async function fetchResults() {
    loading.value = true
    try {
      const params = new URLSearchParams({ page: 1, per_page: BENCH_SIZE })
      const res = await apiFetch(`/iris/results?${params}`)
      if (!res?.ok) { analyses.value = []; listError.value = 'No se pudieron cargar los análisis.'; return }
      const data = await res.json()
      analyses.value = data.analyses ?? []
      totalCount.value = data.total ?? 0
      if (data.thresholds) Object.assign(thresholds, data.thresholds)
      listError.value = null
    } catch {
      analyses.value = []
      listError.value = 'Error de conexión al cargar los análisis.'
    } finally {
      loading.value = false
    }
  }

  /* ══════════════════════ ARCHIVO (histórico completo) ══════════════════
   * Estado propio, deliberadamente aislado del bench: el archivo pagina,
   * filtra y ordena contra el servidor (ver ResultsQuerySchema), así que
   * nada de esto debe tocar `analyses`/`totalCount` del bench ni viceversa.
   */
  const ARCHIVE_PER_PAGE = 20

  const archive = reactive({
    items: [],
    total: 0,
    page: 1,
    perPage: ARCHIVE_PER_PAGE,
    loading: false,
    error: null,
    filters: { search: '', verdict: '', status: '', source: '' },
    sort: { by: 'date', dir: 'desc' },
  })

  const archiveHasFilters = computed(() => Object.values(archive.filters).some(v => v))

  function _archiveParams() {
    const params = new URLSearchParams({
      page: archive.page, per_page: archive.perPage,
      sort_by: archive.sort.by, sort_dir: archive.sort.dir,
    })
    for (const [key, value] of Object.entries(archive.filters)) {
      if (value) params.set(key, value)
    }
    return params
  }

  async function fetchArchive() {
    archive.loading = true
    try {
      const res = await apiFetch(`/iris/results?${_archiveParams()}`)
      if (!res?.ok) { archive.error = 'No se pudieron cargar los análisis.'; return }
      const data = await res.json()
      archive.items = data.analyses ?? []
      archive.total = data.total ?? 0
      if (data.thresholds) Object.assign(thresholds, data.thresholds)
      archive.error = null
    } catch {
      archive.error = 'Error de conexión al cargar los análisis.'
    } finally {
      archive.loading = false
    }
  }

  /** Aplica un parche de filtros (p.ej. `{ verdict: 'Phishing' }`), vuelve a
   * página 1 y refetchea. Pasar `''` en un campo lo despeja. */
  function setArchiveFilters(patch) {
    Object.assign(archive.filters, patch)
    archive.page = 1
    fetchArchive()
  }

  function resetArchiveFilters() {
    archive.filters = { search: '', verdict: '', status: '', source: '' }
    archive.page = 1
    fetchArchive()
  }

  /** Clic en una cabecera de columna ordenable: si ya se ordenaba por ese
   * campo, invierte la dirección; si no, lo adopta con la dirección más
   * útil por defecto (recientes/mayor score primero, título A→Z). */
  function setArchiveSort(field) {
    if (archive.sort.by === field) {
      archive.sort.dir = archive.sort.dir === 'asc' ? 'desc' : 'asc'
    } else {
      archive.sort.by = field
      archive.sort.dir = field === 'title' ? 'asc' : 'desc'
    }
    archive.page = 1
    fetchArchive()
  }

  function goToArchivePage(pg) {
    archive.page = pg
    fetchArchive()
  }

  async function getReport(id) {
    currentReport.loading = true
    currentReport.data = null
    currentId.value = id
    try {
      const res = await apiFetch(`/iris/results/${id}`)
      if (!res?.ok) {
        if (res?.status === 409) {
          currentReport.loading = false
          return
        }
        toast.show('No se pudo cargar el reporte.', 'error')
        return
      }
      const data = await res.json()
      currentReport.data = data
      stopPolling()
      if (data?.status === 'finished') {
        pathFor(id)
      }
      return data
    } finally {
      currentReport.loading = false
    }
  }

  async function getStatus(id) {
    const params = new URLSearchParams({ id })
    const res = await apiFetch(`/iris/status?${params}`)
    if (!res?.ok) return null
    return await res.json()
  }

  async function pathFor(id) {
    if (!id) return null
    if (pathCache.has(id)) {
      currentPath.loading = false
      currentPath.data = pathCache.get(id)
      return currentPath.data
    }
    currentPath.loading = true
    currentPath.data = null
    try {
      const res = await apiFetch(`/iris/results/${id}/path`)
      if (!res?.ok) {
        currentPath.loading = false
        return null
      }
      const data = await res.json()
      pathCache.set(id, data)
      currentPath.data = data
      return data
    } finally {
      currentPath.loading = false
    }
  }

  /** Indicadores de compromiso (O1): dominios/URLs/IPs/emails extraídos bajo demanda. */
  async function iocsFor(id) {
    if (!id) return null
    if (iocsCache.has(id)) {
      currentIocs.loading = false
      currentIocs.data = iocsCache.get(id)
      return currentIocs.data
    }
    currentIocs.loading = true
    currentIocs.data = null
    try {
      const res = await apiFetch(`/iris/results/${id}/iocs`)
      if (!res?.ok) {
        currentIocs.loading = false
        return null
      }
      const data = await res.json()
      iocsCache.set(id, data)
      currentIocs.data = data
      return data
    } finally {
      currentIocs.loading = false
    }
  }

  // A3: getters de valor ya resuelto — antes IrisReportViewer.vue leía
  // pathCache/currentPath/iocsCache/currentIocs directamente (cachés
  // internos de la estrategia de carga bajo demanda, no la API pública del
  // store). El componente ahora solo conoce estos cuatro getters.
  function resolvedPathFor(id) {
    if (!id) return null
    const cached = pathCache.get(id)
    if (cached) return cached
    return currentPath.data?.analysisId === id ? currentPath.data : null
  }
  function isPathLoadingFor(id) {
    if (!id) return false
    return currentPath.loading && currentPath.data?.analysisId !== id
  }
  function resolvedIocsFor(id) {
    if (!id) return null
    const cached = iocsCache.get(id)
    if (cached) return cached
    return currentIocs.data?.analysisId === id ? currentIocs.data : null
  }
  function isIocsLoadingFor(id) {
    if (!id) return false
    return currentIocs.loading && currentIocs.data?.analysisId !== id
  }

  function startPolling(id) {
    stopPolling()
    currentStatus.polling = true
    currentStatus.status = 'pending'
    currentStatus.progress = 0
    // A 2s fijos son 1800 peticiones/hora contra un límite de 300: diez minutos
    // de análisis agotaban el cupo del usuario. Con backoff, un análisis rápido
    // se sigue notando a los 2s y uno lento se va espaciando hasta 20s.
    statusPoller = usePolling(() => _pollStatus(id), {
      intervalMs: 2000,
      backoffFactor: 1.5,
      maxIntervalMs: 20000,
    })
    statusPoller.start()
  }

  // B10/E8: el re-encadenado y la invalidación de ciclos en vuelo los aporta
  // ahora `usePolling`; aquí solo queda qué pedir y cuándo parar. Devolver
  // `false` es la condición terminal.
  async function _pollStatus(id) {
    const st = await getStatus(id)
    // Sin respuesta no hay novedad: devolver algo que no sea `true` deja que el
    // backoff espacie los reintentos en vez de martillear una API caída.
    if (!st) return undefined

    // `true` solo cuando algo se ha movido de verdad; así el backoff se
    // reinicia al primer avance y se estira mientras el análisis está parado.
    const changed = currentStatus.status !== st.status
      || currentStatus.progress !== (st.progress ?? null)

    currentStatus.status = st.status
    currentStatus.progress = st.progress ?? null

    if (st.status === 'finished') {
      await getReport(id)
      await fetchResults()
      currentStatus.polling = false
      return false
    }
    if (st.status === 'failed' || st.status === 'cancelled') {
      currentReport.data = { status: st.status }
      currentReport.loading = false
      await fetchResults()
      currentStatus.polling = false
      return false
    }
    return changed || undefined
  }

  function stopPolling() {
    statusPoller?.stop()
    statusPoller = null
    currentStatus.polling = false
  }

  /** Re-lanza el análisis con el ruleset actual sobre el mismo correo original. */
  async function reanalyzeAnalysis(id) {
    const res = await apiFetch(`/iris/results/${id}/reanalyze`, { method: 'POST' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo relanzar el análisis.'), 'error')
      return null
    }
    const data = await res.json()
    toast.show(`Reanálisis iniciado (ID: ${data.analysisId})`, 'success')
    await fetchResults()
    selectAnalysis(data.analysisId)
    return data.analysisId
  }

  /**
   * Solicita la narrativa ejecutiva IA (IA1) y sondea el informe hasta que
   * aparece `aiSummary` — no hay endpoint de estado propio, la narrativa es
   * simplemente un campo más del informe principal una vez generada.
   */
  async function generateAiSummary(id) {
    const res = await apiFetch(`/iris/results/${id}/ai-summary`, { method: 'POST' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo generar el resumen IA.'), 'error')
      return false
    }
    toast.show('Generando resumen ejecutivo con IA…', 'success')
    aiSummaryLoading.value = true
    return true
  }

  /**
   * Comprueba una vez si el resumen IA ya está listo. Sin polling automático
   * a propósito: el usuario decide cuándo volver a preguntar, en vez de un
   * setTimeout re-encadenado — deja el terreno listo para sustituir esto por
   * un webhook/push más adelante sin tener que desmontar un poller primero.
   */
  async function checkAiSummary(id) {
    const data = await getReport(id)
    if (data?.aiSummary) {
      aiSummaryLoading.value = false
    } else {
      toast.show('El resumen IA todavía se está generando. Vuelve a comprobar en unos segundos.', 'info')
    }
    return data
  }

  async function cancelAnalysis(id) {
    const res = await apiFetch(`/iris/analyze/${id}/cancel`, { method: 'POST' })
    if (!res?.ok) {
      toast.show('No se pudo cancelar el an\u00e1lisis.', 'error')
      return false
    }
    toast.show('An\u00e1lisis cancelado.', 'success')
    stopPolling()
    await getReport(id)
    await fetchResults()
    return true
  }

  async function deleteAnalysis(id) {
    const res = await apiFetch(`/iris/results/${id}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show('No se pudo eliminar el an\u00e1lisis.', 'error')
      return false
    }
    toast.show('An\u00e1lisis eliminado.', 'success')
    pathCache.delete(id)
    iocsCache.delete(id)
    if (currentId.value === id) {
      currentId.value = null
      currentReport.data = null
      currentPath.data = null
      currentIocs.data = null
    }
    await fetchResults()
    return true
  }

  function selectAnalysis(id) {
    if (currentId.value === id) return
    stopPolling()
    stopDocumentPolling()
    currentReport.data = null
    currentPath.data = null
    currentIocs.data = null
    if (id === null) {
      currentId.value = null
      currentStatus.status = null
      currentStatus.progress = null
      return
    }
    const found = analyses.value.find(a => a.analysisId === id)
    if (found && (found.status === 'pending' || found.status === 'running')) {
      currentId.value = id
      startPolling(id)
    } else if (found && found.status === 'finished') {
      getReport(id)
      pathFor(id)
    } else {
      currentId.value = id
      getReport(id)
      pathFor(id)
    }
  }

  /* ════════════════════════════════ DOCUMENTOS (PDF) ════════════════════ */

  /** Pone en cola la generación del informe PDF de un análisis finalizado. */
  async function generateDocument(analysisId) {
    const res = await apiFetch(`/iris/results/${analysisId}/document`, { method: 'POST' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo generar el informe.'), 'error')
      return null
    }
    const data = await res.json()
    toast.show('Generación de informe iniciada.', 'success')
    await fetchDocuments(analysisId)
    pollDocumentStatus(data.documentId, analysisId)
    return data.documentId
  }

  /** Lista los documentos de un análisis concreto (terminados o no). */
  async function fetchDocuments(analysisId) {
    documentsLoading.value = true
    try {
      const res = await apiFetch(`/iris/results/${analysisId}/documents`)
      if (!res?.ok) { documents.value = []; return }
      const data = await res.json()
      documents.value = data.documents ?? []
    } finally {
      documentsLoading.value = false
    }
  }

  /** Consulta puntual de estado de un documento. */
  async function getDocumentStatus(documentId) {
    const res = await apiFetch(`/iris/document-status?documentId=${documentId}`)
    if (!res?.ok) return null
    return await res.json()
  }

  /** Sondea el estado de un documento en generación hasta que termine.
   *
   * E8: usaba `setInterval`, el idioma que este mismo fichero documenta como
   * incorrecto unas líneas más arriba (B10) — con la petición tardando más
   * de 2 s se solapaban varias. `usePolling` re-encadena. */
  function pollDocumentStatus(documentId, analysisId) {
    if (documentPollers.has(documentId)) return
    const poller = usePolling(async () => {
      const st = await getDocumentStatus(documentId)
      if (!st) return true
      if (st.status === 'done' || st.status === 'error') {
        documentPollers.delete(documentId)
        await fetchDocuments(analysisId)
        return false            // condición terminal: deja de sondear
      }
      return true
    }, { intervalMs: 2000, immediate: false })
    documentPollers.set(documentId, poller)
    poller.start()
  }

  /** Detiene todos los pollings de documentos activos (documento colgado,
   * análisis borrado, o navegación fuera de la vista). */
  function stopDocumentPolling() {
    for (const poller of documentPollers.values()) poller.stop()
    documentPollers.clear()
  }

  /** Descarga un documento PDF por ID. */
  async function downloadDocument(documentId) {
    try {
      const res = await apiFetch(`/iris/document/${documentId}/download`)
      if (!res?.ok) { toast.show('No se pudo descargar el informe.', 'error'); return false }
      const blob = await res.blob()
      const name = filenameFromResponse(res, `iris_analysis_${documentId}.pdf`)
      triggerDownload(blob, name)
      toast.show('Informe descargado.', 'success')
      return true
    } catch (e) {
      toast.show('Error al descargar: ' + e.message, 'error')
      return false
    }
  }

  /** Elimina un documento generado. */
  async function deleteDocument(documentId, analysisId) {
    const res = await apiFetch(`/iris/document/${documentId}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show('No se pudo eliminar el informe.', 'error')
      return false
    }
    toast.show('Informe eliminado.', 'success')
    if (analysisId) await fetchDocuments(analysisId)
    return true
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura) — detiene también el
   * polling de estado y de documentos en curso. */
  function $reset() {
    stopPolling()
    stopDocumentPolling()

    analyses.value = []
    loading.value = false
    listError.value = null
    submitting.value = false
    totalCount.value = 0
    Object.assign(thresholds, { legitimate: 80, suspicious: 55 })
    capabilities.value = null

    archive.items = []
    archive.total = 0
    archive.page = 1
    archive.loading = false
    archive.error = null
    archive.filters = { search: '', verdict: '', status: '', source: '' }
    archive.sort = { by: 'date', dir: 'desc' }

    currentId.value = null
    Object.assign(currentReport, { loading: false, data: null })
    Object.assign(currentStatus, { polling: false, status: null, progress: null })
    pathCache.clear()
    Object.assign(currentPath, { loading: false, data: null })
    iocsCache.clear()
    Object.assign(currentIocs, { loading: false, data: null })
    aiSummaryLoading.value = false

    documents.value = []
    documentsLoading.value = false
  }

  return {
    BENCH_SIZE,
    analyses, loading, listError, submitting, totalCount, thresholds,
    capabilities, fetchCapabilities,
    currentId, currentReport, currentStatus, aiSummaryLoading,
    documents, documentsLoading,
    archive, archiveHasFilters,
    fetchArchive, setArchiveFilters, resetArchiveFilters, setArchiveSort, goToArchivePage,
    submitAnalysis, fetchResults, getReport, getStatus, pathFor, iocsFor,
    resolvedPathFor, isPathLoadingFor, resolvedIocsFor, isIocsLoadingFor,
    generateAiSummary, checkAiSummary,
    cancelAnalysis, deleteAnalysis, reanalyzeAnalysis, selectAnalysis,
    startPolling, stopPolling,
    generateDocument, fetchDocuments, getDocumentStatus, downloadDocument, deleteDocument,
    stopDocumentPolling,
    $reset,
  }
})
