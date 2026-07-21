import { defineStore } from 'pinia'
import { ref, reactive, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { useUtils } from '@/composables/useUtils'
import { useToastStore } from '@/stores/toastStore'

export const useIrisStore = defineStore('iris', () => {
  const { apiFetch, apiError } = useApi()
  const { triggerDownload, filenameFromResponse } = useUtils()
  const toast = useToastStore()

  const analyses = ref([])
  const loading = ref(false)
  const listError = ref(null)
  const submitting = ref(false)
  const totalCount = ref(0)
  const page = ref(1)
  const perPage = ref(10)

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
  const documentPollTimers = reactive(new Map())

  let pollTimer = null

  // Fase 2: si hay un mensaje completo (.eml arrastrado) se envía en
  // "message" para que el backend analice cuerpo, enlaces y adjuntos
  // reales; "headers" se mantiene como respaldo cuando solo se pegaron
  // cabeceras a mano.
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

  async function fetchResults(pg = page.value, pp = perPage.value) {
    loading.value = true
    try {
      const params = new URLSearchParams({ page: pg, per_page: pp })
      const res = await apiFetch(`/iris/results?${params}`)
      if (!res?.ok) { analyses.value = []; listError.value = 'No se pudieron cargar los análisis.'; return }
      const data = await res.json()
      analyses.value = data.analyses ?? []
      totalCount.value = data.total ?? 0
      page.value = pg
      listError.value = null
    } catch {
      analyses.value = []
      listError.value = 'Error de conexión al cargar los análisis.'
    } finally {
      loading.value = false
    }
  }

  const loadingMore = ref(false)

  const hasMore = computed(() => analyses.value.length < totalCount.value)

  async function fetchMoreResults() {
    if (loadingMore.value || analyses.value.length >= totalCount.value) return
    loadingMore.value = true
    const nextPage = page.value + 1
    try {
      const params = new URLSearchParams({ page: nextPage, per_page: perPage.value })
      const res = await apiFetch(`/iris/results?${params}`)
      if (!res?.ok) return
      const data = await res.json()
      analyses.value = [...analyses.value, ...(data.analyses ?? [])]
      totalCount.value = data.total ?? totalCount.value
      page.value = nextPage
    } finally {
      loadingMore.value = false
    }
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
    _pollStatus(id)
  }

  // B10: setInterval con callback async no esperaba a que la petición anterior
  // terminara — si getStatus/getReport tardaban más de 2s, podían dispararse
  // varias peticiones solapadas. setTimeout re-encadenado (mismo idioma que
  // traceroute/Themis) garantiza que el siguiente sondeo no arranca hasta que
  // el actual termina. El chequeo de `currentStatus.polling` evita que un
  // ciclo en vuelo se reprograme después de que stopPolling() ya corrió.
  async function _pollStatus(id) {
    const st = await getStatus(id)
    if (!currentStatus.polling) return

    if (!st) {
      pollTimer = setTimeout(() => _pollStatus(id), 2000)
      return
    }

    currentStatus.status = st.status
    currentStatus.progress = st.progress ?? null

    if (st.status === 'finished') {
      await getReport(id)
      await fetchResults()
      stopPolling()
    } else if (st.status === 'failed' || st.status === 'cancelled') {
      currentReport.data = { status: st.status }
      currentReport.loading = false
      await fetchResults()
      stopPolling()
    } else {
      pollTimer = setTimeout(() => _pollStatus(id), 2000)
    }
  }

  function stopPolling() {
    if (pollTimer) {
      clearTimeout(pollTimer)
      pollTimer = null
    }
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

  function goToPage(pg) {
    page.value = pg
    fetchResults()
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

  /** Sondea el estado de un documento en generación hasta que termine. */
  function pollDocumentStatus(documentId, analysisId) {
    if (documentPollTimers.has(documentId)) return
    const timer = setInterval(async () => {
      const st = await getDocumentStatus(documentId)
      if (!st) return
      if (st.status === 'done' || st.status === 'error') {
        clearInterval(documentPollTimers.get(documentId))
        documentPollTimers.delete(documentId)
        await fetchDocuments(analysisId)
      }
    }, 2000)
    documentPollTimers.set(documentId, timer)
  }

  /** Detiene todos los pollings de documentos activos (documento colgado,
   * análisis borrado, o navegación fuera de la vista). */
  function stopDocumentPolling() {
    for (const timer of documentPollTimers.values()) clearInterval(timer)
    documentPollTimers.clear()
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
    page.value = 1
    loadingMore.value = false

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
    analyses, loading, listError, submitting, totalCount, page, perPage, loadingMore, hasMore,
    currentId, currentReport, currentStatus, aiSummaryLoading,
    documents, documentsLoading,
    submitAnalysis, fetchResults, fetchMoreResults, getReport, getStatus, pathFor, iocsFor,
    resolvedPathFor, isPathLoadingFor, resolvedIocsFor, isIocsLoadingFor,
    generateAiSummary, checkAiSummary,
    cancelAnalysis, deleteAnalysis, reanalyzeAnalysis, selectAnalysis, goToPage,
    startPolling, stopPolling,
    generateDocument, fetchDocuments, getDocumentStatus, downloadDocument, deleteDocument,
    stopDocumentPolling,
    $reset,
  }
})
