import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { decodeLogPayload } from '@/composables/logTransport'

/**
 * Store de lectura del log del sistema.
 *
 * El contenido permanece solo en memoria: es información sensible y no debe
 * sobrevivir a un cambio de sesión en la misma pestaña.
 */
export const useLogsStore = defineStore('logs', () => {
  const { apiFetch, apiError } = useApi()

  const content = ref('')
  const meta = ref(emptyMeta())
  const loading = ref(false)
  const error = ref(null)
  const errorStatus = ref(null)

  // El snapshot lo entrega el backend y se reutiliza al cambiar de página.
  const snapshot = ref('')
  let lastRequestKey = ''
  let etag = null

  /** Carga una página aplicando los filtros recibidos desde la vista. */
  async function loadLogs(filters) {
    const params = new URLSearchParams({
      page: String(filters.page || 1),
      per_page: String(filters.perPage || 100),
      position: filters.position || 'tail',
    })
    if (filters.from) params.set('from', filters.from)
    if (filters.to) params.set('to', filters.to)
    if (filters.level) params.set('level', filters.level)
    if (filters.contains) params.set('contains', filters.contains)
    if (snapshot.value) params.set('snapshot', snapshot.value)

    const requestKey = params.toString()
    const headers = requestKey === lastRequestKey && etag
      ? { 'If-None-Match': etag }
      : {}

    loading.value = true
    error.value = null
    errorStatus.value = null

    try {
      const response = await apiFetch(`/system/logs?${requestKey}`, { headers })

      // `Response.ok` es false para 304, pero ese estado significa que la
      // página actual sigue siendo válida y no hay que borrar su contenido.
      if (response?.status === 304) return true

      if (!response?.ok) {
        errorStatus.value = response?.status ?? null
        error.value = await apiError(response, 'No se pudo cargar el log del sistema.')
        return false
      }

      const data = await response.json()
      content.value = await decodeLogPayload(data)
      meta.value = data
      snapshot.value = data.snapshot || ''
      lastRequestKey = requestKey
      etag = response.headers.get('ETag')
      return true
    } catch (cause) {
      errorStatus.value = null
      error.value = cause instanceof Error
        ? cause.message
        : 'No se pudo leer el contenido comprimido del log.'
      return false
    } finally {
      loading.value = false
    }
  }

  /** Empieza una lectura nueva y descarta el snapshot anterior. */
  function resetSnapshot() {
    snapshot.value = ''
    lastRequestKey = ''
    etag = null
  }

  /** Limpia también el contenido sensible al cerrar sesión. */
  function $reset() {
    content.value = ''
    meta.value = emptyMeta()
    loading.value = false
    error.value = null
    errorStatus.value = null
    resetSnapshot()
  }

  return {
    content,
    meta,
    loading,
    error,
    errorStatus,
    loadLogs,
    resetSnapshot,
    $reset,
  }
})

function emptyMeta() {
  return {
    compression: '',
    encoding: '',
    totalBytes: 0,
    returnedBytes: 0,
    compressedBytes: 0,
    truncated: false,
    totalLines: 0,
    returnedLines: 0,
    page: 1,
    perPage: 100,
    totalPages: 0,
    position: 'tail',
    hasPrevious: false,
    hasNext: false,
    snapshot: '',
    snapshotBytes: 0,
    currentBytes: 0,
    lastModified: '',
    timeZone: '',
    firstLine: null,
    lastLine: null,
  }
}
