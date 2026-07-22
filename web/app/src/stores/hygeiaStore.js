import { defineStore } from 'pinia'
import { reactive } from 'vue'
import { useApi } from '@/composables/useApi'

/**
 * Store de activos monitorizados de Hygeia: alta, listado, baja, rotación
 * de clave y serie temporal de métricas del activo seleccionado.
 *
 * `lastAgentKey` guarda la clave de agente en claro justo tras un alta o
 * una rotación — se muestra una única vez en un modal y se descarta con
 * `clearAgentKey()`; nunca se vuelve a pedir al servidor.
 */
export const useHygeiaStore = defineStore('hygeia', () => {
  const { apiFetch, apiError } = useApi()

  const state = reactive({
    assets: [], loading: false, error: null,
    selectedId: null,
    metrics: [], metricsTruncated: false, metricsLoading: false, metricsError: null,
    latest: null, latestError: null,
    lastAgentKey: null,
  })

  /**
   * Carga los activos monitorizados del usuario.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.silent=false] - No levanta el flag de carga. Lo usa
   *   el sondeo periódico de la vista: marcar "cargando" cada pocos segundos
   *   haría parpadear la lista entera en cada refresco.
   */
  async function fetchAssets({ silent = false } = {}) {
    if (!silent) state.loading = true
    try {
      const res = await apiFetch('/hygeia/assets')
      if (!res?.ok) { state.error = await apiError(res, 'No se pudieron cargar los activos.'); return }
      const data = await res.json()
      state.assets = data.assets ?? []
      state.error = null
    } catch { state.error = 'No se pudo conectar con la API.' }
    finally { if (!silent) state.loading = false }
  }

  /** Da de alta un activo. La clave de agente queda en `state.lastAgentKey`, una única vez. */
  async function createAsset({ hostname, os = null, labels = {} }) {
    try {
      const res = await apiFetch('/hygeia/assets', {
        method: 'POST',
        body: JSON.stringify({ hostname, os, labels }),
      })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo dar de alta el activo.'); return null }
      const data = await res.json()
      state.assets.unshift(data.asset)
      state.lastAgentKey = data.agentKey
      return data.asset
    } catch { state.error = 'No se pudo conectar con la API.'; return null }
  }

  /** Da de baja un activo, revocando su clave de agente. */
  async function deleteAsset(id) {
    try {
      const res = await apiFetch(`/hygeia/assets/${id}`, { method: 'DELETE' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo eliminar el activo.'); return false }
      state.assets = state.assets.filter((a) => a.id !== id)
      if (state.selectedId === id) state.selectedId = null
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /** Regenera la clave de agente de un activo. La nueva clave queda en `state.lastAgentKey`. */
  async function rotateKey(id) {
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/rotate-key`, { method: 'POST' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo rotar la clave.'); return null }
      const data = await res.json()
      state.lastAgentKey = data.agentKey
      return data.agentKey
    } catch { state.error = 'No se pudo conectar con la API.'; return null }
  }

  /** Selecciona un activo para ver su detalle y carga sus métricas. */
  function selectAsset(id) {
    state.selectedId = id
    state.metrics = []
    state.metricsTruncated = false
    state.metricsError = null
    state.latest = null
    state.latestError = null
    if (id) { fetchMetrics(id); fetchLatest(id) }
  }

  /**
   * Carga la serie temporal de métricas escalares del activo dado.
   *
   * @param {number} id - Id del activo.
   * @param {object} [opts]
   * @param {boolean} [opts.silent=false] - No levanta el flag de carga (ver `fetchAssets`).
   */
  async function fetchMetrics(id, { silent = false } = {}) {
    if (!silent) state.metricsLoading = true
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/metrics`)
      // La selección puede haber cambiado mientras la petición volaba: sin
      // esta guarda, la respuesta del activo anterior pisaría la del actual.
      if (state.selectedId !== id) return
      if (!res?.ok) { state.metricsError = await apiError(res, 'No se pudieron cargar las métricas.'); return }
      const data = await res.json()
      state.metrics = data.snapshots ?? []
      state.metricsTruncated = data.truncated ?? false
      state.metricsError = null
    } catch { if (state.selectedId === id) state.metricsError = 'No se pudo conectar con la API.' }
    finally { if (!silent) state.metricsLoading = false }
  }

  /**
   * Carga el último heartbeat completo del activo: disco por montaje, red por
   * interfaz, procesos y uso por núcleo — lo que no cabe en la serie temporal.
   *
   * Un activo que aún no ha reportado responde 200 con `metrics: null`, que no
   * es un error: se refleja como ausencia de datos, no como fallo.
   *
   * No tiene variante `silent` como `fetchMetrics`: es un único punto, se
   * pinta en secciones que ya existen y su llegada no hace parpadear nada, así
   * que nunca ha necesitado levantar un flag de carga propio.
   *
   * @param {number} id - Id del activo.
   */
  async function fetchLatest(id) {
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/metrics/latest`)
      if (state.selectedId !== id) return
      if (!res?.ok) { state.latestError = await apiError(res, 'No se pudo cargar el último heartbeat.'); return }
      state.latest = await res.json()
      state.latestError = null
    } catch { if (state.selectedId === id) state.latestError = 'No se pudo conectar con la API.' }
  }

  /** Descarta la clave de agente mostrada — llamar al cerrar el modal de una sola vez. */
  function clearAgentKey() { state.lastAgentKey = null }

  /** Limpia el estado (logout SPA sin recarga dura). */
  function $reset() {
    Object.assign(state, {
      assets: [], loading: false, error: null,
      selectedId: null,
      metrics: [], metricsTruncated: false, metricsLoading: false, metricsError: null,
      latest: null, latestError: null,
      lastAgentKey: null,
    })
  }

  return {
    state,
    fetchAssets, createAsset, deleteAsset, rotateKey,
    selectAsset, fetchMetrics, fetchLatest, clearAgentKey,
    $reset,
  }
})
