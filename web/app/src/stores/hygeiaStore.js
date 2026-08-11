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
    inventory: [], inventoryCollectedAt: null, inventoryLoading: false, inventoryError: null,
    // Resumen del último análisis del inventario con Lybra (Fase I). `scanId`
    // nulo = nunca analizado, que es el estado inicial de todo activo, no un
    // error. El desglose completo vive en Themis; aquí solo los recuentos.
    analysis: null, analysisLoading: false, analyzing: false, analysisError: null,
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
  async function createAsset({ hostname, os = null, labels = {}, isPersistent = true }) {
    try {
      const res = await apiFetch('/hygeia/assets', {
        method: 'POST',
        body: JSON.stringify({ hostname, os, labels, isPersistent }),
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

  /**
   * Marca si un activo debería estar siempre encendido o se apaga a propósito.
   *
   * La fila se reemplaza con la que devuelve la API en vez de esperar al
   * siguiente sondeo de `fetchAssets` (uno de cada cuatro ticks): el estado del
   * interruptor tiene que verse en el momento en que se pulsa.
   */
  async function setPersistence(id, isPersistent) {
    try {
      const res = await apiFetch(`/hygeia/assets/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ isPersistent }),
      })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo actualizar el activo.'); return false }
      const asset = await res.json()
      const index = state.assets.findIndex((a) => a.id === id)
      if (index !== -1) state.assets[index] = asset
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /** Selecciona un activo para ver su detalle y carga sus métricas. */
  function selectAsset(id) {
    state.selectedId = id
    state.metrics = []
    state.metricsTruncated = false
    state.metricsError = null
    state.latest = null
    state.latestError = null
    state.inventory = []
    state.inventoryCollectedAt = null
    state.inventoryError = null
    state.analysis = null
    state.analysisError = null
    if (id) { fetchMetrics(id); fetchLatest(id); fetchInventory(id); fetchAnalysis(id) }
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

  /**
   * Carga el último inventario de software conocido del activo dado.
   *
   * No tiene variante `silent`: el inventario solo cambia cada horas (§
   * contrato de ingesta v1.0, cadencia típica 6h), así que no lo toca el
   * sondeo de 15s de la vista — solo la selección de activo y el refresco manual.
   *
   * @param {number} id - Id del activo.
   */
  async function fetchInventory(id) {
    state.inventoryLoading = true
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/inventory`)
      if (state.selectedId !== id) return
      if (!res?.ok) { state.inventoryError = await apiError(res, 'No se pudo cargar el inventario.'); return }
      const data = await res.json()
      state.inventory = data.software ?? []
      state.inventoryCollectedAt = data.collectedAt ?? null
      state.inventoryError = null
    } catch { if (state.selectedId === id) state.inventoryError = 'No se pudo conectar con la API.' }
    finally { if (state.selectedId === id) state.inventoryLoading = false }
  }

  /**
   * Carga el resumen del último análisis de inventario del activo (Fase I).
   *
   * @param {number} id - Id del activo.
   * @param {object} [opts]
   * @param {boolean} [opts.silent=false] - No levanta el flag de carga. Lo usa
   *   el sondeo mientras un análisis está en curso, para no parpadear.
   */
  async function fetchAnalysis(id, { silent = false } = {}) {
    if (!silent) state.analysisLoading = true
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/analysis`)
      // La selección puede haber cambiado mientras la petición volaba.
      if (state.selectedId !== id) return
      if (!res?.ok) { state.analysisError = await apiError(res, 'No se pudo cargar el análisis.'); return }
      state.analysis = await res.json()
      state.analysisError = null
    } catch { if (state.selectedId === id) state.analysisError = 'No se pudo conectar con la API.' }
    finally { if (state.selectedId === id) state.analysisLoading = false }
  }

  /**
   * Lanza un análisis del inventario del activo con el motor Lybra (Fase I).
   *
   * El escaneo corre en la TaskQueue, así que al volver solo hay un id: el
   * sondeo de la vista es quien refresca el resumen hasta que termine.
   *
   * @param {number} id - Id del activo.
   * @returns {Promise<number|null>} Id del escaneo lanzado, o null si falló.
   */
  async function analyzeInventory(id) {
    state.analyzing = true
    try {
      const res = await apiFetch(`/hygeia/assets/${id}/analyze`, { method: 'POST' })
      if (!res?.ok) { state.analysisError = await apiError(res, 'No se pudo lanzar el análisis.'); return null }
      const data = await res.json()
      state.analysisError = null
      await fetchAnalysis(id)
      return data.scanId ?? null
    } catch { state.analysisError = 'No se pudo conectar con la API.'; return null }
    finally { state.analyzing = false }
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
      inventory: [], inventoryCollectedAt: null, inventoryLoading: false, inventoryError: null,
      analysis: null, analysisLoading: false, analyzing: false, analysisError: null,
      lastAgentKey: null,
    })
  }

  return {
    state,
    fetchAssets, createAsset, deleteAsset, rotateKey, setPersistence,
    selectAsset, fetchMetrics, fetchLatest, fetchInventory, clearAgentKey,
    fetchAnalysis, analyzeInventory,
    $reset,
  }
})
