import { defineStore } from 'pinia'
import { reactive } from 'vue'
import { useApi } from '@/composables/useApi'

/**
 * Store de anomalías (alertas) de Hygeia: listado con filtros, reconocimiento
 * y resolución manual.
 */
export const useHygeiaAlertsStore = defineStore('hygeiaAlerts', () => {
  const { apiFetch, apiError } = useApi()

  const state = reactive({
    anomalies: [], loading: false, error: null,
  })

  /** Lista las anomalías del usuario, con filtros opcionales (assetId, state, severity). */
  async function fetchAlerts({ assetId = null, state: anomalyState = null, severity = null } = {}) {
    state.loading = true
    try {
      const params = new URLSearchParams()
      if (assetId) params.set('assetId', assetId)
      if (anomalyState) params.set('state', anomalyState)
      if (severity) params.set('severity', severity)
      const qs = params.toString()
      const res = await apiFetch(`/hygeia/alerts${qs ? `?${qs}` : ''}`)
      if (!res?.ok) { state.error = await apiError(res, 'No se pudieron cargar las alertas.'); return }
      const data = await res.json()
      state.anomalies = data.anomalies ?? []
      state.error = null
    } catch { state.error = 'No se pudo conectar con la API.' }
    finally { state.loading = false }
  }

  /** Reconoce una anomalía (no la resuelve, solo marca que se ha visto). */
  async function ackAlert(id) {
    try {
      const res = await apiFetch(`/hygeia/alerts/${id}/ack`, { method: 'POST' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo reconocer la anomalía.'); return false }
      const updated = await res.json()
      const idx = state.anomalies.findIndex((a) => a.id === id)
      if (idx !== -1) state.anomalies[idx] = updated
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /** Resuelve manualmente una anomalía. */
  async function resolveAlert(id) {
    try {
      const res = await apiFetch(`/hygeia/alerts/${id}/resolve`, { method: 'POST' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo resolver la anomalía.'); return false }
      const updated = await res.json()
      const idx = state.anomalies.findIndex((a) => a.id === id)
      if (idx !== -1) state.anomalies[idx] = updated
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /** Borra una anomalía ya reconocida o resuelta (la API rechaza una abierta). */
  async function deleteAlert(id) {
    try {
      const res = await apiFetch(`/hygeia/alerts/${id}`, { method: 'DELETE' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo borrar la anomalía.'); return false }
      state.anomalies = state.anomalies.filter((a) => a.id !== id)
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /** Limpia el estado (logout SPA sin recarga dura). */
  function $reset() {
    Object.assign(state, { anomalies: [], loading: false, error: null })
  }

  return { state, fetchAlerts, ackAlert, resolveAlert, deleteAlert, $reset }
})
