import { useAuthStore } from '@/stores/authStore'

/**
 * Extrae un mensaje de error legible de una respuesta fallida (D3/B11).
 *
 * Antes cada store repetía `const data = await res?.json().catch(() => ({}))`
 * seguido de `data.error_description || data.message`: si `res` era `null`
 * (apiFetch devuelve null en error de red o sesión caída), `res?.json()`
 * cortocircuitaba TODA la cadena a `undefined` — `data` quedaba `undefined`
 * y `data.message` lanzaba un `TypeError` silencioso (atrapado por el
 * try/catch exterior, pero ocultando el mensaje real).
 *
 * @param {Response|null} res - Lo que devolvió `apiFetch` (puede ser null)
 * @param {string} fallback - Mensaje a usar si no hay `res` o su cuerpo no trae uno
 * @returns {Promise<string>}
 */
export async function apiError(res, fallback) {
  if (!res) return fallback
  const data = await res.json().catch(() => ({}))
  return data.error_description || data.message || data.error || fallback
}

/**
 * Composable para llamadas autenticadas a la API REST.
 *
 * Inyecta automáticamente el header Authorization con el JWT vigente
 * (refrescándolo si está próximo a expirar). Si el servidor responde
 * con 401, intenta refrescar el token y rehacer la petición una vez.
 * Si el refresco falla, redirige al login.
 *
 * @example
 * import { useApi } from '@/composables/useApi'
 * const { apiFetch } = useApi()
 * const res = await apiFetch('/iris/analyze', { method: 'POST', body: '...' })
 * const data = await res.json()
 *
 * @returns {{ apiFetch: (path: string, options?: object) => Promise<Response|null> }}
 */
export function useApi() {
  const auth = useAuthStore()

  /**
   * Wrapper autenticado sobre fetch con re-intento en 401.
   *
   * @param {string} path - Ruta de la API (ej: '/iris/analyze')
   * @param {object} [options={}] - Opciones de fetch (method, body, headers)
   * @param {boolean} [_isRetry=false] - Interno: true si es un re-intento
   * @returns {Promise<Response|null>} Response, o null sin sesión / error de red
   */
  async function apiFetch(path, options = {}, _isRetry = false) {
    const token = await auth.getToken()
    if (!token) {
      auth.logout()
      return null
    }

    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    }

    if (options.body instanceof FormData) {
      delete headers['Content-Type']
    }

    let res
    try {
      res = await fetch(path, { ...options, headers })
    } catch (e) {
      console.error('[Ellysia] apiFetch error:', e)
      return null
    }

    // ── 401 handling ──────────────────────────────────────────────────
    if (res.status === 401) {
      // ¿La sesión cayó porque la contraseña de acceso cambió? → pantalla dedicada
      let body = null
      try {
        body = await res.clone().json()
      } catch {
        /* cuerpo no-JSON: ignorar */
      }
      if (body && (body.code === 1609 || body.error === 'password_changed')) {
        auth.endSession('password_changed')
        return null
      }

      // 401 genérico: refrescar el token una vez y reintentar.
      if (!_isRetry) {
        const refreshed = await auth.refreshAccessToken()
        if (!refreshed) {
          auth.logout()
          return null
        }
        return apiFetch(path, options, true)
      }

      auth.logout()
      return null
    }

    return res
  }

  return { apiFetch, apiError }
}
