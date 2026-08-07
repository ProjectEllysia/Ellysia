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
  const serverMsg = data.error_description || data.message || data.error
  if (res.status === 403 && (data.error === 'forbidden' || data.error_description === 'Insufficient permissions')) {
    return 'No tienes permisos suficientes para realizar esta acción.'
  }
  return serverMsg || fallback
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

    // ── 402: corte por plan ───────────────────────────────────────────
    // Un solo punto para los catorce sitios que pueden cortar. El cuerpo del
    // 402 es contrato (tope, consumo y cuándo se renueva), así que se puede
    // decir algo útil en vez de "error 402". Se devuelve la respuesta igual:
    // quien llama puede querer reaccionar además del aviso.
    if (res.status === 402) {
      const body = await res.clone().json().catch(() => null)
      const { useToastStore } = await import('@/stores/toastStore')
      useToastStore().show(planLimitMessage(body), 'warn', 6000)
    }

    return res
  }

  /**
   * Traduce el cuerpo de un 402 a algo que un humano entienda.
   *
   * Distingue "tu plan no lo incluye" (se arregla mejorando de plan) de "te
   * has quedado sin cupo" (se arregla esperando al mes que viene), que es la
   * razón de que sean dos códigos distintos y no uno.
   */
  function planLimitMessage(body) {
    const detail = body?.details ?? {}
    if (body?.code === 1902) {
      return 'Tu plan no incluye esta funcionalidad. Puedes verlo en Planes.'
    }
    if (detail.resetsAt) {
      const when = new Date(detail.resetsAt).toLocaleDateString('es-ES', {
        day: 'numeric', month: 'long',
      })
      return `Has alcanzado el límite de tu plan (${detail.used}/${detail.value}). Se renueva el ${when}.`
    }
    if (detail.value != null) {
      return `Has alcanzado el límite de tu plan (${detail.used}/${detail.value}).`
    }
    return body?.error_description || 'Has alcanzado un límite de tu plan.'
  }

  return { apiFetch, apiError }
}
