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

  // Los errores de validación de schema (422) NO traen `error_description`:
  // flask-smorest devuelve {"code":422,"errors":{"json":{"campo":["motivo"]}}}.
  // Sin este caso, cualquier campo mal rellenado en cualquier formulario de la
  // aplicación se veía como el mensaje genérico de quien llamara, y no había
  // forma de saber QUÉ estaba mal.
  const validation = validationMessage(data)
  if (validation) return validation

  const serverMsg = data.error_description || data.message || data.error
  if (res.status === 403 && (data.error === 'forbidden' || data.error_description === 'Insufficient permissions')) {
    return 'No tienes permisos suficientes para realizar esta acción.'
  }
  return serverMsg || fallback
}

/**
 * Etiquetas de los campos que se rellenan a mano.
 *
 * Llevan el artículo incorporado y van en singular a propósito: el mensaje se
 * arma concatenando etiqueta + motivo, y sin artículo sale "Contraseña es
 * obligatorio" — mal de género y de sonido. Con él, cada motivo de abajo encaja
 * con cualquier etiqueta sin tener que concordar nada.
 */
const FIELD_LABELS = {
  username: 'El identificador',
  email: 'El correo',
  first_name: 'El nombre',
  last_name: 'El apellido',
  password: 'La contraseña',
  name: 'El nombre',
  code: 'El código',
  limitKey: 'La clave de límite',
  monthlyPriceCents: 'El precio',
  operation: 'La operación',
  token: 'El token',
}

/**
 * Motivos de Marshmallow, que llegan en inglés, traducidos.
 *
 * Todos están redactados para que funcionen detrás de cualquier etiqueta, sin
 * concordar en género ni número — de ahí "falta por rellenar" en vez de "es
 * obligatorio".
 */
const REASONS = [
  [/Missing data for required field/i, 'falta por rellenar'],
  [/Not a valid email address/i, 'no parece una dirección válida'],
  [/Length must be between (\d+) and (\d+)/i, 'debe tener entre $1 y $2 caracteres'],
  [/Shorter than minimum length (\d+)/i, 'necesita al menos $1 caracteres'],
  [/Longer than maximum length (\d+)/i, 'no puede pasar de $1 caracteres'],
  [/Must be one of: (.+)/i, 'tiene que ser uno de: $1'],
  [/Not a valid integer/i, 'tiene que ser un número'],
  [/Not a valid number/i, 'tiene que ser un número'],
  [/Unknown field/i, 'no se reconoce'],
]

/**
 * Convierte el cuerpo de un 422 en una frase que se pueda leer.
 *
 * Se nombran los campos como los ve quien rellena el formulario, no como se
 * llaman en el schema: "El correo no es una dirección válida" en vez de
 * "email: Not a valid email address".
 *
 * @returns {string|null} El mensaje, o null si esto no era un error de validación.
 */
export function validationMessage(data) {
  const fields = data?.errors?.json ?? data?.errors?.query
  if (!fields || typeof fields !== 'object') return null

  const problems = Object.entries(fields).map(([field, reasons]) => {
    const label = FIELD_LABELS[field] ?? `El campo «${field}»`
    // Se quita el punto final del motivo antes de sustituir: si no, al unir
    // varios problemas salían dos puntos seguidos.
    const raw = String(Array.isArray(reasons) ? reasons[0] : reasons).replace(/\.\s*$/, '')
    for (const [pattern, spanish] of REASONS) {
      if (pattern.test(raw)) return `${label} ${raw.replace(pattern, spanish)}`
    }
    return `${label}: ${raw}`
  })

  if (!problems.length) return null
  return `${problems.join('. ')}.`
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
