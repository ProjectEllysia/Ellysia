import { useAuthStore } from '@/stores/authStore'
import { setRateLimited } from '@/composables/rateLimitState'

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
 * Peticiones GET idénticas que están ahora mismo en vuelo.
 *
 * Vive fuera de `useApi()` a propósito: cada componente que llama al
 * composable crea su propia instancia, así que un Map por instancia no
 * colapsaría nada. El de aquí lo comparte toda la aplicación.
 *
 * Es el mismo patrón que `authStore` ya usa para el refresco de token
 * (`_refreshInFlight`), y por el mismo motivo que documenta allí: sin esto,
 * una vista que carga tres cosas a la vez gasta tres veces el cupo. ThemisView
 * lanza cuatro peticiones al montar y HygeiaView cinco.
 */
const _inFlight = new Map()

/**
 * Tope para el reintento automático de un 429. Por encima de esta espera no se
 * reintenta solo: se avisa y se devuelve el error, porque bloquear la vista un
 * minuto largo es peor que decir lo que pasa.
 */
const MAX_AUTO_RETRY_SECONDS = 5

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
    // Solo se colapsan los GET: repetir una lectura da el mismo resultado,
    // repetir un POST no. La clave incluye la ruta completa con su query.
    const method = (options.method ?? 'GET').toUpperCase()
    if (method === 'GET' && !_isRetry) {
      const pending = _inFlight.get(path)
      if (pending) {
        // Cada quien necesita poder leer el cuerpo por su cuenta: un Response
        // solo se consume una vez, así que se reparten clones.
        return pending.then(res => (res ? res.clone() : res))
      }
      const promise = _doFetch(path, options, false)
      _inFlight.set(path, promise)
      try {
        const res = await promise
        return res ? res.clone() : res
      } finally {
        _inFlight.delete(path)
      }
    }
    return _doFetch(path, options, _isRetry)
  }

  /** El fetch de verdad, sin la capa de deduplicación. */
  async function _doFetch(path, options = {}, _isRetry = false) {
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

    // ── 429: cupo de peticiones agotado ───────────────────────────────
    // Antes caía en el `return res` de abajo y cada store lo mostraba como su
    // error genérico ("No se pudieron cargar los escaneos"), que es mentira:
    // los escaneos están, lo que falta es cupo. El servidor manda `Retry-After`
    // con los segundos exactos, así que se puede decir la verdad y esperar lo
    // justo en vez de reintentar a ciegas.
    if (res.status === 429) {
      const waitSeconds = retryAfterSeconds(res)
      setRateLimited(waitSeconds)

      // Un solo reintento, y solo si la espera es corta: por encima de eso
      // dejar la pestaña bloqueada esperando es peor que devolver el error.
      if (!_isRetry && waitSeconds > 0 && waitSeconds <= MAX_AUTO_RETRY_SECONDS) {
        await new Promise(r => setTimeout(r, waitSeconds * 1000 + 250))
        return _doFetch(path, options, true)
      }

      const { useToastStore } = await import('@/stores/toastStore')
      useToastStore().show(rateLimitMessage(waitSeconds), 'warn', 6000)
    }

    return res
  }

  /**
   * Segundos que el servidor pide esperar, leídos del `Retry-After`.
   *
   * La cabecera admite dos formatos (RFC 9110 §10.2.3): segundos, o una fecha
   * HTTP. Se aceptan los dos; si no viene ninguna, se asume un minuto, que es
   * la ventana más corta que usa la API.
   */
  function retryAfterSeconds(res) {
    const raw = res.headers.get('Retry-After')
    if (!raw) return 60
    const seconds = Number(raw)
    if (Number.isFinite(seconds)) return Math.max(0, Math.ceil(seconds))
    const date = Date.parse(raw)
    if (Number.isNaN(date)) return 60
    return Math.max(0, Math.ceil((date - Date.now()) / 1000))
  }

  /** El aviso de cupo agotado, con la espera en unidades que se leen bien. */
  function rateLimitMessage(seconds) {
    if (seconds >= 3600) {
      const hours = Math.ceil(seconds / 3600)
      return `Has hecho demasiadas peticiones. Vuelve a intentarlo en ${hours} ${hours === 1 ? 'hora' : 'horas'}.`
    }
    if (seconds >= 60) {
      const minutes = Math.ceil(seconds / 60)
      return `Has hecho demasiadas peticiones. Vuelve a intentarlo en ${minutes} ${minutes === 1 ? 'minuto' : 'minutos'}.`
    }
    return `Has hecho demasiadas peticiones. Vuelve a intentarlo en ${seconds} segundos.`
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
