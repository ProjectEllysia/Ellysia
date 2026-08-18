import { defineStore, getActivePinia } from 'pinia'
import { ref, computed } from 'vue'
import router from '@/router'

/**
 * Clave usada en localStorage para persistir los datos de sesión del usuario.
 * La bóveda de Acheron no se guarda aquí: sus claves y datos descifrados viven
 * únicamente en memoria.
 * @type {string}
 */
const STORAGE_KEY = 'seq_session'

/**
 * Clave en sessionStorage para el motivo de fin de sesión, de forma que
 * sobreviva a la recarga de página que provoca endSession().
 * @type {string}
 */
const REASON_KEY = 'seq_session_end_reason'

/** Margen para renovar el access token antes de que llegue a caducar. */
const TOKEN_REFRESH_MARGIN_MS = 60 * 1000

/**
 * Store de autenticación — gestiona JWT, login, logout y refresh automático.
 *
 * Sustituye al `SeqSession` del legacy (shared.js). Usa Pinia para que los cambios
 * de estado (login, logout, rol) sean reactivos y cualquier componente se entere.
 *
 * @example
 * import { useAuthStore } from '@/stores/authStore'
 * const auth = useAuthStore()
 * auth.login('root', 'root')  // POST /oauth/token, guarda en localStorage
 * auth.isAdmin                 // true si el rol es admin o root
 * auth.username()              // extraído del payload JWT
 */
export const useAuthStore = defineStore('auth', () => {
  /** @type {import('vue').Ref<string|null>} Token JWT de acceso */
  const accessToken = ref(null)
  /** @type {import('vue').Ref<string|null>} Token de refresco */
  const refreshToken = ref(null)
  /** @type {import('vue').Ref<number>} Timestamp UNIX de expiración del access token */
  const expiresAt = ref(0)
  /** @type {import('vue').Ref<string>} Rol del usuario (role_user, role_admin, role_root) */
  const role = ref('role_user')
  /**
   * Motivo por el que terminó la última sesión, para que LoginView muestre un
   * mensaje dedicado. 'password_changed' = la contraseña de acceso cambió.
   * @type {import('vue').Ref<string|null>}
   */
  const sessionEndReason = ref(null)

  /** Promesa del refresco en curso, o null. No es estado reactivo: nadie lo
   *  pinta, solo sirve para que los refrescos concurrentes se fusionen. */
  let _refreshInFlight = null

  /** Motivo detectado durante un refresco de arranque fallido. */
  let _refreshFailureReason = null

  /** @type {import('vue').ComputedRef<boolean>} True si hay un access token vigente */
  const isAuthenticated = computed(() => !!accessToken.value)
  /** @type {import('vue').ComputedRef<boolean>} True si es admin o root */
  const isAdmin = computed(() => role.value === 'role_admin' || role.value === 'role_root')
  /** @type {import('vue').ComputedRef<boolean>} True si es root */
  const isRoot = computed(() => role.value === 'role_root')

  /**
   * Decodifica el payload de un JWT sin verificar la firma.
   * Extrae username, role y demás claims del cuerpo (parte central).
   * @param {string} token - JWT en formato header.payload.signature
   * @returns {object} Payload decodificado, o {} si falla el parseo
   */
  function parseJwt(token) {
    try {
      const encoded = token.split('.')[1]
      if (!encoded) return {}
      const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
      const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
      const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0))
      return JSON.parse(new TextDecoder().decode(bytes))
    } catch {
      return {}
    }
  }

  /**
   * Devuelve la caducidad real declarada por el JWT, en milisegundos.
   * El cliente solo usa este dato para no presentar una sesión obsoleta; la
   * firma y la revocación las sigue comprobando el servidor.
   */
  function jwtExpiresAt(token) {
    const exp = parseJwt(token).exp
    return Number.isFinite(exp) && exp > 0 ? exp * 1000 : 0
  }

  function clearStoredSession() {
    localStorage.removeItem(STORAGE_KEY)
    // Limpia también la ubicación antigua tras una migración o un logout.
    sessionStorage.removeItem(STORAGE_KEY)
  }

  /**
   * Devuelve el nombre de usuario extraído del JWT en memoria.
   * No requiere llamada a la API. Vacío si no hay sesión.
   * @returns {string}
   */
  function username() {
    if (!accessToken.value) return ''
    const payload = parseJwt(accessToken.value)
    return payload.username || payload.sub || ''
  }

  /**
   * Restaura la sesión desde localStorage.
   *
   * Si todavía existe una sesión de una versión anterior en sessionStorage, se
   * migra una sola vez. El JWT se valida localmente antes de aceptarlo; si el
   * access token está caducado, `restoreSession()` intentará renovarlo con el
   * refresh token antes de que el router haga su primera navegación.
   * @returns {boolean} True si se encontró una sesión válida
   */
  function loadFromStorage() {
    let raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) {
      raw = sessionStorage.getItem(STORAGE_KEY)
      if (raw) {
        try {
          localStorage.setItem(STORAGE_KEY, raw)
          sessionStorage.removeItem(STORAGE_KEY)
        } catch {
          // Si el navegador no permite escribir localStorage, se puede usar
          // esta carga una vez sin romper el arranque de la SPA.
        }
      }
    }
    if (!raw) return false
    try {
      const data = JSON.parse(raw)
      if (!data?.accessToken) {
        clearStoredSession()
        return false
      }
      const tokenExpiry = jwtExpiresAt(data.accessToken)
      if (!tokenExpiry) {
        clearStoredSession()
        return false
      }
      accessToken.value = data.accessToken
      refreshToken.value = data.refreshToken || null
      // `expiresAt` es una ayuda de cliente; el claim exp del JWT es la fuente
      // fiable para decidir si hay que renovar el access token.
      expiresAt.value = tokenExpiry
      role.value = data.role || 'role_user'
      return true
    } catch {
      clearStoredSession()
      return false
    }
  }

  /**
   * Persiste el estado actual de la sesión en localStorage.
   * Se llama automáticamente tras login() y refreshAccessToken().
   */
  function saveToStorage() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      accessToken: accessToken.value,
      refreshToken: refreshToken.value,
      expiresAt: expiresAt.value,
      role: role.value,
    }))
    sessionStorage.removeItem(STORAGE_KEY)
  }

  /**
   * Autentica al usuario contra /oauth/token con grant_type password.
   * En caso de éxito, persiste los tokens en localStorage y actualiza
   * el estado reactivo del store. Si la cuenta tiene MFA activado, el
   * servidor no devuelve tokens todavía: devuelve un `challengeToken` que
   * hay que canjear con verifyMfa() tras introducir el código TOTP.
   * @param {string} username - Nombre de usuario
   * @param {string} password - Contraseña
   * @returns {Promise<{mfaRequired: boolean, challengeToken?: string, methods?: string[]}>}
   *          mfaRequired=false si el login se completó (tokens ya guardados);
   *          mfaRequired=true si falta el segundo factor.
   * @throws {Error} Si las credenciales son inválidas, hay rate-limit, o el servidor devuelve error
   * @example
   * const step = await auth.login('root', 'root')
   * if (step.mfaRequired) { await auth.verifyMfa(step.challengeToken, code) }
   */
  async function login(username, password) {
    const res = await fetch('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grantType: 'password', username, password }),
    })
    const data = await res.json()
    if (!res.ok) {
      if (res.status === 401) throw new Error('Credenciales incorrectas.')
      if (res.status === 429) throw new Error('Demasiados intentos. Espera unos minutos.')
      throw new Error(data.error_description || `Error del servidor (${res.status})`)
    }

    if (data.mfaRequired) {
      return { mfaRequired: true, challengeToken: data.challengeToken, methods: data.methods || [] }
    }

    _applyTokens(data)
    return { mfaRequired: false }
  }

  /**
   * Canjea un challenge de MFA (emitido por login() cuando mfaRequired=true)
   * por los tokens reales, aportando un código TOTP o un código de recuperación.
   * @param {string} challengeToken - Token devuelto por login()
   * @param {{code?: string, recoveryCode?: string}} secondFactor - Uno de los dos
   * @throws {Error} Si el código es inválido, el challenge expiró, o hay rate-limit
   * @example await auth.verifyMfa(step.challengeToken, { code: '123456' })
   */
  async function verifyMfa(challengeToken, { code, recoveryCode } = {}) {
    const res = await fetch('/oauth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeToken, code, recoveryCode }),
    })
    const data = await res.json()
    if (!res.ok) {
      if (res.status === 401) throw new Error(data.error_description || 'Código inválido o verificación expirada.')
      if (res.status === 429) throw new Error('Demasiados intentos. Espera unos minutos.')
      throw new Error(data.error_description || `Error del servidor (${res.status})`)
    }
    _applyTokens(data)
  }

  /** Vuelca la respuesta de tokens (login directo o tras verifyMfa) al estado reactivo. */
  function _applyTokens(data) {
    accessToken.value = data.access_token
    refreshToken.value = data.refresh_token
    expiresAt.value = jwtExpiresAt(data.access_token) || Date.now() + data.expires_in * 1000
    role.value = data.role || 'role_user'
    saveToStorage()
  }

  /**
   * Restaura la sesión antes de instalar el router.
   *
   * Un access token caducado no implica necesariamente que haya que pedir las
   * credenciales otra vez: mientras el refresh token siga vigente, se renueva
   * aquí. Si no se puede renovar, se elimina la sesión persistida sin intentar
   * navegar, porque el router todavía no ha empezado su primera navegación.
   * @returns {Promise<boolean>} True si la sesión quedó restaurada.
   */
  async function restoreSession() {
    if (!loadFromStorage()) return false

    const token = await getToken()
    if (token) return true

    const reason = _refreshFailureReason
    accessToken.value = null
    refreshToken.value = null
    expiresAt.value = 0
    role.value = 'role_user'
    sessionEndReason.value = reason
    clearStoredSession()
    if (reason) sessionStorage.setItem(REASON_KEY, reason)
    return false
  }

  /**
   * Obtiene el access token vigente, refrescándolo si está a punto de expirar
   * (menos de 60 segundos restantes). Si el refresco falla o no hay sesión,
   * redirige al login.
   * @returns {Promise<string|null>} Access token, o null si la sesión terminó
   */
  async function getToken() {
    if (!accessToken.value) return null
    if (Date.now() > expiresAt.value - TOKEN_REFRESH_MARGIN_MS) {
      const ok = await refreshAccessToken()
      if (!ok) return null
    }
    return accessToken.value
  }

  /**
   * Renueva el access token mediante /oauth/token con grant_type refresh_token.
   * Actualiza y persiste el nuevo token automáticamente.
   * @returns {Promise<boolean>} True si el refresco fue exitoso
   */
  async function refreshAccessToken() {
    // Un solo refresco en vuelo, compartido por todos los que lo pidan a la vez.
    // Sin esto, cada 401 simultáneo lanzaba el suyo: una vista que carga tres
    // cosas en paralelo gastaba tres de los veinte refrescos por hora que
    // permite /oauth/token, y a la media docena el siguiente recibía un 429.
    // Como un refresco fallido termina en logout(), el limitador de tasa
    // acababa cerrando la sesión y devolviendo al login.
    if (!_refreshInFlight) {
      _refreshInFlight = _doRefresh().finally(() => { _refreshInFlight = null })
    }
    return _refreshInFlight
  }

  async function _doRefresh() {
    _refreshFailureReason = null
    if (!refreshToken.value) return false
    try {
      const res = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grantType: 'refresh_token', refresh_token: refreshToken.value }),
      })
      if (!res.ok) {
        let body = null
        try { body = await res.clone().json() } catch { /* respuesta sin JSON */ }
        if (body?.code === 1609 || body?.error === 'password_changed') {
          _refreshFailureReason = 'password_changed'
        }
        return false
      }
      const data = await res.json()
      if (!data.access_token) return false
      accessToken.value = data.access_token
      expiresAt.value = jwtExpiresAt(data.access_token) || Date.now() + data.expires_in * 1000
      if (data.role) role.value = data.role
      saveToStorage()
      return true
    } catch {
      return false
    }
  }

  /**
   * Limpia el estado del resto de stores tras cerrar sesión (Q6).
   *
   * `pinia.state.value = {}` no basta para los "setup stores" de este
   * proyecto: no limpia los `ref()`/`reactive()` ya vinculados a las
   * plantillas, así que dejaba datos de la sesión anterior visibles hasta
   * el siguiente fetch. Cada store expone su propio `$reset()` (Pinia no lo
   * genera automáticamente para setup stores); aquí solo se orquesta la
   * llamada, sin acoplar authStore a qué stores existen — se itera la
   * instancia activa de Pinia y se resetea cualquiera que lo implemente.
   * `auth`/`toast`/`theme` quedan fuera a propósito: `auth` ya se limpia en
   * las líneas de arriba, y toast/theme son preferencias de dispositivo/UI,
   * no datos de sesión — resetearlas en cada logout sería una regresión de UX.
   */
  function _resetOtherStores() {
    const pinia = getActivePinia()
    pinia?._s.forEach((store, id) => {
      if (id === 'auth') return
      try {
        store.$reset()
      } catch (e) {
        // Pinia expone $reset en todo store, pero para "setup stores" sin
        // implementación propia (toast, theme) el stub por defecto LANZA en
        // vez de ser un no-op — es el caso esperado para esos dos, no un error.
        if (!String(e?.message).includes('does not implement')) {
          console.error(`[Ellysia] $reset() falló en store "${id}":`, e)
        }
      }
    })
  }

  /**
   * Cierra la sesión: revoca el token en el servidor (fire-and-forget),
   * limpia el estado de todos los stores y navega al login por el router
   * (sin recarga dura de página).
   */
  function logout() {
    const token = accessToken.value
    accessToken.value = null
    refreshToken.value = null
    expiresAt.value = 0
    role.value = 'role_user'
    sessionEndReason.value = null
    clearStoredSession()
    if (token) {
      fetch('/oauth/revoke', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      }).catch(() => {})
    }
    _resetOtherStores()
    router.push('/login')
  }

  /**
   * Termina la sesión por un motivo concreto (p.ej. la contraseña de acceso
   * cambió en otro dispositivo). A diferencia de logout(), NO intenta revocar
   * en el servidor (los tokens ya son inválidos) y registra el motivo para que
   * LoginView muestre el mensaje adecuado.
   * @param {string} reason - p.ej. 'password_changed'
   */
  function endSession(reason) {
    accessToken.value = null
    refreshToken.value = null
    expiresAt.value = 0
    role.value = 'role_user'
    sessionEndReason.value = reason || null
    clearStoredSession()
    if (reason) sessionStorage.setItem(REASON_KEY, reason)
    _resetOtherStores()
    router.push('/login')
  }

  /** Consume (lee y limpia) el motivo de fin de sesión persistido. */
  function takeSessionEndReason() {
    const r = sessionStorage.getItem(REASON_KEY) || sessionEndReason.value
    sessionStorage.removeItem(REASON_KEY)
    sessionEndReason.value = null
    return r
  }

  return {
    accessToken, refreshToken, expiresAt, role, sessionEndReason,
    isAuthenticated, isAdmin, isRoot,
    username, loadFromStorage, restoreSession, saveToStorage,
    login, verifyMfa, getToken, logout, refreshAccessToken, endSession, takeSessionEndReason,
  }
})
