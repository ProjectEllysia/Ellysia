import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * Clave usada en sessionStorage para persistir los datos de sesión.
 * @type {string}
 */
const STORAGE_KEY = 'seq_session'

/**
 * Clave en sessionStorage para el motivo de fin de sesión, de forma que
 * sobreviva a la recarga de página que provoca endSession().
 * @type {string}
 */
const REASON_KEY = 'seq_session_end_reason'

/**
 * Store de autenticación — gestiona JWT, login, logout y refresh automático.
 *
 * Sustituye al `SeqSession` del legacy (shared.js). Usa Pinia para que los cambios
 * de estado (login, logout, rol) sean reactivos y cualquier componente se entere.
 *
 * @example
 * import { useAuthStore } from '@/stores/authStore'
 * const auth = useAuthStore()
 * auth.login('root', 'admin')  // POST /oauth/token, guarda en sessionStorage
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
      return JSON.parse(atob(token.split('.')[1]))
    } catch {
      return {}
    }
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
   * Restaura la sesión desde sessionStorage.
   * Se llama en App.vue al montar la aplicación.
   * @returns {boolean} True si se encontró una sesión válida
   */
  function loadFromStorage() {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return false
    try {
      const data = JSON.parse(raw)
      if (!data?.accessToken) return false
      accessToken.value = data.accessToken
      refreshToken.value = data.refreshToken
      expiresAt.value = data.expiresAt
      role.value = data.role || 'role_user'
      return true
    } catch {
      return false
    }
  }

  /**
   * Persiste el estado actual de la sesión en sessionStorage.
   * Se llama automáticamente tras login() y refreshAccessToken().
   */
  function saveToStorage() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
      accessToken: accessToken.value,
      refreshToken: refreshToken.value,
      expiresAt: expiresAt.value,
      role: role.value,
    }))
  }

  /**
   * Autentica al usuario contra /oauth/token con grant_type password.
   * En caso de éxito, persiste los tokens en sessionStorage y actualiza
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
   * const step = await auth.login('root', 'admin')
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
    expiresAt.value = Date.now() + data.expires_in * 1000
    role.value = data.role || 'role_user'
    saveToStorage()
  }

  /**
   * Obtiene el access token vigente, refrescándolo si está a punto de expirar
   * (menos de 60 segundos restantes). Si el refresco falla o no hay sesión,
   * redirige al login.
   * @returns {Promise<string|null>} Access token, o null si la sesión terminó
   */
  async function getToken() {
    if (!accessToken.value) return null
    if (Date.now() > expiresAt.value - 60000) {
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
    if (!refreshToken.value) return false
    try {
      const res = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grantType: 'refresh_token', refresh_token: refreshToken.value }),
      })
      if (!res.ok) return false
      const data = await res.json()
      accessToken.value = data.access_token
      expiresAt.value = Date.now() + data.expires_in * 1000
      saveToStorage()
      return true
    } catch {
      return false
    }
  }

  /**
   * Cierra la sesión: revoca el token en el servidor (fire-and-forget),
   * limpia el estado y el sessionStorage, y redirige al login.
   */
  function logout() {
    const token = accessToken.value
    accessToken.value = null
    refreshToken.value = null
    expiresAt.value = 0
    role.value = 'role_user'
    sessionEndReason.value = null
    sessionStorage.removeItem(STORAGE_KEY)
    if (token) {
      fetch('/oauth/revoke', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      }).catch(() => {})
    }
    window.location.href = '/login'
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
    sessionStorage.removeItem(STORAGE_KEY)
    // Persistir el motivo: window.location.href recarga la página y reinicia el
    // store, así que el ref en memoria se perdería.
    if (reason) sessionStorage.setItem(REASON_KEY, reason)
    window.location.href = '/login'
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
    username, loadFromStorage, saveToStorage,
    login, verifyMfa, getToken, logout, refreshAccessToken, endSession, takeSessionEndReason,
  }
})
