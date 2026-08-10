import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'
import { useCache } from '@/composables/useCache'

const CACHE_KEY = 'me'
const PROFILE_TTL = 5 * 60 * 1000

/**
 * Store de perfil de usuario — carga y actualiza los datos personales.
 *
 * Sustituye la lógica de profile.js (122 líneas de manipulación DOM directa).
 * Centraliza las llamadas GET/PUT de /users/me y el cambio de contraseña.
 * Cachea GET /users/me con TTL de 5min para evitar peticiones redundantes.
 */
export const useProfileStore = defineStore('profile', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()
  const profileCache = useCache({ storage: 'session', keyPrefix: 'profile:', ttl: PROFILE_TTL, maxSize: 20 })

  /** Datos del perfil del usuario autenticado */
  // emailVerified arranca en null y no en false: hasta que el perfil llega
  // no se sabe, y pintar el aviso de "confirma tu correo" a quien ya lo
  // confirmo seria acusarle por un dato que aun no habia cargado.
  const profile = reactive({ first_name: '', last_name: '', email: '', username: '', role: '', created_at: '', emailVerified: null, mustChangePassword: false })
  /** Indicador de carga en curso */
  const loading = ref(false)

  function _hydrate(data) {
    Object.assign(profile, {
      first_name: data.first_name || '',
      last_name: data.last_name || '',
      email: data.email || '',
      username: data.username || '',
      role: data.role || '',
      created_at: data.created_at || '',
      emailVerified: data.emailVerified ?? null,
      mustChangePassword: data.mustChangePassword ?? false,
    })
  }

  function _snapshot() {
    return {
      first_name: profile.first_name,
      last_name: profile.last_name,
      email: profile.email,
      username: profile.username,
      role: profile.role,
      created_at: profile.created_at,
      emailVerified: profile.emailVerified,
      mustChangePassword: profile.mustChangePassword,
    }
  }

  /**
   * Obtiene el perfil del usuario autenticado desde GET /users/me.
   * Usa caché con TTL de 5 minutos para evitar peticiones redundantes.
   */
  async function loadProfile() {
    const cached = profileCache.get(CACHE_KEY)
    if (cached) {
      _hydrate(cached)
      return
    }

    loading.value = true
    try {
      const res = await apiFetch('/users/me')
      if (!res?.ok) return
      const data = await res.json()
      _hydrate(data)
      profileCache.set(CACHE_KEY, _snapshot())
    } finally { loading.value = false }
  }

  /**
   * Actualiza el nombre y apellido del usuario vía PUT /users/me.
   * Actualiza la caché y el estado reactivo sin re-fetch.
   * @param {string} first_name - Nuevo nombre
   * @param {string} last_name - Nuevo apellido
   * @returns {Promise<boolean>} True si se actualizó correctamente
   */
  async function updateProfile(first_name, last_name) {
    const res = await apiFetch('/users/me', {
      method: 'PUT',
      body: JSON.stringify({ first_name, last_name }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'Error al actualizar el perfil.'), 'error')
      return false
    }
    profile.first_name = first_name
    profile.last_name = last_name
    profileCache.set(CACHE_KEY, _snapshot())
    toast.show('Perfil actualizado.', 'success')
    return true
  }

  /**
   * Cambia la contraseña del usuario vía PUT /users/change-password.
   * @param {string} currentPassword - Contraseña actual (el servidor la reverifica)
   * @param {string} newPassword - Nueva contraseña (mín. 8 caracteres)
   * @returns {Promise<boolean>} True si se cambió correctamente
   */
  async function changePassword(currentPassword, newPassword) {
    const res = await apiFetch('/users/change-password', {
      method: 'PUT',
      body: JSON.stringify({ currentPassword, newPassword }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'Error al cambiar la contraseña.'), 'error')
      return false
    }
    toast.show('Contraseña actualizada. Cerrando sesión…', 'success')
    return true
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura). También vacía la
   * caché de sessionStorage (`profile:me`, TTL 5min) — sin esto, un usuario
   * nuevo en la misma pestaña vería el nombre/email del anterior hasta que
   * expirase por su cuenta. */
  function $reset() {
    Object.assign(profile, { first_name: '', last_name: '', email: '', username: '', role: '', created_at: '', emailVerified: null, mustChangePassword: false })
    loading.value = false
    profileCache.clear()
  }

  return { profile, loading, loadProfile, updateProfile, changePassword, $reset }
})
