import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de gestión de usuarios — lista, crea y administra atributos ABAC.
 *
 * Sustituye la lógica de users.js (383 líneas de manipulación DOM directa).
 * Centraliza la lista de usuarios, el agrupamiento por rol, y las llamadas
 * a la API para creación y atributos.
 *
 * @module usersStore
 */
export const useUsersStore = defineStore('users', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  /** Lista plana de todos los usuarios */
  const users = ref([])
  /** Carga de usuarios en curso */
  const loading = ref(false)

  /** Usuarios agrupados por rol (root/admin/user) para las secciones de tarjetas */
  const grouped = computed(() => {
    const g = { root: [], admin: [], user: [] }
    for (const u of users.value) {
      const r = u.role || 'role_user'
      if (r === 'role_root') g.root.push(u)
      else if (r === 'role_admin') g.admin.push(u)
      else g.user.push(u)
    }
    return g
  })

  /**
   * Carga la lista completa de usuarios desde GET /users.
   */
  async function loadUsers() {
    loading.value = true
    try {
      const res = await apiFetch('/users')
      if (!res?.ok) { toast.show('Error al cargar usuarios.', 'error'); return }
      const data = await res.json()
      users.value = (data.users || data || []).map(u => ({
        ...u,
        role: u.role || 'role_user',
      }))
    } finally { loading.value = false }
  }

  /**
   * Crea un nuevo usuario vía POST /users/sign-up.
   * @param {object} userData - {username, email, first_name, last_name, password, role?}
   * @returns {Promise<boolean>} True si se creó correctamente
   */
  async function createUser(userData) {
    const res = await apiFetch('/users/sign-up', {
      method: 'POST',
      body: JSON.stringify(userData),
    })
    if (!res?.ok) {
      if (res?.status === 409) toast.show(await apiError(res, 'Usuario o email ya existe.'), 'error')
      else if (res?.status === 403) toast.show('Permisos insuficientes para crear usuarios.', 'error')
      else toast.show(await apiError(res, 'Error al crear usuario.'), 'error')
      return false
    }
    toast.show('Usuario creado exitosamente.', 'success')
    await loadUsers()
    return true
  }

  /**
   * Obtiene los atributos ABAC de un usuario.
   * @param {number|string} userId - ID del usuario
   * @returns {Promise<string[]>} Lista de nombres de atributos
   */
  async function loadUserAttributes(userId) {
    try {
      const res = await apiFetch(`/users/${userId}/attributes`)
      if (!res?.ok) return []
      const data = await res.json()
      return data.attributes ?? data ?? []
    } catch { return [] }
  }

  /** PUT/DELETE /users/{id}/attributes — comparten cuerpo salvo método y mensajes */
  async function _updateAttributes(userId, attrs, method, { errorMsg, successMsg }) {
    const res = await apiFetch(`/users/${userId}/attributes`, {
      method,
      body: JSON.stringify({ attributes: attrs }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, errorMsg), 'error')
      return false
    }
    toast.show(successMsg, 'success')
    return true
  }

  /**
   * Añade atributos a un usuario vía PUT /users/{id}/attributes.
   * @param {number|string} userId - ID del usuario
   * @param {string[]} attrs - Lista de nombres de atributos a añadir
   * @returns {Promise<boolean>}
   */
  function addAttributes(userId, attrs) {
    return _updateAttributes(userId, attrs, 'PUT', {
      errorMsg: 'Error al añadir atributos.',
      successMsg: 'Atributos actualizados.',
    })
  }

  /**
   * Elimina atributos de un usuario vía DELETE /users/{id}/attributes.
   * @param {number|string} userId - ID del usuario
   * @param {string[]} attrs - Lista de nombres de atributos a eliminar
   * @returns {Promise<boolean>}
   */
  function removeAttributes(userId, attrs) {
    return _updateAttributes(userId, attrs, 'DELETE', {
      errorMsg: 'Error al eliminar atributos.',
      successMsg: 'Atributo eliminado.',
    })
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura). */
  function $reset() {
    users.value = []
    loading.value = false
  }

  return { users, loading, grouped, loadUsers, createUser, loadUserAttributes, addAttributes, removeAttributes, $reset }
})
