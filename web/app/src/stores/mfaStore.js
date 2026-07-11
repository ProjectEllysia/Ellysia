import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de MFA (TOTP) — inscripción, confirmación y desactivación del
 * segundo factor del usuario autenticado. Espejo de profileStore.js.
 *
 * Flujo de activación: setupTotp() (genera QR) → el usuario escanea con su
 * app autenticadora → confirmTotp(code) (confirma y devuelve los códigos
 * de recuperación, que solo se muestran una vez).
 */
export const useMfaStore = defineStore('mfa', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  /** Estado de MFA del usuario autenticado */
  const status = reactive({ enabled: false, confirmedAt: null })
  /** Datos de una inscripción en curso (no confirmada aún) */
  const pendingSetup = reactive({ secret: '', provisioningUri: '' })
  const loading = ref(false)

  /** Consulta GET /users/mfa y actualiza el estado reactivo. */
  async function loadStatus() {
    loading.value = true
    try {
      const res = await apiFetch('/users/mfa')
      if (!res?.ok) return
      const data = await res.json()
      status.enabled = data.enabled
      status.confirmedAt = data.confirmedAt
    } finally { loading.value = false }
  }

  /**
   * Inicia la inscripción TOTP vía POST /users/mfa/totp/setup.
   * @returns {Promise<boolean>} True si se generó el secreto/QR correctamente.
   */
  async function setupTotp() {
    const res = await apiFetch('/users/mfa/totp/setup', { method: 'POST' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo iniciar la activación de MFA.'), 'error')
      return false
    }
    const data = await res.json()
    pendingSetup.secret = data.secret
    pendingSetup.provisioningUri = data.provisioningUri
    return true
  }

  /**
   * Confirma la inscripción con el primer código TOTP vía
   * POST /users/mfa/totp/confirm.
   * @param {string} code - Código de 6 dígitos de la app autenticadora
   * @returns {Promise<string[]|null>} Los códigos de recuperación (una sola vez), o null si falló
   */
  async function confirmTotp(code) {
    const res = await apiFetch('/users/mfa/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'Código inválido.'), 'error')
      return null
    }
    const data = await res.json()
    status.enabled = true
    status.confirmedAt = new Date().toISOString()
    pendingSetup.secret = ''
    pendingSetup.provisioningUri = ''
    toast.show('MFA activado correctamente.', 'success')
    return data.recoveryCodes
  }

  /**
   * Desactiva MFA vía DELETE /users/mfa/totp. Requiere un código TOTP vigente
   * o un código de recuperación como confirmación.
   * @param {{code?: string, recoveryCode?: string}} secondFactor
   * @returns {Promise<boolean>} True si se desactivó correctamente.
   */
  async function disableTotp({ code, recoveryCode } = {}) {
    const res = await apiFetch('/users/mfa/totp', {
      method: 'DELETE',
      body: JSON.stringify({ code, recoveryCode }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'Código inválido.'), 'error')
      return false
    }
    status.enabled = false
    status.confirmedAt = null
    toast.show('MFA desactivado.', 'success')
    return true
  }

  /** Cancela una inscripción en curso sin llamar a la API (el setup sin confirmar es inofensivo). */
  function cancelSetup() {
    pendingSetup.secret = ''
    pendingSetup.provisioningUri = ''
  }

  return { status, pendingSetup, loading, loadStatus, setupTotp, confirmTotp, disableTotp, cancelSetup }
})
