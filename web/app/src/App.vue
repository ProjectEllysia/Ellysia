<template>
  <router-view />
  <AppToast />
</template>

<script setup>
// La sesión se restaura en main.js, antes de instalar el router: aquí era
// demasiado tarde, porque la primera navegación (y su guard) ya se había
// resuelto cuando App se montaba.
import { watch } from 'vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useAuthStore } from '@/stores/authStore'
import { useMfaStore } from '@/stores/mfaStore'
import { useToastStore } from '@/stores/toastStore'

const auth = useAuthStore()
const mfa = useMfaStore()
const toast = useToastStore()

let mfaCheckPromise = null
let mfaCheckToken = null

/** Comprueba MFA una vez por entrada de sesión, no en cada cambio de ruta. */
async function notifyIfMfaIsDisabled() {
  const token = auth.accessToken
  if (!token) return
  if (mfaCheckPromise && mfaCheckToken === token) return mfaCheckPromise

  mfaCheckToken = token
  mfaCheckPromise = (async () => {
    try {
      const status = await mfa.loadStatus()
      // El token puede haber sido revocado mientras terminaba la petición. No
      // muestres un aviso de una sesión anterior al usuario siguiente.
      if (auth.accessToken !== token || !status || status.enabled) return
      toast.show(
        'Tu cuenta no tiene activada la autenticación multifactor.',
        'warn',
        10000,
        { label: 'Activar MFA', to: '/profile#mfa' },
      )
    } catch (error) {
      // Un fallo al consultar el estado de seguridad no debe bloquear el SPA.
      console.error('[Ellysia] No se pudo comprobar el estado MFA:', error)
    }
  })().finally(() => {
    if (mfaCheckToken === token) {
      mfaCheckPromise = null
      mfaCheckToken = null
    }
  })

  return mfaCheckPromise
}

watch(() => auth.isAuthenticated, (isAuthenticated) => {
  if (isAuthenticated) void notifyIfMfaIsDisabled()
  else toast.dismiss()
}, { immediate: true })
</script>
