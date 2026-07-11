import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'
import { useUtils } from '@/composables/useUtils'

/**
 * Store de configuración del sistema — carga/guarda SecOpsConfig.json.
 *
 * Sustituye la lógica de config.js (147 líneas). El JSON anidado del backend
 * se aplana a claves con notación de punto para poder usar v-model directamente
 * en los inputs del formulario. Al guardar se reconstruye el objeto anidado y
 * se envía completo a PUT /system.
 */
export const useConfigStore = defineStore('config', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()
  const { flatten, unflatten, deepMerge } = useUtils()

  /** Configuración aplanada con claves "section.sub.key" (reactivo para v-model) */
  const configFlat = reactive({})
  /** Copia de la configuración original para el botón de reset */
  let originalFlat = {}
  /** Carga inicial en curso */
  const loading = ref(false)
  /** Guardado en curso */
  const saving = ref(false)

  /**
   * Carga la configuración desde GET /system y la aplana.
   */
  async function loadConfig() {
    loading.value = true
    try {
      const res = await apiFetch('/system')
      if (!res?.ok) { toast.show('Error al cargar la configuración.', 'error'); return }
      const data = await res.json()
      const flat = flatten(data)
      Object.assign(configFlat, flat)
      originalFlat = { ...flat }
    } finally { loading.value = false }
  }

  /** Restaura los valores del formulario a la última configuración guardada */
  function resetForm() {
    Object.assign(configFlat, originalFlat)
  }

  /**
   * Guarda la configuración actual vía PUT /system.
   * @returns {Promise<boolean>} True si se guardó correctamente
   */
  async function saveConfig() {
    saving.value = true
    try {
      const merged = deepMerge(unflatten(originalFlat), unflatten({ ...configFlat }))
      const res = await apiFetch('/system', {
        method: 'PUT',
        body: JSON.stringify(merged),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al guardar la configuración.'), 'error')
        return false
      }
      originalFlat = { ...configFlat }
      toast.show('Configuración guardada.', 'success')
      return true
    } finally { saving.value = false }
  }

  return { configFlat, loading, saving, loadConfig, resetForm, saveConfig }
})
