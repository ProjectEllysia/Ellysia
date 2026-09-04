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
 *
 * C9: GET /system devuelve un ETag de contenido; PUT /system exige que se
 * reenvíe vía cabecera If-Match, y responde 409 si no coincide (otra sesión
 * guardó primero) — evita el last-write-wins silencioso entre dos root/pestañas.
 */
export const useConfigStore = defineStore('config', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()
  const { flatten, unflatten, deepMerge } = useUtils()

  /** Configuración aplanada con claves "section.sub.key" (reactivo para v-model) */
  const configFlat = reactive({})
  /** Copia de la configuración original para el botón de reset */
  let originalFlat = {}
  /** ETag de la última carga/guardado, reenviado como If-Match en el PUT */
  let etag = null
  /** Carga inicial en curso */
  const loading = ref(false)
  /** Guardado en curso */
  const saving = ref(false)
  /** Catálogo de modelos por proveedor de IA, indexado por nombre de estrategia.
   *  Cada entrada es { models, isReachable, error } tal cual la devuelve
   *  GET /system/ai/models. */
  const aiModels = reactive({})
  /** Consulta del catálogo en curso */
  const aiModelsLoading = ref(false)

  /**
   * Carga la configuración desde GET /system y la aplana.
   */
  async function loadConfig() {
    loading.value = true
    try {
      const res = await apiFetch('/system')
      if (!res?.ok) { toast.show('Error al cargar la configuración.', 'error'); return }
      const data = await res.json()
      etag = res.headers.get('ETag')
      const flat = flatten(data)
      Object.assign(configFlat, flat)
      originalFlat = { ...flat }
    } finally { loading.value = false }
  }

  /**
   * Pregunta a cada proveedor de IA qué modelos sirve ahora mismo.
   *
   * Va aparte de `loadConfig` y no bloquea el formulario: son llamadas de red
   * a terceros (OpenAI, Google) que pueden tardar o no responder, y el panel
   * tiene que poder pintarse igual. Mientras no llegue —o si nunca llega— el
   * selector de modelo cae a campo de texto libre.
   */
  async function loadAiModels() {
    aiModelsLoading.value = true
    try {
      const res = await apiFetch('/system/ai/models')
      if (!res?.ok) return
      const data = await res.json()
      for (const row of data.strategies || []) aiModels[row.strategy] = row
    } finally { aiModelsLoading.value = false }
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
        headers: etag ? { 'If-Match': etag } : {},
        body: JSON.stringify(merged),
      })
      if (!res?.ok) {
        if (res?.status === 409) {
          toast.show(
            await apiError(res, 'La configuración cambió desde que la cargaste. Recárgala antes de guardar.'),
            'error',
          )
        } else {
          toast.show(await apiError(res, 'Error al guardar la configuración.'), 'error')
        }
        return false
      }
      etag = res.headers.get('ETag')
      originalFlat = { ...configFlat }
      toast.show('Configuración guardada.', 'success')
      return true
    } finally { saving.value = false }
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura) — configFlat trae
   * toda la config global (root-only), no debe sobrevivir a la sesión. */
  function $reset() {
    for (const key of Object.keys(configFlat)) delete configFlat[key]
    for (const key of Object.keys(aiModels)) delete aiModels[key]
    originalFlat = {}
    etag = null
    loading.value = false
    saving.value = false
  }

  return {
    configFlat, loading, saving, aiModels, aiModelsLoading,
    loadConfig, loadAiModels, resetForm, saveConfig, $reset,
  }
})
