import { defineStore } from 'pinia'
import { reactive } from 'vue'
import { useApi } from '@/composables/useApi'

/**
 * Store del catálogo de etiquetas de Hygeia.
 *
 * Guarda las dos clases juntas, tal como llegan de la API: las de sistema
 * (`tagType: 'system'`, comunes a todo el mundo) y las personales
 * (`tagType: 'user'`). Para asignarlas son intercambiables; solo se
 * distinguen al crear y al borrar, que es cosa exclusiva de las propias.
 *
 * El dueño de los activos sigue siendo `hygeiaStore`: aquí vive el catálogo,
 * allí a qué activo se le ha puesto qué.
 */
export const useHygeiaTagsStore = defineStore('hygeiaTags', () => {
  const { apiFetch, apiError } = useApi()

  const state = reactive({
    tags: [], loading: false, error: null,
  })

  /**
   * Carga el catálogo visible: las de sistema más las del usuario.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.silent=false] - No levanta el flag de carga, para
   *   los refrescos que siguen a una escritura (el catálogo ya está pintado y
   *   no debe parpadear).
   */
  async function fetchTags({ silent = false } = {}) {
    if (!silent) state.loading = true
    try {
      const res = await apiFetch('/hygeia/tags')
      if (!res?.ok) { state.error = await apiError(res, 'No se pudieron cargar las etiquetas.'); return }
      const data = await res.json()
      state.tags = data.tags ?? []
      state.error = null
    } catch { state.error = 'No se pudo conectar con la API.' }
    finally { if (!silent) state.loading = false }
  }

  /**
   * Añade una etiqueta al repositorio personal del usuario.
   *
   * @param {object} tag
   * @param {string} tag.name - Texto de la etiqueta.
   * @param {string} tag.color - Nombre de color de la paleta (ver `tagColors.js`).
   * @returns {Promise<object|null>} La etiqueta creada, o null si falló.
   */
  async function createTag({ name, color = 'slate' }) {
    try {
      const res = await apiFetch('/hygeia/tags', {
        method: 'POST',
        body: JSON.stringify({ name, color }),
      })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo crear la etiqueta.'); return null }
      const tag = await res.json()
      state.tags.push(tag)
      state.error = null
      return tag
    } catch { state.error = 'No se pudo conectar con la API.'; return null }
  }

  /**
   * Borra una etiqueta personal.
   *
   * Se lleva sus asociaciones con los activos, nunca los activos: quien la
   * llevaba se queda, sin ella. De reflejarlo en la lista de activos ya
   * cargada se encarga `hygeiaStore.dropTagFromAssets`.
   *
   * @param {number} id - Id de la etiqueta.
   */
  async function deleteTag(id) {
    try {
      const res = await apiFetch(`/hygeia/tags/${id}`, { method: 'DELETE' })
      if (!res?.ok) { state.error = await apiError(res, 'No se pudo borrar la etiqueta.'); return false }
      state.tags = state.tags.filter((tag) => tag.id !== id)
      state.error = null
      return true
    } catch { state.error = 'No se pudo conectar con la API.'; return false }
  }

  /**
   * Ajusta en local el recuento de activos de una etiqueta.
   *
   * Lo llama la vista tras guardar las etiquetas de un activo, para no tener
   * que recargar el catálogo entero por un número que ya se conoce.
   *
   * @param {number[]} added - Etiquetas que el activo acaba de ganar.
   * @param {number[]} removed - Etiquetas que acaba de perder.
   */
  function adjustCounts(added, removed) {
    for (const tag of state.tags) {
      if (added.includes(tag.id)) tag.assetCount = (tag.assetCount ?? 0) + 1
      if (removed.includes(tag.id)) tag.assetCount = Math.max(0, (tag.assetCount ?? 0) - 1)
    }
  }

  /** Limpia el estado (logout SPA sin recarga dura). */
  function $reset() {
    Object.assign(state, { tags: [], loading: false, error: null })
  }

  return { state, fetchTags, createTag, deleteTag, adjustCounts, $reset }
})
