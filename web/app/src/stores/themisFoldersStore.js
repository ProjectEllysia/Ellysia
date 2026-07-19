import { defineStore } from 'pinia'
import { reactive } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de carpetas de Themis (A2: extraído de themisStore).
 *
 * Único punto de acoplamiento real con el store de escaneos: cuando se
 * borra/cancela un escaneo desde la tabla principal, ese store necesita
 * poder localizar (y actualizar) la copia del mismo escaneo dentro de una
 * carpeta — por eso `findScanInFolders` se expone como API pública en vez
 * de quedarse como helper privado.
 */
export const useThemisFoldersStore = defineStore('themisFolders', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  const folders = reactive({ items: [], loading: false, error: null })
  const folderForms = reactive({
    create: { show: false, submitting: false },
    rename: { show: false, folderId: null, name: '', submitting: false },
  })
  const moveScan = reactive({ show: false, scanId: null, folderId: null, submitting: false })

  /** Busca un escaneo por ID en todas las carpetas (incluyendo unfoldered). Retorna { folder, idx } o null. */
  function findScanInFolders(scanId) {
    for (const folder of folders.items) {
      const idx = (folder.scans || []).findIndex(s => s.id === scanId)
      if (idx !== -1) return { folder, idx }
    }
    return null
  }

  /** Busca una carpeta por ID. */
  function _findFolder(folderId) {
    return folders.items.find(f => f.id === folderId)
  }

  /** Obtiene (o crea) la pseudo-carpeta unfoldered. Siempre la sitúa primera. */
  function _getUnfoldered() {
    let unf = folders.items.find(f => f.id === null)
    if (!unf) {
      unf = { id: null, name: 'Sin carpeta', scans: [], scanCount: 0 }
      folders.items.unshift(unf)
    }
    return unf
  }

  async function loadFolders() {
    folders.loading = true
    try {
      const res = await apiFetch('/themis/folders')
      if (!res?.ok) { folders.items = []; folders.error = 'No se pudieron cargar las carpetas.'; return }
      const data = await res.json()
      folders.items = data.folders ?? []
      // Append the virtual unfoldered group as a folder-like entry
      if (data.unfoldered) folders.items.push(data.unfoldered)
      folders.error = null
    } catch { folders.items = []; folders.error = 'Error de conexión.' }
    finally { folders.loading = false }
  }

  async function createFolder(name) {
    folderForms.create.submitting = true
    try {
      const res = await apiFetch('/themis/folders', { method: 'POST', body: JSON.stringify({ name }) })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al crear la carpeta.'), 'error')
        return false
      }
      const data = await res.json()
      const now = new Date().toISOString()
      folders.items.splice(folders.items.findIndex(f => f.id === null) + 1, 0, {
        id: data.folderId, name, scans: [], scanCount: 0, createdAt: now, updatedAt: now,
      })
      toast.show(`Carpeta "${name}" creada`, 'success')
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { folderForms.create.submitting = false }
  }

  async function renameFolder(folderId, name) {
    folderForms.rename.submitting = true
    try {
      const res = await apiFetch(`/themis/folders/${folderId}`, {
        method: 'PUT',
        body: JSON.stringify({ name }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al renombrar la carpeta.'), 'error')
        return false
      }
      const folder = _findFolder(folderId)
      if (folder) folder.name = name
      toast.show('Carpeta renombrada', 'success')
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { folderForms.rename.submitting = false }
  }

  async function deleteFolder(folderId) {
    const res = await apiFetch(`/themis/folders/${folderId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar la carpeta.', 'error'); return false }

    const idx = folders.items.findIndex(f => f.id === folderId)
    if (idx !== -1) {
      const folder = folders.items[idx]
      if (folder.scans?.length) {
        const unf = _getUnfoldered()
        unf.scans.push(...folder.scans)
        unf.scanCount = (unf.scanCount || 0) + folder.scans.length
      }
      folders.items.splice(idx, 1)
    }

    toast.show('Carpeta eliminada.', 'success')
    return true
  }

  async function moveScanToFolder(scanId, folderId) {
    moveScan.submitting = true
    try {
      const res = await apiFetch(`/themis/folders/${folderId}/scans`, {
        method: 'POST',
        body: JSON.stringify({ scanId }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al mover el escaneo.'), 'error')
        return false
      }
      toast.show('Escaneo movido a la carpeta.', 'success')
      await loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { moveScan.submitting = false }
  }

  async function removeScanFromFolder(scanId, folderId) {
    const res = await apiFetch(`/themis/folders/${folderId}/scans/${scanId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo quitar el escaneo de la carpeta.', 'error'); return false }

    const folder = _findFolder(folderId)
    if (folder) {
      const idx = (folder.scans || []).findIndex(s => s.id === scanId)
      if (idx !== -1) {
        const [scan] = folder.scans.splice(idx, 1)
        folder.scanCount = Math.max(0, (folder.scanCount || 0) - 1)
        const unf = _getUnfoldered()
        unf.scans.push(scan)
        unf.scanCount = (unf.scanCount || 0) + 1
      }
    }

    toast.show('Escaneo eliminado de la carpeta.', 'success')
    return true
  }

  async function addScansToFolder(scanIds, folderId) {
    try {
      const res = await apiFetch(`/themis/folders/${folderId}/scans/batch`, {
        method: 'POST',
        body: JSON.stringify({ scanIds }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al añadir escaneos a la carpeta.'), 'error')
        return false
      }
      toast.show(`${scanIds.length} escaneo(s) añadido(s) a la carpeta.`, 'success')
      await loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    }
  }

  function openMoveScan(scanId, currentFolderId) {
    moveScan.show = true
    moveScan.scanId = scanId
    moveScan.folderId = currentFolderId
  }

  function closeMoveScan() {
    moveScan.show = false
    moveScan.scanId = null
    moveScan.folderId = null
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura). */
  function $reset() {
    Object.assign(folders, { items: [], loading: false, error: null })
    Object.assign(folderForms, {
      create: { show: false, submitting: false },
      rename: { show: false, folderId: null, name: '', submitting: false },
    })
    Object.assign(moveScan, { show: false, scanId: null, folderId: null, submitting: false })
  }

  return {
    folders, folderForms, moveScan,
    findScanInFolders,
    loadFolders, createFolder, renameFolder, deleteFolder,
    moveScanToFolder, removeScanFromFolder, addScansToFolder,
    openMoveScan, closeMoveScan,
    $reset,
  }
})
