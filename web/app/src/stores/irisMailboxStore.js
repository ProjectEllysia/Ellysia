import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

export const useIrisMailboxStore = defineStore('irisMailbox', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  const providers = ref([])
  const connections = ref([])
  const loading = ref(false)
  const listError = ref(null)
  const connecting = ref(false)
  // IDs de conexión con un sondeo manual en curso — alimenta el estado de
  // "ocupado" por fila (antes no existía ninguno) mientras se espera a que
  // el worker de iris.ingest, que corre aparte, termine de verdad.
  const syncingIds = reactive(new Set())

  async function fetchProviders() {
    const res = await apiFetch('/iris/mailbox/providers')
    if (!res?.ok) return
    const data = await res.json()
    providers.value = data.providers ?? []
  }

  async function fetchConnections() {
    loading.value = true
    try {
      const res = await apiFetch('/iris/mailbox/connections')
      if (!res?.ok) { connections.value = []; listError.value = 'No se pudieron cargar las conexiones.'; return }
      const data = await res.json()
      connections.value = data.connections ?? []
      listError.value = null
    } catch {
      connections.value = []
      listError.value = 'Error de conexión al cargar las conexiones de buzón.'
    } finally {
      loading.value = false
    }
  }

  /**
   * Inicia el flujo OAuth: pide la URL de autorización y navega la página
   * completa a Google/Microsoft. Redirect de página completa (no popup)
   * porque el backend ya cierra el flujo con un redirect de servidor tras
   * el callback (`GET /iris/mailbox/callback` -> vuelve aquí) -- no hace
   * falta postMessage ni gestión de ventanas.
   */
  async function connect(provider) {
    connecting.value = true
    try {
      const res = await apiFetch('/iris/mailbox/connect', {
        method: 'POST',
        body: JSON.stringify({ provider }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo iniciar la conexión.'), 'error')
        return
      }
      const data = await res.json()
      window.location.href = data.authorizeUrl
    } finally {
      connecting.value = false
    }
  }

  async function updateConnection(id, { folder, status } = {}) {
    const body = {}
    if (folder !== undefined) body.folder = folder
    if (status !== undefined) body.status = status
    const res = await apiFetch(`/iris/mailbox/connections/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo actualizar la conexión.'), 'error')
      return false
    }
    toast.show('Conexión actualizada.', 'success')
    await fetchConnections()
    return true
  }

  async function deleteConnection(id) {
    const res = await apiFetch(`/iris/mailbox/connections/${id}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo eliminar la conexión.'), 'error')
      return false
    }
    toast.show('Conexión eliminada.', 'success')
    connections.value = connections.value.filter((c) => c.connectionId !== id)
    return true
  }

  /**
   * Antes esta función no refetcheaba nunca — "Sondear ahora" parecía no
   * hacer nada porque `lastSyncAt` en la lista se quedaba congelado hasta
   * la próxima recarga manual de la página. El sondeo real corre en un
   * worker de `iris.ingest` aparte (encolado, no síncrono con este POST),
   * así que una única foto inmediata normalmente todavía no lo refleja:
   * se refetchea una vez al encolar y una segunda vez tras un margen para
   * capturar el resultado real, y `syncingIds` da al usuario una señal
   * visual de que algo está en marcha durante ese margen.
   */
  async function syncConnection(id) {
    syncingIds.add(id)
    try {
      const res = await apiFetch(`/iris/mailbox/connections/${id}/sync`, { method: 'POST' })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo sincronizar la conexión.'), 'error')
        return false
      }
      toast.show('Sincronización en cola.', 'success')
      await fetchConnections()
      setTimeout(() => { fetchConnections() }, 3000)
      return true
    } finally {
      setTimeout(() => { syncingIds.delete(id) }, 3000)
    }
  }

  function $reset() {
    providers.value = []
    connections.value = []
    loading.value = false
    listError.value = null
    connecting.value = false
    syncingIds.clear()
  }

  return {
    providers, connections, loading, listError, connecting, syncingIds,
    fetchProviders, fetchConnections, connect, updateConnection, deleteConnection, syncConnection,
    $reset,
  }
})
