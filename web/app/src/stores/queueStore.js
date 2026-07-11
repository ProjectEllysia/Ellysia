import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de gestion de la cola de tareas en segundo plano (TaskQueue / RQ).
 *
 * Consume los endpoints de /system/tasks/* para listar, cancelar
 * y ajustar la configuracion de la cola.
 *
 * @module queueStore
 */
export const useQueueStore = defineStore('queue', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  /** Estado global de la cola (maxWorkers, aliveWorkers, counts) */
  const status = ref({
    maxWorkers: 0,
    aliveWorkers: 0,
    runningCount: 0,
    pendingCount: 0,
    historyCount: 0,
  })

  /** Listas de tareas por tab activo */
  const tasks = ref([])

  /** Carga en curso */
  const loading = ref(false)

  /** Paginacion */
  const currentPage = ref(1)
  const totalCount = ref(0)
  const perPage = ref(20)

  /** Filtro activo */
  const activeTab = ref('running')

  /**
   * Carga el estado global de la cola desde GET /system/tasks/status.
   */
  async function loadStatus() {
    try {
      const res = await apiFetch('/system/tasks/status')
      if (!res?.ok) {
        toast.show('Error al cargar el estado de la cola.', 'error')
        return
      }
      const data = await res.json()
      status.value = data
    } catch {
      toast.show('Error al conectar con la cola.', 'error')
    }
  }

  /**
   * Carga las tareas segun el tab activo y la pagina actual.
   */
  async function loadTasks() {
    loading.value = true
    try {
      const params = new URLSearchParams({
        page: String(currentPage.value),
        per_page: String(perPage.value),
        status: activeTab.value,
      })
      const res = await apiFetch(`/system/tasks?${params}`)
      if (!res?.ok) {
        toast.show('Error al cargar las tareas.', 'error')
        return
      }
      const data = await res.json()
      tasks.value = data.tasks ?? []
      totalCount.value = data.totalCount ?? 0
    } catch {
      toast.show('Error al conectar con la cola.', 'error')
    } finally {
      loading.value = false
    }
  }

  /**
   * Cancela una tarea por su UUID vía POST /system/tasks/{id}/cancel.
   */
  async function cancelTask(taskId) {
    try {
      const res = await apiFetch(`/system/tasks/${taskId}/cancel`, {
        method: 'POST',
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al cancelar la tarea.'), 'error')
        return false
      }
      toast.show('Tarea cancelada.', 'success')
      await loadStatus()
      await loadTasks()
      return true
    } catch {
      toast.show('Error al cancelar la tarea.', 'error')
      return false
    }
  }

  /**
   * Actualiza el numero maximo de workers via PUT /system/tasks/config.
   */
  async function updateMaxWorkers(maxWorkers) {
    try {
      const res = await apiFetch('/system/tasks/config', {
        method: 'PUT',
        body: JSON.stringify({ max_workers: maxWorkers }),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'Error al actualizar configuracion.'), 'error')
        return false
      }
      toast.show(`Workers ajustados a ${maxWorkers}.`, 'success')
      await loadStatus()
      return true
    } catch {
      toast.show('Error al actualizar la configuracion.', 'error')
      return false
    }
  }

  /**
   * Cambia de tab y recarga las tareas.
   */
  function switchTab(tab) {
    activeTab.value = tab
    currentPage.value = 1
    loadTasks()
  }

  /**
   * Cambia de pagina y recarga.
   */
  function goToPage(page) {
    currentPage.value = page
    loadTasks()
  }

  return {
    status,
    tasks,
    loading,
    activeTab,
    currentPage,
    totalCount,
    perPage,
    loadStatus,
    loadTasks,
    cancelTask,
    updateMaxWorkers,
    switchTab,
    goToPage,
  }
})
