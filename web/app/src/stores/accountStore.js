import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de la capa comercial: plan efectivo, consumo y organización.
 *
 * El plan NO viaja en el JWT a propósito (ver el §14 del documento de diseño):
 * un cambio de plan tiene que notarse en la siguiente petición, no cuando
 * caduque el token. Por eso se pide al servidor y se guarda aquí.
 *
 * @module accountStore
 */
export const useAccountStore = defineStore('account', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()

  /** Plan efectivo + estado de vigencia (GET /plans/me) */
  const plan = ref(null)
  /** Consumo por clave (GET /plans/me/usage) */
  const usage = ref({})
  /** Organización propia, o null si no pertenece a ninguna */
  const organization = ref(null)
  /** Catálogo público (GET /plans) */
  const catalog = ref([])

  const loading = ref(false)

  /** ¿Hay algo que avisar sobre la suscripción? */
  const notice = computed(() => {
    if (!plan.value) return null
    if (plan.value.status === 'past_due' && plan.value.graceUntil) {
      return {
        kind: 'warn',
        text: `Hay un problema con tu pago. Tu plan sigue activo hasta el ${formatDate(plan.value.graceUntil)}.`,
      }
    }
    if (plan.value.cancelAtPeriodEnd && plan.value.currentPeriodEnd) {
      return {
        kind: 'info',
        text: `Has cancelado tu plan. Seguirá funcionando hasta el ${formatDate(plan.value.currentPeriodEnd)}.`,
      }
    }
    if (plan.value.status && !plan.value.isEffective) {
      return {
        kind: 'warn',
        text: 'Tu plan ha terminado. Estás en el plan gratuito; no se ha borrado nada.',
      }
    }
    return null
  })

  /** Claves por encima de su tope: solo lectura hasta bajar del límite. */
  const exceededKeys = computed(() =>
    Object.entries(usage.value)
      .filter(([, entry]) => entry.exceeded)
      .map(([key]) => key),
  )

  const isOwner = computed(() => organization.value?.isOwner === true)

  function formatDate(iso) {
    if (!iso) return ''
    return new Date(iso).toLocaleDateString('es-ES', {
      day: 'numeric', month: 'long', year: 'numeric',
    })
  }

  /** Catálogo público. No necesita sesión: es la tabla de precios. */
  async function loadCatalog() {
    try {
      const res = await fetch('/plans')
      if (!res.ok) return
      catalog.value = (await res.json()).plans ?? []
    } catch {
      /* la vista muestra su estado vacío */
    }
  }

  async function loadPlan() {
    const res = await apiFetch('/plans/me')
    if (!res?.ok) return
    plan.value = await res.json()
  }

  async function loadUsage() {
    const res = await apiFetch('/plans/me/usage')
    if (!res?.ok) return
    usage.value = (await res.json()).usage ?? {}
  }

  /**
   * Organización propia, o null si no pertenece a ninguna.
   *
   * El endpoint responde 200 con `organization: null` en vez de 404: no estar
   * en ninguna es un estado normal, y con el 404 la mayoría de las cuentas veía
   * un error rojo en la consola en cada carga.
   */
  async function loadOrganization() {
    const res = await apiFetch('/organizations/mine')
    if (!res?.ok) return
    organization.value = (await res.json()).organization ?? null
  }

  /** Todo lo de la cuenta de una vez, para el arranque de la sesión. */
  async function loadAll() {
    loading.value = true
    try {
      await Promise.all([loadPlan(), loadUsage(), loadOrganization()])
    } finally {
      loading.value = false
    }
  }

  async function createOrganization(name) {
    const res = await apiFetch('/organizations', {
      method: 'POST',
      body: JSON.stringify({ name }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudo crear la organización.'), 'error')
      return false
    }
    organization.value = await res.json()
    toast.show('Organización creada.', 'success')
    return true
  }

  function reset() {
    plan.value = null
    usage.value = {}
    organization.value = null
  }

  return {
    plan, usage, organization, catalog, loading,
    notice, exceededKeys, isOwner,
    loadCatalog, loadPlan, loadUsage, loadOrganization, loadAll,
    createOrganization, reset, formatDate,
  }
})
