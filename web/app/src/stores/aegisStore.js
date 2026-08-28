import { defineStore } from 'pinia'
import { computed, reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useCache } from '@/composables/useCache'
import { useUtils } from '@/composables/useUtils'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de Aegis — generación de píldoras de concienciación con IA.
 *
 * Sustituye la lógica dispersa en aegis.js (521 líneas). Centraliza los
 * temas, marcas, documentos, tweaks de generación, historial, visor y el
 * perfil de organización (valores estables precargados en cada generación).
 */
export const useAegisStore = defineStore('aegis', () => {
  const { apiFetch, apiError } = useApi()
  const toast = useToastStore()
  const { triggerDownload, filenameFromResponse } = useUtils()

  /** Caché de documentos del visor (evita re-fetch al navegar entre documentos ya vistos) */
  const docCache = useCache({ keyPrefix: 'aegis:doc:', maxSize: 50 })

  /** Lista de temas disponibles */
  const topics = ref([])
  /** Documentos del historial del usuario */
  const documents = ref([])
  const listError = ref(null)
  /** Tema seleccionado para generación */
  const selectedTopicId = ref(null)
  /** Documento actualmente en el visor */
  const currentDocId = ref(null)
  /** Modo de ordenación del historial */
  const sortMode = ref('date-desc')
  /** Productos vigilados: pares { vendor, product } del índice CPE */
  const trackedProducts = ref([])
  /** Deducir los productos del inventario de los agentes de Hygeia */
  const useHygeiaInventory = ref(true)
  /** Si el usuario tiene algún agente con inventario (decide si se ofrece) */
  const hygeiaInventoryAvailable = ref(false)
  /** Ajustes de white-labeling del perfil (v-model de WhiteLabelFields).
      `ref` y no `reactive`: el componente emite un objeto nuevo en cada
      cambio, y a un `reactive` del store no se le puede reasignar. */
  const whiteLabel = ref({ level: 'none', logo: '', color: '' })
  /** Nivel máximo que concede el plan contratado; lo dicta el servidor */
  const maxWhiteLabelLevel = ref('none')
  /** Resultados del buscador de productos */
  const productResults = ref([])
  /** Búsqueda de productos en curso */
  const searchingProducts = ref(false)
  /**
   * Motivo por el que la última búsqueda no devolvió nada, cuando no fue
   * porque el catálogo no tuviera coincidencias. Cadena vacía si fue bien.
   */
  const productSearchError = ref('')
  /** Generación en curso */
  const generating = ref(false)
  /** Último fallo de generación, para pintarlo donde ocurrió y no solo en un
      toast que se desvanece. `null` cuando no hay ninguno. */
  const generateError = ref(null)
  /** Carga de historial en curso */
  const loading = ref(false)
  /** Modo edición del documento en el visor */
  const editing = ref(false)
  /** Guardado de edición en curso */
  const saving = ref(false)
  /** Carga del perfil de organización en curso */
  const loadingOrgProfile = ref(false)
  /** Guardado del perfil de organización en curso */
  const savingOrgProfile = ref(false)

  /** Parámetros de generación (tweaks) */
  const tweaks = reactive({
    company: '',
    language: 'es',
    tone: 'profesional',
    audienceLevel: 'mixed',
    mentionContact: '',
    sector: '',
    topicFocus: '',
    companySize: '',
    employeeCount: null,
    jurisdiction: '',
    workModel: '',
    recentIncident: '',
  })

  /** Estado del documento en el visor */
  const viewerDoc = reactive({ loading: false, data: null })

  /**
   * Si el perfil de organización ya tiene datos (heurística: 'company'
   * relleno, el único campo obligatorio al generar). Sirve para que el
   * panel de perfil arranque colapsado cuando ya no hay nada que revisar,
   * y expandido la primera vez.
   */
  const orgProfileConfigured = computed(() => !!tweaks.company)

  /* ── CAMPAÑAS ── */

  /** Modal de campaña abierto/cerrado */
  const campaignModalOpen = ref(false)
  /** Listas de distribución del usuario (cacheadas para el modal) */
  const distributionLists = ref([])
  /** Carga de listas en curso */
  const loadingLists = ref(false)
  /** Campañas ya lanzadas para la píldora abierta en el modal */
  const campaignsForDoc = ref([])
  /** Creación de una lista nueva en curso */
  const creatingList = ref(false)
  /** Lanzamiento de campaña en curso */
  const launchingCampaign = ref(false)
  /** Campaña desplegada en el modal, con sus destinatarios y notas */
  const campaignDetail = ref(null)
  /** Carga del detalle de campaña en curso */
  const loadingCampaignDetail = ref(false)
  /** Eliminación de campaña en curso */
  const deletingCampaign = ref(false)
  /** Modal de mantenimiento de listas de distribución abierto/cerrado */
  const listsModalOpen = ref(false)
  /** Destinatarios de la lista desplegada en ese modal */
  const listRecipients = ref([])
  /** Id de la lista desplegada (null = ninguna) */
  const expandedListId = ref(null)

  /* ── CARGA INICIAL ── */

  /**
   * Carga los temas desde GET /aegis/topics.
   *
   * Los temas son filas sembradas en la base de datos: no cambian durante una
   * sesión. AegisView llamaba a esto en cada montaje, así que ir y volver del
   * generador tres veces costaba tres peticiones para pintar la misma rejilla.
   * `reset()` vacía `topics`, de modo que cerrar sesión vuelve a pedirlos.
   */
  async function loadTopics() {
    if (topics.value.length) return
    try {
      const res = await apiFetch('/aegis/topics')
      if (res?.ok) {
        const data = await res.json()
        topics.value = data.topics ?? data ?? []
      }
    } catch { /* noop */ }
  }

  /**
   * Busca productos en el índice CPE del espejo local de NVD
   * (GET /aegis/products). Sustituye al antiguo catálogo fijo de 19 marcas:
   * la lista sale de la base de conocimiento y solo ofrece productos que de
   * verdad tienen algún CVE registrado.
   * @param {string} term
   */
  async function searchProducts(term) {
    const query = (term || '').trim()
    productSearchError.value = ''
    if (query.length < 2) { productResults.value = []; return }
    searchingProducts.value = true
    try {
      const res = await apiFetch(`/aegis/products?q=${encodeURIComponent(query)}`)
      if (!res?.ok) {
        productResults.value = []
        // Un fallo vaciaba `productResults` igual que una búsqueda sin
        // coincidencias, así que la UI no podía distinguirlos y enseñaba "sin
        // coincidencias en el catálogo" — al usuario le decía que su producto
        // no existe cuando lo que pasa es que no hemos podido preguntarlo.
        // El 429 además tiene su propio aviso porque el endpoint está limitado
        // a 120 peticiones/hora; useApi ya lanza un toast, pero el toast se va
        // a los pocos segundos y esto se queda junto a la lista vacía.
        productSearchError.value = res?.status === 429
          ? 'Has agotado las búsquedas por ahora. Inténtalo de nuevo en unos minutos.'
          : 'No se pudo consultar el catálogo de vulnerabilidades.'
        return
      }
      const data = await res.json()
      productResults.value = data.products ?? []
    } catch {
      // Aquí solo se llega si `res.json()` no puede parsear el cuerpo: los
      // fallos de red los absorbe `apiFetch`, que devuelve `null` y entra por
      // la rama de arriba. Mismo mensaje: para el usuario es el mismo problema.
      productResults.value = []
      productSearchError.value = 'No se pudo consultar el catálogo de vulnerabilidades.'
    }
    finally { searchingProducts.value = false }
  }

  /** Añade un producto a los vigilados, sin duplicar. */
  function addTrackedProduct(entry) {
    if (!entry?.vendor) return
    const exists = trackedProducts.value.some(
      p => p.vendor === entry.vendor && p.product === entry.product,
    )
    if (!exists) trackedProducts.value.push({ vendor: entry.vendor, product: entry.product })
    productResults.value = []
  }

  /** Quita un producto de los vigilados. */
  function removeTrackedProduct(entry) {
    trackedProducts.value = trackedProducts.value.filter(
      p => !(p.vendor === entry.vendor && p.product === entry.product),
    )
  }

  /**
   * Carga el perfil de organización desde GET /aegis/org-profile y precarga
   * los campos estables de `tweaks` (y las marcas habituales) con sus
   * valores — para que el usuario no tenga que reintroducirlos cada vez.
   * Si no hay perfil guardado, el backend devuelve los mismos defaults con
   * los que `tweaks` ya arranca, así que no hace falta distinguir el caso.
   */
  async function loadOrgProfile() {
    loadingOrgProfile.value = true
    try {
      const res = await apiFetch('/aegis/org-profile')
      if (!res?.ok) return
      const data = await res.json()
      tweaks.company        = data.company ?? ''
      tweaks.mentionContact = data.mentionContact ?? ''
      tweaks.tone           = data.tone || 'profesional'
      tweaks.companySize    = data.companySize ?? ''
      tweaks.jurisdiction   = data.jurisdiction ?? ''
      tweaks.language       = data.language || 'es'
      tweaks.sector         = data.sector ?? ''
      tweaks.workModel      = data.workModel ?? ''
      tweaks.employeeCount  = data.employeeCount ?? null
      trackedProducts.value = [...(data.trackedProducts ?? [])]
      useHygeiaInventory.value = data.useHygeiaInventory ?? true
      hygeiaInventoryAvailable.value = data.hygeiaInventoryAvailable ?? false
      whiteLabel.value = {
        level: data.whiteLabelLevel || 'none',
        logo:  data.brandLogo ?? '',
        color: data.brandColor ?? '',
      }
      maxWhiteLabelLevel.value = data.maxWhiteLabelLevel || 'none'
    } finally { loadingOrgProfile.value = false }
  }

  /**
   * Guarda (crea o actualiza) el perfil de organización vía
   * PUT /aegis/org-profile, con los valores estables actuales de `tweaks`.
   * @returns {Promise<boolean>}
   */
  async function saveOrgProfile() {
    savingOrgProfile.value = true
    try {
      const payload = {
        company:          tweaks.company,
        mentionContact:   tweaks.mentionContact,
        tone:             tweaks.tone,
        companySize:      tweaks.companySize,
        jurisdiction:     tweaks.jurisdiction,
        language:         tweaks.language,
        sector:           tweaks.sector,
        workModel:        tweaks.workModel,
        employeeCount:    tweaks.employeeCount || null,
        trackedProducts:  [...trackedProducts.value],
        useHygeiaInventory: useHygeiaInventory.value,
        whiteLabelLevel:  whiteLabel.value.level,
        brandLogo:        whiteLabel.value.logo,
        brandColor:       whiteLabel.value.color,
      }
      const res = await apiFetch('/aegis/org-profile', { method: 'PUT', body: JSON.stringify(payload) })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo guardar el perfil de organización.'), 'error')
        return false
      }
      toast.show('Perfil de organización guardado.', 'success')
      return true
    } finally { savingOrgProfile.value = false }
  }

  /* ── HISTORIAL ── */

  /** Carga el historial de documentos del usuario desde GET /aegis/documents */
  async function loadHistory() {
    loading.value = true
    try {
      const res = await apiFetch('/aegis/documents')
      if (!res?.ok) { documents.value = []; listError.value = 'No se pudieron cargar los documentos.'; return }
      const data = await res.json()
      documents.value = [...(data.documents ?? [])]
      listError.value = null
    } catch {
      documents.value = []
      listError.value = 'Error de conexión.'
    } finally { loading.value = false }
  }

  /** Devuelve los documentos ordenados según el sortMode actual */
  function sortedDocuments() {
    const docs = [...documents.value]
    switch (sortMode.value) {
      case 'date-asc':
        return docs.sort((a, b) => new Date(a.generatedAt) - new Date(b.generatedAt))
      case 'name-asc':
        return docs.sort((a, b) => (a.title || '').localeCompare(b.title || ''))
      case 'status':
        return docs.sort((a, b) => (a.status || '').localeCompare(b.status || ''))
      default:
        return docs.sort((a, b) => new Date(b.generatedAt) - new Date(a.generatedAt))
    }
  }

  /* ── GENERACIÓN ── */

  /**
   * Inicia la generación asíncrona de una píldora vía POST /aegis/generate.
   * @returns {Promise<boolean>} True si la solicitud fue aceptada
   */
  async function generate() {
    if (!selectedTopicId.value) {
      toast.show('Selecciona un tema primero.', 'warn')
      return false
    }
    generating.value = true
    generateError.value = null
    try {
      const payload = {
        topicId: selectedTopicId.value,
        tweaks: {
          ...tweaks,
          trackedProducts: [...trackedProducts.value],
          useHygeiaInventory: useHygeiaInventory.value,
          employeeCount: tweaks.employeeCount || null,
        },
      }
      const res = await apiFetch('/aegis/generate', { method: 'POST', body: JSON.stringify(payload) })
      if (!res?.ok) {
        // El toast se va solo a los pocos segundos. Si te has girado, la
        // generación falló y no queda rastro en ninguna parte: la vista sigue
        // igual que antes de pulsar. El error se guarda además en la store
        // para poder pintarlo donde ocurrió.
        generateError.value = await apiError(res, 'Error al generar la píldora.')
        toast.show(generateError.value, 'error')
        return false
      }
      const data = await res.json()
      toast.show(`Píldora en generación (ID: ${data.documentId})`, 'success')
      await loadHistory()
      return true
    } finally { generating.value = false }
  }

  /* ── VISOR ── */

  /**
   * Carga un documento en el visor central desde GET /aegis/document?id=<id>.
   * Si el documento ya está en caché, lo sirve instantáneamente sin re-fetch.
   * @param {number|string} id - ID del documento
   */
  async function loadDocument(id) {
    currentDocId.value = id

    const cached = docCache.get(id)
    if (cached) {
      viewerDoc.loading = false
      viewerDoc.data = cached
      return
    }

    viewerDoc.loading = true
    viewerDoc.data = null
    try {
      const res = await apiFetch(`/aegis/document?id=${id}`)
      if (!res?.ok) { toast.show('No se pudo cargar el documento.', 'error'); return }
      const data = await res.json()
      viewerDoc.data = data
      docCache.set(id, data)
    } finally { viewerDoc.loading = false }
  }

  /** Cierra/limpia el visor */
  function closeViewer() {
    currentDocId.value = null
    viewerDoc.data = null
    editing.value = false
  }

  /* ── EDICIÓN ── */

  /** Entra en modo edición de la píldora actual */
  function startEdit() {
    if (viewerDoc.data?.status === 'done') editing.value = true
  }

  /** Sale del modo edición descartando cambios no guardados */
  function cancelEdit() {
    editing.value = false
  }

  /**
   * Persiste el contenido editado de la píldora vía PUT /aegis/document?id=<id>.
   * @param {number|string} docId - ID del documento
   * @param {object} pillData - { subtitle, intro, closing, contactEmail, company, tips }
   * @returns {Promise<boolean>} True si se guardó correctamente
   */
  async function savePill(docId, pillData) {
    saving.value = true
    try {
      const res = await apiFetch(`/aegis/document?id=${docId}`, {
        method: 'PUT',
        body: JSON.stringify(pillData),
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudieron guardar los cambios.'), 'error')
        return false
      }
      const data = await res.json()
      viewerDoc.data = data
      docCache.set(docId, data)
      editing.value = false
      toast.show('Píldora actualizada.', 'success')
      await loadHistory()
      return true
    } finally { saving.value = false }
  }

  /* ── ACCIONES SOBRE DOCUMENTOS ── */

  /**
   * Elimina un documento vía DELETE /aegis/document?id=<id>.
   * @param {number|string} id - ID del documento
   * @returns {Promise<boolean>}
   */
  async function deleteDocument(id) {
    const res = await apiFetch(`/aegis/document?id=${id}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show('No se pudo eliminar el documento.', 'error')
      return false
    }
    docCache.delete(id)
    if (currentDocId.value === id) closeViewer()
    await loadHistory()
    return true
  }

  /**
   * Descarga una exportación en el formato indicado.
   * @param {number|string} docId - ID del documento
   * @param {'md'|'html'|'json'} format - Formato de exportación
   * @returns {Promise<boolean>}
   */
  async function downloadExport(docId, format) {
    try {
      const res = await apiFetch(`/aegis/export/${docId}/download?format=${format}&inline=false`)
      if (!res?.ok) { toast.show('No se pudo exportar.', 'error'); return false }
      const blob = await res.blob()
      const name = filenameFromResponse(res, `documento_${docId}.${format}`)
      triggerDownload(blob, name)
      toast.show('Documento descargado.', 'success')
      return true
    } catch { toast.show('Error al descargar.', 'error'); return false }
  }

  /**
   * Abre una vista previa en Markdown en una nueva pestaña.
   * @param {number|string} docId - ID del documento
   */
  async function previewMarkdown(docId) {
    try {
      const res = await apiFetch(`/aegis/export/md/${docId}?inline=true`)
      if (!res?.ok) { toast.show('No se pudo previsualizar.', 'error'); return }
      const text = await res.text()
      const w = window.open('', '_blank')
      if (w) {
        w.document.write(`<pre style="padding:2rem;white-space:pre-wrap;font-family:monospace;line-height:1.6">${text.replace(/</g, '&lt;')}</pre>`)
      }
    } catch { toast.show('Error al previsualizar.', 'error') }
  }

  /* ── CAMPAÑAS ── */

  /**
   * Abre el modal de campaña para la píldora actualmente en el visor y
   * precarga las listas de distribución + las campañas ya lanzadas para ella.
   */
  async function openCampaignModal() {
    campaignModalOpen.value = true
    await Promise.all([
      loadDistributionLists(),
      currentDocId.value ? loadCampaignsForDocument(currentDocId.value) : Promise.resolve(),
    ])
  }

  /** Cierra el modal de campaña */
  function closeCampaignModal() {
    campaignModalOpen.value = false
    campaignDetail.value = null
  }

  /** Carga las listas de distribución del usuario desde GET /aegis/lists */
  async function loadDistributionLists() {
    loadingLists.value = true
    try {
      const res = await apiFetch('/aegis/lists')
      if (!res?.ok) { distributionLists.value = []; return }
      const data = await res.json()
      distributionLists.value = [...(data.lists ?? [])]
    } finally { loadingLists.value = false }
  }

  /**
   * Carga las campañas ya lanzadas para una píldora concreta.
   * GET /aegis/campaigns no filtra por documento: se filtra en cliente.
   * @param {number|string} documentId
   */
  async function loadCampaignsForDocument(documentId) {
    try {
      const res = await apiFetch('/aegis/campaigns')
      if (!res?.ok) { campaignsForDoc.value = []; return }
      const data = await res.json()
      campaignsForDoc.value = (data.campaigns ?? []).filter(c => c.documentId === documentId)
    } catch { campaignsForDoc.value = [] }
  }

  /**
   * Carga el detalle de una campaña (GET /aegis/campaigns/{id}), que incluye
   * cada destinatario con su estado (sent/opened/completed) y su nota.
   * Llamar con el mismo id que ya está abierto lo cierra.
   * @param {number|string} campaignId
   */
  async function loadCampaignDetail(campaignId) {
    if (campaignDetail.value?.id === campaignId) { campaignDetail.value = null; return }
    loadingCampaignDetail.value = true
    campaignDetail.value = null
    try {
      const res = await apiFetch(`/aegis/campaigns/${campaignId}`)
      if (!res?.ok) { toast.show('No se pudo cargar el detalle de la campaña.', 'error'); return }
      campaignDetail.value = await res.json()
    } finally { loadingCampaignDetail.value = false }
  }

  /**
   * Elimina una campaña (DELETE /aegis/campaigns/{id}) y su tracking —
   * invalida cualquier enlace de quiz que ya se hubiera enviado. Devuelve
   * true si se eliminó.
   * @param {number|string} campaignId
   */
  async function deleteCampaign(campaignId) {
    deletingCampaign.value = true
    try {
      const res = await apiFetch(`/aegis/campaigns/${campaignId}`, { method: 'DELETE' })
      if (!res?.ok) { toast.show('No se pudo eliminar la campaña.', 'error'); return false }
      if (campaignDetail.value?.id === campaignId) campaignDetail.value = null
      campaignsForDoc.value = campaignsForDoc.value.filter(c => c.id !== campaignId)
      toast.show('Campaña eliminada.', 'success')
      return true
    } finally { deletingCampaign.value = false }
  }

  /**
   * Crea una lista de distribución nueva con destinatarios y la añade a
   * distributionLists. Devuelve la lista creada, o null si falló.
   * @param {string} name
   * @param {Array<{email: string, name?: string}>} recipients
   */
  async function createDistributionListWithRecipients(name, recipients) {
    creatingList.value = true
    try {
      const res = await apiFetch('/aegis/lists', { method: 'POST', body: JSON.stringify({ name }) })
      const list = await res?.json().catch(() => null)
      if (!res?.ok || !list?.id) {
        toast.show(list?.message || 'No se pudo crear la lista.', 'error')
        return null
      }
      if (recipients.length) {
        const recRes = await apiFetch(`/aegis/lists/${list.id}/recipients`, {
          method: 'POST',
          body: JSON.stringify({ recipients }),
        })
        if (!recRes?.ok) {
          toast.show('Lista creada, pero no se pudieron añadir los destinatarios.', 'warn')
        }
      }
      await loadDistributionLists()
      const created = distributionLists.value.find(l => l.id === list.id) || { ...list, recipientCount: recipients.length }
      return created
    } finally { creatingList.value = false }
  }

  /* ── MANTENIMIENTO DE LISTAS ── */

  /** Abre el modal de listas y (re)carga las listas del usuario */
  async function openListsModal() {
    listsModalOpen.value = true
    expandedListId.value = null
    listRecipients.value = []
    await loadDistributionLists()
  }

  /** Cierra el modal de listas */
  function closeListsModal() {
    listsModalOpen.value = false
    expandedListId.value = null
    listRecipients.value = []
  }

  /**
   * Despliega una lista y carga sus destinatarios. Llamar con la lista ya
   * desplegada la pliega (mismo patrón que loadCampaignDetail).
   * @param {number} listId
   */
  async function toggleListRecipients(listId) {
    if (expandedListId.value === listId) { expandedListId.value = null; listRecipients.value = []; return }
    expandedListId.value = listId
    listRecipients.value = []
    const res = await apiFetch(`/aegis/lists/${listId}/recipients`)
    if (!res?.ok) { toast.show('No se pudieron cargar los destinatarios.', 'error'); return }
    const data = await res.json()
    listRecipients.value = data.recipients ?? []
  }

  /**
   * Añade destinatarios a una lista existente. Los duplicados los ignora el
   * backend, así que el recuento se relee de la lista en lugar de sumarse.
   * @param {number} listId
   * @param {Array<{email: string, name?: string}>} recipients
   */
  async function addRecipientsToList(listId, recipients) {
    if (!recipients.length) return false
    const res = await apiFetch(`/aegis/lists/${listId}/recipients`, {
      method: 'POST',
      body: JSON.stringify({ recipients }),
    })
    if (!res?.ok) { toast.show('No se pudieron añadir los destinatarios.', 'error'); return false }
    const data = await res.json().catch(() => ({}))
    listRecipients.value = [...listRecipients.value, ...(data.recipients ?? [])]
    await loadDistributionLists()
    toast.show(`${data.count ?? recipients.length} destinatario(s) añadido(s).`, 'success')
    return true
  }

  /**
   * Elimina un destinatario de una lista.
   * @param {number} listId
   * @param {number} recipientId
   */
  async function removeRecipientFromList(listId, recipientId) {
    const res = await apiFetch(`/aegis/lists/${listId}/recipients/${recipientId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el destinatario.', 'error'); return false }
    listRecipients.value = listRecipients.value.filter(r => r.id !== recipientId)
    await loadDistributionLists()
    return true
  }

  /**
   * Elimina una lista de distribución entera con sus destinatarios.
   * @param {number} listId
   */
  async function deleteDistributionList(listId) {
    const res = await apiFetch(`/aegis/lists/${listId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar la lista.', 'error'); return false }
    if (expandedListId.value === listId) { expandedListId.value = null; listRecipients.value = [] }
    distributionLists.value = distributionLists.value.filter(l => l.id !== listId)
    toast.show('Lista eliminada.', 'success')
    return true
  }

  /**
   * Crea una campaña (draft) y la lanza inmediatamente: congela el quiz,
   * genera un token por destinatario y encola el envío en segundo plano.
   * @param {{documentId: number, listId: number, name: string}} params
   * @returns {Promise<boolean>}
   */
  async function launchNewCampaign({ documentId, listId, name }) {
    launchingCampaign.value = true
    try {
      const createRes = await apiFetch('/aegis/campaigns', {
        method: 'POST',
        body: JSON.stringify({ documentId, listId, name }),
      })
      const campaign = await createRes?.json().catch(() => null)
      if (!createRes?.ok || !campaign?.id) {
        toast.show(campaign?.message || 'No se pudo crear la campaña.', 'error')
        return false
      }

      const launchRes = await apiFetch(`/aegis/campaigns/${campaign.id}/launch`, { method: 'POST' })
      const launchData = await launchRes?.json().catch(() => ({}))
      if (!launchRes?.ok) {
        toast.show(launchData.message || 'No se pudo lanzar la campaña.', 'error')
        return false
      }

      toast.show('Campaña lanzada. El envío continúa en segundo plano.', 'success')
      await loadCampaignsForDocument(documentId)
      return true
    } finally { launchingCampaign.value = false }
  }

  /** Limpia el estado (Q6: logout SPA sin recarga dura) — incluye la caché
   * de documentos del visor (memoria) y los tweaks precargados con el
   * perfil de organización del usuario saliente. */
  function $reset() {
    docCache.clear()

    topics.value = []
    documents.value = []
    listError.value = null
    selectedTopicId.value = null
    currentDocId.value = null
    sortMode.value = 'date-desc'
    trackedProducts.value = []
    useHygeiaInventory.value = true
    hygeiaInventoryAvailable.value = false
    // El logo y el color son del usuario que se va: dejarlos aquí los enseña
    // al siguiente que entre en la misma pestaña, y si su GET del perfil falla
    // (loadOrgProfile no sobrescribe nada entonces) se los acabaría guardando.
    whiteLabel.value = { level: 'none', logo: '', color: '' }
    maxWhiteLabelLevel.value = 'none'
    productResults.value = []
    searchingProducts.value = false
    productSearchError.value = ''
    generating.value = false
    loading.value = false
    editing.value = false
    saving.value = false
    loadingOrgProfile.value = false
    savingOrgProfile.value = false

    Object.assign(tweaks, {
      company: '', language: 'es', tone: 'profesional', audienceLevel: 'mixed',
      mentionContact: '', sector: '', topicFocus: '', companySize: '',
      employeeCount: null, jurisdiction: '', workModel: '', recentIncident: '',
    })
    Object.assign(viewerDoc, { loading: false, data: null })

    campaignModalOpen.value = false
    distributionLists.value = []
    loadingLists.value = false
    campaignsForDoc.value = []
    creatingList.value = false
    launchingCampaign.value = false
    campaignDetail.value = null
    loadingCampaignDetail.value = false
    deletingCampaign.value = false
    listsModalOpen.value = false
    listRecipients.value = []
    expandedListId.value = null
  }

  return {
    topics, documents, listError, selectedTopicId, currentDocId, sortMode,
    trackedProducts, useHygeiaInventory, hygeiaInventoryAvailable,
    whiteLabel, maxWhiteLabelLevel,
    productResults, searchingProducts, productSearchError,
    generating, generateError, loading, editing, saving, tweaks, viewerDoc,
    loadingOrgProfile, savingOrgProfile, orgProfileConfigured,
    searchProducts, addTrackedProduct, removeTrackedProduct,
    loadTopics, loadOrgProfile, saveOrgProfile, loadHistory, sortedDocuments, generate,
    loadDocument, closeViewer, deleteDocument, downloadExport, previewMarkdown,
    startEdit, cancelEdit, savePill,
    campaignModalOpen, distributionLists, loadingLists, campaignsForDoc,
    creatingList, launchingCampaign, campaignDetail, loadingCampaignDetail, deletingCampaign,
    openCampaignModal, closeCampaignModal, loadDistributionLists,
    createDistributionListWithRecipients, launchNewCampaign, loadCampaignDetail, deleteCampaign,
    listsModalOpen, listRecipients, expandedListId,
    openListsModal, closeListsModal, toggleListRecipients,
    addRecipientsToList, removeRecipientFromList, deleteDistributionList,
    $reset,
  }
})
