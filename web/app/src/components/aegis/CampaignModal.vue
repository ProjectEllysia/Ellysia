<template>
  <Teleport to="body">
    <div class="modal-overlay" data-module="aegis" @click.self="close" @keydown.esc="close">
      <div class="modal--campaign" role="dialog" aria-modal="true" aria-labelledby="campaign-modal-title">
        <header class="campaign-header">
          <div class="campaign-header-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </div>
          <div class="campaign-header-text">
            <h2 id="campaign-modal-title">Lanzar campaña</h2>
            <p>{{ doc?.subtitle || doc?.title }}</p>
          </div>
          <button type="button" class="modal-close" @click="close" aria-label="Cerrar">&times;</button>
        </header>

        <Transition name="campaign-fade" mode="out-in">
          <div v-if="launched" key="success" class="campaign-success">
            <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="8 12 11 15 16 9"/></svg>
            <h3>Campaña en marcha</h3>
            <p>Enviando a {{ launchedCount }} destinatario{{ launchedCount === 1 ? '' : 's' }}. El envío continúa en segundo plano.</p>
          </div>

          <div v-else key="form" class="campaign-body">
            <div class="quiz-status" :class="{ 'quiz-status--warn': questionCount === 0 }">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 2-3 4"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <span v-if="questionCount > 0">{{ questionCount }} pregunta{{ questionCount === 1 ? '' : 's' }} de comprobación listas</span>
              <span v-else>Esta píldora no tiene preguntas de quiz — no se puede lanzar una campaña</span>
            </div>

            <div class="form-group">
              <label for="camp-name">Nombre de la campaña</label>
              <input id="camp-name" v-model="campaignName" type="text" maxlength="128" class="input" placeholder="Ej: Formación Q1 — Ventas" />
            </div>

            <div class="list-source-toggle" role="tablist">
              <button type="button" role="tab" :aria-selected="mode === 'existing'" :class="{ active: mode === 'existing' }" @click="mode = 'existing'">Lista existente</button>
              <button type="button" role="tab" :aria-selected="mode === 'new'" :class="{ active: mode === 'new' }" @click="mode = 'new'">Nueva lista</button>
            </div>

            <div v-if="mode === 'existing'" class="form-group">
              <p v-if="store.loadingLists" class="hint">Cargando listas…</p>
              <p v-else-if="!store.distributionLists.length" class="hint">Aún no tienes listas de distribución — crea una nueva.</p>
              <select v-else v-model.number="selectedListId" class="input select">
                <option :value="null">Selecciona una lista</option>
                <option v-for="l in store.distributionLists" :key="l.id" :value="l.id">
                  {{ l.name }} — {{ l.recipientCount }} destinatario{{ l.recipientCount === 1 ? '' : 's' }}
                </option>
              </select>
            </div>

            <template v-else>
              <div class="form-group">
                <label for="camp-list-name">Nombre de la lista</label>
                <input id="camp-list-name" v-model="newListName" type="text" maxlength="128" class="input" placeholder="Ej: Plantilla completa" />
              </div>
              <div class="form-group">
                <label for="camp-emails">Destinatarios</label>
                <textarea
                  id="camp-emails"
                  v-model="emailsRaw"
                  rows="4"
                  class="input textarea"
                  placeholder="Un email por línea (o separados por coma)
ana@empresa.com
bob@empresa.com"
                ></textarea>
                <span class="recipient-count" :class="{ 'recipient-count--empty': recipientCount === 0 }">
                  {{ recipientCount }} destinatario{{ recipientCount === 1 ? '' : 's' }} detectado{{ recipientCount === 1 ? '' : 's' }}
                </span>
              </div>
            </template>

            <div v-if="store.campaignsForDoc.length" class="past-campaigns">
              <span class="past-campaigns-label">Campañas anteriores de esta píldora</span>
              <div v-for="c in store.campaignsForDoc" :key="c.id" class="past-campaign-row">
                <span class="badge" :class="statusBadgeClass(c.status)">{{ statusLabel(c.status) }}</span>
                <span class="past-campaign-name">{{ c.name }}</span>
                <span class="past-campaign-date">{{ formatDate(c.createdAt) }}</span>
              </div>
            </div>
          </div>
        </Transition>

        <footer v-if="!launched" class="campaign-footer">
          <button type="button" class="btn btn--secondary" @click="close">Cancelar</button>
          <button type="button" class="btn btn--primary" :disabled="!canLaunch || busy" @click="handleLaunch">
            <span v-if="busy" class="btn-spin-inline"></span>
            {{ busy ? 'Lanzando…' : 'Lanzar campaña' }}
          </button>
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useAegisStore } from '@/stores/aegisStore'
import { useUtils } from '@/composables/useUtils'

const props = defineProps({ doc: { type: Object, required: true } })
const emit = defineEmits(['close'])

const store = useAegisStore()
const { formatDate } = useUtils()

function defaultCampaignName() {
  const title = props.doc?.subtitle || props.doc?.title || 'Píldora'
  const today = new Date().toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit' })
  return `${title} — ${today}`
}

const mode = ref('existing')
const selectedListId = ref(null)
const newListName = ref('')
const emailsRaw = ref('')
const campaignName = ref(defaultCampaignName())
const launched = ref(false)
const launchedCount = ref(0)

const questionCount = computed(() => props.doc?.pill?.questions?.length || 0)

const parsedRecipients = computed(() => {
  const seen = new Set()
  const out = []
  for (const raw of emailsRaw.value.split(/[\n,;]+/)) {
    const email = raw.trim().toLowerCase()
    if (!email || seen.has(email)) continue
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) continue
    seen.add(email)
    out.push({ email })
  }
  return out
})
const recipientCount = computed(() => parsedRecipients.value.length)

const canLaunch = computed(() => {
  if (questionCount.value === 0 || !campaignName.value.trim()) return false
  if (mode.value === 'existing') return !!selectedListId.value
  return newListName.value.trim().length > 0 && recipientCount.value > 0
})

const busy = computed(() => store.creatingList || store.launchingCampaign)

async function handleLaunch() {
  if (!canLaunch.value || busy.value) return

  let listId = selectedListId.value
  let count = store.distributionLists.find(l => l.id === listId)?.recipientCount ?? 0

  if (mode.value === 'new') {
    const created = await store.createDistributionListWithRecipients(newListName.value.trim(), parsedRecipients.value)
    if (!created) return
    listId = created.id
    count = created.recipientCount ?? parsedRecipients.value.length
  }

  const ok = await store.launchNewCampaign({
    documentId: props.doc.id,
    listId,
    name: campaignName.value.trim(),
  })
  if (ok) {
    launchedCount.value = count
    launched.value = true
    setTimeout(close, 1800)
  }
}

function close() { emit('close') }

const statusLabels = { draft: 'Borrador', sending: 'Enviando', sent: 'Enviada', closed: 'Cerrada' }
const statusBadges = { draft: 'badge--pending', sending: 'badge--running', sent: 'badge--done', closed: 'badge--cancelled' }
function statusLabel(status) { return statusLabels[status] || status }
function statusBadgeClass(status) { return statusBadges[status] || 'badge--pending' }
</script>

<style scoped>
.modal--campaign { background: var(--surface); border: 1px solid var(--border-solid); border-radius: var(--radius); max-width: 460px; width: 100%; max-height: 88vh; display: flex; flex-direction: column; overflow: hidden; }

.campaign-header { display: flex; align-items: flex-start; gap: 0.75rem; padding: 1.1rem 1.25rem 0.9rem; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.campaign-header-icon { width: 34px; height: 34px; border-radius: 9px; background: var(--accent-dim); color: var(--accent-bright); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.campaign-header-text { flex: 1; min-width: 0; }
.campaign-header-text h2 { font-size: 1.38rem; font-weight: 800; color: var(--text); margin: 0 0 0.15rem; font-family: var(--font-display); }
.campaign-header-text p { font-size: 1.37rem; color: var(--text-dim); margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.modal-close { background: none; border: none; color: var(--text-muted); font-size: 1.76rem; line-height: 1; cursor: pointer; padding: 0.1rem 0.3rem; flex-shrink: 0; border-radius: 5px; transition: all 0.15s; }
.modal-close:hover { color: var(--text); background: var(--bg); }

.campaign-body { padding: 1.1rem 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 0.85rem; }

.quiz-status { display: flex; align-items: center; gap: 0.4rem; padding: 0.5rem 0.65rem; border-radius: 7px; background: var(--success-dim); color: var(--success); font-size: 1.33rem; font-weight: 600; }
.quiz-status svg { flex-shrink: 0; }
.quiz-status--warn { background: var(--warn-dim); color: var(--warn); }

.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: 1.26rem; font-weight: 600; color: var(--text-dim); }
.input { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: 1.43rem; outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s; font-family: inherit; }
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; }
.textarea { resize: vertical; min-height: 3.6rem; line-height: 1.5; font-family: var(--font-mono); font-size: 1.33rem; }

.hint { font-size: 1.37rem; color: var(--text-muted); margin: 0; }

.recipient-count { font-size: 1.26rem; font-weight: 600; color: var(--accent-bright); }
.recipient-count--empty { color: var(--text-muted); }

.list-source-toggle { display: flex; gap: 0.3rem; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 3px; }
.list-source-toggle button { flex: 1; padding: 0.4rem 0.5rem; font-size: 1.3rem; font-weight: 600; border-radius: 6px; border: none; background: none; color: var(--text-muted); cursor: pointer; transition: all 0.15s; }
.list-source-toggle button.active { background: var(--accent-dim); color: var(--accent-bright); }

.past-campaigns { margin-top: 0.2rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
.past-campaigns-label { display: block; font-size: 1.19rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 0.5rem; }
.past-campaign-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.35rem 0; font-size: 1.37rem; }
.past-campaign-name { flex: 1; min-width: 0; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.past-campaign-date { color: var(--text-muted); font-size: 1.22rem; font-family: var(--font-mono); flex-shrink: 0; }

.campaign-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0.9rem 1.25rem; border-top: 1px solid var(--border); flex-shrink: 0; }
.btn-spin-inline { width: 12px; height: 12px; border: 2px solid rgba(0,0,0,0.2); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }

.campaign-success { padding: 2.5rem 1.5rem; display: flex; flex-direction: column; align-items: center; text-align: center; gap: 0.5rem; color: var(--success); }
.campaign-success h3 { font-size: 1.35rem; font-weight: 700; color: var(--text); margin: 0.4rem 0 0; font-family: var(--font-display); }
.campaign-success p { font-size: 1.43rem; color: var(--text-dim); margin: 0; max-width: 300px; line-height: 1.5; }

.campaign-fade-enter-active, .campaign-fade-leave-active { transition: opacity 0.2s ease; }
.campaign-fade-enter-from, .campaign-fade-leave-to { opacity: 0; }
@media (prefers-reduced-motion: reduce) {
  .campaign-fade-enter-active, .campaign-fade-leave-active { transition: none !important; }
}
</style>
