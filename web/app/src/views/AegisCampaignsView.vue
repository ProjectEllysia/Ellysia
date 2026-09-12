<template>
  <div class="campaigns-page" data-module="aegis">
    <StarBackground />
    <Topbar title="Aegis" badge="Campañas" back-to="/aegis/generador" back-label="Generador" />

    <div class="campaigns-layout">
      <!-- Píldoras que tienen alguna campaña, de la más reciente a la más antigua -->
      <aside class="panel panel--pills" aria-label="Píldoras con campañas">
        <header class="panel-head">
          <h2>Píldoras</h2>
          <button
            type="button"
            class="btn-icon"
            :class="{ spinning: store.loadingCampaigns }"
            title="Refrescar"
            aria-label="Refrescar campañas"
            @click="refresh"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          </button>
        </header>

        <div class="panel-scroll">
          <p v-if="!loaded" class="panel-note">Cargando campañas…</p>
          <div v-else-if="store.campaignsError" class="panel-note panel-note--error">
            <p>{{ store.campaignsError }}</p>
            <button type="button" class="retry" @click="refresh">Reintentar</button>
          </div>
          <div v-else-if="!pills.length" class="panel-note">
            <p>Aún no has lanzado ninguna campaña.</p>
            <router-link to="/aegis/generador" class="inline-link">Abre una píldora en el generador y lánzala</router-link>
          </div>

          <button
            v-for="pill in pills"
            :key="pill.id"
            type="button"
            class="pill-row"
            :class="{ 'pill-row--active': pill.id === selectedPillId }"
            :aria-pressed="pill.id === selectedPillId"
            @click="selectPill(pill.id)"
          >
            <span class="pill-title">{{ pill.title }}</span>
            <span class="pill-meta">
              {{ pill.campaigns.length }} campaña{{ pill.campaigns.length === 1 ? '' : 's' }}
              · última el {{ formatDate(pill.lastAt) }}
            </span>
          </button>
        </div>
      </aside>

      <!-- Campañas de la píldora elegida y su resumen conjunto -->
      <section class="panel panel--campaigns" aria-label="Campañas de la píldora">
        <template v-if="selectedPill">
          <header class="pill-head">
            <p class="eyebrow">Píldora</p>
            <h2 class="pill-heading">{{ selectedPill.title }}</h2>
          </header>

          <div class="summary-grid">
            <div class="stat">
              <span class="stat-value">{{ selectedPill.summary.campaignCount }}</span>
              <span class="stat-label">Campañas</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ selectedPill.summary.recipientCount }}</span>
              <span class="stat-label">Personas</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ selectedPill.summary.openRate }}%</span>
              <span class="stat-label">Abrieron el enlace</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ selectedPill.summary.completionRate }}%</span>
              <span class="stat-label">Completaron el test</span>
            </div>
            <div class="stat">
              <span class="stat-value">
                {{ selectedPill.summary.averageScorePercent == null ? '—' : `${selectedPill.summary.averageScorePercent}%` }}
              </span>
              <span class="stat-label">Aciertos de media</span>
            </div>
          </div>

          <div class="panel-scroll">
            <button
              v-for="campaign in selectedPill.campaigns"
              :key="campaign.id"
              type="button"
              class="campaign-row"
              :class="{ 'campaign-row--active': campaign.id === selectedCampaignId }"
              :aria-pressed="campaign.id === selectedCampaignId"
              @click="selectCampaign(campaign.id)"
            >
              <span class="campaign-row-top">
                <span class="badge" :class="campaignStatusBadge(campaign.status)">{{ campaignStatusLabel(campaign.status) }}</span>
                <span class="campaign-name">{{ campaign.name }}</span>
                <span class="campaign-date">{{ formatDate(campaign.launchedAt || campaign.createdAt) }}</span>
              </span>
              <span class="campaign-row-bottom">
                <span class="mini-progress" aria-hidden="true">
                  <span :style="{ width: `${percentOf(campaign.completedCount, campaign.recipientCount)}%` }"></span>
                </span>
                <span class="campaign-count">{{ campaign.completedCount }}/{{ campaign.recipientCount }} completaron</span>
              </span>
            </button>
          </div>
        </template>
        <p v-else-if="pills.length" class="panel-note">Elige una píldora para ver sus campañas.</p>
      </section>

      <!-- Resultados de la campaña elegida -->
      <section class="panel panel--detail" aria-label="Resultados de la campaña">
        <p v-if="store.loadingCampaignDetail" class="panel-note">Cargando resultados…</p>

        <template v-else-if="detail">
          <header class="detail-head">
            <div class="detail-title">
              <span class="badge" :class="campaignStatusBadge(detail.status)">{{ campaignStatusLabel(detail.status) }}</span>
              <h2>{{ detail.name }}</h2>
            </div>
            <button type="button" class="delete-btn" @click="deleteTarget = detail">Eliminar campaña</button>
          </header>
          <p class="detail-meta">
            Creada el {{ formatDate(detail.createdAt) }}<template v-if="detail.launchedAt"> · lanzada el {{ formatMoment(detail.launchedAt) }}</template><template v-if="listName"> · lista «{{ listName }}»</template>
            · {{ detail.questionCount }} pregunta{{ detail.questionCount === 1 ? '' : 's' }}
          </p>

          <div class="detail-stats">
            <div class="stat">
              <span class="stat-value">{{ summary.recipientCount }}</span>
              <span class="stat-label">Destinatarios</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ summary.openedCount }}</span>
              <span class="stat-label">Abrieron el enlace</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ summary.completedCount }}</span>
              <span class="stat-label">Completaron el test</span>
            </div>
            <div class="stat">
              <span class="stat-value">{{ averageScoreText }}</span>
              <span class="stat-label">Nota media</span>
              <span v-if="averageScorePercent != null" class="stat-sub">{{ averageScorePercent }}% de aciertos</span>
            </div>
          </div>

          <div class="funnel">
            <div class="funnel-row">
              <span class="funnel-label">Abrieron el enlace</span>
              <span class="progress" role="img" :aria-label="`${openRate}% abrió el enlace`">
                <span class="progress-fill progress-fill--opened" :style="{ width: `${openRate}%` }"></span>
              </span>
              <span class="funnel-value">{{ openRate }}%</span>
            </div>
            <div class="funnel-row">
              <span class="funnel-label">Completaron el test</span>
              <span class="progress" role="img" :aria-label="`${completionRate}% completó el test`">
                <span class="progress-fill" :style="{ width: `${completionRate}%` }"></span>
              </span>
              <span class="funnel-value">{{ completionRate }}%</span>
            </div>
          </div>

          <template v-if="detail.questions?.length">
            <h3 class="section-label">Resultados por pregunta</h3>
            <ol class="questions">
              <li v-for="question in detail.questions" :key="question.position" class="question">
                <div class="question-head">
                  <span class="question-prompt">{{ question.prompt }}</span>
                  <span class="question-rate">
                    {{ question.answeredCount ? `${percentOf(question.correctCount, question.answeredCount)}% acertó` : 'Sin respuestas' }}
                  </span>
                </div>
                <ul class="options">
                  <li
                    v-for="(option, index) in question.options"
                    :key="index"
                    class="option"
                    :class="{ 'option--correct': index === question.correctIndex }"
                  >
                    <span class="option-text">
                      {{ option }}
                      <span v-if="index === question.correctIndex" class="option-tag">Correcta</span>
                    </span>
                    <span class="option-bar" aria-hidden="true">
                      <span :style="{ width: `${percentOf(question.optionCounts[index], question.answeredCount)}%` }"></span>
                    </span>
                    <span class="option-count">{{ question.optionCounts[index] }}</span>
                  </li>
                </ul>
              </li>
            </ol>
          </template>

          <h3 class="section-label">Destinatarios</h3>
          <p v-if="!detail.recipients.length" class="panel-note panel-note--inline">Esta campaña todavía no tiene destinatarios.</p>
          <div v-else class="table-wrap">
            <table class="recipients">
              <thead>
                <tr>
                  <th scope="col">Destinatario</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Enviado</th>
                  <th scope="col">Abrió</th>
                  <th scope="col">Completó</th>
                  <th scope="col" class="num">Nota</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="recipient in detail.recipients" :key="recipient.id">
                  <td>
                    <span v-if="recipient.name" class="recipient-name">{{ recipient.name }}</span>
                    <span class="recipient-email">{{ recipient.email }}</span>
                  </td>
                  <td class="nowrap">
                    <span class="dot" :class="`dot--${recipient.status}`" aria-hidden="true"></span>
                    {{ recipientStatusLabel(recipient.status) }}
                  </td>
                  <td class="moment">{{ formatMoment(recipient.sentAt) }}</td>
                  <td class="moment">{{ formatMoment(recipient.openedAt) }}</td>
                  <td class="moment">{{ formatMoment(recipient.completedAt) }}</td>
                  <td class="num">{{ recipient.status === 'completed' ? `${recipient.score}/${detail.questionCount}` : '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>

        <div v-else-if="selectedCampaignId" class="panel-note panel-note--error">
          <p>No se pudieron cargar los resultados.</p>
          <button type="button" class="retry" @click="store.loadCampaignDetail(selectedCampaignId)">Reintentar</button>
        </div>
        <p v-else-if="selectedPill" class="panel-note">Elige una campaña para ver sus resultados.</p>
      </section>
    </div>

    <ConfirmModal
      :show="!!deleteTarget"
      title="Eliminar campaña"
      :message="`¿Eliminar «${deleteTarget?.name}»? Los enlaces de quiz ya enviados a sus destinatarios dejarán de funcionar.`"
      confirm-label="Eliminar"
      danger
      @confirm="confirmDelete"
      @cancel="deleteTarget = null"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import { useAegisStore } from '@/stores/aegisStore'
import { useUtils } from '@/composables/useUtils'
import {
  campaignStatusBadge,
  campaignStatusLabel,
  percentOf,
  recipientStatusLabel,
  scorePercent,
  summarizePill,
  summarizeRecipients,
} from '@/components/aegis/campaigns'

const store = useAegisStore()
const route = useRoute()
const router = useRouter()
const { formatDate } = useUtils()

/** Si ya terminó la primera carga (evita enseñar «no hay campañas» mientras carga) */
const loaded = ref(false)
/** Píldora elegida; la URL la conserva en `?pildora=<id>` para poder enlazarla y recargar */
const selectedPillId = ref(Number(route.query.pildora) || null)
/** Campaña cuyos resultados se ven en el panel de detalle */
const selectedCampaignId = ref(null)
/** Campaña pendiente de confirmar su borrado (null = ninguna) */
const deleteTarget = ref(null)

/**
 * Píldoras que tienen alguna campaña, cada una con sus campañas y su resumen.
 * El servidor entrega las campañas de la más reciente a la más antigua, así
 * que el orden de primera aparición deja arriba la píldora con la última campaña.
 */
const pills = computed(() => {
  const campaignsByPill = new Map()
  for (const campaign of store.campaigns) {
    if (!campaignsByPill.has(campaign.documentId)) campaignsByPill.set(campaign.documentId, [])
    campaignsByPill.get(campaign.documentId).push(campaign)
  }
  const titles = new Map(store.documents.map(document => [document.id, document.title]))
  return [...campaignsByPill].map(([id, campaigns]) => ({
    id,
    campaigns,
    title: titles.get(id) || `Píldora #${id}`,
    lastAt: campaigns[0].launchedAt || campaigns[0].createdAt,
    summary: summarizePill(campaigns),
  }))
})

const selectedPill = computed(() => pills.value.find(pill => pill.id === selectedPillId.value) ?? null)

/** El detalle cargado, solo si es el de la campaña elegida (no uno anterior) */
const detail = computed(() =>
  store.campaignDetail?.id === selectedCampaignId.value ? store.campaignDetail : null,
)
const summary = computed(() => summarizeRecipients(detail.value?.recipients))
const openRate = computed(() => percentOf(summary.value.openedCount, summary.value.recipientCount))
const completionRate = computed(() => percentOf(summary.value.completedCount, summary.value.recipientCount))
const averageScorePercent = computed(() => scorePercent(summary.value.averageScore, detail.value?.questionCount))
const averageScoreText = computed(() => {
  if (summary.value.averageScore == null) return '—'
  const average = summary.value.averageScore.toLocaleString('es-ES', { maximumFractionDigits: 1 })
  return `${average}/${detail.value.questionCount}`
})
const listName = computed(() => store.distributionLists.find(list => list.id === detail.value?.listId)?.name ?? '')

watch(selectedPillId, (id) => {
  router.replace({ query: id ? { pildora: String(id) } : {} })
})

/**
 * Formatea una fecha con hora corta para las columnas de seguimiento.
 *
 * @param {string|null} iso - Fecha ISO del servidor.
 * @returns {string} «dd/mm, hh:mm», o «—» si el destinatario no llegó a ese punto.
 */
function formatMoment(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

/**
 * Elige una píldora y abre su campaña más reciente.
 *
 * @param {number} pillId - Id de la píldora.
 */
function selectPill(pillId) {
  if (pillId === selectedPillId.value) return
  selectedPillId.value = pillId
  selectedCampaignId.value = null
  ensureSelection()
}

/**
 * Elige una campaña y carga sus resultados, salvo que ya estén en pantalla.
 *
 * @param {number} campaignId - Id de la campaña.
 */
function selectCampaign(campaignId) {
  if (campaignId === selectedCampaignId.value && detail.value) return
  selectedCampaignId.value = campaignId
  store.loadCampaignDetail(campaignId)
}

/**
 * Deja siempre algo elegido cuando hay datos: si la píldora elegida ya no
 * existe (no venía en la URL, se borraron sus campañas) pasa a la primera, y
 * si su campaña elegida ya no está, abre la más reciente.
 */
function ensureSelection() {
  if (!pills.value.some(pill => pill.id === selectedPillId.value)) {
    selectedPillId.value = pills.value[0]?.id ?? null
    selectedCampaignId.value = null
  }
  const pill = selectedPill.value
  if (pill && !pill.campaigns.some(campaign => campaign.id === selectedCampaignId.value)) {
    selectCampaign(pill.campaigns[0].id)
  }
}

/**
 * Recarga el listado y, si la campaña elegida sigue ahí, también sus resultados.
 *
 * @returns {Promise<void>}
 */
async function refresh() {
  const previousCampaignId = selectedCampaignId.value
  await store.loadCampaigns()
  ensureSelection()
  if (previousCampaignId && selectedCampaignId.value === previousCampaignId) {
    store.loadCampaignDetail(previousCampaignId)
  }
}

/**
 * Borra la campaña confirmada y reajusta la selección.
 *
 * @returns {Promise<void>}
 */
async function confirmDelete() {
  const campaign = deleteTarget.value
  deleteTarget.value = null
  if (!campaign || !(await store.deleteCampaign(campaign.id))) return
  selectedCampaignId.value = null
  ensureSelection()
}

onMounted(async () => {
  await Promise.all([store.loadCampaigns(), store.loadHistory(), store.loadDistributionLists()])
  loaded.value = true
  ensureSelection()
})
</script>

<style scoped>
.campaigns-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }

/* Una sola pantalla con tres columnas que scrollean por su cuenta — mismo
   esqueleto que el generador, para que pasar de uno a otro no desoriente. */
.campaigns-layout { display: flex; height: calc(100vh - var(--topbar-h)); overflow: hidden; position: relative; z-index: 1; }
.panel { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
.panel--pills     { flex: 0 0 300px; background: var(--surface); border-right: 1px solid var(--border-med); }
.panel--campaigns { flex: 0 0 380px; background: var(--surface); border-right: 1px solid var(--border-med); }
.panel--detail    { flex: 1 1 0%; background: var(--surface-2); overflow-y: auto; padding: 1.4rem 1.75rem 2rem; }
.panel-scroll { flex: 1; overflow-y: auto; overflow-x: hidden; min-height: 0; padding: 0.4rem; }

.panel--pills     { animation: seq-fade-up 0.45s ease-out backwards; }
.panel--campaigns { animation: seq-fade-up 0.45s ease-out 0.07s backwards; }
.panel--detail    { animation: seq-fade-up 0.45s ease-out 0.14s backwards; }

.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.85rem 1.1rem 0.65rem; border-bottom: 1px solid var(--border); }
.panel-head h2 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }

.panel-note { padding: 2rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-lg); margin: 0; }
.panel-note p { margin: 0 0 0.6rem; }
.panel-note--error { color: var(--danger); }
.panel-note--inline { padding: 0.5rem 0; text-align: left; }
.inline-link { color: var(--accent-bright); font-size: var(--fs-md); }

.btn-icon { width: 28px; height: 28px; border-radius: 5px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0; }
.btn-icon:hover { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
.btn-icon.spinning svg { animation: seq-spin 0.7s linear infinite; }
.retry { padding: 0.25rem 0.7rem; background: transparent; border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: var(--fs-sm); cursor: pointer; transition: background var(--transition); }
.retry:hover { background: var(--danger-dim); }

/* ── Columna de píldoras ── */
.pill-row {
  display: flex; flex-direction: column; gap: 0.15rem; width: 100%;
  padding: 0.6rem 0.7rem; margin-bottom: 2px; border-radius: 7px;
  background: none; border: 1px solid transparent; font-family: inherit; text-align: left; cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.pill-row:hover { background: var(--bg); }
.pill-row--active { background: var(--bg); border-color: var(--accent); }
.pill-title { font-size: var(--fs-lg); font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.pill-meta { font-size: var(--fs-md); color: var(--text-muted); }

/* ── Columna de campañas ── */
.pill-head { padding: 1rem 1.1rem 0.4rem; }
.eyebrow { margin: 0 0 0.2rem; font-size: var(--fs-sm); font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent); }
.pill-heading { margin: 0; font-size: var(--fs-xl); font-weight: 700; color: var(--text); font-family: var(--font-display); font-size-adjust: var(--fsa-display); line-height: 1.25; }

.summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.4rem; padding: 0.6rem 1.1rem 0.9rem; border-bottom: 1px solid var(--border); }

.campaign-row {
  display: flex; flex-direction: column; gap: 0.4rem; width: 100%;
  padding: 0.6rem 0.7rem; margin-bottom: 2px; border-radius: 7px;
  background: none; border: 1px solid transparent; font-family: inherit; text-align: left; cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.campaign-row:hover { background: var(--bg); }
.campaign-row--active { background: var(--bg); border-color: var(--accent); }
.campaign-row-top, .campaign-row-bottom { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
.campaign-name { flex: 1; min-width: 0; color: var(--text); font-size: var(--fs-lg); font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.campaign-date { color: var(--text-muted); font-size: var(--fs-sm); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); flex-shrink: 0; }
.mini-progress { flex: 1; height: 4px; border-radius: 2px; background: var(--surface-2); overflow: hidden; }
.mini-progress span { display: block; height: 100%; background: var(--accent); border-radius: 2px; }
.campaign-count { color: var(--text-muted); font-size: var(--fs-sm); flex-shrink: 0; }

/* ── Detalle ── */
.detail-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
.detail-title { display: flex; flex-direction: column; align-items: flex-start; gap: 0.4rem; min-width: 0; }
.detail-title h2 { margin: 0; font-size: var(--fs-2xl); font-weight: 700; color: var(--text); font-family: var(--font-display); font-size-adjust: var(--fsa-display); overflow-wrap: anywhere; }
.detail-meta { margin: 0.5rem 0 1.2rem; color: var(--text-dim); font-size: var(--fs-md); }
.delete-btn {
  flex-shrink: 0; padding: 0.4rem 0.8rem; border-radius: 7px;
  background: transparent; border: 1px solid var(--border-solid); color: var(--text-dim);
  font-family: inherit; font-size: var(--fs-md); font-weight: 600; cursor: pointer; transition: all 0.15s;
}
.delete-btn:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }

.detail-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; }
.stat { display: flex; flex-direction: column; align-items: center; gap: 0.1rem; padding: 0.6rem 0.4rem; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; text-align: center; }
.stat-value { font-size: var(--fs-xl); font-weight: 700; color: var(--accent-bright); font-family: var(--font-display); font-size-adjust: var(--fsa-display); line-height: 1.15; }
.stat-label { font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); }
.stat-sub { font-size: var(--fs-sm); color: var(--text-dim); }
.detail-stats .stat { padding: 0.85rem 0.5rem; }
.detail-stats .stat-value { font-size: var(--fs-2xl); }

.funnel { display: flex; flex-direction: column; gap: 0.55rem; margin: 1.2rem 0 1.6rem; }
.funnel-row { display: grid; grid-template-columns: 11rem 1fr 3rem; align-items: center; gap: 0.75rem; font-size: var(--fs-md); }
.funnel-label { color: var(--text-dim); }
.funnel-value { color: var(--text); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); text-align: right; }
.progress { height: 8px; border-radius: 4px; background: var(--bg); overflow: hidden; }
.progress-fill { display: block; height: 100%; background: var(--success); border-radius: 4px; transition: width 0.35s ease; }
.progress-fill--opened { background: var(--warn); }

.section-label { margin: 0 0 0.6rem; font-size: var(--fs-md); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); }

/* Resultados por pregunta: cuánta gente eligió cada opción. La correcta se
   marca con texto además de con color, para quien no distingue el verde. */
.questions { list-style: none; margin: 0 0 1.6rem; padding: 0; display: flex; flex-direction: column; gap: 0.75rem; counter-reset: question; }
.question { padding: 0.8rem 0.95rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; counter-increment: question; }
.question-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.6rem; }
.question-prompt { color: var(--text); font-weight: 600; font-size: var(--fs-lg); line-height: 1.4; }
.question-prompt::before { content: counter(question) ". "; color: var(--text-muted); }
.question-rate { flex-shrink: 0; color: var(--accent-bright); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); }
.options { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.35rem; }
.option { display: grid; grid-template-columns: minmax(0, 1fr) 9rem 2rem; align-items: center; gap: 0.75rem; font-size: var(--fs-md); color: var(--text-dim); }
.option-text { min-width: 0; overflow-wrap: anywhere; }
.option-tag { display: inline-block; margin-left: 0.4rem; padding: 0.05rem 0.35rem; border-radius: 4px; background: var(--success-dim); color: var(--success); font-size: var(--fs-xs); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
.option--correct .option-text { color: var(--text); }
.option-bar { height: 6px; border-radius: 3px; background: var(--bg); overflow: hidden; }
.option-bar span { display: block; height: 100%; border-radius: 3px; background: var(--text-muted); }
.option--correct .option-bar span { background: var(--success); }
.option-count { text-align: right; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); color: var(--text); }

.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }
.recipients { width: 100%; border-collapse: collapse; font-size: var(--fs-md); }
.recipients th { text-align: left; padding: 0.55rem 0.75rem; font-size: var(--fs-xs); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); border-bottom: 1px solid var(--border); white-space: nowrap; }
.recipients td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); color: var(--text-dim); vertical-align: middle; }
.recipients tbody tr:last-child td { border-bottom: none; }
.recipient-name { display: block; color: var(--text); font-weight: 600; }
.recipient-email { display: block; overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.moment { white-space: nowrap; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm); }
.num { text-align: right; white-space: nowrap; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 0.35rem; background: var(--text-muted); vertical-align: middle; }
.dot--opened { background: var(--warn); }
.dot--completed { background: var(--success); }

.pill-row:focus-visible, .campaign-row:focus-visible, .btn-icon:focus-visible,
.retry:focus-visible, .delete-btn:focus-visible, .inline-link:focus-visible {
  outline: 2px solid var(--accent-bright); outline-offset: 2px;
}

@media (max-width: 1200px) {
  .campaigns-layout { flex-direction: column; height: auto; overflow: visible; }
  .panel--pills, .panel--campaigns { flex: 0 0 auto; border-right: none; border-bottom: 1px solid var(--border-med); }
  .panel-scroll { max-height: 22rem; }
  .panel--detail { overflow: visible; }
}

@media (max-width: 640px) {
  .detail-stats { grid-template-columns: repeat(2, 1fr); }
  .funnel-row { grid-template-columns: 1fr 3rem; }
  .funnel-row .progress { grid-column: 1 / -1; grid-row: 2; }
  .detail-head { flex-direction: column; }
}

@media (prefers-reduced-motion: reduce) {
  .panel--pills, .panel--campaigns, .panel--detail { animation: none !important; }
  .progress-fill { transition: none !important; }
}
</style>
