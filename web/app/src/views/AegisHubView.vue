<template>
  <ModuleHub
    module-id="aegis"
    :icon="aegisIcon"
    name="Aegis"
    numeral="II"
    epigraph="Praesidio"
    tagline="Formación de concienciación generada por IA, enviada y demostrada con campañas."
    myth="El escudo de Zeus y Atenea, forjado para proteger antes del golpe."
    claim="Concienciación que llega antes que el ataque"
    tool-route="/aegis/generador"
    tool-label="Abrir generador"
    :highlight="highlight"
    :features="features"
    :resources="resources"
  >
    <template #metric>
      <p v-if="loading" class="metric-loading">Cargando última campaña…</p>
      <template v-else-if="lastCampaign">
        <span class="metric-label">Última campaña — {{ lastCampaign.name }}</span>
        <span class="metric-value">{{ completionRate }}% completado</span>
        <span class="metric-sub">{{ completedCount }} de {{ totalRecipients }} destinatarios</span>
      </template>
      <p v-else class="metric-empty">Aún no has lanzado ninguna campaña. Genera una píldora y estrénala.</p>
    </template>
  </ModuleHub>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import ModuleHub from '@/components/shared/ModuleHub.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/authStore'
import aegisIcon from '@/assets/images/aegis/Ellysia-Aegis-Blue-BgN.png'

const { apiFetch } = useApi()
const auth = useAuthStore()

// Dato de producto para la visita pública (sin sesión no hay campañas propias).
const highlight = { label: 'La formación', value: 'A Medida', sub: 'generada por IA para tu normativa' }

const loading = ref(true)
const lastCampaign = ref(null)
const totalRecipients = ref(0)
const completedCount = ref(0)

const completionRate = computed(() =>
  totalRecipients.value ? Math.round((completedCount.value / totalRecipients.value) * 100) : 0
)

const features = [
  {
    kicker: 'Píldoras IA',
    title: 'Formación a la medida de tu empresa',
    desc: 'La IA escribe cada píldora según tu tamaño, tu marco regulatorio (RGPD, ENS, NIS2), tu modelo de trabajo e incluso tus incidentes recientes.',
  },
  {
    kicker: 'Quiz',
    title: 'Cada píldora comprueba que caló',
    desc: 'Junto al contenido se generan preguntas tipo test, editables antes de lanzar. Saber no es suponer.',
  },
  {
    kicker: 'Campañas',
    title: 'Envía, sigue, demuestra',
    desc: 'Listas de distribución, envío por correo y seguimiento de quién abrió y quién completó. El test es público: tu plantilla no necesita cuentas.',
  },
  {
    kicker: 'Evidencia',
    title: 'Exportable como cumplimiento',
    desc: 'Markdown, JSON o PDF listos para archivar como prueba de que la formación ocurrió.',
  },
]

const resources = [
  { label: 'INCIBE — Guías de concienciación para empresas', href: 'https://www.incibe.es/', external: true },
]

/** Última campaña lanzada (no en borrador) — para la placa de actividad. */
async function loadLastCampaignMetric() {
  loading.value = true
  try {
    const listRes = await apiFetch('/aegis/campaigns')
    if (!listRes?.ok) return
    const { campaigns = [] } = await listRes.json()

    const launched = campaigns
      .filter((c) => c.status !== 'draft' && c.launchedAt)
      .sort((a, b) => new Date(b.launchedAt) - new Date(a.launchedAt))

    if (!launched.length) return

    const detailRes = await apiFetch(`/aegis/campaigns/${launched[0].id}`)
    if (!detailRes?.ok) return
    const detail = await detailRes.json()

    lastCampaign.value = detail
    totalRecipients.value = detail.recipients?.length ?? 0
    completedCount.value = detail.recipients?.filter((r) => r.status === 'completed').length ?? 0
  } finally {
    loading.value = false
  }
}

onMounted(() => { if (auth.isAuthenticated) loadLastCampaignMetric(); else loading.value = false })
</script>
