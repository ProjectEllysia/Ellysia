<template>
  <ModuleHub
    module-id="iris"
    :icon="irisIcon"
    name="Iris"
    numeral="III"
    epigraph="Veritas"
    tagline="Análisis de cabeceras de correo contra el phishing, con veredicto explicado."
    myth="La mensajera de los dioses; ningún mensaje falso cruza su arco."
    claim="Verifica quién firma cada correo"
    tool-route="/iris/analisis"
    tool-label="Analizar un correo"
    :highlight="highlight"
    :features="features"
    :resources="resources"
  >
    <template #metric>
      <p v-if="loading" class="metric-loading">Cargando actividad reciente…</p>
      <template v-else-if="recentTotal">
        <span class="metric-label">Correos examinados</span>
        <span class="metric-value">{{ recentTotal }}</span>
        <span class="metric-sub">{{ phishingCount }} marcados como phishing ({{ phishingRate }}%)</span>
      </template>
      <p v-else class="metric-empty">Todavía no has examinado ningún correo. Arrastra un .eml y empieza.</p>
    </template>
  </ModuleHub>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import ModuleHub from '@/components/shared/ModuleHub.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/authStore'
import irisIcon from '@/assets/images/iris/Iris-Red-BgN.png'

const { apiFetch } = useApi()
const auth = useAuthStore()

// Dato de producto para la visita pública (sin sesión no hay análisis propios).
const highlight = { label: 'La verificación', value: '37 reglas', sub: 'contra el phishing en cada correo' }

const loading = ref(true)
const recentTotal = ref(0)
const phishingCount = ref(0)

const phishingRate = computed(() =>
  recentTotal.value ? Math.round((phishingCount.value / recentTotal.value) * 100) : 0
)

const features = [
  {
    kicker: '37 reglas',
    title: 'La firma del correo, a examen',
    desc: 'SPF, DKIM, DMARC, suplantación de remitente y anomalías en la ruta de entrega: cada cabecera declara, y las 37 reglas escuchan.',
  },
  {
    kicker: 'Quishing',
    title: 'Los códigos QR también declaran',
    desc: 'Los QR incrustados en el correo se decodifican y analizan como el vector de phishing que pueden ser.',
  },
  {
    kicker: 'IOCs',
    title: 'Listos para bloquear',
    desc: 'Dominios, IPs y enlaces sospechosos extraídos del mensaje, preparados para llevarlos a tu gateway.',
  },
  {
    kicker: 'Veredicto',
    title: 'Explicado, no solo puntuado',
    desc: 'Un resumen en lenguaje natural cuenta por qué el correo es legítimo, sospechoso o phishing — no te deja solo ante un número.',
  },
]

const resources = [
  { label: 'INCIBE — Oficina de Seguridad del Internauta (OSI)', href: 'https://www.osi.es/', external: true },
]

/** Actividad reciente (hasta 100 análisis más nuevos) — para la placa de actividad. */
async function loadRecentActivity() {
  loading.value = true
  try {
    const res = await apiFetch('/iris/results?page=1&per_page=100')
    if (!res?.ok) return
    const { analyses = [] } = await res.json()
    recentTotal.value = analyses.length
    phishingCount.value = analyses.filter((a) => a.verdict === 'Phishing').length
  } finally {
    loading.value = false
  }
}

onMounted(() => { if (auth.isAuthenticated) loadRecentActivity(); else loading.value = false })
</script>
