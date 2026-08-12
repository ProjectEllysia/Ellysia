<template>
  <ModuleHub
    module-id="hygeia"
    :icon="hygeiaIcon"
    name="Hygeia"
    numeral="V"
    epigraph="Salus"
    tagline="Telemetría de hardware en tiempo real, con alertas antes de que el problema se note."
    myth="La diosa de la salud; vigila los signos vitales de cada activo antes de que se apague ninguno."
    claim="Vigila el pulso de cada activo"
    tool-route="/hygeia/activos"
    tool-label="Ver mis activos"
    :shortcuts="[{ label: 'Etiquetas', to: '/hygeia/etiquetas' }]"
    :highlight="highlight"
    :features="features"
    :resources="resources"
  >
    <template #metric>
      <p v-if="loading" class="metric-loading">Cargando actividad reciente…</p>
      <template v-else-if="total">
        <span class="metric-label">Activos monitorizados</span>
        <span class="metric-value">{{ total }}</span>
        <span class="metric-sub">{{ online }} en línea ahora mismo</span>
      </template>
      <p v-else class="metric-empty">Todavía no monitorizas ningún activo. Da de alta el primero.</p>
    </template>
  </ModuleHub>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import ModuleHub from '@/components/shared/ModuleHub.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/authStore'
import hygeiaIcon from '@/assets/images/hygeia/Hygeia-DarkGreen-BgN.png'

const { apiFetch } = useApi()
const auth = useAuthStore()

// Dato de producto para la visita pública (sin sesión no hay activos propios).
const highlight = { label: 'Detección de presencia', value: '< 1 min', sub: 'para saber si un host se ha caído' }

const loading = ref(true)
const total = ref(0)
const online = ref(0)

const features = [
  {
    kicker: 'Push, no pull',
    title: 'El agente empuja, tú no sondeas',
    desc: 'Un agente ligero envía heartbeats cada pocos segundos — funciona detrás de NAT, sin abrir ningún puerto en el activo.',
  },
  {
    kicker: 'Umbrales con histéresis',
    title: 'Una alerta, no un aluvión',
    desc: 'CPU, memoria, disco y swap se vigilan con umbrales configurables; una anomalía se abre una vez y se resuelve sola al normalizarse.',
  },
  {
    kicker: 'Host caído',
    title: 'El silencio también es una señal',
    desc: 'Si un activo deja de reportar, Hygeia lo detecta en dos escalones — inestable primero, caído después — y avisa.',
  },
  {
    kicker: 'Aviso por correo',
    title: 'Las anomalías críticas no esperan',
    desc: 'Una anomalía crítica dispara un correo al dueño del activo, sin bloquear ni ralentizar la ingesta de telemetría.',
  },
]

const resources = []

/** Estado actual de los activos propios — para la placa de actividad. */
async function loadAssetSummary() {
  loading.value = true
  try {
    const res = await apiFetch('/hygeia/assets')
    if (!res?.ok) return
    const { assets = [] } = await res.json()
    total.value = assets.length
    online.value = assets.filter((a) => a.status === 'online').length
  } finally {
    loading.value = false
  }
}

onMounted(() => { if (auth.isAuthenticated) loadAssetSummary(); else loading.value = false })
</script>
