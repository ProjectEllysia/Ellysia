<template>
  <ModuleHub
    module-id="acheron"
    :icon="acheronIcon"
    name="Acheron"
    numeral="IV"
    epigraph="Custodia"
    tagline="Bóveda cifrada en tu navegador: el servidor solo ve el cifrado, nunca la llave."
    myth="El río que nadie cruza sin la llave."
    claim="Guarda lo que no debe perderse"
    tool-route="/acheron/boveda"
    tool-label="Abrir bóveda"
    :highlight="highlight"
    :features="features"
    :resources="resources"
  >
    <template #metric>
      <p v-if="loading" class="metric-loading">Comprobando tu bóveda…</p>
      <template v-else-if="itemCount">
        <span class="metric-label">Secretos custodiados</span>
        <span class="metric-value">{{ itemCount }}</span>
        <span v-if="lastUpdated" class="metric-sub">Última actualización: {{ lastUpdatedLabel }}</span>
      </template>
      <p v-else class="metric-empty">Todavía no tienes bóveda. Crear la tuya lleva un minuto.</p>
    </template>
  </ModuleHub>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import ModuleHub from '@/components/shared/ModuleHub.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/authStore'
import acheronIcon from '@/assets/images/acheron/Acheron-Purple-BgN.png'

const { apiFetch } = useApi()
const auth = useAuthStore()

// Dato de producto para la visita pública (sin sesión no hay bóveda propia).
const highlight = { label: 'Conocimiento cero', value: '0 llaves', sub: 'viajan a nuestro servidor' }

const loading = ref(true)
const itemCount = ref(0)
const lastUpdated = ref(null)

const lastUpdatedLabel = computed(() =>
  lastUpdated.value ? new Date(lastUpdated.value).toLocaleDateString('es-ES') : ''
)

const features = [
  {
    kicker: 'Cifrado local',
    title: 'La llave nunca viaja',
    desc: 'AES-256-GCM en tu navegador: el servidor guarda el cifrado y solo tú posees la contraseña maestra. Ni siquiera nosotros podemos leer tu bóveda.',
  },
  {
    kicker: 'Siete tipos',
    title: 'Una bóveda para todo',
    desc: 'Credenciales, tarjetas, notas y más, bajo la misma contraseña maestra y el mismo cifrado.',
  },
  {
    kicker: 'Generador',
    title: 'Contraseñas fuertes al vuelo',
    desc: 'Genera y guarda contraseñas robustas sin salir de la bóveda, con medidor de fortaleza incluido.',
  },
  {
    kicker: 'La llave de Lybra',
    title: 'Alimenta el escaneo autenticado',
    desc: 'Las credenciales custodiadas aquí pueden abrir la puerta a los escaneos autenticados de Themis. Acheron no es solo el candado: es la llave.',
  },
]

const resources = [
  { label: 'NIST — Guía de gestión de contraseñas (SP 800-63B)', href: 'https://pages.nist.gov/800-63-3/sp800-63b.html', external: true },
]

/**
 * El recuento de secretos y la fecha de última modificación son metadatos en
 * claro (título y timestamps no van cifrados, solo el contenido sensible de
 * cada tipo) — por eso se pueden mostrar sin pedir la contraseña maestra,
 * igual que ya hace AcheronView para decidir si la bóveda existe.
 */
async function loadVaultMetric() {
  loading.value = true
  try {
    const res = await apiFetch('/acheron/vault')
    if (!res?.ok) return
    const data = await res.json()

    const lists = Object.values(data).filter((v) => Array.isArray(v))
    itemCount.value = lists.reduce((sum, list) => sum + list.length, 0)

    const timestamps = lists.flat().map((item) => item.updatedAt).filter(Boolean)
    if (timestamps.length) lastUpdated.value = timestamps.sort().at(-1)
  } finally {
    loading.value = false
  }
}

onMounted(() => { if (auth.isAuthenticated) loadVaultMetric(); else loading.value = false })
</script>
