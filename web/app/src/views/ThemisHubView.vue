<template>
  <ModuleHub
    module-id="themis"
    :icon="themisIcon"
    name="Themis"
    numeral="I"
    epigraph="Iudicium"
    tagline="Detección de vulnerabilidades con motor propio y los escáneres clásicos como testigos."
    myth="La que sostiene la balanza y no dicta sentencia sin pesar antes cada indicio."
    claim="Pesa cada amenaza antes de que golpee"
    tool-route="/themis/escaneos"
    tool-label="Abrir escáner"
    :highlight="highlight"
    :shortcuts="shortcuts"
    :features="features"
    :resources="resources"
  >
    <template #metric>
      <p v-if="store.loadingStats" class="metric-loading">Cargando estadísticas…</p>
      <template v-else-if="store.stats.total">
        <span class="metric-label">Escaneos emitidos</span>
        <span class="metric-value">{{ store.stats.total }}</span>
        <span class="metric-sub">Lybra {{ store.stats.lybra }} · Nmap {{ store.stats.nmap }} · Nikto {{ store.stats.nikto }} · Nuclei {{ store.stats.nuclei }}</span>
      </template>
      <p v-else class="metric-empty">Todavía no has lanzado ningún escaneo. El primero tarda un minuto.</p>
    </template>
  </ModuleHub>
</template>

<script setup>
import { onMounted } from 'vue'
import ModuleHub from '@/components/shared/ModuleHub.vue'
import { useThemisStore } from '@/stores/themisStore'
import { useAuthStore } from '@/stores/authStore'
import themisIcon from '@/assets/images/themis/Themis-Turqoise-BgN.png'

const store = useThemisStore()
const auth = useAuthStore()

// Dato de producto para la visita pública (sin sesión no hay actividad propia).
const highlight = { label: 'El veredicto', value: 'Lybra', sub: 'motor propio, y tres escáneres como testigos' }

const shortcuts = [
  { label: 'Nuevo escaneo Lybra', to: '/themis/escaneos?world=lybra' },
  { label: 'Escáneres externos', to: '/themis/escaneos?world=external' },
  { label: 'Historial', to: '/themis/escaneos?world=lybra&view=history' },
]

const features = [
  {
    kicker: 'Motor propio',
    title: 'Lybra emite el veredicto',
    desc: 'Descubre los puertos por su cuenta, puntúa cada hallazgo en su contexto y sigue su ciclo de vida: abierto, corregido, reaparecido.',
  },
  {
    kicker: 'Segunda opinión',
    title: 'Los escáneres clásicos, como testigos',
    desc: 'Nmap, Nikto y Nuclei corroboran el mismo objetivo cuando quieres contrastar el veredicto. Un objetivo, todas las miradas.',
  },
  {
    kicker: 'Informes',
    title: 'Redactados por IA, listos para entregar',
    desc: 'Cada escaneo puede convertirse en un PDF en lenguaje claro, pensado para quien decide, no solo para quien administra.',
  },
  {
    kicker: 'Vigilia',
    title: 'Escaneos que se repiten solos',
    desc: 'Programa la recurrencia una vez y Themis vuelve al objetivo puntualmente, sin que tengas que acordarte.',
  },
]

const resources = [
  { label: 'NVD — National Vulnerability Database', href: 'https://nvd.nist.gov/', external: true },
  { label: 'OWASP', href: 'https://owasp.org/', external: true },
]

onMounted(() => { if (auth.isAuthenticated) store.loadStats() })
</script>
