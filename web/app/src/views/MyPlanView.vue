<template>
  <div class="plan-page">
    <StarBackground />
    <Topbar title="Mi plan" />

    <main class="main">
      <div v-if="account.loading" class="skeleton skeleton--lg"></div>

      <template v-else-if="account.plan">
        <!-- Avisos: caducidad, impago o cancelación pendiente -->
        <div v-if="account.notice" class="notice" :class="`notice--${account.notice.kind}`">
          {{ account.notice.text }}
        </div>

        <section class="head">
          <div>
            <span class="head-eyebrow">Tu plan</span>
            <h1 class="head-name">{{ account.plan.plan.name }}</h1>
            <p v-if="account.plan.plan.tagline" class="head-tagline">
              {{ account.plan.plan.tagline }}
            </p>
          </div>
          <router-link to="/planes" class="btn btn--secondary">Ver todos los planes</router-link>
        </section>

        <section v-if="source" class="source">{{ source }}</section>

        <section class="section">
          <h2>Consumo</h2>
          <p class="section-desc">
            Lo que va del periodo. Las existencias no se reinician: se liberan
            borrando.
          </p>

          <ul class="limits">
            <li v-for="(entry, key) in sortedUsage" :key="key" class="row"
                :class="{ 'row--exceeded': entry.exceeded }">
              <div class="row-head">
                <span class="row-label">{{ label(key) }}</span>
                <span class="row-value">{{ describe(entry) }}</span>
              </div>
              <div class="bar" :aria-hidden="entry.value === null || entry.value === 0">
                <div class="bar-fill" :style="{ width: percent(entry) }"></div>
              </div>
              <p v-if="entry.exceeded" class="row-note">
                Por encima del tope: puedes leer y borrar, pero no crear más hasta
                bajar de {{ entry.value }}. No se ha borrado nada.
              </p>
              <p v-else-if="entry.resetsAt" class="row-note row-note--muted">
                Se renueva el {{ account.formatDate(entry.resetsAt) }}
              </p>
            </li>
          </ul>
        </section>
      </template>

      <p v-else class="empty">No se ha podido cargar tu plan.</p>
    </main>
  </div>
</template>

<script setup>
/**
 * Consumo y límites de la cuenta.
 *
 * `plan` y `status` pueden no casar, y es intencionado: un Gold caducado
 * enseña los topes de Freemium con un aviso que dice cuándo terminó. Degradar
 * en silencio sería peor que degradar.
 */
import { computed, onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useAccountStore } from '@/stores/accountStore'

const account = useAccountStore()

const LABELS = {
  'themis.lybra.scans': 'Escaneos de Lybra',
  'themis.thirdparty.scans': 'Escaneos con Nmap / Nikto / Nuclei',
  'themis.scheduled': 'Escaneos programados',
  'themis.reports.ai': 'Informes con IA',
  'aegis.pills': 'Píldoras de concienciación',
  'aegis.campaigns': 'Campañas lanzadas',
  'aegis.recipients': 'Destinatarios en listas',
  'iris.analyses': 'Análisis de correo',
  'iris.ai_summaries': 'Resúmenes con IA',
  'iris.mailbox.connections': 'Buzones conectados',
  'acheron.vaults': 'Bóvedas',
  'acheron.items': 'Secretos guardados',
  'hygeia.assets': 'Activos monitorizados',
  'ai.requests': 'Peticiones a la IA',
  'organization.members': 'Miembros de la organización',
}

/** Lo excedido primero: es lo único que exige una acción. */
const sortedUsage = computed(() => {
  const entries = Object.entries(account.usage)
  entries.sort(([, a], [, b]) => Number(b.exceeded) - Number(a.exceeded))
  return Object.fromEntries(entries)
})

const source = computed(() => {
  if (!account.plan) return ''
  if (account.plan.source === 'default') {
    return 'Estás en el plan gratuito.'
  }
  return ''
})

function label(key) {
  return LABELS[key] ?? key
}

function describe(entry) {
  if (entry.value === 0) return 'No incluido'
  if (entry.used === null) return entry.value === null ? 'Ilimitado' : `hasta ${entry.value}`
  if (entry.value === null) return `${entry.used} · ilimitado`
  return `${entry.used} / ${entry.value}`
}

function percent(entry) {
  if (entry.value === null || entry.value === 0 || entry.used === null) return '0%'
  return `${Math.min(100, Math.round((entry.used / entry.value) * 100))}%`
}

onMounted(() => account.loadAll())
</script>

<style scoped>
.plan-page { min-height: 100vh; background: var(--bg); }
.main { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.empty { color: var(--text-muted); text-align: center; padding: 3rem 0; }

.notice {
  padding: 0.9rem 1.1rem; border-radius: 8px; margin-bottom: 1.5rem;
  font-size: var(--fs-md);
  border: 1px solid var(--border-med);
  background: var(--accent-dim);
  color: var(--text);
}
.notice--warn { border-color: var(--warning, #d4a04a); }

.head {
  display: flex; align-items: flex-end; justify-content: space-between;
  gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1.5rem;
}
.head-eyebrow {
  font-family: var(--font-epic); font-size: var(--fs-body); font-weight: 500;
  letter-spacing: 0.3em; text-transform: uppercase; color: var(--accent);
}
.head-name {
  font-family: var(--font-display); font-size: clamp(1.8rem, 4vw, 2.4rem);
  font-weight: 600; color: var(--text); margin-top: 0.3rem;
}
.head-tagline { color: var(--text-muted); margin-top: 0.2rem; }

.source { color: var(--text-muted); font-size: var(--fs-md); margin-bottom: 1.5rem; }

.section {
  background: var(--surface); border: 1px solid var(--border-solid);
  border-radius: 12px; padding: 1.5rem;
}
.section h2 { font-size: var(--fs-xl); font-weight: 600; color: var(--text); }
.section-desc { font-size: var(--fs-body); color: var(--text-muted); margin-top: 0.3rem; }

.limits { list-style: none; margin-top: 1.4rem; display: flex; flex-direction: column; gap: 1.2rem; }
.row-head { display: flex; justify-content: space-between; gap: 1rem; margin-bottom: 0.4rem; }
.row-label { color: var(--text-dim); font-size: var(--fs-md); }
.row-value { color: var(--text); font-weight: 600; font-family: var(--font-mono); font-size: var(--fs-body); }

.bar { height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; }
.bar-fill { height: 100%; background: var(--accent); transition: width 0.4s ease; }
.row--exceeded .bar-fill { background: var(--danger); }

.row-note { font-size: var(--fs-body); color: var(--danger); margin-top: 0.4rem; }
.row-note--muted { color: var(--text-muted); }

.btn {
  font-family: var(--font-epic); font-size: var(--fs-body); font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  padding: 0.6rem 1.2rem; border-radius: 3px;
  border: 1px solid var(--border-med); color: var(--text-dim);
  transition: all var(--transition);
}
.btn:hover { border-color: var(--accent); color: var(--accent-bright); }
</style>
