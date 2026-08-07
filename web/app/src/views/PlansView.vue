<template>
  <div class="plans-page">
    <SiteHeader />

    <main class="main">
      <header class="intro">
        <span class="eyebrow">Planes</span>
        <h1 class="title">Defenderse no debería ser un privilegio</h1>
        <p class="lede">
          Empieza gratis. Sube cuando tus activos lo pidan, no cuando lo pida una
          licencia.
        </p>
      </header>

      <p v-if="loaded && !account.catalog.length" class="empty">
        Todavía no hay planes publicados.
      </p>

      <section v-else class="grid">
        <article v-for="plan in account.catalog" :key="plan.code" class="card"
                 :class="{ 'card--default': plan.isDefault }">
          <header class="card-head">
            <h2 class="card-name">{{ plan.name }}</h2>
            <p v-if="plan.tagline" class="card-tagline">{{ plan.tagline }}</p>
            <p class="card-price">
              <span class="card-amount">{{ euros(plan.monthlyPriceCents) }}</span>
              <span class="card-period">/mes</span>
            </p>
            <p v-if="plan.orgAddonPriceCents" class="card-addon">
              +{{ euros(plan.orgAddonPriceCents) }}/mes con organización
            </p>
          </header>

          <ul class="card-limits">
            <li v-for="key in FEATURED" :key="key" class="limit">
              <span class="limit-label">{{ LABELS[key] }}</span>
              <span class="limit-value" :class="{ 'limit-value--none': isZero(plan, key) }">
                {{ describe(plan, key) }}
              </span>
            </li>
          </ul>

          <router-link v-if="!auth.isAuthenticated" to="/login" class="card-cta">
            {{ plan.isDefault ? 'Empezar gratis' : 'Entrar' }}
          </router-link>
          <router-link v-else to="/mi-plan" class="card-cta">Ver mi plan</router-link>
        </article>
      </section>

      <p class="footnote">
        Los planes con organización reparten sus límites entre los miembros: una
        bolsa común, no una licencia por cabeza. Y unirse a una organización nunca
        sustituye tu plan personal — se suman.
      </p>
    </main>

    <SiteFooter />
  </div>
</template>

<script setup>
/**
 * Tabla de precios. Pública: la ve quien todavía no tiene cuenta.
 *
 * Se enseña un puñado de claves y no las quince: una tabla con quince filas por
 * plan no la lee nadie. El detalle completo está en "Mi plan", ya con el
 * consumo al lado, que es donde de verdad importa.
 */
import { onMounted, ref } from 'vue'
import SiteHeader from '@/components/shared/SiteHeader.vue'
import SiteFooter from '@/components/shared/SiteFooter.vue'
import { useAccountStore } from '@/stores/accountStore'
import { useAuthStore } from '@/stores/authStore'

const account = useAccountStore()
const auth = useAuthStore()

const FEATURED = [
  'themis.lybra.scans',
  'iris.analyses',
  'acheron.items',
  'hygeia.assets',
  'ai.requests',
  'organization.members',
]

const LABELS = {
  'themis.lybra.scans': 'Escaneos de vulnerabilidades',
  'iris.analyses': 'Análisis de correo',
  'acheron.items': 'Secretos en la bóveda',
  'hygeia.assets': 'Activos monitorizados',
  'ai.requests': 'Peticiones a la IA',
  'organization.members': 'Miembros de la organización',
}

function euros(cents) {
  return `${(cents / 100).toLocaleString('es-ES', { maximumFractionDigits: 0 })} €`
}

function limitOf(plan, key) {
  return plan.limits?.holder?.[key]
}

function isZero(plan, key) {
  const limit = limitOf(plan, key)
  return !limit || limit.value === 0
}

/** `null` es ilimitado y `0` es "no incluido": no son lo mismo. */
function describe(plan, key) {
  const limit = limitOf(plan, key)
  if (!limit || limit.value === 0) return 'No incluido'
  if (limit.value === null) return 'Ilimitado'
  return limit.period === 'month' ? `${limit.value} al mes` : `${limit.value}`
}

const loaded = ref(false)

onMounted(async () => {
  await account.loadCatalog()
  loaded.value = true
})
</script>

<style scoped>
.plans-page { min-height: 100vh; background: var(--bg); display: flex; flex-direction: column; }
.main { flex: 1; max-width: 1180px; margin: 0 auto; padding: 3.5rem 1.5rem 4rem; width: 100%; }

.intro { text-align: center; margin-bottom: 3rem; }
.eyebrow {
  font-family: var(--font-epic); font-size: var(--fs-md); font-weight: 500;
  letter-spacing: 0.42em; text-transform: uppercase; color: var(--accent);
}
.title {
  font-family: var(--font-display);
  font-size: clamp(1.9rem, 4vw, 2.8rem); font-weight: 600;
  color: var(--text); margin-top: 0.9rem; line-height: 1.2;
}
.lede { font-size: var(--fs-xl); color: var(--text-muted); margin-top: 0.8rem; }
.empty { text-align: center; color: var(--text-muted); padding: 3rem 0; }

.grid {
  display: grid; gap: 1.5rem;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
}

.card {
  display: flex; flex-direction: column;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 12px;
  padding: 1.6rem 1.4rem;
}
.card--default { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent-dim); }

.card-name {
  font-family: var(--font-epic); font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.16em; text-transform: uppercase; color: var(--text);
}
.card-tagline { font-size: var(--fs-body); color: var(--text-muted); margin-top: 0.3rem; min-height: 2.4em; }
.card-price { margin-top: 1rem; }
.card-amount { font-size: 2rem; font-weight: 700; color: var(--accent-bright); }
.card-period { font-size: var(--fs-md); color: var(--text-muted); margin-left: 0.2rem; }
.card-addon { font-size: var(--fs-body); color: var(--text-muted); margin-top: 0.3rem; }

.card-limits {
  list-style: none; margin: 1.4rem 0; padding: 1.2rem 0 0;
  border-top: 1px solid var(--border);
  display: flex; flex-direction: column; gap: 0.6rem; flex: 1;
}
.limit { display: flex; justify-content: space-between; gap: 0.8rem; font-size: var(--fs-body); }
.limit-label { color: var(--text-dim); }
.limit-value { color: var(--text); font-weight: 600; text-align: right; white-space: nowrap; }
.limit-value--none { color: var(--text-muted); font-weight: 400; }

.card-cta {
  display: block; text-align: center;
  font-family: var(--font-epic); font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.16em; text-transform: uppercase;
  padding: 0.7rem 1rem; border-radius: 3px;
  color: var(--accent-bright); background: var(--accent-dim);
  border: 1px solid var(--accent);
  transition: all var(--transition);
}
.card-cta:hover { background: var(--accent); color: var(--on-accent); }

.footnote {
  margin-top: 2.5rem; text-align: center;
  font-size: var(--fs-body); color: var(--text-muted);
  max-width: 62ch; margin-left: auto; margin-right: auto;
}
</style>
