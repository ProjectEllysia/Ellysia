<template>
  <div class="logs-page">
    <StarBackground />
    <Topbar title="Logs del sistema" />

    <main class="main">
      <header class="page-header">
        <div>
          <span class="eyebrow">Observatorio interno</span>
          <h1>Logs del sistema</h1>
          <p class="subtitle">Busca actividad de la API sin abandonar el hilo de la operación.</p>
        </div>
        <button class="btn btn--secondary" type="button" :disabled="store.loading" @click="refresh">
          {{ store.loading ? 'Actualizando…' : 'Actualizar' }}
        </button>
      </header>

      <form class="filter-panel" @submit.prevent="applyFilters">
        <div class="filter-heading">
          <div>
            <span class="filter-kicker">Consulta</span>
            <h2>Acota la lectura</h2>
          </div>
          <span class="snapshot-state" :class="{ 'snapshot-state--live': store.meta.currentBytes > store.meta.snapshotBytes }">
            {{ snapshotLabel }}
          </span>
        </div>

        <div class="filter-grid">
          <div class="form-group form-group--wide">
            <label>Orden de lectura</label>
            <div class="segmented" role="radiogroup" aria-label="Orden de lectura">
              <label class="segment" :class="{ active: draft.position === 'tail' }">
                <input v-model="draft.position" type="radio" value="tail" />
                <span>Últimas líneas</span>
              </label>
              <label class="segment" :class="{ active: draft.position === 'head' }">
                <input v-model="draft.position" type="radio" value="head" />
                <span>Primeras líneas</span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <label for="logs-from">Desde</label>
            <input id="logs-from" v-model="draft.from" type="datetime-local" step="1" class="inp" />
          </div>
          <div class="form-group">
            <label for="logs-to">Hasta</label>
            <input id="logs-to" v-model="draft.to" type="datetime-local" step="1" class="inp" />
          </div>
          <div class="form-group">
            <label for="logs-level">Nivel</label>
            <select id="logs-level" v-model="draft.level" class="inp">
              <option value="">Todos</option>
              <option value="DEBUG">DEBUG</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>
          <div class="form-group">
            <label for="logs-page-size">Líneas por página</label>
            <select id="logs-page-size" v-model.number="draft.perPage" class="inp">
              <option :value="50">50</option>
              <option :value="100">100</option>
              <option :value="250">250</option>
              <option :value="500">500</option>
            </select>
          </div>
          <div class="form-group form-group--wide">
            <label for="logs-contains">Contiene</label>
            <input
              id="logs-contains"
              v-model.trim="draft.contains"
              type="search"
              maxlength="200"
              class="inp"
              placeholder="usuario, ruta, excepción…"
            />
          </div>
        </div>

        <div class="filter-actions">
          <span class="filter-hint">Las fechas usan la hora del servidor{{ store.meta.timeZone ? ` (${store.meta.timeZone})` : '' }}.</span>
          <button class="btn btn--primary" type="submit" :disabled="store.loading">Aplicar filtros</button>
        </div>
      </form>

      <div v-if="store.loading && !store.content" class="loading-block" aria-live="polite">
        <div class="log-skeleton" v-for="line in 8" :key="line"></div>
      </div>

      <section v-else-if="store.error" class="state state--error" role="alert">
        <span class="state-mark">!</span>
        <div>
          <h2>{{ store.errorStatus === 409 ? 'La lectura quedó obsoleta' : 'No se pudo cargar el log' }}</h2>
          <p>{{ store.error }}</p>
        </div>
        <button class="btn btn--secondary" type="button" @click="recover">Iniciar lectura nueva</button>
      </section>

      <section v-else class="log-card" aria-live="polite">
        <div class="log-card-head">
          <div>
            <span class="log-card-kicker">secops.log</span>
            <h2>{{ resultLabel }}</h2>
          </div>
          <div class="log-stats">
            <span>{{ formatBytes(store.meta.totalBytes) }}</span>
            <span>{{ store.meta.totalLines }} líneas</span>
          </div>
        </div>

        <div v-if="store.meta.truncated" class="notice" role="status">
          Esta vista muestra una página de {{ store.meta.totalLines }} líneas coincidentes.
        </div>
        <div v-if="store.content" class="log-window">
          <pre>{{ store.content }}</pre>
        </div>
        <div v-else class="empty-state">No hay líneas que coincidan con estos filtros.</div>

        <footer class="log-card-foot">
          <span class="line-range">{{ lineRange }}</span>
          <nav class="pagination" aria-label="Paginación de logs">
            <button class="page-btn" type="button" :disabled="!store.meta.hasPrevious || store.loading" @click="goToPage(store.meta.page - 1)">
              Anterior
            </button>
            <span class="page-status">Página {{ store.meta.page }} / {{ store.meta.totalPages || 1 }}</span>
            <button class="page-btn" type="button" :disabled="!store.meta.hasNext || store.loading" @click="goToPage(store.meta.page + 1)">
              Siguiente
            </button>
          </nav>
        </footer>
      </section>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useLogsStore } from '@/stores/logsStore'

const store = useLogsStore()

const draft = reactive({
  position: 'tail',
  from: '',
  to: '',
  level: '',
  contains: '',
  perPage: 100,
})
const applied = ref({ ...draft, page: 1 })

const snapshotLabel = computed(() => {
  if (!store.meta.snapshotBytes) return 'Sin snapshot'
  return store.meta.currentBytes > store.meta.snapshotBytes ? 'Hay líneas nuevas' : 'Lectura estable'
})

const resultLabel = computed(() => {
  if (!store.meta.returnedLines) return 'Sin coincidencias'
  return store.meta.position === 'tail' ? 'Entradas más recientes' : 'Entradas iniciales'
})

const lineRange = computed(() => {
  if (!store.meta.returnedLines) return '0 líneas en esta página'
  if (store.meta.firstLine === store.meta.lastLine) return `Línea ${store.meta.firstLine}`
  return `Líneas ${store.meta.firstLine}–${store.meta.lastLine}`
})

async function applyFilters() {
  applied.value = { ...draft, page: 1 }
  store.resetSnapshot()
  await store.loadLogs(applied.value)
}

async function goToPage(page) {
  await store.loadLogs({ ...applied.value, page })
}

async function refresh() {
  store.resetSnapshot()
  await store.loadLogs({ ...applied.value })
}

async function recover() {
  store.resetSnapshot()
  await store.loadLogs({ ...applied.value, page: 1 })
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

onMounted(() => applyFilters())
</script>

<style scoped>
.logs-page {
  min-height: 100vh;
  background:
    radial-gradient(circle at 88% 8%, rgba(212,160,74,0.08), transparent 28rem),
    var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}
.main { max-width: 1120px; margin: 0 auto; padding: 2rem 1.1rem 4.5rem; position: relative; z-index: 1; }
.page-header { display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem; margin-bottom: 1.4rem; }
.eyebrow, .filter-kicker, .log-card-kicker {
  display: block;
  color: var(--accent);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-sm); letter-spacing: 0.15em; text-transform: uppercase;
}
.page-header h1 { margin: 0.35rem 0 0; color: var(--text); font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-3xl); font-weight: 800; }
.subtitle { margin: 0.35rem 0 0; color: var(--text-dim); font-size: var(--fs-lg); }
.filter-panel, .log-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 18px 50px rgba(0,0,0,0.18); }
.filter-panel { padding: 1.15rem; margin-bottom: 1.1rem; }
.filter-heading { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; padding-bottom: 0.9rem; border-bottom: 1px solid var(--border); }
.filter-heading h2, .log-card-head h2 { margin: 0.25rem 0 0; color: var(--text); font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-xl); }
.snapshot-state { color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm); }
.snapshot-state--live { color: var(--warn); }
.filter-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.85rem; padding-top: 1rem; }
.form-group--wide { grid-column: span 2; }
.form-group label { display: block; color: var(--text-muted); font-size: var(--fs-md); font-weight: 600; margin-bottom: 0.35rem; }
.inp { width: 100%; }
.segmented { display: flex; gap: 0.35rem; min-height: 40px; }
.segment { flex: 1; display: flex; align-items: center; justify-content: center; border: 1px solid var(--border-med); border-radius: 7px; color: var(--text-dim); cursor: pointer; font-size: var(--fs-md); transition: all 0.2s ease; }
.segment input { position: absolute; opacity: 0; pointer-events: none; }
.segment.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.segment:focus-within { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
.filter-actions { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-top: 1rem; }
.filter-hint { color: var(--text-muted); font-size: var(--fs-sm); }
.log-card { overflow: hidden; }
.log-card-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; padding: 1.1rem 1.15rem; border-bottom: 1px solid var(--border); }
.log-stats { display: flex; gap: 0.85rem; color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm); text-align: right; }
.notice { padding: 0.6rem 1.15rem; background: var(--warn-dim); color: var(--warn); border-bottom: 1px solid var(--border); font-size: var(--fs-md); }
.log-window { max-height: 62vh; overflow: auto; background: var(--bg); }
.log-window pre { min-width: max-content; margin: 0; padding: 1rem 1.15rem 1.25rem; color: var(--text); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm); line-height: 1.65; tab-size: 4; }
.log-card-foot { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.85rem 1.15rem; border-top: 1px solid var(--border); }
.line-range, .page-status { color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-sm); }
.pagination { display: flex; align-items: center; gap: 0.65rem; }
.page-btn { padding: 0.4rem 0.65rem; border: 1px solid var(--border-med); border-radius: 6px; color: var(--text-dim); background: var(--surface-2); font-size: var(--fs-md); cursor: pointer; }
.page-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent-bright); }
.page-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.loading-block { display: flex; flex-direction: column; gap: 0.45rem; padding: 1rem 0; }
.log-skeleton { height: 1.25rem; border-radius: 4px; background: var(--surface); animation: pulse 1.4s ease-in-out infinite; }
.state { display: flex; align-items: center; gap: 0.8rem; padding: 1.2rem; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
.state--error { color: var(--danger); }
.state h2 { margin: 0; color: var(--text); font-size: var(--fs-lg); }
.state p { margin: 0.25rem 0 0; color: var(--text-dim); }
.state-mark { display: grid; place-items: center; width: 2rem; height: 2rem; border: 1px solid currentColor; border-radius: 50%; font-weight: 800; }
.empty-state { padding: 4rem 1rem; color: var(--text-muted); text-align: center; font-size: var(--fs-lg); }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.42; } }
@media (max-width: 800px) {
  .page-header { align-items: flex-start; flex-direction: column; }
  .filter-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .form-group--wide { grid-column: span 2; }
  .log-card-head, .log-card-foot { align-items: flex-start; flex-direction: column; }
  .log-stats { text-align: left; }
}
@media (max-width: 520px) {
  .main { padding-inline: 0.75rem; }
  .filter-grid { display: block; }
  .form-group { margin-top: 0.8rem; }
  .filter-grid .form-group:first-child { margin-top: 0; }
  .filter-actions { align-items: stretch; flex-direction: column; }
  .filter-actions .btn { width: 100%; }
  .segmented { min-height: 44px; }
  .pagination { justify-content: space-between; width: 100%; }
  .page-status { order: 2; }
}
</style>
