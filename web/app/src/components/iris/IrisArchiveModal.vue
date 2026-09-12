<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="show" class="archive-overlay" @click.self="close">
        <div ref="boxRef" class="archive-box" role="dialog" aria-modal="true" aria-labelledby="archive-title">
          <span class="tick tick--tl"></span>
          <span class="tick tick--tr"></span>
          <span class="tick tick--bl"></span>
          <span class="tick tick--br"></span>

          <header class="archive-header">
            <div class="archive-heading">
              <p class="archive-eyebrow">Archivo de análisis</p>
              <h2 id="archive-title" class="archive-title">Histórico completo</h2>
            </div>
            <button type="button" class="archive-close" title="Cerrar (Esc)" aria-label="Cerrar archivo" @click="close">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </header>

          <div class="archive-filters">
            <div class="archive-search">
              <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>
              </svg>
              <input
                ref="searchRef"
                v-model="searchInput"
                type="text"
                class="search-input"
                placeholder="Buscar por título… (/)"
                aria-label="Buscar por título"
              />
              <button v-if="searchInput" type="button" class="search-clear" aria-label="Limpiar búsqueda" @click="searchInput = ''">&times;</button>
            </div>

            <div class="pill-group" role="group" aria-label="Filtrar por veredicto">
              <button v-for="opt in verdictOptions" :key="opt.value" type="button" class="pill"
                :class="{ active: store.archive.filters.verdict === opt.value }"
                @click="store.setArchiveFilters({ verdict: opt.value })">
                <span v-if="opt.dot" class="pill-dot" :class="`pill-dot--${opt.dot}`"></span>{{ opt.label }}
              </button>
            </div>

            <div class="pill-group" role="group" aria-label="Filtrar por origen">
              <button v-for="opt in sourceOptions" :key="opt.value" type="button" class="pill"
                :class="{ active: store.archive.filters.source === opt.value }"
                @click="store.setArchiveFilters({ source: opt.value })">{{ opt.label }}</button>
            </div>

            <div class="pill-group" role="group" aria-label="Filtrar por estado">
              <button v-for="opt in statusOptions" :key="opt.value" type="button" class="pill"
                :class="{ active: store.archive.filters.status === opt.value }"
                @click="store.setArchiveFilters({ status: opt.value })">{{ opt.label }}</button>
            </div>

            <div class="pill-group" role="group" aria-label="Filtrar por revisión">
              <button v-for="opt in reviewOptions" :key="opt.value" type="button" class="pill"
                :class="{ active: store.archive.filters.review === opt.value }"
                @click="store.setArchiveFilters({ review: opt.value })">{{ opt.label }}</button>
            </div>

            <div class="archive-search archive-search--ioc">
              <input
                v-model="iocInput"
                type="text"
                class="search-input"
                placeholder="IOC: dominio, IP, URL o hash"
                aria-label="Buscar por indicador de compromiso"
              />
            </div>

            <select
              v-if="store.userTags.length"
              class="tag-select"
              aria-label="Filtrar por etiqueta"
              :value="store.archive.filters.tag"
              @change="store.setArchiveFilters({ tag: $event.target.value })"
            >
              <option value="">Todas las etiquetas</option>
              <option v-for="tag in store.userTags" :key="tag.name" :value="tag.name">{{ tag.name }} ({{ tag.count }})</option>
            </select>

            <button v-if="store.archiveHasFilters" type="button" class="clear-filters" @click="store.resetArchiveFilters()">
              Limpiar filtros
            </button>
          </div>

          <!-- Vistas guardadas: volver a una cola de trabajo sin reconstruir cada filtro. -->
          <div class="archive-views">
            <span class="views-label">Vistas</span>
            <span v-for="view in store.savedViews" :key="view.viewId" class="view-chip">
              <button type="button" class="view-apply" @click="store.applySavedView(view)">{{ view.name }}</button>
              <button type="button" class="view-delete" :aria-label="`Borrar la vista ${view.name}`" @click="store.deleteSavedView(view.viewId)">&times;</button>
            </span>
            <form v-if="store.archiveHasFilters" class="view-save" @submit.prevent="saveView">
              <input v-model="viewName" type="text" maxlength="60" class="view-name" placeholder="Nombre de la vista" aria-label="Nombre de la vista" />
              <button type="submit" class="view-save-btn" :disabled="!viewName.trim()">Guardar vista</button>
            </form>
            <span v-else-if="!store.savedViews.length" class="views-hint">Filtra y guarda la combinación para volver a ella.</span>
          </div>

          <div class="archive-table-wrap">
            <Transition name="fade-swap" mode="out-in">
              <div v-if="showLoading" key="loading" class="archive-state">
                <span class="spinner"></span>
                <span>Cargando análisis…</span>
              </div>
              <div v-else-if="store.archive.error" key="error" class="archive-state archive-state--error">
                <span>{{ store.archive.error }}</span>
                <button type="button" class="retry-btn" @click="store.fetchArchive()">Reintentar</button>
              </div>
              <div v-else-if="!store.archive.items.length && store.archiveHasFilters" key="empty-filtered" class="archive-state">
                <span>Ningún análisis coincide con estos filtros.</span>
                <button type="button" class="retry-btn" @click="store.resetArchiveFilters()">Limpiar filtros</button>
              </div>
              <div v-else-if="!store.archive.items.length" key="empty" class="archive-state">
                <span>Todavía no hay análisis. Pega unas cabeceras o conecta un buzón para empezar.</span>
              </div>
              <table v-else key="table">
                <thead>
                  <tr>
                    <th class="col-compare" title="Marca dos para compararlos (x)"></th>
                    <th class="col-id">ID</th>
                    <th class="sortable" :class="{ 'sortable--active': store.archive.sort.by === 'title' }" @click="store.setArchiveSort('title')">
                      Título<span class="sort-indicator">{{ sortIndicator('title') }}</span>
                    </th>
                    <th class="col-origin">Origen</th>
                    <th class="sortable col-date" :class="{ 'sortable--active': store.archive.sort.by === 'date' }" @click="store.setArchiveSort('date')">
                      Fecha<span class="sort-indicator">{{ sortIndicator('date') }}</span>
                    </th>
                    <th class="sortable" :class="{ 'sortable--active': store.archive.sort.by === 'status' }" @click="store.setArchiveSort('status')">
                      Estado<span class="sort-indicator">{{ sortIndicator('status') }}</span>
                    </th>
                    <th class="sortable col-score" :class="{ 'sortable--active': store.archive.sort.by === 'score' }" @click="store.setArchiveSort('score')">
                      Puntuación<span class="sort-indicator">{{ sortIndicator('score') }}</span>
                    </th>
                  </tr>
                </thead>
                <TransitionGroup name="row" tag="tbody">
                  <tr
                    v-for="(item, index) in store.archive.items"
                    :key="item.analysisId"
                    class="archive-row"
                    :class="{ focused: focusedIndex === index }"
                    :style="{ '--row-delay': rowDelay(index) + 'ms' }"
                    @click="choose(item.analysisId)"
                    @mouseenter="focusedIndex = index"
                  >
                    <td class="col-compare" @click.stop>
                      <input type="checkbox" :checked="compareIds.includes(item.analysisId)" :aria-label="`Comparar #${item.analysisId}`" @change="toggleCompare(item.analysisId)" />
                    </td>
                    <td class="mono col-id">#{{ item.analysisId }}</td>
                    <td class="col-title">
                      {{ item.title || '(sin título)' }}
                      <span v-if="item.reviewed" class="reviewed-chip" title="Revisado por un analista">revisado</span>
                      <span v-for="tag in item.tags || []" :key="tag" class="tag-chip">{{ tag }}</span>
                    </td>
                    <td class="col-origin">
                      <span class="origin-chip" :class="item.connectionId ? 'origin-chip--auto' : 'origin-chip--manual'">
                        {{ item.connectionId ? 'AUTO' : 'MANUAL' }}
                      </span>
                    </td>
                    <td class="mono col-date">{{ formatDate(item.startedAt) }}</td>
                    <td>
                      <span class="status-chip" :class="`status--${item.status}`">{{ analysisStatusLabel(item.status) }}</span>
                    </td>
                    <td class="col-score">
                      <div v-if="item.totalScore != null" class="score-rail" :title="`${item.totalScore} · ${verdictLabel(item.verdict)}`">
                        <span class="rail-track"></span>
                        <span class="rail-tick" :style="{ left: store.thresholds.suspicious + '%' }"></span>
                        <span class="rail-tick" :style="{ left: store.thresholds.legitimate + '%' }"></span>
                        <span class="rail-marker" :class="`marker--${verdictClass(item.verdict)}`" :style="{ left: clampScore(item.totalScore) + '%' }"></span>
                      </div>
                      <span v-else class="score-pending">—</span>
                      <span class="score-number mono">{{ item.totalScore ?? '' }}</span>
                    </td>
                  </tr>
                </TransitionGroup>
              </table>
            </Transition>
          </div>

          <footer class="archive-footer">
            <button type="button" class="compare-btn" :disabled="compareIds.length !== 2" title="Marca dos filas (x) y compáralas (c)" @click="compareOpen = true">
              Comparar ({{ compareIds.length }}/2)
            </button>
            <span class="archive-summary">
              <template v-if="store.archiveHasFilters">{{ store.archive.total }} de {{ store.totalCount }} análisis</template>
              <template v-else>{{ store.archive.total }} análisis en total</template>
            </span>
            <AppPagination
              :current="store.archive.page"
              :total="store.archive.total"
              :per-page="store.archive.perPage"
              @go="store.goToArchivePage"
            />
          </footer>
        </div>
      </div>
    </Transition>
    <IrisCompareModal :show="compareOpen" :analysis-ids="compareIds" @close="compareOpen = false" />
  </Teleport>
</template>

<script setup>
/**
 * El archivo de análisis: histórico completo con filtros/orden en servidor
 * (ResultsQuerySchema). IrisHistoryStrip solo enseña los BENCH_SIZE más
 * recientes; esto es donde vive la paginación, la búsqueda y el orden por
 * campo — antes inexistentes (el "orden" de la tira solo reordenaba lo ya
 * cargado en cliente).
 */
import { ref, watch, onBeforeUnmount } from 'vue'
import AppPagination from '@/components/shared/AppPagination.vue'
import IrisCompareModal from '@/components/iris/IrisCompareModal.vue'
import { useIrisStore } from '@/stores/irisStore'
import { useModalA11y } from '@/composables/useModalA11y'
import { analysisStatusLabel, verdictClass, verdictLabel } from '@/components/iris/verdict'

const props = defineProps({
  show: { type: Boolean, default: false },
})
const emit = defineEmits(['close', 'select'])

const store = useIrisStore()

const boxRef = ref(null)
const searchRef = ref(null)
const searchInput = ref('')
const focusedIndex = ref(-1)

const verdictOptions = [
  { value: '', label: 'Todos' },
  { value: 'Legitimate', label: 'Legítimo', dot: 'legit' },
  { value: 'Suspicious', label: 'Sospechoso', dot: 'susp' },
  { value: 'Phishing', label: 'Phishing', dot: 'phish' },
]
const sourceOptions = [
  { value: '', label: 'Todos' },
  { value: 'manual', label: 'Manual' },
  { value: 'mailbox', label: 'Buzón' },
]
const statusOptions = [
  { value: '', label: 'Todos' },
  { value: 'finished', label: 'Finalizado' },
  { value: 'failed', label: 'Fallido' },
  { value: 'cancelled', label: 'Cancelado' },
]
// «Pendiente» es un análisis terminado que nadie ha corregido todavía.
const reviewOptions = [
  { value: '', label: 'Todos' },
  { value: 'pending', label: 'Pendiente de revisar' },
  { value: 'reviewed', label: 'Revisado' },
]

const iocInput = ref('')
const viewName = ref('')
// Dos análisis marcados para abrirlos lado a lado (IrisCompareModal).
const compareIds = ref([])
const compareOpen = ref(false)

let iocDebounce = null
watch(iocInput, (val) => {
  clearTimeout(iocDebounce)
  iocDebounce = setTimeout(() => {
    if (val.trim() !== store.archive.filters.ioc) store.setArchiveFilters({ ioc: val.trim() })
  }, 350)
})

// Aplicar una vista guardada o limpiar filtros cambia los filtros desde
// fuera: las cajas de texto tienen que seguirlos.
watch(() => store.archive.filters.search, (val) => { if (val !== searchInput.value.trim()) searchInput.value = val })
watch(() => store.archive.filters.ioc, (val) => { if (val !== iocInput.value.trim()) iocInput.value = val })

/** Marca o desmarca un análisis para comparar; con dos marcados, el
 * tercero sustituye al más antiguo. */
function toggleCompare(id) {
  compareIds.value = compareIds.value.includes(id)
    ? compareIds.value.filter(existing => existing !== id)
    : [...compareIds.value, id].slice(-2)
}

async function saveView() {
  if (await store.saveArchiveView(viewName.value.trim())) viewName.value = ''
}

let searchDebounce = null
watch(searchInput, (val) => {
  clearTimeout(searchDebounce)
  searchDebounce = setTimeout(() => {
    store.setArchiveFilters({ search: val.trim() })
  }, 250)
})

// El spinner solo aparece si la carga tarda >200ms — evita el parpadeo en
// respuestas rápidas (mismo idioma que ScanTable.vue).
const showLoading = ref(false)
let loadingTimer = null
watch(() => store.archive.loading, (val) => {
  clearTimeout(loadingTimer)
  if (val) loadingTimer = setTimeout(() => { showLoading.value = true }, 200)
  else showLoading.value = false
})

watch(() => props.show, (visible) => {
  if (visible) {
    searchInput.value = store.archive.filters.search
    iocInput.value = store.archive.filters.ioc
    focusedIndex.value = -1
    store.fetchArchive()
    store.fetchSavedViews()
    store.fetchTags()
  }
})

onBeforeUnmount(() => {
  clearTimeout(searchDebounce)
  clearTimeout(iocDebounce)
  clearTimeout(loadingTimer)
})

useModalA11y(() => props.show, { boxRef, autofocusRef: searchRef, onClose: close, onKeydown: onExtraKeydown })

function close() {
  emit('close')
}

function choose(id) {
  emit('select', id)
  close()
}

function rowDelay(index) {
  return Math.min(index, 10) * 25
}

function sortIndicator(field) {
  if (store.archive.sort.by !== field) return ''
  return store.archive.sort.dir === 'asc' ? '▲' : '▼'
}

function clampScore(score) {
  if (score == null) return 0
  return Math.min(100, Math.max(0, score))
}

function formatDate(iso) {
  if (!iso) return ''
  try { return new Date(iso).toLocaleDateString('es-ES', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}

/** "/" enfoca la búsqueda; ↑/↓ recorren filas; Enter abre la fila enfocada;
 * x marca la fila enfocada para comparar y c abre la comparación —
 * Escape y Tab ya los cubre useModalA11y. ConfirmModal no hace ninguna de
 * las dos cosas de aquí, pero a esta escala (una tabla completa) se echan en
 * falta. */
function onExtraKeydown(e) {
  // Con la comparación abierta, el teclado es suyo; y escribir el nombre de
  // una vista no debe abrir la fila enfocada al pulsar Enter.
  if (compareOpen.value || e.target?.classList?.contains('view-name')) return
  if (e.key === '/' && document.activeElement !== searchRef.value) {
    e.preventDefault()
    searchRef.value?.focus()
    return
  }

  const items = store.archive.items
  const isTyping = ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target?.tagName)
  if (!isTyping && e.key === 'x' && items[focusedIndex.value]) {
    toggleCompare(items[focusedIndex.value].analysisId)
    return
  }
  if (!isTyping && e.key === 'c' && compareIds.value.length === 2) {
    compareOpen.value = true
    return
  }
  if (e.key === 'ArrowDown' && items.length) {
    e.preventDefault()
    focusedIndex.value = Math.min(focusedIndex.value + 1, items.length - 1)
    return
  }
  if (e.key === 'ArrowUp' && items.length) {
    e.preventDefault()
    focusedIndex.value = Math.max(focusedIndex.value - 1, 0)
    return
  }
  if (e.key === 'Enter' && focusedIndex.value >= 0) {
    const item = items[focusedIndex.value]
    if (item) choose(item.analysisId)
  }
}

</script>

<style scoped>
.archive-overlay {
  position: fixed;
  inset: 0;
  z-index: 200;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  background: radial-gradient(120% 80% at 50% 50%, rgba(11, 12, 16, 0.55) 0%, rgba(11, 12, 16, 0.88) 100%);
  backdrop-filter: blur(6px);
}

.archive-box {
  position: relative;
  display: flex;
  flex-direction: column;
  width: min(980px, 100%);
  max-height: 85vh;
  background: color-mix(in srgb, var(--surface) 96%, transparent);
  border: 1px solid var(--border-med);
  border-radius: 16px;
  box-shadow: 0 24px 70px rgba(0, 0, 0, 0.5), 0 0 0 1px color-mix(in srgb, var(--accent) 10%, transparent);
  overflow: hidden;
}

/* Marcas de esquina — el mismo idioma que el visor de intake de IrisView. */
.tick {
  position: absolute;
  width: 20px;
  height: 20px;
  border: 2px solid var(--accent);
  opacity: 0.55;
  pointer-events: none;
  z-index: 1;
}
.tick--tl { top: 10px; left: 10px; border-right: 0; border-bottom: 0; border-top-left-radius: 5px; }
.tick--tr { top: 10px; right: 10px; border-left: 0; border-bottom: 0; border-top-right-radius: 5px; }
.tick--bl { bottom: 10px; left: 10px; border-right: 0; border-top: 0; border-bottom-left-radius: 5px; }
.tick--br { bottom: 10px; right: 10px; border-left: 0; border-top: 0; border-bottom-right-radius: 5px; }

.archive-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  padding: 1.4rem 1.6rem 1rem;
  flex-shrink: 0;
}

.archive-eyebrow {
  margin: 0 0 0.25rem;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-xs);
  letter-spacing: 0.28em;
  text-transform: uppercase;
  color: var(--accent);
}

.archive-title {
  margin: 0;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-2xl);
  font-weight: 700;
  color: var(--text);
}

.archive-close {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  flex-shrink: 0;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s;
}
.archive-close:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }
.archive-close svg { width: 15px; height: 15px; }

.archive-filters {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.6rem;
  padding: 0 1.6rem 1.1rem;
  flex-shrink: 0;
}

.archive-search {
  position: relative;
  display: flex;
  align-items: center;
  flex: 1 1 220px;
  min-width: 180px;
}
.search-icon { position: absolute; left: 0.6rem; width: 15px; height: 15px; color: var(--text-muted); pointer-events: none; }
.search-input {
  width: 100%;
  box-sizing: border-box;
  padding: 0.45rem 1.9rem 0.45rem 2.1rem;
  background: var(--bg);
  border: 1px solid var(--border-solid);
  border-radius: 7px;
  color: var(--text);
  font-size: var(--fs-md);
  font-family: inherit;
  outline: none;
  transition: border-color 0.2s;
}
.search-input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-dim); }
.search-clear {
  position: absolute; right: 0.4rem;
  width: 20px; height: 20px; border: none; border-radius: 50%;
  background: none; color: var(--text-muted); cursor: pointer;
  font-size: var(--fs-lg); line-height: 1; display: grid; place-items: center;
}
.search-clear:hover { color: var(--text); }

.pill-group { display: flex; gap: 0.2rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 0.2rem; flex-shrink: 0; }
.pill {
  display: flex; align-items: center; gap: 0.3rem;
  padding: 0.32rem 0.6rem;
  background: none; border: none; border-radius: 6px;
  color: var(--text-muted); font-size: var(--fs-md); font-weight: 500;
  cursor: pointer; transition: all 0.15s; white-space: nowrap;
}
.pill:hover { color: var(--text-dim); }
.pill.active { background: var(--surface-3); color: var(--text); font-weight: 600; }
.pill-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.pill-dot--legit { background: var(--success); }
.pill-dot--susp { background: var(--warn); }
.pill-dot--phish { background: var(--danger); }

.clear-filters {
  background: none; border: none;
  color: var(--accent-bright); font-size: var(--fs-sm); font-weight: 600;
  cursor: pointer; text-decoration: underline; text-underline-offset: 2px;
  flex-shrink: 0;
}

.archive-table-wrap { flex: 1; overflow-y: auto; border-top: 1px solid var(--border); }

.archive-state {
  display: flex; flex-direction: column; align-items: center; gap: 0.6rem;
  padding: 3rem 1rem; color: var(--text-muted); font-size: var(--fs-lg); text-align: center;
}
.archive-state--error { color: var(--danger); }
.retry-btn {
  padding: 0.35rem 0.8rem; border-radius: 6px; border: 1px solid var(--border-solid);
  background: var(--surface-2); color: var(--text-dim); font-size: var(--fs-md); cursor: pointer;
}
.retry-btn:hover { border-color: var(--accent); color: var(--accent); }

.spinner {
  width: 22px; height: 22px; border: 2px solid var(--border);
  border-top-color: var(--accent); border-radius: 50%;
  animation: seq-spin 0.7s linear infinite;
}

table { width: 100%; border-collapse: collapse; }
th {
  position: sticky; top: 0; z-index: 2;
  padding: 0.6rem 1rem; text-align: left;
  font-size: var(--fs-sm); font-weight: 600; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.05em;
  background: var(--surface-2);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text-dim); }
th.sortable--active { color: var(--accent-bright); }
.sort-indicator { display: inline-block; width: 0.9em; font-size: 0.8em; margin-left: 0.15em; }
.col-id { width: 60px; }
.col-origin { width: 90px; }
.col-score { width: 200px; }

td {
  padding: 0.55rem 1rem;
  font-size: var(--fs-md);
  color: var(--text);
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-variant-numeric: tabular-nums; }
.col-date { color: var(--text-dim); white-space: nowrap; }
.col-title { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.archive-row { cursor: pointer; transition: background 0.12s; }
.archive-row:hover, .archive-row.focused { background: var(--surface-2); }
.archive-row.focused { outline: 1px solid var(--accent); outline-offset: -1px; }

.origin-chip {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: 0.62rem; font-weight: 700; letter-spacing: 0.06em;
  padding: 0.1rem 0.32rem; border-radius: 4px;
}
.origin-chip--auto { color: var(--accent-bright); background: var(--accent-dim); }
.origin-chip--manual { color: var(--text-muted); background: var(--surface-3); }

.status-chip {
  font-size: var(--fs-sm); font-weight: 600; text-transform: capitalize;
  padding: 0.12rem 0.5rem; border-radius: 999px;
}
.status--finished { color: var(--text-dim); background: var(--surface-3); }
.status--running, .status--pending { color: var(--info); background: var(--info-dim); }
.status--failed { color: var(--danger); background: var(--danger-dim); }
.status--cancelled { color: var(--text-muted); background: var(--surface-3); }

/* ── El raíl de score — la pieza firma del archivo ───────────────────── */
.score-rail {
  position: relative;
  display: inline-block;
  width: 120px;
  height: 14px;
  vertical-align: middle;
  margin-right: 0.5rem;
}
.rail-track {
  position: absolute; top: 50%; left: 0; right: 0; height: 2px;
  transform: translateY(-50%);
  background: var(--border-solid);
  border-radius: 2px;
}
.rail-tick {
  position: absolute; top: 0; width: 1px; height: 100%;
  background: var(--text-muted); opacity: 0.5;
}
.rail-marker {
  position: absolute; top: 50%; width: 8px; height: 8px;
  transform: translate(-50%, -50%);
  border-radius: 50%;
  transition: left 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 0 0 2px var(--surface);
}
.marker--legit { background: var(--success); }
.marker--susp { background: var(--warn); }
.marker--phish { background: var(--danger); }
.marker--unknown { background: var(--text-muted); }
.score-pending { color: var(--text-muted); margin-right: 0.5rem; }
.score-number { color: var(--text-dim); font-size: var(--fs-sm); }

.archive-footer {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: 0.75rem 1.4rem; border-top: 1px solid var(--border); flex-shrink: 0;
}
.archive-summary { font-size: var(--fs-sm); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-variant-numeric: tabular-nums; }
.archive-footer :deep(.pagination) { margin-top: 0; }

/* ── Transiciones ─────────────────────────────────────────────────────── */
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-active .archive-box, .modal-leave-active .archive-box {
  transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.2s ease;
}
.modal-enter-from .archive-box, .modal-leave-to .archive-box {
  opacity: 0; transform: scale(0.96) translateY(10px);
}

.fade-swap-enter-active, .fade-swap-leave-active { transition: opacity 0.18s ease; }
.fade-swap-enter-from, .fade-swap-leave-to { opacity: 0; }

.row-move { transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.row-enter-active {
  transition: opacity 0.25s cubic-bezier(0.22, 1, 0.36, 1), transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
  transition-delay: var(--row-delay, 0ms);
}
.row-leave-active { transition: opacity 0.18s ease; }
.row-enter-from, .row-leave-to { opacity: 0; transform: translateY(6px); }

@media (prefers-reduced-motion: reduce) {
  .modal-enter-active, .modal-leave-active,
  .modal-enter-active .archive-box, .modal-leave-active .archive-box,
  .fade-swap-enter-active, .fade-swap-leave-active,
  .row-move, .row-enter-active, .row-leave-active,
  .rail-marker { transition: none !important; }
}

@media (max-width: 720px) {
  .archive-box { max-height: 92vh; }
  .col-origin, .col-date { display: none; }
  .score-rail { width: 70px; }
}
/* ── Triaje: revisión, IOC, etiquetas, vistas guardadas y comparación ── */
.archive-search--ioc { max-width: 260px; }
.tag-select {
  padding: 0.35rem 0.5rem; font-size: var(--fs-sm);
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border-med); border-radius: 6px;
}
.archive-views {
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem;
  padding: 0 1.4rem 0.7rem;
}
.views-label { font-size: var(--fs-xs); letter-spacing: 0.18em; text-transform: uppercase; color: var(--text-muted); }
.views-hint { font-size: var(--fs-sm); color: var(--text-muted); }
.view-chip { display: inline-flex; align-items: center; border: 1px solid var(--border-med); border-radius: 999px; overflow: hidden; }
.view-apply, .view-delete { border: none; background: transparent; color: var(--text-dim); font-size: var(--fs-sm); cursor: pointer; padding: 0.2rem 0.6rem; }
.view-apply:hover { color: var(--accent-bright); }
.view-delete { padding: 0.2rem 0.45rem; border-left: 1px solid var(--border); }
.view-delete:hover { color: var(--danger); }
.view-save { display: inline-flex; gap: 0.35rem; }
.view-name {
  padding: 0.25rem 0.5rem; font-size: var(--fs-sm); width: 11rem;
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border-med); border-radius: 6px;
}
.view-save-btn, .compare-btn {
  padding: 0.25rem 0.7rem; font-size: var(--fs-sm); font-weight: 600;
  border: 1px solid var(--accent); border-radius: 6px; background: transparent; color: var(--accent-bright); cursor: pointer;
}
.view-save-btn:disabled, .compare-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.col-compare { width: 2rem; text-align: center; }
.tag-chip, .reviewed-chip {
  display: inline-block; margin-left: 0.35rem; padding: 0 0.45rem;
  font-size: var(--fs-xs); border-radius: 999px; vertical-align: middle;
}
.tag-chip { background: var(--info-dim); color: var(--info); }
.reviewed-chip { background: var(--success-dim); color: var(--success); }
</style>
