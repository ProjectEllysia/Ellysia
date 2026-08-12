<template>
  <div class="asset-list">
    <header class="toolbar">
      <h3 class="toolbar-title">Activos</h3>
      <div class="toolbar-actions">
        <RouterLink class="btn-icon" to="/hygeia/etiquetas" title="Gestionar etiquetas" aria-label="Gestionar etiquetas">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" />
            <path d="M7 7h.01" />
          </svg>
        </RouterLink>
        <button class="btn-icon" title="Inventario en PDF" aria-label="Descargar el inventario en PDF"
          @click="$emit('report')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <path d="M14 2v6h6M12 18v-6M9 15l3 3 3-3" />
          </svg>
        </button>
        <button class="btn-icon" title="Recargar" aria-label="Recargar activos" @click="$emit('refresh')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M23 4v6h-6M1 20v-6h6" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </svg>
        </button>
        <button class="btn-new" @click="$emit('create')">Nuevo activo</button>
      </div>
    </header>

    <!-- Filtro por etiqueta. Solo se ofrecen las que alguien lleva: una tira de
         chips con el catálogo entero sería casi todo ruido cuando la mitad no
         está puesta en ningún sitio. -->
    <div v-if="filterableTags.length" class="filter-bar">
      <button
        v-for="tag in filterableTags" :key="tag.id"
        type="button" class="filter-chip" :class="{ 'filter-chip--on': activeTagIds.includes(tag.id) }"
        :aria-pressed="activeTagIds.includes(tag.id)"
        :style="{ '--tag-hue': hueOf(tag.color) }"
        @click="toggleFilter(tag.id)"
      >{{ tag.name }}</button>
      <button v-if="activeTagIds.length" type="button" class="filter-clear" @click="activeTagIds = []">
        Quitar filtros
      </button>
    </div>

    <!-- Sin <Transition mode="out-in"> a propósito: la transición de salida
         depende de requestAnimationFrame, que el navegador suspende en las
         pestañas de fondo — justo donde vive un panel de monitorización. Al
         volver a la pestaña, la vista se quedaba congelada a medio cambio de
         estado. Un fundido no vale ese riesgo. -->
    <!-- Filas fantasma con la misma silueta que las reales (punto de pulso +
         dos líneas de texto): al llegar los activos ocupan el mismo alto y la
         lista no se estira de golpe. -->
    <ul v-if="loading" class="rows" aria-busy="true" aria-label="Cargando activos">
      <li v-for="n in SKELETON_ROWS" :key="n" class="row row--ghost" aria-hidden="true">
        <span class="skeleton skeleton--circle ghost-pulse"></span>
        <span class="ghost-text">
          <span class="skeleton skeleton--line skeleton--w60"></span>
          <span class="skeleton skeleton--line skeleton--w40"></span>
        </span>
      </li>
    </ul>

    <p v-else-if="error" class="state-msg state-msg--error">
      {{ error }}
      <button type="button" class="retry" @click="$emit('refresh')">Reintentar</button>
    </p>

    <div v-else-if="!assets.length" class="state-empty">
      <p class="empty-title">Ningún activo todavía</p>
      <p class="empty-sub">Da de alta el primero para empezar a recibir sus heartbeats.</p>
      <button class="btn-new" @click="$emit('create')">Nuevo activo</button>
    </div>

    <div v-else-if="!visibleAssets.length" class="state-empty">
      <p class="empty-title">Ningún activo con esas etiquetas</p>
      <p class="empty-sub">Prueba a quitar algún filtro.</p>
      <button class="btn-new" @click="activeTagIds = []">Quitar filtros</button>
    </div>

    <ul v-else class="rows">
      <li v-for="asset in visibleAssets" :key="asset.id" class="row" :class="{ 'row--selected': asset.id === selectedId }">
        <button class="row-select" :aria-pressed="asset.id === selectedId" @click="$emit('select', asset.id)">
          <span class="pulse" :class="pulseClass(asset)" aria-hidden="true"></span>
          <span class="row-text">
            <span class="row-host">{{ asset.hostname }}</span>
            <span class="row-meta">{{ statusLabel(asset) }} · {{ timeAgo(asset.lastSeenAt) }}</span>
            <!-- Tira aparte y con salto de línea propio: `.row-host` y
                 `.row-meta` son `nowrap` con elipsis y no sirven de molde. -->
            <span v-if="asset.tags?.length" class="row-tags">
              <TagBadge v-for="tag in shownTags(asset)" :key="tag.id" :tag="tag" small />
              <span v-if="asset.tags.length > MAX_ROW_TAGS" class="row-tags-more">
                +{{ asset.tags.length - MAX_ROW_TAGS }}
              </span>
            </span>
          </span>
        </button>

        <span class="row-actions">
          <button class="btn-icon" title="Etiquetas" :aria-label="`Etiquetas de ${asset.hostname}`"
            @click="$emit('tag', asset.id)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" />
              <path d="M7 7h.01" />
            </svg>
          </button>
          <button class="btn-icon" :class="{ 'btn-icon--muted': !asset.isPersistent }"
            :title="asset.isPersistent ? 'Marcar como host que se apaga a propósito' : 'Marcar como host siempre encendido'"
            :aria-pressed="!asset.isPersistent"
            :aria-label="`${asset.hostname}: ${asset.isPersistent ? 'dejar de avisar cuando esté caído' : 'volver a avisar cuando esté caído'}`"
            @click="$emit('toggle-persistent', asset.id)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M12 3v9" />
              <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
            </svg>
          </button>
          <button class="btn-icon" title="Rotar clave" :aria-label="`Rotar la clave de ${asset.hostname}`"
            @click="$emit('rotate', asset.id)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M21 2v6h-6M3 22v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L21 8M21 15a9 9 0 0 1-14.85 3.36L3 16" />
            </svg>
          </button>
          <button class="btn-icon btn-icon--danger" title="Eliminar" :aria-label="`Eliminar ${asset.hostname}`"
            @click="$emit('delete', asset.id)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14z" />
            </svg>
          </button>
        </span>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import TagBadge from './TagBadge.vue'
import { hueOf } from './tagColors'
import { timeAgo } from './format'

const props = defineProps({
  assets: { type: Array, default: () => [] },
  selectedId: { type: [Number, null], default: null },
  loading: { type: Boolean, default: false },
  error: { type: String, default: null },
})
defineEmits(['select', 'create', 'delete', 'rotate', 'refresh', 'toggle-persistent', 'tag', 'report'])

/** Filas fantasma mientras carga: las que caben sin alargar el panel. */
const SKELETON_ROWS = 4

/** Badges que caben en una fila sin robarle el sitio al hostname. */
const MAX_ROW_TAGS = 3

/**
 * Filtrado por etiqueta, en cliente y con estado local.
 *
 * La lista completa ya está en memoria —la vista la sondea entera cada
 * minuto—, así que filtrar aquí es instantáneo y no gasta ni una petición.
 * El estado no sube a la vista porque nadie más lo necesita: quien filtra la
 * lista es la lista.
 */
const activeTagIds = ref([])

/** Solo las etiquetas realmente puestas en algún activo: filtrar por una que
 *  nadie lleva solo puede vaciar la lista. */
const filterableTags = computed(() => {
  const seen = new Map()
  for (const asset of props.assets) {
    for (const tag of asset.tags ?? []) seen.set(tag.id, tag)
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name))
})

/** Conjunción: al sumar etiquetas se estrecha la lista, no se ensancha. */
const visibleAssets = computed(() => {
  if (!activeTagIds.value.length) return props.assets
  return props.assets.filter((asset) => {
    const ids = (asset.tags ?? []).map((tag) => tag.id)
    return activeTagIds.value.every((id) => ids.includes(id))
  })
})

function toggleFilter(id) {
  activeTagIds.value = activeTagIds.value.includes(id)
    ? activeTagIds.value.filter((active) => active !== id)
    : [...activeTagIds.value, id]
}

function shownTags(asset) {
  return (asset.tags ?? []).slice(0, MAX_ROW_TAGS)
}

const STATUS_LABELS = { pending: 'Pendiente', online: 'En línea', stale: 'Inestable', offline: 'Caído' }

/**
 * Un activo que se apaga a propósito no está "caído": pintarlo en rojo sería
 * exactamente el ruido que su marca elimina. El estado es el mismo (`offline`),
 * solo cambia cómo se lee.
 */
function statusLabel(asset) {
  if (asset.status === 'offline' && asset.isPersistent === false) return 'Apagado'
  return STATUS_LABELS[asset.status] || asset.status
}

function pulseClass(asset) {
  if (asset.status === 'offline' && asset.isPersistent === false) return 'pulse--dormant'
  return `pulse--${asset.status}`
}
</script>

<style scoped>
.asset-list { display: flex; flex-direction: column; gap: 0.85rem; }

.toolbar { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.toolbar-title {
  margin: 0;
  font-size: var(--fs-xl); font-weight: 600;
  color: var(--text); white-space: nowrap;
}
.toolbar-actions { display: flex; align-items: center; gap: 0.4rem; }

.btn-new {
  padding: 0.4rem 0.8rem;
  background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 6px;
  color: var(--accent-bright);
  font-size: var(--fs-body); font-weight: 600; white-space: nowrap; cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.btn-new:hover { background: var(--accent); color: var(--on-accent); }

.btn-icon {
  width: 30px; height: 30px; flex-shrink: 0;
  display: grid; place-items: center;
  background: transparent; border: 1px solid var(--border-med); border-radius: 6px;
  color: var(--text-muted); cursor: pointer;
  transition: border-color var(--transition), color var(--transition);
}
/* El enlace a la vista de etiquetas comparte estilo con los botones de icono,
   pero no hereda su reset de anclas. */
a.btn-icon { text-decoration: none; }
.btn-icon svg { width: 14px; height: 14px; }
.btn-icon:hover { border-color: var(--accent); color: var(--accent-bright); }
.btn-icon--danger:hover { border-color: var(--danger); color: var(--danger); }
/* Interruptor pulsado: el activo está marcado como "se apaga a propósito". */
.btn-icon--muted { border-style: dashed; opacity: 0.65; }

/* ── Filas ── */
.rows { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.3rem; }

.row {
  display: flex; align-items: stretch; gap: 0.3rem;
  border: 1px solid transparent; border-radius: 7px;
  transition: background var(--transition), border-color var(--transition);
}
.row:hover { background: var(--surface-2); }
.row--selected { background: var(--accent-dim); border-color: color-mix(in srgb, var(--accent) 35%, transparent); }

.row-select {
  flex: 1; min-width: 0;
  display: flex; align-items: center; gap: 0.6rem;
  padding: 0.55rem 0.6rem;
  background: none; border: none; border-radius: 7px;
  text-align: left; cursor: pointer;
}
.row-text { min-width: 0; display: flex; flex-direction: column; gap: 0.1rem; }
.row-host {
  font-size: var(--fs-body); font-weight: 600; color: var(--text);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row-meta {
  font-size: var(--fs-sm); color: var(--text-muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row-tags { display: flex; flex-wrap: wrap; gap: 0.2rem; margin-top: 0.2rem; }
.row-tags-more { align-self: center; font-size: var(--fs-caption); color: var(--text-muted); }

/* ── Filtro por etiqueta ── */
.filter-bar { display: flex; flex-wrap: wrap; gap: 0.3rem; }

.filter-chip {
  padding: 0.15rem 0.5rem;
  background: transparent;
  border: 1px solid color-mix(in srgb, var(--tag-hue) 38%, transparent);
  border-radius: 999px;
  color: var(--text-muted);
  font-size: var(--fs-caption); cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.filter-chip:hover { color: var(--text-dim); }
.filter-chip--on {
  background: color-mix(in srgb, var(--tag-hue) 22%, transparent);
  color: var(--tag-hue);
  font-weight: 600;
}

.filter-clear {
  padding: 0.15rem 0.5rem;
  background: none; border: 1px dashed var(--border-med); border-radius: 999px;
  color: var(--text-muted); font-size: var(--fs-caption); cursor: pointer;
}
.filter-clear:hover { color: var(--text-dim); border-color: var(--text-muted); }

.row-actions { display: flex; align-items: center; gap: 0.25rem; padding-right: 0.45rem; }

/* El punto de estado late solo cuando el host está vivo: es el único
   elemento animado de la vista, y dice de un vistazo quién sigue reportando. */
.pulse { width: 9px; height: 9px; flex-shrink: 0; border-radius: 50%; background: var(--text-muted); }

.pulse--online { background: var(--success); animation: pulse-ring 2.4s ease-out infinite; }
.pulse--stale { background: var(--warn); }
.pulse--offline { background: var(--danger); }
.pulse--pending { background: var(--text-muted); box-shadow: inset 0 0 0 1px var(--border-med); }
/* Caído a propósito: apagado, no en alarma. */
.pulse--dormant { background: transparent; box-shadow: inset 0 0 0 1.5px var(--text-muted); }
/* La fila fantasma repite el padding y el gap de .row-select. El min-height
   es el alto medido de una fila real (55px): las dos líneas del fantasma son
   algo más bajas que el hostname y su metadato, y sin esto la lista crecía
   6px por fila al llegar los activos. */
.row--ghost { align-items: center; gap: 0.6rem; padding: 0.55rem 0.6rem; min-height: 55px; }
.ghost-pulse { width: 9px; flex-shrink: 0; }
.ghost-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 0.35rem; }

@keyframes pulse-ring {
  0%        { box-shadow: 0 0 0 0 color-mix(in srgb, var(--success) 55%, transparent); }
  70%, 100% { box-shadow: 0 0 0 7px transparent; }
}

/* ── Estados ── */
.state-msg { margin: 0; padding: 1.6rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-body); }
.state-msg--error { color: var(--danger); }
.retry {
  margin-left: 0.5rem; padding: 0.2rem 0.6rem;
  background: transparent; border: 1px solid var(--danger); border-radius: 6px;
  color: var(--danger); font-size: var(--fs-sm); cursor: pointer;
}

.state-empty {
  padding: 2rem 1rem; text-align: center;
  border: 1px dashed var(--border-med); border-radius: 8px;
}
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0 0 0.9rem; font-size: var(--fs-body); color: var(--text-muted); }

.row-select:focus-visible, .btn-icon:focus-visible, .btn-new:focus-visible, .retry:focus-visible,
.filter-chip:focus-visible, .filter-clear:focus-visible {
  outline: 2px solid var(--accent-bright); outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
  .pulse--online { animation: none; }
}
</style>
