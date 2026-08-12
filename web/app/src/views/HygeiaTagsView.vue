<template>
  <div class="tags-page" data-module="hygeia">
    <StarBackground />
    <Topbar title="Hygeia" badge="Etiquetas" back-to="/hygeia/activos" back-label="Activos" />

    <main class="tags-layout">
      <header class="head">
        <div class="head-text">
          <h2 class="head-title">Etiquetas</h2>
          <p class="head-sub">
            El catálogo común lo comparte todo el mundo; las tuyas solo las ves tú.
            Borrar una la quita de los activos que la llevaban — los activos se quedan.
          </p>
        </div>
        <button class="btn-new" @click="startCreating">Nueva etiqueta</button>
      </header>

      <div class="controls">
        <input
          v-model.trim="search"
          type="search"
          class="search-input"
          placeholder="Buscar una etiqueta…"
        />
        <div class="scope">
          <button
            v-for="option in SCOPES" :key="option.value"
            type="button" class="scope-btn" :class="{ 'scope-btn--on': scope === option.value }"
            :aria-pressed="scope === option.value"
            @click="scope = option.value"
          >{{ option.label }}</button>
        </div>
      </div>

      <!-- Alta en línea, no en modal: es un nombre y un color, y el catálogo de
           al lado es justo lo que hay que mirar para no repetir una. -->
      <form v-if="creating" class="create-row" @submit.prevent="submitNewTag">
        <input
          ref="newNameInput"
          v-model.trim="newName"
          type="text" class="search-input"
          placeholder="Nombre de la etiqueta" maxlength="48" required
        />
        <span class="swatches">
          <button
            v-for="color in TAG_COLOR_NAMES" :key="color"
            type="button" class="swatch" :class="{ 'swatch--on': color === newColor }"
            :style="{ background: hueOf(color) }"
            :aria-label="`Color ${color}`" :aria-pressed="color === newColor"
            @click="newColor = color"
          ></button>
        </span>
        <button type="submit" class="btn-primary" :disabled="saving">
          {{ saving ? 'Creando…' : 'Crear' }}
        </button>
        <button type="button" class="btn-secondary" @click="creating = false">Cancelar</button>
      </form>

      <p v-if="tagsStore.state.loading" class="state-msg">Cargando etiquetas…</p>

      <p v-else-if="tagsStore.state.error" class="state-msg state-msg--error">
        {{ tagsStore.state.error }}
        <button type="button" class="retry" @click="tagsStore.fetchTags()">Reintentar</button>
      </p>

      <div v-else-if="!filteredTags.length" class="state-empty">
        <p class="empty-title">Ninguna etiqueta que coincida</p>
        <p class="empty-sub">Prueba con otra búsqueda, o crea una nueva.</p>
      </div>

      <ul v-else class="tag-grid">
        <li
          v-for="tag in filteredTags" :key="tag.id"
          class="tag-card" :class="{ 'tag-card--selected': tag.id === selectedId }"
        >
          <button class="tag-main" :aria-pressed="tag.id === selectedId" @click="toggleSelected(tag.id)">
            <TagBadge :tag="tag" />
            <span class="tag-meta">
              {{ tag.tagType === 'system' ? 'Catálogo común' : 'Personal' }}
              · {{ countLabel(tag) }}
            </span>
          </button>

          <button
            v-if="tag.tagType === 'user'"
            class="btn-icon btn-icon--danger"
            title="Borrar etiqueta" :aria-label="`Borrar la etiqueta ${tag.name}`"
            @click="pendingDelete = tag"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14z" />
            </svg>
          </button>
        </li>
      </ul>

      <!-- Al elegir una etiqueta se ve quién la lleva: es la pregunta que trae
           a alguien a esta pantalla. -->
      <section v-if="selectedTag" class="carriers">
        <h3 class="carriers-title">
          Activos con «{{ selectedTag.name }}»
        </h3>
        <p v-if="!carriers.length" class="carriers-empty">
          Ningún activo lleva esta etiqueta todavía.
        </p>
        <ul v-else class="carriers-list">
          <li v-for="asset in carriers" :key="asset.id">
            <RouterLink class="carrier" to="/hygeia/activos">
              <span class="pulse" :class="`pulse--${asset.status}`" aria-hidden="true"></span>
              {{ asset.hostname }}
            </RouterLink>
          </li>
        </ul>
      </section>
    </main>

    <ConfirmModal
      :show="!!pendingDelete"
      title="Borrar etiqueta"
      :message="deleteMessage"
      confirm-label="Borrar"
      danger
      @confirm="confirmDelete"
      @cancel="pendingDelete = null"
    />
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import TagBadge from '@/components/hygeia/TagBadge.vue'
import { TAG_COLOR_NAMES, hueOf } from '@/components/hygeia/tagColors'
import { useHygeiaStore } from '@/stores/hygeiaStore'
import { useHygeiaTagsStore } from '@/stores/hygeiaTagsStore'
import { useToastStore } from '@/stores/toastStore'

const store = useHygeiaStore()
const tagsStore = useHygeiaTagsStore()
const toast = useToastStore()

const SCOPES = [
  { value: 'all', label: 'Todas' },
  { value: 'system', label: 'Catálogo común' },
  { value: 'user', label: 'Mías' },
]

const search = ref('')
const scope = ref('all')
const selectedId = ref(null)
const pendingDelete = ref(null)

const creating = ref(false)
const newName = ref('')
const newColor = ref('slate')
const newNameInput = ref(null)
const saving = ref(false)

const filteredTags = computed(() => {
  const needle = search.value.toLowerCase()
  return tagsStore.state.tags.filter((tag) => {
    if (scope.value !== 'all' && tag.tagType !== scope.value) return false
    return !needle || tag.name.toLowerCase().includes(needle)
  })
})

const selectedTag = computed(() =>
  tagsStore.state.tags.find((tag) => tag.id === selectedId.value) || null
)

const carriers = computed(() => {
  if (!selectedTag.value) return []
  return store.state.assets.filter(
    (asset) => (asset.tags ?? []).some((tag) => tag.id === selectedId.value),
  )
})

const deleteMessage = computed(() => {
  const count = pendingDelete.value?.assetCount ?? 0
  const carried = count === 1 ? 'del activo que la lleva' : `de los ${count} activos que la llevan`
  return count
    ? `Se quitará «${pendingDelete.value.name}» ${carried}. Los activos no se borran.`
    : `Se borrará la etiqueta «${pendingDelete.value?.name}». No la lleva ningún activo.`
})

function countLabel(tag) {
  const count = tag.assetCount ?? 0
  return count === 1 ? '1 activo' : `${count} activos`
}

function toggleSelected(id) {
  selectedId.value = selectedId.value === id ? null : id
}

function startCreating() {
  creating.value = true
  newName.value = ''
  newColor.value = 'slate'
  nextTick(() => newNameInput.value?.focus())
}

async function submitNewTag() {
  if (!newName.value) return
  saving.value = true
  try {
    const tag = await tagsStore.createTag({ name: newName.value, color: newColor.value })
    if (!tag) {
      toast.show(tagsStore.state.error || 'No se pudo crear la etiqueta.', 'error')
      return
    }
    creating.value = false
    toast.show(`Etiqueta «${tag.name}» creada.`, 'success')
  } finally {
    saving.value = false
  }
}

async function confirmDelete() {
  const tag = pendingDelete.value
  pendingDelete.value = null
  if (!tag) return

  const ok = await tagsStore.deleteTag(tag.id)
  if (!ok) {
    toast.show(tagsStore.state.error || 'No se pudo borrar la etiqueta.', 'error')
    return
  }
  // La lista de activos ya está en memoria: quitarle la etiqueta aquí evita
  // volver a pedirla entera por un cambio que el cliente ya sabe hacer.
  store.dropTagFromAssets(tag.id)
  if (selectedId.value === tag.id) selectedId.value = null
  toast.show(`Etiqueta «${tag.name}» borrada.`, 'success')
}

onMounted(() => {
  // Los activos hacen falta para el recuento por etiqueta y para la lista de
  // quién la lleva; si se llega aquí directo por URL, aún no están cargados.
  tagsStore.fetchTags()
  if (!store.state.assets.length) store.fetchAssets()
})
</script>

<style scoped>
.tags-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.tags-layout {
  position: relative;
  z-index: 1;
  max-width: 900px;
  margin: 0 auto;
  padding: 1.5rem 1.5rem 3rem;
}

.head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.head-title { margin: 0 0 0.3rem; font-size: var(--fs-2xl); font-weight: 600; color: var(--text); }
.head-sub { margin: 0; max-width: 56ch; font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; }

.btn-new {
  padding: 0.45rem 0.9rem; flex-shrink: 0;
  background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 6px;
  color: var(--accent-bright); font-size: var(--fs-body); font-weight: 600; cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.btn-new:hover { background: var(--accent); color: var(--on-accent); }

.controls { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; margin: 1.2rem 0 0.9rem; }

.search-input {
  flex: 1; min-width: 180px;
  padding: 0.45rem 0.6rem;
  background: var(--surface); border: 1px solid var(--border-med); border-radius: 6px;
  color: var(--text); font-size: var(--fs-md);
}
.search-input:focus { outline: none; border-color: var(--accent); }

.scope { display: flex; gap: 0.25rem; }
.scope-btn {
  padding: 0.35rem 0.7rem;
  background: transparent; border: 1px solid var(--border-med); border-radius: 999px;
  color: var(--text-muted); font-size: var(--fs-sm); cursor: pointer;
  transition: background var(--transition), color var(--transition);
}
.scope-btn:hover { color: var(--text-dim); }
.scope-btn--on { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); font-weight: 600; }

.create-row {
  display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
  margin-bottom: 0.9rem; padding: 0.7rem;
  background: var(--surface); border: 1px dashed var(--accent); border-radius: 8px;
}

.swatches { display: flex; gap: 0.25rem; }
.swatch { width: 18px; height: 18px; border-radius: 50%; border: 1px solid var(--border-med); cursor: pointer; }
.swatch--on { box-shadow: 0 0 0 2px var(--surface), 0 0 0 3px var(--text-dim); }

.btn-secondary, .btn-primary { padding: 0.4rem 0.85rem; border-radius: 6px; font-size: var(--fs-md); font-weight: 600; cursor: pointer; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover:not(:disabled) { background: var(--accent-bright); }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

/* ── Catálogo ── */
.tag-grid {
  list-style: none; margin: 0; padding: 0;
  display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 0.5rem;
}

.tag-card {
  display: flex; align-items: center; gap: 0.4rem;
  padding: 0.55rem 0.6rem;
  background: var(--surface); border: 1px solid var(--border-med); border-radius: 8px;
  transition: border-color var(--transition), background var(--transition);
}
.tag-card:hover { border-color: var(--accent); }
.tag-card--selected { background: var(--accent-dim); border-color: var(--accent); }

.tag-main {
  flex: 1; min-width: 0;
  display: flex; flex-direction: column; align-items: flex-start; gap: 0.25rem;
  background: none; border: none; text-align: left; cursor: pointer;
}
.tag-meta { font-size: var(--fs-caption); color: var(--text-muted); }

.btn-icon {
  width: 28px; height: 28px; flex-shrink: 0;
  display: grid; place-items: center;
  background: transparent; border: 1px solid var(--border-med); border-radius: 6px;
  color: var(--text-muted); cursor: pointer;
  transition: border-color var(--transition), color var(--transition);
}
.btn-icon svg { width: 14px; height: 14px; }
.btn-icon--danger:hover { border-color: var(--danger); color: var(--danger); }

/* ── Quién la lleva ── */
.carriers { margin-top: 1.6rem; padding-top: 1.1rem; border-top: 1px solid var(--border-med); }
.carriers-title { margin: 0 0 0.6rem; font-size: var(--fs-lg); font-weight: 600; color: var(--text); }
.carriers-empty { margin: 0; font-size: var(--fs-md); color: var(--text-muted); }
.carriers-list { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.4rem; }

.carrier {
  display: inline-flex; align-items: center; gap: 0.4rem;
  padding: 0.3rem 0.6rem;
  background: var(--surface); border: 1px solid var(--border-med); border-radius: 6px;
  color: var(--text-dim); font-size: var(--fs-sm); text-decoration: none;
  transition: border-color var(--transition), color var(--transition);
}
.carrier:hover { border-color: var(--accent); color: var(--text); }

.pulse { width: 8px; height: 8px; flex-shrink: 0; border-radius: 50%; background: var(--text-muted); }
.pulse--online { background: var(--success); }
.pulse--stale { background: var(--warn); }
.pulse--offline { background: var(--danger); }

/* ── Estados ── */
.state-msg { margin: 2rem 0; text-align: center; color: var(--text-muted); font-size: var(--fs-body); }
.state-msg--error { color: var(--danger); }
.retry {
  margin-left: 0.5rem; padding: 0.2rem 0.6rem;
  background: transparent; border: 1px solid var(--danger); border-radius: 6px;
  color: var(--danger); font-size: var(--fs-sm); cursor: pointer;
}

.state-empty { padding: 2.4rem 1rem; text-align: center; border: 1px dashed var(--border-med); border-radius: 8px; }
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0; font-size: var(--fs-body); color: var(--text-muted); }

.tag-main:focus-visible, .btn-icon:focus-visible, .btn-new:focus-visible,
.scope-btn:focus-visible, .swatch:focus-visible, .carrier:focus-visible {
  outline: 2px solid var(--accent-bright); outline-offset: 2px;
}
</style>
