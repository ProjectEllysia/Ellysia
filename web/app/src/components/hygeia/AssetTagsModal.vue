<template>
  <Teleport to="body">
    <Transition name="modal">
      <!-- `data-module` va en el overlay, no en la página: Teleport saca este
           nodo de la raíz de la vista y sin esto el modal heredaría el acento
           dorado por defecto en vez del verde de Hygeia. -->
      <div v-if="show" class="modal-overlay" data-module="hygeia" @click.self="$emit('close')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>Etiquetas de {{ asset?.hostname }}</h3>
            <button class="close-btn" @click="$emit('close')">&times;</button>
          </div>

          <div class="modal-body">
            <input
              ref="searchInput"
              v-model.trim="search"
              type="search"
              class="search-input"
              placeholder="Buscar o crear una etiqueta…"
              @keydown.enter.prevent="onEnter"
            />

            <div v-if="chosen.length" class="chosen">
              <TagBadge
                v-for="tag in chosen" :key="tagKey(tag)"
                :tag="tag" removable
                @remove="toggle(tag)"
              />
            </div>

            <div class="groups">
              <template v-for="group in groups" :key="group.title">
                <p v-if="group.tags.length" class="group-title">{{ group.title }}</p>
                <label v-for="tag in group.tags" :key="tag.id" class="option">
                  <input type="checkbox" :checked="isSelected(tag.id)" @change="toggle(tag)" />
                  <TagBadge :tag="tag" />
                  <span class="option-count">{{ countLabel(tag) }}</span>
                </label>
              </template>

              <p v-if="!hasVisibleTags && !canCreate" class="empty">
                No hay ninguna etiqueta que coincida.
              </p>
            </div>

            <!-- Crear desde aquí: lo que se escriba y no exista se puede añadir
                 al repositorio personal y queda marcado en el acto. Se guarda
                 con el resto al aceptar, en una sola operación. -->
            <div v-if="canCreate" class="create">
              <button type="button" class="create-btn" @click="stageNewTag">
                Crear «{{ search }}»
              </button>
              <span class="swatches">
                <button
                  v-for="color in TAG_COLOR_NAMES" :key="color"
                  type="button" class="swatch" :class="{ 'swatch--on': color === newColor }"
                  :style="{ background: hueOf(color) }"
                  :aria-label="`Color ${color}`" :aria-pressed="color === newColor"
                  @click="newColor = color"
                ></button>
              </span>
            </div>

            <p v-if="error" class="error">{{ error }}</p>

            <div class="modal-footer">
              <button type="button" class="btn-secondary" @click="$emit('close')">Cancelar</button>
              <button type="button" class="btn-primary" :disabled="submitting" @click="submit">
                {{ submitting ? 'Guardando…' : 'Guardar' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import TagBadge from './TagBadge.vue'
import { TAG_COLOR_NAMES, hueOf } from './tagColors'

const props = defineProps({
  show: { type: Boolean, default: false },
  /** Activo que se está etiquetando; sus `tags` son el estado de partida. */
  asset: { type: Object, default: null },
  /** Catálogo visible: las de sistema más las del usuario. */
  tags: { type: Array, default: () => [] },
  submitting: { type: Boolean, default: false },
  error: { type: String, default: '' },
})
const emit = defineEmits(['submit', 'close'])

const search = ref('')
const selectedIds = ref([])
/** Etiquetas escritas aquí que aún no existen en el servidor. */
const pendingNew = ref([])
const newColor = ref('slate')
const searchInput = ref(null)

// Al abrir se parte de lo que el activo ya lleva; al cerrar no se limpia nada,
// porque el siguiente `show` lo vuelve a hacer.
watch(() => props.show, (visible) => {
  if (!visible) return
  search.value = ''
  pendingNew.value = []
  newColor.value = 'slate'
  selectedIds.value = (props.asset?.tags ?? []).map((tag) => tag.id)
  nextTick(() => searchInput.value?.focus())
})

const normalizedSearch = computed(() => search.value.trim().toLowerCase())

function matches(tag) {
  return !normalizedSearch.value || tag.name.toLowerCase().includes(normalizedSearch.value)
}

const groups = computed(() => [
  { title: 'Catálogo común', tags: props.tags.filter((t) => t.tagType === 'system' && matches(t)) },
  { title: 'Mis etiquetas', tags: props.tags.filter((t) => t.tagType === 'user' && matches(t)) },
])

const hasVisibleTags = computed(() => groups.value.some((group) => group.tags.length))

/** Solo se ofrece crear si lo escrito no existe ya, ni en el catálogo ni entre las pendientes. */
const canCreate = computed(() => {
  if (!normalizedSearch.value) return false
  const taken = [...props.tags, ...pendingNew.value]
    .some((tag) => tag.name.toLowerCase() === normalizedSearch.value)
  return !taken
})

/** Las pendientes aún no tienen id, así que la clave de lista es su nombre. */
function tagKey(tag) { return tag.id ?? `new:${tag.name}` }

function isSelected(id) { return selectedIds.value.includes(id) }

const chosen = computed(() => [
  ...props.tags.filter((tag) => selectedIds.value.includes(tag.id)),
  ...pendingNew.value,
])

function toggle(tag) {
  if (tag.id == null) {
    pendingNew.value = pendingNew.value.filter((pending) => pending.name !== tag.name)
    return
  }
  selectedIds.value = isSelected(tag.id)
    ? selectedIds.value.filter((id) => id !== tag.id)
    : [...selectedIds.value, tag.id]
}

function countLabel(tag) {
  const count = tag.assetCount ?? 0
  return count === 1 ? '1 activo' : `${count} activos`
}

function stageNewTag() {
  if (!canCreate.value) return
  pendingNew.value = [...pendingNew.value, { name: search.value.trim(), color: newColor.value }]
  search.value = ''
}

/** Enter crea si lo escrito es nuevo; si ya existe, lo marca. */
function onEnter() {
  if (canCreate.value) { stageNewTag(); return }
  const match = props.tags.find((tag) => tag.name.toLowerCase() === normalizedSearch.value)
  if (match) { toggle(match); search.value = '' }
}

function submit() {
  emit('submit', { tagIds: [...selectedIds.value], newTags: [...pendingNew.value] })
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 460px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }

.search-input {
  width: 100%; padding: 0.45rem 0.6rem;
  background: var(--bg); border: 1px solid var(--border-med); border-radius: 6px;
  color: var(--text); font-size: var(--fs-md);
}
.search-input:focus { outline: none; border-color: var(--accent); }

.chosen { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.7rem; }

/* Alto acotado: con el catálogo común más el personal la lista puede pasarse
   de largo, y el botón de guardar tiene que seguir a la vista. */
.groups { max-height: 240px; overflow-y: auto; margin-top: 0.7rem; }

.group-title {
  margin: 0.6rem 0 0.3rem;
  font-size: var(--fs-caption); font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--text-muted);
}

.option {
  display: flex; align-items: center; gap: 0.5rem;
  padding: 0.28rem 0.35rem; border-radius: 6px; cursor: pointer;
}
.option:hover { background: var(--surface-2); }
.option input { accent-color: var(--accent); flex-shrink: 0; }
.option-count { margin-left: auto; font-size: var(--fs-caption); color: var(--text-muted); white-space: nowrap; }

.empty { margin: 0.8rem 0; text-align: center; color: var(--text-muted); font-size: var(--fs-sm); }

.create {
  display: flex; align-items: center; justify-content: space-between; gap: 0.6rem; flex-wrap: wrap;
  margin-top: 0.7rem; padding-top: 0.7rem; border-top: 1px dashed var(--border-med);
}
.create-btn {
  padding: 0.35rem 0.7rem;
  background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 6px;
  color: var(--accent-bright); font-size: var(--fs-sm); font-weight: 600; cursor: pointer;
  max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.create-btn:hover { background: var(--accent); color: var(--on-accent); }

.swatches { display: flex; gap: 0.25rem; }
.swatch {
  width: 16px; height: 16px; border-radius: 50%;
  border: 1px solid var(--border-med); cursor: pointer;
}
.swatch--on { box-shadow: 0 0 0 2px var(--surface), 0 0 0 3px var(--text-dim); }

.error { color: var(--danger); font-size: var(--fs-sm); margin: 0.7rem 0 0; }

.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }
.btn-secondary, .btn-primary { padding: 0.45rem 0.9rem; border-radius: 6px; font-size: var(--fs-md); font-weight: 600; cursor: pointer; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover:not(:disabled) { background: var(--accent-bright); }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
