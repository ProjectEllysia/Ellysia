<template>
  <div class="topic-grid">
    <h4>Temas</h4>

    <div class="topic-search">
      <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" />
      </svg>
      <input
        v-model="search"
        type="text"
        class="search-input"
        placeholder="Buscar tema…"
        aria-label="Buscar tema"
      />
      <button v-if="search" type="button" class="search-clear" aria-label="Limpiar búsqueda" @click="search = ''">&times;</button>
    </div>

    <div class="grid-scroll">
      <button v-for="t in filteredTopics" :key="t.id" type="button"
        class="topic-btn" :class="{ selected: selectedTopicId === t.id }"
        @click="$emit('select', t.id)">
        <span class="topic-name">{{ t.name || t.title || `#${t.id}` }}</span>
        <span v-if="t.description" class="topic-desc">{{ t.description }}</span>
      </button>
      <p v-if="topics.length && !filteredTopics.length" class="empty-hint">
        Ningún tema coincide con «{{ search }}».
      </p>
    </div>

    <p v-if="topics.length === 0" class="empty-hint">No hay temas disponibles.</p>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  topics: { type: Array, default: () => [] },
  selectedTopicId: { type: [Number, null], default: null },
})
defineEmits(['select'])

const search = ref('')

/** Filtro en cliente por nombre/título (sin acentos-fold, simple includes). */
const filteredTopics = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return props.topics
  return props.topics.filter((t) => {
    const label = (t.name || t.title || '').toLowerCase()
    return label.includes(q)
  })
})
</script>

<style scoped>
.topic-grid { display: flex; flex-direction: column; max-height: 340px; }
.topic-grid h4 { font-size: var(--fs-lg); font-weight: 600; color: var(--text-dim); margin: 0 0 0.4rem; flex-shrink: 0; }

/* ── Buscador ── */
.topic-search { position: relative; display: flex; align-items: center; margin-bottom: 0.45rem; flex-shrink: 0; }
.search-icon { position: absolute; left: 0.55rem; width: 15px; height: 15px; color: var(--text-muted); pointer-events: none; }
.search-input {
  width: 100%; box-sizing: border-box;
  padding: 0.4rem 1.9rem 0.4rem 2rem;
  background: var(--bg); border: 1px solid var(--border-solid); border-radius: 7px;
  color: var(--text); font-size: var(--fs-md); font-family: inherit; outline: none;
  transition: border-color 0.2s;
}
.search-input:focus { border-color: var(--accent); }
.search-input::placeholder { color: var(--text-muted); }
.search-clear {
  position: absolute; right: 0.4rem;
  width: 20px; height: 20px; border: none; border-radius: 50%;
  background: none; color: var(--text-muted); cursor: pointer;
  font-size: var(--fs-lg); line-height: 1; display: grid; place-items: center;
  transition: color 0.2s;
}
.search-clear:hover { color: var(--text); }

.grid-scroll { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.35rem; padding-right: 0.25rem; }
.grid-scroll::-webkit-scrollbar { width: 4px; }
.grid-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.topic-btn { display: flex; flex-direction: column; align-items: flex-start; gap: 0.1rem; padding: 0.5rem 0.65rem; font-size: var(--fs-lg); font-weight: 600; border-radius: 7px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; transition: all 0.2s; text-align: left; flex-shrink: 0; }
.topic-btn:hover { border-color: var(--accent); color: var(--text); background: var(--surface); }
.topic-btn.selected { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.topic-name { line-height: 1.3; }
.topic-desc { font-size: var(--fs-body); font-weight: 400; opacity: 0.7; line-height: 1.2; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.empty-hint { font-size: var(--fs-md); color: var(--text-muted); margin: 0.2rem 0; }
</style>
