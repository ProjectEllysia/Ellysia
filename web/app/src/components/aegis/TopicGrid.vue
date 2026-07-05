<template>
  <div class="topic-grid">
    <h4>Temas</h4>
    <div class="grid-scroll">
      <button v-for="t in topics" :key="t.id" type="button"
        class="topic-btn" :class="{ selected: selectedTopicId === t.id }"
        @click="$emit('select', t.id)">
        <span class="topic-name">{{ t.name || t.title || `#${t.id}` }}</span>
        <span v-if="t.description" class="topic-desc">{{ t.description }}</span>
      </button>
    </div>
    <p v-if="topics.length === 0" class="empty-hint">No hay temas disponibles.</p>
  </div>
</template>

<script setup>
defineProps({ topics: { type: Array, default: () => [] }, selectedTopicId: { type: [Number, null], default: null } })
defineEmits(['select'])
</script>

<style scoped>
.topic-grid { display: flex; flex-direction: column; max-height: 300px; }
.topic-grid h4 { font-size: 0.78rem; font-weight: 600; color: var(--text-dim); margin: 0 0 0.4rem; flex-shrink: 0; }
.grid-scroll { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.35rem; padding-right: 0.25rem; }
.grid-scroll::-webkit-scrollbar { width: 4px; }
.grid-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.topic-btn { display: flex; flex-direction: column; align-items: flex-start; gap: 0.1rem; padding: 0.5rem 0.65rem; font-size: 0.8rem; font-weight: 600; border-radius: 7px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; transition: all 0.2s; text-align: left; flex-shrink: 0; }
.topic-btn:hover { border-color: var(--accent); color: var(--text); background: var(--surface); }
.topic-btn.selected { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.topic-name { line-height: 1.3; }
.topic-desc { font-size: 0.65rem; font-weight: 400; opacity: 0.7; line-height: 1.2; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.empty-hint { font-size: 0.75rem; color: var(--text-muted); margin: 0.2rem 0; }
</style>
