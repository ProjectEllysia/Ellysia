<template>
  <div class="tabs" role="tablist">
    <button v-for="tab in tabs" :key="tab.id"
      class="tab" :class="[tab.id, { active: active === tab.id }]"
      role="tab" @click="$emit('switch', tab.id)">
      <span class="tab-dot"></span>
      {{ tab.label }}
    </button>
  </div>
</template>

<script setup>
defineProps({ active: { type: String, required: true } })
defineEmits(['switch'])
const tabs = [
  { id: 'nmap', label: 'Nmap' },
  { id: 'nikto', label: 'Nikto' },
  { id: 'openvas', label: 'OpenVAS' },
]
</script>

<style scoped>
.tabs { display: flex; gap: 0.2rem; margin-bottom: 1.1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0.25rem; }
.tab { flex: 1; padding: 0.5rem 0.85rem; background: none; border: none; border-radius: 6px; color: var(--text-muted); font-size: 0.82rem; font-weight: 500; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.35rem; transition: all 0.2s ease; }
.tab:hover { color: var(--text-dim); }
.tab.active { background: var(--surface-2); color: var(--text); font-weight: 600; }
.tab-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.nmap .tab-dot { background: var(--success); }
.nikto .tab-dot { background: var(--warn); }
.openvas .tab-dot { background: var(--danger); }
</style>
