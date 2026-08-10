<template>
  <div class="scanner-card">
    <div class="scanner-header">
      <span class="scanner-icon" v-html="iconSvg"></span>
      <h3>{{ name }}</h3>
    </div>
    <div class="scanner-body">
      <h4>Paleta de colores</h4>
      <div class="color-grid">
        <div v-for="c in colors" :key="prefix + c.key" class="color-pick">
          <input :id="prefix + '.colorPalette.' + c.key" v-model="flat[prefix + '.colorPalette.' + c.key]" type="color" class="color-input" />
          <span class="color-label">{{ c.label }}</span>
          <span class="color-hex">{{ flat[prefix + '.colorPalette.' + c.key] }}</span>
        </div>
      </div>
      <h4>Prompt del sistema</h4>
      <textarea v-model="flat[prefix + '.prompts.system']" rows="6" class="textarea"></textarea>
      <h4>Plantilla de usuario</h4>
      <textarea v-model="flat[prefix + '.prompts.userTemplate']" rows="6" class="textarea"></textarea>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ name: { type: String, required: true }, icon: { type: String, default: 'scan' }, prefix: { type: String, required: true }, flat: { type: Object, required: true } })
const colors = [
  { key: 'black', label: 'Negro' }, { key: 'dark', label: 'Oscuro' }, { key: 'main', label: 'Principal' },
  { key: 'secondary', label: 'Secundario' }, { key: 'light', label: 'Claro' }, { key: 'white', label: 'Blanco' },
]
const icons = {
  scan: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v3l2 2"/></svg>`,
  web: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  vuln: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
}
const iconSvg = computed(() => icons[props.icon] || icons.scan)
</script>

<style scoped>
.scanner-card { background: var(--surface); border: 1px solid var(--border); border-radius: 9px; overflow: hidden; }
.scanner-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem 0.85rem; border-bottom: 1px solid var(--border); background: var(--bg); }
.scanner-icon { width: 20px; height: 20px; color: var(--accent); flex-shrink: 0; display: flex; }
.scanner-header h3 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.scanner-body { padding: 0.85rem; display: flex; flex-direction: column; gap: 0.65rem; }
.scanner-body h4 { font-size: var(--fs-md); font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0; }
.color-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.35rem; }
.color-pick { display: flex; flex-direction: column; align-items: center; gap: 0.1rem; padding: 0.4rem 0.2rem; background: var(--bg); border-radius: 5px; border: 1px solid var(--border); }
.color-input { width: 30px; height: 22px; border: none; border-radius: 3px; cursor: pointer; background: transparent; padding: 0; }
.color-label { font-size: var(--fs-body); font-weight: 600; color: var(--text-dim); }
.color-hex { font-size: var(--fs-body); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.textarea { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 5px; padding: 0.45rem 0.55rem; color: var(--text); font-size: var(--fs-input); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); outline: none; resize: vertical; width: 100%; box-sizing: border-box; transition: border-color 0.2s; }
.textarea:focus { border-color: var(--accent); }
</style>
