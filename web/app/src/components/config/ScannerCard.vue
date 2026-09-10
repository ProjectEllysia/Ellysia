<template>
  <div class="card scanner-card">
    <CollapsibleSection :default-open="defaultOpen">
      <template #header>
        <div class="scanner-header">
          <span class="scanner-icon" v-html="iconSvg"></span>
          <h3>{{ name }}</h3>
        </div>
      </template>
      <div class="scanner-body">
        <slot />
        <h4>Paleta de colores</h4>
        <div class="color-grid">
          <div v-for="c in colors" :key="prefix + c.key" class="color-pick">
            <input :id="prefix + '.colorPalette.' + c.key" v-model="flat[prefix + '.colorPalette.' + c.key]" type="color" class="color-input" />
            <span class="color-label">{{ c.label }}</span>
            <span class="color-hex">{{ flat[prefix + '.colorPalette.' + c.key] }}</span>
          </div>
        </div>
        <PromptField v-model="flat[prefix + '.prompts.system']" label="Prompt del sistema" :title="name + ' — prompt del sistema'" />
        <PromptField v-model="flat[prefix + '.prompts.userTemplate']" label="Plantilla de usuario" :title="name + ' — plantilla de usuario'" />
      </div>
    </CollapsibleSection>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import PromptField from '@/components/shared/PromptField.vue'
import CollapsibleSection from '@/components/config/CollapsibleSection.vue'
const props = defineProps({
  name: { type: String, required: true },
  icon: { type: String, default: 'scan' },
  prefix: { type: String, required: true },
  flat: { type: Object, required: true },
  // Colapsada por defecto para que las cuatro tarjetas de Themis empiecen a la
  // misma altura: expandir una no debe descolocar a las demás,
  // así que cada tarjeta abre de forma independiente, no en modo acordeón.
  defaultOpen: { type: Boolean, default: false },
})
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
.scanner-card { overflow: hidden; }
/* El toggle de CollapsibleSection es un componente aparte con CSS scoped
   propio: :deep() es lo único que permite darle aquí el mismo aspecto de
   cabecera (fondo, borde inferior, padding) que tenía la cabecera fija antes
   de que la tarjeta fuera colapsable. */
:deep(.collapsible-toggle) { padding: 0.75rem 0.85rem; background: var(--bg); border-bottom: 1px solid var(--border); }
:deep(.collapsible-body) { padding-top: 0; }
.scanner-header { display: flex; align-items: center; gap: 0.5rem; }
.scanner-icon { width: 20px; height: 20px; color: var(--accent); flex-shrink: 0; display: flex; }
.scanner-header h3 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.scanner-body { padding: 0.85rem; display: flex; flex-direction: column; gap: 0.65rem; }
.scanner-body h4 { font-size: var(--fs-md); font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0; }
.color-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.35rem; }
.color-pick { display: flex; flex-direction: column; align-items: center; gap: 0.1rem; padding: 0.4rem 0.2rem; background: var(--bg); border-radius: 5px; border: 1px solid var(--border); }
.color-input { width: 30px; height: 22px; border: none; border-radius: 3px; cursor: pointer; background: transparent; padding: 0; }
.color-label { font-size: var(--fs-body); font-weight: 600; color: var(--text-dim); }
.color-hex { font-size: var(--fs-body); color: var(--text-muted); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
</style>
