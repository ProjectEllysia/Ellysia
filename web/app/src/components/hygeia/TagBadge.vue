<template>
  <span class="tag-badge" :class="{ 'tag-badge--sm': small }" :style="{ '--tag-hue': hueOf(tag.color) }">
    <span class="tag-name">{{ tag.name }}</span>
    <button
      v-if="removable"
      type="button"
      class="tag-remove"
      :aria-label="`Quitar la etiqueta ${tag.name}`"
      @click.stop="$emit('remove', tag.id)"
    >&times;</button>
  </span>
</template>

<script setup>
import { hueOf } from './tagColors'

defineProps({
  tag: { type: Object, required: true },
  /** Muestra la aspa para quitarla. Presentacional: quien decide es el padre. */
  removable: { type: Boolean, default: false },
  /** Versión compacta, para las tiras de las filas de la lista. */
  small: { type: Boolean, default: false },
})
defineEmits(['remove'])
</script>

<style scoped>
/* Un solo bloque para los ocho colores: el matiz entra por `--tag-hue` desde
   JS, así que la paleta vive en un sitio (tagColors.js) y no en ocho reglas
   CSS que habría que mantener en paralelo. */
.tag-badge {
  display: inline-flex; align-items: center; gap: 0.25rem;
  max-width: 100%;
  padding: 0.15rem 0.45rem;
  background: color-mix(in srgb, var(--tag-hue) 16%, transparent);
  border: 1px solid color-mix(in srgb, var(--tag-hue) 38%, transparent);
  border-radius: 999px;
  color: var(--tag-hue);
  font-size: var(--fs-sm); font-weight: 500; line-height: 1.4;
}

.tag-badge--sm { padding: 0.05rem 0.35rem; font-size: var(--fs-caption); }

.tag-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.tag-remove {
  flex-shrink: 0;
  padding: 0 0.1rem;
  background: none; border: none;
  color: inherit; opacity: 0.65;
  font-size: 1em; line-height: 1; cursor: pointer;
}
.tag-remove:hover { opacity: 1; }
.tag-remove:focus-visible { outline: 1px solid currentColor; outline-offset: 1px; }

/* Sobre fondo claro los mismos matices quedan lavados: el texto se oscurece y
   el relleno se aclara para conservar el contraste sin cambiar la paleta. */
[data-theme="dawn"] .tag-badge {
  background: color-mix(in srgb, var(--tag-hue) 12%, white);
  border-color: color-mix(in srgb, var(--tag-hue) 45%, transparent);
  color: color-mix(in srgb, var(--tag-hue) 72%, black);
}
</style>
