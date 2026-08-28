<template>
  <fieldset class="wl">
    <legend class="wl-legend">White-labeling</legend>
    <p class="wl-hint">
      Cuánto de la marca de Ellysia ve quien recibe los envíos de este módulo.
    </p>

    <label
      v-for="option in options"
      :key="option.value"
      class="wl-option"
      :class="{ 'wl-option--active': modelValue.level === option.value, 'wl-option--locked': isLocked(option.value) }"
    >
      <input
        type="radio"
        :value="option.value"
        :checked="modelValue.level === option.value"
        :disabled="isLocked(option.value)"
        @change="setLevel(option.value)"
      />
      <span class="wl-option-text">
        <span class="wl-option-title">
          {{ option.title }}
          <span v-if="isLocked(option.value)" class="wl-lock">No incluido en tu plan</span>
        </span>
        <small>{{ option.description }}</small>
      </span>
    </label>

    <!-- Cada campo se pide desde el escalón que lo usa: ofrecerlo antes sería
         un control que no se pinta en ninguna parte. -->
    <div v-if="modelValue.level !== 'none'" class="wl-color">
      <label class="wl-color-label" for="wl-color-input">Color de énfasis</label>
      <input
        id="wl-color-input"
        type="color"
        class="wl-swatch"
        :value="modelValue.color || DEFAULT_COLOR"
        @input="update({ color: $event.target.value })"
      />
      <code class="wl-color-value">{{ modelValue.color || DEFAULT_COLOR }}</code>
      <!-- "Restablecer" vuelve al acento del producto de forma explícita, no
           vaciando el campo: un color vacío deja el nivel sin su dato y el
           envío lo degradaría en silencio. -->
      <button
        v-if="modelValue.color && modelValue.color !== DEFAULT_COLOR"
        type="button"
        class="wl-remove"
        @click="update({ color: DEFAULT_COLOR })"
      >
        Restablecer
      </button>
    </div>

    <div v-if="levelRank >= LEVELS.indexOf('logo')" class="wl-logo">
      <div v-if="modelValue.logo" class="wl-preview">
        <img :src="modelValue.logo" alt="Logo de la organización" />
        <button type="button" class="wl-remove" @click="clearLogo">Quitar</button>
      </div>

      <label class="wl-file">
        <input type="file" :accept="ACCEPTED_TYPES.join(',')" @change="onFile" />
        <span>{{ modelValue.logo ? 'Cambiar imagen' : 'Añadir imagen corporativa' }}</span>
      </label>

      <p v-if="error" class="wl-error">{{ error }}</p>
      <p v-else-if="!modelValue.logo" class="wl-warning">
        Sin imagen este nivel no se aplica: los envíos saldrán con el escalón
        anterior, «Aplicar color corporativo».
      </p>
      <p v-else class="wl-hint">PNG, JPG o GIF, hasta {{ MAX_KB }} KB.</p>
    </div>

    <p v-if="modelValue.level === 'full'" class="wl-note">
      El remitente del correo sigue siendo el del servidor configurado en la
      instancia: el white-labeling cambia lo que se ve dentro del mensaje, no
      el dominio desde el que sale.
    </p>
  </fieldset>
</template>

<script setup>
/**
 * Ajustes de white-labeling de un módulo: nivel, color y logo de la
 * organización.
 *
 * No sabe de qué módulo son los ajustes ni cómo se guardan — se ata con
 * `v-model` a un objeto `{ level, color, logo }` y avisa de los cambios. El tope lo
 * decide el plan y llega en `maxLevel`; el servidor lo vuelve a comprobar al
 * guardar, así que aquí solo se evita ofrecer lo que se va a rechazar.
 *
 * El logo viaja como data URI, que es como lo guarda la API y como se
 * previsualiza sin subir nada todavía.
 */
import { computed, ref } from 'vue'

const props = defineProps({
  modelValue: { type: Object, required: true },
  /** Nivel máximo que concede el plan ('none' | 'color' | 'logo' | 'full'). */
  maxLevel: { type: String, default: 'none' },
})
const emit = defineEmits(['update:modelValue'])

// Mismos límites que valida el servidor (shared/_white_label.py). Duplicados a
// propósito: aquí solo evitan un viaje que iba a fallar; la comprobación de
// verdad es la del borde de confianza, no esta.
const ACCEPTED_TYPES = ['image/png', 'image/jpeg', 'image/gif']
const MAX_KB = 200

//: El acento del producto, que es lo que se sustituye. Sirve de punto de
//: partida del selector cuando la organización todavía no ha elegido color.
const DEFAULT_COLOR = '#d4a04a'

const LEVELS = ['none', 'color', 'logo', 'full']

const options = [
  {
    value: 'none',
    title: 'Nada de white-labeling',
    description: 'Los envíos salen con la marca de Ellysia, como hasta ahora.',
  },
  {
    value: 'color',
    title: 'Aplicar color corporativo',
    description: 'El color de énfasis (botones, filetes y bordes) pasa a ser el de la organización.',
  },
  {
    value: 'logo',
    title: 'Añadir imagen corporativa',
    description: 'Además del color, se añade el logo de la organización sobre el texto introductorio.',
  },
  {
    value: 'full',
    title: 'Eliminar todo lo relacionado con Ellysia',
    description: 'La cabecera, el pie y la página del test pasan a la marca de la organización.',
  },
]

const error = ref('')

const levelRank = computed(() => Math.max(0, LEVELS.indexOf(props.modelValue.level)))
const maxRank = computed(() => Math.max(0, LEVELS.indexOf(props.maxLevel)))
function isLocked(level) {
  return LEVELS.indexOf(level) > maxRank.value
}

function update(patch) {
  emit('update:modelValue', { ...props.modelValue, ...patch })
}

function setLevel(level) {
  if (isLocked(level)) return
  // El color del selector entra en el modelo en cuanto el nivel lo usa. Si no,
  // se enseñaba DEFAULT_COLOR en la muestra y se guardaba una cadena vacía: el
  // nivel quedaba sin su dato y el envío lo degradaba en silencio (el servidor
  // acepta el guardado, así que no había ni error ni aviso).
  const patch = { level }
  if (level !== 'none' && !props.modelValue.color) patch.color = DEFAULT_COLOR
  update(patch)
}

function clearLogo() {
  error.value = ''
  update({ logo: '' })
}

function onFile(event) {
  const file = event.target.files?.[0]
  // El input se vacía siempre: si no, elegir el mismo fichero dos veces
  // seguidas (tras un error) no dispara un segundo 'change'.
  event.target.value = ''
  if (!file) return

  error.value = ''
  if (!ACCEPTED_TYPES.includes(file.type)) {
    error.value = 'Formato no admitido. Usa PNG, JPG o GIF.'
    return
  }
  if (file.size > MAX_KB * 1024) {
    error.value = `La imagen ocupa ${Math.round(file.size / 1024)} KB y el máximo son ${MAX_KB} KB.`
    return
  }

  const reader = new FileReader()
  reader.onerror = () => { error.value = 'No se ha podido leer la imagen.' }
  reader.onload = () => update({ logo: String(reader.result || '') })
  reader.readAsDataURL(file)
}
</script>

<style scoped>
.wl { border: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
.wl-legend {
  padding: 0; font-size: var(--fs-md); font-weight: 600; color: var(--text);
}
.wl-hint { margin: 0; font-size: var(--fs-sm); color: var(--text-muted); }

.wl-option {
  display: flex; align-items: flex-start; gap: 0.55rem;
  padding: 0.55rem 0.7rem; border-radius: 7px; cursor: pointer;
  background: var(--bg); border: 1px solid var(--border-solid);
  transition: border-color 0.15s, background 0.15s;
}
.wl-option:hover:not(.wl-option--locked) { border-color: var(--accent); }
.wl-option--active { border-color: var(--accent); background: var(--surface-2); }
.wl-option--locked { opacity: 0.55; cursor: not-allowed; }
.wl-option input { margin-top: 0.2rem; accent-color: var(--accent); }
.wl-option-text { display: flex; flex-direction: column; gap: 0.15rem; }
.wl-option-title { font-size: var(--fs-md); font-weight: 600; color: var(--text); }
.wl-option-text small { font-size: var(--fs-sm); color: var(--text-muted); line-height: 1.35; }
.wl-lock {
  margin-left: 0.4rem; padding: 0 0.35rem; border-radius: 4px;
  font-size: var(--fs-xs); font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--text-dim); background: var(--surface-3);
}

.wl-color { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.2rem; }
.wl-color-label { font-size: var(--fs-sm); color: var(--text-dim); }
/* El selector nativo trae un marco y un relleno propios en cada navegador:
   se recortan para que la muestra sea solo el color. */
.wl-swatch {
  width: 34px; height: 26px; padding: 0; cursor: pointer;
  background: none; border: 1px solid var(--border-solid); border-radius: 5px;
}
.wl-swatch::-webkit-color-swatch-wrapper { padding: 2px; }
.wl-swatch::-webkit-color-swatch { border: none; border-radius: 3px; }
.wl-swatch:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
.wl-color-value { font-size: var(--fs-xs); color: var(--text-muted); }

.wl-logo { display: flex; flex-direction: column; gap: 0.45rem; margin-top: 0.2rem; }
.wl-preview { display: flex; align-items: center; gap: 0.6rem; }
.wl-preview img {
  max-width: 140px; max-height: 56px; object-fit: contain;
  background: var(--surface-2); border: 1px solid var(--border-med); border-radius: 6px; padding: 0.3rem;
}
.wl-remove {
  background: none; border: none; padding: 0; cursor: pointer;
  font-family: inherit; font-size: var(--fs-xs); color: var(--text-dim); text-decoration: underline;
}
.wl-remove:hover { color: var(--accent-bright); }

/* El <input type="file"> nativo no se puede estilar: se oculta y el <label>
   que lo envuelve hace de botón. */
.wl-file input { position: absolute; width: 1px; height: 1px; opacity: 0; }
.wl-file {
  display: inline-flex; align-items: center; justify-content: center;
  padding: 0.4rem 0.75rem; border-radius: 7px; cursor: pointer;
  background: var(--bg); border: 1px solid var(--border-solid);
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 600;
}
.wl-file:hover { border-color: var(--accent); color: var(--accent-bright); }
.wl-file:focus-within { outline: 2px solid var(--accent-bright); outline-offset: 2px; }

.wl-error { margin: 0; font-size: var(--fs-xs); color: var(--danger, #c2621d); }
.wl-warning { margin: 0; font-size: var(--fs-sm); color: var(--warn, #a8842a); line-height: 1.35; }
.wl-note {
  margin: 0.2rem 0 0; padding: 0.5rem 0.65rem; border-radius: 6px;
  background: var(--surface-2); border-left: 2px solid var(--border-med);
  font-size: var(--fs-sm); color: var(--text-muted); line-height: 1.4;
}
</style>
