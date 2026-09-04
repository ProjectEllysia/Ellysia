<template>
  <div class="form-group model-picker">
    <label>{{ label }}</label>

    <select v-if="usesDropdown" :value="modelValue" class="inp sel" @change="pick($event.target.value)">
      <option value="">Usar el del entorno ({{ envHint }})</option>
      <option v-for="name in options" :key="name" :value="name">{{ name }}</option>
    </select>

    <input
      v-else
      :value="modelValue"
      type="text"
      class="inp mono"
      :placeholder="envHint"
      @input="pick($event.target.value)"
    />

    <div class="mp-foot">
      <span v-if="loading" class="field-hint">Consultando al proveedor…</span>
      <span v-else-if="catalog?.isReachable" class="field-hint">
        {{ options.length }} {{ options.length === 1 ? 'modelo disponible' : 'modelos disponibles' }}
      </span>
      <span v-else class="field-hint field-hint--warn" :title="catalog?.error">
        No se pudo consultar el proveedor: escribe el identificador a mano.
      </span>

      <button v-if="catalog?.isReachable" type="button" class="mp-toggle" @click="isManual = !isManual">
        {{ isManual ? 'Elegir de la lista' : 'Escribirlo a mano' }}
      </button>
    </div>
  </div>
</template>

<script setup>
/**
 * Selector del modelo de un proveedor de IA.
 *
 * Escribir el identificador a mano (`gpt-4.1-2025-04-14`) es fácil de
 * equivocar, y equivocarse no se nota al guardar: falla mucho después, dentro
 * de un job de fondo, y lo único que ve el usuario es que el informe no se
 * generó. Por eso lo normal aquí es un desplegable con lo que el proveedor
 * dice servir ahora mismo (`GET /system/ai/models`).
 *
 * El campo de texto sigue existiendo por dos motivos, y por eso no es un
 * `<select>` a secas: cuando al proveedor no se le puede preguntar (sin
 * credenciales, servidor apagado) hay que poder configurarlo igual, y cuando
 * el modelo es más nuevo que lo que el catálogo devuelve hay que poder
 * adelantarse.
 *
 * El valor vacío no es "sin modelo": significa delegar en la variable de
 * entorno del proveedor, que es como se comportaba todo antes de que el
 * modelo se pudiera configurar desde aquí.
 */
import { computed, ref } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, required: true },
  /** Fila de GET /system/ai/models: { models, isReachable, error } */
  catalog: { type: Object, default: null },
  /** Variable de entorno que se usa cuando el campo queda vacío */
  envHint: { type: String, required: true },
  loading: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue'])

const isManual = ref(false)

/** Lo que sirve el proveedor, más el valor guardado si el catálogo no lo trae
 *  todavía: un modelo configurado no puede desaparecer del desplegable por no
 *  estar en la respuesta, o al abrir el panel se perdería sin tocar nada. */
const options = computed(() => {
  const served = props.catalog?.models || []
  if (props.modelValue && !served.includes(props.modelValue)) return [props.modelValue, ...served]
  return served
})

const usesDropdown = computed(() => !isManual.value && props.catalog?.isReachable)

function pick(value) { emit('update:modelValue', value) }
</script>

<style scoped>
/* Los estilos de formulario de ConfigView son `scoped`, así que no cruzan al
   interior de un componente hijo: se repiten aquí los cuatro que este usa. */
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; width: 100%; }
.inp:focus { border-color: var(--accent); }
.sel { cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 1.8rem; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2382829a' stroke-width='2.5'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 0.55rem center; background-size: 0.85rem; }
.sel option { background: var(--surface-2); color: var(--text); }
.mono { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.field-hint { font-size: var(--fs-md); color: var(--text-muted); line-height: 1.5; }

.mp-foot { display: flex; align-items: baseline; justify-content: space-between; gap: 0.5rem; }
.field-hint--warn { color: var(--warning, #d0a215); }
.mp-toggle { background: none; border: none; padding: 0; color: var(--accent-bright); font-size: var(--fs-md); font-weight: 600; cursor: pointer; white-space: nowrap; }
.mp-toggle:hover { text-decoration: underline; }
</style>
