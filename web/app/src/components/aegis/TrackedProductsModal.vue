<template>
  <Teleport to="body">
    <Transition name="modal">
      <!-- `data-module` va en el overlay, no en la página: Teleport saca este
           nodo de la raíz de la vista y sin esto el modal heredaría el acento
           dorado por defecto en vez del de Aegis. -->
      <div
        v-if="show"
        class="tp-overlay"
        data-module="aegis"
        @click.self="close"
      >
        <!-- Prefijo `tp-` en vez de `modal-`: shared.css define `.modal`,
             `.modal-header` y compañía de forma global (restos del legacy), y
             un bloque scoped solo gana en las propiedades que declara — el
             global se cuela en todas las demás. IrisArchiveModal escapa igual
             con `archive-`. -->
        <div
          ref="boxRef"
          class="tp-box"
          role="dialog"
          aria-modal="true"
          aria-labelledby="tp-title"
        >
          <div class="tp-header">
            <h3 id="tp-title">Productos vigilados</h3>
            <button
              type="button"
              class="tp-close"
              aria-label="Cerrar"
              title="Cerrar (Esc)"
              @click="close"
            >
              &times;
            </button>
          </div>

          <div class="tp-body">
            <!-- Solo se ofrece si hay algún agente que haya reportado
                 inventario; si no, la preferencia queda latente. -->
            <label v-if="store.hygeiaInventoryAvailable" class="tp-switch">
              <input type="checkbox" v-model="store.useHygeiaInventory" />
              <span>
                Deducir los productos de mis agentes
                <small
                  >Usa el software que Hygeia inventaría en tus activos en lugar
                  de la lista de abajo.</small
                >
              </span>
            </label>

            <p v-if="usingInventory" class="tp-hint">
              Ahora mismo se usan los de tus agentes. Esta lista queda como
              alternativa si desactivas la opción de arriba.
            </p>

            <input
              id="tp-search"
              ref="searchRef"
              v-model="productQuery"
              type="search"
              class="tp-search"
              placeholder="Busca un producto: windows, firefox, apache…"
              autocomplete="off"
              @input="onProductQuery"
            />

            <!-- Un solo hueco para todos los estados, encadenados por
                 prioridad: lo que esté pasando ahora manda sobre lo anterior. -->
            <p class="tp-hint" aria-live="polite">
              <template v-if="store.searchingProducts">Buscando…</template>
              <template v-else-if="store.productSearchError">{{
                store.productSearchError
              }}</template>
              <template v-else-if="trimmedQuery.length === 1"
                >Escribe al menos 2 caracteres.</template
              >
              <template
                v-else-if="trimmedQuery.length >= 2 && !store.productResults.length"
                >Sin coincidencias en el catálogo de vulnerabilidades.</template
              >
            </p>

            <ul v-if="store.productResults.length" class="tp-results">
              <li
                v-for="p in store.productResults"
                :key="`${p.vendor}:${p.product}`"
              >
                <button type="button" @click="pickProduct(p)">
                  <span class="tp-name">{{ p.displayName }}</span>
                  <span class="tp-cpe">{{ p.vendor }}:{{ p.product }}</span>
                </button>
              </li>
            </ul>

            <!-- Los seleccionados van DEBAJO de los resultados, al revés que en
                 AssetTagsModal: así el buscador y la lista no se desplazan
                 hacia abajo cada vez que se añade uno, que es justo donde está
                 mirando el usuario mientras escribe. -->
            <div class="tp-chosen" :class="{ 'tp-chosen--muted': usingInventory }">
              <p class="tp-chosen-title">
                {{ countLabel }}
              </p>
              <div v-if="store.trackedProducts.length" class="tp-chips">
                <span
                  v-for="p in store.trackedProducts"
                  :key="`${p.vendor}:${p.product}`"
                  class="tp-chip"
                >
                  {{ p.vendor
                  }}<template v-if="p.product"> · {{ p.product }}</template>
                  <button
                    type="button"
                    class="tp-chip-remove"
                    :aria-label="`Quitar ${p.vendor} ${p.product}`"
                    @click="store.removeTrackedProduct(p)"
                  >
                    &times;
                  </button>
                </span>
              </div>
              <p v-else class="empty-state">Aún no vigilas ningún producto.</p>
            </div>
          </div>

          <!-- El pie es hermano de `.tp-body`, no hijo: así queda fuera del
               scroll y el botón no se mueve por muchos resultados que haya. -->
          <div class="tp-footer">
            <p class="tp-save-note">
              Los cambios se guardan con «Guardar perfil».
            </p>
            <button type="button" class="tp-done" @click="close">Listo</button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { useAegisStore } from "@/stores/aegisStore";
import { useModalA11y } from "@/composables/useModalA11y";

const props = defineProps({
  show: { type: Boolean, default: false },
});
const emit = defineEmits(["close"]);

const store = useAegisStore();

const productQuery = ref("");
const searchRef = ref(null);
const boxRef = ref(null);

const trimmedQuery = computed(() => productQuery.value.trim());

/** Origen efectivo de los productos: los agentes mandan cuando están activos. */
const usingInventory = computed(
  () => store.hygeiaInventoryAvailable && store.useHygeiaInventory,
);

const countLabel = computed(() => {
  const count = store.trackedProducts.length;
  if (!count) return "Seleccionados";
  return count === 1 ? "1 producto vigilado" : `${count} productos vigilados`;
});

// Debounce: cada pulsación consultaría el índice CPE, y el endpoint está
// limitado a 120 peticiones/hora.
let queryTimer = null;
function onProductQuery() {
  clearTimeout(queryTimer);
  const term = productQuery.value;
  queryTimer = setTimeout(() => store.searchProducts(term), 250);
}

function pickProduct(product) {
  store.addTrackedProduct(product);
  productQuery.value = "";
}

function close() {
  emit("close");
}

// Al abrir se parte de cero; al cerrar se limpia el debounce pendiente.
watch(
  () => props.show,
  (visible) => {
    if (visible) {
      productQuery.value = "";
      // Con menos de 2 caracteres esto solo limpia resultados y error, sin
      // llegar a pedir nada. Evita tocar el estado del store a mano.
      store.searchProducts("");
    } else {
      clearTimeout(queryTimer);
    }
  },
);

useModalA11y(() => props.show, { boxRef, autofocusRef: searchRef, onClose: close });
</script>

<style scoped>
.tp-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  padding: 1rem;
}

/* `min-height: 0` en toda la cadena flex: sin él un hijo no se encoge por
   debajo de su contenido y ninguno de los `max-height` de abajo recorta nada
   — que es exactamente lo que le pasaba al panel. */
.tp-box {
  display: flex;
  flex-direction: column;
  width: min(560px, 100%);
  max-height: 85vh;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
}

.tp-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.85rem 1.1rem;
  border-bottom: 1px solid var(--border);
  flex: 0 0 auto;
}
.tp-header h3 {
  margin: 0;
  font-size: var(--fs-xl);
  color: var(--text);
  font-family: var(--font-display);
  font-size-adjust: var(--fsa-display);
}
.tp-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: var(--fs-xl);
  line-height: 1;
  cursor: pointer;
  padding: 0;
}
.tp-close:hover {
  color: var(--text);
}

.tp-body {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  min-height: 0;
  overflow: hidden;
  padding: 1rem 1.1rem;
}

.tp-switch {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  cursor: pointer;
  font-size: var(--fs-md);
  font-weight: 600;
  color: var(--text-dim);
  flex: 0 0 auto;
}
.tp-switch input {
  margin-top: 0.25rem;
  accent-color: var(--accent);
  flex: 0 0 auto;
}
.tp-switch small {
  display: block;
  font-size: var(--fs-sm);
  color: var(--text-muted);
  font-weight: 400;
}

.tp-hint {
  font-size: var(--fs-sm);
  color: var(--text-muted);
  margin: 0;
  min-height: 1.2em;
  flex: 0 0 auto;
}

.tp-search {
  background: var(--bg);
  border: 1px solid var(--border-solid);
  border-radius: 6px;
  padding: 0.45rem 0.6rem;
  color: var(--text);
  font-size: var(--fs-input);
  font-family: inherit;
  outline: none;
  width: 100%;
  box-sizing: border-box;
  transition: border-color 0.2s;
  flex: 0 0 auto;
}
.tp-search:focus {
  border-color: var(--accent);
}

/* Deja de ser in-flow sin tope real: aquí se queda con su alto y hace scroll,
   en vez de empujar el botón de guardar fuera de la vista. */
.tp-results {
  flex: 1 1 auto;
  min-height: 0;
  max-height: 20rem;
  overflow-y: auto;
  list-style: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--border-med);
  border-radius: var(--radius-sm);
  background: var(--bg);
}
.tp-results button {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 0.5rem;
  width: 100%;
  min-width: 0;
  padding: 0.4rem 0.55rem;
  background: none;
  border: none;
  text-align: left;
  cursor: pointer;
  font-family: inherit;
  color: var(--text);
}
.tp-results button:hover {
  background: var(--accent-dim);
}
.tp-results button:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: -2px;
}
/* El `min-width: 0` es lo que permite que el ellipsis funcione dentro de flex:
   sin él un hijo no baja de su ancho de contenido y el nombre desborda. */
.tp-name {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--fs-md);
}
.tp-cpe {
  flex: 0 0 auto;
  font-family: var(--font-mono);
  font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-xs);
  color: var(--text-muted);
}

.tp-chosen {
  flex: 0 1 auto;
  min-height: 0;
  max-height: 7.5rem;
  overflow-y: auto;
  padding-top: 0.6rem;
  border-top: 1px dashed var(--border-med);
}
.tp-chosen--muted {
  opacity: 0.6;
}
.tp-chosen-title {
  margin: 0 0 0.4rem;
  font-size: var(--fs-caption);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
}
.tp-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
}
.tp-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.15rem 0.4rem;
  font-size: var(--fs-md);
  font-weight: 600;
  background: var(--accent);
  color: var(--on-accent);
  border-radius: 4px;
}
.tp-chip-remove {
  background: none;
  border: none;
  color: inherit;
  cursor: pointer;
  font-size: var(--fs-xl);
  padding: 0;
  line-height: 1;
  opacity: 0.7;
}
.tp-chip-remove:hover {
  opacity: 1;
}

.tp-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  flex: 0 0 auto;
  padding: 0.75rem 1.1rem;
  border-top: 1px solid var(--border);
}
.tp-save-note {
  margin: 0;
  font-size: var(--fs-sm);
  color: var(--text-muted);
}
.tp-done {
  flex: 0 0 auto;
  padding: 0.45rem 0.9rem;
  border-radius: 6px;
  border: 1px solid var(--accent);
  background: var(--accent);
  color: var(--on-accent);
  font-family: inherit;
  font-size: var(--fs-md);
  font-weight: 600;
  cursor: pointer;
}
.tp-done:hover {
  background: var(--accent-bright);
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.2s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

@media (max-width: 560px) {
  .tp-footer {
    flex-direction: column;
    align-items: stretch;
  }
  .tp-done {
    width: 100%;
  }
}
</style>
