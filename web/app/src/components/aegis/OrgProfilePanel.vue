<template>
  <div class="org-profile-panel">
    <button type="button" class="op-header" @click="expanded = !expanded">
      <h2>Perfil de la organización</h2>
      <span
        class="op-chevron"
        :class="{ 'op-chevron--open': expanded }"
        aria-hidden="true"
        >▸</span
      >
    </button>

    <p v-if="!expanded" class="op-summary">
      {{ store.tweaks.company || "Sin configurar todavía" }} ·
      {{ productsSummary }}
    </p>

    <div class="op-collapse" :class="{ expanded }">
      <div class="op-collapse-inner">
        <div class="op-body">
          <div class="form-group">
            <label for="op-company">Empresa</label>
            <input
              id="op-company"
              v-model="store.tweaks.company"
              type="text"
              maxlength="60"
              class="input"
              placeholder="Nombre de la empresa"
            />
          </div>

          <div class="form-group">
            <label for="op-contact">Email de contacto</label>
            <input
              id="op-contact"
              v-model="store.tweaks.mentionContact"
              type="email"
              maxlength="100"
              class="input"
              placeholder="contacto@empresa.com"
            />
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="op-lang">Idioma</label>
              <select
                id="op-lang"
                v-model="store.tweaks.language"
                class="input select"
              >
                <option value="es">Español</option>
                <option value="en">English</option>
                <option value="fr">Français</option>
                <option value="de">Deutsch</option>
              </select>
            </div>
            <div class="form-group">
              <label for="op-tone">Tono</label>
              <select
                id="op-tone"
                v-model="store.tweaks.tone"
                class="input select"
              >
                <option value="profesional">Profesional</option>
                <option value="formal">Formal</option>
                <option value="cercano">Cercano</option>
                <option value="tecnico">Técnico</option>
              </select>
            </div>
          </div>

          <div class="form-group">
            <label for="op-sector">Sector</label>
            <input
              id="op-sector"
              v-model="store.tweaks.sector"
              type="text"
              maxlength="40"
              class="input"
              placeholder="Ej: banca"
            />
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="op-size">Tamaño de empresa</label>
              <select
                id="op-size"
                v-model="store.tweaks.companySize"
                class="input select"
              >
                <option value="">Sin especificar</option>
                <option value="micro">Micro (&lt;10)</option>
                <option value="pequeña">Pequeña (10-50)</option>
                <option value="mediana">Mediana (50-250)</option>
              </select>
            </div>
            <div class="form-group">
              <label for="op-employees">Nº empleados</label>
              <input
                id="op-employees"
                v-model.number="store.tweaks.employeeCount"
                type="number"
                min="1"
                class="input"
                placeholder="Opcional"
              />
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="op-jurisdiction">Jurisdicción</label>
              <input
                id="op-jurisdiction"
                v-model="store.tweaks.jurisdiction"
                type="text"
                maxlength="256"
                class="input"
                placeholder="Ej: España (RGPD)"
              />
            </div>
            <div class="form-group">
              <label for="op-workmodel">Modelo de trabajo</label>
              <select
                id="op-workmodel"
                v-model="store.tweaks.workModel"
                class="input select"
              >
                <option value="">Sin especificar</option>
                <option value="remoto">Remoto</option>
                <option value="híbrido">Híbrido</option>
                <option value="presencial">Presencial</option>
              </select>
            </div>
          </div>

          <!-- El buscador y el interruptor de inventario viven ahora en su
               propio modal: en 400 px de panel no cabían. La lista de
               seleccionados crecía sin tope y empujaba el buscador, y la de
               resultados desplazaba al botón de guardar. -->
          <div class="form-group">
            <label>Productos vigilados</label>
            <button
              type="button"
              class="products-btn"
              @click="productsModalOpen = true"
            >
              <span>Gestionar productos</span>
              <span class="products-count">{{ productsSummary }}</span>
            </button>
          </div>

          <WhiteLabelFields
            v-model="store.whiteLabel"
            :max-level="store.maxWhiteLabelLevel"
          />

          <button
            type="button"
            class="btn-save-profile"
            :disabled="store.savingOrgProfile"
            @click="handleSave"
          >
            <span v-if="store.savingOrgProfile" class="spinner"></span>
            {{
              store.savingOrgProfile
                ? "Guardando…"
                : store.orgProfileConfigured
                  ? "Actualizar perfil"
                  : "Guardar perfil"
            }}
          </button>
        </div>
      </div>
    </div>

    <TrackedProductsModal
      :show="productsModalOpen"
      @close="productsModalOpen = false"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from "vue";
import { useAegisStore } from "@/stores/aegisStore";
import WhiteLabelFields from "@/components/shared/WhiteLabelFields.vue";
import TrackedProductsModal from "./TrackedProductsModal.vue";

const store = useAegisStore();

// Colapsado por defecto si ya hay perfil guardado (nada que revisar cada
// mes); expandido si es la primera vez. Se ajusta tras cargar el perfil.
const expanded = ref(true);

const productsModalOpen = ref(false);

/** Origen efectivo de los productos: los agentes mandan cuando están activos. */
const usingInventory = computed(
  () => store.hygeiaInventoryAvailable && store.useHygeiaInventory,
);

/**
 * Qué se está vigilando, en una línea. Lo usan el resumen del acordeón
 * colapsado y el botón que abre el modal: antes cada uno lo calculaba por su
 * cuenta en el template.
 */
const productsSummary = computed(() => {
  if (usingInventory.value) return "productos de mis agentes";
  const count = store.trackedProducts.length;
  if (!count) return "sin productos";
  return count === 1 ? "1 producto" : `${count} productos`;
});

async function handleSave() {
  const ok = await store.saveOrgProfile();
  if (ok) expanded.value = false;
}

onMounted(async () => {
  await store.loadOrgProfile();
  expanded.value = !store.orgProfileConfigured;
});
</script>

<style scoped>
.org-profile-panel {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
  padding: 1.1rem;
  border-bottom: 1px solid var(--border);
}
.op-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  width: 100%;
  text-align: left;
}
.op-header h2 {
  font-size: var(--fs-xl);
  font-weight: 700;
  color: var(--text);
  margin: 0;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
}
.op-chevron {
  color: var(--text-muted);
  transition: transform 0.2s;
  font-size: var(--fs-2xl);
}
.op-chevron--open {
  transform: rotate(90deg);
}
.op-summary {
  font-size: var(--fs-md);
  color: var(--text-dim);
  margin: 0;
}
/* Colapso suave sin medir alturas a mano: mismo patrón que
   FolderAccordion.vue (grid-template-rows 0fr → 1fr + overflow:hidden en el
   contenedor interno), en vez del v-show original (aparecía/desaparecía de
   golpe). */
.op-collapse {
  display: grid;
  grid-template-rows: 0fr;
  transition: grid-template-rows 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.op-collapse.expanded {
  grid-template-rows: 1fr;
}
.op-collapse-inner {
  overflow: hidden;
  min-height: 0;
}
.op-body {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}
/* Una columna: a este ancho de panel, dos columnas dejaban etiquetas largas
   ("Tamaño de empresa") sin sitio y el input caía a la línea de abajo. */
.form-row {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.form-group label {
  font-size: var(--fs-md);
  font-weight: 600;
  color: var(--text-dim);
}
.input {
  background: var(--bg);
  border: 1px solid var(--border-solid);
  border-radius: 6px;
  padding: 0.4rem 0.55rem;
  color: var(--text);
  font-size: var(--fs-input);
  outline: none;
  width: 100%;
  box-sizing: border-box;
  transition: border-color 0.2s;
  font-family: inherit;
}
.input:focus {
  border-color: var(--accent);
}
.select {
  cursor: pointer;
  appearance: auto;
}
.input[type="number"]::-webkit-inner-spin-button,
.input[type="number"]::-webkit-outer-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.input[type="number"] {
  -moz-appearance: textfield;
}
/* ── Acceso al modal de productos vigilados ── */
.products-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  width: 100%;
  padding: 0.45rem 0.6rem;
  border-radius: 6px;
  border: 1px solid var(--border-solid);
  background: var(--bg);
  color: var(--text);
  font-family: inherit;
  font-size: var(--fs-input);
  cursor: pointer;
  transition: border-color 0.2s;
}
.products-btn:hover {
  border-color: var(--accent);
}
.products-count {
  flex: 0 0 auto;
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--accent-bright);
}
.btn-save-profile {
  margin-top: 0.2rem;
  padding: 0.55rem;
  font-size: var(--fs-md);
  font-weight: 700;
  border-radius: 7px;
  border: 1px solid var(--accent);
  cursor: pointer;
  background: var(--accent-dim);
  color: var(--accent);
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
}
.btn-save-profile:hover:not(:disabled) {
  background: var(--accent);
  color: var(--on-accent);
}
.btn-save-profile:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(0, 0, 0, 0.15);
  border-top-color: currentColor;
  border-radius: 50%;
  animation: seq-spin 0.6s linear infinite;
}

@media (prefers-reduced-motion: reduce) {
  .op-collapse,
  .op-chevron {
    transition: none;
  }
}
</style>
