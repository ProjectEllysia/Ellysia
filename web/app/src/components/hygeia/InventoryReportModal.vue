<template>
  <Teleport to="body">
    <Transition name="modal">
      <!-- `data-module` en el overlay, no en la página: Teleport saca este nodo
           de la raíz de la vista y sin esto heredaría el acento dorado. -->
      <div v-if="show" class="modal-overlay" data-module="hygeia" @click.self="$emit('close')">
        <div class="modal-box">
          <div class="modal-header">
            <h3>Inventario en PDF</h3>
            <button class="close-btn" @click="$emit('close')">&times;</button>
          </div>

          <form class="modal-body" @submit.prevent="submit">
            <fieldset class="scope">
              <legend class="field-label">Qué incluir</legend>

              <label class="option">
                <input v-model="scope" type="radio" value="user" />
                <span class="option-text">
                  Mis activos
                  <small>Los {{ assetCount }} activos dados de alta con tu cuenta.</small>
                </span>
              </label>

              <label class="option" :class="{ 'option--off': !canUseOrganization }">
                <input v-model="scope" type="radio" value="organization" :disabled="!canUseOrganization" />
                <span class="option-text">
                  Toda la organización
                  <small>{{ organizationHint }}</small>
                </span>
              </label>
            </fieldset>

            <label class="check">
              <input v-model="includeSoftware" type="checkbox" />
              <span class="check-text">
                Incluir el software instalado
                <small>Añade un anexo con las aplicaciones de cada activo. Alarga bastante el documento.</small>
              </span>
            </label>

            <p v-if="error" class="error">{{ error }}</p>

            <div class="modal-footer">
              <button type="button" class="btn-secondary" @click="$emit('close')">Cancelar</button>
              <button type="submit" class="btn-primary" :disabled="generating">
                {{ generating ? 'Generando…' : 'Descargar PDF' }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  /** Cuántos activos propios hay, solo para que la opción diga algo concreto. */
  assetCount: { type: Number, default: 0 },
  /** La organización del usuario, o null. Viene de `accountStore.organization`. */
  organization: { type: Object, default: null },
  generating: { type: Boolean, default: false },
  error: { type: String, default: '' },
})
const emit = defineEmits(['submit', 'close'])

const scope = ref('user')
const includeSoftware = ref(false)

/**
 * El ámbito de organización es solo del dueño.
 *
 * Hoy no hay rol intermedio entre `owner` y `member`, y el informe lista los
 * hostnames y el software de todos los compañeros: el backend lo rechaza con
 * un 403, y aquí se refleja en vez de dejar pulsar para fallar después.
 */
const canUseOrganization = computed(() => props.organization?.isOwner === true)

/** Se deshabilita con explicación, no se oculta: una opción que desaparece
 *  parece que no existe; una deshabilitada que dice por qué, enseña. */
const organizationHint = computed(() => {
  if (!props.organization) return 'No perteneces a ninguna organización.'
  if (!canUseOrganization.value) {
    return `Solo el dueño de «${props.organization.name}» puede sacar este informe.`
  }
  const count = props.organization.memberCount ?? 0
  return `Los activos de los ${count} miembros de «${props.organization.name}».`
})

watch(() => props.show, (visible) => {
  if (!visible) return
  scope.value = 'user'
  includeSoftware.value = false
})

function submit() {
  emit('submit', { scope: scope.value, includeSoftware: includeSoftware.value })
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; width: 100%; max-width: 440px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: var(--fs-xl); color: var(--text); }
.close-btn { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); cursor: pointer; }
.modal-body { padding: 1rem 1.1rem; }

.field-label { font-size: var(--fs-sm); color: var(--text-muted); padding: 0; }
.scope { border: none; margin: 0 0 0.9rem; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }

.option { display: flex; align-items: flex-start; gap: 0.5rem; cursor: pointer; }
.option input { margin-top: 0.2rem; accent-color: var(--accent); }
.option--off { cursor: not-allowed; opacity: 0.55; }
.option-text { display: flex; flex-direction: column; gap: 0.1rem; font-size: var(--fs-md); color: var(--text); }
.option-text small { font-size: var(--fs-sm); color: var(--text-muted); }

.check { display: flex; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.85rem; cursor: pointer; }
.check input { margin-top: 0.15rem; accent-color: var(--accent); }
.check-text { display: flex; flex-direction: column; gap: 0.15rem; font-size: var(--fs-md); color: var(--text); }
.check-text small { font-size: var(--fs-sm); color: var(--text-muted); }

.error { color: var(--danger); font-size: var(--fs-sm); margin: 0 0 0.6rem; }

.modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 0.4rem; }
.btn-secondary, .btn-primary { padding: 0.45rem 0.9rem; border-radius: 6px; font-size: var(--fs-md); font-weight: 600; cursor: pointer; }
.btn-secondary { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }
.btn-primary { background: var(--accent); border: 1px solid var(--accent); color: var(--on-accent); }
.btn-primary:hover:not(:disabled) { background: var(--accent-bright); }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
