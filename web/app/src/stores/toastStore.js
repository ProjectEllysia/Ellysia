import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * Store de notificaciones toast — mensajes temporales no bloqueantes.
 *
 * Sustituye a `SeqToast` del legacy (shared.js).
 * Se consume desde AppToast.vue (que renderiza el toast) y desde cualquier
 * lugar donde se necesite mostrar un mensaje:
 *
 * @example
 * import { useToastStore } from '@/stores/toastStore'
 * const toast = useToastStore()
 * toast.show('Escaneo completado', 'success')
 * toast.show('Error de conexión', 'error', 5000)
 */
export const useToastStore = defineStore('toast', () => {
  /** @type {import('vue').Ref<string>} Texto del mensaje */
  const message = ref('')
  /**
   * Tipo o variante visual.
   * @type {import('vue').Ref<'success'|'error'|'warn'|'info'|''>}
   */
  const type = ref('')
  /** @type {import('vue').Ref<boolean>} True mientras el toast sea visible */
  const visible = ref(false)
  /** @type {import('vue').Ref<{label: string, to: string}|null>} Acción opcional */
  const action = ref(null)

  /** @type {number|null} Referencia al timeout de auto-ocultación */
  let timer = null

  /**
   * Muestra un toast con el mensaje y tipo especificados.
   * Si ya hay otro toast visible, lo reemplaza (resetea el temporizador).
   *
   * @param {string} msg - Texto a mostrar
   * @param {'success'|'error'|'warn'|'info'|''} [type='success'] - Variante visual
   * @param {number} [duration=7000] - Milisegundos antes de ocultarse
   * @param {{label: string, to: string}|null} [nextAction=null] - Acción interna opcional
   */
  function show(msg, variant = 'success', duration = 7000, nextAction = null) {
    clearTimeout(timer)
    message.value = msg
    type.value = variant || ''
    action.value = nextAction
    // Si ya hay un toast mostrándose se actualiza en el sitio, sin reanimar:
    // `visible` no cambia, así que Vue no recrea el elemento. Cuando no lo
    // hay, el `v-if` del componente crea el <div> de cero y la animación de
    // entrada corre sola — no hace falta ninguna clave que la fuerce.
    visible.value = true
    timer = setTimeout(dismiss, duration)
  }

  /** Oculta el toast inmediatamente y cancela su cierre automático. */
  function dismiss() {
    clearTimeout(timer)
    timer = null
    visible.value = false
  }

  return { message, type, visible, action, show, dismiss }
})
