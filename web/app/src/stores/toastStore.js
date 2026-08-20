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
  /** Clave para animar también el reemplazo de un toast visible. */
  const id = ref(0)

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
    id.value += 1
    visible.value = true
    timer = setTimeout(dismiss, duration)
  }

  /** Oculta el toast inmediatamente y cancela su cierre automático. */
  function dismiss() {
    clearTimeout(timer)
    timer = null
    visible.value = false
  }

  return { message, type, visible, action, id, show, dismiss }
})
