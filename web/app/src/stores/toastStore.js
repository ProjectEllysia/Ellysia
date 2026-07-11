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

  /** @type {number|null} Referencia al timeout de auto-ocultación */
  let timer = null

  /**
   * Muestra un toast con el mensaje y tipo especificados.
   * Si ya hay otro toast visible, lo reemplaza (resetea el temporizador).
   *
   * @param {string} msg - Texto a mostrar
   * @param {'success'|'error'|'warn'|'info'|''} [type='success'] - Variante visual
   * @param {number} [duration=3400] - Milisegundos antes de ocultarse
   */
  function show(msg, variant = 'success', duration = 3400) {
    clearTimeout(timer)
    message.value = msg
    type.value = variant || ''
    visible.value = true
    timer = setTimeout(() => { visible.value = false }, duration)
  }

  return { message, type, visible, show }
})
