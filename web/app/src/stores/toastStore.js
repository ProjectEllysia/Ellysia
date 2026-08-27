import { defineStore } from 'pinia'
import { readonly, ref } from 'vue'

/** Milisegundos que dura un toast si no se pide otra cosa. */
const DEFAULT_DURATION_MS = 7000

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
 * toast.show('Revisa esto antes de seguir', 'warn', 0)  // no se cierra solo
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

  /** @type {number|null} Timeout de auto-ocultación; `null` si no hay cuenta atrás. */
  let timer = null
  /** Milisegundos que le quedaban al toast la última vez que se armó el timeout. */
  let remainingMs = 0
  /** `Date.now()` de ese último armado, para saber cuánto se ha consumido. */
  let startedAt = 0

  /**
   * Arranca la cuenta atrás de cierre. Se mide contra el reloj de pared en vez
   * de fiarse del timeout, porque `pause()` puede pararla a mitad y hay que
   * saber exactamente cuánto quedaba.
   *
   * @param {number} durationMs - `<= 0` (o no numérico) deja el toast fijo.
   */
  function armTimer(durationMs) {
    clearTimeout(timer)
    timer = null
    remainingMs = durationMs
    // Un toast persistente es una petición legítima (un aviso que el usuario
    // debe cerrar a mano). Antes `duration = 0` se traducía en
    // `setTimeout(dismiss, 0)`, o sea desaparecía en el mismo frame.
    if (!(durationMs > 0)) return
    startedAt = Date.now()
    timer = setTimeout(dismiss, durationMs)
  }

  /**
   * Muestra un toast con el mensaje y tipo especificados.
   * Si ya hay otro toast visible, lo reemplaza (resetea el temporizador).
   *
   * @param {string} msg - Texto a mostrar
   * @param {'success'|'error'|'warn'|'info'|''} [variant='success'] - Variante visual
   * @param {number} [duration=7000] - Milisegundos antes de ocultarse; `<= 0` lo deja fijo
   * @param {{label: string, to: string}|null} [nextAction=null] - Acción interna opcional
   */
  function show(msg, variant = 'success', duration = DEFAULT_DURATION_MS, nextAction = null) {
    message.value = msg
    type.value = variant || ''
    action.value = nextAction
    // Si ya hay un toast mostrándose se actualiza en el sitio, sin reanimar:
    // `visible` no cambia, así que Vue no recrea el elemento. Cuando no lo
    // hay, el `v-if` del componente crea el <div> de cero y la animación de
    // entrada corre sola — no hace falta ninguna clave que la fuerce.
    visible.value = true
    armTimer(duration)
  }

  /**
   * Congela la cuenta atrás guardando lo que quedaba. Se llama al pasar el
   * ratón o el foco por encima: el toast puede traer un error de validación
   * largo (con scroll propio, ver `max-height` en AppToast.vue) y cerrarlo a
   * los 7 s mientras se lee lo deja irrecuperable.
   */
  function pause() {
    // Sin timeout no hay nada que congelar: o ya está pausado, o es persistente.
    if (!timer) return
    clearTimeout(timer)
    timer = null
    const pending = remainingMs - (Date.now() - startedAt)
    // Si el navegador estranguló el timeout y el tiempo ya se había agotado, se
    // cierra en vez de guardar un cero: `remainingMs === 0` significa "toast
    // persistente", y confundir ambos casos dejaría el toast fijo para siempre.
    if (pending <= 0) { dismiss(); return }
    remainingMs = pending
  }

  /** Reanuda la cuenta atrás con el tiempo que quedaba al pausar. */
  function resume() {
    // Sin toast, con cuenta atrás ya corriendo, o persistente (`remainingMs`
    // en 0): no hay nada que reanudar.
    if (timer || !visible.value || remainingMs <= 0) return
    armTimer(remainingMs)
  }

  /** Oculta el toast inmediatamente y cancela su cierre automático. */
  function dismiss() {
    clearTimeout(timer)
    timer = null
    remainingMs = 0
    visible.value = false
  }

  // Solo lectura hacia fuera: el estado se cambia por `show`/`dismiss`, que son
  // quienes mantienen el timeout en sincronía. Un `toast.visible = false` suelto
  // dejaba un `setTimeout` huérfano que cerraba el toast siguiente antes de tiempo.
  return {
    message: readonly(message),
    type: readonly(type),
    visible: readonly(visible),
    action: readonly(action),
    show,
    pause,
    resume,
    dismiss,
  }
})
