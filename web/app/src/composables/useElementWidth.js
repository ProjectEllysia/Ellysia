/**
 * Ancho reactivo de un elemento, atado al `ref` de plantilla y no al elemento.
 *
 * La diferencia importa porque un `ref` de plantilla que vive bajo un `v-if`
 * no apunta a nada mientras esa condición sea falsa. Leerlo una sola vez en
 * `onMounted` —que es como estaba escrito en MetricsChart— tiene dos fallos:
 *
 *   - si el componente monta con la condición en falso, se le pasa `null` a
 *     `ResizeObserver.observe()`, que exige un `Element` y lanza `TypeError`;
 *   - si el elemento se destruye y se vuelve a crear, el observador se queda
 *     mirando el nodo viejo, ya fuera del documento, y el ancho se congela.
 *
 * Vigilando el `ref` los dos casos se caen solos: mientras no haya elemento no
 * se observa nada, y cuando aparece uno nuevo se suelta el anterior.
 */
import { getCurrentInstance, onUnmounted, ref, watch } from 'vue'

/**
 * @param {import('vue').Ref<Element|null>} elementRef  ref de plantilla a vigilar
 * @param {number} fallbackWidth  ancho mientras no haya elemento que medir
 * @returns {import('vue').Ref<number>}  ancho en píxeles, reactivo
 */
export function useElementWidth(elementRef, fallbackWidth = 0) {
  const width = ref(fallbackWidth)
  let resizeObserver = null

  const disconnect = () => {
    resizeObserver?.disconnect()
    resizeObserver = null
  }

  // `flush: 'post'` para que el watcher corra con el DOM ya parcheado: al
  // montar, el ref todavía no está asignado en la fase previa.
  watch(
    elementRef,
    (element) => {
      disconnect()
      if (!element) {
        width.value = fallbackWidth
        return
      }
      width.value = element.clientWidth || fallbackWidth
      // Sin ResizeObserver (entornos sin DOM, navegadores antiguos) el ancho
      // medido sigue siendo correcto; sencillamente deja de actualizarse.
      if (typeof ResizeObserver === 'undefined') return
      resizeObserver = new ResizeObserver(() => {
        width.value = elementRef.value?.clientWidth || 0
      })
      resizeObserver.observe(element)
    },
    { immediate: true, flush: 'post' },
  )

  // Igual que `usePolling`: la guarda permite usar el composable fuera de un
  // componente, que es lo que hace testeable el módulo en Node puro.
  if (getCurrentInstance()) onUnmounted(disconnect)

  return width
}
