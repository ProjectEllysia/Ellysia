import { onMounted, onUnmounted } from 'vue'

/**
 * Cierra un desplegable al pulsar fuera o al pulsar Escape.
 *
 * Un menú que solo se cierra volviendo a pulsar su botón es una trampa: quien
 * lo abre sin querer no tiene forma evidente de salir, y con teclado no hay
 * ninguna. Los menús de exportar de Aegis (`DocumentViewer`, `HistoryPanel`) no
 * tenían ni una cosa ni la otra; `LandingView` sí resolvía el clic fuera, pero
 * a mano y solo para sus desplegables de navegación.
 *
 * Escucha en fase de captura para que el cierre ocurra aunque algo por el
 * camino detenga la propagación, y comprueba el `selector` del contenedor en
 * vez de guardar referencias: así vale para varios menús hermanos con el mismo
 * marcado, que es justo el caso de la lista del historial.
 *
 * @param {string} selector - Selector del contenedor que NO debe cerrar al pulsarlo.
 * @param {() => void} close - Qué hacer para cerrar.
 *
 * @example
 * const exportOpen = ref(null)
 * useDismissable('.item-actions', () => { exportOpen.value = null })
 */
export function useDismissable(selector, close) {
  function onPointerDown(event) {
    if (!event.target.closest?.(selector)) close()
  }

  function onKeydown(event) {
    if (event.key === 'Escape') close()
  }

  onMounted(() => {
    document.addEventListener('pointerdown', onPointerDown, true)
    document.addEventListener('keydown', onKeydown, true)
  })

  onUnmounted(() => {
    document.removeEventListener('pointerdown', onPointerDown, true)
    document.removeEventListener('keydown', onKeydown, true)
  })
}
