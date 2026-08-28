import { nextTick, onBeforeUnmount, watch } from 'vue'

/**
 * Comportamiento de teclado y foco compartido por los modales: Escape cierra,
 * Tab queda atrapado dentro de la caja, se bloquea el scroll del fondo
 * mientras está abierto (con limpieza en onBeforeUnmount — si no, un
 * desmontaje con el modal abierto deja el body bloqueado) y el foco vuelve al
 * disparador al cerrar.
 *
 * El listener de Escape/Tab va en `window`, no como `@keydown.esc` sobre el
 * div del overlay: sobre un div solo dispara si el foco ya está dentro, que
 * es el fallo que arrastraban CampaignModal y DistributionListsModal.
 *
 * `isVisible` es un getter — reactivo para los modales que se quedan
 * montados y alternan una prop `show` (p. ej. `() => props.show` en
 * IrisArchiveModal), o `() => true` para los que el padre monta y desmonta
 * con `v-if` (p. ej. CampaignModal) — ahí el `immediate: true` hace de
 * "onMounted".
 */
export function useModalA11y(isVisible, { boxRef, autofocusRef, onClose, onKeydown } = {}) {
  let previouslyFocused = null

  function trapFocus(e) {
    const root = boxRef?.value
    if (!root) return
    const focusables = Array.from(
      root.querySelectorAll(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])',
      ),
    )
    if (!focusables.length) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Escape') {
      onClose?.()
      return
    }
    if (e.key === 'Tab') trapFocus(e)
    onKeydown?.(e)
  }

  function cleanup() {
    document.body.style.overflow = ''
    window.removeEventListener('keydown', handleKeydown)
    previouslyFocused?.focus?.()
    previouslyFocused = null
  }

  watch(
    isVisible,
    (visible) => {
      if (visible) {
        previouslyFocused = document.activeElement
        document.body.style.overflow = 'hidden'
        window.addEventListener('keydown', handleKeydown)
        nextTick(() => (autofocusRef?.value ?? boxRef?.value)?.focus())
      } else {
        cleanup()
      }
    },
    { immediate: true },
  )

  onBeforeUnmount(cleanup)
}
