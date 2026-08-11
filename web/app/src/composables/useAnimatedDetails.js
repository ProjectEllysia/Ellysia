/**
 * Directiva `v-animate-details`: anima la apertura y el cierre de un
 * `<details>` con la Web Animations API, sin tocar su semántica nativa —
 * teclado, lector de pantalla y el buscador del navegador (Ctrl+F) siguen
 * funcionando exactamente igual que sin ella.
 *
 * CSS solo no llega aquí todavía: ningún motor anima hoy de forma fiable la
 * altura de un `<details>` nativo entre abierto y cerrado (Chrome lo permite
 * en combinación con `@starting-style`, pero Firefox y Safari estable no). Las
 * alternativas sin JS eran no animar, o duplicar el contenido en un `<div>`
 * aparte y perder el elemento nativo — las dos peores que una directiva de
 * unas pocas líneas.
 *
 * Respeta `prefers-reduced-motion`: si está activo, no se engancha nada y el
 * `<details>` abre y cierra de forma instantánea, tal cual haría sin esto.
 */
export const vAnimateDetails = {
  mounted(details) {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return

    const summary = details.querySelector(':scope > summary')
    if (!summary) return

    let animation = null
    let isClosing = false
    let isExpanding = false

    /** El alto natural con todo desplegado: la cabecera más cada hijo que no
     *  sea ella. Genérico a propósito, para no atarse a una clase de
     *  contenido concreta y poder reusar la directiva en cualquier acordeón. */
    function expandedHeight() {
      let total = summary.offsetHeight
      for (const child of details.children) {
        if (child !== summary) total += child.offsetHeight
      }
      return total
    }

    function run(startHeight, endHeight, endsOpen) {
      if (animation) animation.cancel()
      animation = details.animate(
        { height: [`${startHeight}px`, `${endHeight}px`] },
        { duration: 260, easing: 'ease-out' },
      )
      // `.finished` (promesa) y no `onfinish` (evento): el evento se despacha
      // dentro del ciclo de "actualizar animaciones y enviar eventos" del
      // navegador, que corre pegado al renderizado — en una pestaña que no
      // pinta fotogramas, no llega nunca. La promesa es una microtarea de JS
      // normal y se resuelve sin depender de que se pinte nada.
      animation.finished.then(() => {
        details.open = endsOpen
        details.style.height = ''
        animation = null
        isClosing = false
        isExpanding = false
      }).catch(() => {
        // Cancelada por un clic nuevo antes de terminar (`.cancel()` rechaza
        // `.finished`): el ciclo que la reemplaza ya se encarga de limpiar.
        isClosing = false
        isExpanding = false
      })
    }

    function collapse() {
      isClosing = true
      run(details.offsetHeight, summary.offsetHeight, false)
    }

    function expand() {
      // Nada de requestAnimationFrame: no hace falta esperar a un fotograma
      // pintado, porque leer `offsetHeight` ya obliga al navegador a recalcular
      // el layout de forma síncrona. Con `open` puesto, `expandedHeight()` mide
      // el alto real de los hijos aunque el `<details>` siga con la altura
      // vieja forzada — la altura explícita del padre no afecta a lo que mide
      // cada hijo por su cuenta.
      details.style.height = `${details.offsetHeight}px`
      details.open = true
      isExpanding = true
      run(details.offsetHeight, expandedHeight(), true)
    }

    summary.addEventListener('click', (event) => {
      event.preventDefault()
      if (isClosing || !details.open) expand()
      else if (isExpanding || details.open) collapse()
    })
  },
}
