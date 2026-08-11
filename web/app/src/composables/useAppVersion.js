import { ref } from 'vue'

/**
 * Versión de la API, pedida una sola vez por carga de página.
 *
 * La portada la enseña en la placa y el pie la enseña en su barra inferior, y
 * ambos viven en la misma página: cada uno hacía su propio
 * `fetch('/system/say-hello')`, así que la portada gastaba dos peticiones para
 * pintar el mismo número dos veces. El endpoint está limitado a 60 por minuto
 * y lo comparte con el resto de llamadas a `/system`.
 *
 * El estado es de módulo, no de una store: la versión no cambia mientras la
 * pestaña esté abierta, no depende de la sesión y nadie la modifica. Mismo
 * patrón que `rateLimitState.js`.
 *
 * `fetch` crudo y no `apiFetch` a propósito: el endpoint es público y la
 * portada la ve gente sin sesión, donde `apiFetch` cerraría sesión al no
 * encontrar token.
 */

/** La versión, compartida por todos los que llamen. `—` hasta que llegue. */
const version = ref('—')

/** La petición en vuelo, para que dos componentes a la vez no lancen dos. */
let inFlight = null

export function useAppVersion() {
  // Ya resuelta o ya en camino: no se vuelve a pedir.
  if (version.value === '—' && !inFlight) {
    inFlight = fetch('/system/say-hello')
      .then(r => r.json())
      .then(d => { if (d.version) version.value = d.version })
      .catch(() => { /* la vista enseña el guion */ })
  }
  return { version }
}
