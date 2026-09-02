/**
 * Qué ventana de escaneos hay que pedirle al backend.
 *
 * Vive fuera de `themisStore` porque es la parte del arreglo que se puede
 * probar sola: el store arrastra Pinia, Vue y media docena de composables, y lo
 * que aquí falló es una cuenta de dos líneas.
 *
 * **El fallo que arregla.** La lista de escaneos de Lybra crece con un botón
 * "ver más" que añade la siguiente página al final; el refresco (manual, y el
 * sondeo automático que se rearma solo mientras haya un escaneo corriendo)
 * reemplaza la lista con una sola página. Las dos cosas leían el mismo campo
 * `page`, y le daban significados incompatibles: para "ver más" era *la última
 * página traída*, para el refresco *la única página a mostrar*. Con una sola
 * página coinciden y no se nota nada; en cuanto se pulsa "ver más" divergen.
 * El usuario tenía 30 escaneos en pantalla, saltaba el sondeo, y se quedaba con
 * 10 — los más antiguos de los tres bloques, porque se pedía la página 3.
 *
 * **La solución.** El estado guarda cuántas páginas se han revelado, y la
 * petición pide siempre desde la primera con una ventana del tamaño acumulado.
 * Tres ventajas sobre reconstruir la lista pidiendo N páginas seguidas:
 *
 *   - un refresco es *una* petición, no una por página revelada;
 *   - al pedir siempre desde el principio, un escaneo nuevo entra por arriba
 *     sin descolocar la ventana, así que desaparece de paso el duplicado que
 *     produce la paginación por desplazamiento cuando la colección crece por
 *     el mismo extremo que se está paginando;
 *   - con una sola página revelada la petición es idéntica a la de antes, así
 *     que los tipos que usan paginación clásica (`nmap`, `nikto`, `nuclei`,
 *     vía `goToPage`) no cambian de comportamiento.
 */

/**
 * Tope de `per_page` del endpoint. Lo impone el backend
 * (`ResultsQuerySchema`: `validate.Range(min=1, max=100)`), así que pedir más
 * no sería una ventana más grande sino un 422.
 */
export const MAX_PER_PAGE = 100

/**
 * Traduce el estado de una lista a los parámetros de la petición.
 *
 * @param {{page?: number, perPage?: number, loadedPages?: number}} state
 *        El estado por tipo de escaneo (`scans.lybra`, `scans.nmap`, …).
 * @returns {{page: number, perPage: number}} Lo que va en la query.
 */
export function scanWindow(state) {
  // Un valor ausente y uno absurdo (0, negativo, NaN) se tratan igual: se cae
  // al defecto en vez de propagar una query que el backend rechazaría.
  const page = state?.page > 0 ? state.page : 1
  const perPage = state?.perPage > 0 ? state.perPage : 10
  const loadedPages = state?.loadedPages > 0 ? state.loadedPages : 1
  return { page, perPage: Math.min(perPage * loadedPages, MAX_PER_PAGE) }
}

/**
 * Si queda algo por revelar con "ver más".
 *
 * Además del clásico "ya están todos", corta al llegar al tope de `per_page`:
 * revelar otra página pediría una ventana que el backend rechaza, y el botón
 * dejaría de funcionar en vez de dejar de estar.
 *
 * @param {{results?: Array, totalCount?: number, perPage?: number, loadedPages?: number}} state
 * @returns {boolean}
 */
export function canRevealMore(state) {
  const loaded = state?.results?.length ?? 0
  if (loaded >= (state?.totalCount ?? 0)) return false
  return scanWindow(state).perPage < MAX_PER_PAGE
}
