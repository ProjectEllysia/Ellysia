/**
 * Barajado de las opciones del test público de Aegis.
 *
 * Existe porque el modelo coloca la respuesta correcta en la segunda opción
 * con muchísima más frecuencia que en las demás. El prompt pide variar la
 * posición, pero eso es una petición y no una garantía: quien haya hecho dos
 * campañas aprende el patrón antes que el contenido.
 *
 * Devuelve el orden de PRESENTACIÓN (índices originales reordenados), no las
 * opciones ya movidas de sitio. Esa distinción es la que mantiene sano el
 * envío: la vista pinta `options[i]` pero sigue mandando `i`, que es el índice
 * contra el que corrige el servidor (`Campaign.questions_snapshot`).
 *
 * Barajar en el cliente es seguro aquí porque `correctIndex` nunca sale de la
 * API: `to_public_dict()` lo elimina, así que el orden no delata nada.
 */

/**
 * Permutación uniforme de `[0, 1, ..., count-1]` (Fisher-Yates).
 *
 * Nada de `sort(() => Math.random() - 0.5)`: no reparte por igual y dejaría un
 * sesgo residual, que es justo lo que se viene a quitar.
 *
 * Sin semilla a propósito: `Math.random()` ya da un orden distinto por persona,
 * que es lo que se busca. Sembrar con el token solo añadiría estabilidad entre
 * recargas del mismo destinatario, y el test admite un único envío.
 *
 * @param {number} count Número de opciones de la pregunta.
 * @returns {number[]} Índices originales en el orden en que deben pintarse.
 */
export function shuffledOrder(count) {
  const order = Array.from({ length: Math.max(0, count) }, (_, index) => index)
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[order[i], order[j]] = [order[j], order[i]]
  }
  return order
}
