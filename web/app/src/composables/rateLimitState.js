/**
 * Tregua pedida por el servidor tras un 429, compartida por toda la aplicación.
 *
 * Vive en un módulo propio, sin dependencias, por dos motivos:
 *
 * 1. **Ciclo de imports.** Lo escribe `useApi` (que lee el `Retry-After`) y lo
 *    lee `usePolling` (que espacia el siguiente ciclo). Si `usePolling`
 *    importara `useApi` para consultarlo, arrastraría con él la store de
 *    autenticación y Pinia entero.
 * 2. **Los tests de `usePolling` son Node puro**, sin Vite: cualquier import
 *    con alias `@` o que toque Vue rompe `npm run test:polling`.
 *
 * Es estado de módulo a propósito, no de una store: el cupo lo impone el
 * servidor sobre toda la pestaña, así que si un sondeo lo agota, el resto de la
 * interfaz tampoco debe seguir empujando.
 */

let limitedUntil = 0

/** Registra que el servidor no aceptará peticiones durante `seconds` segundos. */
export function setRateLimited(seconds) {
  limitedUntil = Date.now() + Math.max(0, seconds) * 1000
}

/** Milisegundos que faltan para que el servidor vuelva a aceptar peticiones. */
export function rateLimitWaitMs() {
  return Math.max(0, limitedUntil - Date.now())
}

/** Olvida la tregua. Solo para los tests. */
export function clearRateLimit() {
  limitedUntil = 0
}
