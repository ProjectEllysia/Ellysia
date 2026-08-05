import { getCurrentInstance, onUnmounted } from 'vue'

/**
 * Sondeo periódico correcto, en un solo sitio (E8).
 *
 * El SPA tenía seis sondeos escritos a mano con dos idiomas incompatibles:
 * `setInterval` y `setTimeout` re-encadenado. El propio código documentaba
 * por qué el primero está mal (irisStore, B10): con un callback `async`, si
 * la petición tarda más que el intervalo, `setInterval` dispara la siguiente
 * antes de que la anterior termine y se solapan. Aun así quedaban dos
 * `setInterval` vivos, uno de ellos en el mismo fichero que lo explicaba.
 *
 * Este composable fija la forma correcta:
 *   - **Re-encadenado**: el siguiente ciclo se programa cuando el actual
 *     termina, así que nunca hay dos peticiones solapadas.
 *   - **Cancelable de verdad**: un `generation` token invalida los ciclos en
 *     vuelo, de modo que un `stop()` durante un `await` no deja un timer
 *     zombi reprogramándose después.
 *   - **Pausa con la pestaña oculta**: no gasta peticiones en segundo plano,
 *     y al volver a primer plano sondea de inmediato en vez de esperar al
 *     siguiente intervalo.
 *   - **Limpieza automática** cuando se usa dentro de un componente. En una
 *     store de Pinia no hay ciclo de vida al que engancharse, así que ahí el
 *     registro se omite y la store llama a `stop()` ella misma.
 *
 * @param {(attempt: number) => Promise<boolean|void>} task - Trabajo de cada
 *   ciclo. Devolver `false` detiene el sondeo (condición terminal
 *   alcanzada); cualquier otra cosa lo mantiene vivo.
 * @param {object} [options]
 * @param {number} [options.intervalMs=2000] - Espera entre ciclos.
 * @param {number|null} [options.maxAttempts=null] - Tope de ciclos; `null`
 *   para sondear hasta que `task` devuelva `false` o se llame a `stop()`.
 * @param {boolean} [options.pauseWhenHidden=true] - Saltar ciclos mientras
 *   `document.hidden`.
 * @param {boolean} [options.immediate=true] - Ejecutar el primer ciclo al
 *   llamar a `start()` en vez de esperar un intervalo.
 * @returns {{start: Function, stop: Function, isRunning: Function}}
 */
export function usePolling(task, {
  intervalMs = 2000,
  maxAttempts = null,
  pauseWhenHidden = true,
  immediate = true,
} = {}) {
  let timer = null
  let generation = 0
  let attempts = 0
  let running = false

  const isHidden = () =>
    pauseWhenHidden && typeof document !== 'undefined' && document.hidden

  function clearTimer() {
    if (timer) { clearTimeout(timer); timer = null }
  }

  function schedule(gen) {
    clearTimer()
    timer = setTimeout(() => { void tick(gen) }, intervalMs)
  }

  async function tick(gen) {
    // El generation token cubre la ventana del `await` de abajo: si stop()
    // corre mientras la petición está en vuelo, este ciclo debe morir sin
    // reprogramarse.
    if (!running || gen !== generation) return

    if (isHidden()) { schedule(gen); return }

    let keepGoing = true
    try {
      keepGoing = await task(attempts)
    } catch {
      // Un fallo puntual (red caída, 500 transitorio) no cancela el sondeo:
      // el siguiente ciclo lo reintenta. Quien quiera abortar ante un error
      // devuelve `false` desde `task`.
      keepGoing = true
    }
    if (!running || gen !== generation) return

    attempts += 1
    if (keepGoing === false || (maxAttempts !== null && attempts >= maxAttempts)) {
      stop()
      return
    }
    schedule(gen)
  }

  function onVisibilityChange() {
    // Al volver a primer plano, sondear ya en vez de esperar al intervalo.
    if (running && !isHidden()) {
      clearTimer()
      void tick(generation)
    }
  }

  function start() {
    if (running) return
    running = true
    attempts = 0
    generation += 1
    const gen = generation
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisibilityChange)
    }
    if (immediate) void tick(gen)
    else schedule(gen)
  }

  function stop() {
    running = false
    generation += 1   // invalida cualquier ciclo en vuelo
    clearTimer()
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }

  // Solo dentro de un componente: en una store de Pinia no hay instancia
  // activa y registrar el hook aquí no engancharía a nada.
  if (getCurrentInstance()) onUnmounted(stop)

  return { start, stop, isRunning: () => running }
}
