/**
 * Tests de `useElementWidth` — la medida se ata al ref, no al elemento.
 *
 * Node puro, sin framework ni DOM, misma convencion que el resto de `test/`.
 * Lo que se comprueba es justo lo que rompio la grafica de Hygeia: el ref de
 * plantilla vive bajo un `v-if`, asi que puede valer `null` al montar y puede
 * cambiar de elemento a mitad de vida.
 *
 *   - un ref vacio no llega a `observe()` (era el TypeError del navegador:
 *     `ResizeObserver.observe` exige un Element y `null` no lo es);
 *   - cuando aparece elemento, se observa;
 *   - si el elemento se sustituye, se suelta el viejo y se observa el nuevo;
 *   - sin `ResizeObserver` en el entorno, no se lanza nada.
 */

import assert from 'node:assert/strict'
import { nextTick, ref } from 'vue'

const { useElementWidth } = await import('../src/composables/useElementWidth.js')

/** Elemento falso: al composable solo le interesa `clientWidth`. */
const fakeElement = (clientWidth) => ({ clientWidth })

/**
 * ResizeObserver falso instalado como global. Registra a quien observa y
 * expone el callback para poder simular un redimensionado.
 */
function installResizeObserver() {
  // `attempts` guarda TODO lo que se le pasa a observe(), valido o no. Es lo
  // que hace que el test detecte la regresion: si el composable volviera a
  // observar un `null`, el TypeError lo tragaria el watcher de Vue y
  // `observed` seguiria vacio, o sea, el test pasaria en verde.
  const attempts = []
  const observed = []
  const disconnected = []
  const instances = []
  globalThis.ResizeObserver = class {
    constructor(callback) {
      this.callback = callback
      instances.push(this)
    }
    observe(element) {
      attempts.push(element)
      // La comprobacion que hace el navegador de verdad, y que es la que
      // reventaba en produccion.
      if (!element || typeof element !== 'object') {
        throw new TypeError("parameter 1 is not of type 'Element'")
      }
      observed.push(element)
    }
    disconnect() { disconnected.push(this) }
  }
  return {
    attempts,
    observed,
    disconnected,
    lastInstance: () => instances[instances.length - 1],
  }
}

function uninstallResizeObserver() {
  delete globalThis.ResizeObserver
}

let failures = 0
async function test(name, fn) {
  try { await fn(); console.log(`  ok   ${name}`) }
  catch (err) { failures++; console.error(`  FAIL ${name}\n       ${err.message}`) }
  finally { uninstallResizeObserver() }
}

console.log('useElementWidth')

await test('un ref vacio no se observa y conserva el ancho de respaldo', async () => {
  const spy = installResizeObserver()
  const elementRef = ref(null)
  const width = useElementWidth(elementRef, 600)
  await nextTick()
  assert.equal(spy.attempts.length, 0, 'llamo a observe() con un ref vacio')
  assert.equal(width.value, 600)
})

await test('cuando el ref recibe elemento, se observa y se mide', async () => {
  const spy = installResizeObserver()
  const elementRef = ref(null)
  const width = useElementWidth(elementRef, 600)
  await nextTick()

  const element = fakeElement(480)
  elementRef.value = element
  await nextTick()

  assert.deepEqual(spy.observed, [element], 'no observo el elemento nuevo')
  assert.equal(width.value, 480, 'no midio el elemento al engancharse')
})

await test('un redimensionado actualiza el ancho', async () => {
  const spy = installResizeObserver()
  const element = fakeElement(480)
  const elementRef = ref(element)
  const width = useElementWidth(elementRef, 600)
  await nextTick()

  element.clientWidth = 320
  spy.lastInstance().callback()
  assert.equal(width.value, 320)
})

await test('sustituir el elemento suelta el viejo y observa el nuevo', async () => {
  const spy = installResizeObserver()
  const first = fakeElement(480)
  const elementRef = ref(first)
  const width = useElementWidth(elementRef, 600)
  await nextTick()

  // Lo que pasa cuando la tarjeta se destruye (ventana sin lecturas) y se
  // vuelve a crear: el ref pasa por null y luego apunta a otro nodo.
  elementRef.value = null
  await nextTick()
  assert.equal(spy.disconnected.length, 1, 'no solto el observador del nodo destruido')
  assert.equal(width.value, 600, 'no volvio al ancho de respaldo sin elemento')

  const second = fakeElement(300)
  elementRef.value = second
  await nextTick()
  assert.deepEqual(spy.observed, [first, second], 'no reengancho al nodo nuevo')
  assert.equal(width.value, 300)

  // Y el observador nuevo es el que manda: el viejo ya no debe mover nada.
  second.clientWidth = 260
  spy.lastInstance().callback()
  assert.equal(width.value, 260)
})

await test('sin ResizeObserver en el entorno no lanza y mide una vez', async () => {
  uninstallResizeObserver()
  const elementRef = ref(fakeElement(512))
  const width = useElementWidth(elementRef, 600)
  await nextTick()
  assert.equal(width.value, 512)
})

console.log(failures ? `\n${failures} test(s) fallaron` : '\nTodos los tests de useElementWidth pasaron')
process.exit(failures ? 1 : 0)
