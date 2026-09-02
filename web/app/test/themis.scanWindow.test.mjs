/**
 * Tests de `scanWindow` — la ventana de escaneos que se le pide al backend.
 *
 * Node puro, sin framework, misma convención que el resto de `test/`.
 *
 * El fallo que cubren: la lista de Lybra crece con "ver más", que añadía la
 * siguiente página al final y avanzaba `page`; el refresco (manual, y el
 * sondeo automático que se rearma solo mientras haya un escaneo corriendo)
 * leía ese mismo `page` entendiendo que era la única página a mostrar, y
 * reemplazaba la lista con ella. Resultado: el usuario tenía treinta escaneos
 * en pantalla, saltaba el sondeo, y se quedaba con diez — y encima los más
 * antiguos, que son los de la tercera página.
 */

import assert from 'node:assert/strict'

const { scanWindow, canRevealMore, MAX_PER_PAGE } =
  await import('../src/stores/scanWindow.js')

let failures = 0
function test(name, fn) {
  try { fn(); console.log(`  ok   ${name}`) }
  catch (err) { failures++; console.error(`  FAIL ${name}\n       ${err.message}`) }
}

console.log('scanWindow')

test('sin revelar nada, la petición es la de siempre', () => {
  assert.deepEqual(
    scanWindow({ page: 1, perPage: 10, loadedPages: 1 }),
    { page: 1, perPage: 10 },
  )
})

test('la paginación clásica no cambia de comportamiento', () => {
  // nmap/nikto/nuclei van por goToPage y nunca revelan páginas: tienen que
  // seguir pidiendo exactamente la página que se les pide.
  assert.deepEqual(
    scanWindow({ page: 4, perPage: 10, loadedPages: 1 }),
    { page: 4, perPage: 10 },
  )
})

test('revelar páginas agranda la ventana, no avanza la página', () => {
  // Justo el fallo: tras dos "ver más" hay que pedir los 30 desde el
  // principio, no la página 3.
  assert.deepEqual(
    scanWindow({ page: 1, perPage: 10, loadedPages: 3 }),
    { page: 1, perPage: 30 },
  )
})

test('la ventana no rebasa el tope de per_page del backend', () => {
  // `ResultsQuerySchema` valida per_page con Range(min=1, max=100): pedir más
  // no sería una ventana mayor sino un 422.
  assert.equal(scanWindow({ page: 1, perPage: 10, loadedPages: 40 }).perPage, MAX_PER_PAGE)
})

test('un estado incompleto no produce una petición inválida', () => {
  assert.deepEqual(scanWindow({}), { page: 1, perPage: 10 })
  assert.deepEqual(scanWindow(undefined), { page: 1, perPage: 10 })
  assert.deepEqual(scanWindow({ page: 0, perPage: 0, loadedPages: 0 }), { page: 1, perPage: 10 })
})

console.log('canRevealMore')

test('hay más que revelar mientras falten escaneos', () => {
  assert.equal(
    canRevealMore({ results: new Array(10), totalCount: 42, perPage: 10, loadedPages: 1 }),
    true,
  )
})

test('no hay más que revelar cuando ya están todos', () => {
  assert.equal(
    canRevealMore({ results: new Array(42), totalCount: 42, perPage: 10, loadedPages: 5 }),
    false,
  )
})

test('no se revela más allá del tope, aunque queden escaneos', () => {
  // Sin este corte, "ver más" agrandaría la ventana a 110, el backend la
  // rechazaría, y el botón se quedaría sin hacer nada.
  assert.equal(
    canRevealMore({ results: new Array(100), totalCount: 500, perPage: 10, loadedPages: 10 }),
    false,
  )
})

if (failures) {
  console.error(`\n${failures} test(s) fallaron`)
  process.exit(1)
}
console.log('\ntodo en verde')
