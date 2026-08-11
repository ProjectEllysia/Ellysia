/**
 * Test del barajado de opciones del test de Aegis
 * (`components/aegis/quizShuffle.js`).
 *
 * Función pura sin DOM, así que se ejecuta con `node` a secas — mismo
 * precedente que los tests de Acheron y Hygeia, sin traer un framework nuevo.
 *
 *   node web/app/test/aegis.quizShuffle.test.mjs
 */

import { shuffledOrder } from '../src/components/aegis/quizShuffle.js'

let passed = 0
let failed = 0
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

function eq(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  check(name, a === e, `esperado ${e}, obtenido ${a}`)
}

console.log('\nes una permutación')
// Que sea permutación es lo que sostiene la corrección: la vista pinta
// options[i] pero envía i, así que perder o repetir un índice significaría
// enviar la respuesta de otra opción (o no poder marcar una de ellas).
for (const count of [2, 3, 4, 5, 8]) {
  let stillValid = true
  for (let attempt = 0; attempt < 200; attempt++) {
    const order = shuffledOrder(count)
    const sorted = [...order].sort((a, b) => a - b)
    const natural = Array.from({ length: count }, (_, index) => index)
    if (JSON.stringify(sorted) !== JSON.stringify(natural)) stillValid = false
  }
  check(`${count} opciones: mismos índices, sin repetidos ni huecos`, stillValid)
}

console.log('\ncasos borde')
eq('cero opciones', shuffledOrder(0), [])
eq('una opción', shuffledOrder(1), [0])
eq('recuento negativo no revienta', shuffledOrder(-3), [])
check('dos opciones siguen siendo dos', shuffledOrder(2).length === 2)

console.log('\nreparto uniforme')
// El test de verdad: un barajado mal hecho (el clásico
// `sort(() => Math.random() - 0.5)`) pasa los de arriba y falla este, dejando
// el sesgo que se venía a quitar.
const RUNS = 60000
const COUNT = 4
const landedAt = new Array(COUNT).fill(0)
for (let run = 0; run < RUNS; run++) {
  // Dónde acaba pintándose la opción original 1 — la "B" del problema.
  landedAt[shuffledOrder(COUNT).indexOf(1)]++
}
const expectedShare = RUNS / COUNT
const worstDeviation = Math.max(...landedAt.map(hits => Math.abs(hits - expectedShare) / expectedShare))
check(
  'la opción B cae en cada posición con la misma frecuencia',
  worstDeviation < 0.05,
  `desviación máxima ${(worstDeviation * 100).toFixed(1)}% sobre ${JSON.stringify(landedAt)}`,
)

const alwaysSecond = Array.from({ length: 500 }, () => shuffledOrder(4)).every(order => order[1] === 1)
check('no devuelve siempre el orden natural', !alwaysSecond)

console.log(`\n${passed} pasados, ${failed} fallidos`)
process.exit(failed === 0 ? 0 : 1)
