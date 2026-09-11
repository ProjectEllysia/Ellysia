/**
 * Test de la comparación de informes de Iris (`components/iris/compare.js`).
 *
 * Abrir dos mensajes lado a lado solo sirve si salta a la vista qué cambia
 * entre ellos: estos tests fijan que las reglas se emparejan por nombre, que
 * lo que difiere va primero y que una regla presente en un solo informe (dos
 * versiones del catálogo) no se pierde.
 *
 *   node web/app/test/iris.compare.test.mjs
 */

import { compareReports } from '../src/components/iris/compare.js'

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

const rule = (ruleName, score, verdict) => ({ ruleName, score, verdict })
const left = {
  verdict: 'Phishing', totalScore: 30,
  rules: [rule('SPF', 0, 'pass'), rule('Body Links', -20, 'fail'), rule('DMARC', 0, 'pass')],
}
const right = {
  verdict: 'Legitimate', totalScore: 90,
  rules: [rule('SPF', 0, 'pass'), rule('Body Links', 0, 'pass'), rule('DMARC', 0, 'pass'), rule('QR Code Links', 0, 'pass')],
}

console.log('\ncompareReports')
const result = compareReports(left, right)
check('detecta el cambio de veredicto', result.verdictChanged)
eq('la diferencia de score es derecha menos izquierda', result.scoreDelta, 60)
eq('cuenta las reglas que cambian', result.changedCount, 2)
eq('lo que cambia va primero y después por nombre',
  result.rules.map(entry => entry.ruleName),
  ['Body Links', 'QR Code Links', 'DMARC', 'SPF'])
eq('una regla que solo existe en un informe se conserva',
  result.rules.find(entry => entry.ruleName === 'QR Code Links').left, null)

const same = compareReports(left, left)
check('un informe comparado consigo mismo no cambia', !same.verdictChanged && same.changedCount === 0)
eq('sin score en un lado no hay diferencia', compareReports({ ...left, totalScore: null }, right).scoreDelta, null)
eq('sin informes no revienta', compareReports(null, undefined).rules, [])

console.log(`\n${passed} pasados, ${failed} fallidos`)
process.exit(failed === 0 ? 0 : 1)
