/**
 * Test de los formateadores de Hygeia (`components/hygeia/format.js`).
 *
 * Son funciones puras sin DOM, así que se ejecutan con `node` a secas — mismo
 * precedente que los tests de Acheron, sin introducir un framework nuevo.
 *
 *   node web/app/test/hygeia.format.test.mjs
 */

import { fmtBytes, fmtRate, fmtUptime, fmtPct } from '../src/components/hygeia/format.js'

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

console.log('\nfmtBytes')
eq('bytes crudos sin escalar', fmtBytes(512), { text: '512', unit: 'B' })
eq('escala a KB', fmtBytes(2048), { text: '2.0', unit: 'KB' })
eq('escala a MB', fmtBytes(5 * 1024 * 1024), { text: '5.0', unit: 'MB' })
eq('entero a partir de 10', fmtBytes(42 * 1024 * 1024), { text: '42', unit: 'MB' })
eq('escala a GB', fmtBytes(412 * 1024 ** 3), { text: '412', unit: 'GB' })
eq('cero es un dato, no una ausencia', fmtBytes(0), { text: '0', unit: 'B' })

console.log('\nfmtRate')
eq('tasa en B/s', fmtRate(900), { text: '900', unit: 'B/s' })
eq('tasa en KB/s', fmtRate(120000), { text: '117', unit: 'KB/s' })
eq('tasa en MB/s', fmtRate(9.4 * 1024 * 1024), { text: '9.4', unit: 'MB/s' })
eq('tasa nula es dato', fmtRate(0), { text: '0', unit: 'B/s' })

console.log('\nausencia de dato')
const NO_DATA = { text: '—', unit: '' }
eq('fmtBytes(null)', fmtBytes(null), NO_DATA)
eq('fmtBytes(undefined)', fmtBytes(undefined), NO_DATA)
eq('fmtBytes(NaN)', fmtBytes(NaN), NO_DATA)
eq('fmtRate(null)', fmtRate(null), NO_DATA)
check('fmtPct(null) mantiene su sentinel de cadena', fmtPct(null) === '—')

console.log('\nfmtUptime')
eq('minutos', fmtUptime(48 * 60), '48 min')
eq('horas y minutos', fmtUptime(3 * 3600 + 12 * 60), '3 h 12 min')
eq('días y horas', fmtUptime(12 * 86400 + 4 * 3600), '12 d 4 h')
eq('segundos sueltos', fmtUptime(42), '42 s')
eq('sin dato', fmtUptime(null), '—')
eq('negativo no es un uptime', fmtUptime(-5), '—')

console.log(`\n${passed} pasados, ${failed} fallidos\n`)
process.exit(failed === 0 ? 0 : 1)
