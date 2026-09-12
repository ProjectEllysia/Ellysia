/**
 * Test de los rótulos de Iris (`components/iris/verdict.js`).
 *
 * Fija que los valores que el servidor manda en inglés salen en castellano, y
 * que un valor desconocido cae en un rótulo genérico en vez de llegar crudo a
 * la pantalla (CONVENCIONES.md § 12.2).
 *
 *   node web/app/test/iris.verdict.test.mjs
 */

import {
  verdictLabel, verdictClass, analysisStatusLabel, ruleCategoryLabel, ruleVerdictLabel,
} from '../src/components/iris/verdict.js'

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

console.log('\nverdictLabel / verdictClass')
eq('veredicto del servidor, en castellano', verdictLabel('Suspicious'), 'Sospechoso')
eq('no distingue mayúsculas', verdictLabel('legitimate'), 'Legítimo')
eq('sin veredicto', verdictLabel(null), 'Sin veredicto')
eq('veredicto desconocido: genérico, nunca el crudo', verdictLabel('Spam'), 'Sin veredicto')
eq('tono del veredicto', verdictClass('Phishing'), 'phish')
eq('tono desconocido', verdictClass(undefined), 'unknown')

console.log('\nanalysisStatusLabel')
eq('en curso', analysisStatusLabel('running'), 'En análisis')
eq('estado desconocido', analysisStatusLabel('queued'), 'Desconocido')

console.log('\nruleCategoryLabel / ruleVerdictLabel')
eq('categoría', ruleCategoryLabel('content_analysis'), 'Contenido')
eq('categoría desconocida', ruleCategoryLabel('reputation'), 'Otra')
eq('resultado SPF', ruleVerdictLabel('softfail'), 'Falla leve')
eq('resultado desconocido', ruleVerdictLabel('temperror'), 'Otro')

console.log(`\n${passed} pasados, ${failed} fallidos\n`)
process.exit(failed === 0 ? 0 : 1)
