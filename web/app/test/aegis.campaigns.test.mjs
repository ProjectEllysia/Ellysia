/**
 * Test de las cifras y rótulos de campañas de Aegis
 * (`components/aegis/campaigns.js`).
 *
 * Funciones puras sin DOM, así que se ejecuta con `node` a secas — mismo
 * precedente que el resto de tests del SPA.
 *
 *   node web/app/test/aegis.campaigns.test.mjs
 */

import {
  campaignStatusLabel,
  campaignStatusBadge,
  recipientStatusLabel,
  percentOf,
  summarizeRecipients,
  scorePercent,
  summarizePill,
} from '../src/components/aegis/campaigns.js'

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

console.log('\nrótulos')
eq('estado de campaña conocido', campaignStatusLabel('sent'), 'Enviada')
// Un estado nuevo del servidor no puede llegar en crudo a la pantalla.
eq('estado de campaña desconocido cae en genérico', campaignStatusLabel('archived'), 'Desconocido')
eq('insignia desconocida cae en pendiente', campaignStatusBadge('archived'), 'badge--pending')
eq('estado de destinatario', recipientStatusLabel('opened'), 'Abierto')
eq('estado de destinatario desconocido', recipientStatusLabel(undefined), 'Desconocido')

console.log('\nporcentajes')
eq('sin total no divide por cero', percentOf(3, 0), 0)
eq('redondea', percentOf(1, 3), 33)

console.log('\nresumen de destinatarios')
// Quien completó cuenta también como abierto: es lo que hace que la barra de
// "abiertos" nunca quede por debajo de la de "completados".
eq('estados acumulativos y nota media de quien completó', summarizeRecipients([
  { status: 'completed', score: 2 },
  { status: 'completed', score: 1 },
  { status: 'opened', score: null },
  { status: 'sent', score: null },
]), { recipientCount: 4, openedCount: 3, completedCount: 2, averageScore: 1.5 })
eq('sin destinatarios', summarizeRecipients([]),
  { recipientCount: 0, openedCount: 0, completedCount: 0, averageScore: null })

console.log('\nnota en porcentaje')
eq('1.5 de 2 es el 75 %', scorePercent(1.5, 2), 75)
eq('sin nota', scorePercent(null, 2), null)
eq('sin preguntas', scorePercent(1, 0), null)

console.log('\nresumen de una píldora')
// Dos campañas con tests de distinto tamaño (la píldora se editó entre
// medias): 2/2 en la primera es un 100 % y 1/4 en la segunda un 25 %. La
// media bruta de aciertos (1.5) no significaría nada; ponderada por quién
// completó (3 personas al 100 %, 1 al 25 %) es un 81 %.
const pill = summarizePill([
  { recipientCount: 5, openedCount: 4, completedCount: 3, averageScore: 2, questionCount: 2 },
  { recipientCount: 5, openedCount: 2, completedCount: 1, averageScore: 1, questionCount: 4 },
  // Un borrador no tiene destinatarios: no mueve ninguna cifra.
  { recipientCount: 0, openedCount: 0, completedCount: 0, averageScore: null, questionCount: 0 },
])
eq('totales y porcentajes', pill, {
  campaignCount: 3, recipientCount: 10, openRate: 60, completionRate: 40, averageScorePercent: 81,
})
eq('píldora sin campañas', summarizePill([]), {
  campaignCount: 0, recipientCount: 0, openRate: 0, completionRate: 0, averageScorePercent: null,
})

console.log(`\n${passed} pasados, ${failed} fallidos`)
process.exit(failed === 0 ? 0 : 1)
