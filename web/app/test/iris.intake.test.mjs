/**
 * Test de la admisión de ficheros de Iris (`components/iris/intake.js`).
 *
 * B13: la vista tenía su propio tope de tamaño (20 MiB) mientras el backend
 * aplicaba otro (10 MiB). El usuario elegía un fichero que la interfaz daba
 * por bueno, esperaba a que se cargara entero en memoria y recibía un rechazo
 * del API. Estos tests fijan que la decisión sale del límite que publica el
 * servidor y no de una constante escrita a mano.
 *
 * Funciones puras sin DOM, así que se ejecutan con `node` a secas — mismo
 * precedente que los tests de Acheron y Hygeia, sin introducir un framework:
 *
 *   node web/app/test/iris.intake.test.mjs
 */

import {
  FALLBACK_MAX_MESSAGE_BYTES,
  MODE_HEADERS,
  MODE_MESSAGE,
  buildSubmission,
  classifyIntake,
  formatByteLimit,
  isEmlFile,
  resolveMaxMessageBytes,
} from '../src/components/iris/intake.js'

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

const MB = 1024 * 1024
const file = (name, size, type = '') => ({ name, size, type })

console.log('\nisEmlFile')
check('acepta por extensión', isEmlFile(file('correo.eml', 10)))
check('acepta en mayúsculas', isEmlFile(file('CORREO.EML', 10)))
check('acepta por tipo MIME sin extensión', isEmlFile(file('adjunto', 10, 'message/rfc822')))
check('rechaza un PDF', !isEmlFile(file('informe.pdf', 10)))
check('rechaza la ausencia de fichero', !isEmlFile(null))

console.log('\nresolveMaxMessageBytes')
eq('usa el límite que publica el servidor', resolveMaxMessageBytes({ maxMessageBytes: 5 * MB }), 5 * MB)
eq('sin capacidades cae al respaldo', resolveMaxMessageBytes(null), FALLBACK_MAX_MESSAGE_BYTES)
eq('sin el campo cae al respaldo', resolveMaxMessageBytes({}), FALLBACK_MAX_MESSAGE_BYTES)
// Un 0 o un null significan "el servidor no me lo ha dicho", no "no hay
// límite": tratarlos como cero rechazaría absolutamente todo.
eq('un cero no es un límite', resolveMaxMessageBytes({ maxMessageBytes: 0 }), FALLBACK_MAX_MESSAGE_BYTES)
eq('un null no es un límite', resolveMaxMessageBytes({ maxMessageBytes: null }), FALLBACK_MAX_MESSAGE_BYTES)
eq('una cadena no es un límite', resolveMaxMessageBytes({ maxMessageBytes: '5000' }), FALLBACK_MAX_MESSAGE_BYTES)
eq('el respaldo coincide con el default del backend', FALLBACK_MAX_MESSAGE_BYTES, 10 * MB)

console.log('\nclassifyIntake — el límite lo manda el servidor')
const capabilities = { maxMessageBytes: 10 * MB }

eq('un .eml pequeño se manda entero',
  classifyIntake(file('a.eml', 2 * MB), capabilities),
  { accepted: true, reason: 'ok', headersOnly: false, limit: 10 * MB })

eq('justo en el límite todavía cabe entero',
  classifyIntake(file('a.eml', 10 * MB), capabilities),
  { accepted: true, reason: 'ok', headersOnly: false, limit: 10 * MB })

eq('un byte por encima pasa a solo cabeceras',
  classifyIntake(file('a.eml', 10 * MB + 1), capabilities),
  { accepted: true, reason: 'too-big', headersOnly: true, limit: 10 * MB })

// El caso que motiva el issue: 15 MiB caía en la franja entre el tope viejo
// del frontend (20 MiB) y el real del backend (10 MiB). La interfaz lo daba
// por bueno y el API lo rechazaba después.
eq('los 15 MiB de la franja discordante ya no se mandan enteros',
  classifyIntake(file('a.eml', 15 * MB), capabilities),
  { accepted: true, reason: 'too-big', headersOnly: true, limit: 10 * MB })

eq('un fichero que no es .eml no se lee siquiera',
  classifyIntake(file('informe.pdf', 1), capabilities),
  { accepted: false, reason: 'not-eml', headersOnly: false, limit: null })

console.log('\nclassifyIntake — sigue la configuración del servidor')
// Si alguien sube el tope por PUT /system, la interfaz debe seguirlo sin que
// haya que tocar el código del navegador. Es la propiedad que la constante
// escrita a mano no podía tener.
eq('un tope mayor deja pasar enteros ficheros antes truncados',
  classifyIntake(file('a.eml', 15 * MB), { maxMessageBytes: 20 * MB }).headersOnly,
  false)
eq('un tope menor los trunca antes',
  classifyIntake(file('a.eml', 6 * MB), { maxMessageBytes: 5 * MB }).headersOnly,
  true)

console.log('\nformatByteLimit')
eq('10 MB', formatByteLimit(10 * MB), '10 MB')
eq('20 MB', formatByteLimit(20 * MB), '20 MB')
eq('decimal por debajo de 10', formatByteLimit(2.5 * MB), '2.5 MB')
eq('sin límite no hay texto', formatByteLimit(0), '')

console.log('\nbuildSubmission — el modo viaja explícito')
eq('modo cabeceras envía solo las cabeceras',
  buildSubmission({ mode: MODE_HEADERS, headers: 'From: a', message: 'From: a\n\ncuerpo' }),
  { mode: 'headers', headers: 'From: a' })
eq('modo completo envía solo el mensaje',
  buildSubmission({ mode: MODE_MESSAGE, headers: 'From: a', message: 'From: a\n\ncuerpo', title: 'T' }),
  { mode: 'message', message: 'From: a\n\ncuerpo', title: 'T' })
// Sin mensaje cargado (fichero truncado por tamaño o cabeceras pegadas a mano)
// el modo completo no tiene nada que enviar: cae a cabeceras en vez de mandar
// una petición que el servidor rechazaría.
eq('modo completo sin mensaje cae a cabeceras',
  buildSubmission({ mode: MODE_MESSAGE, headers: 'From: a', message: null }),
  { mode: 'headers', headers: 'From: a' })
eq('sin título no se envía la clave',
  Object.keys(buildSubmission({ mode: MODE_HEADERS, headers: 'From: a', title: '' })),
  ['mode', 'headers'])

console.log(`\n${passed} pasados, ${failed} fallidos`)
process.exit(failed === 0 ? 0 : 1)
