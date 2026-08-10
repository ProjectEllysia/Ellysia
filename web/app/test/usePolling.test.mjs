/**
 * Tests de `usePolling` (E8) — la forma correcta de sondear, en un sitio.
 *
 * Node puro, sin framework, misma convención que el resto de `test/`.
 * Lo que se comprueba es justo lo que los seis sondeos escritos a mano
 * hacían mal o de forma distinta entre sí:
 *   - que dos peticiones nunca se solapan aunque la tarea tarde más que el
 *     intervalo (el bug que `setInterval` provocaba, documentado en B10);
 *   - que `stop()` durante una petición en vuelo no deja un timer zombi;
 *   - que una condición terminal detiene el sondeo;
 *   - que `maxAttempts` acota;
 *   - que la pestaña oculta no gasta peticiones.
 */

import assert from 'node:assert/strict'

// `usePolling` importa `vue` solo para el hook opcional de desmontaje.
const { usePolling } = await import('../src/composables/usePolling.js')

const sleep = (ms) => new Promise(r => setTimeout(r, ms))

// document falso: usePolling lo consulta para la pausa/visibilidad.
function installDocument({ hidden = false } = {}) {
  const listeners = new Set()
  globalThis.document = {
    hidden,
    addEventListener: (name, fn) => { if (name === 'visibilitychange') listeners.add(fn) },
    removeEventListener: (name, fn) => { if (name === 'visibilitychange') listeners.delete(fn) },
  }
  return {
    setHidden(value) {
      globalThis.document.hidden = value
      for (const fn of listeners) fn()
    },
    listenerCount: () => listeners.size,
  }
}

let failures = 0
async function test(name, fn) {
  installDocument()
  try { await fn(); console.log(`  ok   ${name}`) }
  catch (err) { failures++; console.error(`  FAIL ${name}\n       ${err.message}`) }
}

console.log('usePolling')

await test('re-encadena: nunca solapa dos ciclos aunque la tarea tarde mas que el intervalo', async () => {
  let inFlight = 0, maxInFlight = 0, calls = 0
  const poller = usePolling(async () => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight)
    await sleep(40)             // tarea mas lenta que el intervalo
    inFlight--; calls++
  }, { intervalMs: 5 })
  poller.start()
  await sleep(200)
  poller.stop()
  assert.ok(calls >= 2, `esperaba varios ciclos, hubo ${calls}`)
  assert.equal(maxInFlight, 1, `se solaparon ${maxInFlight} peticiones`)
})

await test('stop() durante una peticion en vuelo no reprograma', async () => {
  let calls = 0
  const poller = usePolling(async () => { calls++; await sleep(30) }, { intervalMs: 5 })
  poller.start()
  await sleep(10)               // ciclo 1 en vuelo
  poller.stop()
  const callsAtStop = calls
  await sleep(120)
  assert.equal(calls, callsAtStop, 'siguio sondeando despues de stop()')
  assert.equal(poller.isRunning(), false)
})

await test('devolver false detiene el sondeo (condicion terminal)', async () => {
  let calls = 0
  const poller = usePolling(async () => { calls++; return calls < 3 }, { intervalMs: 5 })
  poller.start()
  await sleep(150)
  assert.equal(calls, 3, `esperaba parar en 3 ciclos, hubo ${calls}`)
  assert.equal(poller.isRunning(), false)
})

await test('maxAttempts acota el numero de ciclos', async () => {
  let calls = 0
  const poller = usePolling(async () => { calls++ }, { intervalMs: 5, maxAttempts: 4 })
  poller.start()
  await sleep(150)
  assert.equal(calls, 4, `esperaba 4 ciclos, hubo ${calls}`)
  assert.equal(poller.isRunning(), false)
})

await test('un error en la tarea no cancela el sondeo', async () => {
  let calls = 0
  const poller = usePolling(async () => { calls++; throw new Error('red caida') }, { intervalMs: 5 })
  poller.start()
  await sleep(80)
  poller.stop()
  assert.ok(calls >= 3, `un fallo aborto el sondeo (solo ${calls} ciclos)`)
})

await test('pestaña oculta: no gasta peticiones, y al volver sondea de inmediato', async () => {
  const doc = installDocument({ hidden: true })
  let calls = 0
  const poller = usePolling(async () => { calls++ }, { intervalMs: 10 })
  poller.start()
  await sleep(60)
  assert.equal(calls, 0, `sondeo ${calls} veces con la pestaña oculta`)
  doc.setHidden(false)
  await sleep(20)
  assert.ok(calls >= 1, 'no reanudo al volver a primer plano')
  poller.stop()
  assert.equal(doc.listenerCount(), 0, 'stop() dejo el listener de visibilidad colgado')
})

await test('start() dos veces no duplica el sondeo', async () => {
  let calls = 0
  const poller = usePolling(async () => { calls++ }, { intervalMs: 10 })
  poller.start(); poller.start()
  await sleep(55)
  poller.stop()
  assert.ok(calls <= 7, `doble start() duplico el ritmo (${calls} ciclos)`)
})

/* ── Backoff ──────────────────────────────────────────────────────────────
   Un sondeo a ritmo fijo gasta cupo proporcional al tiempo, no al trabajo:
   /themis/results cada 4 s son 900 peticiones/hora contra un limite de 300.
   Lo que se comprueba aqui es que el intervalo crece sin novedad, se reinicia
   en cuanto la hay, y que sin backoff nada de esto cambia el ritmo. */

/** Mide los huecos entre ciclos consecutivos. */
function medirHuecos(opciones, ciclos = 5) {
  return new Promise(resolve => {
    const huecos = []
    let anterior = Date.now()
    const poller = usePolling(async (intento) => {
      const ahora = Date.now()
      if (intento > 0) huecos.push(ahora - anterior)
      anterior = ahora
      if (intento >= ciclos) { poller.stop(); resolve(huecos); return false }
      return opciones.novedadEn === intento ? true : undefined
    }, { pauseWhenHidden: false, ...opciones })
    poller.start()
  })
}

await test('backoffFactor por defecto (1) mantiene el ritmo constante', async () => {
  const huecos = await medirHuecos({ intervalMs: 20 })
  for (const hueco of huecos) {
    assert.ok(hueco < 45, `el intervalo crecio sin pedirlo: ${huecos.join(', ')}`)
  }
})

await test('sin novedad, el intervalo crece con el factor indicado', async () => {
  const huecos = await medirHuecos({ intervalMs: 20, backoffFactor: 2, maxIntervalMs: 2000 })
  assert.ok(
    huecos[huecos.length - 1] > huecos[0] * 2,
    `el intervalo no crecio: ${huecos.join(', ')}`,
  )
})

await test('maxIntervalMs pone techo al crecimiento', async () => {
  const huecos = await medirHuecos({ intervalMs: 20, backoffFactor: 3, maxIntervalMs: 60 }, 6)
  for (const hueco of huecos) {
    assert.ok(hueco < 110, `se paso del techo de 60ms: ${huecos.join(', ')}`)
  }
})

await test('devolver true (hubo novedad) reinicia el intervalo', async () => {
  // Sin novedad hasta el ciclo 3; ahi se reinicia, asi que el hueco siguiente
  // tiene que ser mucho menor que el que venia acumulandose.
  const huecos = await medirHuecos({ intervalMs: 20, backoffFactor: 2, maxIntervalMs: 2000, novedadEn: 3 })
  const antesDelReinicio = huecos[2]
  const despuesDelReinicio = huecos[3]
  assert.ok(
    despuesDelReinicio < antesDelReinicio,
    `no reinicio tras la novedad: ${huecos.join(', ')}`,
  )
})

console.log(failures ? `\n${failures} test(s) fallaron` : '\nTodos los tests de usePolling pasaron')
process.exit(failures ? 1 : 0)
