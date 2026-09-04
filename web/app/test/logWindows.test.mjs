/**
 * Los atajos de ventana del visor de logs tienen que llegar al backend con la
 * forma que el backend acepta.
 *
 * Lo que se comprueba aquí no es aritmética de fechas —el navegador no calcula
 * ninguna—, sino la traducción de los filtros de la vista a los parámetros de
 * `GET /system/logs`. Hay dos reglas que romperlas cuesta un error 400 o, peor,
 * una ventana silenciosamente equivocada:
 *
 *   - Un atajo activo manda `lastMinutes` y **no** manda `from`/`to`. El
 *     backend rechaza recibir los dos, porque pedir a la vez «los últimos diez
 *     minutos» y «desde las nueve» no significa nada.
 *   - «Todo» no es un atajo de cero minutos: es la ausencia de límite, así que
 *     no manda `lastMinutes` en absoluto.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  LOG_WINDOWS,
  DEFAULT_WINDOW_ID,
  buildLogQuery,
  windowMinutes,
  windowLabel,
} from '../src/composables/logWindows.js'

const asObject = (params) => Object.fromEntries(params.entries())

test('cada atajo manda su ventana en minutos y ninguna fecha suelta', () => {
  for (const option of LOG_WINDOWS) {
    const query = asObject(buildLogQuery({
      windowId: option.id,
      from: '2026-09-01T10:00:00',
      to: '2026-09-01T11:00:00',
    }))

    assert.equal(query.from, undefined, `${option.id} no debe mandar from`)
    assert.equal(query.to, undefined, `${option.id} no debe mandar to`)

    if (option.minutes === null) {
      assert.equal(query.lastMinutes, undefined, 'la ventana sin límite no acota')
    } else {
      assert.equal(query.lastMinutes, String(option.minutes))
    }
  }
})

test('la ventana personalizada manda las fechas escritas a mano', () => {
  const query = asObject(buildLogQuery({
    windowId: 'custom',
    from: '2026-09-01T10:00:00',
    to: '2026-09-01T11:00:00',
  }))

  assert.equal(query.from, '2026-09-01T10:00:00')
  assert.equal(query.to, '2026-09-01T11:00:00')
  assert.equal(query.lastMinutes, undefined)
})

test('los minutos de los atajos crecen y no se repiten', () => {
  const acotados = LOG_WINDOWS.filter((option) => option.minutes !== null)
  const minutos = acotados.map((option) => option.minutes)

  assert.deepEqual(minutos, [...minutos].sort((a, b) => a - b))
  assert.equal(new Set(minutos).size, minutos.length)
  assert.equal(acotados.length + 1, LOG_WINDOWS.length, 'solo «Todo» carece de límite')
})

test('el atajo por defecto existe y acota', () => {
  assert.ok(LOG_WINDOWS.some((option) => option.id === DEFAULT_WINDOW_ID))
  assert.equal(typeof windowMinutes(DEFAULT_WINDOW_ID), 'number')
  assert.ok(windowLabel(DEFAULT_WINDOW_ID).length > 0)
})

test('un identificador desconocido no acota ni revienta', () => {
  assert.equal(windowMinutes('no-existe'), null)
  assert.equal(windowLabel('no-existe'), '')
})

test('los filtros de nivel y texto viajan junto a la ventana', () => {
  const query = asObject(buildLogQuery({
    windowId: '30m',
    minLevel: 'WARNING',
    contains: 'traceback',
    position: 'head',
    page: 3,
    perPage: 250,
  }))

  assert.deepEqual(query, {
    page: '3',
    per_page: '250',
    position: 'head',
    lastMinutes: '30',
    minLevel: 'WARNING',
    contains: 'traceback',
  })
})

test('sin filtros se piden las últimas líneas de la primera página', () => {
  const query = asObject(buildLogQuery({}))

  assert.deepEqual(query, { page: '1', per_page: '100', position: 'tail' })
})
