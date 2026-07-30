/**
 * Test de la concurrencia optimista del cliente web de Acheron.
 *
 * No toca la API ni la criptografía: valida contra un `apiFetch` falso que
 * `vaultWrite` manda If-Match, que reintenta UNA vez tras un 409 de revisión
 * obsoleta recargando antes el vault, y que no confunde ese 409 con el de
 * internalId duplicado.
 *
 *   node web/app/test/acheron.sync.test.mjs
 */

import { vaultWrite } from '../src/acheron/sync.js'

let passed = 0
let failed = 0
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

/** Respuesta mínima con la superficie que usa sync.js: ok/status/clone/json. */
function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    clone() { return this },
    async json() { return body },
  }
}

/** apiFetch falso que va devolviendo respuestas de una cola y registra llamadas. */
function fakeApi(queue) {
  const calls = []
  return {
    calls,
    apiFetch: async (path, options) => {
      calls.push({ path, ifMatch: options.headers?.['If-Match'] })
      return queue.shift() ?? response(500, {})
    },
  }
}

async function run() {
  // ── Escritura limpia ─────────────────────────────────────────────────
  console.log('vaultWrite sin conflicto')
  {
    const { apiFetch, calls } = fakeApi([response(201, { revision: 5 })])
    const ctx = { revision: 4, refresh: async () => { throw new Error('no debería recargar') } }

    const { res, refreshed } = await vaultWrite(apiFetch, '/acheron/storables', { method: 'POST' }, ctx)

    check('manda If-Match con la revisión actual', calls[0].ifMatch === '"4"', calls[0].ifMatch)
    check('una sola petición', calls.length === 1, String(calls.length))
    check('no marca recarga', refreshed === false)
    check('propaga la respuesta', res.status === 201)
    check('guarda la revisión nueva', ctx.revision === 5, String(ctx.revision))
  }

  // ── Conflicto de revisión: recarga y reintenta ───────────────────────
  console.log('\nvaultWrite con revisión obsoleta')
  {
    const { apiFetch, calls } = fakeApi([
      response(409, { error: 'vault_revision_mismatch', currentRevision: 7, yourRevision: 4 }),
      response(201, { revision: 8 }),
    ])
    let refreshes = 0
    const ctx = {
      revision: 4,
      refresh: async () => { refreshes++; ctx.revision = 7; return true },
    }

    const { res, refreshed } = await vaultWrite(apiFetch, '/acheron/storables', { method: 'POST' }, ctx)

    check('recarga una vez', refreshes === 1, String(refreshes))
    check('reintenta con la revisión fresca', calls[1]?.ifMatch === '"7"', calls[1]?.ifMatch)
    check('exactamente dos peticiones', calls.length === 2, String(calls.length))
    check('marca recarga para el llamante', refreshed === true)
    check('el reintento sale bien', res.status === 201)
    check('guarda la revisión resultante', ctx.revision === 8, String(ctx.revision))
  }

  // ── El 409 de internalId duplicado NO se reintenta ───────────────────
  console.log('\nvaultWrite con 409 ajeno a la revisión')
  {
    const { apiFetch, calls } = fakeApi([response(409, { error: 'StorableConflictError' })])
    const ctx = { revision: 4, refresh: async () => { throw new Error('no debería recargar') } }

    const { res, refreshed } = await vaultWrite(apiFetch, '/acheron/storables', { method: 'POST' }, ctx)

    check('no reintenta', calls.length === 1, String(calls.length))
    check('no marca recarga', refreshed === false)
    check('devuelve el 409 al llamante', res.status === 409)
  }

  // ── Si la recarga falla, no se reintenta a ciegas ────────────────────
  console.log('\nvaultWrite cuando la recarga falla')
  {
    const { apiFetch, calls } = fakeApi([
      response(409, { error: 'vault_revision_mismatch', currentRevision: 7 }),
    ])
    const ctx = { revision: 4, refresh: async () => false }

    const { res, refreshed } = await vaultWrite(apiFetch, '/acheron/storables', { method: 'POST' }, ctx)

    check('no reintenta sin estado fresco', calls.length === 1, String(calls.length))
    check('no marca recarga', refreshed === false)
    check('devuelve el conflicto', res.status === 409)
  }

  // ── Sin revisión conocida no se manda la cabecera ────────────────────
  console.log('\nvaultWrite sin revisión conocida')
  {
    const { apiFetch, calls } = fakeApi([response(200, {})])
    const ctx = { revision: null, refresh: async () => true }

    await vaultWrite(apiFetch, '/acheron/vault', { method: 'PATCH' }, ctx)

    check('omite If-Match', calls[0].ifMatch === undefined, String(calls[0].ifMatch))
    check('no inventa revisión', ctx.revision === null, String(ctx.revision))
  }

  console.log(`\n${passed} passed, ${failed} failed`)
  if (failed > 0) process.exit(1)
}

run().catch((e) => {
  console.error(e)
  process.exit(1)
})
