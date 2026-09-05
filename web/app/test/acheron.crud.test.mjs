/**
 * Test del flujo de alta/edición del cliente cripto de Acheron.
 *
 * No toca la API: valida que `createStorable` y `buildUpdateChanges` producen
 * ciphertext que vuelve a descifrarse con la vaultKey real (la del vault de los
 * vectores), que el `internalId` es un hash de 16 hex, y que la edición solo
 * cifra los campos realmente modificados.
 *
 *   node web/app/test/acheron.crud.test.mjs
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { openVault, WrongPasswordError } from '../src/acheron/vault.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = resolve(here, 'acheron-vectors.json')

let passed = 0
let failed = 0
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

async function run() {
  const { cases } = JSON.parse(readFileSync(vectorsPath, 'utf8'))
  const c = cases[0] // Argon2
  const vault = await openVault(c.vault, c.masterPassword, c.username)

  // ── Alta ─────────────────────────────────────────────────────────────
  console.log('createStorable')
  const plain = { username: 'nuevo@example.com', domain: 'example.com', password: 's3cr3t-new' }
  const { payload, item } = await vault.createStorable('accounts', 'Mi cuenta nueva', plain)

  check('kind correcto', payload.kind === 'account', payload.kind)
  check('internalId es 16 hex', /^[0-9a-f]{16}$/.test(payload.internalId), payload.internalId)
  check('item local lleva el id', item.id === payload.internalId)
  check('campos cifrados (no en claro)', payload.password !== plain.password)

  // El payload se descifra con la vaultKey y reproduce el texto plano.
  const back = await vault.decryptStorable('accounts', payload)
  check('alta: title round-trip', back.title === 'Mi cuenta nueva')
  check('alta: username round-trip', back.username === plain.username)
  check('alta: domain round-trip', back.domain === plain.domain)
  check('alta: password round-trip', back.password === plain.password)

  // ── Edición ──────────────────────────────────────────────────────────
  console.log('\nbuildUpdateChanges')
  const current = await vault.decryptStorable('accounts', c.vault.accounts[0])
  const { changes, item: updated } = await vault.buildUpdateChanges(
    'accounts', current, current.title,
    { username: current.username, domain: 'cambiado.com', password: current.password },
  )

  const changedKeys = Object.keys(changes)
  check('solo cambia el campo modificado', changedKeys.length === 1 && changedKeys[0] === 'domain', changedKeys.join(','))

  const decChanges = await vault.decryptStorable('accounts', changes)
  check('edición: domain cifrado correcto', decChanges.domain === 'cambiado.com')
  check('item local actualizado', updated.domain === 'cambiado.com')
  check('item local conserva lo no tocado', updated.username === current.username)
  check('updatedAt cambia', updated.updatedAt !== current.updatedAt)

  // Sin cambios reales → changes vacío.
  const noop = await vault.buildUpdateChanges('accounts', current, current.title, {
    username: current.username, domain: current.domain, password: current.password,
  })
  check('sin cambios → changes vacío', Object.keys(noop.changes).length === 0)

  // ── Cambio de contraseña maestra ─────────────────────────────────────
  console.log('\nchangePassword')
  const newPassword = c.masterPassword + '-rotada-9'
  const before = await vault.decryptStorable('accounts', c.vault.accounts[0])

  const meta = await vault.changePassword(c.masterPassword, newPassword, c.username)
  check('devuelve checker/vaultKey/algorithm', !!meta.checker && !!meta.vaultKey && !!meta.algorithm)
  check('rota el salt', meta.algorithm.salt !== c.vault.algorithm.salt)
  check('no muta el vault original', vault.raw.checker === c.vault.checker)

  // El vault persistido reusa los storables (vaultKey sin cambiar) + nuevos metadatos.
  const rotated = { ...c.vault, checker: meta.checker, vaultKey: meta.vaultKey, algorithm: meta.algorithm }

  // La contraseña antigua ya no abre el vault rotado.
  let oldRejected = false
  try {
    await openVault(rotated, c.masterPassword, c.username)
  } catch (e) {
    oldRejected = e instanceof WrongPasswordError
  }
  check('la contraseña antigua es rechazada', oldRejected)

  // La nueva contraseña abre el vault y los storables se descifran intactos.
  const reopened = await openVault(rotated, newPassword, c.username)
  const after = await reopened.decryptStorable('accounts', rotated.accounts[0])
  check('nueva contraseña: title intacto', after.title === before.title)
  check('nueva contraseña: password intacto', after.password === before.password)

  console.log(`\nResultado: ${passed} OK, ${failed} fallidos`)
  if (failed > 0) process.exit(1)
}

run().catch((e) => { console.error(e); process.exit(1) })
