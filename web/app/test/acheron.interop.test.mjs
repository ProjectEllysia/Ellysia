/**
 * Test de interoperabilidad Java → JS para el cliente cripto de Acheron.
 *
 * Carga los vectores generados por AcheronCore (acheron-vectors.json, en este
 * mismo directorio; ver el README de la suite para saber de qué versión salen),
 * abre cada vault con su master password y comprueba que el módulo JS descifra
 * EXACTAMENTE los valores en texto plano esperados. Verifica además el
 * round-trip (cifrar → descifrar) y que un master password incorrecto falla.
 *
 * Sin framework de test: se ejecuta con `node`. Sale con código != 0 si algo
 * falla, para poder usarse en CI.
 *
 *   node web/app/test/acheron.interop.test.mjs
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { openVault, WrongPasswordError } from '../src/acheron/vault.js'
import { STORABLE_CATEGORIES } from '../src/acheron/storableFields.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = resolve(here, 'acheron-vectors.json')

let passed = 0
let failed = 0

function check(name, condition, detail = '') {
  if (condition) {
    passed++
    console.log(`  ✓ ${name}`)
  } else {
    failed++
    console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`)
  }
}

async function run() {
  const { cases } = JSON.parse(readFileSync(vectorsPath, 'utf8'))
  console.log(`Vectores: ${vectorsPath}\n`)

  for (const c of cases) {
    console.log(`Caso KDF=${c.kdf} (user=${c.username})`)

    // 1) Apertura + validación del checker con el password correcto.
    const vault = await openVault(c.vault, c.masterPassword, c.username)

    // 2) Interop Java→JS: descifrar cada storable y comparar con lo esperado.
    const decryptedById = {}
    for (const category of STORABLE_CATEGORIES) {
      for (const item of c.vault[category] || []) {
        decryptedById[item.id] = await vault.decryptStorable(category, item)
      }
    }

    for (const [id, expected] of Object.entries(c.expected)) {
      const got = decryptedById[id]
      check(`${id}: presente`, !!got, 'no descifrado')
      if (!got) continue
      for (const [field, value] of Object.entries(expected)) {
        check(
          `${id}.${field} descifra correcto`,
          got[field] === value,
          `esperado ${JSON.stringify(value)}, obtenido ${JSON.stringify(got[field])}`,
        )
      }
    }

    // 3) Round-trip JS: cifrar de nuevo un storable y volver a descifrarlo.
    const firstCategory = STORABLE_CATEGORIES.find((cat) => (c.vault[cat] || []).length)
    const plainItem = await vault.decryptStorable(firstCategory, c.vault[firstCategory][0])
    const reEncrypted = await vault.encryptStorable(firstCategory, plainItem)
    const reDecrypted = await vault.decryptStorable(firstCategory, reEncrypted)
    check(
      `round-trip ${firstCategory}[0] preserva el contenido`,
      JSON.stringify(reDecrypted) === JSON.stringify(plainItem),
    )

    // 4) Master password incorrecto → WrongPasswordError.
    let threw = false
    try {
      await openVault(c.vault, c.masterPassword + 'x', c.username)
    } catch (e) {
      threw = e instanceof WrongPasswordError
    }
    check('master password incorrecto rechazado', threw)

    // 5) changePassword sobre el vault real de Java (cubre Argon2 y PBKDF2):
    //    rota la contraseña, reabre con la nueva y descifra lo mismo.
    const newPassword = c.masterPassword + '-rotada'
    const meta = await vault.changePassword(c.masterPassword, newPassword, c.username)
    check('changePassword rota el salt', meta.algorithm.salt !== c.vault.algorithm.salt)

    const rotated = { ...c.vault, checker: meta.checker, vaultKey: meta.vaultKey, algorithm: meta.algorithm }

    let oldRejected = false
    try {
      await openVault(rotated, c.masterPassword, c.username)
    } catch (e) {
      oldRejected = e instanceof WrongPasswordError
    }
    check('tras rotar, la contraseña antigua se rechaza', oldRejected)

    const rotatedVault = await openVault(rotated, newPassword, c.username)
    for (const [id, expected] of Object.entries(c.expected)) {
      for (const category of STORABLE_CATEGORIES) {
        const item = (rotated[category] || []).find((it) => it.id === id)
        if (!item) continue
        const got = await rotatedVault.decryptStorable(category, item)
        for (const [field, value] of Object.entries(expected)) {
          check(`rotado ${id}.${field} intacto`, got[field] === value,
            `esperado ${JSON.stringify(value)}, obtenido ${JSON.stringify(got[field])}`)
        }
      }
    }

    console.log('')
  }

  console.log(`Resultado: ${passed} OK, ${failed} fallidos`)
  if (failed > 0) process.exit(1)
}

run().catch((e) => {
  console.error(e)
  process.exit(1)
})
