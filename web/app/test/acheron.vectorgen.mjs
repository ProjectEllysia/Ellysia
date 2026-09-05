/**
 * Genera los VECTORES DE PRUEBA que produce el cliente JS, para que
 * AcheronCore (Java) verifique que sabe leer lo que escribe este motor.
 *
 * Es el espejo de `VectorGenerator.java`, con los papeles cambiados: allí Java
 * es el emisor y este cliente el receptor; aquí es al revés. Entre los dos
 * cierran el círculo, porque hasta ahora sólo se comprobaba la dirección
 * Java → JS: que este cliente supiera leer lo que escribe el Java. La dirección
 * contraria importa igual, porque la SPA escribe en la bóveda cada vez que un
 * usuario guarda una credencial, y quien lo lee después es la app Android.
 *
 * No es un test: es un generador. Se ejecuta a propósito cuando cambia el
 * formato de cable, y su salida se commitea.
 *
 *   node web/app/test/acheron.vectorgen.mjs [ruta-de-salida]
 *
 * Salida por defecto: acheron-vectors-js.json, en este mismo directorio.
 *
 * SOBRE EL DETERMINISMO: la salida cambia en cada ejecución aunque no cambie
 * nada del código. AES-GCM usa un IV aleatorio por operación y cada bóveda
 * nueva estrena salt y vaultKey, así que el ciphertext nunca se repite. Eso es
 * correcto y deseado: el consumidor Java no compara bytes, DESCIFRA y compara
 * el texto en claro, que es la única forma de verificar interoperabilidad con
 * un cifrado autenticado. Por eso el fichero se regenera a mano y no en cada
 * arranque de la suite.
 */

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { openVault, createVault } from '../src/acheron/vault.js'
import { deriveKey, aesGcmEncrypt, sha256Hex, generateSaltB64, randomBytes, b64encode }
  from '../src/acheron/crypto.js'

const USERNAME = 'alice'
const MASTER_PASSWORD = 'correct horse battery staple'

/** Los tres storables de cada caso, en claro. Mismos tipos que el generador Java. */
const STORABLES = [
  ['accounts', 'Gmail', {
    username: 'alice@gmail.com', domain: 'mail.google.com', password: 'P@ssw0rd-acc-0',
  }],
  ['creditcards', 'Personal Card', {
    cardHolderName: 'ALICE DOE', cardNumber: '4111111111111111',
    expirationDate: '12/29', postalCode: '28001', cvv: '123',
  }],
  ['securenotes', 'Recovery codes', {
    content: 'linea uno\nlinea dos con acentos: ñ á ü\nlinea tres',
  }],
]

/**
 * Metadatos de una bóveda PBKDF2. `createVault` sólo sabe hacer Argon2id, que
 * es lo que la SPA usa en producción, así que el caso PBKDF2 se arma aquí con
 * los mismos pasos: derivar, cifrar el checker y envolver la vaultKey.
 */
async function createPbkdf2Vault(masterPassword, username) {
  const algorithm = {
    transformation: 'AES/GCM/NoPadding',
    kdf: 'PBKDF2',
    kdfIterations: '600000',
    kdfKeyLength: '256',
    salt: generateSaltB64(),
  }
  const derivedKey = await deriveKey(masterPassword, algorithm)
  return {
    algorithm,
    checker: await aesGcmEncrypt(derivedKey, await sha256Hex(username)),
    vaultKey: await aesGcmEncrypt(derivedKey, b64encode(randomBytes(32))),
  }
}

/** Arma una bóveda completa con sus tres storables cifrados. */
async function buildCase(kdf, meta, masterPassword) {
  const vault = { version: 1, ...meta }
  for (const [category] of STORABLES) vault[category] = []

  const openable = await openVault(vault, masterPassword, USERNAME)
  const expected = {}

  for (const [category, title, fields] of STORABLES) {
    const { payload, item } = await openable.createStorable(category, title, fields)
    // El vault JSON usa `id`; el payload de la API usa `internalId`. Los
    // vectores reproducen la forma del vault, que es la que se descifra.
    const { internalId, kind, ...ciphertext } = payload
    vault[category].push({
      id: internalId, allowedUsers: [], ...ciphertext,
    })
    expected[internalId] = { title, ...fields }
    void item
  }

  return { kdf, masterPassword, username: USERNAME, vault, expected }
}

async function main() {
  const cases = []

  // 1) Argon2id: lo que la SPA escribe en producción.
  cases.push(await buildCase('Argon2', await createVault(MASTER_PASSWORD, USERNAME), MASTER_PASSWORD))

  // 2) PBKDF2: el otro KDF que el formato admite.
  cases.push(await buildCase('PBKDF2', await createPbkdf2Vault(MASTER_PASSWORD, USERNAME), MASTER_PASSWORD))

  // 3) Argon2id tras rotar la contraseña maestra. Es el caso de mayor riesgo:
  //    changePassword reescribe los tres campos maestros de la bóveda
  //    (checker, vaultKey y algorithm), así que un fallo aquí no corrompe un
  //    campo suelto, deja la bóveda entera ilegible para el otro cliente.
  const rotatedBase = await buildCase('Argon2', await createVault(MASTER_PASSWORD, USERNAME), MASTER_PASSWORD)
  const newPassword = MASTER_PASSWORD + '-rotada'
  const opened = await openVault(rotatedBase.vault, MASTER_PASSWORD, USERNAME)
  const rotatedMeta = await opened.changePassword(MASTER_PASSWORD, newPassword, USERNAME)
  cases.push({
    ...rotatedBase,
    kdf: 'Argon2-rotado',
    masterPassword: newPassword,
    vault: { ...rotatedBase.vault, ...rotatedMeta },
  })

  // Autoverificación antes de escribir. No sustituye a la comprobación del
  // lado Java —que es la que de verdad cierra el círculo— pero impide
  // commitear un fichero que ni este propio motor sabe releer.
  for (const c of cases) {
    const reopened = await openVault(c.vault, c.masterPassword, c.username)
    for (const [category] of STORABLES) {
      for (const item of c.vault[category]) {
        const got = await reopened.decryptStorable(category, item)
        for (const [field, value] of Object.entries(c.expected[item.id])) {
          if (got[field] !== value) {
            throw new Error(
              `caso ${c.kdf}: ${item.id}.${field} debería ser ${JSON.stringify(value)} ` +
                `y se releyó ${JSON.stringify(got[field])}`,
            )
          }
        }
      }
    }
  }

  const here = dirname(fileURLToPath(import.meta.url))
  const out = process.argv[2] || resolve(here, 'acheron-vectors-js.json')
  writeFileSync(out, JSON.stringify({ cases }, null, 2) + '\n', 'utf8')

  console.log(`Vectores escritos en ${out}`)
  for (const c of cases) {
    console.log(`  caso kdf=${c.kdf}  storables=${Object.keys(c.expected).length}`)
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
