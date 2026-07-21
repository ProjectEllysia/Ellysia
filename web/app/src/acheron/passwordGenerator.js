/**
 * Generador de contraseñas aleatorias, 100% local (Web Crypto API).
 *
 * No se comunica con el servidor: coherente con el resto de Acheron, donde
 * el cifrado y las claves nunca salen del navegador. Usa la misma fuente de
 * aleatoriedad segura que `crypto.js` (`crypto.getRandomValues`), con
 * rechazo uniforme para no sesgar el módulo hacia ningún carácter.
 */

import { randomBytes } from './crypto.js'

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const DIGITS = '0123456789'
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?'
const AMBIGUOUS = new Set('0O1lI')

/** Entero uniforme en [0, max) usando bytes criptográficos (rechazo de sesgo por módulo). */
function secureInt(max) {
  const limit = 256 - (256 % max)
  let byte
  do {
    byte = randomBytes(1)[0]
  } while (byte >= limit)
  return byte % max
}

function secureChoice(str) {
  return str[secureInt(str.length)]
}

function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureInt(i + 1)
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

/**
 * Genera una contraseña aleatoria segura.
 *
 * @param {object} [options]
 * @param {number} [options.length=20]
 * @param {boolean} [options.uppercase=true]
 * @param {boolean} [options.lowercase=true]
 * @param {boolean} [options.digits=true]
 * @param {boolean} [options.symbols=true]
 * @param {boolean} [options.excludeAmbiguous=true] excluye 0/O, 1/l/I
 * @returns {string}
 */
export function generatePassword({
  length = 20,
  uppercase = true,
  lowercase = true,
  digits = true,
  symbols = true,
  excludeAmbiguous = true,
} = {}) {
  let pools = [uppercase && UPPER, lowercase && LOWER, digits && DIGITS, symbols && SYMBOLS].filter(
    Boolean,
  )
  if (excludeAmbiguous) {
    pools = pools.map((pool) => [...pool].filter((c) => !AMBIGUOUS.has(c)).join(''))
  }

  const alphabet = pools.join('')
  const chars = pools.map((pool) => secureChoice(pool)) // >=1 carácter de cada set activado
  while (chars.length < length) chars.push(secureChoice(alphabet))

  return secureShuffle(chars).join('')
}
