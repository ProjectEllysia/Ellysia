import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { decodeLogPayload } from '../src/composables/logTransport.js'

const text = '[+] [ERROR] fallo\nLínea continuadora'
const compressed = gzipSync(Buffer.from(text, 'utf8'))

const payload = {
  compression: 'gzip',
  encoding: 'base64',
  content: compressed.toString('base64'),
  returnedBytes: new TextEncoder().encode(text).byteLength,
}

assert.equal(await decodeLogPayload(payload), text)

await assert.rejects(
  decodeLogPayload({ ...payload, compression: 'deflate' }),
  /formato de log no compatible/,
)

await assert.rejects(
  decodeLogPayload({ ...payload, returnedBytes: payload.returnedBytes + 1 }),
  /contenido del log llegó incompleto/,
)

console.log('logTransport: 3 pruebas pasaron')
