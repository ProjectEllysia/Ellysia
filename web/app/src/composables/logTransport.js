const MAX_DECODED_BYTES = 4 * 1024 * 1024

/** Decodifica el contrato gzip/base64 servido por GET /system/logs. */
export async function decodeLogPayload(data) {
  if (data?.encoding !== 'base64' || data?.compression !== 'gzip') {
    throw new Error('El servidor devolvió un formato de log no compatible.')
  }
  if (!Number.isInteger(data.returnedBytes) || data.returnedBytes < 0 || data.returnedBytes > MAX_DECODED_BYTES) {
    throw new Error('La respuesta del log supera el tamaño permitido.')
  }
  if (typeof globalThis.DecompressionStream !== 'function') {
    throw new Error('Este navegador no permite descomprimir el log.')
  }

  const binary = atob(data.content || '')
  const compressed = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    compressed[index] = binary.charCodeAt(index)
  }

  const stream = new Blob([compressed])
    .stream()
    .pipeThrough(new DecompressionStream('gzip'))
  const text = await new Response(stream).text()
  const actualBytes = new TextEncoder().encode(text).byteLength
  if (actualBytes !== data.returnedBytes) {
    throw new Error('El contenido del log llegó incompleto.')
  }
  return text
}
