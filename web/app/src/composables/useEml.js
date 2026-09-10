/**
 * Parser ligero de archivos .eml (RFC 822/5322) para el intake de Iris.
 *
 * Extrae el bloque de cabeceras crudo y el asunto ("concepto") del correo,
 * decodificando las palabras codificadas MIME (=?charset?B/Q?...?=) habituales.
 * Se usa solo para rellenar el formulario (vista previa); el texto completo
 * del .eml se envía aparte a la API en el campo `message`, para que las
 * reglas de análisis más profundo (enlaces del cuerpo, adjuntos reales,
 * cadena Received) puedan analizarlo.
 *
 * @example
 * import { parseEml } from '@/composables/useEml'
 * const { rawHeaders, subject } = parseEml(emlText)
 */

/**
 * Decodifica palabras codificadas MIME (encoded-words) a texto legible.
 * Soporta codificación Base64 (B) y Quoted-Printable (Q) con cualquier
 * charset reconocido por TextDecoder (utf-8, iso-8859-1, …).
 * @param {string} str
 * @returns {string}
 */
function decodeEncodedWords(str) {
  if (!str || !str.includes('=?')) return str
  // El espacio en blanco entre dos encoded-words adyacentes se ignora (RFC 2047).
  const collapsed = str.replace(/\?=\s+=\?/g, '?==?')
  return collapsed.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
    try {
      let bytes
      if (enc.toUpperCase() === 'B') {
        const bin = atob(text.replace(/\s+/g, ''))
        bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
      } else {
        const q = text
          .replace(/_/g, ' ')
          .replace(/=([0-9A-Fa-f]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
        bytes = Uint8Array.from(q, (c) => c.charCodeAt(0))
      }
      return new TextDecoder(charset.toLowerCase()).decode(bytes)
    } catch {
      return text
    }
  })
}

/**
 * Localiza la cabecera Subject en el bloque de cabeceras, uniendo las líneas
 * plegadas (continuation lines que empiezan por espacio/tab) y decodificándola.
 * @param {string} headerBlock - Bloque de cabeceras separadas por '\n'
 * @returns {string} Asunto decodificado, o cadena vacía
 */
function extractSubject(headerBlock) {
  const lines = headerBlock.split('\n')
  let raw = null
  for (const line of lines) {
    if (raw !== null) {
      if (/^[ \t]/.test(line)) {
        raw += ' ' + line.trim()
        continue
      }
      break
    }
    const m = /^subject:(.*)$/i.exec(line)
    if (m) raw = m[1].trim()
  }
  return raw ? decodeEncodedWords(raw).replace(/\s+/g, ' ').trim() : ''
}

/**
 * Parsea el texto de un .eml.
 * @param {string} text - Contenido textual del archivo (basta con la cabecera)
 * @returns {{ rawHeaders: string, subject: string }}
 */
export function parseEml(text) {
  const normalized = (text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const sep = normalized.indexOf('\n\n')
  const rawHeaders = (sep === -1 ? normalized : normalized.slice(0, sep)).trim()
  return { rawHeaders, subject: extractSubject(rawHeaders) }
}
