/**
 * Decisiones de admisión de un fichero arrastrado a Iris.
 *
 * Vive fuera de `IrisView.vue` por dos motivos. El primero es poder probarlo:
 * son funciones puras sin DOM, igual que `components/hygeia/format.js`, así
 * que corren con `node` a secas (ver `test/iris.intake.test.mjs`).
 *
 * El segundo es la razón de ser de este módulo. El tope de tamaño estaba escrito a mano en
 * la vista (`20 * 1024 * 1024`) mientras el backend aplicaba otro
 * (`iris.maxMessageBytes`, 10 MiB): el usuario elegía un fichero que la
 * interfaz daba por bueno, esperaba a que se cargara entero en memoria y
 * recibía un rechazo del API. Una constante duplicada en el navegador deriva
 * en cuanto alguien cambia la configuración del servidor —y ya había
 * derivado, al doble—, así que el límite se pide a `GET /iris/capabilities` y
 * aquí solo queda cómo aplicarlo.
 */

/** Tope de emergencia si `/iris/capabilities` no ha respondido todavía.
 *
 *  Coincide con el default de `IrisConfig.max_message_bytes`. No es la fuente
 *  de verdad —el servidor lo es— sino lo que evita que la vista quede
 *  inutilizable mientras la petición está en vuelo o si falla. Ante la duda,
 *  es preferible pecar por defecto: un fichero rechazado de más se puede
 *  reintentar, uno aceptado de más se rechaza igualmente al enviarlo, pero
 *  después de habérselo comido entero.
 */
export const FALLBACK_MAX_MESSAGE_BYTES = 10 * 1024 * 1024

/** ¿Es un `.eml`? Se acepta por extensión o por tipo MIME: los navegadores no
 *  siempre rellenan `file.type` para ficheros arrastrados desde el disco. */
export function isEmlFile(file) {
  if (!file) return false
  return /\.eml$/i.test(file.name ?? '') || file.type === 'message/rfc822'
}

/** Tope efectivo a partir de la respuesta de capacidades del servidor.
 *
 *  Solo acepta enteros positivos: un `null`, un `0` o un valor no numérico
 *  significan "el servidor no me lo ha dicho", no "no hay límite" — tratarlos
 *  como cero rechazaría absolutamente todo.
 */
export function resolveMaxMessageBytes(capabilities) {
  const declared = capabilities?.maxMessageBytes
  if (typeof declared === 'number' && Number.isFinite(declared) && declared > 0) {
    return Math.floor(declared)
  }
  return FALLBACK_MAX_MESSAGE_BYTES
}

/**
 * Decide qué hacer con un fichero antes de leerlo.
 *
 * Devuelve `{ accepted, reason, headersOnly }`:
 *
 * - `accepted: false` — no es un `.eml`; no hay nada que leer.
 * - `headersOnly: true` — es un `.eml` pero pasa del tope, así que solo se
 *   enviarán las cabeceras extraídas. No es un rechazo: un correo enorme casi
 *   siempre lo es por sus adjuntos, y sus cabeceras siguen siendo analizables.
 * - `headersOnly: false` — cabe entero y se manda completo, para que las
 *   reglas de contenido (cuerpo, enlaces, adjuntos) puedan aplicarse.
 */
export function classifyIntake(file, capabilities) {
  if (!isEmlFile(file)) {
    return { accepted: false, reason: 'not-eml', headersOnly: false, limit: null }
  }

  const limit = resolveMaxMessageBytes(capabilities)
  const headersOnly = (file.size ?? 0) > limit

  return {
    accepted: true,
    reason: headersOnly ? 'too-big' : 'ok',
    headersOnly,
    limit,
  }
}

/** Tamaño legible para el aviso que ve el usuario ("10 MB"). */
export function formatByteLimit(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return ''
  const megabytes = bytes / (1024 * 1024)
  const rounded = megabytes >= 10 ? Math.round(megabytes) : Math.round(megabytes * 10) / 10
  return `${rounded} MB`
}
