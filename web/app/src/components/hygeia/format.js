/**
 * Formateo compartido por los componentes de Hygeia.
 *
 * Vive aquí y no en `useUtils` porque solo lo consumen la lista de activos y
 * el panel de detalle: la antigüedad relativa ("hace 4 s") solo aporta en una
 * vista de monitorización, donde lo que importa es si el dato es de ahora o
 * de hace media hora, no la fecha exacta.
 */

const MINUTE = 60
const HOUR = 3600
const DAY = 86400

/**
 * Antigüedad de un instante en lenguaje natural.
 *
 * @param {string|null} iso - Instante en ISO 8601, o null si nunca ocurrió.
 * @returns {string} "ahora mismo", "hace 4 s", "hace 3 min", "hace 2 h", "hace 5 d" o "nunca".
 */
export function timeAgo(iso) {
  if (!iso) return 'nunca'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'

  const secs = Math.max(0, Math.round((Date.now() - then) / 1000))
  if (secs < 5) return 'ahora mismo'
  if (secs < MINUTE) return `hace ${secs} s`
  if (secs < HOUR) return `hace ${Math.floor(secs / MINUTE)} min`
  if (secs < DAY) return `hace ${Math.floor(secs / HOUR)} h`
  return `hace ${Math.floor(secs / DAY)} d`
}

/**
 * Porcentaje con precisión adaptativa: un decimal cuando el valor es pequeño
 * (0,7 % dice algo; "1 %" perdería el matiz) y entero a partir de 10.
 *
 * @param {number|null} value - Porcentaje 0-100.
 * @returns {string} Valor formateado, o "—" si no hay dato.
 */
export function fmtPct(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return value >= 10 ? value.toFixed(0) : value.toFixed(1)
}

/** Ausencia de dato: mismo sentinel que `fmtPct`, en la forma que espera el gráfico. */
const NO_DATA = { text: '—', unit: '' }

function isMissing(value) {
  return value === null || value === undefined || Number.isNaN(value)
}

/**
 * Escala un valor a la mayor unidad en la que siga siendo legible.
 *
 * Base 1024 y etiquetas cortas (KB, MB...) en lugar de las estrictas KiB/MiB:
 * es lo que espera leer quien vigila un panel de monitorización, y la
 * precisión que se pierde en el nombre no cambia ninguna decisión.
 *
 * Devuelve `{ text, unit }` por separado, no una cadena ya montada, porque el
 * gráfico rotula el número grande y la unidad con estilos distintos — y
 * porque en tasas la unidad depende del valor, así que no puede venir fija
 * desde el descriptor de la serie.
 */
function scale(value, units) {
  if (isMissing(value)) return NO_DATA

  const sign = value < 0 ? '-' : ''
  let magnitude = Math.abs(value)
  let step = 0
  while (magnitude >= 1024 && step < units.length - 1) {
    magnitude /= 1024
    step += 1
  }

  // Misma precisión adaptativa que `fmtPct`: el matiz importa cuando la
  // cifra es pequeña y estorba cuando es grande.
  const text = magnitude >= 10 || step === 0 ? magnitude.toFixed(0) : magnitude.toFixed(1)
  return { text: sign + text, unit: units[step] }
}

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
const RATE_UNITS = BYTE_UNITS.map((u) => `${u}/s`)

/**
 * Tamaño en bytes, escalado a la unidad legible.
 *
 * @param {number|null} bytes
 * @returns {{text: string, unit: string}} p. ej. `{ text: '412', unit: 'GB' }`.
 */
export function fmtBytes(bytes) {
  return scale(bytes, BYTE_UNITS)
}

/**
 * Tasa de transferencia en bytes por segundo, escalada a la unidad legible.
 *
 * @param {number|null} bytesPerSec
 * @returns {{text: string, unit: string}} p. ej. `{ text: '9.4', unit: 'MB/s' }`.
 */
export function fmtRate(bytesPerSec) {
  return scale(bytesPerSec, RATE_UNITS)
}

/**
 * Carga media a 1 minuto (load1), con un decimal fijo.
 *
 * No tiene unidad ni techo natural: es un número de procesos en cola de
 * ejecución, así que la precisión la da el decimal, no la escala.
 *
 * @param {number|null} value - Carga media, o null si no la reporta (Windows).
 * @returns {string} "1.5", "0.0" o "—".
 */
export function fmtLoad1(value) {
  if (isMissing(value)) return '—'
  return value.toFixed(1)
}

/**
 * Tiempo encendido en lenguaje natural, con dos unidades de precisión.
 *
 * Se usa sobre el instante de arranque derivado, no sobre el uptime crudo:
 * el segundo envejece entre sondeos y el primero no.
 *
 * @param {number|null} seconds
 * @returns {string} "12 d 4 h", "3 h 12 min", "48 min" o "—".
 */
export function fmtUptime(seconds) {
  if (isMissing(seconds) || seconds < 0) return '—'

  const days = Math.floor(seconds / DAY)
  const hours = Math.floor((seconds % DAY) / HOUR)
  const minutes = Math.floor((seconds % HOUR) / MINUTE)

  if (days) return `${days} d ${hours} h`
  if (hours) return `${hours} h ${minutes} min`
  if (minutes) return `${minutes} min`
  return `${Math.floor(seconds)} s`
}
