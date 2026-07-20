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
