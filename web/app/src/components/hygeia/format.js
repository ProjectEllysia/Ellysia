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
 * Potencia eléctrica en vatios, escalada a kW cuando el valor lo pide.
 *
 * A diferencia de bytes/tasas (base 1024), la escala aquí es base 1000: un
 * portátil son decenas de vatios y un servidor con GPU centenares, así que
 * kW solo entra en juego muy por encima de eso (equipos de sala de
 * servidores agregados, no un único host).
 *
 * @param {number|null} watts
 * @returns {{text: string, unit: string}} p. ej. `{ text: '187', unit: 'W' }`.
 */
export function fmtWatts(watts) {
  if (isMissing(watts)) return NO_DATA
  if (Math.abs(watts) >= 1000) {
    const kw = watts / 1000
    return { text: kw >= 10 ? kw.toFixed(0) : kw.toFixed(1), unit: 'kW' }
  }
  return { text: watts >= 10 ? watts.toFixed(0) : watts.toFixed(1), unit: 'W' }
}

/**
 * Clasifica una lectura de potencia en sus cuatro estados posibles.
 *
 * La distinción entre medición y estimación se hace siempre sobre
 * `estimated`, nunca sobre el contenido de `source`: el servidor acepta
 * cualquier cadena ahí para que el agente pueda añadir fuentes nuevas sin
 * coordinación, así que ramificar por su valor se rompería con la primera
 * fuente nueva.
 *
 * Sin potencia, el cuarto estado (`'virtual'`) distingue "esta máquina es
 * un invitado, la mide su host" de "este equipo no tiene sensores": el
 * registro de energía del procesador no se virtualiza, así que la ausencia
 * de dato en un invitado no es un defecto de hardware, es la única
 * respuesta posible. Se ramifica exactamente igual que `source`: solo el
 * literal `"guest"` activa el mensaje, cualquier otro valor (`"host"`,
 * ausente, o una cadena que el servidor no reconozca) cae en el genérico
 * `'unavailable'` — nunca se le exige a `virtualizationRole` encajar en una
 * lista cerrada.
 *
 * @param {{watts: number|null, estimated: boolean|null, source: string|null}|null} power
 *   Bloque de potencia tal como lo sirve `metrics.power` del último heartbeat.
 * @param {{role: string|null, system: string|null}} [virtualization] - Identidad
 *   de virtualización del activo (`asset.virtualizationRole`/`virtualizationSystem`).
 * @returns {{state: 'measured'|'estimated'|'unavailable'|'virtual', watts: number|null,
 *   estimated: boolean|null, source: string|null, virtualizationSystem: string|null}}
 */
export function classifyPower(power, virtualization = null) {
  if (!power || power.watts === null || power.watts === undefined) {
    const isGuest = virtualization?.role === 'guest'
    return {
      state: isGuest ? 'virtual' : 'unavailable',
      watts: null, estimated: null, source: null,
      virtualizationSystem: isGuest ? (virtualization?.system ?? null) : null,
    }
  }
  return {
    state: power.estimated ? 'estimated' : 'measured',
    watts: power.watts,
    estimated: power.estimated ?? null,
    source: power.source ?? null,
    virtualizationSystem: null,
  }
}

/**
 * Energía en kWh, con la precisión que pide su magnitud.
 *
 * @param {number|null} kwh
 * @returns {{text: string, unit: string}}
 */
export function fmtEnergy(kwh) {
  if (isMissing(kwh)) return NO_DATA
  return { text: kwh >= 10 ? kwh.toFixed(1) : kwh.toFixed(2), unit: 'kWh' }
}

const CURRENCY_SYMBOLS = { EUR: '€', USD: '$', GBP: '£' }

/**
 * Coste monetario, con el símbolo de la moneda configurada cuando se
 * reconoce (o el propio código ISO como último recurso).
 *
 * @param {number|null} cost
 * @param {string} [currency='EUR'] - Código ISO 4217.
 * @returns {{text: string, unit: string}}
 */
export function fmtCost(cost, currency = 'EUR') {
  if (isMissing(cost)) return NO_DATA
  return { text: cost.toFixed(2), unit: CURRENCY_SYMBOLS[currency] || currency }
}

const CLASSIFICATION_LABELS = {
  observed: 'Observado',
  observed_partial: 'Datos parciales',
  projected: 'Proyección',
}

/** Rótulo en castellano de una clasificación de procedencia. */
export function powerPeriodLabel(classification) {
  return CLASSIFICATION_LABELS[classification] || classification
}

/**
 * Compone los textos de un periodo de consumo a partir de la
 * respuesta de ``GET /hygeia/assets/<id>/power-summary``.
 *
 * Función pura y testeable aparte del componente: formatea energía y coste,
 * y traduce la clasificación de procedencia a lo que se pinta en la
 * ficha, sin decidir dónde ni cómo se muestra.
 *
 * @param {object|null} period - Un bloque ``day``/``week``/``month``/``monthProjected``.
 * @returns {{kwh: {text,unit}, cost: {text,unit}, classification: string,
 *   classificationLabel: string, coverageFraction: number|null}|null}
 */
export function describePowerPeriod(period) {
  if (!period) return null
  return {
    kwh: fmtEnergy(period.kwh),
    cost: fmtCost(period.cost, period.currency),
    classification: period.classification,
    classificationLabel: powerPeriodLabel(period.classification),
    coverageFraction: period.coverageFraction ?? null,
  }
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
