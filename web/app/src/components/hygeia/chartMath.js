/**
 * Lógica pura del gráfico de Hygeia — sin Vue ni DOM, para poder testearla
 * en Node igual que `format.js`.
 *
 * Aquí viven tres cosas que el componente necesita y que no deben depender
 * del render:
 *   - El catálogo de series (`SERIES`): una sola fuente de verdad para la
 *     barra secundaria (MetricNav) y para el trazado (MetricsChart). Añadir
 *     una métrica es una entrada más aquí, sin tocar componentes.
 *   - La escala del eje Y (`yRange`, `yTicks`, `niceCeil`): el porcentaje
 *     tiene techo natural (0–100) y no debe escalarse al máximo de los
 *     datos — un 45 % de CPU a mitad de la gráfica debe LEERSE como la
 *     mitad de la potencia, no de lo registrado. Las series sin techo
 *     (red, carga) escalan a un máximo "bonito" ligeramente por encima
 *     del dato.
 *   - La geometría temporal (`timeTicks`, `detectGaps`, ...): el eje X es
 *     tiempo real, y el tiempo sin señal (apagado) se deriva de los huecos
 *     de la serie, no se inventa.
 */

import { fmtLoad1, fmtPct, fmtRate } from './format.js'

const PCT = (v) => ({ text: fmtPct(v), unit: '%' })

/**
 * Series que se pueden trazar y todo lo que las distingue.
 *
 * - `fixedMax`: techo natural del eje Y (100 para porcentajes, `null` para
 *   las que no tienen). Con techo, el eje es fijo y honesto; sin él, se
 *   escala al dato con `niceCeil`.
 * - `minSpan`: amplitud mínima del eje Y aunque la serie sea plana; sin
 *   este suelo, un host en reposo amplificaría décimas de ruido hasta
 *   parecer un sismógrafo.
 * - `color`: se inyecta como custom property, no como clase CSS, para que
 *   añadir una serie no obligue a tocar la hoja de estilos.
 */
export const SERIES = [
  { key: 'cpu',    name: 'CPU',       field: 'cpuPct',    color: 'var(--accent-bright)',
    fixedMax: 100, minSpan: 6,    fmt: PCT },
  { key: 'mem',    name: 'Memoria',   field: 'memPct',    color: 'var(--info)',
    fixedMax: 100, minSpan: 6,    fmt: PCT },
  { key: 'swap',   name: 'Swap',      field: 'swapPct',   color: 'var(--warn)',
    fixedMax: 100, minSpan: 6,    fmt: PCT },
  { key: 'disk',   name: 'Disco',     field: 'diskMaxPct', color: 'var(--danger)',
    fixedMax: 100, minSpan: 6,    fmt: PCT },
  // Entrada y salida comparten tono a propósito: son la misma magnitud en
  // dos sentidos, y la paleta no tiene seis matices distintos que repartir.
  { key: 'net-rx', name: 'Red · in',  field: 'netRxBps',  color: 'var(--success)',
    fixedMax: null, minSpan: 8192, fmt: fmtRate },
  { key: 'net-tx', name: 'Red · out', field: 'netTxBps',
    color: 'color-mix(in srgb, var(--success) 50%, var(--text-muted))',
    fixedMax: null, minSpan: 8192, fmt: fmtRate },
  { key: 'load1',  name: 'Carga',     field: 'load1',     color: 'var(--accent)',
    fixedMax: null, minSpan: 1,    fmt: (v) => ({ text: fmtLoad1(v), unit: '' }) },
]

export function seriesOf(key) {
  return SERIES.find((s) => s.key === key) ?? null
}

/* ── Escala del eje Y ──────────────────────────────────────────────────── */

/** Pasos "bonitos" normalizados: 1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10 × 10^k. */
const NICE_STEPS = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]

/**
 * Redondea un valor positivo al número "bonito" inmediatamente superior.
 *
 * 245_760 → 250_000, 96 → 100, 0.42 → 0.5. Es el máximo del eje Y en las
 * series sin techo: un número así se lee a ojo y la rejilla queda entera.
 *
 * @param {number} value - Valor a redondear (0 o negativo → 0).
 * @returns {number} El número bonito más cercano por arriba.
 */
export function niceCeil(value) {
  if (!Number.isFinite(value) || value <= 0) return 0
  const magnitude = 10 ** Math.floor(Math.log10(value))
  const normalized = value / magnitude
  for (const step of NICE_STEPS) {
    if (normalized <= step) return step * magnitude
  }
  return 10 * magnitude
}

/**
 * Rango del eje Y de una serie.
 *
 * Con `fixedMax` el rango es fijo (0–100): el valor manda sobre el gráfico,
 * no al revés. Sin techo, el máximo es el dato redondeado a un número
 * bonito con un 20 % de aire (para que la línea no se pegue al borde), y
 * nunca por debajo del `minSpan` de la serie.
 *
 * @param {object} series - Descriptor de `SERIES`.
 * @param {number[]} values - Valores a representar (no vacío).
 * @returns {{lo: number, hi: number}}
 */
export function yRange(series, values) {
  if (series.fixedMax) return { lo: 0, hi: series.fixedMax }
  const max = Math.max(...values)
  return { lo: 0, hi: Math.max(niceCeil(max * 1.2), series.minSpan) }
}

/**
 * Líneas de rejilla horizontales del eje Y.
 *
 * Con techo fijo, pasos limpios (0/25/50/75/100). Sin techo, un paso
 * bonito sobre el rango; las líneas no pasan del techo del rango (la
 * última puede quedar por debajo: mejor que invadir el borde superior).
 *
 * @param {object} series - Descriptor de `SERIES`.
 * @param {{lo: number, hi: number}} range - Rango de `yRange`.
 * @param {number} count - Número de intervalos deseado (por defecto 4).
 * @returns {number[]} Valores de las líneas de rejilla.
 */
export function yTicks(series, range, count = 4) {
  if (series.fixedMax) {
    const step = series.fixedMax / count
    return Array.from({ length: count + 1 }, (_, i) => step * i)
  }
  const step = niceCeil(range.hi / count)
  const ticks = []
  for (let i = 0; i * step <= range.hi + 1e-9; i++) ticks.push(i * step)
  return ticks
}

/* ── Eje temporal ──────────────────────────────────────────────────────── */

/**
 * Instantes equidistantes entre el inicio y el fin de la ventana.
 *
 * @param {number} t0Ms - Inicio de la ventana (epoch ms).
 * @param {number} t1Ms - Fin de la ventana (epoch ms).
 * @param {number} count - Número de intervalos (por defecto 5).
 * @returns {number[]} `count + 1` instantes, de `t0Ms` a `t1Ms` inclusive.
 */
export function timeTicks(t0Ms, t1Ms, count = 5) {
  const step = (t1Ms - t0Ms) / count
  return Array.from({ length: count + 1 }, (_, i) => t0Ms + step * i)
}

const pad = (n) => String(n).padStart(2, '0')

/**
 * Etiqueta corta de un instante en el eje X.
 *
 * Hasta 24 h de ventana basta con la hora ("14:05"); por encima, el día se
 * vuelve necesario ("25/08 14:05"). Siempre en hora local del navegador:
 * quien vigila lee su propio reloj, no el UTC del servidor.
 *
 * @param {number} ts - Instante (epoch ms).
 * @param {number} spanMs - Amplitud de la ventana.
 * @returns {string}
 */
export function formatTimeTick(ts, spanMs) {
  const d = new Date(ts)
  const hhmm = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  if (spanMs < 24 * 3600e3) return hhmm
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${hhmm}`
}

/* ── Tiempo sin señal (apagado) ────────────────────────────────────────── */

/**
 * Umbral a partir del cual un hueco sin heartbeats cuenta como "apagado".
 *
 * Se deriva del intervalo real de la serie (la mediana de los deltas): un
 * agente que late cada 15 s tolera 45 s de silencio sin escandalizarse, y
 * uno que late cada 5 min necesita más manga. En modo agregado (cubos), el
 * suelo es un cubo entero — un cubo vacío YA es una ausencia significativa.
 *
 * @param {number|null} medianDeltaMs - Mediana de los deltas, o null si no hay pares.
 * @param {number|null} bucketSec - Segundos del cubo de agregación, o null en serie cruda.
 * @returns {number} Umbral en milisegundos.
 */
export function gapThresholdMs(medianDeltaMs, bucketSec) {
  const floor = bucketSec ? bucketSec * 1000 : 90_000
  return Math.max(3 * (medianDeltaMs || 0), floor)
}

/**
 * Mediana de los intervalos entre lecturas consecutivas.
 *
 * La mediana, no la media: un único apagón de 2 h en medio de una serie de
 * 15 s no debe inflar el "intervalo típico" y perdonar huecos de 10 min.
 *
 * @param {number[]} timesMs - Instantes ordenados (epoch ms).
 * @returns {number|null} Mediana en ms, o null con menos de dos instantes.
 */
export function medianDeltaMs(timesMs) {
  if (timesMs.length < 2) return null
  const deltas = []
  for (let i = 1; i < timesMs.length; i++) deltas.push(timesMs[i] - timesMs[i - 1])
  deltas.sort((a, b) => a - b)
  const mid = Math.floor(deltas.length / 2)
  return deltas.length % 2 ? deltas[mid] : (deltas[mid - 1] + deltas[mid]) / 2
}

/**
 * Huecos sin señal dentro de la ventana, incluidos los bordes.
 *
 * El primer hueco puede empezar en el borde izquierdo (el activo no latía
 * al empezar la ventana) y el último puede llegar al borde derecho (sigue
 * apagado ahora mismo): ambos son información y se pintan.
 *
 * En serie cruda el umbral es estricto (un hueco debe ser MAYOR que el
 * umbral). En serie agregada se descuenta la duración que cubre cada punto,
 * de forma que un cubo vacío exacto ya cuenta como ausencia.
 *
 * @param {number[]} timesMs - Instantes con datos (epoch ms), ordenados.
 * @param {number} thresholdMs - Umbral de `gapThresholdMs`.
 * @param {number} t0Ms - Inicio de la ventana.
 * @param {number} t1Ms - Fin de la ventana.
 * @param {number} coveredMs - Tiempo que cubre cada punto agregado.
 * @returns {Array<{start: number, end: number}>} Huecos, en ms.
 */
export function detectGaps(timesMs, thresholdMs, t0Ms, t1Ms, coveredMs = 0) {
  const gaps = []
  let prev = t0Ms
  let previousIsPoint = false

  for (const t of timesMs) {
    const gapLength = t - prev - (previousIsPoint ? coveredMs : 0)
    const isGap = previousIsPoint && coveredMs
      ? gapLength >= thresholdMs
      : t - prev > thresholdMs
    if (isGap) {
      gaps.push({
        start: previousIsPoint
          ? (coveredMs ? Math.max(prev + coveredMs, t0Ms) : prev)
          : t0Ms,
        end: t,
      })
    }
    prev = t
    previousIsPoint = true
  }

  const tailLength = t1Ms - prev - (previousIsPoint ? coveredMs : 0)
  const tailIsGap = previousIsPoint && coveredMs
    ? tailLength >= thresholdMs
    : t1Ms - prev > thresholdMs
  if (tailIsGap) {
    gaps.push({
      start: previousIsPoint
        ? (coveredMs ? Math.max(prev + coveredMs, t0Ms) : prev)
        : t0Ms,
      end: t1Ms,
    })
  }

  return gaps
}

/**
 * Tiempo total sin señal dentro de la ventana.
 *
 * `detectGaps` ya dice DÓNDE están los huecos; esto dice CUÁNTO suman, que es
 * lo que permite escribir "sin señal 23 h 40 min de 24 h" en el pie. Sin esa
 * cifra, una ventana con un único pico y el resto vacío se lee como un
 * gráfico roto en lugar de como un equipo que estuvo apagado.
 *
 * Los huecos vienen de `detectGaps`, que los emite ordenados y disjuntos, así
 * que basta con sumarlos: no hay solapes que descontar.
 *
 * @param {Array<{start: number, end: number}>} gaps - Huecos de `detectGaps`.
 * @returns {number} Milisegundos sin señal (0 si no hay huecos).
 */
export function totalGapMs(gaps) {
  return gaps.reduce((total, gap) => total + Math.max(0, gap.end - gap.start), 0)
}

/**
 * Divide los puntos en tramos cuando el segmento entre dos de ellos cruza
 * una franja que no debe llevar trazado.
 *
 * @param {Array<{t: number}>} points - Puntos ordenados por instante.
 * @param {Array<{start: number, end: number}>} ranges - Franjas a respetar.
 * @returns {Array<Array<{t: number}>>} Tramos consecutivos.
 */
export function splitAtRanges(points, ranges) {
  if (!points.length) return []

  const segments = []
  let segment = [points[0]]
  for (let i = 1; i < points.length; i += 1) {
    const previous = points[i - 1]
    const point = points[i]
    const crossesRange = ranges.some((range) => previous.t < range.end && point.t > range.start)
    if (crossesRange) {
      segments.push(segment)
      segment = []
    }
    segment.push(point)
  }
  segments.push(segment)
  return segments
}

/**
 * Anchura útil del trazado, dejando un carril para las etiquetas del eje Y.
 *
 * @param {number} totalWidth - Anchura total del SVG en píxeles.
 * @returns {number} Anchura del área de datos.
 */
export function plotWidthForAxis(totalWidth) {
  return Math.max(0, totalWidth - 64)
}

/* ── Formato de lectura ────────────────────────────────────────────────── */

/**
 * Une número y unidad de un valor formateado: pegados en porcentaje
 * ("37%"), separados en el resto ("9.4 MB/s").
 *
 * @param {{text: string, unit: string}} formatted - Salida de un `fmt` de serie.
 * @returns {string}
 */
export function formatValue(formatted) {
  if (!formatted.unit) return formatted.text
  return formatted.unit === '%' ? `${formatted.text}%` : `${formatted.text} ${formatted.unit}`
}

/**
 * Duración en lenguaje natural ("45 min", "3 h 12 min", "2 d 4 h").
 *
 * @param {number} ms - Milisegundos.
 * @returns {string}
 */
export function fmtDuration(ms) {
  const secs = Math.round(ms / 1000)
  if (secs < 60) return `${secs} s`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins} min`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} h ${mins % 60} min`
  const days = Math.floor(hours / 24)
  return `${days} d ${hours % 24} h`
}

/* ── Ventanas temporales ───────────────────────────────────────────────── */

/**
 * Presets de ventana del filtro de la pestaña Gráficas.
 *
 * Hasta 1 h la serie viaja cruda (cabe en el tope de puntos del servidor
 * incluso a cadencia mínima de 5 s); a partir de 6 h se pide agregada por
 * cubos (`bucketSec`), porque 24 h de heartbeats de 15 s serían 5.760
 * puntos y el servidor recorta a 1.000. El tamaño del cubo se elige para
 * que la ventana quepa entera (~300 cubos).
 */
export const WINDOW_PRESETS = [
  { label: '15m', ms: 15 * 60e3,    bucketSec: null },
  { label: '1h',  ms: 60 * 60e3,    bucketSec: null },
  { label: '6h',  ms: 6 * 3600e3,   bucketSec: 60 },
  { label: '24h', ms: 24 * 3600e3,  bucketSec: 300 },
  { label: '7d',  ms: 7 * 86400e3,  bucketSec: 1800 },
]

export const DEFAULT_WINDOW_MS = 60 * 60e3

/**
 * Cubo de agregación que corresponde a una ventana.
 *
 * @param {number} ms - Duración de la ventana (un valor de `WINDOW_PRESETS`).
 * @returns {number|null} Segundos del cubo, o null si la ventana va cruda.
 */
export function bucketForWindow(ms) {
  return WINDOW_PRESETS.find((w) => w.ms === ms)?.bucketSec ?? null
}
