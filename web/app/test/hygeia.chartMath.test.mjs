/**
 * Test de la lógica pura del gráfico de Hygeia (`components/hygeia/chartMath.js`).
 *
 * Funciones puras sin DOM ni Vue: se ejecutan con `node` a secas, mismo
 * precedente que el resto de `test/`, sin framework.
 *
 *   node web/app/test/hygeia.chartMath.test.mjs
 */

import {
  SERIES, niceCeil, yRange, yTicks, timeTicks, formatTimeTick, fmtDuration,
  medianDeltaMs, gapThresholdMs, detectGaps, totalGapMs, splitAtRanges, formatValue, bucketForWindow,
  plotWidthForAxis, WINDOW_PRESETS, DEFAULT_WINDOW_MS,
} from '../src/components/hygeia/chartMath.js'

let passed = 0
let failed = 0
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

function eq(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  check(name, a === e, `esperado ${e}, obtenido ${a}`)
}

console.log('\ncatálogo de series')
check('las siete métricas registrables', SERIES.length === 7)
check('claves únicas', new Set(SERIES.map((s) => s.key)).size === SERIES.length)
eq('porcentajes con techo natural 100', SERIES.filter((s) => s.fixedMax === 100).map((s) => s.key),
  ['cpu', 'mem', 'swap', 'disk'])
check('carga (load1) existe y es la séptima', SERIES[6].key === 'load1' && SERIES[6].fixedMax === null)
check('red y carga sin techo', ['net-rx', 'net-tx', 'load1'].every((k) => SERIES.find((s) => s.key === k).fixedMax === null))

console.log('\nniceCeil')
eq('redondea a paso bonito', niceCeil(245760), 250000)
eq('enteros a centena', niceCeil(96), 100)
eq('fracciones pequeñas', niceCeil(0.42), 0.5)
eq('ya bonito se queda', niceCeil(2500), 2500)
eq('potencias exactas', niceCeil(1000), 1000)
eq('cero y negativos no escalan', [niceCeil(0), niceCeil(-4)], [0, 0])
eq('no finito no escalan', niceCeil(NaN), 0)

console.log('\nyRange / yTicks')
const cpu = SERIES.find((s) => s.key === 'cpu')
const net = SERIES.find((s) => s.key === 'net-rx')
const load = SERIES.find((s) => s.key === 'load1')
eq('CPU con techo fijo aunque el dato sea bajo', yRange(cpu, [45, 12, 37]), { lo: 0, hi: 100 })
eq('CPU plano también fijo', yRange(cpu, [9, 9, 9]), { lo: 0, hi: 100 })
eq('rejilla fija 0-100', yTicks(cpu, yRange(cpu, [45])), [0, 25, 50, 75, 100])
const netRange = yRange(net, [120000])
check('red escala a máximo bonito con aire', netRange.hi >= 120000 * 1.2 && netRange.hi % 1000 === 0)
const loadRange = yRange(load, [2.3])
eq('carga con suelo de amplitud', loadRange, { lo: 0, hi: 3 })
check('rejilla de carga creciente y dentro del rango',
  yTicks(load, loadRange).every((t, i, a) => i === 0 || t > a[i - 1]) && yTicks(load, loadRange).at(-1) <= loadRange.hi)
eq('red plana no amplifica ruido', yRange(net, [500]), { lo: 0, hi: 8192 })

console.log('\ntimeTicks')
const ticks = timeTicks(0, 60000, 4)
eq('extremos incluidos', [ticks[0], ticks[ticks.length - 1]], [0, 60000])
eq('paso equidistante', ticks[1] - ticks[0], 15000)
eq('cuatro intervalos, cinco instantes', ticks.length, 5)

console.log('\nformatTimeTick')
const TZ_SHIFT = new Date(0).getTimezoneOffset() * 60000
eq('ventana corta: solo hora', formatTimeTick(TZ_SHIFT, 3600e3), '00:00')
eq('hora de tarde', formatTimeTick(TZ_SHIFT + 14 * 3600e3, 3600e3), '14:00')
check('ventana de días añade la fecha', /^\d{2}\/\d{2} \d{2}:\d{2}$/.test(formatTimeTick(TZ_SHIFT, 7 * 86400e3)))

console.log('\nfmtDuration')
eq('segundos', fmtDuration(45e3), '45 s')
eq('minutos', fmtDuration(12 * 60e3), '12 min')
eq('horas y minutos', fmtDuration((3 * 3600 + 12 * 60) * 1000), '3 h 12 min')
eq('días y horas', fmtDuration((2 * 86400 + 4 * 3600) * 1000), '2 d 4 h')
eq('horas redondas sin el cero de los minutos', fmtDuration(6 * 3600e3), '6 h')
eq('un dia redondo sin el cero de las horas', fmtDuration(24 * 3600e3), '1 d')
eq('una semana redonda', fmtDuration(7 * 86400e3), '7 d')

console.log('\nmedianDeltaMs')
eq('mediana impar (3 deltas)', medianDeltaMs([0, 1000, 4000, 5000]), 1000)
eq('mediana par (4 deltas)', medianDeltaMs([0, 1000, 4000, 5000, 11000]), 2000)
eq('un solo instante no tiene mediana', medianDeltaMs([0]), null)
eq('vacío no tiene mediana', medianDeltaMs([]), null)

console.log('\ngapThresholdMs')
eq('crudo: 3 × mediana con suelo de 90 s', gapThresholdMs(15000, null), 90000)
eq('crudo: mediana alta manda', gapThresholdMs(120000, null), 360000)
eq('sin mediana: suelo crudo', gapThresholdMs(null, null), 90000)
eq('agregado: un cubo entero de suelo', gapThresholdMs(15000, 300), 300000)
eq('agregado: el factor aún manda con mediana grande', gapThresholdMs(120000, 300), 360000)

console.log('\ndetectGaps')
const thr = 60000
eq('sin huecos', detectGaps([0, 30000, 60000], thr, 0, 90000), [])
eq('hueco interior', detectGaps([0, 30000, 120000], thr, 0, 150000),
  [{ start: 30000, end: 120000 }])
eq('espaciado exacto al umbral no es caída', detectGaps([60000, 120000], thr, 0, 180000), [])
eq('borde izquierdo (aún no latía)', detectGaps([120000, 180000], thr, 0, 240000),
  [{ start: 0, end: 120000 }])
eq('borde derecho (sigue apagado)', detectGaps([0, 60000], thr, 0, 180000),
  [{ start: 60000, end: 180000 }])
eq('hueco interior grande y borde derecho', detectGaps([0, 120000, 300000], thr, 0, 420000),
  [{ start: 0, end: 120000 }, { start: 120000, end: 300000 }, { start: 300000, end: 420000 }])
eq('sin datos: toda la ventana es hueco', detectGaps([], thr, 0, 120000),
  [{ start: 0, end: 120000 }])
eq('hueco entre cubos empieza tras el cubo ocupado',
  detectGaps([0, 120000], thr, 0, 180000, 60000),
  [{ start: 60000, end: 120000 }])
eq('hueco al final empieza tras el ultimo cubo ocupado',
  detectGaps([0], thr, 0, 180000, 60000),
  [{ start: 60000, end: 180000 }])
eq('un tramo parcial tras el cubo no es una caida',
  detectGaps([0, 60000], thr, 0, 150000, 60000), [])
eq('el hueco inicial de cubos empieza en el borde de ventana',
  detectGaps([150000], thr, 0, 180000, 60000),
  [{ start: 0, end: 150000 }])

console.log('\ntiempo total sin senal')
eq('sin huecos no hay ausencia', totalGapMs([]), 0)
eq('suma los huecos sueltos',
  totalGapMs([{ start: 0, end: 60000 }, { start: 120000, end: 300000 }]), 240000)
eq('una ventana entera sin datos suma la ventana entera',
  totalGapMs(detectGaps([], thr, 0, 24 * 3600e3)), 24 * 3600e3)
eq('un pico aislado deja el resto de la ventana sin senal',
  totalGapMs(detectGaps([3600e3], thr, 0, 24 * 3600e3)), 24 * 3600e3)
eq('ignora franjas invertidas en vez de restar tiempo',
  totalGapMs([{ start: 300000, end: 120000 }]), 0)

console.log('\ntramos del trazado')
const trace = [{ t: 0 }, { t: 60000 }, { t: 120000 }, { t: 180000 }]
eq('corta el trazado al atravesar una franja roja',
  splitAtRanges(trace, [{ start: 60000, end: 120000 }]).map((part) => part.map((p) => p.t)),
  [[0, 60000], [120000, 180000]])
eq('corta el trazado en varias franjas',
  splitAtRanges(trace, [{ start: 0, end: 60000 }, { start: 150000, end: 180000 }])
    .map((part) => part.map((p) => p.t)),
  [[0], [60000, 120000], [180000]])

console.log('\ncarril del eje Y')
eq('reserva espacio para el eje Y en escritorio', plotWidthForAxis(900), 836)
eq('reserva espacio suficiente para etiquetas de tasa', plotWidthForAxis(300), 236)

console.log('\nformatValue')
eq('porcentaje pegado', formatValue({ text: '37', unit: '%' }), '37%')
eq('tasa separada', formatValue({ text: '9.4', unit: 'MB/s' }), '9.4 MB/s')
eq('sin unidad, texto a secas', formatValue({ text: '1.5', unit: '' }), '1.5')

console.log('\nventanas')
eq('presets cubren 15m a 7d', WINDOW_PRESETS.map((w) => w.label), ['15m', '1h', '6h', '24h', '7d'])
eq('cortas van crudas', [bucketForWindow(WINDOW_PRESETS[0].ms), bucketForWindow(WINDOW_PRESETS[1].ms)], [null, null])
eq('largas agregan por cubos', [bucketForWindow(WINDOW_PRESETS[2].ms), bucketForWindow(WINDOW_PRESETS[3].ms), bucketForWindow(WINDOW_PRESETS[4].ms)], [60, 300, 1800])
eq('desconocida no agrega', bucketForWindow(1234567), null)
eq('la ventana por defecto es 1 h', DEFAULT_WINDOW_MS, 3600e3)

console.log(`\n${passed} pasados, ${failed} fallidos\n`)
process.exit(failed === 0 ? 0 : 1)
