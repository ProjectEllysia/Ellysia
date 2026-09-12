/**
 * Test de los formateadores de Hygeia (`components/hygeia/format.js`).
 *
 * Son funciones puras sin DOM, así que se ejecutan con `node` a secas — mismo
 * precedente que los tests de Acheron, sin introducir un framework nuevo.
 *
 *   node web/app/test/hygeia.format.test.mjs
 */

import {
  fmtBytes, fmtRate, fmtUptime, fmtPct, fmtLoad1,
  fmtWatts, classifyPower, fmtEnergy, fmtCost, describePowerPeriod,
  anomalyKindLabel, assetStatusLabel,
} from '../src/components/hygeia/format.js'

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

console.log('\nfmtBytes')
eq('bytes crudos sin escalar', fmtBytes(512), { text: '512', unit: 'B' })
eq('escala a KB', fmtBytes(2048), { text: '2.0', unit: 'KB' })
eq('escala a MB', fmtBytes(5 * 1024 * 1024), { text: '5.0', unit: 'MB' })
eq('entero a partir de 10', fmtBytes(42 * 1024 * 1024), { text: '42', unit: 'MB' })
eq('escala a GB', fmtBytes(412 * 1024 ** 3), { text: '412', unit: 'GB' })
eq('cero es un dato, no una ausencia', fmtBytes(0), { text: '0', unit: 'B' })

console.log('\nfmtRate')
eq('tasa en B/s', fmtRate(900), { text: '900', unit: 'B/s' })
eq('tasa en KB/s', fmtRate(120000), { text: '117', unit: 'KB/s' })
eq('tasa en MB/s', fmtRate(9.4 * 1024 * 1024), { text: '9.4', unit: 'MB/s' })
eq('tasa nula es dato', fmtRate(0), { text: '0', unit: 'B/s' })

console.log('\nausencia de dato')
const NO_DATA = { text: '—', unit: '' }
eq('fmtBytes(null)', fmtBytes(null), NO_DATA)
eq('fmtBytes(undefined)', fmtBytes(undefined), NO_DATA)
eq('fmtBytes(NaN)', fmtBytes(NaN), NO_DATA)
eq('fmtRate(null)', fmtRate(null), NO_DATA)
check('fmtPct(null) mantiene su sentinel de cadena', fmtPct(null) === '—')

console.log('\nfmtUptime')
eq('minutos', fmtUptime(48 * 60), '48 min')
eq('horas y minutos', fmtUptime(3 * 3600 + 12 * 60), '3 h 12 min')
eq('días y horas', fmtUptime(12 * 86400 + 4 * 3600), '12 d 4 h')
eq('segundos sueltos', fmtUptime(42), '42 s')
eq('sin dato', fmtUptime(null), '—')
eq('negativo no es un uptime', fmtUptime(-5), '—')

console.log('\nfmtLoad1')
eq('carga con un decimal', fmtLoad1(1.5), '1.5')
eq('cero es un dato, no una ausencia', fmtLoad1(0), '0.0')
eq('sin dato (Windows no la reporta)', fmtLoad1(null), '—')

console.log('\nfmtWatts (P19)')
eq('vatios sueltos', fmtWatts(45), { text: '45', unit: 'W' })
eq('un decimal por debajo de 10', fmtWatts(4.7), { text: '4.7', unit: 'W' })
eq('cero es un dato, no una ausencia', fmtWatts(0), { text: '0.0', unit: 'W' })
eq('escala a kW por encima de 1000 W', fmtWatts(1500), { text: '1.5', unit: 'kW' })
eq('kW entero a partir de 10', fmtWatts(12000), { text: '12', unit: 'kW' })
eq('sin dato', fmtWatts(null), NO_DATA)

console.log('\nclassifyPower (P20)')
eq('sin bloque de potencia: no disponible',
  classifyPower(null),
  { state: 'unavailable', watts: null, estimated: null, source: null, virtualizationSystem: null })
eq('watts null: no disponible aunque el bloque exista',
  classifyPower({ watts: null, estimated: false, source: 'rapl' }),
  { state: 'unavailable', watts: null, estimated: null, source: null, virtualizationSystem: null })
eq('estimated false: medición',
  classifyPower({ watts: 187.5, estimated: false, source: 'rapl' }),
  { state: 'measured', watts: 187.5, estimated: false, source: 'rapl', virtualizationSystem: null })
eq('estimated true: estimación',
  classifyPower({ watts: 60, estimated: true, source: 'windows-model' }),
  { state: 'estimated', watts: 60, estimated: true, source: 'windows-model', virtualizationSystem: null })
eq('watts=0 es una medición, no una ausencia (el borde que sostiene la Fase 3)',
  classifyPower({ watts: 0, estimated: false, source: 'smart-plug' }),
  { state: 'measured', watts: 0, estimated: false, source: 'smart-plug', virtualizationSystem: null })

console.log('\nclassifyPower — virtualización (P29)')
eq('invitado sin potencia: estado "virtual" con el hipervisor',
  classifyPower(null, { role: 'guest', system: 'kvm' }),
  { state: 'virtual', watts: null, estimated: null, source: null, virtualizationSystem: 'kvm' })
eq('host sin potencia: sigue siendo el genérico "no disponible"',
  classifyPower(null, { role: 'host', system: null }),
  { state: 'unavailable', watts: null, estimated: null, source: null, virtualizationSystem: null })
eq('rol desconocido (o ausente) sin potencia: genérico, nunca se exige una lista cerrada',
  classifyPower(null, { role: null, system: null }),
  { state: 'unavailable', watts: null, estimated: null, source: null, virtualizationSystem: null })
eq('sin el segundo argumento: se comporta igual que antes de P29',
  classifyPower(null),
  { state: 'unavailable', watts: null, estimated: null, source: null, virtualizationSystem: null })
eq('invitado CON potencia: la lectura manda, no es "virtual"',
  classifyPower({ watts: 5.0, estimated: true, source: 'guest-model' }, { role: 'guest', system: 'kvm' }),
  { state: 'estimated', watts: 5.0, estimated: true, source: 'guest-model', virtualizationSystem: null })

console.log('\nfmtEnergy / fmtCost')
eq('energía con dos decimales por debajo de 10', fmtEnergy(1.234), { text: '1.23', unit: 'kWh' })
eq('energía con un decimal a partir de 10', fmtEnergy(23.456), { text: '23.5', unit: 'kWh' })
eq('sin energía observada', fmtEnergy(null), NO_DATA)
eq('coste en euros', fmtCost(1.5, 'EUR'), { text: '1.50', unit: '€' })
eq('coste en una moneda sin símbolo conocido usa el código', fmtCost(2, 'JPY'), { text: '2.00', unit: 'JPY' })
eq('sin coste', fmtCost(null, 'EUR'), NO_DATA)

console.log('\ndescribePowerPeriod (P24/P25)')
eq('periodo observado',
  describePowerPeriod({ kwh: 1.0, cost: 0.15, currency: 'EUR', classification: 'observed', coverageFraction: 0.97 }),
  {
    kwh: { text: '1.00', unit: 'kWh' }, cost: { text: '0.15', unit: '€' },
    classification: 'observed', classificationLabel: 'Observado', coverageFraction: 0.97,
  })
eq('periodo proyectado', describePowerPeriod({
  kwh: 30, cost: 4.5, currency: 'EUR', classification: 'projected', coverageFraction: null,
}).classificationLabel, 'Proyección')
eq('periodo nulo no rompe', describePowerPeriod(null), null)

console.log('\nanomalyKindLabel')
eq('tipo conocido', anomalyKindLabel('host_down'), 'Host caído')
eq('tipo desconocido: rótulo genérico, nunca el identificador crudo', anomalyKindLabel('disk_io_high'), 'Anomalía')
eq('sin tipo', anomalyKindLabel(null), 'Anomalía')

console.log('\nassetStatusLabel')
eq('estado conocido', assetStatusLabel('stale'), 'Inestable')
eq('estado desconocido: rótulo genérico, nunca el valor crudo', assetStatusLabel('degraded'), 'Desconocido')

console.log(`\n${passed} pasados, ${failed} fallidos\n`)
process.exit(failed === 0 ? 0 : 1)
