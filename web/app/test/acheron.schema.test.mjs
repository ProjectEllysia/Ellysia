/**
 * Correspondencia entre el esquema de storables y sus etiquetas.
 *
 * El contrato de datos y `storableLabels.js` (lo que se
 * ve en pantalla) vivían en el mismo literal y era imposible desincronizarlos.
 * Al separarlos, esa imposibilidad desapareció: si el esquema añade un campo y
 * las etiquetas no, el formulario pinta un `undefined` donde iba un nombre; si
 * sobra una etiqueta, queda código muerto que nadie ve.
 *
 * La comprobación es en AMBOS sentidos a propósito. Verificar sólo que "todo
 * campo tiene etiqueta" deja pasar el caso de la etiqueta que sobra, que es
 * justo el que aparece al borrar un campo del esquema.
 *
 * Sin este test la separación sería un riesgo neto en lugar de una mejora.
 *
 * El esquema ya no vive aquí: llega de `@projectellysia/acheron-core-web`, que
 * a su vez lo copia de `AcheronSchema` y lo verifica en su propia suite. Lo que
 * queda por comprobar en la SPA es lo que solo la SPA tiene: que sus etiquetas
 * sigan describiendo los campos que el paquete declara.
 *
 *   node web/app/test/acheron.schema.test.mjs
 */

import { STORABLE_SCHEMA } from '@projectellysia/acheron-core-web'
import { STORABLE_LABELS } from '../src/acheron/storableLabels.js'
import { STORABLE_TYPES } from '../src/acheron/storableTypes.js'

let passed = 0
let failed = 0

function check(name, condition, detail = '') {
  if (condition) {
    passed++
    console.log(`  ✓ ${name}`)
  } else {
    failed++
    console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`)
  }
}

/** Diferencia de conjuntos, como lista ordenada para que el mensaje sea legible. */
const missingFrom = (wanted, have) => wanted.filter((x) => !have.includes(x)).sort()

console.log('Correspondencia esquema ↔ etiquetas\n')

/* ── 1) Cada tipo del esquema tiene su bloque de etiquetas, y al revés ── */

const schemaKinds = STORABLE_SCHEMA.map((t) => t.kind)
const labelKinds = Object.keys(STORABLE_LABELS)

check(
  'todo tipo del esquema tiene etiquetas',
  missingFrom(schemaKinds, labelKinds).length === 0,
  `sin etiquetas: ${missingFrom(schemaKinds, labelKinds).join(', ')}`,
)
check(
  'no sobra ningún bloque de etiquetas',
  missingFrom(labelKinds, schemaKinds).length === 0,
  `etiquetas huérfanas: ${missingFrom(labelKinds, schemaKinds).join(', ')}`,
)

/* ── 2) Campo a campo, en ambos sentidos ── */

for (const type of STORABLE_SCHEMA) {
  const labels = STORABLE_LABELS[type.kind]
  if (!labels) continue // ya reportado arriba

  const schemaFields = type.fields.map((f) => f.key)
  const labelFields = Object.keys(labels.fields ?? {})

  check(
    `${type.kind}: todo campo tiene etiqueta`,
    missingFrom(schemaFields, labelFields).length === 0,
    `sin etiqueta: ${missingFrom(schemaFields, labelFields).join(', ')}`,
  )
  check(
    `${type.kind}: no sobra ninguna etiqueta`,
    missingFrom(labelFields, schemaFields).length === 0,
    `huérfanas: ${missingFrom(labelFields, schemaFields).join(', ')}`,
  )

  // Una etiqueta vacía pinta igual de mal que una ausente.
  for (const [key, field] of Object.entries(labels.fields ?? {})) {
    check(
      `${type.kind}.${key}: la etiqueta no está vacía`,
      typeof field.label === 'string' && field.label.trim() !== '',
      `label = ${JSON.stringify(field.label)}`,
    )
  }

  for (const meta of ['label', 'plural', 'newLabel']) {
    check(
      `${type.kind}: tiene ${meta}`,
      typeof labels[meta] === 'string' && labels[meta].trim() !== '',
      `${meta} = ${JSON.stringify(labels[meta])}`,
    )
  }
}

/* ── 3) El esquema que sirve el paquete no lleva texto visible ── */

// El paquete ya lo valida en su suite, pero comprobarlo aquí cuesta nada y
// cubre el caso de que alguien "arregle" un undefined en el formulario
// parcheando el esquema en node_modules en vez de las etiquetas.
const TEXTO_VISIBLE = ['label', 'plural', 'newLabel', 'subtitleKey']
for (const type of STORABLE_SCHEMA) {
  const enTipo = TEXTO_VISIBLE.filter((k) => k in type)
  check(
    `${type.kind}: el esquema no lleva texto visible`,
    enTipo.length === 0,
    `encontrado: ${enTipo.join(', ')}`,
  )
  for (const field of type.fields) {
    const enCampo = TEXTO_VISIBLE.filter((k) => k in field)
    check(
      `${type.kind}.${field.key}: el campo del esquema no lleva texto visible`,
      enCampo.length === 0,
      `encontrado: ${enCampo.join(', ')}`,
    )
  }
}

/* ── 4) La vista compuesta sirve lo que el formulario espera ── */

for (const type of STORABLE_TYPES) {
  const sinLabel = type.fields.filter((f) => !f.label).map((f) => f.key)
  check(
    `${type.kind}: compuesto, todo campo trae label`,
    sinLabel.length === 0,
    `sin label tras componer: ${sinLabel.join(', ')}`,
  )
  const sinKey = type.fields.filter((f) => !f.key).length
  check(`${type.kind}: compuesto, todo campo conserva su key`, sinKey === 0)
}

console.log(`\nResultado: ${passed} OK, ${failed} fallidos`)
if (failed > 0) process.exit(1)
