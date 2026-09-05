/**
 * Vista compuesta de los tipos de storable para la interfaz: une el contrato
 * de datos (`storableSchema.js`) con su presentación (`storableLabels.js`).
 *
 * Antes las dos cosas vivían en el mismo literal. Se separaron porque el
 * esquema tenía que viajar a un paquete compartido, y no se podía publicar sin
 * arrastrar las etiquetas en castellano: cambiar el texto de un botón habría
 * obligado a publicar una versión nueva del paquete de criptografía.
 *
 * Ya ha viajado: el esquema llega de `@projectellysia/acheron-core-web`, que a
 * su vez lo copia de `AcheronSchema`. Aquí solo quedan las etiquetas.
 *
 * La forma que exporta este fichero es la misma de antes, así que los
 * componentes no notan nada. La capa cripto NO pasa por aquí: vive en el
 * paquete y lee el esquema directamente, y por eso nunca ve una etiqueta.
 *
 * `acheron.schema.test.mjs` verifica que las dos mitades siguen hablando de
 * los mismos campos.
 */
import { STORABLE_SCHEMA } from '@projectellysia/acheron-core-web'
import { STORABLE_LABELS } from './storableLabels.js'

/**
 * Tipos con esquema y etiquetas fusionados. Cada campo lleva su `key` y
 * `secret` del esquema, más `label` y las pistas de formulario de las
 * etiquetas.
 */
export const STORABLE_TYPES = STORABLE_SCHEMA.map((type) => {
  const labels = STORABLE_LABELS[type.kind] ?? { fields: {} }
  return {
    ...type,
    ...labels,
    fields: type.fields.map((field) => ({
      ...field,
      ...(labels.fields[field.key] ?? {}),
    })),
  }
})

/** Spec por categoría (clave plural del vault JSON). */
export const TYPE_BY_CATEGORY = Object.fromEntries(STORABLE_TYPES.map((t) => [t.category, t]))

/** Spec por kind (singular de la API). */
export const TYPE_BY_KIND = Object.fromEntries(STORABLE_TYPES.map((t) => [t.kind, t]))
