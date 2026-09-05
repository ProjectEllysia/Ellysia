/**
 * Vista que necesita la capa cripto: qué campos tiene cada categoría y las
 * correspondencias categoría↔kind. Se DERIVA de `storableSchema.js`, el
 * contrato de datos, para que no pueda divergir de la API ni del móvil.
 *
 * Deriva del esquema y no de `storableTypes.js` a propósito: aquél lleva
 * además las etiquetas de la interfaz, y la criptografía no debe depender de
 * nada que se vea en pantalla.
 *
 * Cada campo aquí listado se cifra individualmente como Base64(IV‖ct). Además,
 * `title` SIEMPRE va cifrado (lo añade `vault.js`). Los metadatos `id`,
 * `createdAt`, `updatedAt`, `allowedUsers` van en claro.
 */
import { STORABLE_SCHEMA } from './storableSchema.js'

/** category → array de claves de campos sensibles. */
export const STORABLE_FIELDS = Object.fromEntries(
  STORABLE_SCHEMA.map((t) => [t.category, t.fields.map((f) => f.key)]),
)

/** Las categorías de storables presentes en un vault JSON, en orden. */
export const STORABLE_CATEGORIES = STORABLE_SCHEMA.map((t) => t.category)

/** category (plural, vault JSON) → kind (singular, API `POST /storables`). */
export const KIND_BY_CATEGORY = Object.fromEntries(
  STORABLE_SCHEMA.map((t) => [t.category, t.kind]),
)

/** kind → category. */
export const CATEGORY_BY_KIND = Object.fromEntries(
  STORABLE_SCHEMA.map((t) => [t.kind, t.category]),
)
