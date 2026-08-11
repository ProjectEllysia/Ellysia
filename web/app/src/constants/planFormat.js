/**
 * Cómo se lee un plan: etiquetas, precios y límites.
 *
 * Vivía dentro de `PlansView.vue`. La portada enseña ahora una versión
 * resumida del catálogo y necesita exactamente lo mismo, así que en vez de
 * copiar seis funciones se sacan aquí: si mañana cambia cómo se dice
 * "ilimitado", cambia en un sitio y no en dos que se van separando.
 *
 * Módulo plano, sin `ref` ni composable: son funciones puras sobre el JSON que
 * devuelve `GET /plans`. Mismo criterio que `components/hygeia/format.js`.
 */

/**
 * Las claves que se enseñan, de las 15 que trae cada plan. El orden importa:
 * es el que se pinta.
 */
export const FEATURED = [
  'themis.lybra.scans',
  'iris.analyses',
  'acheron.items',
  'hygeia.assets',
  'ai.requests',
  'organization.members',
]

/** Las tres que mejor resumen un plan de un vistazo, para la portada. */
export const HEADLINE = [
  'themis.lybra.scans',
  'hygeia.assets',
  'iris.analyses',
]

export const LABELS = {
  'themis.lybra.scans': 'Escaneos de vulnerabilidades',
  'iris.analyses': 'Análisis de correo',
  'acheron.items': 'Secretos en la bóveda',
  'hygeia.assets': 'Activos monitorizados',
  'ai.requests': 'Peticiones a la IA',
  'organization.members': 'Miembros de la organización',
}

/** Etiquetas cortas para la portada, donde no hay ancho para las largas. */
export const SHORT_LABELS = {
  'themis.lybra.scans': 'Escaneos',
  'iris.analyses': 'Análisis de correo',
  'acheron.items': 'Secretos',
  'hygeia.assets': 'Activos',
  'ai.requests': 'Peticiones a la IA',
  'organization.members': 'Miembros',
}

export function euros(cents) {
  return `${(cents / 100).toLocaleString('es-ES', { maximumFractionDigits: 0 })} €`
}

/** El límite del titular del plan (no el de sus miembros). */
export function limitOf(plan, key) {
  return plan.limits?.holder?.[key]
}

export function isZero(plan, key) {
  const limit = limitOf(plan, key)
  return !limit || limit.value === 0
}

/**
 * El límite en palabras.
 *
 * `null` y `0` NO son lo mismo y el backend lo documenta así: `null` significa
 * ilimitado y `0` significa que el plan no incluye la característica.
 */
export function describe(plan, key) {
  const limit = limitOf(plan, key)
  if (!limit || limit.value === 0) return 'No incluido'
  if (limit.value === null) return 'Ilimitado'
  return limit.period === 'month' ? `${limit.value} al mes` : `${limit.value}`
}
