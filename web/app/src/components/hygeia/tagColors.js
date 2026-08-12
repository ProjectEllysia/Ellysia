/**
 * Traducción de los nombres de color que guarda la API (`TAG_COLORS` en
 * `schemas.py`) al matiz que se pinta.
 *
 * La base de datos guarda «amber», no `#d9a441`: así el matiz exacto se puede
 * retocar aquí sin reescribir una sola fila, y un cambio de tema no obliga a
 * migrar nada. Un único mapa para las dos cosas que necesitan color —el badge
 * y el selector de swatches—, para que no puedan desincronizarse.
 *
 * Los matices están elegidos para leerse sobre el fondo oscuro por defecto; el
 * tema claro los oscurece en el propio badge, no aquí.
 */
export const TAG_HUES = {
  slate:  '#8a93a6',
  green:  '#5a8f6d',
  teal:   '#3fa39b',
  blue:   '#5b8fd6',
  violet: '#9b7bd4',
  amber:  '#d9a441',
  red:    '#d2603f',
  pink:   '#d46fa0',
}

/** Nombres de la paleta, en el orden en que se ofrecen al elegir. */
export const TAG_COLOR_NAMES = Object.keys(TAG_HUES)

/** Matiz de un color, con «slate» como red de seguridad si llega uno desconocido. */
export function hueOf(color) {
  return TAG_HUES[color] || TAG_HUES.slate
}
