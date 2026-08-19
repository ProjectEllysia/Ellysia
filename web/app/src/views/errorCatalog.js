/**
 * Catálogo de errores HTTP de la SPA.
 *
 * Es el único sitio que hay que tocar para añadir (o afinar) una página de
 * error: `ErrorView.vue` resuelve el código contra este catálogo y monta la
 * entrada correspondiente. Un código sin entrada cae en una página genérica
 * (o en la de 500 si es un error de servidor), así que ninguna URL puede
 * terminar en una pantalla en blanco.
 *
 * Cada entrada:
 * - `title`: titular de la página.
 * - `paragraphs`: párrafos explicativos.
 * - `links`: enlaces de salida; se renderizan como "Desde aquí puedes ...".
 *   Las etiquetas llevan el verbo y el artículo incorporados para que la
 *   frase suene bien sin tener que concordar nada.
 * - `reload`: opcional; si es true, la vista muestra un botón de recarga.
 */
export const ERROR_CATALOG = {
  404: {
    title: 'Esta página no existe',
    paragraphs: [
      'La dirección a la que has llegado no corresponde a ninguna página de Ellysia. Puede que el enlace esté mal escrito, o que la página se moviera de sitio.',
    ],
    links: [
      { to: '/', label: 'volver a la portada' },
      { to: '/themis', label: 'ver las herramientas' },
      { to: '/planes', label: 'consultar los planes' },
    ],
  },
  403: {
    title: 'No tienes permiso para ver esto',
    paragraphs: [
      'La página existe, pero tu cuenta no puede abrirla: es una sección restringida a un rol concreto, o la sesión cambió de permisos desde que entraste.',
      'Si crees que deberías poder acceder, ponte en contacto con quien administra Ellysia.',
    ],
    links: [
      { to: '/', label: 'volver a la portada' },
      { to: '/themis', label: 'ver las herramientas' },
      { to: '/planes', label: 'consultar los planes' },
    ],
  },
  409: {
    title: 'La operación no se pudo completar',
    paragraphs: [
      'Lo que intentabas hacer choca con el estado actual de los datos: el elemento puede que ya exista, que haya cambiado desde que lo cargaste o que la acción ya se hubiera hecho antes.',
      'Recarga la página para ver el estado actual e inténtalo de nuevo.',
    ],
    reload: true,
    links: [
      { to: '/', label: 'volver a la portada' },
      { to: '/themis', label: 'ver las herramientas' },
    ],
  },
  500: {
    title: 'Algo se ha roto',
    paragraphs: [
      'La página ha fallado al cargar: el servidor ha respondido con un error. No es culpa de lo que estuvieras haciendo, y normalmente basta con reintentar.',
      'Si el problema persiste, vuelve a intentarlo en unos minutos.',
    ],
    reload: true,
    links: [
      { to: '/', label: 'volver a la portada' },
    ],
  },
}

/**
 * Entrada genérica para códigos 4xx sin entrada propia en el catálogo.
 * `title` es una función porque lleva el código dentro.
 */
function genericEntry(code) {
  return {
    title: `Error ${code}`,
    paragraphs: [
      'Algo no ha salido como se esperaba y esta página no sabe decirte mucho más. Vuelve a la portada; si el problema se repite, guarda este código por si necesitas referirte a él.',
    ],
    links: [
      { to: '/', label: 'volver a la portada' },
      { to: '/planes', label: 'consultar los planes' },
    ],
  }
}

/**
 * Resuelve un código HTTP contra el catálogo.
 *
 * - Entrada exacta → esa.
 * - 5xx sin entrada → la de 500 (cualquier error de servidor se explica
 *   igual de bien con su copia).
 * - 4xx sin entrada → entrada genérica con el código.
 * - Código inválido o ausente → 404.
 *
 * @param {string|number|undefined} code - Código HTTP (ruta, meta o query).
 * @returns {{ code: number, entry: object }} Código normalizado y su entrada.
 */
export function resolveError(code) {
  const numeric = Number(code)
  if (!Number.isInteger(numeric) || numeric < 100 || numeric > 599) {
    return { code: 404, entry: ERROR_CATALOG[404] }
  }
  const entry = ERROR_CATALOG[numeric] ?? (numeric >= 500 ? ERROR_CATALOG[500] : genericEntry(numeric))
  return { code: numeric, entry }
}
