// Sin dependencias a propósito: los tests de este fichero son Node puro, sin
// Vite, así que no pueden resolver el alias `@` ni cargar Vue ni Pinia.

/**
 * Ventanas temporales rápidas del visor de logs.
 *
 * Cada atajo es solo un número de minutos con nombre. La ventana no se
 * convierte aquí en un par de fechas: se manda al backend como `lastMinutes`
 * y es él quien la resuelve contra su propio reloj. Las marcas del log no
 * llevan zona horaria —son la hora local de la API—, así que si el navegador
 * calculara «hace diez minutos», un administrador conectado desde otro huso
 * pediría una ventana desplazada por la diferencia horaria.
 *
 * El valor `null` de `TODO` significa «sin límite inferior»: no manda
 * `lastMinutes`, y el backend lee el fichero entero.
 */
export const LOG_WINDOWS = [
  { id: '10m', label: '10 min', minutes: 10 },
  { id: '30m', label: '30 min', minutes: 30 },
  { id: '1h', label: '1 hora', minutes: 60 },
  { id: '6h', label: '6 horas', minutes: 360 },
  { id: '24h', label: '24 horas', minutes: 1440 },
  { id: '7d', label: '7 días', minutes: 10080 },
  { id: 'all', label: 'Todo', minutes: null },
]

export const DEFAULT_WINDOW_ID = '1h'

/** Minutos del atajo indicado, o `null` si no acota (o no existe). */
export function windowMinutes(windowId) {
  const found = LOG_WINDOWS.find((option) => option.id === windowId)
  return found ? found.minutes : null
}

/** Etiqueta legible del atajo, para los textos de la vista. */
export function windowLabel(windowId) {
  const found = LOG_WINDOWS.find((option) => option.id === windowId)
  return found ? found.label : ''
}

/**
 * Traduce los filtros de la vista a los parámetros de `GET /system/logs`.
 *
 * Se separa de la store para poder probarlo sin navegador: es donde vive la
 * decisión de qué combinaciones son excluyentes, y el backend rechaza con un
 * 400 las que no lo respetan (mandar a la vez `lastMinutes` y `from` es
 * ambiguo, así que un atajo activo desactiva las fechas escritas a mano).
 */
export function buildLogQuery(filters) {
  const params = new URLSearchParams({
    page: String(filters.page || 1),
    per_page: String(filters.perPage || 100),
    position: filters.position || 'tail',
  })

  const minutes = filters.windowId ? windowMinutes(filters.windowId) : null
  if (minutes !== null) {
    params.set('lastMinutes', String(minutes))
  } else if (!filters.windowId || filters.windowId === 'custom') {
    if (filters.from) params.set('from', filters.from)
    if (filters.to) params.set('to', filters.to)
  }

  if (filters.level) params.set('level', filters.level)
  if (filters.minLevel) params.set('minLevel', filters.minLevel)
  if (filters.contains) params.set('contains', filters.contains)

  return params
}
