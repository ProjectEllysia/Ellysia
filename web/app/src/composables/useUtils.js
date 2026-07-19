/**
 * Utilidades comunes reutilizables en stores y componentes Vue.
 *
 * Sustituye a `SeqUI.formatDate()`, `getInitials()` y otras helpers del legacy.
 *
 * @example
 * import { useUtils } from '@/composables/useUtils'
 * const { formatDate, getInitials } = useUtils()
 * formatDate('2025–01–15T10:30:00Z')  // "15/01/2025"
 * getInitials('Ana', 'Garcia')         // "AG"
 */
export function useUtils() {
  /**
   * Convierte una fecha ISO en formato local corto (dd/mm/aaaa).
   * @param {string|null} iso - Fecha en formato ISO 8601
   * @returns {string} Fecha formateada, o cadena vacía si es null
   */
  function formatDate(iso) {
    if (!iso) return ''
    try {
      return new Date(iso).toLocaleDateString('es-ES', { year: 'numeric', month: '2-digit', day: '2-digit' })
    } catch { return iso }
  }

  /**
   * Devuelve las iniciales de un nombre y apellido.
   * @param {string} first - Nombre
   * @param {string} last - Apellido
   * @returns {string} Dos caracteres en mayúscula, ej: "AG"
   */
  function getInitials(first, last) {
    const f = first?.charAt(0)?.toUpperCase() || '?'
    const l = last?.charAt(0)?.toUpperCase() || '?'
    return f + l
  }

  /**
   * Aplana un objeto anidado a claves con notación de punto.
   * @param {object} obj - Objeto anidado
   * @param {string} [prefix=''] - Prefijo para la clave actual (uso recursivo)
   * @returns {Record<string,any>} Objeto plano con claves "a.b.c"
   * @example flatten({a:{b:1}}) → {"a.b":1}
   */
  function flatten(obj, prefix = '') {
    const result = {}
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        Object.assign(result, flatten(v, key))
      } else {
        result[key] = v ?? ''
      }
    }
    return result
  }

  /**
   * Des-aplana claves con punto de vuelta a un objeto anidado.
   * @param {Record<string,any>} flat - Objeto con claves "a.b.c"
   * @returns {object} Objeto anidado
   */
  function unflatten(flat) {
    const result = {}
    for (const [key, val] of Object.entries(flat)) {
      const parts = key.split('.')
      let current = result
      for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]] || typeof current[parts[i]] !== 'object') {
          current[parts[i]] = {}
        }
        current = current[parts[i]]
      }
      current[parts[parts.length - 1]] = val
    }
    return result
  }

  /**
   * Fusión profunda: clona target y sobrescribe con las claves de source.
   * Los arrays y valores primitivos se reemplazan directamente.
   * @param {object} target - Objeto base
   * @param {object} source - Objeto con los nuevos valores
   * @returns {object} Nuevo objeto fusionado
   */
  function deepMerge(target, source) {
    const result = JSON.parse(JSON.stringify(target))
    for (const [k, v] of Object.entries(source)) {
      if (v && typeof v === 'object' && !Array.isArray(v) && result[k] && typeof result[k] === 'object' && !Array.isArray(result[k])) {
        result[k] = deepMerge(result[k], v)
      } else {
        result[k] = v
      }
    }
    return result
  }

  /**
   * Descarga un blob como archivo, liberando la URL temporal tras el click.
   * @param {Blob} blob - Contenido a descargar
   * @param {string} filename - Nombre de archivo sugerido
   */
  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    setTimeout(() => { URL.revokeObjectURL(url); a.remove() }, 1000)
  }

  /**
   * Extrae el filename de una cabecera Content-Disposition (D7: el mismo
   * regex estaba copiado en themisStore/aegisStore/irisStore).
   * @param {Response} res - Respuesta de fetch con la cabecera
   * @param {string} fallback - Nombre a usar si la cabecera no trae uno
   * @returns {string}
   */
  function filenameFromResponse(res, fallback) {
    const cd = res.headers.get('Content-Disposition') ?? ''
    return cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? fallback
  }

  return { formatDate, getInitials, flatten, unflatten, deepMerge, triggerDownload, filenameFromResponse }
}
