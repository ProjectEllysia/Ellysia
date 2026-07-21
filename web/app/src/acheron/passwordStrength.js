/**
 * Heurística de solidez de contraseña para la barra de UI. Sin dependencias
 * externas ni llamadas al servidor: se evalúa enteramente en el navegador
 * mientras el usuario escribe.
 */

const COMMON_WEAK = [
  'password', 'contraseña', '123456', '12345678', 'qwerty', 'letmein',
  'admin', 'welcome', 'abc123', 'iloveyou', 'monkey', 'dragon',
]

const LEVELS = [
  { label: 'Muy débil', color: '#d96c6c' },
  { label: 'Débil', color: '#e08a4f' },
  { label: 'Regular', color: '#e0c34f' },
  { label: 'Fuerte', color: '#8fc36a' },
  { label: 'Muy fuerte', color: '#5fbf7a' },
]

/**
 * @param {string} password
 * @returns {{ score: number, label: string, color: string, percent: number }}
 *   score de 0 (muy débil) a 4 (muy fuerte)
 */
export function scorePassword(password) {
  if (!password) return { score: 0, percent: 0, ...LEVELS[0] }

  let points = 0
  const len = password.length

  // Longitud: hasta 4 puntos
  if (len >= 8) points += 1
  if (len >= 12) points += 1
  if (len >= 16) points += 1
  if (len >= 20) points += 1

  // Variedad de caracteres: hasta 4 puntos
  if (/[a-z]/.test(password)) points += 1
  if (/[A-Z]/.test(password)) points += 1
  if (/\d/.test(password)) points += 1
  if (/[^A-Za-z0-9]/.test(password)) points += 1

  // Penalizaciones: contraseñas comunes o con repeticiones evidentes
  const lower = password.toLowerCase()
  if (COMMON_WEAK.some((w) => lower.includes(w))) points -= 3
  if (/(.)\1{2,}/.test(password)) points -= 1
  if (len < 8) points -= 2

  const score = Math.min(4, Math.max(0, Math.floor(points / 2)))
  return { score, percent: ((score + 1) / 5) * 100, ...LEVELS[score] }
}
