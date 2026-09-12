/**
 * Rótulos y cifras de las campañas de Aegis.
 *
 * Los estados de campaña y de destinatario los pintan la vista de campañas y
 * su detalle; con un mapa por componente, al traducir uno el de al lado se
 * quedaba atrás (CONVENCIONES.md § 12.2). Las cifras viven aquí porque son
 * aritmética pura y se prueban con `node` sin montar la vista.
 *
 * Los estados de un destinatario son acumulativos: cada uno guarda solo el
 * punto más avanzado al que llegó, así que quien completó el test también
 * abrió el enlace, y quien lo abrió también recibió el correo. El servidor
 * cuenta igual en el resumen de `GET /aegis/campaigns`.
 */

const CAMPAIGN_STATUS_LABELS = {
  draft: 'Borrador', sending: 'Enviando', sent: 'Enviada', failed: 'Fallida', closed: 'Cerrada',
}
const CAMPAIGN_STATUS_BADGES = {
  draft: 'badge--pending', sending: 'badge--running', sent: 'badge--done',
  failed: 'badge--error', closed: 'badge--cancelled',
}

/**
 * Rótulo del estado de una campaña.
 *
 * @param {string|null} status - `draft`, `sending`, `sent`, `failed` o `closed`.
 * @returns {string} El rótulo del estado, o «Desconocido» si no se conoce.
 */
export function campaignStatusLabel(status) {
  return CAMPAIGN_STATUS_LABELS[status] || 'Desconocido'
}

/**
 * Clase de insignia (de `shared.css`) con la que se colorea el estado de una campaña.
 *
 * @param {string|null} status - Estado de la campaña, como en `campaignStatusLabel`.
 * @returns {string} La clase `badge--*` del estado, o `'badge--pending'` si no se conoce.
 */
export function campaignStatusBadge(status) {
  return CAMPAIGN_STATUS_BADGES[status] || 'badge--pending'
}

const RECIPIENT_STATUS_LABELS = { sent: 'Enviado', opened: 'Abierto', completed: 'Completado' }

/**
 * Rótulo del punto al que llegó un destinatario.
 *
 * @param {string|null} status - `sent`, `opened` o `completed`.
 * @returns {string} El rótulo del estado, o «Desconocido» si no se conoce.
 */
export function recipientStatusLabel(status) {
  return RECIPIENT_STATUS_LABELS[status] || 'Desconocido'
}

/**
 * Porcentaje entero de `part` sobre `total`.
 *
 * @param {number} part - La parte (abiertos, completados…).
 * @param {number} total - El total sobre el que se calcula.
 * @returns {number} Entre 0 y 100, redondeado; `0` si `total` es 0.
 */
export function percentOf(part, total) {
  return total ? Math.round((part / total) * 100) : 0
}

/**
 * Resume las filas de seguimiento de una campaña con la misma forma que el
 * resumen que trae cada campaña en `GET /aegis/campaigns`.
 *
 * Sirve al detalle, que carga los destinatarios frescos: sus cifras no
 * dependen de cuándo se cargó el listado.
 *
 * @param {Array<{status: string, score: number|null}>} recipients - Destinatarios
 *   del detalle de la campaña.
 * @returns {{recipientCount: number, openedCount: number, completedCount: number,
 *   averageScore: number|null}} Contadores acumulativos y aciertos medios de quienes
 *   completaron; `averageScore` es `null` si nadie ha completado.
 */
export function summarizeRecipients(recipients = []) {
  const completed = recipients.filter(recipient => recipient.status === 'completed')
  const scored = completed.filter(recipient => typeof recipient.score === 'number')
  return {
    recipientCount: recipients.length,
    openedCount: recipients.filter(recipient => recipient.status === 'opened').length + completed.length,
    completedCount: completed.length,
    averageScore: scored.length
      ? scored.reduce((total, recipient) => total + recipient.score, 0) / scored.length
      : null,
  }
}

/**
 * Nota media expresada como porcentaje de aciertos.
 *
 * @param {number|null} averageScore - Aciertos medios de quienes completaron.
 * @param {number} questionCount - Preguntas sobre las que puntúa la campaña.
 * @returns {number|null} Entre 0 y 100, redondeado; `null` si no hay nota o la
 *   campaña no tiene preguntas.
 */
export function scorePercent(averageScore, questionCount) {
  if (averageScore == null || !questionCount) return null
  return Math.round((averageScore / questionCount) * 100)
}

/**
 * Resume todas las campañas de una píldora.
 *
 * La nota no se promedia en bruto: cada campaña congela su test al lanzarse,
 * así que si la píldora se editó entre dos envíos una campaña puede puntuar
 * sobre 3 preguntas y otra sobre 2. Cada nota se pasa a porcentaje de su
 * propia campaña y se pondera por cuántas personas completaron.
 *
 * @param {Array<{recipientCount: number, openedCount: number, completedCount: number,
 *   averageScore: number|null, questionCount: number}>} campaigns - Campañas de la
 *   píldora tal como las da `GET /aegis/campaigns`.
 * @returns {{campaignCount: number, recipientCount: number, openRate: number,
 *   completionRate: number, averageScorePercent: number|null}} Totales de la
 *   píldora; los porcentajes son enteros entre 0 y 100 y `averageScorePercent`
 *   es `null` si nadie ha completado ningún test.
 */
export function summarizePill(campaigns = []) {
  let recipientCount = 0
  let openedCount = 0
  let completedCount = 0
  let scoredCount = 0
  let weightedScore = 0

  for (const campaign of campaigns) {
    recipientCount += campaign.recipientCount ?? 0
    openedCount += campaign.openedCount ?? 0
    completedCount += campaign.completedCount ?? 0
    if (campaign.averageScore != null && campaign.questionCount && campaign.completedCount) {
      weightedScore += (campaign.averageScore / campaign.questionCount) * campaign.completedCount
      scoredCount += campaign.completedCount
    }
  }

  return {
    campaignCount: campaigns.length,
    recipientCount,
    openRate: percentOf(openedCount, recipientCount),
    completionRate: percentOf(completedCount, recipientCount),
    averageScorePercent: scoredCount ? Math.round((weightedScore / scoredCount) * 100) : null,
  }
}
