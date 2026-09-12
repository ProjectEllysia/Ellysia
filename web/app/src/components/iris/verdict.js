/**
 * Rótulos en castellano de los valores cerrados que Iris recibe del servidor:
 * veredicto y estado de un análisis, y categoría y resultado de cada regla.
 *
 * Viven aquí y no en cada componente porque los pintan la tira del
 * historial, el archivo, el comparador, los documentos, los casos y el
 * informe: con un mapa por fichero, al traducir uno el de al lado seguía en
 * inglés (CONVENCIONES.md § 12.2). Todos caen en un rótulo genérico ante un
 * valor desconocido, nunca en el crudo.
 */

const VERDICT_LABELS = { legitimate: 'Legítimo', suspicious: 'Sospechoso', phishing: 'Phishing' }
const VERDICT_CLASSES = { legitimate: 'legit', suspicious: 'susp', phishing: 'phish' }

/**
 * Rótulo del veredicto de un análisis.
 *
 * @param {string|null} verdict - Veredicto del servidor (`Legitimate`,
 *   `Suspicious` o `Phishing`); no distingue mayúsculas.
 * @returns {string} «Legítimo», «Sospechoso», «Phishing», o «Sin veredicto»
 *   si falta o no se conoce.
 */
export function verdictLabel(verdict) {
  return VERDICT_LABELS[verdict?.toLowerCase()] || 'Sin veredicto'
}

/**
 * Sufijo de clase CSS con el que se colorea un veredicto.
 *
 * @param {string|null} verdict - Veredicto del servidor; no distingue mayúsculas.
 * @returns {'legit'|'susp'|'phish'|'unknown'} El tono del veredicto, o
 *   `'unknown'` si falta o no se conoce.
 */
export function verdictClass(verdict) {
  return VERDICT_CLASSES[verdict?.toLowerCase()] || 'unknown'
}

const ANALYSIS_STATUS_LABELS = {
  pending: 'Pendiente', running: 'En análisis', finished: 'Finalizado',
  failed: 'Fallido', cancelled: 'Cancelado',
}

/**
 * Rótulo del estado de un análisis.
 *
 * @param {string|null} status - `pending`, `running`, `finished`, `failed` o `cancelled`.
 * @returns {string} El rótulo del estado, o «Desconocido» si no se conoce.
 */
export function analysisStatusLabel(status) {
  return ANALYSIS_STATUS_LABELS[status] || 'Desconocido'
}

const RULE_CATEGORY_LABELS = {
  authentication: 'Autenticación', header_analysis: 'Cabeceras', content_analysis: 'Contenido',
}

/**
 * Rótulo de la categoría de una regla.
 *
 * @param {string|null} category - `authentication`, `header_analysis` o `content_analysis`.
 * @returns {string} El rótulo de la categoría, o «Otra» si no se conoce.
 */
export function ruleCategoryLabel(category) {
  return RULE_CATEGORY_LABELS[category] || 'Otra'
}

/**
 * Resultados de regla. Muchos son los resultados estándar de SPF, DKIM y
 * DMARC (`softfail`, `bestguess`…); el código exacto no se pierde, pasa al
 * tooltip de la tarjeta (CONVENCIONES.md § 12.3).
 */
const RULE_VERDICT_LABELS = {
  pass: 'Correcto', fail: 'Falla', softfail: 'Falla leve', suspicious: 'Sospechoso',
  neutral: 'Neutro', missing: 'Ausente', error: 'Error', trusted: 'De confianza',
  // DMARC: sin registro, pero pasaría si lo tuviera / política aplicada / sin política.
  bestguess: 'Estimado', policy: 'Política aplicada', none: 'Sin política',
  spoof: 'Suplantación',
  // Destinatarios: ni To ni Cc / solo en copia / «undisclosed recipients».
  empty: 'Sin destinatarios', empty_to: 'Solo en copia', undisclosed: 'Destinatarios ocultos',
  // Cabecera Date.
  future: 'Fecha futura', past: 'Fecha antigua', unparseable: 'Fecha ilegible',
}

/**
 * Rótulo del resultado de una regla.
 *
 * @param {string|null} verdict - Resultado que emite la regla (`pass`,
 *   `fail`, `softfail`, `bestguess`, `empty_to`…).
 * @returns {string} El rótulo del resultado, o «Otro» si no se conoce.
 */
export function ruleVerdictLabel(verdict) {
  return RULE_VERDICT_LABELS[verdict] || 'Otro'
}
