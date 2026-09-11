/**
 * Comparación de dos informes de Iris lado a lado.
 *
 * Vive fuera del componente para poder probarla con `node` a secas (ver
 * `test/iris.compare.test.mjs`), igual que `intake.js`. Recibe los informes tal
 * como los devuelve `GET /iris/results/<id>` y no reinterpreta nada: solo
 * empareja reglas y señala qué cambia. Empareja por `ruleId`, que es estable
 * aunque el nombre visible cambie entre dos versiones del catálogo, y por
 * `ruleName` en análisis anteriores a que existiera el id.
 */

/**
 * Empareja las reglas de dos informes y resume en qué difieren.
 *
 * @param {object} left Informe de la izquierda (`rules`, `verdict`, `totalScore`…).
 * @param {object} right Informe de la derecha.
 * @returns {{verdictChanged: boolean, scoreDelta: number|null, changedCount: number,
 *   rules: Array<{ruleName: string, left: {score: number, verdict: string}|null,
 *   right: {score: number, verdict: string}|null, changed: boolean}>}}
 *   `scoreDelta` es derecha menos izquierda (`null` si falta algún score). Las
 *   reglas que cambian van primero; dentro de cada grupo, por nombre.
 */
export function compareReports(left, right) {
  const byKey = new Map()
  for (const [side, report] of [['left', left], ['right', right]]) {
    for (const rule of report?.rules ?? []) {
      const key = rule.ruleId || rule.ruleName
      const entry = byKey.get(key) ?? { ruleId: rule.ruleId ?? null, ruleName: rule.ruleName, left: null, right: null }
      entry[side] = { score: rule.score, verdict: rule.verdict }
      byKey.set(key, entry)
    }
  }

  const rules = [...byKey.values()].map(entry => ({
    ...entry,
    changed: entry.left?.verdict !== entry.right?.verdict || entry.left?.score !== entry.right?.score,
  }))
  rules.sort((a, b) => (Number(b.changed) - Number(a.changed)) || a.ruleName.localeCompare(b.ruleName))

  const hasScores = typeof left?.totalScore === 'number' && typeof right?.totalScore === 'number'
  return {
    verdictChanged: left?.verdict !== right?.verdict,
    scoreDelta: hasScores ? Math.round((right.totalScore - left.totalScore) * 10) / 10 : null,
    changedCount: rules.filter(rule => rule.changed).length,
    rules,
  }
}
