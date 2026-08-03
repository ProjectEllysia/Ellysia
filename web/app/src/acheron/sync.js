/**
 * Concurrencia optimista del vault de Acheron (lado cliente).
 *
 * El servidor mantiene un contador `revision` que sube en toda mutación del
 * vault y lo exige en `If-Match` para no dejar que un cliente con un snapshot
 * viejo pise lo que escribió otro dispositivo. Aquí vive esa mecánica, fuera
 * del componente, para poder probarla sin montar la vista.
 */

/** Lee el JSON de una respuesta sin consumirla (el llamante aún puede usarla). */
export async function peekJson(res) {
  if (!res) return null
  try {
    return await res.clone().json()
  } catch {
    return null
  }
}

/**
 * Ejecuta una escritura del vault mandando `If-Match`, y la reintenta una vez
 * si el servidor la rechaza por revisión obsoleta.
 *
 * El reintento reenvía el MISMO cuerpo cifrado: la `vaultKey` no cambia con las
 * escrituras de otros dispositivos, así que el ciphertext sigue siendo válido y
 * el cambio se reaplica sobre el estado fresco sin tocar criptografía ni volver
 * a pedir la contraseña maestra.
 *
 * @param {(path: string, options?: object) => Promise<Response|null>} apiFetch
 * @param {string} path
 * @param {object} options  opciones de fetch (method, body, headers)
 * @param {{ revision: number|null, refresh: () => Promise<boolean> }} ctx
 *        `revision` se actualiza in situ con la que devuelve el servidor;
 *        `refresh` recarga el vault en caliente y debe dejar `revision` al día.
 * @returns {Promise<{ res: Response|null, refreshed: boolean }>}
 *          `refreshed` indica que hubo conflicto y el estado local ya se releyó,
 *          así que el llamante no debe parchearlo a mano.
 */
export async function vaultWrite(apiFetch, path, options, ctx) {
  const send = () => apiFetch(path, {
    ...options,
    headers: {
      ...(options.headers ?? {}),
      ...(ctx.revision != null ? { 'If-Match': `"${ctx.revision}"` } : {}),
    },
  })

  let res = await send()
  let body = await peekJson(res)

  if (res && res.status === 409 && body?.error === 'vault_revision_mismatch') {
    if (!(await ctx.refresh())) return { res, refreshed: false }
    res = await send()
    body = await peekJson(res)
    trackRevision(ctx, res, body)
    return { res, refreshed: true }
  }

  trackRevision(ctx, res, body)
  return { res, refreshed: false }
}

function trackRevision(ctx, res, body) {
  if (res && res.ok && typeof body?.revision === 'number') {
    ctx.revision = body.revision
  }
}
