# Análisis de viabilidad: mejoras de seguridad en Acheron + MFA global para la API

## Contexto

Acheron (`API/src/modules/acheron`) es el gestor de secretos "zero-knowledge" de SeQ: la contraseña maestra nunca sale del cliente, deriva una clave (Argon2id/PBKDF2 vía Web Crypto + `hash-wasm`) que desenvuelve una `vaultKey` AES-256-GCM, y un `checker` (SHA-256 del username, cifrado) permite validar localmente que la maestra es correcta. El servidor solo almacena blobs cifrados y parámetros de KDF.

Primero se analizaron los **servicios** de Acheron (no la calidad del código) para detectar problemas y mejoras de seguridad, incluyendo viabilidad de Passkeys. Tras esa primera pasada, el usuario pidió reenfocar el análisis de MFA: en vez de tratarlo como una mejora aislada de Acheron, diseñarlo como **funcionalidad global de la API** — protege el login de toda la plataforma (Aegis, Sentinel, Iris, Acheron, administración), no solo el acceso al vault. Alcance acordado: backend (`API/`) + frontend web (`web/app/src`); el cliente móvil (`SeQ-AcheronMobile`) queda fuera porque el repo no está disponible en la ruta esperada.

## Estado actual verificado

- **Login actual** (`API/src/modules/users/endpoints.py:85-152`, `oauth_token`): `POST /oauth/token` con `grantType: "password"` verifica credenciales y **emite access+refresh token en un solo paso**, sin ningún hueco para un segundo factor. `TokenRequestSchema`/`TokenResponseSchema` (`users/schemas.py:4-28`) no tienen ningún campo relacionado con MFA.
- **JWT** (`users/managers.py:532-573,602-635`): PyJWT, claims `sub`, `username`, `exp`, `iat`, `jti`, `type`, `role`, `pwd_at` (para el contrato de cambio de contraseña, código 401 `1609`). El patrón de "claim adicional + comparación de recencia" (`pwd_at` vs `password_changed_at`) es exactamente el molde a reutilizar para MFA.
- **Modelo `User`** (`users/model.py:129-204`): sin ninguna columna ni tabla relacionada con MFA/TOTP/WebAuthn.
- **Guards existentes** (`users/services/permissions.py:186-396`): `require_oauth_token`, `require_role`, `require_attributes` — patrón de decorador reutilizable, pero el gate de MFA propuesto no necesita uno nuevo (ver diseño abajo).
- **Frontend**: `web/app/src/stores/authStore.js:122` hace `login(username, password)` → `POST /oauth/token` directamente y guarda los tokens; es el único punto que hay que tocar para manejar un segundo paso de login.
- **Nada de MFA/TOTP/WebAuthn/FIDO2 existe hoy en todo el repo** (`requirements.txt`, `pyproject.toml`, grep completo): terreno nuevo, pero con patrones muy claros a seguir.
- **Acheron** (`API/src/modules/acheron`): zero-knowledge correcto a nivel arquitectónico; el `checker` nunca se valida en servidor (`schemas.py:74-82`, `managers.py`), por lo que la "fuerza bruta contra el checker" es un ataque **offline** una vez que un atacante obtiene el JSON del vault — no algo que un rate-limit del servidor pueda frenar. Esto es relevante para el diseño de MFA: el punto de control real está en el **login** (impedir que se obtenga un token válido), no en el propio endpoint de vault.
- **Infraestructura general**: `Flask-Limiter` en memoria (no sobrevive reinicios ni escala multi-worker), sin cabeceras de seguridad (CSP/HSTS), auditoría solo en logs de aplicación (sin tabla dedicada).

## Hallazgos priorizados (Acheron)

| # | Hallazgo | Severidad | Nota |
|---|----------|-----------|------|
| 1 | Sin segundo factor en todo el acceso a la plataforma | Alta | Ver diseño de MFA global abajo — es la mejora que más reduce este riesgo |
| 2 | `VaultPasswordChangeSchema` no valida `metadataVersion` esperado | Media | Rotaciones concurrentes pueden pisarse sin detección de conflicto |
| 3 | Sin límites de longitud en campos de `Storable`/schemas | Media | Abuso de almacenamiento |
| 4 | Sin tabla de auditoría para acciones sobre el vault (ni ahora sobre MFA) | Media | Debería cubrir también los eventos de enroll/verify/fail de MFA |
| 5 | Rate limiter en memoria (`storage_uri="memory://"`) | Media | Prerrequisito real para que cualquier lockout de MFA sea correcto en producción multi-worker |
| 6 | Sin cabeceras de seguridad app-wide | Baja-Media | Hardening general |
| 7 | Sin gestión de sesiones/dispositivos | Baja | Relevante para UX de gestión de métodos WebAuthn |
| 8 | Sin verificación de contraseñas filtradas (HIBP) | Baja | Debe hacerse 100% en cliente para no romper zero-knowledge |

## Diseño propuesto: MFA como funcionalidad global de la API

**Principio de diseño:** el gate de MFA se aplica en la **emisión del token** (`POST /oauth/token`), no endpoint por endpoint. Así, cualquier módulo (Aegis, Sentinel, Iris, Acheron, administración de usuarios) queda protegido automáticamente sin tocar sus guards individuales — posesión de un access token válido implica que el MFA ya se satisfizo para esa sesión.

**Modelo de datos nuevo** (en `API/src/modules/users/model.py`, junto a `User`):
- `MFATotpCredential`: `user_id` (FK único), `secret_encrypted`, `confirmed_at`, `created_at`
- `MFAWebAuthnCredential`: `id`, `user_id` (FK), `credential_id` (único), `public_key`, `sign_count`, `transports`, `nickname`, `created_at`, `last_used_at`
- `MFARecoveryCode`: `id`, `user_id` (FK), `code_hash`, `used_at` (nullable)
- Un usuario puede tener 0, 1 o varios métodos; MFA está "activo" si existe al menos un método confirmado.

**Flujo de login modificado** (`oauth_token()`, grant `password`):
1. `verify_credentials` igual que hoy (`users/managers.py:90-140`).
2. Usuario sin MFA → comportamiento actual, sin cambios (compatibilidad total con cuentas existentes).
3. Usuario con MFA → en vez de emitir access+refresh token, se emite un `challengeToken` de vida corta (JWT `type:"mfa_pending"`, ~5 min, `sub=user_id`) y se responde `200 {"mfaRequired": true, "challengeToken": ..., "methods": ["totp","webauthn"]}` (no es un 401 de credenciales inválidas).
4. Nuevo endpoint `POST /oauth/mfa/verify`: recibe `challengeToken` + (`code` TOTP, o assertion WebAuthn, o `recoveryCode`). Si es válido, emite el access+refresh token reales con un nuevo claim `mfa_at` (epoch, simétrico a `pwd_at`), exactamente igual que el camino de éxito actual.
5. **Aquí sí tiene sentido un lockout servidor-side** (a diferencia del `checker` de Acheron, que es offline): un TOTP de 6 dígitos es adivinable online. Contador de intentos ligado al `challengeToken` (p.ej. máx. 5, luego invalidarlo y forzar login desde cero) + `Flask-Limiter` por cuenta/IP.

**Endpoints de gestión nuevos** (`users`):
- `POST /users/mfa/totp/setup` → genera secreto (`pyotp`) + URI `otpauth://` (requiere `require_oauth_token`)
- `POST /users/mfa/totp/confirm` → valida el primer código, marca `confirmed_at`, devuelve códigos de recuperación (una sola vez, mostrados una única vez)
- `POST /users/mfa/webauthn/register-options` / `register` → ceremonia estándar (`webauthn`/`py_webauthn`)
- `GET /users/mfa` → lista de métodos activos (base para una futura UI de gestión de dispositivos)
- `DELETE /users/mfa/{method_id}` → si es el último método, exigir reautenticación y considerar `revoke_all_user_tokens` (mismo patrón que cambio de contraseña)

**Reutilización de lo existente:**
- El grant `refresh_token` no necesita re-verificar MFA, igual que hoy no re-verifica password (la confianza ya se estableció al emitir el primer token tras el challenge).
- `revoke_all_user_tokens` (`managers.py:749-762`) se reutiliza al activar/desactivar MFA.
- `require_oauth_token`/`require_attributes` no requieren cambios estructurales — el gate ya ocurrió antes de que exista un token.
- Paso opcional futuro (step-up): para acciones muy sensibles (cambio de contraseña, exportar vault de Acheron) comparar recencia de `mfa_at` igual que se hace con `pwd_at`. No necesario para el MVP.

**Dependencias nuevas:** `pyotp`, `webauthn` (py_webauthn). El QR de aprovisionamiento TOTP se puede renderizar en el frontend a partir del URI `otpauth://`, sin librería extra en backend.

**Auditoría:** registrar enroll/verify/fail de MFA — refuerza el hallazgo #4, ahora también relevante para `users`, no solo `acheron`.

**Frontend:** `web/app/src/stores/authStore.js:122` (`login()`) debe manejar la respuesta `mfaRequired` y pedir el código antes de completar sesión; nuevo paso de "verificación en dos pasos" en el flujo de login.

## Viabilidad y esfuerzo (MFA global)

| Pieza | Viabilidad | Esfuerzo |
|---|---|---|
| TOTP end-to-end (setup/confirm/verify/recovery codes) | Alta | Medio (días) |
| Challenge token + endpoint `/oauth/mfa/verify` | Alta | Bajo-Medio |
| Rate limiting/lockout dedicado al challenge | Alta | Bajo (requiere backend Redis para el limiter en producción, ver hallazgo #5) |
| Gestión de métodos (`GET/DELETE /users/mfa`) | Alta | Bajo |
| WebAuthn como método adicional (registro/verificación) | Alta | Medio-Alto (cross-browser) |
| Step-up para acciones sensibles (`mfa_at` recency) | Media | Bajo, pero es fase posterior |
| Frontend (login de dos pasos + gestión de métodos) | Alta | Medio |

## Passkeys para desbloqueo del vault de Acheron (viabilidad, complementaria)

Distinto del MFA de login: usar la extensión PRF de WebAuthn (`prf`/`hmac-secret`) para derivar, de forma determinista y sin salir del autenticador, un secreto que alimente el KDF del vault — en vez de (o junto a) la contraseña maestra. Precedente real: Bitwarden lo hace así. Viabilidad **media**: soporte de PRF no es universal (autenticadores de plataforma sí, muchas llaves de seguridad no), exige detección de capacidad + fallback obligatorio a la maestra, y toca `web/app/src/acheron/crypto.js`/`vault.js`. Debe tratarse como método de conveniencia adicional — nunca reemplazo del camino de recuperación (maestra). Se recomienda prototiparlo **después** del MFA global, reutilizando el registro de credenciales WebAuthn si ya existe.

Se descarta guardar en servidor un secreto ligado a la credencial WebAuthn para reconstruir la `vaultKey`: rompería zero-knowledge.

## Roadmap

**Fase 0 — victorias rápidas en Acheron (días):** `metadataVersion` esperado en `PATCH /vault`, límites de longitud en `StorableCreateSchema`, cabeceras de seguridad app-wide.

**Fase 1 — MFA global (bloque principal):**
1. Modelos + `POST /oauth/mfa/verify` + TOTP end-to-end + login de dos pasos (mínimo viable)
2. Códigos de recuperación + `GET/DELETE /users/mfa`
3. WebAuthn como método adicional, reutilizando el mismo `challengeToken`
4. Backend Redis para el rate limiter (prerrequisito real de producción)
5. Tabla de auditoría para eventos de MFA (y, de paso, para Acheron — hallazgo #4)

**Fase 2 — prototipo WebAuthn-PRF para desbloqueo de vault (Acheron):** detección de capacidad, fallback obligatorio a maestra, pruebas en `web/app/test/acheron.interop.test.mjs`.

**Fase 3 — opcional:** gestión de dispositivos/sesiones, HIBP client-side.

## Archivos clave

- `API/src/modules/users/model.py` — nuevos modelos MFA
- `API/src/modules/users/endpoints.py:85-152` (`oauth_token`, a modificar), nuevo `oauth_mfa_verify`, nuevos endpoints `/users/mfa/*`
- `API/src/modules/users/managers.py:532-573` (`create_access_token`, añadir `mfa_at`), `:602-635` (`verify_access_token`), nuevos `create_challenge_token`/`verify_challenge_token` en `OAuthTokenManager`
- `API/src/modules/users/schemas.py` — nuevos schemas para challenge/verify/enroll
- `web/app/src/stores/authStore.js:122` — manejar `mfaRequired`
- `API/requirements.txt` — añadir `pyotp`, `webauthn`
- Acheron (fase 0/2): `API/src/modules/acheron/{schemas.py,model.py,managers.py,endpoints.py}`, `web/app/src/acheron/{crypto.js,vault.js}`

## Fuera de alcance / no-objetivos

- No se modifica ningún código en esta pasada — es un documento de viabilidad.
- No se profundiza en el cliente móvil (repo no disponible en la ruta esperada).
- No se propone recuperación de contraseña maestra "por servidor": rompería zero-knowledge; se documenta como pérdida de datos irrecuperable por diseño.

## Verificación (cuando se pase a implementación)

- Fase 1: test de que el login con MFA activo devuelve `mfaRequired` en vez de tokens; test de que un `challengeToken` agotado (>5 intentos) se invalida; flujo de setup/confirm de TOTP probado en navegador vía las herramientas de preview.
- Fase 2: prueba manual de desbloqueo con Passkey (PRF) en un autenticador compatible + verificación de fallback en uno no compatible.

## Housekeeping

Al aprobar este plan, lo primero que haré es crear `plans/` en la raíz del repo y copiar este documento allí — no pude hacerlo antes porque el modo planificación solo permite editar el archivo de plan interno.
