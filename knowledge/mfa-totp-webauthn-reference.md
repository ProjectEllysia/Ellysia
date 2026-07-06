# MFA, TOTP y WebAuthn — Referencia rápida para cuando tengas dudas

## ¿Qué es MFA y por qué queremos implementarlo?

MFA es básicamente decirle al usuario: "vale, me has dado tu contraseña, pero no me fío solo de eso. Dame algo más." Ese "algo más" puede ser:

- **Algo que tienes**: un código que solo tú puedes generar (TOTP en tu móvil), una Passkey en tu ordenador, una llave de seguridad USB
- **Algo que eres**: tu huella dactilar, tu cara (reconocimiento facial)

En la práctica, combinamos lo que tienes + lo que eres. Por ejemplo: "dame tu contraseña + un código de 6 dígitos que solo tu app puede generar" o "dame tu contraseña + desbloquea tu huella dactilar".

¿Por qué lo hacemos en SeQ? Porque Acheron guarda secretos valiosos cifrados. Si alguien roba tu contraseña (de una filtración, un ataque, etc.), con MFA activo no puede entrar igual — necesita tu móvil, tu Passkey, lo que sea que uses como segundo factor.

---

## TOTP: el código de 6 dígitos que tu móvil genera

### La idea básica

Imagina que tú y el servidor tienen una **contraseña privada compartida** (el "seed"). Cada 30 segundos, ambos hacen la misma operación matemática con esa contraseña + la hora actual, y obtienen un código de 6 dígitos. Es imposible que se desincronicen porque los dos usan la misma hora.

Ejemplo:
- Tú: seed + hora 14:30:00 → código "123456"
- Servidor: seed + hora 14:30:00 → código "123456" ✓ coincide

Pasados 30 segundos:
- Tú: seed + hora 14:30:30 → código "789012"
- Servidor: seed + hora 14:30:30 → código "789012" ✓ coincide

Un atacante que ve pasar "123456" no puede hacer nada con él pasados esos 30 segundos — ya cambió a "789012".

### ¿Cómo se instala?

1. El usuario dice "quiero activar 2FA"
2. El servidor genera un secreto aleatorio: una cadena de caracteres que se verá como `JBSWY3DPEBLW64TMMQ======`
3. El servidor le devuelve un **código QR** que contiene ese secreto codificado
4. El usuario abre Google Authenticator (o Authy, o lo que use) en su móvil y escanea el QR
5. La app del móvil **descifra el secreto del QR** y lo guarda localmente
6. A partir de ese momento, la app genera códigos cada 30 segundos

Lo importante: **el secreto se envía una sola vez** (en el QR durante setup). Después, solo viajan los códigos temporales de 6 dígitos.

### ¿Y si me roban el móvil?

Si alguien obtiene el **secreto**, sí puede generar todos los códigos futuros. Por eso:
- El secreto debe estar **encriptado en la base de datos** del servidor
- El secreto debe estar **protegido en el móvil** (normalmente está encriptado en el almacenamiento seguro del teléfono)
- Por eso también damos al usuario **códigos de recuperación** (más abajo)

Si alguien solo intercepta un código "123456", no le sirve de nada. Es como una clave temporal que cambia cada 30 segundos.

### Cómo funciona en práctica (el login)

1. Usuario: entra username + contraseña (su contraseña de acceso normal)
2. Servidor: ✓ contraseña correcta, pero usuario tiene 2FA activado
3. Servidor: devuelve `{"mfaRequired": true, "challengeToken": "...", "methods": ["totp"]}`
4. Frontend: muestra un popup pidiendo "ingresa tu código de 6 dígitos"
5. Usuario: abre su app autenticadora (Google Authenticator), ve "123456", lo copia
6. Usuario: pega "123456" en el popup y envía
7. Servidor: `POST /oauth/mfa/verify` recibe el challenge + "123456"
8. Servidor: genera el código que debería ser ahora (sabiendo su secreto) y verifica: "¿es 123456?" → ✓ sí
9. Servidor: emite los tokens de verdad (access + refresh)

---

## WebAuthn / Passkeys: la biometría criptográfica

### La diferencia clave: tu clave privada nunca sale

Con TOTP, el servidor y tu móvil comparten un secreto (el seed). Con WebAuthn, **el servidor nunca toca tu clave privada**. Funcionan así:

1. Registras un Passkey (por ejemplo, la huella dactilar de tu móvil)
2. Tu móvil genera internamente un par: clave privada (se queda en el móvil, nunca sale) + clave pública (se envía al servidor)
3. El servidor guarda solo la **clave pública**

Después, cada vez que quieres autenticarte:
1. El servidor te envía un desafío criptográfico: "Demuéstrame que eres tú firmando esto"
2. Tu móvil (con tu biometría/huella/reconocimiento facial) firma ese desafío con su clave privada
3. Tu móvil envía la firma al servidor
4. El servidor verifica: "¿esta firma es válida si la verifico con la clave pública que guardé?" → ✓ sí → autenticado

**Lo crucial:** la clave privada nunca se ve, ni se envía, ni sale del dispositivo. Está en un enclave seguro (en móviles, PCs modernas).

### ¿Por qué es tan seguro contra phishing?

Porque la clave privada está ligada al **servidor específico** (por el certificado TLS/HTTPS). Si un atacante te hace una página fake de SeQ (phishing), tu móvil se da cuenta de que el certificado no coincide y se niega a firmar. La clave privada dice: "no, esa no es seq.local, eso es fake.seq.com, me niego".

Con contraseñas, un phishing fake se ve igual y funciona igual. Con Passkeys, no.

### Cómo se registra un Passkey

1. Usuario: "quiero agregar un Passkey"
2. Servidor: genera un desafío criptográfico (challenge) y le devuelve opciones al navegador
3. Navegador: abre la ceremonia de WebAuthn
   - En iOS/Mac: "Usa Face ID para registrar este Passkey"
   - En Android: "Usa tu huella dactilar para registrar este Passkey"
   - En una llave de seguridad: "Toca la llave"
4. El usuario se autentica localmente (cara, huella, PIN, toque)
5. El autenticador genera el par de claves
6. El navegador devuelve al servidor: credential ID + clave pública
7. Servidor guarda: credential ID + clave pública + metadata (nombre del Passkey, cuándo fue registrado, etc.)

Después, el usuario puede registrar más Passkeys (en su otro móvil, en su PC, en una llave de seguridad, etc.).

### Cómo se usa para autenticarse

1. Usuario: username (no necesita contraseña, o la puede omitir)
2. Servidor: "bien, generemos un desafío. ¿Qué Passkeys tienes registrados?"
3. Servidor: devuelve al navegador una lista de IDs de Passkeys registrados + el desafío
4. Navegador: "tienes 2 Passkeys. ¿Cuál usas?" (o lo adivina si es uno solo)
5. Usuario: toca/mira/unlocks el Passkey (biometría)
6. Autenticador: genera una firma del desafío usando su clave privada
7. Navegador devuelve: signature + metadata
8. Servidor: verifica la firma con la clave pública → ✓ autenticado

---

## El flujo de login en SeQ: antes y después

### Cómo es ahora (sin MFA)

```
Usuario abre login
  ↓
Entra username + contraseña
  ↓
POST /oauth/token {grantType: "password", username, password}
  ↓
Servidor: ¿contraseña correcta? ✓ sí
  ↓
Emite access_token + refresh_token
  ↓
Usuario autenticado, entra a la app
```

Super rápido. Un paso.

### Cómo será con MFA

```
Usuario abre login
  ↓
Entra username + contraseña
  ↓
POST /oauth/token {grantType: "password", username, password}
  ↓
Servidor: ¿contraseña correcta? ✓ sí
  ↓
¿Tiene MFA activado? ¿SÍ? → emite un "challengeToken" (token temporal, 5 minutos)
                            Respuesta: {mfaRequired: true, challengeToken, methods: ["totp", "webauthn"]}
           ¿NO? → comportamiento actual (emite access_token + refresh_token)
  ↓
[Frontend detecta mfaRequired: true]
  ↓
Muestra pantalla: "Ingresa tu código de 2FA"
  ↓
Usuario abre app autenticadora, ve "123456", lo copia
O: Usuario toca Passkey, reconocimiento facial/huella
  ↓
POST /oauth/mfa/verify {challengeToken, code: "123456"}
                     O: {challengeToken, assertionResponse: {...}}
  ↓
Servidor: ¿código correcto? o ¿firma válida? ✓ sí
  ↓
Emite access_token + refresh_token (CON claim mfa_at: <timestamp>)
  ↓
Usuario autenticado, entra a la app
```

Dos pasos. Más seguro.

### Lo importante del diseño

- **Compatibilidad**: usuarios sin MFA siguen con un paso (como ahora)
- **Dos métodos**: puedes usar TOTP o WebAuthn (o tener ambos como backup)
- **Recuperación**: si pierdes tu app, usas un código de recuperación
- **Refresh token**: una vez que tienes un access_token válido, el refresh token sigue funcionando sin re-verificar MFA (ya probaste que eres tú)

---

## Códigos de recuperación: el plan B

Imagina que tu móvil se te cae al río. Dile adiós. Pero tienes 2FA activado. ¿Cómo entras?

Los códigos de recuperación son exactamente eso: 8-10 códigos que te damos **una sola vez** cuando activas TOTP. Son cosas como:

```
ABCD-1234
EFGH-5678
IJKL-9012
...
```

Cuando activas TOTP, te mostramos esos códigos en pantalla y te pedimos que los copies a un lugar seguro (gestor de contraseñas, nota, papel, lo que sea). Cada código se puede usar una sola vez para entrar en caso de emergencia.

Entonces:
1. Pierdes el móvil
2. Intentas entrar a SeQ
3. En la pantalla de "ingresa tu código de 2FA", seleccionas "usar código de recuperación"
4. Copias uno de los que guardaste: "ABCD-1234"
5. Entras
6. Ese código queda marcado como "usado" y ya no funciona (no se puede reutilizar)

Simple, pero efectivo como red de seguridad.

---

## JWT: qué claims nuevos llevaremos

Actualmente, cuando te logueas, el access_token tiene claims como:

```json
{
  "sub": "1",           // tu ID de usuario
  "username": "admin",
  "role": "role_admin",
  "pwd_at": 1700000000, // cuándo cambió tu contraseña (para detectar cambios)
  "exp": 1704067200,    // cuándo expira
  "iat": 1704063600     // cuándo se emitió
}
```

Con MFA, añadiremos:

```json
{
  "sub": "1",
  "username": "admin",
  "role": "role_admin",
  "pwd_at": 1700000000,
  "mfa_at": 1704063500,  // ← NUEVO: cuándo completaste MFA
  "exp": 1704067200,
  "iat": 1704063600
}
```

**Por qué**: así como la app web chequea `pwd_at` para saber si tu contraseña cambió (y puede pedirte que te loguees de nuevo), en el futuro podemos chequear `mfa_at` para saber si tu MFA es "reciente" — útil para acciones muy sensibles como cambiar contraseña o exportar todo el vault.

---

## Passkeys para desbloquear el vault de Acheron (la parte difícil)

Esto es **diferente** a MFA de login. No es para entrar a la app, es para **desbloquear el cifrado del vault localmente**.

### El problema actual

Hoy, en Acheron:
1. Te logueas (con MFA, si quieres)
2. Llegas a la pantalla del vault
3. Entras tu contraseña maestra
4. El navegador deriva una clave (Argon2id o PBKDF2)
5. Esa clave desenvuelve el vault (AES-256-GCM)
6. Ves tus secretos

La contraseña maestra es lo único que necesitas en el navegador. Está bien porque es zero-knowledge (el servidor no lo ve nunca), pero si un atacante te la roba, puede desbloquear el vault offline (fuerza bruta contra el `checker`).

### La idea de Passkeys para el vault

¿Y si, en lugar de derivar la clave de tu contraseña maestra, la derivamos de un **secreto generado por tu autenticador** (Passkey con biometría)? Así:

1. Te registras un Passkey en tu móvil (con huella dactilar)
2. Cuando intentas desbloquear el vault, el navegador pide que desbloquees con tu huella
3. Tu móvil **genera un secreto determinista** ligado a tu Passkey
4. Ese secreto se usa para derivar la clave del vault
5. Desbloqueas el vault

**Ventaja**: el atacante tendría que tener tanto el JSON del vault como tu móvil **y** tu huella. Mucho más difícil.

**Desventaja**: si pierdes tu móvil, no puedes desbloquear el vault. Por eso siempre hay que tener un **plan B**: poder seguir usando la contraseña maestra.

### La tecnología detrás

Se llama **PRF** (Pseudo-Random Function) en WebAuthn. Es una extensión que le permite a tu autenticador devolver un secreto criptográfico basado en una entrada (salt). Es determinista: mismo salt → mismo secreto. Es privado: solo tu autenticador lo ve.

Bitwarden lo implementa así. Apple lo soporta en iCloud Keychain (Passkeys en iCloud). Pero muchas llaves de seguridad USB no lo soportan aún.

**Para SeQ**: es viable pero requiere:
1. Detectar si el navegador/autenticador soportan PRF
2. Si sí: ofrecer desbloqueo con Passkey
3. Si no: fallback automático a contraseña maestra
4. Nunca obligar PRF — la contraseña maestra es el camino de recuperación

Recomendamos implementarlo **después** del MFA global, una vez que Passkeys ya existan en la BD.

---

## Checklist mental para cuando implementemos

### Fase 1: TOTP + MFA global

Lo más importante primero. Cuando termines esto, cualquier usuario puede activar 2FA con TOTP.

- Crear tablas en BD: `MFATotpCredential`, `MFAWebAuthnCredential`, `MFARecoveryCode`
- Modificar el login (`oauth_token`): si el usuario tiene MFA, devolver `challengeToken` en vez de tokens reales
- Crear `POST /oauth/mfa/verify`: toma el `challengeToken` + código TOTP, verifica, emite tokens
- Setup de TOTP (`POST /users/mfa/totp/setup`): genera secreto, devuelve QR
- Confirmar TOTP (`POST /users/mfa/totp/confirm`): usuario envía su primer código, confirmamos, devolvemos recovery codes
- Rate limiting: máx. 5 intentos fallidos por `challengeToken`, luego invalidar
- Frontend: manejar el flujo de login en dos pasos

### Fase 2: WebAuthn

Una vez TOTP funcione, agregar Passkeys.

- Setup: `POST /users/mfa/webauthn/register-options` + `register`
- Login: `POST /oauth/mfa/verify` (WebAuthn assertion)
- Gestión: `GET /users/mfa` (ver qué métodos tienes), `DELETE /users/mfa/{id}` (desactivar uno)

### Fase 3: Acheron improvements

Mientras tanto, las "victorias rápidas" en Acheron.

- Validar `metadataVersion` esperado en `PATCH /vault` (detectar rotaciones concurrentes)
- Límites de longitud en los campos de secretos
- Cabeceras de seguridad en la app

### Fase 4: PRF para vault (el final épico)

Cuando todo lo anterior esté listo y probado.

- Detectar soporte de PRF en navegador
- Modificar el KDF del vault para opcionalmente usar el secreto de Passkey
- Fallback obligatorio a contraseña maestra

---

## Librerías y referencias que usaremos

**Backend (Python):**
- `pyotp`: para generar y verificar códigos TOTP (súper simple)
- `webauthn` (py_webauthn): para toda la ceremonia WebAuthn (más complejo, pero bien documentado)

**Frontend (Vue.js):**
- `navigator.credentials.create()`: API nativa del navegador para registrar Passkeys
- `navigator.credentials.get()`: API nativa para autenticarse con Passkeys
- QR del TOTP: se genera en el backend como `otpauth://...`, el frontend lo renderiza con cualquier librería de QR (hay muchas)

**Referencias importantes:**
- RFC 6238: cómo funciona TOTP (la matemática)
- W3C WebAuthn spec: cómo funciona WebAuthn (muy largo, pero completo)
- Bitwarden: mirá cómo lo hace ellos (referencia real de Passkeys en un gestor de contraseñas)

---

**Última cosa**: cuando implementemos, consulta este documento siempre que tengas una duda. Es fácil perderse en los detalles. Aquí está todo resumido, humano, sin tanto "jargon" técnico.
