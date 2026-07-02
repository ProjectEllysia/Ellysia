# IRIS Phishing Detection Rules — Study Guide

Cuaderno de estudio sobre las 35 reglas de detección de phishing del motor IRIS.
Cada regla explica: qué analiza, qué concepto de ciberseguridad hay detrás,
cuándo es indicio de phishing y cuándo es un falso positivo (legítimo).

---

## Tabla de Contenidos

1. [Autenticación de Correo (SPF, DKIM, DMARC, Domain Alignment)](#1-autenticación-de-correo)
2. [Análisis de Identidad del Remitente](#2-análisis-de-identidad-del-remitente)
3. [Análisis de Cabeceras de Respuesta y Ruta de Retorno](#3-análisis-de-cabeceras-de-respuesta-y-ruta-de-retorno)
4. [Análisis de Hilos y Encadenamiento](#4-análisis-de-hilos-y-encadenamiento)
5. [Análisis de Destinatarios](#5-análisis-de-destinatarios)
6. [Análisis de Marcas de Tiempo y Cadena Received](#6-análisis-de-marcas-de-tiempo-y-cadena-received)
7. [Análisis de Tipo de Contenido y Confianza](#7-análisis-de-tipo-de-contenido-y-confianza)
8. [Análisis del Cuerpo del Mensaje](#8-análisis-del-cuerpo-del-mensaje)
9. [Análisis de Enlaces en el Cuerpo](#9-análisis-de-enlaces-en-el-cuerpo)
10. [Análisis de Imágenes y Adjuntos](#10-análisis-de-imágenes-y-adjuntos)
11. [Resumen de Scores y Severidades](#11-resumen-de-scores-y-severidades)

---

## 1. Autenticación de Correo

La autenticación de correo electrónico es la primera línea de defensa contra
el spoofing. Existen tres protocolos principales que trabajan juntos: SPF,
DKIM y DMARC. Entenderlos es fundamental para saber por qué un correo que
"parece" venir de `paypal.com` puede en realidad ser falso.

### Arquitectura del Sistema de Correo

Antes de entrar en cada protocolo, es importante entender que un correo
electrónico tiene dos identidades distintas:

```
Sobre (Envelope):  MAIL FROM: <bounces@legit.com>     ← Return-Path
Carta (Message):   From: "PayPal Support" <support@paypal.com>   ← Visible
```

El **sobre** (MAIL FROM / Return-Path) es lo que usan los servidores SMTP
para enrutar y gestionar rebotes. La **carta** (cabecera `From`) es lo que
ve el usuario. Un atacante puede escribir cualquier cosa en `From` — la
autenticación existe precisamente para verificar que quien dice ser el
remitente realmente está autorizado.

---

### 1.1 SPF (Sender Policy Framework)

**Archivo:** `spf.py`

**Qué analiza:**
SPF verifica que el servidor que entregó el correo está autorizado por el
dueño del dominio para enviar correo en su nombre. Funciona mediante
registros DNS de tipo TXT.

**Cómo funciona:**
1. El dominio `ejemplo.com` publica un registro TXT como:
   ```
   "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all"
   ```
2. Cuando un servidor recibe un correo que dice `MAIL FROM: alguien@ejemplo.com`,
   consulta el registro SPF de `ejemplo.com`.
3. Compara la IP del servidor que entregó el correo con las IPs autorizadas.
4. El resultado se registra en la cabecera `Authentication-Results` como
   `spf=pass`, `spf=fail`, `spf=softfail`, `spf=neutral`, etc.

**Resultados posibles:**

| Resultado SPF | Significado | Score IRIS |
|---|---|---|
| `pass` | El servidor está autorizado | +5 |
| `fail` / `hardfail` | El servidor NO está autorizado | -20 |
| `softfail` / `neutral` | El dominio no tiene política estricta | -5 |
| `permerror` / `temperror` | Error DNS al consultar | -3 |
| ausente | No hay información SPF | 0 |

**Cuándo es phishing:**
- **SPF fail/hardfail**: Significa que el servidor que envió el correo no está
  en la lista de servidores autorizados. Si el dominio es `paypal.com` y SPF
  falla, el correo NO viene de PayPal, punto. Score: **-20**, la penalización
  más alta del sistema.

**Cuándo NO es phishing (falsos positivos):**
- **SPF ausente**: Muchos dominios pequeños no configuran SPF. No es sospechoso
  por sí mismo; solo un SPF *fail* es evidencia de spoofing.
- **SPF pass con dominio incorrecto**: SPF autentica el `MAIL FROM` (sobre),
  NO el `From` visible. Un atacante puede comprar `evil.com`, configurar SPF
  correctamente, y luego poner `From: soporte@paypal.com`. SPF dará `pass`
  porque el sobre es `evil.com` y su SPF es válido — pero el remitente visible
  es falso. Este gap lo cubre la regla **Domain Alignment**.

**Concepto clave de ciberseguridad:**
SPF protege el **sobre** (MAIL FROM/Return-Path), no el remitente visible
(`From`). Esta es la limitación más importante de SPF y la razón por la que
existen DKIM y DMARC.

---

### 1.2 DKIM (DomainKeys Identified Mail)

**Archivo:** `dkim.py`

**Qué analiza:**
DKIM verifica la integridad del mensaje mediante una firma criptográfica.
El servidor del remitente firma partes seleccionadas del correo (cabeceras
y cuerpo) con su clave privada. El destinatario verifica la firma usando la
clave pública publicada en el DNS del dominio firmante.

**Cómo funciona:**
1. El servidor emisor calcula un hash del contenido del mensaje y de ciertas
   cabeceras (incluyendo `From`).
2. Firma ese hash con su clave privada y lo añade en la cabecera
   `DKIM-Signature`, que incluye el parámetro `d=` (dominio firmante).
3. El servidor receptor consulta el DNS de `d=` para obtener la clave pública
   (registro TXT en `selector._domainkey.dominio.com`).
4. Verifica que la firma coincide y que el contenido no fue alterado.

**Ejemplo de cabecera DKIM-Signature:**
```
DKIM-Signature: v=1; a=rsa-sha256; d=paypal.com; s=pp-dkim1;
  h=from:to:subject:date; bh=base64hash; b=base64signature
```

**Resultados:**

| Resultado DKIM | Significado | Score IRIS |
|---|---|---|
| `pass` | Firma válida, contenido íntegro | +5 |
| `fail` | Firma inválida, contenido alterado | -15 |
| ausente | No hay firma DKIM | 0 (neutral) |

**Cuándo es phishing:**
- **DKIM fail**: La firma no es válida. Esto significa que el correo fue
  alterado después de ser firmado (un atacante modificó cabeceras o cuerpo
  tras la firma original), o el atacante intentó forjar una firma sin tener
  la clave privada. Score: **-15**.

**Cuándo NO es phishing:**
- **DKIM pass con dominio incorrecto**: Igual que SPF, DKIM solo autentica
  el dominio `d=` (el que firmó), no el `From` visible. Un atacante puede
  firmar con su propio dominio `evil.com` y DKIM dará `pass`, pero el `From`
  visible seguirá siendo falso. De nuevo, el gap lo cubre **Domain Alignment**.
- **DKIM ausente**: Muchas organizaciones legítimas no implementan DKIM.
  No es sospechoso por sí mismo.

**Concepto clave:**
DKIM proporciona **integridad** (el mensaje no fue modificado en tránsito)
y **autenticidad del dominio firmante**, pero no vincula el dominio firmante
con el remitente visible. Un DKIM `pass` de `sendgrid.net` no significa que
el `From: ceo@tuempresa.com` sea legítimo — SendGrid firmó el correo, pero
cualquiera puede usar SendGrid con cualquier `From`.

---

### 1.3 DMARC (Domain-based Message Authentication, Reporting & Conformance)

**Archivo:** `dmarc.py`

**Qué analiza:**
DMARC es la capa que une SPF y DKIM exigiendo **alineación de dominio**:
el dominio autenticado por SPF o DKIM debe coincidir con el dominio visible
en `From`. Además, el dueño del dominio publica una política que indica qué
hacer cuando la autenticación falla.

**Cómo funciona:**
1. El dominio `paypal.com` publica un registro DNS TXT en `_dmarc.paypal.com`:
   ```
   "v=DMARC1; p=reject; rua=mailto:dmarc@paypal.com; pct=100"
   ```
2. Cuando un correo llega con `From: soporte@paypal.com`, el servidor receptor:
   - Verifica SPF: ¿el servidor que entregó está autorizado por `paypal.com`?
   - Verifica DKIM: ¿el dominio `d=` de la firma DKIM es `paypal.com`?
   - Si al menos uno pasa Y está alineado con `paypal.com` → DMARC `pass`
   - Si ambos fallan o no alinean → se aplica la política `p=`:
     - `none`: no hacer nada (monitorización)
     - `quarantine`: enviar a spam
     - `reject`: rechazar el correo

**Resultados:**

| Resultado DMARC | Significado | Score IRIS |
|---|---|---|
| `pass` | SPF/DKIM alineados con From | +5 |
| `fail` | Sin alineación → el From es falso | -20 |
| `none` | Dominio sin política (p=none) | -3 |
| `bestguesspass` | Aproximación de pass | +3 |
| `reject/quarantine` | Dominio publica política estricta | +3 |
| ausente | No hay información DMARC | 0 |

**Cuándo es phishing:**
- **DMARC fail (-20)**: Es la señal más fuerte del sistema. Significa que
  ni SPF ni DKIM están alineados con el `From` visible. En otras palabras:
  el correo dice venir de `paypal.com` pero ni el servidor que lo envió ni
  la firma criptográfica pertenecen a `paypal.com`. Esto es suplantación
  comprobada.

**Cuándo NO es phishing:**
- **DMARC none**: El dominio existe pero su dueño configuró `p=none`
  (solo monitorizar). Es una mala práctica de seguridad, pero común en
  dominios pequeños. No indica que el correo sea phishing.
- **DMARC ausente**: Si el usuario pegó cabeceras parciales, puede faltar
  `Authentication-Results`. No se penaliza.

**Concepto clave:**
DMARC es el protocolo que realmente previene el spoofing del `From` visible.
Sin DMARC, SPF y DKIM son necesarios pero no suficientes. Por eso se penaliza
tan fuerte el DMARC fail (-20) y el SPF fail (-20): si un dominio legítimo
tiene DMARC `reject`, simplemente no puede ser suplantado.

---

### 1.4 Domain Alignment (Alineación de Dominio)

**Archivo:** `domain_alignment.py`

**Qué analiza:**
Esta regla cierra el gap que SPF y DKIM dejan abierto. Verifica que cuando
SPF o DKIM reportan `pass`, el dominio que autenticaron **coincide** realmente
con el dominio del `From` visible. Es esencialmente la verificación manual
de lo que DMARC hace automáticamente.

**Ejemplo concreto del problema:**
```
From: "CEO" <ceo@tuempresa.com>
DKIM-Signature: d=sendgrid.net
Authentication-Results: dkim=pass
```
Aquí DKIM dio `pass`, pero `sendgrid.net` autenticó el correo, no `tuempresa.com`.
SendGrid es un ESP legítimo — pero tu CEO probablemente no usa SendGrid para
enviar correos internos. Este es el fingerprint clásico de un ataque:
el atacante alquila o registra un dominio, configura DKIM, y pone un `From`
falso. La regla detecta exactamente esto.

**Cómo funciona:**
1. Extrae el dominio `From` (ej: `tuempresa.com`).
2. Si DMARC ya reportó `pass`, no hace falta verificar más (DMARC ya probó
   la alineación).
3. Si no hay DMARC `pass`, busca en `Authentication-Results`:
   - Si `dkim=pass`, extrae `d=` de la firma DKIM.
   - Si `spf=pass`, extrae `smtp.mailfrom=` del resultado.
4. Compara el dominio registrable de cada uno con el dominio `From`.

**Resultados:**

| Resultado | Significado | Score IRIS |
|---|---|---|
| Alineado (coinciden) | SPF/DKIM autentican mismo dominio que From | +3 |
| NO alineado (no coinciden) | SPF/DKIM pasan pero dominio distinto al From | -15 |
| DMARC ya pasó | No necesita verificación adicional | +3 |
| Sin identidad que comparar | No hay SPF/DKIM pass que analizar | 0 |

**Cuándo es phishing:**
- **Desalineación (-15)**: SPF o DKIM pasaron, pero el dominio autenticado
  es diferente al `From`. Es el patrón exacto de un atacante que controla
  su propio dominio con SPF/DKIM correcto y falsifica el `From`.

**Cuándo NO es phishing:**
- **ESP legítimos**: Si tu empresa envía newsletters por Mailchimp, el DKIM
  puede ser `d=mailchimp.com` y el `From=newsletter@tuempresa.com`. Pero en
  este caso DMARC debería estar configurado con `p=quarantine` o `p=reject`
  y el ESP incluido en el SPF — por lo que DMARC pasaría y esta regla no
  añadiría penalización.
- **DMARC ya pass**: Si DMARC pasó, esta regla se salta el análisis porque
  DMARC ya validó la alineación.

**Concepto clave:**
Esta regla es la red de seguridad para cuando DMARC no está presente o no
pasó, pero SPF/DKIM sí pasaron individualmente. Un SPF pass aislado
**no significa nada** sobre la legitimidad del remitente si no hay
alineación. Nunca confíes en un SPF/DKIM pass sin verificar contra qué
dominio se autenticaron.

---

## 2. Análisis de Identidad del Remitente

Estas reglas analizan quién dice ser el remitente (`From`) y si esa identidad
es consistente, legítima y no intenta suplantar a marcas conocidas.

### 2.1 From Header Check

**Archivo:** `from_header_check.py`

**Qué analiza:**
Verifica que la cabecera `From` esté presente y no vacía. Es la validación
más básica posible: todo correo legítimo tiene un remitente identificable.

**Cuándo es phishing:**
- `From` vacío o `From: <>`: Indica un correo generado automáticamente sin
  remitente real. Legítimo solo en notificaciones de entrega (NDR/bounce)
  y mensajes del sistema. En correo normal, es muy sospechoso. Score: **-10**.

**Cuándo NO es phishing:**
- `From: <>` en un bounce message (NDR) del servidor de correo es completamente
  normal — el servidor usa `<>` para evitar bucles de rebote.

**Concepto clave:**
Aunque simple, esta regla atrapa correos malformados generados por kits de
phishing rudimentarios que ni siquiera se molestan en falsificar un remitente.

---

### 2.2 Display Name Spoofing (Suplantación de Nombre Visible)

**Archivo:** `display_name_spoof.py`

**Qué analiza:**
El campo `From` tiene dos partes: el **display name** (nombre visible) y la
**dirección real**. Esta regla detecta cuando el nombre visible contiene una
marca conocida (PayPal, Microsoft, Amazon, etc.) pero la dirección de correo
real no pertenece a esa marca.

**Ejemplo:**
```
From: "PayPal Support" <phisher123@gmail.com>
```
El display name dice "PayPal Support" pero la dirección real es Gmail.
PayPal nunca envía correos desde Gmail.

**Cómo funciona:**
1. Extrae el display name y la dirección de correo del `From`.
2. Busca palabras clave de marcas conocidas en el display name (ej: "paypal",
   "microsoft", "apple", "netflix", "banco", "santander", "bbva"...).
3. Si encuentra una marca, verifica si el dominio del correo pertenece a la
   lista de dominios oficiales de esa marca.
4. Si no coincide, clasifica el dominio: ¿es un proveedor gratuito (Gmail,
   Outlook, Yahoo) o un dominio cualquiera?

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Display name contiene marca + dominio oficial de la marca | +5 (pass, confianza) |
| Display name contiene marca + dominio gratuito (Gmail, Outlook) | -12 (spoof) |
| Display name contiene marca + dominio no oficial (no gratuito) | -8 (spoof) |
| Display name no contiene marcas conocidas | +2 (pass) |

**Cuándo es phishing:**
- **Marca + Gmail (-12)**: Es el caso más claro. Ninguna empresa seria usa
  Gmail para comunicaciones oficiales. Score más alto porque el atacante
  usó un servicio gratuito, lo cual es trivial de hacer.
- **Marca + dominio no oficial (-8)**: El atacante registró su propio dominio
  (ej: `soporte-paypal.com`). Puede pasar SPF/DKIM con su dominio. Score
  ligeramente menor porque al menos no es un correo gratuito desechable.

**Cuándo NO es phishing:**
- **Marca + dominio oficial (+5)**: El display name dice "PayPal" y el correo
  es `@paypal.com`. Perfectamente legítimo. La regla incluso da puntos
  positivos.
- **Sin marca (+2)**: El display name no menciona ninguna marca conocida.
  Podría ser phishing genérico, pero esta regla no lo detecta.

**Concepto clave:**
El display name es **arbitrario** — cualquiera puede poner "CEO de Microsoft"
como nombre visible. Los clientes de correo modernos muestran el display name
de forma prominente (a veces más que la dirección real), lo que hace esta
técnica de suplantación especialmente efectiva. Es lo que se conoce como
**display name deception** o **friendly name spoofing**.

---

### 2.3 Display Name Email Mismatch (Desajuste Nombre-Dirección)

**Archivo:** `display_name_email_mismatch.py`

**Qué analiza:**
Similar a Display Name Spoofing, pero en lugar de buscar marcas conocidas,
detecta cuando la parte local del correo (lo que va antes del `@`) es una
cadena **aleatoria/autogenerada**, lo que indica una cuenta recién creada
para phishing masivo.

**Ejemplo:**
```
From: "PayPal Support" <x8hd92kj.thx@gmail.com>
```
La parte local `x8hd92kj.thx` no es un nombre humano ni un rol — parece
generada automáticamente por un script o kit de phishing.

**Cómo funciona:**
1. Extrae el display name y la dirección de correo.
2. Analiza la parte local (antes del `@`) con heurísticas:
   - ¿Es un rol conocido? (`support`, `info`, `admin`, `noreply`...)
   - ¿Es corto? (< 8 caracteres, probablemente nombre real)
   - ¿Mezcla dígitos y letras en patrón no-palabra?
   - ¿Tiene puntos o signos `+`?
   - ¿La proporción de dígitos es > 35%?
3. Si parece aleatoria, se dispara la alerta.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Display name sugiere organización + local-part aleatoria | -10 |
| Local-part normal o tipo rol (support, info...) | 0 (neutral) |
| Sin display name o sin email | 0 (neutral) |

**Cuándo es phishing:**
- **Display name corporativo + local-part aleatoria (-10)**: El atacante
  creó una cuenta con nombre visible "Soporte Técnico" pero la dirección
  es una cadena autogenerada tipo `a7k3m9x.verify@outlook.com`. Es
  característico de registros masivos automatizados para campañas de phishing.

**Cuándo NO es phishing:**
- **Local-part de rol**: `support@`, `info@`, `noreply@` son direcciones
  funcionales perfectamente legítimas.
- **Local-part corto sin dígitos**: Nombres como `juan.perez@` o `mgarcia@`
  no disparan la regla.
- **Sin display name**: Si no hay nombre visible, no hay desajuste que detectar.

**Concepto clave:**
Esta regla complementa a Display Name Spoofing detectando cuentas que no
necesariamente suplantan una marca concreta, sino que usan nombres genéricos
("Soporte", "Administración", "Recursos Humanos") desde cuentas recién
creadas y desechables. Es el patrón de **phishing masivo** (spray-and-pray)
vs el **spear phishing** dirigido.

---

### 2.4 Lookalike Sender Domain (Dominio Falso del Remitente)

**Archivo:** `lookalike_domain.py`

**Qué analiza:**
Detecta cuando el dominio del `From` NO es el dominio oficial de una marca,
sino una imitación creada mediante typosquatting, homóglifos (homoglyphs),
dominios "cousin" (combosquatting) o codificación punycode/IDN.

Esta regla inspecciona el **dominio real registrado**, no el display name.
Es más difícil de evadir que la suplantación de nombre visible.

**Tipos de imitación detectados:**

| Tipo | Ejemplo | Descripción |
|---|---|---|
| **Typosquatting** | `paypa1.com` | Un carácter cambiado; error tipográfico |
| **Homoglyph** | `paypaI.com` (con 'I' mayúscula en vez de 'l') | Carácter visualmente idéntico pero distinto en Unicode |
| **Cousin/Combosquat** | `paypal-security.com` | Marca + palabra adicional en el dominio registrable |
| **Punycode/IDN** | `xn--pypal-4ve.com` | Dominio con caracteres Unicode que parecen ASCII |

**Cómo funciona:**
1. Extrae el dominio del `From`.
2. Si contiene `xn--`, es punycode/IDN → alerta inmediata (-15).
3. Extrae el "registrable label" (ej: de `login.paypal.com` → `paypal`).
4. Si es exactamente una marca conocida → pass (es el dominio real).
5. Divide el label en tokens; para cada token:
   - ¿Es una marca exacta dentro de una palabra más larga? → cousin domain
   - ¿Al normalizar homóglifos coincide con una marca? → homoglyph
   - ¿Distancia Levenshtein = 1 con alguna marca? → typosquat

**Reglas estrictas para typosquat:**
- La marca debe tener ≥ 5 caracteres (evita falsos positivos con "visa",
  "ebay", "aws" que son palabras cortas comunes).
- Mismo primer carácter que la marca.
- Diferencia de longitud ≤ 1.
- Distancia de edición exactamente 1.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Dominio es marca exacta (ej: `paypal.com`) | +1 (pass) |
| Punycode/IDN (`xn--`) | -15 |
| Homoglyph, typo o cousin domain | -15 |

**Cuándo es phishing:**
- **Punycode (-15)**: Los caracteres Unicode permiten registrar dominios que
  parecen idénticos al original. Por ejemplo, la 'а' cirílica (U+0430) es
  visualmente idéntica a la 'a' latina (U+0061). Un dominio registrado con
  caracteres cirílicos que deletrean "paypal" se verá exactamente igual en
  la barra de direcciones. El prefijo `xn--` delata la codificación IDN.
- **Cousin domain (-15)**: `paypal-security.com` o `microsoft-verify.com`
  aparentan ser subdominios oficiales pero son dominios independientes
  controlados por el atacante. Pueden tener SPF/DKIM/DMARC perfectamente
  configurados para su propio dominio.

**Cuándo NO es phishing:**
- **Dominio exacto de la marca (+1)**: `paypal.com`, `microsoft.com`, etc.
- **Dominio sin similitud con marcas**: Una empresa legítima con un nombre
  que no se parece a ninguna marca conocida.

**Concepto clave:**
Los atacantes modernos ya no dependen de spoofing de cabeceras (que DMARC
bloquea). En su lugar, **registran dominios que parecen legítimos** y
configuran correctamente SPF/DKIM/DMARC para sus propios dominios. Esto
evade completamente las reglas de autenticación. Las reglas de lookalike
son la defensa contra esta evolución del ataque.

---

### 2.5 Subdomain Impersonation (Suplantación por Subdominio)

**Archivo:** `subdomain_impersonation.py`

**Qué analiza:**
Complementa a Lookalike Sender Domain analizando el **dominio completo**,
no solo la etiqueta registrable. Detecta patrones donde una marca conocida
aparece como subdominio o combinada con "action words" en un dominio
controlado por el atacante.

**Ejemplos de patrones detectados:**

| Patrón | Ejemplo | Explicación |
|---|---|---|
| Marca como subdominio | `paypal.com.secure-login.tk` | El dominio real es `.tk`; `paypal.com` es solo un subdominio falso |
| Marca + action word | `secure-paypal.com` | La marca está combinada con palabra de acción en el dominio registrable |
| Marca + guion + acción | `account-microsoft-verify.com` | Múltiples tokens de marca/acción |
| Punycode en subdominio | `xn--pple-43d.login.com` | IDN en cualquier etiqueta del dominio |

**Cómo funciona:**
1. Extrae el dominio completo del `From`.
2. Si el dominio registrable es exactamente una marca → pass (dominio real).
3. Separa el dominio en etiquetas (labels) separadas por puntos.
4. En las etiquetas que NO son el dominio registrable (subdominios), busca
   marcas conocidas completas.
5. En TODAS las etiquetas (incluyendo el registrable), busca combinaciones
   de `marca-actionword` separadas por guiones (ej: `paypal-login` donde
   `paypal` es la marca y `login` es una action word como "login", "verify",
   "secure", "account", "update", etc.).

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Dominio real de marca legítima | +1 (pass) |
| Marca en subdominio | -12 |
| Marca + action word | -8 |
| Punycode en cualquier etiqueta | -10 |

**Cuándo es phishing:**
- **Marca en subdominio (-12)**: `paypal.com.phishing-site.xyz` — el atacante
  usa "paypal.com" como una etiqueta de subdominio (lo cual es perfectamente
  legal en DNS) para engañar visualmente. Muchos usuarios miran solo el
  principio del dominio y asumen que es legítimo.

**Cuándo NO es phishing:**
- **Dominio real de la marca**: `www.paypal.com` o `login.paypal.com` — la
  marca está en el dominio registrable, no en un subdominio de otro dominio.
- **Subdominios sin marcas**: `www.empresa-legitima.com` no contiene marcas
  conocidas en sus subdominios.

**Concepto clave:**
DNS permite que cualquier dueño de dominio cree cualquier subdominio. Si
yo registro `evil.tk`, puedo crear `paypal.com.evil.tk` y es perfectamente
válido. La confusión visual explota que muchos usuarios leen de izquierda
a derecha y asumen que lo primero que ven es el dominio real. En realidad,
el dominio real se lee de derecha a izquierda: `.tk` es el TLD, `evil` es
el dominio registrable, y `paypal.com` es solo un subdominio decorativo.

---

### 2.6 Misspelled Brand Names (Nombres de Marca Mal Escritos)

**Archivo:** `misspelled_brands.py`

**Qué analiza:**
Detecta homóglifos y typosquatting de marcas conocidas en el **asunto**
(`Subject`) y en el **nombre visible** (`From` display name), no en el
dominio real. Complementa a Lookalike Sender Domain analizando el texto
visible al usuario.

**Ejemplos:**
- "Micr0soft" (homóglifo: '0' parece 'o')
- "PayPa1" (homóglifo: '1' parece 'l')
- "Netfl1x" (homóglifo)
- "Amaz0n" (homóglifo)
- "Paymen" → "PayPal" (typo: distancia Levenshtein 1, aunque letra inicial
  difiere, por eso se usa también homóglifo)

**Cómo funciona:**
1. Concatena `Subject` y nombre visible del remitente.
2. Extrae palabras de 5+ caracteres.
3. Si la palabra es exactamente una marca → la ignora (es legítima).
4. Normaliza homóglifos (reemplaza '0'→'o', '1'→'l', '@'→'a', '$'→'s',
   '€'→'e', etc.) y compara con marcas conocidas.
5. Para typos clásicos, aplica reglas estrictas:
   - Marca de ≥ 5 caracteres
   - Misma letra inicial
   - Diferencia de longitud ≤ 1
   - Distancia Levenshtein = 1

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin palabras sospechosas | 0 (pass) |
| 1 homóglifo o typo detectado | -5 |
| 2+ homóglifos o typos detectados | -10 |

**Cuándo es phishing:**
- **Homóglifo en asunto (-5/-10)**: "Verifica tu cuenta de Micr0soft" —
  el atacante usa caracteres visualmente similares para evadir filtros
  de texto exacto. Es intencional: ningún error tipográfico legítimo
  produce "Micr0soft".

**Cuándo NO es phishing (falsos positivos controlados):**
- **Palabras cortas ignoradas**: Marcas como "visa", "ebay", "aws", "amex"
  son demasiado cortas (4 letras) y demasiado comunes en otros contextos.
  No se analizan como typos para evitar falsos positivos masivos.
- **Palabras en español**: "aviso" no es un typo de "visa", "marca" no es
  typo de "amex". Las reglas estrictas (misma letra inicial + distancia 1)
  evitan estos falsos positivos.

**Concepto clave:**
La normalización de homóglifos (homoglyph normalization) es una técnica de
defensa que convierte caracteres visualmente similares a su forma canónica
antes de comparar. Sin esta técnica, "Micr0soft" y "Microsoft" serían
palabras diferentes para cualquier filtro de texto. Los atacantes explotan
que el ojo humano lee patrones, no caracteres individuales, mientras que
los filtros simples comparan bytes.

---

### 2.7 Suspicious TLD (TLD Sospechoso)

**Archivo:** `suspicious_tld.py`

**Qué analiza:**
Detecta si el dominio del remitente (en `From`, `Reply-To` o `Return-Path`)
usa un TLD (Top-Level Domain) de bajo costo o gratuito que es
desproporcionadamente usado en campañas de phishing.

**TLDs marcados como sospechosos:**
`.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.loan`, `.work`,
`.click`, `.zip`, `.download`, `.review`, `.country`, `.kim`, `.men`, `.bid`,
`.trade`, `.racing`, `.win`, `.stream`, `.date`, `.party`, `.science`,
`.accountant`, `.faith`

**Por qué estos TLDs son sospechosos:**
- **Gratuitos**: `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (Freenom) permiten
  registrar dominios sin costo y sin verificación de identidad.
- **Baratos**: `.xyz`, `.top`, `.click`, `.work` cuestan centavos el primer
  año. Ideales para campañas de usar y tirar.
- **Sin restricciones**: No requieren presencia local ni documentación.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin TLDs sospechosos | +1 (pass) |
| 1 dominio con TLD sospechoso | -5 |
| N dominios con TLD sospechoso | -5 × N |

**Cuándo es phishing:**
- **`.tk`/`.ml`/`.ga`/`.cf`/`.gq` en cualquier cabecera**: Son dominios
  gratuitos sin verificación. Casi ninguna empresa legítima los usa.
- **Combinación de TLD sospechoso + marca conocida**: `paypal-verify.tk` —
  esta regla aporta una penalización adicional que se suma a lookalike
  domain y display name spoofing.

**Cuándo NO es phishing:**
- **`.xyz` usado por startups**: Algunas empresas tecnológicas usan `.xyz`
  legítimamente (ej: Alphabet usa `abc.xyz`). La penalización es baja (-5)
  y se evalúa en conjunto con otras reglas.
- **`.work` como TLD de portfolio**: Un profesional puede usar `.work` para
  su sitio de portfolio. Pero en correo corporativo es raro.

**Concepto clave:**
El TLD es el componente más a la derecha del dominio (`gmail.com` → `.com`).
Los TLDs baratos/gratuitos permiten a los atacantes registrar cientos de
dominios desechables a bajo costo, rotándolos cuando son bloqueados. Esta
táctica se llama **domain fluxing** y depende de la disponibilidad de TLDs
sin barreras de entrada.

---

## 3. Análisis de Cabeceras de Respuesta y Ruta de Retorno

Estas reglas analizan la coherencia entre tres identidades del correo:
- **From**: lo que el usuario ve como remitente
- **Reply-To**: a dónde van las respuestas
- **Return-Path** (Envelope-From / MAIL FROM): a dónde van los rebotes

En un correo legítimo, estas identidades suelen ser la misma o pertenecer
a la misma organización. Las discrepancias son explotadas en ataques BEC
y phishing.

---

### 3.1 Reply-To Check

**Archivo:** `reply_to.py`

**Qué analiza:**
Detecta cuando la cabecera `Reply-To` apunta a un dominio organizacional
diferente al del `From`. Si respondes al correo, tu respuesta va al atacante
en lugar del remitente visible.

**Ejemplo clásico de BEC:**
```
From: "CEO" <ceo@empresa.com>
Reply-To: ceo.urgencia@gmail.com
```
El empleado ve que el correo viene del CEO. Responde. Su respuesta va a
Gmail, controlado por el atacante, no al CEO real.

**Cómo funciona:**
1. Extrae el dominio del `From` y del `Reply-To`.
2. Compara los **dominios registrables** (no subdominios) de ambos.
3. `info.unir.net` y `comunicaciones.unir.net` tienen el mismo dominio
   registrable `unir.net` → son de la misma organización → sin alerta.
4. `ceo@empresa.com` y `ceo@gmail.com` tienen dominios registrables
   diferentes (`empresa.com` vs `gmail.com`) → alerta.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin Reply-To (normal en correo directo) | +3 (pass) |
| Reply-To mismo dominio registrable que From | +3 (pass) |
| Reply-To dominio registrable diferente | -10 (fail) |

**Cuándo es phishing:**
- **Reply-To a dominio diferente (-10)**: La desconexión entre el remitente
  visible y el destino de respuesta es el modus operandi del Business Email
  Compromise (BEC). El atacante quiere que la víctima responda, no que mire
  la dirección real.

**Cuándo NO es phishing:**
- **Newsletters de ESP**: `From: newsletter@empresa.com` con
  `Reply-To: replies@email.mailchimp.com` → mismo dominio registrable que
  la empresa no, pero es un patrón legítimo de email marketing. Sin embargo,
  esta regla lo marcaría como fail. La regla **Reply-To Free Provider** y
  **Triangulation** ayudan a refinar el contexto.
- **Sin Reply-To (+3)**: El correo no tiene Reply-To, lo cual es normal en
  correo personal y transaccional directo. La regla premia esto con +3.

**Concepto clave:**
`From` y `Reply-To` son cabeceras independientes definidas en el mensaje.
El remitente puede poner cualquier valor en ambas. La comparación a nivel
de **dominio registrable** (no dominio completo) es importante porque muchos
ESP usan subdominios legítimos para gestionar respuestas, y penalizar eso
generaría falsos positivos masivos.

---

### 3.2 Reply-To Free Provider (Reply-To a Proveedor Gratuito)

**Archivo:** `reply_to_free_provider.py`

**Qué analiza:**
Versión más específica de Reply-To Check. Detecta cuando el remitente visible
(`From`) usa un dominio corporativo (no gratuito), pero las respuestas se
redirigen a un proveedor gratuito (Gmail, Outlook, Yahoo, etc.). Este es el
patrón más común de BEC.

**Ejemplo:**
```
From: "Director Financiero" <dfinanciero@multinacional.com>
Reply-To: director.prjct@gmail.com
Return-Path: director.prjct@gmail.com
```
El atacante falsifica el `From` (o compromete la cuenta real) y redirige
las respuestas a su Gmail personal.

**Cómo funciona:**
1. Extrae el dominio del `From`. Si es gratuito, no aplica (el remitente
   mismo ya es sospechoso, pero eso lo cubren otras reglas).
2. Extrae dominios de `Reply-To` y `Return-Path`.
3. Verifica si alguno es un proveedor gratuito Y es diferente al dominio
   del `From`.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| From corporativo + Reply/Return gratuito | -8 (fail) |
| From gratuito (no aplica) | +1 (pass) |
| Sin redirección a gratuito | +1 (pass) |

**Cuándo es phishing:**
- **Corporativo → Gmail/Outlook (-8)**: Nadie en una empresa configura su
  `Reply-To` para que las respuestas vayan a un Gmail personal. Si el
  dominio del `From` es `empresa.com`, el dominio de `Reply-To` debería
  ser `empresa.com` o un ESP conocido de la empresa.

**Cuándo NO es phishing:**
- **Pequeños negocios que usan Gmail**: Un autónomo puede usar
  `From: info@mi-tienda.com` (dominio propio) y `Reply-To: mipyme@gmail.com`
  porque no tiene servidor de correo. Es mala práctica pero no phishing.
  La penalización es moderada (-8) y se evalúa en conjunto con otras reglas.
- **From ya es gratuito**: Si el remitente ya es `@gmail.com`, que el
  Reply-To también lo sea no añade información.

**Concepto clave:**
El BEC (Business Email Compromise) es el tipo de ataque más costoso.
El FBI reporta pérdidas de miles de millones anuales. El patrón "dominio
corporativo en From + correo gratuito en Reply-To" es una firma casi
inequívoca. La defensa principal: **verificar siempre por un canal
alternativo** (llamada telefónica, mensaje en persona) antes de realizar
transferencias o enviar datos sensibles.

---

### 3.3 Return-Path Mismatch (Desajuste de Ruta de Retorno)

**Archivo:** `return_path_mismatch.py`

**Qué analiza:**
Compara el dominio del `Return-Path` (también llamado `Envelope-From` o
`MAIL FROM`) con el dominio del `From` visible. Si difieren, el correo
pudo ser generado por un servidor no autorizado.

**Return-Path vs From:**
- `Return-Path`: Lo usa el protocolo SMTP para enrutar y notificar rebotes.
  Añadido por el servidor de entrega final. El usuario no lo ve.
- `From`: Lo que muestra el cliente de correo al usuario.

**Ejemplo de phishing:**
```
Return-Path: <bounce@evil-phish.xyz>
From: "Banco Santander" <aviso@santander.com>
```
El sobre (Return-Path) revela el verdadero origen: `evil-phish.xyz`. El
remitente visible es falso.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin Return-Path | 0 (neutral) |
| Return-Path mismo dominio que From | +2 (pass) |
| Return-Path dominio diferente al From | -8 (fail) |

**Cuándo es phishing:**
- **Dominios diferentes (-8)**: El servidor que realmente entregó el correo
  no tiene relación con el dominio que dice el `From`.

**Cuándo NO es phishing:**
- **ESP legítimos**: `Return-Path: <bounces@sendgrid.net>` con
  `From: newsletter@tuempresa.com`. SendGrid es un ESP que gestiona los
  rebotes por tu empresa. La diferencia de dominio es normal en email
  marketing. Sin embargo, esta regla individual no distingue ESPs — se
  analiza junto con otras reglas como Triangulation para contexto.

**Concepto clave:**
`Return-Path` es añadido por el MTA (Mail Transfer Agent) final basado en
el `MAIL FROM` del protocolo SMTP. El remitente no controla directamente
su valor; es un subproducto de la transacción SMTP real. Por eso es más
difícil de falsificar que el `From` y constituye una señal más fiable del
verdadero origen.

---

### 3.4 From / Reply-To / Return-Path Triangulation

**Archivo:** `reply_to_path_mismatch.py`

**Qué analiza:**
En lugar de comparar pares (From vs Reply-To, From vs Return-Path), analiza
los **tres juntos**. Si las tres cabeceras apuntan a tres dominios
organizacionales distintos, es una firma estructural de phishing/BEC.

**Ejemplo de triangulación maliciosa:**
```
From: "CEO" <ceo@empresa.com>           ← Dominio A
Reply-To: ceo.urgente@outlook.com       ← Dominio B
Return-Path: bounce@phish-kit.xyz       ← Dominio C
```
Tres dominios diferentes. Ningún correo legítimo tiene esta estructura.

**Cómo funciona:**
1. Extrae el dominio registrable de `From`, `Reply-To` y `Return-Path`.
2. Cuenta cuántos son distintos.
3. Si son exactamente 3 distintos → alerta.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| 0, 1 o 2 dominios distintos | 0 (neutral) |
| 3 dominios distintos (triangulación) | -12 (fail) |

**Cuándo es phishing:**
- **Triangulación completa (-12)**: El atacante suplanta un `From` legítimo
  (dominio A), redirige respuestas a su webmail (dominio B), y el servidor
  SMTP que usó para enviar es otro distinto (dominio C). Es el rastro de
  una infraestructura de ataque con múltiples capas.

**Cuándo NO es phishing:**
- **2 dominios distintos**: `From=empresa.com`, `Reply-To=empresa.com`,
  `Return-Path=sendgrid.net`. Esto es normal cuando se usa un ESP. Solo 3
  dominios distintos disparan la alerta.
- **1 dominio distinto**: Todo apunta a la misma organización.

**Concepto clave:**
En un correo legítimo, las tres identidades orbitan alrededor de la misma
organización. El `From` es el remitente, el `Reply-To` puede ser un
departamento diferente pero del mismo dominio, y el `Return-Path` puede ser
el ESP de la empresa pero sigue siendo un servicio contratado POR la empresa.
Tres dominios **no relacionados** significan que el correo atravesó
infraestructura que nadie de la empresa controla.

---

## 4. Análisis de Hilos y Encadenamiento

Estas reglas analizan si el correo es realmente parte de una conversación
legítima o si está fingiendo serlo.

---

### 4.1 Fake Reply Chain (Cadena de Respuesta Falsa)

**Archivo:** `fake_reply_chain.py`

**Qué analiza:**
Detecta cuando el `Subject` comienza con prefijos de respuesta/reenvío
(`Re:`, `Fwd:`, `AW:`, `RV:`, `ENC:`) pero NO existen las cabeceras de
threading que toda respuesta legítima debe tener (`In-Reply-To`,
`References`, `Thread-Index`, `Thread-Topic`).

**Prefijos detectados:**
- `Re:`, `RE:`, `Re[2]:` — respuesta (inglés)
- `Fwd:`, `FW:` — reenviado
- `AW:`, `AW[2]:` — Antwort (alemán)
- `R:`, `R[1]:` — respuesta
- `RV:` — reenvío (español)
- `ENC:` — encaminado (portugués)

**Ejemplo de phishing:**
```
Subject: Re: Su factura pendiente #4582
In-Reply-To: (vacío)
References: (vacío)
```
El asunto dice "Re:" como si fuera respuesta a algo, pero no hay rastro de
a qué mensaje respondería. Es un correo nuevo disfrazado de respuesta.

**Cabeceras de threading que deberían existir:**
- **In-Reply-To**: Contiene el Message-ID del mensaje al que se responde.
- **References**: Cadena de Message-IDs de toda la conversación.
- **Thread-Index / Thread-Topic**: Alternativas de Microsoft Outlook/Exchange.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Asunto con prefijo + cabeceras de threading presentes | +2 (pass) |
| Asunto con prefijo + SIN cabeceras de threading | -4 (fail) |
| Asunto sin prefijo de respuesta | 0 (pass) |

**Cuándo es phishing:**
- **"Re:" sin In-Reply-To (-4)**: El atacante quiere que parezca que ya ha
  habido comunicación previa, generando confianza. La víctima piensa "esto
  es respuesta a algo que yo envié" y baja la guardia.

**Cuándo NO es phishing:**
- **Asunto normal sin "Re:"**: No aplica.
- **"Re:" con In-Reply-To/References (+2)**: Es una respuesta legítima a
  una conversación real. La regla incluso otorga puntos positivos.
- **Outlook Thread-Index**: Microsoft Exchange a veces no incluye
  In-Reply-To pero sí `Thread-Index`. La regla reconoce ambas variantes.

**Concepto clave:**
RFC 5322 define las cabeceras `In-Reply-To` y `References` para mantener
el árbol de conversación. Todo cliente de correo que responde a un mensaje
las incluye automáticamente. Un `Re:` manual (escrito por un humano o un
script) sin estas cabeceras es una bandera roja inmediata.

---

### 4.2 Self-Referencing In-Reply-To (Auto-Referencia en Threading)

**Archivo:** `in_reply_to_self_reference.py`

**Qué analiza:**
Detecta cuando el `In-Reply-To` (o el primer `References`) apunta al
**propio Message-ID del mismo correo**. Es decir, el correo dice ser
respuesta a sí mismo.

**Ejemplo:**
```
Message-ID: <abc123@phish.kit>
In-Reply-To: <abc123@phish.kit>
References: <abc123@phish.kit>
```
El mensaje se cita a sí mismo como su predecesor. Circular.

**Por qué sucede:**
Los kits de phishing que simulan hilos de conversación a veces generan un
`Message-ID` falso y luego, por error o por simplicidad del script, reutilizan
el mismo ID como `In-Reply-To` para un "segundo" mensaje de la campaña.
También puede ocurrir cuando un atacante fabrica manualmente cabeceras de
threading para añadir verosimilitud y comete este error.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin Message-ID | 0 (neutral) |
| In-Reply-To == Message-ID | -12 (fail) |
| Primer References == Message-ID | -12 (fail) |
| Sin auto-referencia | 0 (pass) |

**Cuándo es phishing:**
- **Auto-referencia (-12)**: Es un error que ningún MTA o MUA (cliente de
  correo) legítimo comete jamás. La probabilidad de que sea phishing es
  extremadamente alta. El score es -12, uno de los más altos en reglas de
  cabeceras individuales.

**Cuándo NO es phishing:**
- **Nunca ocurre en correo legítimo**: Un mensaje no puede ser respuesta a
  sí mismo. Si esta regla se dispara, es phishing con probabilidad cercana
  al 100%. Los únicos casos donde no se dispara son cuando el Message-ID
  no existe (neutral).

**Concepto clave:**
Un `Message-ID` es un identificador único global generado por el MTA que
origina el mensaje. RFC 5322 exige que sea único en el universo
(`id-left@id-right` donde `id-right` es un dominio). El `In-Reply-To`
siempre debe contener un Message-ID **distinto, generado previamente**.
La auto-referencia es una violación directa de la especificación.

---

### 4.3 Message-ID Check

**Archivo:** `message_id_check.py`

**Qué analiza:**
Verifica que la cabecera `Message-ID` esté presente y tenga una longitud
mínima razonable (> 5 caracteres).

**Por qué es importante:**
Todo MTA legítimo genera un `Message-ID` único y sustancial (típicamente
40+ caracteres con formato `<hash@domain>`). Un `Message-ID` ausente o
anormalmente corto sugiere un correo generado por un script simple que no
implementa correctamente el protocolo SMTP.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Message-ID presente y >= 5 caracteres | +1 (pass) |
| Message-ID ausente o < 5 caracteres | -4 (fail) |

**Cuándo es phishing:**
- **Falta o es cortísimo (-4)**: Kits de phishing rudimentarios y scripts
  de envío masivo a menudo omiten el Message-ID o usan valores placeholder.

**Cuándo NO es phishing:**
- **Presente y normal (+1)**: La mayoría del correo legítimo tiene Message-ID.
  Pero su presencia no es una prueba de legitimidad — un atacante sofisticado
  también genera Message-IDs.

**Concepto clave:**
Esta es una regla de "higiene" — atrapa lo más bajo de la cadena alimenticia
de phishing. Los atacantes sofisticados no caen aquí, pero los scripts
automáticos básicos sí.

---

### 4.4 Message-ID Domain

**Archivo:** `msgid_domain.py`

**Qué analiza:**
Compara el dominio dentro del `Message-ID` (la parte después del `@`) con
el dominio del `From`. Los MTA legítimos suelen generar el Message-ID en
la infraestructura del dominio remitente.

**Estructura de un Message-ID:**
```
Message-ID: <20240615.abc123-def456@mail.empresa.com>
                                     ^^^^^^^^^^^^^^^^
                                     dominio del Message-ID
```

**Cómo funciona:**
1. Extrae `id-right` (dominio tras `@`) del Message-ID.
2. Extrae el dominio registrable y lo compara con el dominio registrable
   del `From`.
3. Si coinciden → pass.
4. Si el dominio del Message-ID es un ESP conocido (SendGrid, Amazon SES,
   Mailgun, etc.) → pass (el ESP generó el Message-ID, es normal).
5. Si difieren y no es ESP → fail (leve).

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Message-ID y From mismo dominio | +1 (pass) |
| Message-ID de ESP conocido | 0 (pass) |
| Dominios diferentes | -3 (fail) |

**Cuándo es phishing:**
- **Dominios diferentes no-ESP (-3)**: El mensaje dice `From: info@banco.com`
  pero el Message-ID es `<...@some-random-server.xyz>`. El correo fue generado
  en infraestructura ajena al banco.

**Cuándo NO es phishing:**
- **ESPs (+0)**: Si usas Mailchimp, el Message-ID típicamente será
  `<...@mailchimp.com>`, no `@tuempresa.com`. Es normal.
- **Pequeña empresa con hosting compartido**: El servidor de correo puede
  tener un hostname diferente al dominio del `From`. Penalización baja (-3)
  para no castigar estos casos.

**Concepto clave:**
El `Message-ID` revela qué servidor generó originalmente el correo. Si el
correo dice venir del Banco Santander pero el Message-ID se generó en un
servidor ruso, algo no cuadra. Es una señal forense sutil pero valiosa
cuando se combina con otras reglas.

---

## 5. Análisis de Destinatarios

### 5.1 Undisclosed Recipients (Destinatarios Ocultos)

**Archivo:** `undisclosed_recipients.py`

**Qué analiza:**
Detecta correos enviados sin destinatario visible (BCC masivo), un patrón
común en campañas de phishing que se envían a miles de víctimas.

**Situaciones detectadas:**

| Situación | Explicación | Score IRIS |
|---|---|---|
| To vacío Y CC vacío | Todos en BCC — envío masivo ciego | -6 |
| To = "Undisclosed-Recipients" | El remitente explícitamente oculta destinatarios | -5 |
| To vacío pero CC presente | Patrón inusual pero posible en workflows | -2 |
| To y/o CC con destinatarios | Normal | +2 (pass) |

**Cuándo es phishing:**
- **BCC total (-6)**: Las campañas de phishing masivo se envían con todos
  los destinatarios en BCC para que las víctimas no vean que el mismo correo
  llegó a miles de personas.
- **Undisclosed-Recipients (-5)**: Es una cadena textual que indica intención
  expresa de ocultar destinatarios.

**Cuándo NO es phishing:**
- **Newsletters legítimas**: Las listas de correo legítimas también usan BCC
  o proveedores que ocultan destinatarios. La penalización es baja (-6/-5)
  justamente porque hay usos legítimos.
- **Correo directo normal (+2)**: Si el `To` contiene tu dirección o la de
  tu empresa, es correo normal.

**Concepto clave:**
BCC (Blind Carbon Copy) es una funcionalidad legítima de SMTP, pero su uso
exclusivo (sin `To` ni `CC`) es atípico en correo empresarial directo. Un
correo de tu banco NUNCA te llegará con destinatarios ocultos — siempre te
dirigirá por tu nombre o email en el `To`.

---

## 6. Análisis de Marcas de Tiempo y Cadena Received

Las cabeceras `Received:` forman la "trazabilidad" del correo: cada servidor
por el que pasa añade una línea con su IP, timestamp y detalles del protocolo.
Analizar esta cadena revela manipulación.

**Estructura de las cabeceras Received:**
```
Received: from mail.evil.com (mail.evil.com [192.168.1.100])
    by mx.destino.com with ESMTPS; Thu, 2 Jul 2025 10:00:00 -0400
Received: from localhost (localhost [127.0.0.1])
    by mail.evil.com with SMTP; Thu, 2 Jul 2025 10:05:00 -0400
```
El orden es de **destino a origen**: la primera línea es el último servidor
que tocó el correo (tu servidor de entrada), la última es el origen.

---

### 6.1 Date Header Anomaly (Anomalía de Fecha)

**Archivo:** `date_anomaly.py`

**Qué analiza:**
Verifica que la cabecera `Date` del correo esté presente, sea parseable y
esté dentro de un rango temporal razonable (no en el futuro lejano ni en
el pasado remoto).

**Rangos aceptables:**
- Máximo 1 día en el futuro (pequeño desfase horario o reloj ligeramente
  adelantado es normal).
- Máximo 365 días en el pasado (correos antiguos reenviados).

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Fecha normal (último año) | +1 (pass) |
| Fecha ausente | -3 (missing) |
| Fecha no parseable | -4 (unparseable) |
| Fecha > 1 día en el futuro | -4 (future) |
| Fecha > 365 días en el pasado | -2 (past) |

**Cuándo es phishing:**
- **Fecha futura (-4)**: Los atacantes pueden manipular la fecha para que
  el correo aparezca como "nuevo" en el inbox durante más tiempo, o
  simplemente porque el script de envío tiene un error de configuración
  horaria.
- **Fecha no parseable (-4)**: Formato de fecha inválido. Un MTA legítimo
  siempre genera fechas en RFC 5322.
- **Fecha ausente (-3)**: Correos generados automáticamente sin fecha.

**Cuándo NO es phishing:**
- **Pequeña diferencia horaria**: Unos minutos u horas de diferencia por
  zona horaria entran en el margen de 1 día.
- **Correos archivados**: Si reenvías un correo de hace años, tendrá fecha
  antigua pero es legítimo. Penalización baja (-2).

**Concepto clave:**
La cabecera `Date` la establece el MUA (cliente de correo) o MTA que origina
el mensaje. Los MTA legítimos sincronizan sus relojes por NTP y generan
fechas precisas. Una fecha drásticamente incorrecta sugiere que el mensaje
no pasó por un MTA estándar.

---

### 6.2 Received Chain (Cadena Received)

**Archivo:** `received_chain.py`

**Qué analiza:**
La cadena de cabeceras `Received:` que traza la ruta del correo desde el
origen hasta el destino. Esta regla busca anomalías en esa cadena.

**Qué detecta:**
1. **IP de origen privada/interna**: Si el primer salto (origen) tiene una
   IP privada (10.x.x.x, 192.168.x.x, 172.16-31.x.x), significa que el
   correo se originó en una red interna que no debería estar expuesta.
   Esto ocurre cuando un atacante falsifica cabeceras Received y usa IPs
   de ejemplo/placeholder.

2. **Desfase Date vs primer Received**: Compara la cabecera `Date` (cuándo
   se escribió el correo) con el timestamp del primer salto Received
   (cuándo se entregó al primer servidor). Un desfase > 6 horas sugiere
   manipulación.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Cadena normal | +1 (pass) |
| IP de origen privada | -5 |
| Desfase Date vs Received > 6h | -5 |
| Sin cadena Received | 0 (neutral) |

**Cuándo es phishing:**
- **IP privada en origen (-5)**: Un correo legítimo que viaja por Internet
  no puede originarse en `192.168.1.1`. Esa IP solo existe en redes locales.
  Aparece cuando el atacante fabrica cabeceras Received y no sabe qué IP
  poner, o cuando copia cabeceras de un entorno de prueba.
- **Desfase grande (-5)**: La hora del correo no coincide con cuándo fue
  enviado realmente según los servidores. Sugiere fabricación de cabeceras.

**Cuándo NO es phishing:**
- **Sin cadena Received**: Si el usuario pegó cabeceras incompletas, puede
  faltar la cadena Received. Neutral.
- **Desfase pequeño (< 6h)**: Diferentes zonas horarias y relojes no
  perfectamente sincronizados.

**Concepto clave:**
Las cabeceras `Received:` son la "cadena de custodia" del correo. Son
añadidas secuencialmente por cada MTA, cada uno añadiendo sus propios datos.
Falsificarlas coherentemente es difícil porque requieren que el atacante
conozca la topología de red entre el origen y el destino.

---

### 6.3 Received Chain Temporal Inconsistency

**Archivo:** `received_chain_temporal_inconsistency.py`

**Qué analiza:**
Va más allá de la regla anterior: verifica que los timestamps en la cadena
`Received:` sean **monótonamente crecientes** desde el origen (más antiguo)
hasta el destino (más reciente). Si un salto tiene una marca de tiempo más
antigua que el salto anterior, hay una inconsistencia.

**Orden de los Received:**
```
Received[0] → Último salto (tu servidor, el más reciente)  ← arriba
Received[1] → Salto intermedio
Received[2] → Salto intermedio
Received[-1] → Primer salto (origen, el más antiguo)      ← abajo
```

**La regla espera:** `timestamp[0] >= timestamp[1] >= ... >= timestamp[-1]`
(Cada salto añade su Received DESPUÉS del anterior, así que en orden de
arriba a abajo, las fechas deben decrecer.)

**Qué detecta:**
Una **inversión temporal**: cuando un salto intermedio tiene un timestamp
posterior al salto que lo precede en la cadena. Físicamente imposible en
una transmisión legítima — un servidor no puede recibir un correo antes de
que el servidor anterior lo haya enviado.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Timestamps monótonos (correcto) | +1 (pass) |
| Cadena muy corta (< 2 hops) o timestamps no parseables | 0 (neutral) |
| 1 inversión temporal | -10 |
| 2+ inversiones temporales | -15 |

**Cuándo es phishing:**
- **Inversiones temporales (-10/-15)**: RFC 5321 §4.4 exige que cada MTA
  añada su Received en orden cronológico. Las inversiones solo aparecen
  cuando las cabeceras han sido fabricadas o alteradas manualmente.

**Cuándo NO es phishing:**
- **Timestamps monótonos (+1)**: Orden cronológico correcto.
- **Cadena corta**: Con solo 1 Received no hay nada que comparar.

**Concepto clave:**
Esta es una de las reglas de mayor confianza porque las inversiones
temporales en la cadena Received no ocurren en tráfico legítimo. Un atacante
que fabrica cabeceras Received puede cometer errores de timestamp fácilmente,
y esta regla los detecta.

---

### 6.4 Received Path Anomaly (Anomalía de Ruta)

**Archivo:** `received_path_anomaly.py`

**Qué analiza:**
Señales complementarias en la cadena Received que no están cubiertas por
otras reglas. Evita double-counting (las inversiones temporales y las IPs
privadas ya las penalizan otras reglas).

**Qué detecta (señales nuevas):**

1. **TLS downgrade**: Un salto encriptado (TLS) seguido de un salto en
   texto claro. Indica que el correo perdió su cifrado en algún punto
   del recorrido, posiblemente porque un atacante intermedio eliminó TLS.

2. **Cadena excesivamente larga (≥ 5 hops con IPs mayormente únicas)**:
   Múltiples saltos con IPs diferentes. Las rutas legítimas suelen tener
   2-3 saltos. Una ruta muy larga con IPs variadas sugiere un intento de
   ofuscar el origen real.

3. **Hops con timestamps no parseables**: Algunos hops no exponen timestamp
   mientras el resto de la cadena sí. Sugiere fabricación parcial.

**Resultados:**

| Señales detectadas | Score IRIS |
|---|---|
| Sin anomalías (ruta limpia) | +2 (pass) |
| TLS downgrade | -6 |
| Cadena muy larga (≥ 5 hops únicos) | -4 |
| Timestamps faltantes en algunos hops | -3 |

**Cuándo es phishing:**
- **TLS downgrade (-6)**: En 2025, todo el tráfico SMTP entre servidores
  legítimos usa TLS. Un downgrade a texto claro es extremadamente raro
  y sugiere intervención maliciosa (MITM stripping).
- **Cadena larga (-4)**: Los atacantes a veces añaden múltiples Received
  falsos para ocultar el verdadero origen o para hacer pasar el correo
  por múltiples servidores comprometidos.

**Cuándo NO es phishing:**
- **Ruta limpia y corta (+2)**: La regla premia proactivamente una cadena
  Received limpia, corta y completamente encriptada.

**Concepto clave:**
TLS en SMTP (STARTTLS o SMTPS) cifra el canal entre MTAs. Un downgrade
indica que la conexión perdió cifrado, algo que solo ocurre si un atacante
activo está interceptando (ataque STRIPTLS) o si las cabeceras fueron
fabricadas inconsistentemente.

---

## 7. Análisis de Tipo de Contenido y Confianza

### 7.1 Content-Type Check

**Archivo:** `content_type_check.py`

**Qué analiza:**
Informa del tipo de contenido del correo (text/plain, multipart/alternative,
text/html). Es puramente informativo.

**Historia de la regla:**
Originalmente, ser "plain-text only" se penalizaba como indicio de phishing
(bajo el argumento de que el correo legítimo moderno es HTML). Pero en la
práctica, una enorme cantidad de correo transaccional legítimo (notificaciones
de GitHub, Slack, bancos, universidades) es texto plano. El poder
discriminatorio era ~cero, así que la regla ahora solo reporta sin penalizar.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Cualquier tipo de contenido | 0 (informational) |

**Cuándo es phishing:**
- **No aplica**: Esta regla ya no penaliza.

**Concepto clave:**
Los correos pueden ser `text/plain` (solo texto), `text/html` (solo HTML),
o `multipart/alternative` (ambas versiones; el cliente muestra la que
soporte). El tipo de contenido por sí mismo no indica phishing.

---

### 7.2 List-Unsubscribe

**Archivo:** `list_unsubscribe.py`

**Qué analiza:**
Verifica la presencia de un mecanismo de baja (List-Unsubscribe y
List-Unsubscribe-Post según RFC 2369 y RFC 8058). La presencia de un sistema
de baja legítimo es una **señal débil de legitimidad**.

**Por qué es señal de legitimidad:**
Los remitentes de marketing masivo legítimos (newsletters, notificaciones)
están obligados por leyes como CAN-SPAM (EEUU) y GDPR (Europa) a incluir
un mecanismo de baja funcional. Los phishers no quieren que te des de baja;
quieren que hagas clic en el enlace malicioso.

**Cabeceras analizadas:**
```
List-Unsubscribe: <https://example.com/unsubscribe?id=123>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```
La segunda cabecera (RFC 8058) permite darse de baja con un solo clic sin
visitar una página web, lo cual es un indicador aún más fuerte de
cumplimiento normativo.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin List-Unsubscribe | 0 (neutral) |
| List-Unsubscribe sin target (http/mailto) | 0 (neutral) |
| List-Unsubscribe con target | +2 |
| List-Unsubscribe con One-Click (Post) | +3 |

**Cuándo es phishing:**
- **Nunca penaliza**: Esta regla solo da puntos positivos o neutrales. La
  ausencia de List-Unsubscribe no es sospechosa (mucho correo legítimo no
  lo tiene).

**Cuándo es legítimo (confianza):**
- **One-Click unsubscribe (+3)**: Requiere implementación técnica adicional
  que los phishers raramente se molestan en incluir. Es la señal de confianza
  más fuerte de esta regla.

**Concepto clave:**
Esta regla aplica el principio de "inclusión de características de
cumplimiento normativo como señal de legitimidad". Los atacantes evitan
incluir mecanismos de baja porque quieren maximizar el alcance, no
reducirlo. Un botón de "darse de baja" funcional va contra los intereses
del atacante.

---

## 8. Análisis del Cuerpo del Mensaje

Estas reglas analizan el contenido real del correo: palabras, frases,
patrones de texto y estructura HTML.

---

### 8.1 Alarming Keywords (Palabras Alarmantes)

**Archivo:** `alarming_keywords.py`

**Qué analiza:**
Detecta lenguaje de urgencia, presión y miedo en el `Subject` y en el
nombre visible del remitente. Las campañas de phishing dependen de la
urgencia para que la víctima actúe sin pensar.

**Sistema de pesos (tiered keywords):**

| Categoría | Peso | Ejemplos |
|---|---|---|
| **High-signal** (acción inmediata) | 2 puntos | `"account suspended"`, `"verify now"`, `"security alert"`, `"unauthorized access"`, `"password expired"`, `"urgent action required"`, `"your account has been"`, `"immediately"`, `"24 hours"` |
| **Low-signal** (marketing/promoción) | 1 punto | `"free"`, `"limited time"`, `"act now"`, `"exclusive offer"`, `"don't miss"` |
| **Emojis alarmantes** | 1 punto | `⚠️`, `🚨`, `❗`, `🔴`, `⛔` |

**Escala de severidad basada en peso total:**

| Peso total | Severidad | Score IRIS |
|---|---|---|
| 0 | pass | +1 |
| 1-2 | low | -5 |
| 3-4 | medium | -10 |
| 5+ | high | -15 |

**Cuándo es phishing:**
- **Múltiples high-signal (-15)**: `"⚠️ URGENT: Your account has been suspended. Verify now!"` —
  combina emoji alarmante con frases de alto impacto. Es el patrón clásico
  de phishing de credenciales.
- **Alta densidad de urgencia (-10)**: Varias keywords alarmantes en asunto
  y display name juntos.

**Cuándo NO es phishing:**
- **Keywords de marketing (-5)**: `"Limited time offer: Free shipping!"` —
  es marketing legítimo, no phishing. Peso bajo porque son low-signal.
  La penalización es solo -5, indicando "poco sospechoso, pero presta
  atención".
- **Sin keywords (+1)**: Asunto normal.

**Concepto clave:**
La ingeniería social es el eslabón más débil de la ciberseguridad. Los
atacantes explotan sesgos cognitivos: **urgencia** (actúa ya o pierdes
algo), **autoridad** (somos el banco/la policía/RRHH), **miedo** (tu
cuenta fue hackeada). Esta regla detecta el sesgo de urgencia, el más
común en phishing.

---

### 8.2 Body Content (Contenido del Cuerpo)

**Archivo:** `body_content.py`

**Qué analiza:**
Escanea el cuerpo del correo (tanto texto como HTML) en busca de:

1. **Frases de credenciales/pago**: `"verify your account"`, `"update your
   password"`, `"confirm your identity"`, `"login to your account"`,
   `"unusual sign-in"`, `"billing information"`, `"credit card"`, etc.

2. **Texto oculto evasivo**: Técnicas HTML que esconden texto del usuario
   pero lo dejan visible para scanners de contenido.

**Texto oculto evasivo:**

| Técnica | Ejemplo HTML | Propósito |
|---|---|---|
| `display:none` | `<span style="display:none">texto</span>` | Ocultar completamente |
| `visibility:hidden` | `<span style="visibility:hidden">texto</span>` | Ocultar visualmente pero ocupa espacio |
| `font-size:0` | `<span style="font-size:0">texto</span>` | Tamaño de fuente cero |
| `opacity:0` | `<span style="opacity:0">texto</span>` | Transparente |

**La regla es inteligente sobre qué texto oculto considera malicioso:**
- **NO penaliza** estilos en `<style>` (definiciones CSS para responsive
  design, completamente normales en emails de marketing).
- **NO penaliza** texto oculto genérico (el preview text/preheader de todo
  email marketing usa `display:none`, es estándar de la industria).
- **SÍ penaliza** texto oculto que contiene **enlaces** (un enlace invisible
  que la víctima no ve) o **frases de phishing** (keyword-stuffing oculto
  para engañar filtros).

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin frases ni texto oculto malicioso | 0 (pass) |
| 1 frase de phishing | -5 |
| 2 frases de phishing | -10 |
| 3+ frases de phishing | -15 |
| Texto oculto malicioso | -10 adicional |

**Cuándo es phishing:**
- **Frases de credenciales (-5 por frase, máx -15)**: El cuerpo pide
  verificar cuenta, actualizar contraseña o confirmar datos de pago.
  Combinado con otras señales (lookalike domain, SPF fail), es phishing
  confirmado.
- **Texto oculto + enlace (-10)**: Un `<a href="evil.com">` dentro de
  `<span style="display:none">`. Esto no tiene absolutamente ningún
  propósito legítimo — es una técnica de cloaking (ocultación).

**Cuándo NO es phishing:**
- **Correo transaccional legítimo**: "Verify your email address" de un
  servicio en el que ACABAS de registrarte es normal. La regla por sí sola
  no determina phishing; la combinación de reglas da el veredicto.
- **`<style>` blocks con `display:none`**: Ignorados. Son CSS para diseño
  responsive, no ocultación maliciosa.

**Concepto clave:**
El **keyword-stuffing** oculto es una técnica de evasión donde el atacante
llena el HTML con texto "inocente" (poemas, noticias, párrafos aleatorios)
oculto con CSS, para que los filtros basados en texto vean contenido
legítimo mientras la víctima solo ve la imagen/phishing. Esta regla
detecta específicamente cuando el texto oculto es en sí mismo malicioso.

---

### 8.3 BEC Wire Transfer Pattern (Patrón de Transferencia BEC)

**Archivo:** `bare_url_bec_pattern.py`

**Qué analiza:**
Detecta el patrón específico de Business Email Compromise: un remitente
que usa un dominio corporativo (posiblemente legítimo o suplantado) cuyo
cuerpo contiene frases típicas de fraude financiero.

**Frases BEC detectadas:**
- Wire transfer / transferencia bancaria
- Gift cards / tarjetas de regalo
- Crypto / cryptocurrency / Bitcoin
- Change bank account / cambio de cuenta bancaria
- Urgent payment / pago urgente
- Invoice attached / factura adjunta
- Update payment details / actualizar datos de pago

**Qué hace especial a esta regla:**
A diferencia de Body Content, esta regla pondera las frases contra la
**legitimidad del dominio remitente**. En BEC:
- El dominio `From` es un dominio corporativo real (la cuenta fue
  comprometida o el dominio suplantado con éxito).
- El payload no son credenciales (como en phishing tradicional), sino una
  **solicitud de acción financiera** (transferir dinero, comprar tarjetas,
  cambiar datos bancarios).
- Las reglas de autenticación pueden dar PASS (porque el dominio real de
  la empresa tiene SPF/DKIM configurado).

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin frases BEC | 0 (neutral) |
| 1 frase BEC | -15 |
| 2+ frases BEC | -19 o -21 |
| Frase(s) BEC + Reply-To a dominio diferente | Penalización adicional -4 |

**Cuándo es phishing:**
- **BEC confirmado (-15 a -21)**: Es el ataque más peligroso porque:
  1. Puede venir de una cuenta real comprometida (SPF/DKIM/DMARC pasan).
  2. El dominio es legítimo (no un lookalike).
  3. La única señal está en el cuerpo pidiendo acción financiera.

**Cuándo NO es phishing:**
- **CFO legítimo pidiendo transferencia**: El director financiero real puede
  enviar correos sobre pagos urgentes. La regla no puede distinguir legítimo
  de falso sin contexto organizacional. Por eso la recomendación siempre es:
  **verificar por canal alternativo** (teléfono, en persona).

**Concepto clave:**
BEC es el ataque más costoso en ciberseguridad (miles de millones en
pérdidas anuales según el FBI). A diferencia del phishing tradicional que
busca credenciales, BEC busca **transferencias de dinero directas**. No
necesita malware ni enlaces — solo ingeniería social pura. La defensa
técnica (SPF/DKIM/DMARC) no lo detiene si la cuenta real fue comprometida.
La única defensa efectiva es el **factor humano**: verificación por canal
alternativo.

---

### 8.4 Generic Greeting (Saludo Genérico)

**Archivo:** `generic_greeting.py`

**Qué analiza:**
Detecta el patrón de phishing masivo: un saludo impersonal ("Dear customer",
"Dear user", "Dear sir/madam") combinado con un verbo de acción sospechoso
("verify", "confirm", "update", "suspend", "password") en el cuerpo.

**Por qué la combinación es importante:**
- Saludo genérico solo → puede ser newsletter legítima (primera comunicación).
- Verbo de acción solo → correo transaccional normal ("Your order has shipped").
- **Ambos juntos** → un remitente que no te conoce por tu nombre te está
  pidiendo que hagas algo con urgencia. Es el patrón del phishing masivo
  que no tiene información personal de la víctima.

**Saludos genéricos detectados (multilingüe):**
- Inglés: `"dear customer"`, `"dear user"`, `"dear sir"`, `"dear madam"`,
  `"hello user"`, `"dear account holder"`, `"valued customer"`, `"dear client"`
- Español: `"estimado usuario"`, `"estimado cliente"`, `"querido usuario"`,
  `"estimado señor"`, `"estimada señora"`, `"buenos días"`

**Verbos de acción sospechosos:**
`"verify"`, `"confirm"`, `"update"`, `"suspend"`, `"restore"`, `"validate"`,
`"authenticate"`, `"reactivate"`, `"unlock"`, `"password"`, `"sign in"`,
`"log in"`, `"review"`, `"authorize"`

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin saludo genérico o sin verbo de acción | 0 (neutral) |
| Saludo genérico + 1 verbo de acción | -8 |
| Saludo genérico + 2+ verbos de acción | -11 |

**Cuándo es phishing:**
- **Combinación (-8/-11)**: "Dear Customer, please verify your account to
  avoid suspension." El atacante no sabe tu nombre (phishing masivo) pero
  quiere que actúes con urgencia.

**Cuándo NO es phishing:**
- **Solo saludo genérico**: "Dear customer, here is your monthly statement."
  Puede ser una newsletter o un banco con comunicación genérica.
- **Solo verbo de acción**: "Your password was changed successfully" de un
  servicio legítimo. Es correo transaccional normal.
- **Saludo personalizado**: "Hola Juan" — la regla ni siquiera evalúa esto;
  solo busca saludos genéricos.

**Concepto clave:**
El phishing masivo (spray-and-pray) se envía a millones de direcciones sin
información personal. El saludo genérico delata que el remitente no sabe
quién eres. Un banco o servicio donde tienes cuenta siempre conoce tu nombre.
El spear phishing (dirigido) sí incluye tu nombre, por lo que esta regla no
lo detecta — pero otras reglas (lookalike domain, SPF, etc.) sí.

---

### 8.5 URL in Subject (URL en el Asunto)

**Archivo:** `url_in_subject.py`

**Qué analiza:**
Detecta si el asunto del correo contiene URLs, un patrón inusual en correo
legítimo pero común en phishing.

**Patrones de URL detectados:**
1. URLs completas: `https://evil.com/login`
2. URLs sin protocolo: `www.bank-verify.tk`
3. Dominios con TLDs sospechosos: `pagina-pago.xyz/reset`

**Por qué es sospechoso:**
- El asunto es para describir el tema del correo, no para poner enlaces.
- Un enlace en el asunto elude la necesidad de que la víctima abra el correo.
- En clientes de correo con vista previa, el enlace es clickeable directamente
  desde la bandeja de entrada.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin URLs en asunto | +1 (pass) |
| 1 URL en asunto | -5 |
| 2+ URLs en asunto | -10 |

**Cuándo es phishing:**
- **URL en asunto (-5/-10)**: "Verify your account: https://bit.ly/3xK9mP"
  — el atacante pone el enlace directamente en el asunto para que la
  víctima haga clic sin abrir el correo. Los acortadores (bit.ly, t.co)
  son especialmente sospechosos porque ocultan el destino real.

**Cuándo NO es phishing:**
- **Marketing con URLs**: Algunas campañas de marketing incluyen URLs en el
  asunto. Es mala práctica pero no necesariamente phishing. Penalización
  baja (-5).
- **Sin URLs (+1)**: Normal.

**Concepto clave:**
El asunto (Subject) en RFC 5322 es un campo de texto libre sin restricciones
técnicas. Los atacantes explotan esto para incluir enlaces clickeables
directamente en la vista previa del inbox, reduciendo la fricción entre
recibir el correo y caer en el ataque.

---

## 9. Análisis de Enlaces en el Cuerpo

Estas reglas analizan los enlaces extraídos del cuerpo del correo, tanto
texto como HTML. Es donde reside la mayor parte del payload de phishing:
enlaces a páginas de harvesting de credenciales.

---

### 9.1 Body Links (Enlaces del Cuerpo)

**Archivo:** `body_links.py`

**Qué analiza:**
La regla más completa de análisis de enlaces. Inspecciona cada hipervínculo
del cuerpo en busca de múltiples patrones de ataque.

**Patrones detectados:**

#### 9.1.1 data: URI Links

**Qué es:** Un enlace cuyo `href` es un URI `data:` que contiene el payload
embebido en el propio enlace (ej: `data:text/html;base64,PHNjcmlwdD5hbGVydC...`).

**Score: -10**

**Cuándo es phishing:** El correo legítimo NUNCA usa `data:` URIs como enlaces
clicables. Es una técnica para embeber páginas de phishing completas sin
necesidad de hosting externo.

#### 9.1.2 Userinfo Credential Lure

**Qué es:** Un enlace como `http://paypal.com@evil.io/login` donde el texto
antes del `@` parece legítimo pero la parte después del `@` es el verdadero
destino.

**Cómo funciona:** En URLs, `usuario:password@host` es sintaxis legítima para
autenticación HTTP. Los navegadores modernos ignoran el `userinfo` y navegan
solo al host después del `@`, pero el texto antes puede ser cualquier cosa
que engañe a la víctima.

**Score: -15**

**Cuándo es phishing:** Ningún correo legítimo usa la sintaxis `userinfo@host`
para enmascarar destinos. Es una técnica de ofuscación pura.

#### 9.1.3 Brand Impersonation in Subdomain

**Qué es:** Un dominio que contiene una marca conocida como etiqueta de
subdominio, pero el dominio registrable real es de otra persona.
Ej: `github.com.session-security.com`

**Detección:**
- Busca marcas canónicas en cualquier etiqueta del host.
- También detecta cuando el propio dominio del remitente aparece como
  subdominio de otro dominio (el atacante suplanta al remitente legítimo).

**Score: -20** (la penalización individual más alta de body_links)

**Cuándo es phishing:** Es la señal de phishing más fuerte en enlaces. El
atacante crea un subdominio con el nombre de la marca para engañar.

#### 9.1.4 Punycode/IDN in Link

**Qué es:** Cualquier etiqueta del host comienza con `xn--`, indicando
caracteres Unicode codificados en Punycode.

**Score: -8**

**Cuándo es phishing:** Los IDN homógrafos permiten registrar dominios que
parecen legítimos usando caracteres Unicode visualmente idénticos a ASCII.

#### 9.1.5 IP Literal Host

**Qué es:** Un enlace a una dirección IP en lugar de un dominio.
Ej: `http://192.168.1.100/phishing`

**Score: -6**

**Cuándo es phishing:** El correo legítimo casi nunca enlaza a IPs directamente
(sin certificado SSL válido, sin nombre de dominio). Excepción: enlaces internos
de red corporativa.

#### 9.1.6 URL Shorteners

**Qué es:** Enlaces que pasan por acortadores conocidos (bit.ly, t.co, ow.ly,
tinyurl.com, etc.).

**Score: -4**

**Cuándo es phishing:** Los acortadores ocultan el destino real. Los phishers
los usan para evadir filtros de dominio. Penalización baja porque el marketing
legítimo también los usa.

#### 9.1.7 Cloaked Link (Link Enmascarado)

**Qué es:** El texto visible del enlace muestra un dominio (ej: "paypal.com")
pero el `href` real apunta a otro diferente.

**Ejemplo:**
```html
<a href="http://evil.com/login">https://www.paypal.com/login</a>
```

**Detección:** Busca dominios en el texto visible y los compara con el host
real del href.

**Score: -12**

**Cuándo es phishing:** Es la técnica más antigua y efectiva de phishing. La
víctima ve "paypal.com", hace clic, y llega a "evil.com".

**Cuándo NO es phishing:** Servicios legítimos de tracking de clicks (email
marketing) usan dominios de tracking diferentes al dominio visible. Pero en
esos casos, el texto visible no muestra un dominio concreto, sino texto como
"Haz clic aquí".

#### 9.1.8 Excessive Subdomains

**Qué es:** Un host con más de 4 etiquetas (ej: `click.email.notices.secure-portal-x7.info`).

**Score: -5**

**Cuándo es phishing:** Los phishers usan subdominios profundos para crear URLs
que parezcan rutas legítimas (`banco.com/login/seguro/verificar`), cuando en
realidad cada "directorio" es un subdominio.

#### 9.1.9 Dense Encoding (Codificación Densa)

**Qué es:** URLs con una alta proporción de caracteres percent-encoded
(ej: `%68%74%74%70%73%3A%2F%2F`).

**Score: -6**

**Cuándo es phishing:** La codificación densa ofusca la URL para evadir
filtros y confundir al usuario. Un par de `%20` (espacios) es normal; una
URL donde el 30%+ de los caracteres son secuencias `%XX` es deliberadamente
ofuscada.

#### 9.1.10 Credential Harvest Path

**Qué es:** La ruta/query de la URL contiene keywords de cosecha de
credenciales (`login`, `verify`, `account`, `password`, `signin`, `update`,
`confirm`, `secure`, `webscr`...) Y el dominio NO es ni el del remitente
ni una marca conocida.

**Variante insegura (-10):** Si además la URL usa HTTP (no HTTPS), es el
patrón clásico de página de harvesting de credenciales: una página insegura
pidiendo datos sensibles.

**Variante normal (-6):** Mismas keywords pero con HTTPS.

**Cuándo es phishing:** `http://evil.xyz/login.php?redirect=verify` — un
dominio desconocido pidiendo login es casi seguro phishing. La excepción
son los dominios del propio remitente y marcas conocidas (que también
tienen páginas de login legítimas).

**Tabla resumen de patrones en body_links:**

| Patrón | Score | Confianza |
|---|---|---|
| Brand impersonation (subdominio con marca) | -20 | Muy alta |
| Userinfo credential lure (`@`) | -15 | Muy alta |
| Cloaked link (texto vs href) | -12 | Alta |
| data: URI link | -10 | Muy alta |
| Punycode/IDN | -8 | Alta |
| IP literal | -6 | Media |
| Dense encoding | -6 | Media |
| Credential harvest path | -6/-10 | Media-Alta |
| Excessive subdomains | -5 | Baja |
| URL shortener | -4 | Baja |
| Score máximo acumulado | -25 (cap) | — |

**Concepto clave global:**
Body Links es la regla que atrapa la mayoría del phishing moderno. Mientras
que los ataques antiguos usaban dominios lookalike en el `From`, los ataques
modernos usan dominios legítimos en el `From` (pasando SPF/DKIM/DMARC) y
esconden el payload en los enlaces del cuerpo. Esta regla es la razón por
la que el análisis de cuerpo completo (Fase 2) existe en IRIS.

---

### 9.2 Compromised Legitimate Domain (Dominio Legítimo Comprometido)

**Archivo:** `compromised_legitimate_domain.py`

**Qué analiza:**
Detecta enlaces a dominios **aparentemente legítimos** que probablemente han
sido comprometidos y están siendo usados para alojar páginas de phishing.

**Por qué es importante:**
Las reglas de lookalike domain y brand impersonation detectan dominios
falsos. Pero una tendencia creciente es **comprometer sitios web legítimos**
y usar sus dominios (con buena reputación) para alojar phishing. Estos
dominios no son sospechosos por sí mismos — tienen buena reputación, SSL
válido, y pasan filtros de dominio.

**Qué patrones detecta en dominios legítimos:**

1. **Open Redirectors**: URLs con parámetros de redirección que apuntan a
   un dominio externo malicioso.
   ```
   https://sitio-legitimo.com/redirect?url=https://evil.com
   ```
   Parámetros buscados: `redirect`, `url`, `return`, `goto`, `next`,
   `target`, `redir`, `link`, `destination`, `continue`, `forward`.

2. **Paths opacos generados por kits**: URLs con un path de un solo segmento
   largo y alfanumérico, típico de los paths generados por kits de phishing.
   ```
   https://sitio-legitimo.com/aB3xK9mQ2wR7f
   ```
   Heurística: path sin subdirectorios, ≥ 12 caracteres, sin extensión,
   ≥ 95% alfanumérico.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin patrones sospechosos | 0 (pass) |
| 1 evidencia (redirect u opaque path) | -6 |
| 2+ evidencias (ambas) | -9 |

**Cuándo es phishing:**
- **Open redirect (-6)**: El atacante encontró un endpoint de redirección
  abierta en un sitio legítimo. El enlace empieza con el dominio legítimo
  (pasa filtros de reputación) pero termina en el destino malicioso.
- **Path opaco (-6)**: Los kits de phishing generan URLs aleatorias para
  evadir detección. Un path como `/aB3xK9mQ2wR7f` en el directorio raíz de
  un sitio legítimo no es una página normal.

**Cuándo NO es phishing:**
- **Paths legítimos**: `/wp-content/uploads/2024/report.pdf` tiene estructura
  de directorios y extensión — no es opaco.
- **Sin redirect externo**: Un parámetro `?url=/internal-page` que redirige
  internamente no es malicioso.

**Concepto clave:**
Los **open redirects** son una vulnerabilidad web (CWE-601) donde una
aplicación permite redirigir al usuario a una URL arbitraria. Los atacantes
los explotan para dar legitimidad a sus enlaces de phishing. La URL comienza
con `https://banco-legitimo.com/redirect?url=...` y el filtro de correo ve
"banco-legitimo.com" y lo deja pasar. La víctima hace clic, pasa brevemente
por el sitio legítimo, y es redirigida al phishing.

---

## 10. Análisis de Imágenes y Adjuntos

### 10.1 External Image Tracking (Seguimiento por Imagen Externa)

**Archivo:** `body_external_image_tracking.py`

**Qué analiza:**
Detecta cuando el cuerpo HTML del correo carga imágenes desde un dominio que
NO es el dominio `From` y NO es un ESP/tracker conocido. Este es un patrón
de tracking pixel y de payload de phishing en imágenes.

**Por qué es sospechoso:**
- **Tracking pixel**: Una imagen de 1x1 píxel transparente alojada en un
  servidor del atacante. Cuando abres el correo, tu cliente descarga la
  imagen, confirmando al atacante que tu dirección está activa y que abriste
  el correo.
- **Payload como imagen**: El phishing está renderizado como una imagen
  (logo falso, formulario falso) en lugar de texto. Los filtros de texto
  no pueden leer imágenes.

**Imágenes consideradas legítimas (ignoradas):**
- Imágenes del mismo dominio que el `From` (la empresa carga sus propias
  imágenes).
- Imágenes de ESPs/trackers conocidos: `sendgrid.net`, `mailgun.com`,
  `amazonses.com`, `mcsv.net` (Mailchimp), `hubspot.com`, `salesforce.com`,
  `marketo.com`, etc.
- Imágenes inline (cid:) — embebidas en el propio correo.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin imágenes externas sospechosas | 0 (pass) |
| Imágenes de 1 dominio externo no-ESP | -5 |
| Imágenes de 2+ dominios externos no-ESP | -8 |

**Cuándo es phishing:**
- **Imagen de dominio desconocido (-5/-8)**: El correo dice ser de
  `@empresa.com` pero carga imágenes de `random-server.xyz`. El atacante
  aloja el contenido visual malicioso en su propia infraestructura.
- **Múltiples dominios externos (-8)**: Varios servidores de tracking y
  payload. Infraestructura de ataque más elaborada.

**Cuándo NO es phishing:**
- **Imágenes del mismo dominio**: Si `From: newsletter@tienda.com` y las
  imágenes vienen de `tienda.com` o `cdn.tienda.com`, es normal.
- **ESPs legítimos**: La mayoría del email marketing legítimo carga imágenes
  desde CDNs y plataformas de email marketing.
- **Sin HTML**: Correo texto plano, no aplica.

**Concepto clave:**
El **tracking pixel** (también llamado web beacon) es una técnica de
inteligencia de ataque: el atacante sabe quién abrió el correo, desde qué
IP, con qué cliente. Con esta información, puede priorizar víctimas que
interactuaron y lanzar ataques más dirigidos. Es la fase de reconocimiento
antes del ataque real.

---

### 10.2 Image-Only Email (Correo Solo Imagen)

**Archivo:** `image_only_email.py`

**Qué analiza:**
Detecta correos cuyo contenido visible es esencialmente una sola imagen
con poco o nada de texto real. Es una técnica anti-scanner: el payload de
phishing está renderizado como imagen, evadiendo filtros de texto.

**Criterios:**
- Texto extraído < 10 palabras.
- Al menos 1 imagen.
- La(s) imagen(es) se cargan desde URL externa o data: URI.

**Por qué es efectivo contra filtros:**
- Los filtros de spam/phishing analizan texto (keywords, frases, URLs).
- Si todo el contenido está en una imagen, el texto extraído está vacío.
- La imagen renderiza un formulario de login falso, un logo de banco, un
  CAPTCHA de verificación, etc.
- La víctima ve "Microsoft" con un formulario de password; el filtro ve
  `<img src="evil.com/phish.jpg">`.

**Resultados:**

| Situación | Score IRIS |
|---|---|
| Sin imágenes o texto suficiente | 0 (pass) |
| Imagen única con poco texto | -10 (fail) |

**Cuándo es phishing:**
- **Correo imagen sin texto (-10)**: No hay razón legítima para enviar un
  correo corporativo/transaccional como imagen pura. Es deliberadamente
  evasivo.
- **Imagen + texto mínimo irrelevante**: "Ver adjunto" con una imagen que
  es un formulario de login.

**Cuándo NO es phishing:**
- **Firmas de correo con logo**: Un correo con texto real y una imagen de
  firma corporativa al final. Tiene texto suficiente (>> 10 palabras), no se
  dispara la regla.
- **Newsletters con imágenes + texto**: El email marketing moderno es rico
  en imágenes pero incluye texto real (descripciones de productos, enlaces,
  etc.).

**Concepto clave:**
Los filtros antispam basados en texto existen desde los años 90. Los atacantes
saben que si convierten el phishing a imagen, evaden la mayoría de los filtros
tradicionales. Las defensas modernas necesitan OCR (reconocimiento óptico de
caracteres) o análisis de metadatos de imagen — IRIS opta por detectar la
**ausencia de texto** como señal, en lugar de intentar leer la imagen.

---

### 10.3 Suspicious Attachments (Adjuntos Sospechosos)

**Archivo:** `suspicious_attachments.py`

**Qué analiza:**
Inspecciona los adjuntos MIME reales del correo. Si el mensaje completo está
disponible (Fase 2), inspecciona cada parte MIME individualmente. Si solo hay
cabeceras, recurre a heurísticas de `Content-Type` y `Content-Disposition`.

**Patrones detectados en adjuntos reales:**

#### Extensiones peligrosas
- **Ejecutables**: `.exe`, `.bat`, `.cmd`, `.com`, `.msi`, `.ps1`, `.vbs`,
  `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.scr`
- **Scripts**: `.jar`, `.py`, `.pl`, `.sh`
- **Acceso remoto**: `.rdp`

**Score: -8**

**Cuándo es phishing:** Estas extensiones son vectores de entrega de malware.
Ningún correo legítimo adjunta ejecutables sin acuerdo previo.

#### Doble Extensión
- **Ejemplo**: `factura.pdf.exe`, `foto.jpg.scr`
- La víctima ve `factura.pdf` porque Windows oculta extensiones conocidas.
  La extensión real es `.exe`.

**Score: -8**

**Cuándo es phishing:** Es la táctica más antigua de malware. Explota la
configuración por defecto de Windows de ocultar extensiones.

#### Macros en Office
- **Extensiones**: `.docm`, `.xlsm`, `.pptm`, `.dotm`
- Documentos de Office con macros habilitadas. Las macros pueden ejecutar
  código arbitrario (VBA).

**Score: -10**

**Cuándo es phishing:** Adjuntar un documento con macros es el vector #1 de
ransomware y malware bancario. "Factura pendiente.docm" — la víctima abre,
habilita macros, y el malware se ejecuta.

#### HTML Smuggling
- **MIME type**: `text/html`
- Un adjunto HTML puede contener JavaScript que construye y descarga un
  payload malicioso en el navegador de la víctima (técnica de HTML smuggling).

**Score: -6**

**Cuándo es phishing:** Adjuntar HTML como "factura.html" en lugar de PDF es
inusual. El HTML puede contener JavaScript ofuscado que descarga malware.

#### ZIP con Ejecutable
- Un archivo `.zip` que contiene en su interior un archivo con extensión
  ejecutable.

**Score: -12** (la penalización más alta de attachments)

**Cuándo es phishing:** Comprimir un ejecutable en ZIP es un intento de evadir
filtros que bloquean `.exe`. El atacante espera que el filtro no inspeccione
dentro del ZIP. Esta regla inspecciona los contenidos del ZIP.

**Resultados (modo headers-only, fallback):**

| Situación | Score IRIS |
|---|---|
| Sin extensiones ni MIME types sospechosos | 0 (pass) |
| Extensión peligrosa en filename | -6 |
| Doble extensión en filename | -2 (adicional) |
| MIME type sospechoso en Content-Type | -5 |

**Score máximo acumulado:** -25 (cap)

**Cuándo NO es phishing:**
- **PDFs, imágenes, documentos Office sin macros**: Adjuntos normales.
- **ZIPs con contenido legítimo**: Archivos comprimidos con documentos,
  imágenes, etc. La regla solo penaliza ZIPs que contienen ejecutables.
- **Correo interno con scripts**: Equipos de desarrollo pueden compartir
  scripts. Pero en correo externo, es sospechoso.

**Concepto clave:**
El correo electrónico es el vector de entrega #1 de malware. Los atacantes
usan ingeniería social para que la víctima abra el adjunto ("factura",
"currículum", "multa de tráfico", "fotos comprometidas"). Las extensiones
peligrosas son bien conocidas, por eso los atacantes usan ofuscación: doble
extensión, ZIP conteniendo ejecutables, macros en Office, HTML smuggling.

---

## 11. Resumen de Scores y Severidades

### Escala de Scores en IRIS

IRIS usa un modelo **sustractivo**: cada correo empieza con un score base y
las reglas restan puntos según las señales de phishing detectadas. Un score
negativo indica sospecha; cuanto más negativo, mayor confianza de phishing.

| Rango de Score | Interpretación |
|---|---|
| +10 o más | Muy probablemente legítimo |
| 0 a +10 | Sin señales de phishing claras |
| -5 a 0 | Señales débiles, revisar |
| -15 a -5 | Señales moderadas, probable phishing |
| -25 a -15 | Señales fuertes, muy probable phishing |
| Menos de -25 | Phishing confirmado por múltiples señales |

### Penalizaciones más fuertes (señales de mayor confianza)

| Score | Regla | Señal |
|---|---|---|
| -20 | **SPF** | SPF fail/hardfail — servidor no autorizado |
| -20 | **DMARC** | DMARC fail — sin alineación SPF/DKIM con From |
| -20 | **Body Links** | Brand impersonation en subdominio de enlace |
| -15 | **DKIM** | DKIM fail — firma inválida |
| -15 | **Domain Alignment** | SPF/DKIM autentican dominio ≠ From |
| -15 | **Lookalike Sender Domain** | Dominio imitando marca (typo/homoglyph/cousin/punycode) |
| -15 | **Body Links** | Userinfo credential lure (`@` en URL) |
| -15 | **BEC Wire Transfer** | Patrón de fraude financiero BEC |
| -15 | **Alarming Keywords** | Alta densidad de keywords de urgencia |
| -12 | **Display Name Spoofing** | Display name de marca + email gratuito |
| -12 | **Fake Reply Chain** | Auto-referencia en In-Reply-To |
| -12 | **From/Reply/Return Triangulation** | Tres dominios distintos |
| -12 | **Body Links** | Cloaked link (texto ≠ href) |
| -12 | **Suspicious Attachments** | ZIP con ejecutable dentro |

### Señales positivas (aumentan confianza)

| Score | Regla | Señal |
|---|---|---|
| +5 | **SPF** | SPF pass |
| +5 | **DKIM** | DKIM pass |
| +5 | **DMARC** | DMARC pass |
| +5 | **Display Name Spoofing** | Display name de marca con dominio oficial |
| +3 | **Reply-To Check** | Reply-To sin desajuste o ausente |
| +3 | **List-Unsubscribe** | One-Click unsubscribe (RFC 8058) |
| +3 | **Domain Alignment** | SPF/DKIM alineados con From |
| +2 | **Received Path Anomaly** | Ruta limpia, corta y encriptada |
| +2 | **Undisclosed Recipients** | To/CC con destinatarios visibles |
| +1 | **Date Header Anomaly** | Fecha dentro de rango normal |
| +1 | **Message-ID Check** | Message-ID presente |

### Máximos por regla (cap)

Algunas reglas tienen un score máximo acumulado para evitar que una sola
regla domine el veredicto:

| Regla | Score Floor (máximo negativo) |
|---|---|
| Body Links | -25 |
| Suspicious Attachments | -25 |

---

## Principios Generales del Motor IRIS

### Modelo Sustractivo
IRIS no intenta "detectar buenos y malos" con un clasificador binario. En su
lugar, construye un **perfil de riesgo** restando puntos por cada señal
sospechosa. Un correo con SPF fail + DMARC fail + lookalike domain acumula
penalizaciones que se suman. Un correo con solo una señal débil (ej: URL
shortener) recibe una penalización baja.

### Por qué No es un Sistema de "Pass/Fail"
Un correo legítimo puede tener una señal débil (ej: TLD .xyz en un dominio
de startup). Un correo de phishing puede no tener señales en una regla
concreta. El score agregado da una imagen más precisa que cualquier
clasificador binario.

### Fase 1 vs Fase 2
- **Fase 1 (headers-only)**: El usuario pega cabeceras de correo. Se ejecutan
  reglas de autenticación (SPF, DKIM, DMARC) y análisis de cabeceras. Rápido
  pero incompleto.
- **Fase 2 (full message)**: El usuario proporciona el correo completo. Se
  añaden reglas de cuerpo (Body Content, Body Links, BEC Pattern, Image-Only,
  Attachments). Mucho más preciso.

### Complementariedad
Ninguna regla individual es definitiva. La fuerza de IRIS está en la
**combinación**:
- Un SPF fail (-20) + Lookalike Domain (-15) + Body Links con cloaking (-12)
  = phishing confirmado.
- Un DMARC pass (+5) + SPF pass (+5) + DKIM pass (+5) + Display Name con
  dominio oficial (+5) = correo legítimo de alta confianza.

### Falsos Positivos Controlados
Muchas reglas tienen salvaguardas explícitas contra falsos positivos:
- **ESPs conocidos**: Dominios de SendGrid, Mailgun, Amazon SES, Mailchimp
  no se penalizan.
- **Dominio registrable**: Las comparaciones de dominio usan el dominio
  registrable, no el dominio completo, para evitar falsos positivos con
  subdominios legítimos.
- **Marcas cortas ignoradas**: Marcas de 3-4 letras (visa, ebay, aws) no se
  analizan con Levenshtein por riesgo de colisiones con palabras comunes.
- **Texto oculto contextual**: Solo se penaliza el texto oculto que contiene
  enlaces o frases de phishing, no el CSS responsive normal.

---

*Documento generado para estudio de ciberseguridad. Todas las reglas
descritas están implementadas en `API/src/modules/iris/services/rules/`.*
