# Iris — Conector de buzón (Gmail / Microsoft 365) y auditoría previa del motor

## Contexto

Idea propuesta por el usuario: que Ellysia se conecte directamente al buzón de un usuario
(Gmail y/o Outlook/Microsoft 365) y pueda leer sus correos — como mínimo las cabeceras —
para analizarlos con Iris sin que nadie tenga que pegar nada a mano. El propio
`plans/roadmap-ellysia.md` §7 ya identifica esto como la única inversión que justificaría
descongelar Iris: *"congelado hasta que haya ingesta IMAP. Sin ingesta automática es una
demo: nadie pega cabeceras a mano de forma habitual"*. Este plan es esa ingesta.

El usuario planteó además dos cosas que este documento responde de forma explícita:

1. **Guardar las credenciales de acceso en Acheron**, siguiendo el patrón de
   `plans/feature/acheron-hygeia-agent-key-vault.md`, y quizás extraer de ahí un módulo de
   integración de Acheron reutilizable (DRY/LEAN). → **No es viable tal cual**, por una razón
   arquitectónica dura que se desarrolla en la Fase 2. Sí existe un módulo DRY que extraer,
   pero no es de Acheron.
2. **Que Iris "falla más que una escopeta de feria"**, y que conviene auditarlo antes de
   construir encima. → Correcto, y peor de lo esperado. La auditoría (Fase 1), ampliada con un
   **consejo de cuatro perspectivas expertas** (autenticación/forense, red team, analista SOC,
   calibración), encontró: dos **bypasses verificados ejecutando el motor** (inyección de
   `Authentication-Results`, y un `.eml` benigno adjunto que hace analizar el correo
   equivocado), un modelo de scoring **saturado** que clasifica como sospechoso el correo
   legítimo normal (newsletter, banco, RRHH interno), y un catálogo de ~30 comprobaciones que
   un experto haría y el motor no. Construir ingesta automática sobre esto multiplicaría cada
   fallo por el volumen, así que la Fase 1 es bloqueante para el resto del plan.

Este documento es un análisis de viabilidad con diseño técnico concreto, no una decisión de
construirlo ya.

---

## Estado actual verificado

- **Iris** (`API/src/modules/features/iris`) son ~5.000 líneas de backend + 2.228 de test.
  **41 reglas** registradas vía `@iris_rules.register` en 10 ficheros temáticos bajo
  `services/rules/`. (Nota: `ROADMAP.md` y `roadmap-ellysia.md` dicen 37, `STUDY.md` dice 35 —
  ninguno de los tres está actualizado; ver hallazgo D2.)
- **Entrada única y manual**: `POST /iris/analyze` con `{"headers": ...}` o `{"message": ...}`
  (un `.eml` completo como string). No hay ninguna vía de ingesta automática, ni cliente
  OAuth saliente, ni dependencia de cliente de correo en `requirements.txt`
  (`authlib`/`msal`/`google-auth`/`requests-oauthlib` no están).
- **Modelo subtractivo**: `_CEILING = 100.0` y cada regla solo puede restar
  (`managers.py:643` fuerza `min(0.0, score)`), más un sistema de *gates* de alta confianza
  (`_evaluate_gates`) que puede empeorar el veredicto pero nunca mejorarlo.
- **Acheron** (`API/src/modules/features/acheron`) es zero-knowledge real: el cifrado ocurre
  en el navegador (Web Crypto) y el servidor solo persiste blobs cifrados + parámetros KDF
  (`model.py: Vault`). El servidor **no puede descifrar nada del vault**, nunca.
- **Ya existe cifrado en reposo del lado servidor** en `users/services/secrets.py:92-114`
  (`encrypt_totp_secret`/`decrypt_totp_secret`, Fernet con `MFA_ENCRYPTION_KEY`), y su
  docstring documenta exactamente la distinción que este plan necesita: *"Unlike Acheron
  (zero-knowledge — the server never sees plaintext secrets), the server MUST be able to
  read the TOTP secret"*.

---

## Fase 1 — Auditoría del motor (bloqueante)

> **Estado de implementación (2026-07-22, rama `feature/iris/rules-fine-tunning`).**
> Bloques 1-2 y la mayor parte del 3 de la sección 1.8 están implementados y con
> `pytest` en verde (suite completa + corpus de regresión nuevo). Detalle por hallazgo:
>
> **Hecho:**
> - **A1 + N5** — implementados como la *mitigación mínima* que el propio hallazgo A1
>   sanciona ("`auth_results[0]` ya es estrictamente mejor que la última ocurrencia"),
>   pero a nivel de root cause: `parse_raw_headers` ahora conserva la **primera**
>   (más alta = más nueva) ocurrencia de cualquier cabecera repetida, en vez de la
>   última. Esto cierra A1 y N5 a la vez (ambos eran el mismo bug de raíz) sin tocar
>   `auth_rules.py` ni convertir esas 5 reglas a `needs_context`, y sin romper ningún
>   test existente (que solo pasan una ocurrencia por cabecera). La lista de
>   `authserv_id` de confianza (D6) sigue siendo trabajo real pendiente — no se
>   implementó `trusted_auth_results`/`MessageContext.auth_results` de la sección A1
>   porque el mecanismo de "primera ocurrencia" ya resuelve el bypass verificado sin
>   esa complejidad adicional.
> - **N1/G2** — `parse_raw_message` ahora parsea envoltorio *y* anidado
>   (`MessageContext.wrapper_context`); `IrisManager._run_analysis` ejecuta las 40
>   reglas sobre ambos y persiste el veredicto **peor** (empate a favor del interior).
> - **B1** — `shared.phrase_matches()` (regex con `\b`) sustituye el `in` sin límites
>   de palabra en `bec_phrases`, `credential_phrases`, `high_signal_keywords`,
>   `low_signal_keywords`, `generic_greetings`, `action_verbs`. Se eliminaron
>   `"confidencial"`, `"asap"`, `"con urgencia"`, `"lo antes posible"` de
>   `bec_phrases` en **ambos** sitios (`shared.py::_DEFAULTS` y
>   `SecOpsConfig.json::iris.data.bec_phrases` — el JSON tiene prioridad sobre el
>   default de Python y también los contenía; sin tocarlo el fix no aplicaba, cazado
>   por el corpus de regresión nuevo).
> - **B2** — `check_bec_wire_pattern` usa `is_free_provider` para que el mensaje
>   ("dominio corporativo" vs "proveedor gratuito") sea honesto.
> - **B3** — allowlist ESP (`esp_msgid_domains`/`esp_tracker_domains`) aplicada a
>   `check_reply_to`, `check_return_path` y `check_triangulation`.
> - **B4** — `check_suspicious_tld` dedupe por dominio antes de puntuar (ya no cobra
>   una vez por cabecera).
> - **F3 (parcial)** — cluster autenticación: `check_domain_alignment` también
>   diferencia a DMARC cuando `dmarc=fail` (antes solo cuando `dmarc=pass`). Cluster
>   Received: `check_received_path_anomaly` exime `tls_downgrade`/`long_chain` cuando
>   la cadena entera es RFC1918. Cluster identidad: ya cubierto por B3. Cluster marca
>   (fusionar Subdomain Impersonation + Misspelled Brands dentro de Lookalike) **NO
>   implementado** — ver "No hecho" abajo.
> - **F4** — `check_return_path` compara `registrable_domain`, no el host completo
>   (alineado con `check_reply_to`), más el mismo guard ESP de B3.
> - **F5 (parcial)** — solo se amplió `esp_tracker_domains` con Akamai/Fastly/
>   Cloudinary/imgix. La correlación pixel-externo↔host-de-cosecha propuesta **NO**
>   se implementó — habría cambiado `check_external_image_tracking` a no penalizar
>   una imagen externa aislada sin corroborar, lo que contradice
>   `test_external_image_tracking_flags_non_esp_external_image` (test deliberado
>   existente) y reduce detección real de tracking pixels aislados. Ver G22 (medio
>   esfuerzo) para la versión completa.
> - **G6** — Self-Referencing In-Reply-To, inversión temporal de Received, Unicode
>   Evasion y Triangulation promovidos a gate `Suspicious` en
>   `IrisManager._extract_verdict_signals`/`_evaluate_gates`.
> - **N3** — nuevo dataset `multitenant_hosting_domains` (Google Forms/Docs,
>   SharePoint, Notion, Vercel, Netlify, Discord CDN...); `analyze_url` ya no salta
>   el chequeo de credenciales solo por ser dominio de marca cuando además es
>   hosting multi-tenant.
> - **N4/G4** — `url_host` soporta IPv6 entre corchetes; `analyze_url` detecta IP
>   ofuscada decimal/hex (`is_obfuscated_ip_host`).
> - **C2/C3** — `_run_analysis` persiste en un único `UnitOfWork` al final (antes: un
>   `UnitOfWork`/commit por regla); una cancelación a mitad de bucle ya no deja filas
>   huérfanas porque no hay commit hasta el final.
> - **C4** — `iris.maxMessageBytes` (10 MB default, `SecOpsConfig.json`), validado en
>   `AnalyzeRequestSchema` igual que `hygeia/schemas.py` (leído en cada validación,
>   no horneado al importar, para que `PUT /system` surta efecto sin reiniciar).
> - **C6** — `RuleRegistry._rules` pasó de atributo de clase a atributo de instancia.
> - **C7** — resuelto como efecto colateral de C2/C3: el método nuevo
>   (`_persist_analysis_results`) ya no rebinda `result` con el tipo ORM.
> - **Corpus de regresión de FP (bloque 5)** — nuevo
>   `API/tests/unit/test_iris_fp_regression.py`: ejecuta el motor completo (40
>   reglas + agregación + gates) sobre newsletter-vía-ESP, aviso interno con
>   disclaimer, alerta bancaria real (las tres del cuadro de la sección 1.1) y un
>   phishing evidente de control. Las tres legítimas dan `Legitimate`; el phishing
>   sigue dando `Phishing` — verifica que los arreglos de FP no neutralizan detección
>   real.
> - **D1-D3 (parcial)** — nota de cabecera en `STUDY.md` corrigiendo el recuento (35→40)
>   y explicando que las rutas "Archivo:" son pre-consolidación; no se reescribió el
>   documento completo (2300 líneas, bajo impacto en runtime).
>
> **No hecho (deliberado, con motivo):**
> - **C1** (poner a 0 los `+N` de las ramas "pass") — el propio código ya los clampa
>   a 0 en el agregado, pero **~15 tests unitarios existentes verifican
>   explícitamente `score > 0` en aislamiento** para SPF/DKIM/DMARC/Domain
>   Alignment/ARC/List-Unsubscribe (contrato deliberado: cada regla es testeable
>   sola). Aplicar C1 tal cual rompía ese contrato probado sin arreglar ningún bug de
>   comportamiento real. Se dejó como documentación (ver docstring de
>   `auth_rules.py::check_spf`) en vez de como cambio de código.
> - **F6** (recalibración completa de pesos + fusión de reglas + eliminar "Content-Type
>   check") — el informe del consejo con la tabla peso actual→propuesto no está
>   disponible en este repo; recalibrar sin él es a ciegas. Los FP concretos que F6
>   cubre ya quedan resueltos por B1-B4/F3/F4 (estructurales, no de peso). Fusionar
>   Subdomain Impersonation/Misspelled Brands dentro de Lookalike habría roto tests
>   dedicados existentes (`test_iris_new_rules.py`) sin beneficio de comportamiento.
> - **N2** (marcas ES/EU/logística/cripito) y **G1/G3/G5/G7-G32** (catálogo de
>   detección nueva) — explícitamente "secundario frente a los bloques 1-3" según
>   este mismo documento (sección 1.8); son features nuevas, no arreglos de reglas
>   existentes.
> - **C5** (persistir `unwrapped_from_forward`/`wrapper_*` como columnas en vez de
>   re-parsear) — requiere migración Alembic; deferred por no poder verificarla
>   contra una base de datos real desde este entorno.
>
> Este resumen se guardó también como memoria persistente de Claude Code
> (`iris-rules-audit-fase1.md`) para continuidad entre sesiones.

Hallazgos verificados leyendo el código, no inferidos. Ordenados por severidad.

**Actualización (2026-07-22): auditoría por consejo.** A la auditoría inicial se añadió un
análisis profundo de las **40 reglas** (el registro tiene 40; el "41" que circulaba contaba
un match del decorador dentro de un docstring de `services/rules/__init__.py`) desde cuatro
perspectivas expertas en paralelo — autenticación/forense de cabeceras, red team de evasión,
analista SOC de triaje, e ingeniería de calibración/falsos positivos. Las conclusiones nuevas
se integran abajo (secciones 1.1, y hallazgos con prefijo **E/F/G/N**). Los bypasses nuevos
se **verificaron ejecutando el motor**, no se infirieron.

**La conclusión que reencuadra todo lo demás:** el problema de Iris no es que le falten
detecciones — las 40 reglas, una a una, están sorprendentemente bien hechas. El problema es
que (a) el modelo de score está **saturado** y hoy ahoga el correo legítimo (sección 1.1),
(b) los *gates* — que son los que de verdad deciden el veredicto — tienen **agujeros
explotables** (sección 1.2), y (c) el parser que alimenta a las 40 reglas tiene **fugas**
que dejan analizar el correo equivocado (sección 1.2). Cualquier trabajo de detección nueva
(sección 1.7) es secundario frente a estos tres.

### 1.1 Crítico — el modelo de scoring está saturado

**Hallazgo F1.** El modelo parte de 100 y solo resta; el umbral `Legitimate` es ≥80, así que
el "presupuesto" para que un correo siga siendo legítimo es **perder menos de 20 puntos**. El
problema: varias reglas ruidosas restan 30-45 puntos a correo perfectamente legítimo, de modo
que **es matemáticamente imposible que una newsletter normal salga `Legitimate`**. Simulado
regla a regla sobre cuatro correos-tipo:

| Correo (todos legítimos salvo el último) | Penalización | Score | Veredicto |
|---|---|---|---|
| Newsletter vía Mailchimp (SPF/DKIM/DMARC pass, baja 1-click) | Return-Path −8, Triangulation −12, Reply-To −10, Alarming −5, Ext.Image −5 | **60** | Suspicious ❌ |
| Aviso interno de RRHH en español (disclaimer legal) | BEC −21 (`confidencial`+`lo antes posible`), Received Path −13, Received Chain −5, Undisclosed −5 | **56** | Suspicious ❌ |
| Alerta de seguridad **real** de un banco español | Alarming −10, BEC −15 (`confidencial`), Generic Greeting −8 | **67** | Suspicious ❌ |
| Phishing evidente (marca + `.tk` + enlace de cosecha) | Lookalike −15, Display Spoof −8, TLD −10, Alarming −15, Body Links −8 | **46** (+gate) | Phishing ✅ |

La separación entre correo legítimo (56-67) y phishing (46) es de ~10 puntos: rango dinámico
casi nulo. Lo que atrapa el phishing en la práctica son **los gates**, no el score. El score
sustractivo, tal como está calibrado, sólo genera falsos positivos.

**Hallazgo F2 (el corolario opuesto).** Al mismo tiempo, señales de fraude **inequívoco**
solo restan y **no gatean**: un `In-Reply-To` que apunta a su propio Message-ID
(`Self-Referencing In-Reply-To`, −12, falsificación que ningún cliente comete jamás) deja el
score en **88 → `Legitimate`**. Verificado. Lo mismo con inversión temporal de la cadena
Received, `Unicode Evasion` y `Triangulation`: son de alta confianza y ninguna dispara gate.

**Implicación de diseño (guía para todo lo demás):** el score debe separar "limpio" de
"revisar", y el "definitivamente malo" debe recaer en los gates. Como los gates son
independientes del score, el score puede **suavizarse mucho** (recalibración, sección 1.3)
sin perder detección, siempre que a la vez se **cierren los agujeros de los gates** (1.2) y se
**promuevan a gate** las señales fuertes hoy inertes (F2). Esto es el contenido que **S6**
(pesos configurables) del `ROADMAP.md` necesita antes de exponer cualquier tuning, y su
prerrequisito real es un corpus de regresión (sección 1.6).

### 1.2 Crítico — bypasses verificados del veredicto

Cinco formas de que el motor emita `Legitimate` sobre un phishing real. A1 y N1 se
verificaron ejecutando el motor.

**Hallazgo A1 · Inyección de `Authentication-Results` (bypass de las 5 reglas de auth).**
`parse_raw_headers` (`services/parsers.py:37-73`) conserva **la última
ocurrencia** de una cabecera repetida: la línea 71 hace `headers[current_key] = current_value`
sin acumular. Los MTA hacen *prepend* de las cabeceras de traza, de modo que la
`Authentication-Results` **más arriba** es la del MTA receptor final (la única fiable) y las
de abajo son las más antiguas — es decir, las que un atacante puede haber inyectado él mismo
en el mensaje que envía.

El resultado es que Iris se queda sistemáticamente con la **menos fiable**. Verificado
ejecutando el parser real:

```
Authentication-Results: mx.google.com; spf=fail ...; dkim=fail; dmarc=fail   ← la real
Received: from real-mx by mx.google.com
Authentication-Results: attacker-inserted; spf=pass ...; dkim=pass; dmarc=pass ← la falsa

→ h['authentication-results'] == 'attacker-inserted; spf=pass ...; dkim=pass; dmarc=pass'
```

Las cinco reglas de `auth_rules.py` (SPF, DKIM, DMARC, Domain Alignment, ARC Chain) leen esa
única clave. Con la cabecera forjada: SPF `pass`, DKIM `pass`, DMARC `pass`, alineación `pass`
— y con ello se desactivan de golpe los gates `spf_fail`, `dmarc_fail`, `align_fail`,
`auth_fail` y las tres combinaciones que dependen de `auth_fail` en `_evaluate_gates`. Es un
bypass de una línea de texto que cualquiera puede añadir a su propio mensaje.

**Arreglo:** dejar de leer la autenticación del dict plano. `MessageContext` ya lleva el
objeto `Message` parseado detrás; exponer `msg.get_all("authentication-results")` (igual que
ya se hace con `received_headers`, `parsers.py:279`) y que las reglas consuman **solo la
primera** — la del hop de confianza. Esto es además el prerrequisito natural de **D6
(Provenance de Authentication-Results)**, que ya está en el `ROADMAP.md` marcado `S/M` y
pendiente: con la lista completa disponible, D6 pasa a ser el paso siguiente barato (detectar
A-R múltiples contradictorios y `authserv-id` incoherente con el último `by` del Received).

Detalle que a D6 le falta y sin el cual se implementa mal: el A-R fiable **no es "el primero
de la lista"**, es el A-R más alto **cuyo `authserv-id` pertenece al conjunto de confianza del
tenant** (`iris.data.trusted_authserv_ids`); si el atacante también prepende un A-R falso con
un authserv-id cualquiera, coger `get_all()[0]` a ciegas lo vuelve a burlar. Y hay que extraer
`spf=(\w+)` del A-R seleccionado, no hacer `"spf=pass" in auth_lower` sobre el string
concatenado (que casa con cualquier A-R inferior). Efecto colateral a asumir: `parse_raw_headers`
alimenta a las otras ~36 reglas, así que el cambio debe ser **aditivo** (campo nuevo en
`MessageContext`, p.ej. `auth_results: list[str]`), no una redefinición del dict.

**En código:**

```python
# services/parsers.py — en _message_context_from, junto a received_headers
# (mismo patrón, msg.items() ya da acceso a todas las ocurrencias):
auth_results = [v for k, v in msg.items() if k.lower() == "authentication-results"]
# ... y añadir el campo a MessageContext:
#     auth_results: List[str] = field(default_factory=list)

# services/shared.py — selección del A-R de confianza, un único punto:
def trusted_auth_results(auth_results: list[str]) -> str:
    """El A-R más alto (más nuevo) cuyo authserv-id es de confianza; si no
    hay lista configurada, el más alto sin más — nunca el último."""
    trusted_ids = set(CR.get_iris_data("trusted_authserv_ids") or [])
    for ar in auth_results:                      # arriba -> abajo = nuevo -> viejo
        authserv_id = ar.split(";", 1)[0].strip()
        if not trusted_ids or authserv_id in trusted_ids:
            return ar
    return auth_results[0] if auth_results else ""

# services/rules/auth_rules.py — cada regla pasa a needs_context=True y usa
# trusted_auth_results(context.auth_results) en vez de headers.get(
# "authentication-results", ""); y el parseo de estado deja de ser
# `"spf=pass" in auth_lower` para ser:
match = re.search(r"\bspf=(\w+)", trusted_ar, re.IGNORECASE)
spf_status = match.group(1).lower() if match else ""
```

Mitigación mínima si no se quiere condicionar a una lista de `authserv-id` de confianza
todavía: simplemente `auth_results[0]` (el más nuevo) ya es estrictamente mejor que la
`última ocurrencia` actual, y es el primer paso antes de añadir la validación de authserv-id.

**Hallazgo N1 · Desanidado `message/rfc822`: Iris analiza el correo equivocado. (VERIFICADO —
bypass total del motor con un adjunto.)** Un atacante envía su phishing como correo exterior
real (su From, sus enlaces maliciosos) y **adjunta un `.eml` benigno** como parte
`message/rfc822`. `parse_raw_message` (`parsers.py:210-329`) llama a `_find_nested_forward`;
si encuentra **cualquier** parte `message/rfc822`, devuelve el `MessageContext` del mensaje
**interno** y descarta el exterior. `_run_analysis` usa `context.headers` = las del interno
(`managers.py:613`), así que **las 40 reglas analizan el `.eml` benigno adjunto**, no el
phishing que la víctima ve. Verificado ejecutando el motor: con un envoltorio *"PayPal
Security / Verify your account / enlace a paypa1-verify.tk"* + un `.eml` adjunto *"Amigo /
Fotos del finde"*, Iris analiza `from=amigo@gmail.com`, `subject="Fotos del finde"`,
`links=[]` — el informe muestra un banner "reenviado" pero el veredicto es del interior →
`Legitimate`. Lo introdujo la feature **I2** del `ROADMAP.md` (celebrada como acierto); nadie
anotó que es abusable cuando el análisis es **automático** — justo el escenario del conector
de buzón (Fase 3-4). **Arreglo (offline, Q):** analizar envoltorio *y* anidado y quedarse con
el **peor** veredicto; o solo desanidar cuando el envoltorio parezca un verdadero "report
phishing" (remitente == destinatario, cuerpo mínimo).

**En código:**

```python
# services/parsers.py::parse_raw_message — hoy, si hay nested, devuelve SOLO
# el MessageContext del interno (líneas 313-327). Cambiar a devolver los dos:
def parse_raw_message(raw: str) -> MessageContext:
    msg = message_from_string(raw)
    nested = _find_nested_forward(msg)
    if nested is not None:
        inner = _message_context_from(nested, nested.as_string())
        inner.unwrapped_from_forward = True
        wrapper = _message_context_from(msg, raw)   # NUEVO: también se parsea el exterior
        inner.wrapper_context = wrapper             # NUEVO: campo en MessageContext
        return inner
    return _message_context_from(msg, raw)

# managers.py::_run_analysis — ejecutar las 40 reglas sobre AMBOS contextos
# cuando context.wrapper_context existe, y quedarse con el veredicto peor:
if context.wrapper_context is not None:
    wrapper_results = _run_all_rules(context.wrapper_context)
    inner_results = _run_all_rules(context)
    results = inner_results if _score_of(inner_results) <= _score_of(wrapper_results) \
        else wrapper_results
```

Alternativa más barata si se prefiere no duplicar la ejecución de reglas: solo desanidar
cuando `wrapper.headers.get("from") == wrapper.headers.get("to")` (patrón real de "reenviar
como phishing"); si no, tratar el `message/rfc822` como un adjunto más (que ya cuenta para
`Suspicious Attachments`) y analizar el exterior tal cual.

**Hallazgo N2 · El "primo autenticado": el límite estructural del diseño offline + listas
finitas.** Un atacante registra `soporte-iberdrola-clientes.com`, configura SPF/DKIM/DMARC
**reales** sobre su propio dominio (pasan legítimamente), display "Iberdrola", cuerpo pidiendo
login. `canonical_brands` (`shared.py:39-60`) son ~100 marcas anglosajonas; **faltan casi
todas las ES/EU y las de logística/cripto/identidad**: Iberdrola, Movistar, Vodafone, Orange,
Endesa, CaixaBank, Sabadell, Bankinter, Correos, AEAT/Agencia Tributaria, DGT, Seguridad
Social, Bizum, Iberia, Renfe, El Corte Inglés, Mercadona, DHL, FedEx, UPS, SEUR, DocuSign,
Okta, Steam, Binance, Coinbase, Stripe, Revolut, N26, Wise… `check_lookalike_domain` y
`check_subdomain_impersonation` solo comparan contra esa lista, así que un lookalike de
cualquiera de ellas **no existe** para Iris. Con auth `pass` y sin marca en lista: cero
penalización, cero gates → **100 → `Legitimate`**. Es el límite estructural: **ningún cambio
offline cierra esta clase del todo** — solo la **edad de dominio** (E1, requiere red) detecta
el "recién registrado". Mitigaciones offline parciales: (a) ampliar los datasets con marcas
ES/EU/logística/cripto (sección 1.3); (b) un gate offline "el `registrable_label` del From
combina un token de marca **o** un `subdomain_action_word` (`secure/clientes/soporte/verify`)
con un segundo token" — captura `soporte-<marca>-clientes.com` sin lista exhaustiva.

**En código:**

```python
# shared.py — nuevo dataset iris.data.suspicious_domain_tokens (o reutilizar
# subdomain_action_words, que ya existe): "soporte", "clientes", "verificacion",
# "seguridad", "portal", "oficina"…

# sender_identity_rules.py — nueva regla en el mismo fichero que
# check_subdomain_impersonation (reutiliza registrable_label, no depende de
# canonical_brands en absoluto):
@iris_rules.register(name="Suspicious Domain Composition", category="header_analysis", ...)
def check_suspicious_domain_composition(headers: dict) -> RuleResult:
    domain = extract_domain(headers.get("from", ""))
    label = registrable_label(domain)
    tokens = [t for t in re.split(r"[^a-z0-9]+", label) if t]
    action_hits = [t for t in tokens if t in subdomain_action_words()]
    # 2+ tokens y al menos uno es una action-word ("clientes", "soporte"...)
    # sin que el registrable_label sea directamente una marca conocida:
    if len(tokens) >= 2 and action_hits and label not in canonical_brands():
        return RuleResult(score=-8, verdict="fail", details={...})
    return RuleResult(score=0, verdict="pass", details={})
```

Para (a) — ampliar `canonical_brands`/`brand_trusted_domains` — es solo añadir entradas al
dataset (`shared.py:39-117` o, mejor, directamente a `SecOpsConfig.json` bloque `iris.data.*`
para no tocar código): Iberdrola, Movistar, CaixaBank, Correos, AEAT, Bizum, DocuSign,
Binance… con sus dominios legítimos conocidos.

**Hallazgo N3 · `analyze_url` salta el chequeo de credenciales en servicios multi-tenant de
marca. (VERIFICADO.)** El chequeo de keywords de cosecha en el path se salta si
`registrable_label(host)` es una marca (`shared.py:754`). Verificado: un formulario de robo de
credenciales en **Google Forms** (`docs.google.com/forms/…/verify-account-login/viewform`)
→ **0 hallazgos, score 0**, porque el label `google` está en `canonical_brands`. Lo mismo con
SharePoint, Google Docs, Firebase (`web.app`), Notion, y demás servicios legítimos multi-tenant
abusados como alojamiento de la página de phishing. **Arreglo:** distinguir "dominio de marca"
de "servicio multi-tenant de marca" (el path/subdominio es de usuario, no de la marca); y una
lista de servicios de hosting abusables (`workers.dev`, `web.app`, `pages.dev`, `vercel.app`,
`netlify.app`, `notion.site`, `t.me`, Discord CDN, gateways IPFS) como señal **combinada**
(nunca gate en solitario, para no penalizar el uso legítimo de Google Forms).

**En código:**

```python
# shared.py — nuevo dataset iris.data.multitenant_hosting_domains:
MULTI_TENANT_HOSTING = {
    "docs.google.com", "forms.gle", "drive.google.com",
    "sharepoint.com", "onedrive.live.com",
    "notion.site", "web.app", "pages.dev", "vercel.app", "netlify.app",
    "t.me", "cdn.discordapp.com",
}

# shared.py::analyze_url — la condición que hoy salta el chequeo (línea 754)
# pasa a comprobar TAMBIÉN si es hosting multi-tenant, no solo si es marca:
is_multitenant = any(host == d or host.endswith("." + d) for d in MULTI_TENANT_HOSTING)
if is_multitenant or (host_reg != sender_domain and registrable_label(host) not in brands):
    path_and_query = f"{parsed.path} {parsed.query}".lower()
    kw_hits = [kw for kw in phishing_keywords if kw in path_and_query]
    if kw_hits:
        # si además es multitenant, el finding_type distingue el caso para no
        # confundirlo con un dominio-primo real en el informe:
        finding_type = "multitenant_credential_page" if is_multitenant else finding_type
        score -= 8   # más bajo que credential_harvest_path: puede ser un formulario legítimo
```

**Hallazgo N4 · `url_host` rompe con IPs ofuscadas e IPv6. (VERIFICADO.)** `analyze_url` solo
marca IP-literal con 4 octetos decimales (`_URL_IP_HOST_RE`). Verificado: `http://0x7f000001/`
(hex) y `http://[::ffff:1.2.3.4]/` (IPv6, donde `url_host` devuelve `"["` por hacer
`netloc.split(":")[0]`) → **0 hallazgos**; `http://2130706433/` (decimal) solo se pilla de
rebote si el path lleva `login`. **Arreglo (Q):** normalizar hosts numéricos (decimal/hex/
octal → IPv4) y soportar IPv6 en `url_host`.

**En código:**

```python
# shared.py::url_host — hoy: netloc.split("@")[-1].split(":")[0]. Un netloc
# IPv6 es "[::1]:8080"; el split(":") lo destroza. Arreglo:
def url_host(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    netloc = parsed.netloc.split("@")[-1]
    if netloc.startswith("["):                       # IPv6 entre corchetes
        return netloc.split("]")[0].lstrip("[").lower() or None
    return netloc.split(":")[0].lower() or None

# shared.py — normalizar decimal/hex/octal antes del check IP-literal:
_DECIMAL_IP_RE = re.compile(r"^\d{7,10}$")
_HEX_IP_RE = re.compile(r"^0x[0-9a-f]{1,8}$", re.IGNORECASE)

def _is_obfuscated_ip(host: str) -> bool:
    if _DECIMAL_IP_RE.match(host):
        try:
            return 0 <= int(host) <= 0xFFFFFFFF
        except ValueError:
            return False
    return bool(_HEX_IP_RE.match(host))

# analyze_url — junto al check IP-literal existente:
if _URL_IP_HOST_RE.match(host) or _is_obfuscated_ip(host):
    findings.append({"type": "ip_literal", "href": href})
    score -= 6
```

**Hallazgo N5 · La regla ARC lee el sello equivocado (bug latente).** Los `ARC-Seal` se
prependen: arriba `i=N` con el `cv=` que resume la validación de **toda** la cadena, abajo
`i=1` (`cv=none`, primer salto). Como `parse_raw_headers` conserva la última ocurrencia,
`check_arc_chain` (`auth_rules.py:359-371`) lee casi siempre `i=1` → `cv=none` → neutral,
incluso en reenvíos legítimos con `cv=pass`. Consecuencia: la suavización de gates para
forwards genuinos (todo el propósito de **D7**) casi no se activa, y un `cv=fail` del sellador
final se pierde. Mismo prerrequisito que A1/D6: `get_all("arc-seal")` y elegir el de mayor
`i=`.

**En código:**

```python
# services/parsers.py — mismo patrón que auth_results (N1) y received_headers:
arc_seals = [v for k, v in msg.items() if k.lower() == "arc-seal"]
# nuevo campo en MessageContext: arc_seals: List[str] = field(default_factory=list)

# services/rules/auth_rules.py::check_arc_chain — pasa a needs_context=True;
# en vez de headers.get("arc-seal", ""), elegir el sello de mayor i=:
_ARC_INDEX_RE = re.compile(r"\bi=(\d+)", re.IGNORECASE)

def _highest_arc_seal(seals: list[str]) -> str:
    def index_of(seal: str) -> int:
        m = _ARC_INDEX_RE.search(seal)
        return int(m.group(1)) if m else 0
    return max(seals, key=index_of, default="")

arc_seal = _highest_arc_seal(context.arc_seals)   # antes: headers.get("arc-seal", "")
```

### 1.3 Alto — falsos positivos, redundancia y calibración

Esto es, concretamente, la "escopeta de feria".

**Hallazgo B1 · Matching por substring sin límites de palabra.** Todos los datasets de
`services/shared.py` se comparan con `kw in texto`. Casos reales encontrados:

| Dataset | Entrada | Qué matchea de más |
|---|---|---|
| `high_signal_keywords` | `"you won"` | `"you won't"`, `"you wonder"` → peso 2 → `alarming_medium` (-10) |
| `low_signal_keywords` | `"free"` | `"freedom"`, `"freelance"`, `"free shipping"` |
| `low_signal_keywords` | `"gratis"` | cualquier promoción legítima |
| `bec_phrases` | `"confidencial"` | **el disclaimer legal de prácticamente todo el correo corporativo español** |
| `bec_phrases` | `"asap"`, `"con urgencia"`, `"lo antes posible"` | correo interno normal |

El de `"confidencial"` es el más grave por su interacción con los gates. Un correo con el
pie de página estándar *"La información contenida en este mensaje es confidencial…"* dispara
`check_bec_wire_pattern` con `score=-15`, `verdict="fail"` → gate `bec_fail` → **Suspicious**.
Y si el remitente o el Reply-To están en un webmail gratuito, `bec_free`
(`managers.py:775-778`) lo escala a **Phishing**. Un autónomo que escribe desde Gmail con un
disclaimer estándar es clasificado como phishing.

**Arreglo:** construir el matcher a partir del dataset con `\b` (regex compilada y cacheada
en `shared.py`, junto a los accessors existentes) en vez de `in`, y revisar las entradas de
una sola palabra genérica — `"confidencial"`, `"asap"`, `"free"` no aportan señal suficiente
para justificar su ruido y deberían salir del dataset o exigir co-ocurrencia.

**En código:**

```python
# shared.py — junto a _cached_tuple/_cached_set, un accessor nuevo que
# construye un Pattern con límites de palabra a partir de cualquier dataset
# de frases (sirve para bec_phrases, credential_phrases, high/low_signal_keywords):
@lru_cache(maxsize=None)
def _phrase_pattern(key: str) -> re.Pattern:
    phrases = sorted(_data(key), key=len, reverse=True)  # más largas primero
    alternation = "|".join(re.escape(p) for p in phrases)
    return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)

# Uso en cada regla — reemplaza `[p for p in bec_phrases() if p in text]`:
matches = _phrase_pattern("bec_phrases").findall(text)
```

Y en el dataset (`shared.py::_DEFAULTS["bec_phrases"]`, o mejor directamente en
`SecOpsConfig.json` bloque `iris.data.bec_phrases` si ya está migrado): eliminar
`"confidencial"`, `"asap"`, `"con urgencia"`, `"lo antes posible"` — no son frases
financieras concretas, son lenguaje de negocio cotidiano.

**Hallazgo B2 · `check_bec_wire_pattern` afirma algo que no comprueba.** Su `description` y
su `recommendation` dicen al usuario *"El remitente usa un dominio corporativo
({from_domain})"* (`body_content_rules.py:195-240`), pero la regla no comprueba en ningún
momento que el dominio sea corporativo: `from_domain` es cualquier dominio parseable,
`gmail.com` incluido. El helper `shared.is_free_provider` ya existe y `managers.py` lo usa
para derivar `bec_free` — la regla simplemente no lo usa. Es un mensaje al usuario que puede
ser literalmente falso.

**En código:**

```python
# body_content_rules.py::check_bec_wire_pattern — usar is_free_provider
# (ya importado en managers.py, falta importarlo aquí) para que el mensaje
# sea honesto y para que la regla misma sepa distinguir el caso:
from ..shared import is_free_provider  # nuevo import

is_corporate = from_domain and not is_free_provider(from_domain)
...
recommendation=(
    f"El cuerpo contiene {len(matches)} frase(s) típica(s) de fraude BEC "
    f"({', '.join(matches[:3])}). El remitente "
    f"{'usa un dominio corporativo' if is_corporate else 'usa un proveedor de correo gratuito'} "
    f"({from_domain}), lo que hace este patrón especialmente peligroso..."
)
```

**Hallazgo B3 · Triple contabilización de la misma señal.** `Reply-To check` (-10),
`Return-Path mismatch` (-8) y `From/Reply-To/Return-Path Triangulation` (-12) miran los
mismos tres campos. Una newsletter legítima con `From: empresa.com`,
`Reply-To: reply.mailchimp.com`, `Return-Path: bounce.sendgrid.net` son exactamente tres
dominios distintos: **-30 puntos** (score 70 → **Suspicious**) por una configuración de ESP
completamente normal. `STUDY.md` §3.1 ya reconoce el falso positivo pero no lo corrige.

Lo llamativo es que el dataset para arreglarlo **ya existe**: `esp_msgid_domains` y
`esp_tracker_domains` en `shared.py`, usados hoy solo por `Message-ID Domain` y por
`External Image Tracking`. Aplicar la misma allowlist a las tres reglas de reply-path
elimina el caso entero.

**En código:**

```python
# reply_path_rules.py — helper compartido al principio del fichero:
def _is_esp_domain(domain: str | None) -> bool:
    if not domain:
        return False
    return domain in esp_msgid_domains() or domain in esp_tracker_domains()

# check_reply_to / check_return_path / check_triangulation — antes de
# devolver el "fail", una salida temprana:
if _is_esp_domain(reply_domain) or _is_esp_domain(return_domain):
    return RuleResult(
        score=1, verdict="pass",
        details={"from": from_addr, "reply_to": reply_to, "esp": True},
        recommendation=None,
    )
```

**Hallazgo B4 · `Suspicious TLD` acumula por cabecera, no por dominio.**
`check_suspicious_tld` (`sender_identity_rules.py:516-564`) recorre From, Reply-To y
Return-Path y suma `-5` por cada acierto, así que **un único dominio** presente en las tres
cabeceras cuesta -15. Y la lista incluye `.info`, `.pro`, `.name`, `.mobi`, `.club` — gTLDs
legacy con uso legítimo masivo. Arreglo: deduplicar por dominio antes de puntuar, y podar la
lista a los TLDs con abuso realmente desproporcionado (los de Freenom y los de céntimo).

**En código:**

```python
# sender_identity_rules.py::check_suspicious_tld — hoy found_tlds es una
# lista (permite duplicados de dominio); cambiar la agregación final:
found_domains = {d["domain"] for d in found_tlds}   # set: un dominio cuenta una vez
count = len(found_domains)
score = -6 * count   # antes: -5 * len(found_tlds), que contaba por cabecera
```

Y en `shared.py::_DEFAULTS["suspicious_tlds"]` (o el bloque `iris.data.suspicious_tlds` del
JSON si ya está migrado): quitar `.info`, `.pro`, `.name`, `.mobi`, `.bar` — dejar solo los
TLDs de coste marginal/verificación nula (Freenom `.tk/.ml/.ga/.cf/.gq`, `.xyz`, `.click`,
`.top`, etc.).

**Hallazgo F3 · Doble/triple/cuádruple contabilización por familias (el hallazgo de
calibración central).** Un único hecho estructural se cobra varias veces porque varias reglas
miran los mismos campos. Cuatro clusters:

- **Identidad (Reply-To check / Triangulation / Reply-To Free / Return-Path mismatch):** un
  único "las tres cabeceras no coinciden" cuesta hasta **−38**. B3 cubre parte; el cluster
  completo son cuatro reglas sobre From/Reply-To/Return-Path.
- **Autenticación (SPF / DMARC / Domain Alignment):** `DMARC=fail` ya implica SPF+DKIM no
  alineados; sumar SPF fail + DMARC fail + Alignment fail = **−55** por el mismo hecho ("no
  está autenticado"). `Domain Alignment` es una reimplementación de DMARC (su propio docstring
  lo dice). Propuesta: que `Domain Alignment` solo actúe **cuando DMARC está ausente**.
- **Imitación de marca (Lookalike / Subdomain Impersonation / Display Name Spoof / Misspelled
  Brands):** `paypal-secure.com` con display "PayPal" cobra **−36** entre las cuatro, más Body
  Links si los enlaces apuntan ahí. Propuesta: fusionar Subdomain + Misspelled dentro de
  Lookalike.
- **Received (Received Chain / Received Path Anomaly):** correo interno corporativo real (5+
  saltos, IP RFC1918 de origen, hops internos sin TLS) → **−18** en correo perfectamente
  legítimo. Propuesta: exentar cadenas internas RFC1918.

**En código (una muestra por cluster, el resto sigue el mismo patrón):**

```python
# Cluster identidad — ya resuelto por el arreglo de B3 (allowlist ESP) más
# la reducción de -10/-8/-12 a un peso menor cada una (ver F6/S6). No hace
# falta fusionar físicamente las reglas: basta con que ninguna de las tres
# vuelva a penalizar el mismo hecho una vez la otra ya lo hizo. Alternativa
# más agresiva: convertir las tres en una sola señal booleana
# `identity_mismatch` consumida solo por un gate en
# managers._extract_verdict_signals, sacándola del todo del score aditivo.

# Cluster autenticación — auth_rules.py::check_domain_alignment, guarda al
# principio de la función (evita re-evaluar lo que DMARC ya decidió):
combined = headers.get("authentication-results", "").lower()
if "dmarc=pass" in combined or "dmarc=fail" in combined:
    return RuleResult(score=0, verdict="neutral",
                       details={"reason": "DMARC ya determinó la alineación"})
# Antes: la función seguía evaluando dkim=/spf= incluso con DMARC ya resuelto.

# Cluster marca — sender_identity_rules.py: mover la lógica de
# check_subdomain_impersonation y check_misspelled_brands DENTRO de
# check_lookalike_domain como findings adicionales del mismo RuleResult
# (un solo score por imitación de marca), y quitar sus dos
# @iris_rules.register independientes.

# Cluster Received — received_timing_rules.py::check_received_path_anomaly,
# antes de contar tls_downgrade/long_chain:
if all(_is_private_ip(h.get("fromIp")) for h in hops if h.get("fromIp")):
    return RuleResult(score=0, verdict="neutral",
                       details={"reason": "cadena enteramente interna (RFC1918)"})
```

**Hallazgo F4 · Bug de FP concreto: `Return-Path mismatch` compara dominio completo, no
registrable.** `reply_path_rules.py:155-158` hace `extract_domain(return_path) !=
extract_domain(from)` con host completo, mientras su regla hermana `check_reply_to`
(`reply_path_rules.py:71`) sí usa `registrable_domain`. Resultado: `Return-Path:
bounce.mail.paypal.com` vs `From: service@paypal.com` dispara **−8** en correo legítimo por
ESP/subdominio de rebotes — que es la norma en todo el transaccional y masivo. Además ese
mismatch es lo que SPF ya evalúa (el Return-Path *es* el dominio SPF), así que penaliza dos
veces. Una línea: cambiar a `registrable_domain` y no penalizar si es ESP conocido o SPF pasó.

**En código:**

```python
# reply_path_rules.py:155-158 — el fix es literalmente esto:
rp_domain = registrable_domain(extract_domain(return_path))   # antes: extract_domain(...) a secas
from_domain = registrable_domain(extract_domain(from_addr))   # antes: extract_domain(...) a secas
```

**Hallazgo F5 · `External Image Tracking` penaliza cualquier CDN no listado.** La allowlist
`esp_tracker_domains` (`shared.py:319-330`) omite CDNs mainstream (Akamai, Fastly, Cloudinary,
imgix), así que correo legítimo que sirve imágenes desde ellos come **−5/−8** sistemático.
"Cargar una imagen externa" no es phishing por sí solo — debería ser señal solo **en
combinación** (p.ej. si el pixel remoto y el enlace de cosecha son el mismo host de tercero,
que es infraestructura de campaña real), no penalización autónoma.

**En código:**

```python
# attachment_media_rules.py::check_external_image_tracking — necesita ver
# también context.links (hoy solo mira context.body_html), así que se cruza
# con la misma URL host que usa Body Links:
external_hosts = {f["registrable"] for f in findings if f["registrable"]}
harvest_hosts = {registrable_domain(url_host(l.href or "")) for l in context.links}
harvest_hosts.discard(None)

if external_hosts & harvest_hosts:
    # el mismo tercero sirve el pixel Y el enlace de cosecha: señal real
    score = -8
    verdict = "fail"
else:
    # imagen externa aislada, sin corroboración: no penalizar sola
    score = 0
    verdict = "pass" if findings else "neutral"
```

Y ampliar `esp_tracker_domains()` con Akamai/Fastly/Cloudinary/imgix para reducir el ruido de
base incluso antes de aplicar la correlación.

**Hallazgo F6 · Veredicto por regla (síntesis del consejo de calibración).** De las 40:
`Content-Type check` **no puntúa nunca** → ELIMINAR. A FUSIONAR: Subdomain Impersonation y
Misspelled Brands dentro de Lookalike; Domain Alignment dentro de DMARC. A RESTRINGIR (acotar
cuándo disparan): Display Name Spoofing, Lookalike (cousin), Alarming Keywords, Body Content,
BEC, External Image Tracking, Received Path Anomaly, Triangulation. A RECALIBRAR el peso: SPF,
From header check (−10→−3), Reply-To check, Return-Path, Suspicious TLD, Received Chain. A
SUBIR peso por su fiabilidad casi perfecta: `Self-Referencing In-Reply-To` (−12→−15). El resto
(DKIM, DMARC, ARC, Message-ID, Date Anomaly, Unicode Evasion, Encoded-Word, QR, Image-Only,
Suspicious Attachments, Generic Greeting) MANTENER. El rediseño completo de pesos
actual→propuesto vive en el informe del consejo y es el insumo directo de **S6**.

**En código:** hasta que exista **S6** (pesos en `SecOpsConfig.json`), cada peso recalibrado
es una edición directa del literal `score=-N` en la regla correspondiente — no hay
indirección hoy. El vehículo natural para S6, cuando se aborde, es un accessor nuevo en
`config_reading.py`:

```python
# config_reading.py
def get_iris_rule_weight(rule_name: str, default: float) -> float:
    weights = get_iris_config().get("scoring", {})
    return weights.get(rule_name, default)

# uso en cada regla, p.ej. auth_rules.py::check_spf:
score = CR.get_iris_rule_weight("SPF.fail", -20)   # antes: -20 hardcodeado
```

**Principio de recalibración (cierra F1/F2):** suavizar los pesos del score (para que el
correo legítimo pierda &lt;20) **y a la vez** endurecer/añadir gates, porque son los gates —no
el score— los que detectan. Gates a revisar: `cloaked_link → Phishing` exime hosts de ESP
(hoy marca newsletters cuyo texto visible es `brand.com` y el href va al tracker);
`lookalike(cousin) → Phishing` solo debe gatear combinado con fallo de auth (hoy marca
`visa-consulting.com`); y **promover a gate Suspicious** las señales fuertes hoy inertes de F2
(Self-Ref In-Reply-To, inversión temporal Received, Unicode Evasion, Triangulation).

### 1.4 Medio — motor y persistencia

**Hallazgo C1 · Todos los scores positivos son código muerto.** `managers.py:643` hace
`replace(result, score=min(0.0, float(result.score)))`. Unas 20 reglas devuelven +1/+2/+3/+5
en su rama de éxito, sus docstrings los documentan como vigentes (`check_spf`: *"``pass``
(score +5)"*), y `STUDY.md` tiene tablas enteras de scores positivos. Nada de eso cuenta.

No es un bug de comportamiento — el clamp es deliberado y está bien argumentado en el
comentario de `_CEILING` — pero deja el motor **imposible de razonar leyéndolo**. Arreglo:
devolver `0` explícitamente en las ramas de éxito y borrar los positivos de docstrings y
`STUDY.md`, o dejar el clamp como única fuente de verdad y decirlo en cada docstring. Lo que
no puede quedarse es la contradicción.

**En código:** cambio mecánico, regla por regla, sin efecto de comportamiento (el `min(0.0,
score)` de `managers.py:643` ya hacía esto en tiempo de ejecución):

```python
# auth_rules.py::check_spf — antes:
return RuleResult(score=5, verdict="pass", ...)          # nunca llega a sumar
# después:
return RuleResult(score=0, verdict="pass", ...)           # el número ya no miente
```

Aplicar el mismo cambio en las ~20 ramas de éxito de `auth_rules.py`, `sender_identity_rules.py`,
`reply_path_rules.py`, `thread_rules.py`, `recipient_rules.py`, `received_timing_rules.py`,
`content_trust_rules.py`, `body_content_rules.py` que hoy devuelven `+1/+2/+3/+5`.

**Hallazgo C2 · Una transacción por regla.** `_run_analysis` llama a `_persist_rule_result`
dentro del bucle (`managers.py:645`), y ese método abre su propio `UnitOfWork`
(`managers.py:680`). En contexto de background job el `__exit__` **sí** commitea, así que son
**40 commits por análisis** más los de transición de estado. Debería ser un solo `UnitOfWork`
con las 40 filas y un commit al final: atómico y ~40× menos round-trips. Esto importa mucho
más cuando la ingesta automática pase de 1 análisis manual al día a N por buzón y hora.

**En código:**

```python
# managers.py::_run_analysis — hoy, dentro del bucle de reglas:
for idx, rule_def in enumerate(rules_defs):
    ...
    self._persist_rule_result(analysis_id, rule_def, result, idx)  # abre su propio UoW

# Propuesto: un único UnitOfWork envolviendo todo el bucle, acumulando y
# guardando cada IrisRuleResult sin cerrar la transacción hasta el final:
with UnitOfWork() as uow:
    repo = IrisRuleResultRepository(uow)
    for idx, rule_def in enumerate(rules_defs):
        if job.cancelled():
            return   # nada commiteado todavía: C3 queda resuelto gratis
        ...
        repo.save(IrisRuleResult(
            analysis_id=analysis_id, rule_name=rule_def["name"],
            category=rule_def["category"], score=result.score,
            verdict=result.verdict, details=result.details,
            recommendation=result.recommendation, position=idx,
        ))
    # commit único al salir del `with`, tras las 40 filas
```

**Hallazgo C3 · La cancelación deja basura.** Si `job.cancelled()` se detecta en la regla 30
(`managers.py:623`), la función hace `return` y deja las 29 filas de `IrisRuleResult` ya
commiteadas colgando de un análisis marcado `cancelled`. Se resuelve solo con el arreglo de
C2 (si no hay commit hasta el final, no hay nada que limpiar): el `return` dentro del `with
UnitOfWork()` de C2 simplemente nunca llega al commit, así que no hace falta lógica de
limpieza adicional — es un efecto colateral gratis del cambio de C2, no un arreglo propio.

**Hallazgo C4 · Sin límite de tamaño de entrada.** `AnalyzeRequestSchema`
(`schemas.py:22-23`) valida `Length(min=10)` y **ningún máximo**. Un `.eml` de decenas de MB
entra entero a una columna `Text` y se re-parsea (adjuntos incluidos, decodificando base64)
en cada llamada posterior. Con ingesta automática esto deja de ser teórico. Añadir un
`max` configurable en `iris.max_message_bytes`.

**En código:**

```python
# config_reading.py — nuevo getter junto a get_iris_min_headers:
def get_iris_max_message_bytes() -> int:
    return get_iris_config().get("maxMessageBytes", 10 * 1024 * 1024)  # 10 MB por defecto

# schemas.py::AnalyzeRequestSchema — validate.Length ya soporta max=:
headers = fields.String(load_default=None,
    validate=validate.Length(min=10, max=CR.get_iris_max_message_bytes()))
message = fields.String(load_default=None,
    validate=validate.Length(min=10, max=CR.get_iris_max_message_bytes()))
```

**Hallazgo C5 · Re-parseo repetido del mensaje completo.** `parse_raw_message` se ejecuta de
nuevo en `get_analysis_results` (`managers.py:227`), `get_analysis_path`,
`get_analysis_iocs` y `_generate_pdf_async`. El caso peor es `get_analysis_results`: el
frontend lo sondea cada 3 s esperando `aiSummary`, y solo necesita el parseo para tres
campos (`unwrappedFromForward`, `wrapperFrom`, `wrapperSubject`) que podrían persistirse como
columnas al finalizar el análisis.

**En código:**

```python
# model.py::IrisAnalysis — tres columnas nuevas, todas opcionales:
unwrapped_from_forward = Column(Boolean, nullable=False, default=False)
wrapper_from = Column(String(320), nullable=True)
wrapper_subject = Column(String(998), nullable=True)

# managers.py::_run_analysis — persistir junto al resto de campos finales,
# en el mismo _update_analysis(..., status="finished", ...) que ya existe:
self._update_analysis(
    analysis_id, status="finished", total_score=total_score, verdict=verdict,
    gate_reasons=gate_reasons, finished_at=utcnow_naive(),
    unwrapped_from_forward=context.unwrapped_from_forward,   # NUEVO
    wrapper_from=context.wrapper_from or None,               # NUEVO
    wrapper_subject=context.wrapper_subject or None,          # NUEVO
)

# get_analysis_results/get_analysis_path/etc. — leer de analysis.* en vez de
# volver a llamar parse_raw_message(analysis.raw_headers or ""), salvo donde
# de verdad se necesite el MessageContext completo (get_analysis_iocs).
```

**Hallazgo C6 · `RuleRegistry._rules` es atributo de clase.** `services/registry.py:46`
declara `_rules: List[Dict] = []` en el cuerpo de la clase, no en `__init__`. Hoy no explota
porque solo existe el singleton `iris_rules`, pero `clear()` (usado en tests) vacía estado
global compartido y hace que el orden de los tests importe. Mover a `self._rules = []`.

**En código:**

```python
# services/registry.py::RuleRegistry — antes:
class RuleRegistry:
    _rules: List[Dict] = []          # atributo de CLASE: compartido entre instancias

# después:
class RuleRegistry:
    def __init__(self) -> None:
        self._rules: List[Dict] = []  # atributo de instancia
```

**Hallazgo C7 · Sombra de variable en `_persist_rule_result`.** El parámetro
`result: RuleResult` se rebinda con el ORM `IrisRuleResult` (`managers.py:682`). Funciona,
pero es el tipo de sombra que produce un bug la próxima vez que alguien toque la función.

**En código:**

```python
# managers.py::_persist_rule_result — renombrar el parámetro y la variable
# local para que no compartan nombre con el tipo ORM:
def _persist_rule_result(self, analysis_id: int, rule_def: dict,
                          rule_result: RuleResult, position: int) -> None:
    ...
    row = IrisRuleResult(              # antes: `result = IrisRuleResult(...)`
        analysis_id=analysis_id, rule_name=rule_def["name"],
        category=rule_def["category"], score=rule_result.score,
        verdict=rule_result.verdict, details=rule_result.details,
        recommendation=rule_result.recommendation, position=position,
    )
    repo.save(row)
```

### 1.5 Bajo — documentación desincronizada

**Hallazgo D1.** `services/rules/STUDY.md` referencia en cada sección un **"Archivo:"** que
ya no existe (`spf.py`, `dkim.py`, `display_name_spoof.py`, `lookalike_domain.py`…): los ~38
ficheros de una regla se consolidaron en los 10 temáticos en la Fase 0c del `ROADMAP.md`.
Ninguna de esas rutas se actualizó.

**Hallazgo D2.** El recuento de reglas no coincide en ningún sitio: `STUDY.md` dice 35,
`ROADMAP.md` y `roadmap-ellysia.md` decían 37 (ya corregido a 40 en `roadmap-ellysia.md`), y
el registro tiene **40** (verificado importando `iris_rules.get_rules()`).

**Hallazgo D3.** Las tablas de score de `STUDY.md` documentan los positivos como vigentes
(ver C1).

**En código:** D1–D3 no tocan `src/`, son ediciones de Markdown. D1: sustituir cada línea
**"Archivo:"** de `STUDY.md` por el fichero temático real (p.ej. `spf.py` → `auth_rules.py`).
D2/D3: una pasada sobre las tablas de score de `STUDY.md` alineada con el cambio de C1 (los
`+N` pasan a `0`) y con el recuento correcto (40 reglas). Puede hacerse en el mismo commit
que C1 para que el diff de docs y el de código cuenten la misma historia.

### 1.6 Cobertura de test

2.228 líneas de test sobre ~5.000 de código es una proporción sana, y las reglas nuevas
(D1/D4/D5/D7) llegaron con test. El hueco no es de cantidad sino de **tipo**: no hay ningún
test de *calibración* — ni corpus etiquetado, ni test de regresión de falsos positivos sobre
correo legítimo real (newsletter de ESP, correo corporativo con disclaimer, notificación de
banco). Los hallazgos B1–B4 existen precisamente porque nada los habría detectado. Esto es lo
que **S5 (feedback del analista)** del `ROADMAP.md` habilitaría, y es la dependencia real de
**S6 (pesos configurables)**.

### 1.7 Catálogo de comprobaciones que faltan (la pregunta de mayor abanico)

Lo que un técnico experto comprobaría y Iris no hace, consolidado de las cuatro perspectivas
del consejo, deduplicado y ordenado por retorno. **Todo es offline salvo lo marcado "Red".**
Impacto: `S` cierra una clase de ataque entera; `A` alto; `B` medio; `C` marginal. Dificultad:
`Q` horas–1 día; `M` días; `L` semanas / decisión de producto.

**Quick wins offline (mayor retorno inmediato):**

| # | Comprobación | Qué aporta | Imp. | Dif. |
|---|---|---|---|---|
| G1 | Parsear el `DKIM-Signature` (hoy solo se mira presencia): tags `l=` (append al cuerpo tras la firma), `a=rsa-sha1` (RFC 8301), `x=` expirado, `h=` sin `From` firmado | Un `dkim=pass` que no protege nada | S | Q |
| G2 | `message/rfc822`: analizar envoltorio + anidado, peor veredicto (arregla N1) | Bypass total con un adjunto | S | Q |
| G3 | `suspicious_tlds` también en hosts de enlaces del cuerpo (hoy solo From/Reply/Return) | `.tk` con path limpio en el cuerpo | A | Q |
| G4 | Normalizar hosts numéricos (dec/hex/octal) e IPv6 en `url_host` (arregla N4) | IP ofuscada en enlaces | A | Q |
| G5 | Ampliar `free_provider_domains` (gmx.de, web.de, t-online, orange.fr, libero.it, qq, naver…) | Reactiva los gates→Phishing `bec_free`/`spoof_free`/`replyfree` que hoy se apagan con un webmail EU/asiático | A | Q |
| G6 | Promover a gate Suspicious las señales fuertes hoy inertes (Self-Ref In-Reply-To, inversión temporal Received, Unicode Evasion, Triangulation) — arregla F2 | Falsificación inequívoca que hoy sale 88→Legitimate | A | Q |
| G7 | Lookalike contra **el dominio del destinatario** (To/Delivered-To/`for=` del Received), no solo marcas | Impersonación de la propia org / de proveedor — el vector BEC nº1 | A | Q |
| G8 | Fingerprint de infraestructura: `X-Mailer`/`X-PHP-Script`/`X-Originating-IP` vs identidad reclamada | PHPMailer/kit en correo "de marca" | A | Q |
| G9 | Display name **es una dirección** cuyo dominio ≠ From real (sin lista de marcas) | Spoofing genérico de remitente | A | Q |
| G10 | Arreglar la lectura del sello ARC (elegir mayor `i=`) — arregla N5 | Bug latente que ya degrada D7 | A | Q |
| G11 | Hash SHA256 del `.eml` completo (cadena de custodia) | Ticket reproducible | B | Q |
| G12 | Ampliar `canonical_brands`/`brand_trusted_domains` con marcas ES/EU/logística/cripto/identidad | Mitiga parcialmente N2 (sigue siendo lista finita) | B | Q |

**Offline, esfuerzo medio:**

| # | Comprobación | Qué aporta | Imp. | Dif. |
|---|---|---|---|---|
| G13 | **Regla callback/TOAD**: teléfono (E.164) + término de facturación/soporte + correo sin enlaces ni adjuntos | Clase de ataque hoy **invisible** (score 100): "su suscripción se renovó, llame al…" | S | M |
| G14 | Parser HTML real (stdlib `html.parser`): `href` sin comillas, `<form action>`, `<base>`, `<meta refresh>`, `formaction`, `<area>`; concatenar **todas** las partes HTML, no solo la primera | Robo de credenciales por POST y enlaces que el regex `_ANCHOR_RE` no captura, hoy invisibles | S | M |
| G15 | Provenance de `Authentication-Results` (= **D6**, con el detalle de A1: A-R topmost de authserv-id de confianza + `spf=(\w+)` extraído, no substring) | Cierra el bypass A1 de forma robusta | S | M |
| G16 | DKIM replay / oversigning: una cabecera de identidad aparece más veces en el mensaje que las firmadas en `h=` | Prepend de un `From:`/`Subject:` no firmado bajo un `dkim=pass` real | S | M |
| G17 | Lista de servicios de hosting abusables (workers.dev, web.app, pages.dev, vercel/netlify.app, notion.site, t.me, Discord CDN, IPFS, Google Forms/Docs) — señal **combinada**, nunca gate en solitario (arregla parte de N3) | Payload alojado en servicio legítimo | A | M |
| G18 | Correlación Message-ID ↔ hosts `by` del Received; coherencia HELO/PTR/IP por hop | Message-ID `@mail.gmail.com` cuya cadena nunca tocó Google | A | M |
| G19 | Normalizar el cuerpo antes de matchear (colapsar tags sin partir palabras, quitar zero-width, homóglifos) y matching multilingüe/por tokens | Troceo `ver<span>ify`, zero-width, y frases en DE/FR/IT/PT | A | M |
| G20 | Veredictos del propio proveedor ya en cabecera (`X-Forefront-Antispam` `CAT:PHSH`, `compauth=`, SpamAssassin `X-Spam-Status`) — un header que **inculpa** es fiable (el atacante no lo añade) | Inteligencia de un motor maduro, gratis | A | M |
| G21 | Adjuntos fuera de lista: `.svg`(con `<script>`), `.ics`, `.one`, `.xll`, `.chm`, `.wsb`; QR dentro de PDF/SVG; contenedores RAR/7z/CAB (complementa **D3**) | Vectores 2023-2026 no cubiertos | A | M |
| G22 | Correlación pixel-externo ↔ host del enlace de cosecha (mismo tercero = infra de campaña) — también convierte F5 en señal combinada | Sube a Phishing cuando el tracker y la cosecha coinciden | A | M |
| G23 | Coherencia idioma del cuerpo ↔ marca suplantada / TLD (script + stopwords) | "Microsoft en ruso desde un `.top`" | B | M |
| G24 | Desenvolver safe-links (urldefense/mimecast/safelinks) y analizar el target real; inspeccionar el fragment `#` de la URL | Open-redirect y reescritura de seguridad | B | M |
| G25 | Config de dominio(s) propio(s) del tenant → gate "mi dominio pero auth no `pass`" (tras allowlist) | Spoofing interno (From = tu propio dominio) | A | M |
| G26 | ATT&CK derivado **del gate** que disparó, no tag fijo por regla (mejora **S3**) | Ticket accionable: enlace=T1566.002, adjunto=T1566.001, solo-texto=T1598 | B | M |
| G27 | Clustering por invariantes reales — hash de adjunto, host de cosecha, Reply-To, esqueleto del asunto, simhash del cuerpo — **no** por `from_domain` (que es lo primero que rota el atacante) (mejora **O4**) | Triaje de volumen con el conector | B | M |
| G28 | Contador de corroboración = nº de **familias** distintas que fallan → confianza numérica determinista en el informe | Separa 1 señal fuerte de 3 independientes; hoy no hay confianza salvo la del AI writer | A | Q |

**Requiere red (el límite del diseño offline — tramo E del `ROADMAP.md`):**

| # | Comprobación | Qué aporta | Imp. | Dif. |
|---|---|---|---|---|
| G29 | Edad de dominio (RDAP/WHOIS) — **E1** | Único cierre real de N2 (el "primo autenticado recién registrado") | S | L |
| G30 | Reputación URL/dominio (VT/urlscan/PhishTank) — **E2** | Refuerzo global | A | L |
| G31 | Geo/ASN de la IP de origen (GeoIP local MaxMind — solo dataset, sin egress) — **E3** | Origen incoherente con la marca reclamada | B | L |
| G32 | "Primer contacto" derivado del corpus del buzón conectado (no allowlist manual) — mejora **S4/S5** | La señal nº1 del analista humano; solo posible con el conector | A | L |

### 1.8 Orden de arreglo propuesto

Prioridad = impacto sobre veredicto/FP ÷ esfuerzo. Los bloques **Bloqueante** deben estar
antes de activar la ingesta automática (Fases 3-5), porque cada uno se amplifica con el
volumen.

| # | Bloque | Hallazgos | Esf. | Por qué en este orden |
|---|---|---|---|---|
| 1 | **Bloqueante — bypasses** | A1 + G15 (provenance A-R), N1/G2 (`message/rfc822`), N5/G10 (sello ARC) | M | Sin esto, la autenticación no vale nada y el motor analiza el correo equivocado; la ingesta los multiplica |
| 2 | **Bloqueante — FP tóxicos** | B1/B2 (matching+BEC), F4 (Return-Path registrable), limpiar `bec_phrases` | Q | La mayor fuente de FP; rescata las 3 simulaciones legítimas a Legitimate/Suspicious-bajo sin degradar la detección |
| 3 | **Bloqueante — desaturación** | F3 (fusionar clusters), F6 (recalibrar pesos + gates), G6 (gatear señales fuertes) | M | Cierra F1/F2; requiere el corpus de regresión del paso 5 para hacerse con confianza |
| 4 | Legibilidad | C1 (scores muertos) + D1–D3 (docs a 40 reglas) | Q | Hace el motor razonable antes de tocar más pesos |
| 5 | **Corpus de regresión de FP** | (nuevo, sobre correo legítimo real) | M | Prerrequisito de 3 y de **S6**; sin él la recalibración es a ciegas |
| 6 | Rendimiento/higiene ingesta | C2/C3 (transacción única), C4 (tamaño máx), C5/C6/C7 | Q | C4 es prerrequisito de seguridad de la ingesta; C2 de rendimiento |
| 7 | Detección nueva — quick wins | G1, G3, G4, G5, G7, G8, G9, G11, G28 | Q | Cierran V3/V7/V8/V12 y añaden las señales de mayor retorno sin coste de red |
| 8 | Detección nueva — medio | G13 (TOAD), G14 (parser HTML), G16–G27 | M | El grueso del abanico; priorizar G13/G14 (clases de ataque hoy invisibles) |
| 9 | Enriquecimiento de red | G29–G32 (= tramo E del ROADMAP) | L | Único cierre de N2; decisión de producto (rompe la premisa offline) |

Los pasos 1–6 son el mínimo para que la ingesta automática no amplifique fallos existentes.
Los pasos 7–9 son mejora de detección y pueden ir después del conector.

---

## Fase 2 — Dónde viven las credenciales (la decisión de arquitectura)

### 2.1 Por qué Acheron no puede custodiar estas credenciales

La propuesta original era reutilizar el patrón de
`plans/feature/acheron-hygeia-agent-key-vault.md`: un tipo nuevo de `Storable` y una FK
opcional desde Iris. **No funciona aquí**, y el motivo no es de diseño sino de física del
sistema.

Acheron es zero-knowledge de verdad: la `vaultKey` se deriva **en el navegador** a partir de
la contraseña maestra, el cifrado ocurre en cliente, y el servidor solo guarda blobs y
parámetros KDF (`acheron/model.py: Vault`). El servidor **no puede descifrar un `Storable`
jamás**, ni siquiera con acceso total a la base de datos.

El conector de buzón necesita exactamente lo contrario: un worker de RQ, a las 03:00, sin
navegador, sin sesión y sin contraseña maestra, tiene que refrescar un token OAuth y llamar a
la API de Gmail. Si el refresh token vive en Acheron, ese worker no puede leerlo. Las únicas
salidas serían mantener la clave del vault en memoria del servidor (lo que destruye la
propiedad zero-knowledge de Acheron para *todos* los secretos, no solo estos) o exigir que el
usuario esté con la sesión abierta y el vault desbloqueado cada vez que toque sondear — lo
que anula el propósito de la ingesta automática.

La diferencia entre los dos casos es limpia y merece quedar escrita:

| | Clave de agente de Hygeia | Token OAuth de buzón |
|---|---|---|
| ¿Quién necesita el secreto en claro? | Solo el humano, una vez, para pegarlo en el agente | El servidor, indefinidamente, sin humano delante |
| ¿Puede el servidor no saberlo? | Sí | **No** |
| Almacén correcto | Acheron (zero-knowledge) | Cifrado en reposo con clave del servidor |

El plan de Hygeia sigue siendo correcto **para Hygeia**, precisamente porque allí el secreto
solo lo consume una persona.

### 2.2 El módulo DRY que sí hay que extraer

La intuición del usuario sobre un módulo compartido es correcta; el módulo simplemente no es
de Acheron. El precedente exacto ya está construido en
`users/services/secrets.py:92-114`: cifrado Fernet en reposo con una clave del servidor
(`MFA_ENCRYPTION_KEY` vía `CR.get_mfa_config()`), para el secreto TOTP — otro caso de
"el servidor tiene que poder leerlo". Su propio comentario de cabecera ya contrasta el caso
con Acheron.

Hoy ese par de funciones está enterrado en `users` y hardcodeado a una clave concreta. Con un
segundo consumidor, la extracción se justifica:

```python
# src/modules/shared/_crypto.py  (nuevo)
def encrypt_at_rest(plaintext: str, purpose: str) -> str: ...
def decrypt_at_rest(token: str, purpose: str) -> str: ...
```

- `purpose` selecciona la clave (`mfa`, `iris_mailbox`, …) desde config, de modo que
  comprometer una no compromete la otra y cada una se puede rotar por separado.
- `users/services/secrets.py` conserva `encrypt_totp_secret`/`decrypt_totp_secret` como
  wrappers finos con `purpose="mfa"` — cero cambios para sus llamantes actuales.
- Iris consume `purpose="iris_mailbox"`.

Es DRY real (dos consumidores, un mecanismo) y no toca Acheron, que se queda exactamente
donde `roadmap-ellysia.md` §7 lo deja: infraestructura para secretos que solo lee el humano.

**Qué sí puede hacer Acheron aquí, opcionalmente:** ofrecer al usuario un botón "guardar esta
conexión en la bóveda" que cree un `Storable` informativo (qué cuenta está conectada, cuándo).
Es cosmético, no es el almacén operativo, y **no debería entrar en la v1** — añade una
dependencia entre módulos a cambio de nada funcional.

### 2.3 Qué se guarda y qué no

Principio: **guardar lo mínimo que permita volver a pedir acceso, nunca el contenido del
buzón.**

- Se guarda cifrado: `refresh_token`, y `access_token` solo si se cachea hasta su expiración.
- Se guarda en claro: el correo de la cuenta conectada, el proveedor, los scopes concedidos,
  la fecha de conexión y el cursor de sincronización.
- **No se guarda nunca**: contraseñas del usuario (el flujo es OAuth, no contraseña — las
  app-passwords de IMAP quedan fuera de la v1 por esto mismo), ni el cuerpo de los correos
  más allá de lo que el usuario mande explícitamente a analizar.

---

## Fase 3 — Modelo de datos e ingesta

### 3.1 Modelos nuevos (`iris/model.py`)

```python
class IrisMailboxConnection(Base):
    """Una cuenta de correo externa conectada por un usuario."""
    __tablename__ = "IrisMailboxConnection"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    user_id       = Column(Integer, ForeignKey("User.id"), nullable=False)
    provider      = Column(String(20), nullable=False)   # "gmail" | "microsoft"
    account_email = Column(String(320), nullable=False)
    scopes        = Column(String(512), nullable=False)

    # Cifrado con shared._crypto (purpose="iris_mailbox"), NUNCA en claro.
    refresh_token_enc = Column(Text, nullable=False)

    folder        = Column(String(255), nullable=True)   # etiqueta/carpeta a vigilar
    sync_cursor   = Column(String(255), nullable=True)   # historyId (Gmail) / deltaLink (Graph)
    status        = Column(String(20), nullable=False, default="active")
                                                          # active|reauth_required|revoked
    last_sync_at  = Column(DateTime, nullable=True)
    last_error    = Column(Text, nullable=True)
    created_at    = Column(DateTime, nullable=False, default=utcnow_naive)

    __table_args__ = (UniqueConstraint("user_id", "provider", "account_email"),)
```

`IrisAnalysis` gana dos columnas opcionales para no perder la procedencia:

```python
connection_id      = Column(Integer, ForeignKey("IrisMailboxConnection.id"), nullable=True)
source_message_uid = Column(String(255), nullable=True)   # idempotencia: no reanalizar
```

`nullable=True` deja intacto el flujo manual existente. Índice único parcial sobre
`(connection_id, source_message_uid)` para que un reintento no duplique análisis.

### 3.2 El ciclo de sondeo

Categoría nueva de TaskQueue `iris.ingest`, más una entrada en el scheduler:

1. Un job periódico recorre las conexiones `active` cuyo `last_sync_at` supere el intervalo.
2. Por conexión: descifra el refresh token, obtiene un access token, y pide **el delta** desde
   `sync_cursor` (`history.list` en Gmail, `/delta` en Graph) — nunca un listado completo.
3. Por mensaje nuevo: descarga **solo las cabeceras** por defecto (`format=metadata` en Gmail,
   `$select` de `internetMessageHeaders` en Graph). El `.eml` completo solo si el usuario
   activó el modo de análisis completo para esa conexión — es la diferencia entre leer
   metadatos y leer el correo de alguien, y debe ser una decisión suya y explícita.
4. Cada mensaje se mete por `IrisManager.analyze(...)`, que ya existe y ya es asíncrono. La
   ingesta **no toca el motor de reglas**: solo lo alimenta.
5. Se avanza `sync_cursor` únicamente cuando el lote entero se encoló bien.

Errores y modo degradado, siguiendo el patrón de `execute_ai_summary_generation` (que ya
degrada limpiamente): un token revocado marca la conexión `reauth_required` y **para de
sondear** — no reintenta en bucle contra la API del proveedor. El rate limit del proveedor se
respeta con backoff y sin tocar el cursor.

### 3.3 Cuotas

`roadmap-ellysia.md` §8.1 ya señala que la falta de cuotas es un riesgo estructural, y la
ingesta automática es justo donde se materializa: una conexión mal configurada puede generar
miles de análisis. Hacen falta desde el día uno, en `SecOpsConfig.json`:
`iris.maxConnectionsPerUser`, `iris.maxIngestedPerDay`, `iris.pollIntervalMinutes`.

---

## Fase 4 — Los conectores

Interfaz común, dos implementaciones — el mismo patrón de estrategia que ya usan
`tools/scribe` y `tools/herald`, y por las mismas razones:

```
iris/services/mailbox/
    base.py        # MailboxConnector: authorize_url / exchange_code /
                   # refresh / list_new(cursor) / fetch_headers(uid) / fetch_raw(uid)
    gmail.py       # Gmail API v1
    microsoft.py   # Microsoft Graph v1.0
    registry.py    # provider -> conector, elegido por SecOpsConfig
```

**Gmail.** OAuth 2.0 de Google, scope `gmail.readonly` (o `gmail.metadata`, aún más
restrictivo, si basta con cabeceras — encaja con "como mínimo, las cabeceras"). Delta vía
`users.history.list`. Requiere `google-auth` + `google-auth-oauthlib`, o `requests` a pelo
contra los endpoints REST. Aviso de realidad: los scopes de Gmail son *restricted*, y una app
que los pida en producción para usuarios ajenos necesita verificación de Google con
evaluación de seguridad anual por un tercero. Para uso propio o para hasta 100 usuarios de
prueba, el modo "testing" de la consola de Google basta y no cuesta nada.

**Microsoft 365 / Outlook.** OAuth 2.0 de Entra ID, scope `Mail.Read`. Delta vía
`/me/mailFolders/{id}/messages/delta`. Requiere `msal` (biblioteca oficial) o REST directo.
El registro de la app es autoservicio y el consentimiento del usuario individual no requiere
verificación previa. **Es claramente el conector por el que empezar**: misma arquitectura,
una fracción de la fricción administrativa.

**IMAP genérico** queda fuera de la v1 deliberadamente: obliga a guardar una contraseña de
aplicación reutilizable en vez de un token revocable y con scope, que es un perfil de riesgo
peor por un alcance que hoy no hace falta. Se puede añadir después con la misma interfaz.

### 4.1 Endpoints nuevos

Todos bajo `iris_blp`, con `require_oauth_token` y los atributos existentes:

| Método | Ruta | Atributo | Función |
|---|---|---|---|
| `GET` | `/iris/mailbox/providers` | `IRIS_READ` | Proveedores configurados |
| `POST` | `/iris/mailbox/connect` | `IRIS_CREATE` | Devuelve la URL de autorización + `state` |
| `GET` | `/iris/mailbox/callback` | — | Callback OAuth: valida `state`, canjea el código |
| `GET` | `/iris/mailbox/connections` | `IRIS_READ` | Lista (nunca devuelve el token) |
| `PATCH` | `/iris/mailbox/connections/<id>` | `IRIS_UPDATE` | Carpeta, intervalo, pausar |
| `DELETE` | `/iris/mailbox/connections/<id>` | `IRIS_DELETE` | Revoca en el proveedor y borra |
| `POST` | `/iris/mailbox/connections/<id>/sync` | `IRIS_UPDATE` | Sondeo manual |

Detalles que no son opcionales: el `state` de OAuth debe ser de un solo uso, con TTL y ligado
al `user_id` (CSRF en el callback); el `redirect_uri` se construye desde `PUBLIC_WEB_URL`
(que ya existe en la config) y nunca desde un parámetro del request; y el `DELETE` debe
intentar revocar el token contra el proveedor antes de borrar la fila — dejar un refresh token
vivo en Google/Microsoft después de que el usuario haya pulsado "desconectar" es un fallo de
expectativa, aunque nosotros ya no lo guardemos.

---

## Fase 5 — Frontend

- **Nueva vista** `IrisConnectionsView.vue`: lista de cuentas conectadas, estado, última
  sincronización, y un botón "Conectar cuenta" que abre el flujo OAuth en una ventana nueva.
- **`IrisView.vue`**: el historial de análisis distingue el origen (manual vs. buzón, con el
  proveedor y la cuenta), y permite filtrar por conexión.
- **Estado `reauth_required`**: banner claro con acción de reconectar — es el único estado que
  requiere al usuario y hay que hacerlo obvio, no esconderlo en un badge.
- **Antes de conectar**: decir con precisión qué se va a leer (cabeceras vs. correo completo),
  qué se guarda y qué no, y que se puede revocar en cualquier momento. Con el modo "correo
  completo" desactivado por defecto.

---

## Valoración

- **Esfuerzo.** Fase 1: entre Q y M, casi todo son arreglos acotados salvo A1 y el corpus de
  regresión. Fases 2–5: es la funcionalidad más grande que le queda a Iris — OAuth saliente,
  modelo nuevo, scheduler, dos conectores y una vista. Realista: semanas, no días, al ritmo
  declarado de 10–15 h/semana.
- **Riesgo.** El riesgo técnico está concentrado en Fase 1: si A1 no se arregla primero, la
  ingesta automática convierte un bypass de autenticación en un bypass a escala. El riesgo
  operativo está en el manejo del refresh token, que se mitiga con el cifrado en reposo por
  `purpose` y con la revocación en el `DELETE`. El riesgo administrativo (verificación de
  Google) se esquiva empezando por Microsoft.
- **Valor real.** Es lo que convierte a Iris de demo en herramienta, y es la condición que
  `roadmap-ellysia.md` §7 ya puso por escrito para descongelarlo. También descoloca la
  afirmación de ese mismo documento de que *"las 37 reglas están bien hechas y no se tocan"*
  (ya corregida en `roadmap-ellysia.md` a raíz de esta auditoría): el consejo la contradice en
  puntos concretos y verificables — dos bypasses ejecutables y un modelo de scoring saturado.
- **Matiz importante sobre la recalibración.** El grueso del trabajo de Fase 1 **no es añadir
  detecciones, es arreglar y desaturar** lo que ya hay: las 40 reglas, una a una, están bien;
  fallan en las costuras (clusters de doble conteo), en las listas finitas, en el parser, y en
  un score que ahoga el correo legítimo. La detección nueva (sección 1.7) es real y valiosa,
  pero secundaria frente a los bloques 1–3 del orden de arreglo. Regla de oro heredada del
  diseño actual: el score separa "limpio" de "revisar", los **gates** hacen el "malo" — así que
  suavizar pesos y endurecer gates van **juntos**, nunca por separado.
- **Recomendación.** Fase 1 primero y por separado: tiene valor propio (arregla bypasses reales
  de un motor que ya está en uso) y no depende de que el conector llegue a construirse nunca.
  Dentro de Fase 1, el orden de la sección 1.8. Del conector, empezar por Microsoft Graph. IMAP
  genérico y la integración con Acheron, si llegan, después y por separado.

---

## Hallazgos post-desarrollo (2026-07-22/23, tras implementar Fases 2-5)

Fases 2-5 se implementaron y probaron manualmente contra Google real (rama
`feature/iris/rules-fine-tunning`; Fase 1 ya estaba commiteada, Fases 2-5
quedan pendientes de commit hasta este punto). Verificado en vivo:
`POST /iris/mailbox/connect` genera una `authorizeUrl` real y Google la
acepta (reconoce "Ellysia", sin error de `client_id`/`redirect_uri`). Esta
sección recoge lo que la implementación y las pruebas manuales encontraron
que el diseño original no prevé — no son ideas nuevas, son hechos
verificados contra el código/la UI ya construidos.

### Desviaciones deliberadas del diseño de Fase 5

- **Redirect de página completa, no ventana nueva.** El texto original decía
  "un botón que abre el flujo OAuth en una ventana nueva". Se implementó
  como redirect de página completa (`window.location.href`) porque el
  backend ya cierra el flujo con un redirect de servidor tras el callback
  (`GET /iris/mailbox/callback` → `{PUBLIC_WEB_URL}/iris/conexiones`) — usar
  una ventana emergente habría exigido además `postMessage`/gestión de
  ventana para que la SPA principal se enterase de que terminó. Más simple
  y con el mismo resultado percibido por el usuario.
- **El historial de análisis NO distingue todavía origen manual vs. buzón.**
  El diseño original de `IrisView.vue` lo daba por hecho ("distingue el
  origen... y permite filtrar por conexión"). El dato ya existe
  (`IrisAnalysis.connection_id`/`source_message_uid`, persistido desde
  Fase 3) pero no se expone en `AnalysisListItemSchema` ni se renderiza en
  `IrisHistoryStrip.vue`. Ofrecido al usuario como siguiente paso, no
  implementado en esta sesión.

### Bug real encontrado, sin arreglar todavía

- **`IrisAnalysis.connection_id` no tiene `ondelete` en el FK hacia
  `IrisMailboxConnection.id`** (`API/src/modules/features/iris/model.py`).
  En Postgres esto es `RESTRICT` por defecto: en cuanto una conexión tenga
  al menos un análisis asociado (es decir, siempre que haya sobrevivido a un
  sondeo), `IrisMailboxManager.delete_connection()` →
  `DELETE /iris/mailbox/connections/<id>` falla con un error de integridad
  en vez de borrar la fila. **"Desconectar" está roto para el caso de uso
  real.** Los tests existentes no lo cazan porque ninguno crea una
  `IrisMailboxConnection` con análisis asociados antes de borrarla. Arreglo
  previsto: `ondelete="SET NULL"` en el FK (conserva el histórico de
  análisis, solo desvincula la conexión borrada) + migración Alembic nueva.

### Riesgo estructural para SaaS multi-réplica

- **`IrisMailboxScheduler` es un `BackgroundScheduler` en memoria, por
  proceso** (mismo patrón que `HygeiaScheduler`/`Scheduler` de Themis, que
  tienen el mismo límite). Con una sola réplica de la API funciona bien; en
  cuanto se escale horizontalmente (el escenario normal de un SaaS), cada
  réplica sondea las mismas conexiones de forma independiente →
  sondeos/análisis duplicados. No es un bug de esta Fase 4 en particular,
  es un límite de arquitectura que ya existía y que este trabajo hereda sin
  resolver. Solución real: mover el disparo periódico a un scheduler
  externo compartido (cron del sistema pegando a un endpoint interno, o un
  job de APScheduler con `jobstore` en Postgres/Redis en vez de en memoria)
  antes de correr más de una réplica.

### Gaps de producto (no de código) para vender esto como SaaS

- **Calibración del motor de detección incompleta.** La auditoría de Fase 1
  (`iris-rules-audit-fase1`) encontró y arregló los bypasses y los falsos
  positivos más tóxicos, pero dejó fuera deliberadamente la recalibración
  completa de pesos y la fusión de reglas (C1/F6/N2 — ver el bloque de
  estado al inicio de la Fase 1) por falta de la tabla de pesos del consejo.
  Para un producto que se vende como "detector de phishing", la precisión
  percibida es el producto.
- **Sin medición de uso ni facturación por tenant.** Las cuotas actuales
  (`iris.maxConnectionsPerUser`, `iris.maxIngestedPerDay`) son límites de
  protección, no un contador de uso facturable.
- **Sin notificación activa cuando una conexión pasa a `reauth_required`.**
  Hoy el usuario solo se entera si entra a `/iris/conexiones` a mirar; para
  un producto en el que "que siga funcionando solo" es la propuesta de
  valor, un fallo silencioso es especialmente malo.
- **Aviso legal/RGPD pendiente.** Analizar automáticamente el correo de un
  usuario (aunque solo sean cabeceras, ver Fase 2.3 "qué se guarda y qué
  no") es tratamiento de datos que requiere política de privacidad y
  consentimiento explícito antes de vender esto a usuarios en la UE — el
  diseño de datos mínimos ya construido es una condición necesaria, no
  suficiente.

### Bugs de interfaz encontrados en pruebas manuales (ya arreglados)

- **Tipografía inconsistente.** `MailboxConnectionList.vue` se copió de
  `components/hygeia/AssetList.vue`, que usa una escala de fuente pequeña a
  propósito (lista de monitorización densa) — pero Iris usa una escala
  mayor en sus propios componentes (`IrisHistoryStrip.vue` usa `--fs-lg`).
  Arreglado subiendo la escala de la lista de conexiones para igualar el
  resto de Iris.
- **El enlace "Conexiones de buzón" rompía el estilo visual.** Se había
  escrito una clase CSS nueva (`.connections-link`) en vez de reutilizar
  `.back-link`, ya existente en `assets/css/shared.css` y usada por el
  "Volver" del Topbar. Arreglado reutilizando la clase global; verificado
  que el font-size computado coincide exactamente (18px) con el resto de
  los enlaces de navegación de la app.
- **Posición del enlace.** Quedaba entre la cabecera y el historial,
  interfiriendo visualmente con ambos. Movido a debajo de
  `IrisHistoryStrip`, antes del panel principal.

---

## Referencias

- `API/src/modules/features/iris/ROADMAP.md` — hoja de ruta del motor. **I4** ("Integración de
  buzón (IMAP/Graph/Gmail)", `C/L`, "Diseño aparte") es este documento. La auditoría de Fase 1
  desbloquea/detalla varios items existentes: **D6** (provenance A-R, ver G15), **D7** (sello
  ARC, ver N5), **D3** (adjuntos, ver G21), **D9** (confusables, extender a hosts de enlaces),
  **S3** (ATT&CK, ver G26), **O4** (clustering, ver G27), **S4/S5/S6** (allowlist/feedback/
  pesos, ver 1.3 y 1.6), **E1/E2/E3** (enriquecimiento de red, ver G29–G31). Items **nuevos**
  no listados en el ROADMAP: N1 (`message/rfc822`), G13 (callback/TOAD), G3 (TLD en enlaces),
  G8 (fingerprint de infraestructura), G7 (lookalike del dominio propio).
- `plans/roadmap-ellysia.md` §7 — la decisión de congelar Iris hasta que haya ingesta; corregido
  el recuento de reglas (37→40) y la afirmación "bien hechas y no se tocan" a raíz de esta auditoría.
- `plans/feature/acheron-hygeia-agent-key-vault.md` — el patrón que **no** aplica aquí, y por
  qué (Fase 2.1).
- `API/src/modules/users/services/secrets.py:92-114` — el precedente de cifrado en reposo del
  lado servidor que sí aplica.
- **Auditoría por consejo (2026-07-22):** cuatro perspectivas expertas en paralelo —
  autenticación/forense de cabeceras, red team de evasión, analista SOC de triaje, e ingeniería
  de calibración/FP. Sus informes íntegros (tablas de pesos actual→propuesto, simulaciones de
  scoring, catálogo completo de evasiones) son la fuente de las secciones 1.1, 1.3 y 1.7.
