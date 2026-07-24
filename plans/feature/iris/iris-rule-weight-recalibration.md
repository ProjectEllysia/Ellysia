# Iris — Recalibración de pesos de reglas (informe del consejo)

> **Estado: estudio de diseño, NO aplicado.** Es el insumo que faltaba para **S6**
> (pesos configurables) y **F6** (recalibración) del `ROADMAP.md` — el "informe del
> consejo con la tabla peso actual→propuesto" que la auditoría de Fase 1 declaró no
> disponible. No se ha tocado ningún `score=-N` en el código. Aplicarlo requiere
> primero (a) ampliar el corpus de regresión de FP y (b) el orden de implementación
> de la última sección, porque bajar pesos a ciegas sin gates emparejados abre
> agujeros transitorios.

Elaborado convocando cuatro perspectivas expertas en paralelo sobre el **inventario
verificado del código** (rama `feature/iris/rules-fine-tunning`, 40 reglas, modelo
sustractivo desde 100, umbrales 80/55, gates): ingeniería de calibración/FP, red team
de evasión, analista SOC de triaje, y forense de autenticación/cabeceras. Los números
salen de leer las reglas reales, no de inferencia.

---

## 0. La tesis, y las dos correcciones de hecho al plan original

**Tesis (consenso de los cuatro):** el score de Iris está **saturado**. El umbral
Legitimate es ≥80, así que el presupuesto para seguir siendo legítimo es perder <20
puntos — y varias reglas ruidosas restan 30-45 a correo perfectamente normal. Hoy el
rango dinámico entre legítimo (56-67) y phishing (~46) es de ~10 puntos: el número
apenas separa. Lo que atrapa el phishing en la práctica **no es el score, son los
gates**, que son independientes del score. De ahí el principio rector:

> **Suavizar los pesos del score y endurecer/ajustar los gates van SIEMPRE juntos.**
> El score baja hasta que separa "limpio" (85-100) de "revisar" (55-84); los gates
> hacen el "malo" (<55). Como los gates se derivan del `verdict`/`details` de la
> regla y **no del signo del score** (`_extract_verdict_signals`), bajar un peso
> nunca desactiva un gate mientras se conserve el `verdict`.

**Corrección 1 (forense).** El plan afirmaba un triple conteo "SPF fail + DMARC fail +
Domain Alignment fail = −55". **Es inexacto:** `Domain Alignment` YA defiere a `score=0`
cuando `dmarc=fail` (fix F3 aplicado, `auth_rules.py:297-302`). El triple conteo real y
vivo es **SPF −20 + DKIM −15 + DMARC −20 = −55** por el mismo hecho ("no autentica").
Alignment ya está bien; el problema son SPF/DKIM restando en pleno lo que DMARC ya
integra.

**Corrección 2 (calibración).** El plan situaba el aviso interno de RRHH en **56**. La
simulación regla-a-regla lo pone en **mid-70s** — un aviso interno mínimo no dispara
frases BEC ni de credenciales, así que solo pierde ~13-26. Baja a los 60 únicamente si
además lleva urgencia fuerte y un enlace tipo formulario. La dirección de F1 (correo
legítimo normal sale Suspicious) es correcta; el "56" concreto para ese arquetipo estaba
sobreestimado.

**Hallazgo que reencuadra el trabajo (calibración):** suavizar pesos es **necesario pero
no suficiente**. Cuatro reglas contaminantes además llevan un gate `single→Suspicious`,
así que el correo legítimo sale Suspicious *aunque el score suba a ≥80*:
`received_chain_fail` (IP interna del RRHH), `body_content_fail` (lenguaje de banca
legítima), `body_links_fail` (redirect de tracking del newsletter), `bec_fail`
corporativo (aviso de nómina). Estos cuatro gates hay que **estrecharlos** (sección 4).

---

## 1. El mecanismo estructural nuevo: techos de familia

La aportación central del analista SOC, y el cambio de mecánica que convierte la "suma de
reglas" en un "contador de corroboración" legible: **agrupar las reglas por familia y
topar lo que cada familia puede restar** a ~una unidad de señal fuerte. Hoy no existe;
la agregación suma todo plano.

Las 7 familias y su techo propuesto:

| Familia | Techo | Racional |
|---|---|---|
| Autenticación (SPF/DKIM/DMARC/Alignment) | **−25** | "no autentica" es UN hecho; DMARC ya lo integra |
| Identidad (Spoof/Lookalike/Subdomain/Mismatch/From/Misspelled/TLD) | **−28** | "suplanta a alguien" es UN hecho |
| Reply-path (Reply-To/Return-Path/Triangulation) | **−15** | Triangulation ES la combinación de las otras |
| Contenido (Alarming/BEC/Body Content/Greeting/URL-subj/Unicode/Encoded) | **−25** | urgencia+saludo+frase co-ocurren en banca legítima |
| Enlaces (Body Links/QR/Compromised) | **−30** | detector primario, gatea |
| Recibido (Chain/Path/Temporal/Date) | **−12** | mayormente infraestructura interna normal |
| Adjunto (Attachments/Image-Only/Ext-Image) | **−28** | detector primario, gatea |

**Efecto en la escala:** 0 familias→100 (limpio), 1 familia→~72 (revisar), 2→~45
(malo), 3→~17 (malo obvio, "el número grita"). Cada familia independiente que cae cuesta
~25-30, así que el número final codifica **cuántas familias fallaron**, no cuántas reglas
se dispararon. Es lo que restaura la separabilidad para el triaje: el analista puede
ordenar la cola por número y auto-cerrar >85 con confianza.

---

## 2. Tabla consolidada de pesos: actual → propuesto

Reconciliación de las cuatro propuestas (donde diferían, se toma el número más defendible;
para reglas que **gatean**, el valor exacto del score es casi irrelevante para el
veredicto, así que se adopta el más suave). "Recae en" = si la detección de esa señal
descansa en el score o en un gate.

### Autenticación — techo familia −25 (forense es la lente líder)
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| DMARC | fail −20 / none −3 | **−15 / −2** | score + gate | Veredicto integrador (RFC 7489); ancla del cluster |
| SPF | fail −20 / soft −5 / err −3 | **−8 / −3 / 0** (−3 si DMARC concluyente) | score + gate | Subordinada: DMARC ya la integra cuando está presente |
| DKIM | fail −15 | **−8** (−3 si DMARC concluyente) | score | Subordinada + valor propio (tampering); no gatea sola |
| Domain Alignment | fail −15 | **−12** (solo si DMARC ausente; ya defiere) | score + gate | Reconstruye DMARC; nunca apila sobre él |
| ARC Chain | fail −8 | **−6** | score + gate | Hecho distinto (ruptura previa); **fuera** del techo |

Reparto: DMARC ancla −15; SPF/DKIM caen a −3 cuando DMARC es concluyente (fail o pass) y
solo recuperan −8 con DMARC ausente. Escenario spoof puro pasa de −55 a **−21** en score
— sigue cayendo a Suspicious, pero deja de aplastar el rango. La caza real la hace el
gate `spf_fail|dmarc_fail`, intacto.

### Identidad — techo familia −28
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| Lookalike Sender Domain | −15 | **−15** (intacta) | **gate→Phishing** | No toca correo legítimo; gatea sola |
| Display Name Spoofing | −12 / −8 | **−12 / −8** (intacta) | **gate** (spoof_free→Phishing) | No toca legítimo |
| Subdomain Impersonation | −12 / −8 | **−10 / −8** + **promover a gate** | score→**gate** | Único catcher de `marca.com.evil.tk`; hoy a −12 ya deja pasar |
| Display Name Email Mismatch | −10 | **−8** + **promover a gate** | score→**gate** | Footprint BEC; sin gate, −10 nunca baja de 55 |
| From header check | −10 | **−5** | score | From malformado es raro; no contamina legítimo |
| Misspelled Brand Names | −5·min(n,2) | **−3·min(n,2)** | score | Roza palabras multilingües; corroboración débil |
| Suspicious TLD | −5·count | **máx −10** | score | Corroboración; gTLDs legacy con uso legítimo |

### Reply-path — techo familia −15
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| From/Reply-To/Return-Path Triangulation | −12 | **−10** (**subsume** los pairwise) | score + gate | ES la combinación de las otras tres; lleva el peso |
| Reply-To Free Provider | −8 | **−8** (intacta) | gate (replyfree→Susp) | Gatea |
| Reply-To check | −10 | **−6** (suprimido si triangula) | score | Evita apilar −10+−12 sobre el mismo desalineo |
| Return-Path mismatch | −8 | **−4** | score | Tercer conteo pairwise del mismo eje |

### Threading — techo familia (comparte con identidad/cabecera)
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| Self-Referencing In-Reply-To | −12 | **−12** (intacta) | gate→Susp (G6) | Falsificación inequívoca; gatea |
| Fake Reply Chain | −4 | **0** (fusionar en Self-Ref) | — | −4 invisible; solapa con Self-Ref |
| Message-ID check | −4 | **0** (informacional) | — | Mailers legítimos generan Msg-IDs raros |
| Message-ID Domain | −3 | **−2** | score | Gana valor con la correlación nueva (§5) |

### Contenido — techo familia −25
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| BEC Wire Transfer | base −15 | **−8** + gate corporativo nuevo | gate (bec_free→Phishing) | Débil sobre corporativo autenticado; el kill lo da el gate |
| Alarming Keywords | high −15 / med −10 / low −5 | **−10 / −5 / 0** | gate combo (alarming_strong) | Urgencia es estándar en banca; low es ruido puro |
| Body Content (frases / oculto) | −5·min(n,3) / −10 | **−3·min(n,2) / −10** | gate (a estrechar) | "Verifique su cuenta" en banca legítima; el texto oculto sí es evasión |
| Generic Greeting | −8 / −11 | **−3 / −5** | score | Contaminante nº1: "Estimado cliente" + verbo en casi todo legítimo |
| Unicode Evasion | floor −30 | **floor −20** | gate→Susp (G6) | Gatea; floor menor |
| Encoded-Word Abuse | floor −30 | **floor −15** + **promover a gate** | score→**gate** | Hermano de Unicode pero sin gate; único catcher |
| URL in Subject | −5·min(n,2) | **−6 máx** | score | Débil |

### Enlaces — techo familia −30
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| Body Links | floor −25 | **floor −25** (intacta) + eximir redirects ESP en `analyze_url` | gate→Phishing | Gatea cloaked/impersonation; la exención ESP quita el FP del newsletter sin tocar el gate |
| QR Code Links | computado | **igual** (intacta) | gate→Phishing | Gatea |
| Compromised Legit Domain | −6 / −9 | **−6 / −9** (intacta) | score | Corroboración honesta |

### Recibido — techo familia −12 (forense lidera)
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| Received Temporal Inconsistency | −10 / −15 | **−8 / −12** + tolerancia 300s | gate→Susp (G6) | Real, pero ignorar inversiones <5min (clock skew) |
| Received Chain | priv −5 / desfase −5 | **priv 0 (exento interno) / −3** | gate (a estrechar) | Origen RFC1918 es normal en correo interno; Path ya lo exime, Chain no |
| Received Path Anomaly | tls −6 / long −4 / miss −3 | **−4 / −3 / 0** (mantener exención all_internal) | gate combo∧auth_fail | Ya exime interno; reducir magnitud |
| Date Header Anomaly | miss −3 / unp −4 / fut −4 / past −2 | **−2 / −4 / −4 / 0** | score | Solo "future" es señal fuerte; "past"/"missing" comunes |

### Destinatario / Adjunto / Content-trust
| Regla | Actual | Propuesto | Recae en | Motivo |
|---|---|---|---|---|
| Undisclosed Recipients | −6 / −5 / −2 | **−3 / −3 / 0** | score | Newsletters usan BCC de forma rutinaria |
| Suspicious Attachments | floor −25 | **floor −25** (intacta) | gate (attach) | Detector primario; gatea |
| Image-Only Email | −10 | **−6** | score | Marketing legítimo es imagen-pesado |
| External Image Tracking | −5 / −8 | **−3 / −5** | score | Todo email HTML carga de un CDN |
| **Content-Type check** | 0 (muerta) | **eliminar regla** | — | Confirmado código muerto; 40→39 reglas |
| List-Unsubscribe | +2/+3 (muerto por clamp) | **dejar informacional** | — | Positivo neutralizado por el modelo sustractivo |

---

## 3. Gates a AÑADIR — la mejora de detección que compensa el suavizado

El suavizado del score se paga con detección **más afilada** en los gates. Unión de las
propuestas de forense y red team, por prioridad:

| # | Gate nuevo | Nivel | Qué cierra | Fuente |
|---|---|---|---|---|
| G-A | **authserv-id ↔ último `by` del Received** incoherente | pass forjado→**Phishing**; mismatch→Susp | El agujero central: fiarse de `Authentication-Results` sin verificar que lo estampó el receptor real. Un atacante pega `dmarc=pass` y el motor lo cree | Forense (prioridad absoluta) |
| G-B | **recipient_lookalike**: `registrable(From)` es homoglyph/typo/edit-1 del dominio del **destinatario** | **Phishing** | El vector BEC nº1, hoy **invisible** (Lookalike solo compara con marcas, nunca con el dominio propio de la org) | Red team (máxima prioridad) |
| G-C | **display_name_is_foreign_address**: el display parsea como email y su dominio ≠ From | Susp (→Phishing si es dominio del destinatario o marca) | `From: "ceo@acme.com" <attacker@evil.com>` con `evil.com` autenticado | Red team |
| G-D | **toad_callback**: nº teléfono ∧ keywords pago/factura/suscripción/soporte ∧ sin thread previo | Susp | TOAD/callback sin enlaces ni adjuntos ("su suscripción se renovó, llame al…"), clase hoy invisible (score 100) | Red team |
| G-E | **external_login_link**: `alarming_strong ∧ body_link con registrable ≠ From` | Susp | Aproxima el "primo autenticado" con enlace de cosecha sin depender de la lista de marcas | Red team |

## 4. Gates a PROMOVER y a ESTRECHAR — el trabajo bidireccional

**Promover (score-only → gate).** Red team: estas señales son el único separador de su
ataque y a peso actual **ya lo dejan pasar en solitario**. Deben promoverse a gate
**ANTES** de bajar su peso (si no, se abre un agujero transitorio):
- `subdomain_impersonation (brand_in_subdomain)` → **Phishing**
- `encoded_word_abuse` → Suspicious
- `display_name_email_mismatch (random local)` → Suspicious
- `bec_fail ∧ (reply_domain ≠ from_domain)` → **Phishing** (BEC corporativo con reply externo = intención de desvío; endurece el flanco BEC que hoy depende 100% de la lista de frases)

**Estrechar (gate sobre-ancho que hoy marca legítimo).** Calibración: sin esto, el correo
legítimo sigue Suspicious pese a score ≥80:
- `received_chain_fail`: aplicar la exención `all_internal` (que Path Anomaly ya tiene) → deja de gatear sobre cadenas 100% RFC1918. *(Quita el FP del RRHH.)*
- `body_content_fail`: de `single→Susp` a **combinación** `∧ (auth_fail ∨ spoof ∨ body_links_fail)`. *(Quita el FP del banco; el texto oculto sigue gateando.)*
- `body_links_fail`: **no** tocar el gate; eximir redirects de ESP en `analyze_url` para que el tracking legítimo no genere findings. *(Quita el FP del newsletter conservando el detector.)*
- `bec_fail` corporativo: gatea a Susp solo con `redirect` o `auth_fail`; `bec_free` (Gmail) intacto → Phishing.

## 5. Comprobaciones forenses nuevas (score, alimentan combos)

Bajo coste, no salen de las cabeceras, atacan la grieta de "confío en A-R sin verificar":
- **Message-ID ↔ hosts `by`/`from` del Received** (−4, no gatea solo, ruidoso): Msg-ID acuñado por un host ausente de toda la cadena.
- **HELO/PTR/IP por salto** (−5, Susp solo en combo con `auth_fail`): en el hop de origen, HELO que no resuelve al PTR/IP conectante = open-relay/spoof clásico.

---

## 6. Simulación antes / después (los 7 correos-tipo)

**Legítimos (deben salir Legitimate):**

| Correo | Score actual → veredicto | Score propuesto → veredicto |
|---|---|---|
| 1 Newsletter ESP | 63 → Suspicious ❌ | **91 → Legitimate** ✅ |
| 2 Aviso RRHH interno | 74-79 → Suspicious ❌ | **92-97 → Legitimate** ✅ |
| 3 Alerta REAL de banco | 64 → Suspicious ❌ | **82 → Legitimate** ✅ |
| 4 Transaccional | 87 → Legitimate ✅ | **94 → Legitimate** ✅ |

(El veredicto **final** Legitimate de 1-3 exige los estrechamientos de gate de §4; solo
con los pesos, el score sube a ≥80 pero seguirían Suspicious por gate residual — por eso
pesos y gates van juntos.)

**Phishing (deben seguir Phishing) — la detección recae en el gate, no en el score:**

| Correo | Score propuesto | Gate decisivo | Veredicto final |
|---|---|---|---|
| 5 Marca + .tk + cosecha | muy bajo (~17) | `lookalike` **y** `cloaked_link`→Phishing | **Phishing** ✅ |
| 6 BEC desde Gmail | **~92** | `bec_free`→Phishing | **Phishing** ✅ |
| 7 Adjunto malicioso | ~45 | `attach∧auth_fail`→Phishing | **Phishing** ✅ |

**El caso 6 es la demostración de la tesis:** su score sube a 92 (habría dicho
Legitimate), pero el gate `bec_free` lo mantiene Phishing. Score suavizado, gate sostiene
la detección. **Resultado global:** limpio pasa de 56-67 a **82-100**, phishing queda
**17-58**; el rango dinámico pasa de ~10 a ~65 puntos y el número vuelve a ser legible.

---

## 7. Orden de implementación y prerequisitos

Ninguno de los cuatro recomienda aplicar esto de golpe. Orden seguro:

1. **Prerrequisito bloqueante — corpus de regresión de FP.** El
   `tests/unit/test_iris_fp_regression.py` existe pero es pequeño (4 correos). Ampliarlo
   con correo legítimo real variado (más ESPs, banca, RRHH, transaccional, multilingüe)
   **antes** de tocar un solo peso. Sin él la recalibración es a ciegas — fue el bloqueo
   original y sigue siéndolo.
2. **Promover a gate los 4 sole-catchers** (§4, "Promover") **antes** de bajar sus pesos.
   Si se baja el peso primero, se abre un agujero de detección transitorio.
3. **Estrechar los 4 gates sobre-anchos** (§4, "Estrechar") **a la vez** que se bajan los
   pesos contaminantes, o el correo legítimo sigue Suspicious pese al score.
4. **Añadir los gates nuevos** (§3) — es la mejora de detección; priorizar G-A (authserv-id)
   y G-B (recipient_lookalike).
5. **Aplicar los pesos** (§2) y los **techos de familia** (§1). Los techos son el mayor
   cambio de mecánica (nueva lógica de agregación por familia); pueden diferirse a un
   segundo paso si se quiere reducir riesgo.
6. **S6 como vehículo:** mover los pesos a `iris.scoring.*` (config) en lugar de literales
   `score=-N`. Hoy no existe; hasta entonces cada peso es una edición directa. Un accessor
   `CR.get_iris_rule_weight(name, default)` es el patrón natural.

**Contrato de tests que NO se rompe:** la propuesta cambia solo literales negativos
(`score=-N` de las ramas fail); **no toca los positivos** de las ramas pass (SPF/DKIM/
DMARC/Alignment/ARC/List-Unsubscribe), así que los ~15 tests unitarios que verifican
`score > 0` en aislamiento siguen pasando. Los gates son verdict-based, así que bajar un
peso conservando el `verdict` no desactiva ningún gate existente.

---

## Referencias de código

- `API/src/modules/features/iris/managers.py:763-960` — `_aggregate_score` (modelo
  sustractivo + clamp), `_extract_verdict_signals`, `_evaluate_gates` (donde viven los
  gates y la supresión por ARC; donde irían los techos de familia y los gates nuevos).
- `API/src/modules/features/iris/services/rules/auth_rules.py` — cluster auth (Alignment
  ya defiere en dmarc=fail, líneas 297-302).
- `.../rules/body_content_rules.py` — Generic Greeting, Alarming, Body Content, BEC (los
  contaminantes principales).
- `.../rules/reply_path_rules.py` — cluster identidad con exención ESP ya aplicada.
- `.../rules/received_timing_rules.py` — Received Chain (IP privada −5, sin exención) vs
  Path Anomaly (exención `all_internal` ya presente, a replicar en Chain).
- `.../rules/sender_identity_rules.py` — cluster marca (intacto salvo promociones a gate).
- `.../rules/content_trust_rules.py` — Content-Type check (eliminar) y List-Unsubscribe.
- `API/src/modules/system/config_reading.py:913-920` — umbrales `legitimate`/`suspicious`.
- `API/tests/unit/test_iris_fp_regression.py` — corpus a ampliar (prerrequisito 1).
