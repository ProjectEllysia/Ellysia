# Iris — Hoja de ruta de mejoras

Roadmap del analizador anti-phishing Iris. Nace del análisis de carencias de 2026-07
(34 ideas identificadas). Cada mejora lleva su **idea general de implementación**;
las mejoras se implementan de forma incremental, en el orden de los tramos.

**Leyenda** — Valor: `S` máximo · `A` alto · `B` medio · `C` estratégico.
Esfuerzo: `Q` quick win (horas–1 día) · `M` medio (días) · `L` grande (semanas/decisión).
Estado: `[ ]` pendiente · `[~]` en curso · `[x]` hecho.

---

## Reglas transversales (aplican a TODO lo que se implemente)

1. **Datos configurables → `API/SecOpsConfig.json`.** Toda lista de dominios,
   marcas, palabras clave, frases, extensiones o TLDs vive en el bloque
   `iris.data.*` del JSON y se lee vía `config_reading.get_iris_data(key)`.
   Los **regex se quedan compilados en código** (son lógica, no configuración).
   Cada dataset tiene un default en `services/shared.py` para que la app arranque
   aunque falte la clave en el JSON.
2. **Sin imports entre módulos hermanos.** Si dos reglas (o `managers.py`)
   necesitan el mismo símbolo, éste vive en `services/shared.py` (helpers de
   dominio, levenshtein, homóglifos, `find_brand_in_subdomain`, `url_host`,
   `strip_html`, `is_free_provider`, accessors de datos…). Una regla nunca
   importa de otra regla.
3. **Un fichero por categoría, no por regla.** Desde 2026-07-03,
   `services/rules/` agrupa las reglas en 10 ficheros temáticos en vez de
   un fichero por regla (`auth_rules.py`, `sender_identity_rules.py`,
   `reply_path_rules.py`, `thread_rules.py`, `recipient_rules.py`,
   `received_timing_rules.py`, `content_trust_rules.py`,
   `body_content_rules.py`, `body_links_rules.py`,
   `attachment_media_rules.py`). Al añadir una regla nueva, se registra en
   el fichero de su categoría (o se crea uno nuevo si de verdad no encaja
   en ninguno); `services/rules/__init__.py` importa los 10 módulos para
   disparar el registro de `@iris_rules.register`.

---

## Fase 0 — Refactor de base (prerequisito) `[x]`

El código actual incumple las dos reglas. Antes de añadir mejoras:

**0a · `services/shared.py` + eliminar imports cruzados.**
Imports cruzados detectados a eliminar:
- `body_links.py` → `subdomain_impersonation.find_brand_in_subdomain`
- `compromised_legitimate_domain.py` → `body_links._host`
- `lookalike_domain.py` → `misspelled_brands.{CANONICAL_BRANDS,_normalize_homoglyphs,_levenshtein}`
- `subdomain_impersonation.py` → `misspelled_brands.CANONICAL_BRANDS`
- `reply_to_free_provider.py` → `display_name_spoof.FREE_PROVIDER_DOMAINS`
- `managers.py` → `rules.display_name_spoof.FREE_PROVIDER_DOMAINS`

Además se mueven a `shared.py` los helpers hoy en `registry.py`
(`extract_domain`, `registrable_domain`, `extract_display_name`,
`_MULTI_LEVEL_TLDS`) — `registry.py` queda solo con `RuleResult` +
`RuleRegistry`. Se deduplican: `_registrable_label` (idéntica en
`lookalike_domain` y `subdomain_impersonation`), `_strip_html`/`_TAG_RE`
(4 copias), `_host`/`_host_of` (2 copias), chequeo free-provider (3 copias).

**0b · Migrar datos a `SecOpsConfig.json` (`iris.data.*`) + getter.**
Getter genérico en `config_reading.py`: `get_iris_data(key) -> Any | None`.
Datasets a migrar (clave JSON ← origen actual):

| Clave `iris.data.*` | Origen |
|---|---|
| `canonical_brands` | `misspelled_brands.CANONICAL_BRANDS` |
| `homoglyph_map` | `misspelled_brands.HOMOGLYPH_MAP` (como dict char→char) |
| `brand_trusted_domains` | `display_name_spoof.BRAND_TRUSTED_DOMAINS` (como lista de `{keywords, domains}` — JSON no admite tuplas como claves) |
| `free_provider_domains` | `display_name_spoof.FREE_PROVIDER_DOMAINS` |
| `shortener_domains` | `body_links.SHORTENER_DOMAINS` |
| `dangerous_extensions` / `suspicious_mime_types` / `macro_extensions` | `suspicious_attachments` |
| `credential_phrases` | `body_content.CREDENTIAL_PHRASES` |
| `high_signal_keywords` / `low_signal_keywords` / `alarming_emojis` | `alarming_keywords` |
| `suspicious_tlds` | `suspicious_tld.SUSPICIOUS_TLDS` (⚠ `LEGITIMATE_COMMON_TLDS` es código muerto: eliminar) |
| `generic_greetings` / `action_verbs` | `generic_greeting` |
| `bec_phrases` | `bare_url_bec_pattern` (EN+ES unificadas) |
| `subdomain_action_words` | `subdomain_impersonation._ACTION_WORDS` |
| `multi_level_tlds` | `registry._MULTI_LEVEL_TLDS` |
| `esp_tracker_domains` | `body_external_image_tracking.KNOWN_ESP_TRACKER_DOMAINS` |
| `esp_msgid_domains` | `msgid_domain._ESP_MSGID_DOMAINS` |
| `redirect_params` | `compromised_legitimate_domain._REDIRECT_PARAMS` |
| `undisclosed_patterns` | `undisclosed_recipients.UNDISCLOSED_PATTERNS` |

Se quedan en código: regex compilados, prefijos RFC1918, `ZIP_EXTENSIONS`/
`ZIP_MIME_TYPES` (estructurales), umbrales y pesos de score (→ S6).

**Verificación:** suite pytest de iris (unit + integration) vía WSL sin cambios
de comportamiento.

**0c · Reagrupar en ficheros por categoría (2026-07-03).** Los 38 ficheros
de una regla cada uno (más `registry.py`/`shared.py`) se consolidaron en los
10 ficheros temáticos de la regla transversal 3. De paso, revisión de
correctitud fichero a fichero: se eliminó una variable muerta
(`display_words` en lo que era `display_name_spoof.py`), un `_SRC_RE` sin
usar (`body_external_image_tracking.py`), tres regex idénticas
consolidadas en una (`in_reply_to_self_reference.py`), un helper
`_extract_display_name` duplicado de `shared.extract_display_name` con un
bug de cobertura menor (`alarming_keywords.py` no manejaba el caso de
display-name sin `@`), y una lista de TLDs sospechosos hardcodeada e
inline en `url_in_subject.py` que había quedado desincronizada del
dataset canónico `suspicious_tlds` (24 vs 37 entradas) — ahora se
construye dinámicamente desde `iris.data.suspicious_tlds`. Se añadieron
tests unitarios para DKIM y DMARC, que no tenían cobertura directa.

---

## Tramo 1 — Sweet spot (valor alto × esfuerzo bajo)

### `[x]` S1 · Exponer las razones de los gates — **S/Q**
`_evaluate_gates` ya devuelve `(verdict, triggered)`; `_apply_verdict_gates` la
loguea y descarta. **Hecho:** `_apply_verdict_gates` devuelve la tupla; columna
JSONB `gate_reasons` en `IrisAnalysis` (migración `d4e5f6a7b8c9` — ⚠ requiere
`alembic upgrade head` con la BD levantada); `gateReasons` en
`get_analysis_results` + `schemas.py`; sección "Por qué este veredicto" en
`IrisReportViewer.vue` y en el PDF (`append_gate_reasons`). Follow-up posible:
traducir los strings de razones (hoy en inglés técnico) al castellano.

### `[x]` S2 · Top señales contribuyentes — **A/Q**
Los scores por regla ya se persisten. **Hecho:** `IrisManager._top_signals`
deriva las 5 reglas con score más negativo (nombre, categoría, score, índice)
en `get_analysis_results`; expuesto como `topSignals` en `schemas.py`. Sin
cambios de BD. Frontend: bloque "Principales señales" (chips clicables) arriba
del listado de reglas en `IrisReportViewer.vue` — al pulsar un chip expande y
hace scroll a la card de esa regla.

### `[x]` D2 · Heurísticas de URL profundas — **A/Q**
**Hecho.** `services/rules/body_links_rules.py` extendido con 5 nuevos tipos de finding:
- `userinfo_credential_lure`: `@` en el netloc (`http://paypal.com@evil.io`).
- `data_uri_link`: href con esquema `data:`.
- `excessive_subdomains`: host con más de 4 labels.
- `dense_encoding`: ≥4 triples `%XX` que superan el 30% de la longitud de la URL.
- `credential_harvest_path` / `insecure_credential_page`: keywords de
  `iris.data.url_phishing_keywords` en path/query de un host que **no** es el
  dominio del remitente ni el dominio de una marca canónica (usa
  `registrable_label` para comparar, no el dominio completo — evita falsos
  positivos en `paypal.com/signin` o `acme.com/login` del propio remitente);
  variante `insecure_credential_page` (penalización mayor) cuando además es
  `http` sin cifrar.
Cada tipo tiene su propia penalización y el floor `MAX_SCORE_FLOOR` sigue
limitando el total. 8 tests nuevos en `test_iris_message_parser.py`
(incluyendo dos negativos: marca propia y dominio del remitente no se
penalizan por tener "login" en el path).

### `[x]` O1 · Export de IOCs — **A/Q**
**Hecho**, con un scope algo distinto al esbozo original: en vez de un
servicio `iocs.py` que escarba los `details` heterogéneos ya persistidos
(un dict distinto por regla, frágil ante cambios futuros), `IrisManager.
get_analysis_iocs` re-parsea `raw_headers` con `parse_raw_message` (mismo
patrón que `get_analysis_path`, sin columna nueva en BD) y extrae
dominios/emails de From-Reply-To-Return-Path, hosts+URLs de los links del
cuerpo, e IPs de la cadena Received — consistente aunque cambien las
reglas. Endpoint `GET /iris/results/<id>/iocs`
(`AnalysisIocsResponseSchema`). Export **CSV** generado en el cliente desde
los datos ya cargados (sin round-trip extra). **Diferido:** STIX 2.1 (mucho
más esfuerzo del que justifica un "quick win") y hashes de adjuntos (depende
de D8, no implementado aún).

### `[x]` O2 · Render defanged en la UI — **A/Q**
**Hecho**: helper `defang()` inline en `IrisReportViewer.vue` (`hxxp://`,
`[.]`, `[at]`) aplicado a las 4 categorías del panel de IOCs. Sin toggle
"ver valor real": el texto plano no es clicable en ningún caso, así que
mostrar siempre la forma defanged es el default más seguro y no hacía falta
la complejidad de un composable aparte ni de un toggle.

### `[x]` I2 · Desanidar `.eml` adjunto (message/rfc822) — **S/M**
**Hecho**, con la UX decidida: se analiza el interno automáticamente y se
señala en el informe. `parsers._find_nested_forward` detecta la parte
`message/rfc822` (antes invisible: `Message.is_multipart()` es `True`
también para estas partes, así que el bucle existente las saltaba en
silencio junto con los multipart reales) y `parse_raw_message` devuelve
el `MessageContext` del mensaje **interno**, con
`unwrapped_from_forward=True` y `wrapper_from`/`wrapper_subject` del
envoltorio. Bug encontrado y corregido en el camino: leer el envoltorio
con `parse_raw_headers(raw)` (el parser de líneas de todo el texto, sin
noción de límites MIME) devolvía el From/Subject del mensaje **interno**
en vez del externo, porque sigue "leyendo cabeceras" más allá de la
primera línea en blanco; se lee del objeto `Message` ya parseado
(`msg.get("from")`) en su lugar. `managers._run_analysis` ahora deriva
`headers` de `context.headers` (antes eran dos parseos independientes del
mismo `raw_input`, una inconsistencia latente que este caso exponía).
Banner "Correo reenviado como adjunto detectado" en `IrisReportViewer.vue`.

### `[x]` D8 · Hashes de adjuntos como IOC — **B/Q**
**Hecho**, con más alcance del sugerido: además de SHA256+MD5 en
`details.findings[*]` de `suspicious_attachments` (solo adjuntos ya
marcados sospechosos), `IrisManager.get_analysis_iocs` (O1) calcula SHA256
de **todos** los adjuntos con contenido, sin importar si alguna regla los
marcó — un analista pivotando a VirusTotal quiere el hash exista o no un
hallazgo. Nueva categoría `hashes` en el endpoint de IOCs, el schema y el
panel del frontend.

### `[x]` D4 · RLO/bidi + confusables Unicode — **B/Q**
**Hecho**: nueva regla `services/rules/body_content_rules.py`. Detecta
controles bidi (`U+202E` RLO y 10 más) en Subject/From/nombres de adjunto
— spoofing de extensión (`invoice[RLO]fdp.exe`) — y mezcla de scripts
confusables (cirílico/griego + latino) en display name/subject/dominio.
Los codepoints se construyen con `chr(0x202E)` etc. en vez de glifos
literales en el fuente (embeber el propio carácter RLO en código es
exactamente el patrón "Trojan Source" / CVE-2021-42574 que la regla
existe para detectar — los tests hacen lo mismo por la misma razón). Solo
flagea mezcla de scripts, nunca texto 100% no-latino (evita penalizar
correo multilingüe legítimo).

### `[x]` D5 · Abuso de encoded-words (RFC 2047) — **B/Q**
**Hecho**: nueva regla `services/rules/body_content_rules.py`. Detecta
bloques `=?charset?...?=` atomizados (muchos bloques cortos encadenados,
heurística: ≥4 bloques con longitud media decodificada <8 — evita
falsos positivos en subjects internacionales largos y legítimos que
generan pocos bloques largos), charset `utf-7`/variantes (nuevo dataset
`iris.data.exotic_charsets`, deliberadamente sin incluir charsets
regionales legítimos como shift-jis/iso-2022-jp), charsets mezclados en
la misma cabecera, y URLs que solo aparecen tras decodificar (invisibles
en la cabecera cruda). Reutiliza `services/parsers.decode_mime_words`.

### `[x]` D7 · Cadena ARC — **B/Q**
**Hecho**: nueva regla `check_arc_chain` en `services/rules/auth_rules.py`.
Lee `cv=` de `ARC-Seal`/`ARC-Authentication-Results` (validez *declarada*,
sin re-verificar firmas ARC — misma limitación aceptada que SPF/DKIM/DMARC).
`cv=pass` (+2) suaviza `spf_fail`/`dmarc_fail`/`align_fail` en
`_extract_verdict_signals` (un reenvío legítimo por lista de correo/
forwarder rompe SPF/alineación como efecto secundario esperado);
`cv=fail` (-8) es su propio gate a Suspicious; `cv=none` (primer salto,
nada que decir) y ausencia total de ARC son neutrales, no penalizan.

### `[x]` O5 · Botón re-analizar — **C/Q**
**Hecho**, sin `reanalyzed_from_id` persistido (marcado opcional en la
idea original; se descartó la columna nueva para mantener esto como
quick win — el título del nuevo análisis, `"<título> (reanálisis)"`, es
la única traza de la relación). Endpoint `POST /iris/results/<id>/
reanalyze` re-lanza `manager.analyze` con el `raw_headers` almacenado
(que ya contiene el `.eml` completo cuando lo hubo, no solo cabeceras).
Botón "↻" en `IrisReportViewer.vue`, visible solo si el análisis está
`finished`.

---

## Tramo 2 — Alto impacto, esfuerzo medio

### `[x]` D1 · Quishing (códigos QR) — **S/M**
**Hecho.** Dependencia elegida: `opencv-python-headless` (~80MB con numpy,
pero wheel autocontenido sin librería nativa de sistema — decisión
consultada con el usuario frente a `pyzbar`+`libzbar0`, que habría sido
más ligera pero frágil entre entornos). `check_qr_code_links` en
`services/rules/body_links_rules.py` (`needs_context=True`): decodifica
cualquier QR en `context.attachments` cuyo `content_type` empiece por
`image/` (cubre inline y adjuntos reales — ambos ya caían en
`attachments` porque el parser exige solo un `filename`, no
`Content-Disposition: attachment`) vía `cv2.QRCodeDetector().
detectAndDecodeMulti()`, filtra a payloads que parezcan URL (un QR puede
codificar vCards/WiFi/texto plano, irrelevante aquí), y pasa cada URL por
`shared.analyze_url()` — la lógica de heurísticas por URL de Body Links
extraída a una función reutilizable como pedía la idea original (misma
batería de chequeos: cloaking solo aplica cuando hay `visible_text`, que
un QR no tiene). Gate nuevo en `managers.py`: `QR Code Links` en `fail` →
Phishing directo. Tests generan QRs reales con la librería `qrcode`
(solo dev/test, en `requirements-dev.txt`; producción solo *decodifica*,
nunca genera).

### `[x]` IA1 · IrisAIWriter (narrativa IA) — **S/M**
**Hecho**, siguiendo el patrón de `sentinel/services/analyzers.py`:
`services/ai_writer.py` con `IrisAIWriter(generator: AIGenerator)` —
prompt de sistema (analista anti-phishing calibrado, "explica lo que ya
se detectó, no inventes nada nuevo") + user prompt con veredicto/score/
gate reasons/reglas falladas (nombre, categoría, penalización,
recomendación — solo las que restaron puntos). Salida JSON:
`executive_summary`, `attacker_intent`, `recommendations[]`,
`confidence` (ALTA/MEDIA/BAJA, normalizado si el modelo devuelve algo
fuera de rango). Prompts en `SecOpsConfig.json` bloque `iris.prompts.
summary` (nuevo getter `get_iris_prompts()` en `config_reading.py` —
`get_prompts_config()` existente está hardcodeado al bloque `sentinel`,
no es genérico pese al nombre). Estrategia vía `get_ai_strategy_for
("iris")`, reutilizado sin cambios. Endpoint `POST /iris/results/<id>/
ai-summary` asíncrono (TaskQueue, categoría `iris.ai_summary`) +
columna JSONB `ai_summary` en `IrisAnalysis` (migración `e5f6a7b8c9d0`).

Diferencia deliberada con el patrón de sentinel: allí la narrativa IA se
genera *inline* al construir el PDF y nunca se persiste por separado
(sentinel no tiene visor de informe web, solo PDF). El visor de Iris
(`IrisReportViewer.vue`) es una vista JSON en vivo, así que la narrativa
se genera bajo demanda vía su propio endpoint y se persiste en la columna
para sobrevivir independientemente de cualquier exportación a PDF. Sin
endpoint de estado propio: el frontend simplemente sondea `GET /iris/
results/<id>` cada 3s hasta que aparece `aiSummary` (mismo enfoque que
gate reasons/top signals: un campo más del informe principal). Degradación
limpia: `execute_ai_summary_generation` captura cualquier fallo del backend
de IA (backend no configurado, circuit breaker abierto, respuesta
malformada) y deja `ai_summary` en `NULL` sin tumbar el análisis ya
finalizado al que está adjunto.

### `[ ]` D6 · Provenance de Authentication-Results — **S/M**
Endurece la autenticación **sin criptografía** (el límite de DKIM cripto es
aceptado). **Idea:** nueva regla `services/rules/auth_rules.py` (nueva funcion `check_auth_results_provenance`) +
helper en `shared.py` que parsea el/los `Authentication-Results`: (1) si hay
**múltiples** A-R con `authserv-id` distintos y resultados contradictorios →
posible inyección; (2) si el `authserv-id` no es coherente con el último hop
del Received (`by ...`) → A-R forjado; (3) lista opcional
`iris.data.trusted_authserv_ids` del tenant. Señal fuerte para
`_extract_verdict_signals` (un A-R forjado invalida el "pass" de SPF/DKIM/DMARC).

### `[ ]` D3 · Inspección profunda de adjuntos — **A/M**
Extender `suspicious_attachments` con inspectores por tipo (en
`services/attachment_inspectors.py` para no engordar la regla):
- **PDF**: URLs embebidas, `/JavaScript`, `/Launch`, `/OpenAction` (regex sobre
  el stream; sin dependencia pesada).
- **Office OOXML**: es ZIP → buscar `vbaProject.bin` (macro real, no solo
  extensión), `externalLinks`, plantilla remota en `settings.xml.rels`
  (template injection), DDE en document.xml.
- **HTML adjunto**: formularios con `action` externo, JS ofuscado
  (`unescape`/`atob`/blobs base64 largos) → smuggling.

### `[ ]` S4 · Allowlist de remitentes de confianza — **A/M**
Nuevo modelo `IrisTrustedSender` (user_id, dominio/dirección, creado_en) +
CRUD endpoints + chequeo en `_run_analysis`: si el From (con auth alineada
`pass`) está en la allowlist del usuario, marcar el informe
(`trusted_sender: true`) y suavizar el veredicto base (no los gates de
adjuntos/links — la confianza no debe tapar un adjunto ejecutable). UI: botón
"marcar como remitente de confianza" en el informe.

### `[ ]` S5 · Feedback del analista — **A/M**
Columna `user_verdict` (`legitimate|malicious|null`) + `user_verdict_note` en
`IrisAnalysis` + endpoint `POST /iris/results/<id>/feedback`. UI: dos botones
en el informe. Valor: corpus etiquetado para calibrar reglas (y futuro S6/ML).

### `[ ]` I1 · Soporte `.msg` (Outlook) — **A/M**
Dependencia `extract-msg`. **Idea:** en el backend, `services/msg_converter.py`
convierte `.msg` → texto RFC822 equivalente y lo alimenta al pipeline actual.
Frontend: aceptar `.msg` en drag&drop (`IrisView.vue`) subiéndolo como
multipart (nuevo endpoint o campo base64), ya que el parseo binario no puede
hacerse en el navegador con `parseEml`.

### `[ ]` IA2 · Clasificación de intención por LLM — **B/M**
Regla opcional `services/rules/body_content_rules.py` (nueva funcion `check_ai_intent`) (activable por config `iris.ai_intent_enabled`):
clasifica el cuerpo en `credential_harvest|payment_fraud|delivery_scam|...` con
`scribe.AIGenerator`. Solo aporta señal (score bajo) — nunca gate por sí sola.
Cachear por hash del cuerpo. Apagada por defecto para no meter latencia/coste.

### `[ ]` D9 · Confusables Unicode completos en dominio — **B/M**
Sustituir el mapa de homóglifos ASCII por la tabla de confusables de Unicode
(lib `confusable_homoglyphs` o tabla embebida). Aplica a `lookalike_domain` y
`misspelled_brands` vía `shared.normalize_homoglyphs`.

### `[ ]` O3 · Anclar evidencia a cabeceras — **B/M**
Convención: cada regla añade `details.evidence_headers: ["from", "reply-to"]`.
El frontend resalta esas líneas en el raw al hacer hover/click sobre el
hallazgo. Cambio incremental por regla (empezar por las 10 de mayor peso).

### `[ ]` O4 · Clustering de campañas — **B/M**
Consulta en `repositories.py`: agrupar análisis del usuario por
`from_domain`/asunto normalizado/hosts de links compartidos (nueva tabla ligera
`IrisIndicator(analysis_id, type, value)` poblada al finalizar el análisis —
también sirve a O1). Vista "campañas" en el historial.

### `[ ]` I3 · Análisis por lotes — **B/M**
Endpoint `POST /iris/analyze/batch` (múltiples `.eml` o un `.zip`): crea N
análisis y devuelve los IDs; el TaskQueue ya absorbe la concurrencia. UI: drop
de varios ficheros → tabla de triaje con veredictos.

### `[ ]` S3 · Mapeo MITRE ATT&CK — **B/M**
Metadato estático por regla: `mitre: ["T1566.002"]` en el decorador
`@iris_rules.register`. Se propaga a `details`/informe/PDF. Tabla de mapeo en
`iris.data.mitre_map` si se prefiere configurable.

### `[ ]` E4 · Chequeo ligero con web_search de scribe — **B/M**
Puente intermedio antes del enriquecimiento completo: acción bajo demanda
(botón "investigar dominio") que usa la tool `web_search` de scribe para
buscar el dominio del remitente y resume si aparenta legítimo. No es una regla
(no corre en cada análisis): endpoint separado.

### `[ ]` S6 · Pesos y umbrales configurables — **C/M**
Extensión natural de Fase 0: mover pesos de reglas y floors
(`MAX_SCORE_FLOOR`, `_REASON_SCORES`, umbrales de `alarming_keywords`, etc.) a
`iris.scoring.*`. Requiere suite de regresión (S5 ayuda) antes de permitir
tuning libre.

### `[ ]` O6 · Export JSON del informe + filtros — **C/M**
`GET /iris/results/<id>?format=json` ya existe de facto (la API es JSON);
añadir export descargable con esquema estable + filtros por veredicto en
`/iris/results` (`?verdict=Phishing`).

---

## Tramo 3 — Decisión de producto (rompen la premisa offline / integraciones)

### `[ ]` E1 · Edad de dominio (WHOIS/RDAP) — **A/L**
Primer paso de enriquecimiento de red. `services/enrichment/rdap.py` con caché
en BD (tabla `IrisDomainCache`) y TTL; regla `domain_age` (dominio <30 días =
señal fuerte). Requiere decidir egress, timeouts y modo degradado (neutral sin
red). Config `iris.enrichment.enabled`.

### `[ ]` E2 · Reputación de URL/dominio (VT/urlscan/PhishTank) — **C/L**
Cliente(s) con API key en `.env`, caché agresiva, cuota. Solo tras E1 (misma
infra de enriquecimiento).

### `[ ]` E3 · Reputación/geo/ASN de IP de origen — **C/L**
Sobre la IP del primer hop del Received (ya parseada). GeoIP local (MaxMind)
evita egress; ASN/reputación requiere feed externo.

### `[ ]` I4 · Integración de buzón (IMAP/Graph/Gmail) — **C/L**
Módulo de ingesta que monitoriza una carpeta "sospechosos" y crea análisis
automáticamente. Credenciales OAuth por tenant. **Diseño aparte:**
`plans/feature/iris/iris-mailbox-connector.md`, que además incluye como fase
previa y bloqueante una auditoría completa del motor (destaca un bypass
verificado de las 5 reglas de autenticación por `Authentication-Results`
duplicada, y desbloquea D6 de paso).

### `[ ]` I5 · Extensión de navegador / plugin — **C/L**
Proyecto cliente separado que reenvía a la API. Fuera del repo actual.

### `[ ]` O7 · Webhooks + dashboard de métricas — **C/L**
Webhook configurable (`iris.webhooks[]`) al finalizar con veredicto Phishing;
dashboard con distribución de veredictos, marcas más suplantadas, tendencia.

### `[ ]` IA3 · Traducción + explicación multilingüe — **C/L**
Extensión de IA1 cuando el idioma del cuerpo ≠ idioma del usuario.

---

## Matriz de referencia

| | Q | M | L |
|---|---|---|---|
| **S** | S1 | D1, IA1, D6, I2 | — |
| **A** | S2, D2, O1, O2 | D3, S4, S5, I1 | E1 |
| **B** | D4, D5, D8, D7 | IA2, O3, O4, I3, S3, E4, D9 | — |
| **C** | O5 | S6, O6 | E2, E3, I4, I5, O7, IA3 |

## Verificación estándar (toda mejora)

1. Tests unit/integration de iris vía WSL:
   `wsl -e bash -lc "cd /mnt/c/Users/gmiga/Documents/GitHub/SecOps/API && ../.venv/bin/python -m pytest tests/unit/test_iris*.py tests/integration/test_iris*.py -q"`
2. Un `.eml` real por `POST /iris/analyze` → informe con el nuevo
   comportamiento visible.
3. Si toca frontend: preview + captura del informe.
