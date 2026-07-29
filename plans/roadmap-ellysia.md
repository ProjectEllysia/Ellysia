# Ellysia — Plan de producto y roadmap

> Documento de gobierno del proyecto. Ordena al resto de planes (`lybra-engine-roadmap.md`,
> `feature/hygeia/*`, `improvements/*`) y decide qué se construye, qué se congela y qué no se
> construye. Sustituye por completo al antiguo plan de viabilidad SaaS, cuyas dos premisas
> centrales dejaron de ser ciertas: decía que Themis era "un envoltorio de Nmap/Nikto/OpenVAS"
> (hoy Lybra es un motor propio con cinco fases implementadas) y que Hygeia no debía
> construirse todavía (hoy está terminado de extremo a extremo).

---

## 1. La premisa que gobierna todo lo demás

**El objetivo declarado de Ellysia es construirlo, no venderlo.** Esto no es una concesión ni
un premio de consolación: es la premisa de diseño de este documento, y todo lo que sigue se
deriva de ella. Un plan que finja lo contrario produce decisiones peores, porque optimiza para
un objetivo que nadie va a perseguir.

Tres datos objetivos sostienen esa premisa:

| Dato | Valor |
|---|---|
| Dedicación real | 10–15 h/semana (side-project; trabajo y máster tienen prioridad) |
| Contacto comercial acumulado | Ninguno |
| Preferencia revelada por el historial de commits | Lybra y Hygeia (técnicamente ricos) construidos antes que pagos, registro público o reset de contraseña |

Ese tercer punto es el más informativo. Durante los últimos meses el trabajo se ha ido, sin
excepción, hacia lo técnicamente interesante y no hacia lo comercialmente necesario. No es un
fallo de disciplina: es la señal de qué mueve realmente el proyecto. El plan anterior pedía
integrar Stripe y montar conversaciones con consultoras; no se hizo nada de eso, y sí se
construyó un módulo entero de telemetría con detección de anomalías. Un plan honesto se
escribe a favor de esa corriente, no en contra.

**Consecuencia práctica:** este es un **roadmap técnico** con una **vía comercial mantenida
viva al mínimo coste** (§8). No hay calendario de ventas, ni objetivos de conversión, ni
checklist de "días 0–30". Hay una lista de trabajo interesante ordenada por valor, y un
disparador objetivo por si algún día la vía comercial deja de ser hipotética.

---

## 2. Estado real del sistema

Verificado directamente contra el código, no contra planes anteriores.

### 2.1 Volumen

| Componente | Tamaño | Nota |
|---|---|---|
| Themis (con Lybra) | ~16.600 líneas | El módulo más grande; Lybra son ~3.000 de ellas |
| Iris | ~7.700 líneas | 41 reglas de cabeceras, quishing, documentos |
| Aegis | ~5.100 líneas | Píldoras IA, campañas, quiz público |
| Hygeia | ~2.700 líneas | Backend completo Fases 0–5 |
| Acheron | ~1.800 líneas | Vault zero-knowledge (la cripto pesada vive en cliente) |
| SPA Vue | 77 vistas, ~21.000 líneas | Incluye hubs públicos y páginas legales |
| Tests | 60 ficheros, 708 tests | Unit + integration, SQLite con externos mockeados |

### 2.2 Lybra — el motor propio (`lybra-engine-roadmap.md`)

Es, objetivamente, la pieza más valiosa del repositorio y la que justifica que Ellysia exista
como algo más que una integración de herramientas ajenas.

| Fase | Pista | Estado real |
|---|---|---|
| **0** — Cimientos (`Finding`, `ScanType.LYBRA`, CPE persistido) | Correlación | ✓ implementada |
| **0.9** — Contrato de entrada externa de servicios (`Service.origin`, modo `services=`) | Correlación | ✓ implementada — desbloquea la Fase I |
| **1** — Matcher CPE→CVE | Correlación | ✓ implementada |
| **2** — KB local | Correlación | ✓ implementada — refleja NVD, CISA-KEV y FIRST-EPSS |
| **N** — Dissectors y checks de red no-HTTP (SMB, FTP, SMTP/IMAP/POP3, MySQL, Redis, VNC…) | Bajo nivel | ◐ parcial — siete protocolos con dissector, cierra la brecha G1 que dejaba OpenVAS |
| **I** — Inventario de Hygeia como escaneo autenticado | Correlación | ◐ parcial — la tubería funciona de extremo a extremo; falta que el motor sepa resolver software de escritorio a CPE (Fase I-b) |
| **5** — Dedup multi-fuente, ciclo de vida, scoring | Correlación | ✓ implementada |
| **6** — Pipeline orquestado | Convergencia | ✓ implementada |
| **U** — Nuclei: herramienta de primera clase, corroborador y oráculo | Bajo nivel | ○ planificada — **prerrequisito del cierre de la Fase R** (ver §5.2) |
| **R** — Runtime de checks propio | Bajo nivel | ◐ parcial — soporta `http`, `tls` y `network`; falta `script`; el feed es JSON, no el YAML estilo Nuclei del diseño; su cierre depende de la Fase U |
| **F** — Fingerprinting propio | Bajo nivel | ◐ parcial — HTTP, SSH, TLS y siete protocolos de la Fase N; falta JARM |
| **T** — Transporte propio | Bajo nivel | ◐ parcial — connect scan sobre asyncio; faltan SYN sin estado, sondas UDP y control de tasa AIMD |
| **O**, **D**, **4**, DAST, y toda la Etapa 2 (P, E, C, A, B, G, S, X) | Ambas | ○ planificadas |

La pista de correlación está, en su núcleo, **completa** (0.9, 1, 2, 5, 6 hechas; solo I-b queda
abierta). La pista de bajo nivel —la que da carácter propio al escáner— está a medias en sus fases,
y es donde queda el trabajo con más identidad. El detalle completo de las quince fases vive en
`lybra-engine-roadmap.md`; esta tabla es el resumen que gobierna las prioridades del §5.

### 2.3 Hygeia — el módulo de telemetría (`feature/hygeia/hygeia-backend.md`)

Implementado de extremo a extremo: modelos, ingesta autenticada por clave de agente, detección
síncrona con histéresis, ciclo de vida de anomalías, job de presencia, retención, series
temporales, notificación por correo vía `herald`, SPA con dashboard y gráficas, y tests de
ingesta/métricas/scheduling.

| Fase del plan de Hygeia | Estado |
|---|---|
| 0–5 (alta, ingesta, detección, alertas, presencia, retención, series, correo) | ✓ implementadas |
| 6 (baseline estadístico, resumen IA, downsampling) | ○ |
| **H0–H3 (inventario de software → matcher de Lybra)** | ○ — **la pieza que falta y la más valiosa**, ver §5.1 |
| D0 (descarga del agente desde la SPA) | ○ |

### 2.4 Fundaciones transversales

| Pieza | Estado |
|---|---|
| OAuth2 + JWT, Argon2id, roles + ABAC, aislamiento por `user_id` | ✓ |
| MFA TOTP + códigos de recuperación, end-to-end | ✓ |
| TaskQueue persistente (RQ + Redis), categorías, cancelación cooperativa, progreso | ✓ |
| Rate limiter sobre Redis (sobrevive multi-worker y reinicios) | ✓ |
| Hubs públicos de los 5 módulos + páginas legales preliminares | ✓ |
| Migraciones Alembic lineales, aplicadas al arrancar | ✓ |
| Registro público de usuarios | ❌ |
| Recuperación de contraseña | ❌ |
| Cuotas por usuario | ❌ salvo `maxAssetsPerUser` en Hygeia |
| Pagos y página de precios | ❌ |
| Backups automatizados y monitorización de disponibilidad | ❌ |
| Lockfile de dependencias | ❌ `requirements.txt` sin fijar versiones |
| `themis.areLocalIpsAllowed` | ⚠ en `true` — cómodo en local, **desactiva la defensa anti-SSRF**; revertir antes de exponer nada a Internet |

---

## 3. Diagnóstico honesto

**Lo que Ellysia es de verdad hoy:** una plataforma de seguridad con un motor de detección de
vulnerabilidades propio y funcional, un módulo de telemetría de activos completo, y tres
módulos satélite de madurez desigual. La ingeniería es sólida —capas respetadas, 708 tests,
frontera transaccional explícita, cripto de cliente verificada por vectores compartidos— y el
volumen de trabajo acumulado es sustancial.

**Lo que Ellysia no es:** un producto. No porque le falte código, sino porque le faltan las
cosas aburridas que convierten código en producto (alta de usuarios, cobro, respaldo de datos)
y, sobre todo, porque no ha sido expuesto nunca a un usuario que no seas tú. Cero contacto
comercial no significa "todavía no he empezado a vender"; significa que ninguna de las hipótesis
de producto ha sido contrastada con la realidad.

**Dónde está el autoengaño a evitar.** El riesgo específico de este proyecto no es abandonarlo:
es seguir añadiendo módulos nuevos indefinidamente porque empezar algo es más divertido que
terminarlo. Ya hay cinco módulos, tres de ellos con fases sin cerrar, más nueve planes de
diseño escritos sin implementar (webhooks, WebAuthn, vault de claves de agente, botón de
reinicio, Tailwind, escalado de BD, factory de decoradores…). **Escribir un plan nuevo se ha
convertido en un sustituto barato de terminar uno viejo.** Con 10–15 h/semana, la restricción
real no es la capacidad técnica: es el número de frentes abiertos simultáneamente.

Por eso este documento cierra frentes en vez de abrirlos, y por eso su regla principal es la
del §7.

---

## 4. La decisión de producto: el activo como unidad

Si algún día Ellysia se ofrece a alguien, el núcleo es **Hygeia + Themis/Lybra**, y la unidad
de valor es **el activo**: una máquina de la que Ellysia conoce a la vez su salud (telemetría
continua) y su exposición (vulnerabilidades, desde la red y desde el inventario).

Por qué esta combinación y no otra:

- **Hygeia aporta uso diario.** Un agente empujando cada 15 segundos es un producto vivo; un
  escáner que se lanza una vez al mes no lo es. En cualquier producto de suscripción, la
  frecuencia de uso es lo que sostiene la renovación.
- **Lybra aporta el diferenciador.** Es lo único de todo el repositorio que no se puede
  replicar instalando una herramienta libre. La telemetría de host, sola, compite con Zabbix,
  Netdata y UptimeRobot en una categoría saturada donde Ellysia no tiene ninguna ventaja.
- **Juntos se refuerzan de forma concreta, no retórica.** El agente que ya está instalado para
  medir CPU puede leer el inventario de paquetes y alimentar el matcher CPE→CVE que ya existe.
  Eso da cobertura de CVE sin fingerprinting remoto, sin SSH y sin credenciales nuevas —
  incluso en hosts tras NAT que Themis nunca podría escanear. Es la integración H0–H3 del plan
  de Hygeia, y es la razón técnica de que la respuesta a "¿cuál es el producto?" sea "los dos".

Un cliente hipotético paga por activo cubierto, en **tramos** (por ejemplo hasta 5 / hasta 20 /
hasta 50), no por unidad suelta: escala con el valor entregado sin la fricción psicológica de
un contador que sube. Esto queda anotado como hipótesis; no se fija hasta que exista una
conversación real que lo contraste.

---

## 5. Roadmap técnico

Ordenado por valor, no por facilidad. Las estimaciones asumen 10–15 h/semana y son
deliberadamente conservadoras: a este ritmo, un mes son ~50 horas efectivas.

### 5.1 Prioridad 1 — La integración inventario → Lybra (Hygeia H0–H2)

**Qué es:** el agente recolecta los paquetes instalados (`dpkg -l` / `rpm -qa` / `winget list`)
y los empuja a un endpoint nuevo con cadencia baja; el backend resuelve el `Host` de Themis
correspondiente, traduce el inventario a la forma `Service` que Lybra ya consume, y dispara el
motor. Los hallazgos caen en el mismo árbol Host→Service→Finding, heredando gratis la
deduplicación multi-fuente, el ciclo de vida y el scoring de la Fase 5.

**Por qué primero:** es lo único del roadmap entero que convierte dos módulos en un producto.
Sin esto, Hygeia y Themis son dos herramientas que comparten login. Además es barato en
proporción a lo que entrega —el motor de detección ya existe y no se toca— y resuelve de
antemano el problema de los backports que la Fase 4 de Lybra pretendía atacar por SSH.

**Alcance:** endpoint `POST /hygeia/inventory` con la misma auth de agente y las mismas guardas
de payload que la ingesta · columna `MonitoredAsset.host_id` con resolución/creación del `Host`
· adaptador inventario→servicios (simétrico a los de Nikto/OpenVAS que ya existen, pero con
puerto opcional) · disparo de `LybraEngineManager` vía TaskQueue · envío diferencial por hash
del listado. Requiere trabajo en el repo del agente además de en este.

**Estimación:** 4–6 semanas.

### 5.2 Prioridad 2 — Nuclei: herramienta, corroborador y oráculo (Fase U de Lybra)

**Qué es:** incorporar Nuclei a Ellysia en cuatro papeles que comparten la misma pieza de trabajo
—el traductor de su salida a `Finding`—: (U1) un `ScanType.NUCLEI` de primera clase, lanzable solo
desde el panel de Themis con su propio PDF, exactamente como hoy se lanzan Nmap o Nikto; (U2) un
corroborador más del análisis profundo de Lybra; (U3) un oráculo diferencial para el banco de
pruebas, que mide falsos positivos sobre objetivos sin etiqueta previa; y (U4) una medición —no
todavía la implementación— de qué fracción del feed comunitario de plantillas es ingerible por el
runtime de checks propio.

**Por qué antes que cerrar la Fase R:** Nuclei pasa el mismo examen de naturaleza que ya distingue
a Nmap y Nikto de OpenVAS (§6) — es un binario con un feed de datos, no una plataforma ajena — así
que encaja sin contradecir la premisa de Lybra. Y resulta que **es el prerrequisito real de la
Prioridad 3**: la migración del feed propio al esquema YAML de Nuclei, la ingesta de sus
plantillas y el umbral de precisión ≥0,9 que cierra la Fase R dependen de un dato que hoy no existe
—qué fracción del lenguaje de Nuclei soporta el runtime propio— y de una vara de medir para el
propio umbral. Hacerlo antes evita migrar el feed dos veces y evita declarar una precisión que
nadie ha medido. Como beneficio de producto añadido, sustituye a Nikto como corroborador con datos
mucho mejores (CVE + CVSS frente al OSVDB de Nikto, muerto desde 2016) y entrega, de paso, una
herramienta más para el panel de Themis sin construir ningún módulo nuevo — sigue siendo Themis,
no una sexta pieza, así que no choca con la regla del §9.

**Estimación:** 2–3 semanas (U1–U3; U4 es un script de medición de horas, no semanas).

### 5.3 Prioridad 3 — Cerrar la Fase R de Lybra

**Qué falta:** el tipo de check `script` (plugins Python para lógica multipaso) y la migración del
feed de JSON al esquema declarativo YAML compatible con plantillas de Nuclei — el tipo `network`
ya está construido, aportado por la Fase N. Depende de la Prioridad 2: el esquema YAML al que se
migra es el de Nuclei, la ingesta de plantillas es literalmente el resultado de U4, y el umbral de
precisión ≥0,9 se mide contra el oráculo diferencial de U3.

**Por qué:** la Fase R es, según el propio roadmap del motor, la capa de identidad — es lo que
independiza a Lybra de Nikto. Está a medias, y una fase a medias es la peor posición posible: ya
pagas su complejidad sin cobrar su beneficio. El paso a YAML tiene además un efecto multiplicador
que ninguna otra tarea del roadmap tiene: convierte "escribir una detección nueva" en editar un
fichero de datos en vez de tocar código.

**Estimación:** 3–5 semanas.

### 5.4 Prioridad 4 — Ampliar la KB con OSV/GHSA

La KB refleja NVD, KEV y EPSS. Falta OSV/GHSA, que es donde vive la vulnerabilidad de
dependencias de aplicación (npm, PyPI, Go…). Con la integración de inventario de §5.1 ya en
marcha, esta fuente pasa de "nice-to-have" a directamente aprovechable: el inventario de un
host incluye paquetes que NVD cubre mal y OSV cubre bien.

**Estimación:** 2–3 semanas.

### 5.5 Prioridad 5 — Fases F y T de Lybra

Completar el fingerprinting (JARM) y el transporte (SYN sin estado, sondas UDP, control AIMD).
Es el trabajo técnicamente más entretenido de todo el roadmap y el que más independiza de Nmap,
pero entrega menos valor de producto por hora que las cuatro anteriores: hoy Nmap ya cubre esa
función correctamente. **Es trabajo de identidad y de disfrute, no de necesidad** — lo cual,
dada la premisa del §1, es un motivo legítimo para hacerlo, siempre que sea una decisión
consciente y no un desvío de las prioridades 1–4.

**Estimación:** 6–10 semanas para ambas.

### 5.6 Oportunista — Fase G (hallazgo → píldora de Aegis)

Generar automáticamente una píldora de concienciación y un plan de remediación con el comando
exacto a partir de un `Finding`. Conecta Themis con Aegis usando `scribe`, que ya está
cableado. Cierra el bucle detección→acción, que es el argumento de venta más natural que tiene
la plataforma. No es urgente, pero es la mejor relación valor/esfuerzo de la Etapa 2.

**Estimación:** 2–3 semanas.

---

## 6. OpenVAS: se elimina

**Decisión (actualizada el 2026-07-28; sustituye a la decisión anterior de "congelado, no se
borra"): se elimina del código, no solo del producto.** El plan de desmontaje y de sustitución
de su cobertura vive en `lybra-engine-roadmap.md` (§§1, 7 y 8); aquí queda el razonamiento de
gobierno, resumido.

El motivo de fondo no cambia respecto a la decisión anterior. OpenVAS/Greenbone es una
plataforma completa con su propio protocolo de gestión, su propio ciclo de escaneo y su propia
base de NVTs; integrarla es hacer de proxy autenticado hacia otra API, no añadir capacidad
propia. Frente a Nmap y Nikto —binarios cuya salida Ellysia parsea para construir su propio
modelo— OpenVAS no deja margen para aportar nada encima. Contradice la razón de ser de Lybra, y
sigue siendo con diferencia el servicio más pesado del `docker-compose` (feed de NVTs con ~15
minutos de arranque en frío, un solo host por escaneo, `NET_ADMIN` + `NET_RAW`, 1 GiB de
memoria compartida).

**Qué cambió respecto a "congelar":** dos hallazgos, al revisar el plan del motor con la
pregunta "¿qué nos haría falta para prescindir de OpenVAS?", abarataron el borrado por debajo
del umbral que justificaba dejarlo estático:

1. El banco de pruebas de Lybra (`API/tests/oracle/`) nunca usó a OpenVAS como oráculo de
   detección, pese a que un plan anterior lo daba por hecho — verificado contra el código, no
   contra el plan. Borrarlo no deja a Lybra sin instrumento de medición; el sustituto (verdad
   por etiqueta conocida en imágenes vulnerables + Nuclei como oráculo diferencial, el papel U3
   de la Prioridad 2 del §5.2) no depende de OpenVAS en absoluto.
2. La brecha de cobertura real que deja no son "cien mil NVTs", sino cinco cosas concretas y
   acotadas (protocolos no-HTTP, escaneo autenticado, verdad del proveedor sobre backports,
   credenciales por defecto, y una cola larga de appliances de nicho que se descarta a
   propósito). Cuatro de las cinco ya eran fases de este roadmap; la Fase N
   (`lybra-engine-roadmap.md`) pasa a liderar precisamente para cerrar la única que de verdad
   importa antes de que el borrado duela.

Como el proyecto no tiene usuarios ni contacto comercial (§1), nadie pierde cobertura real al
borrarlo ya: el coste de mantenerlo conectado (arranque lento, un corroborador de hasta 4 h
disparándose en cada análisis profundo del motor propio) es presente y cierto; la pérdida de
cobertura es hipotética y, en la práctica, ya cubierta por las fases en marcha. Por eso el
desmontaje empieza por desconectarlo de inmediato (paso E0 de `lybra-engine-roadmap.md`) en
lugar de esperar a que las fases de sustitución terminen.

**Qué no cambia respecto a la decisión anterior:** si algún día hay un cliente real que lo pida
expresamente, la única forma sensata seguiría siendo una instancia dedicada suya, facturada
aparte — eso ya no es una opción de este roadmap una vez borrado el código, sino una
reintegración desde cero si llegara a hacer falta.

---

## 7. Los otros módulos

La regla que gobierna esta sección: **ningún módulo satélite recibe trabajo nuevo hasta que
las prioridades 1–4 del §5 estén cerradas.** Siguen todos visibles y funcionando en la
plataforma; lo que se congela es la inversión de tiempo, no la funcionalidad.

- **Aegis — add-on comercial separado.** Es el único módulo con un comprador potencialmente
  distinto (responsable de cumplimiento, no de sistemas) y un mensaje propio: concienciación
  obligatoria de ENS/GDPR sin contratar a nadie. Se mantiene como está, y si alguna vez hay
  vía comercial, se ofrece aparte del núcleo por activos. No es el wedge: eso fue una decisión
  del plan anterior tomada cuando Themis no tenía motor propio, y ya no aplica.
- **Acheron — infraestructura interna.** Deja de posicionarse como gestor de contraseñas: esa
  categoría ya está ganada por Bitwarden y 1Password, y Acheron no compite. Su papel es ser el
  vault que alimenta el escaneo autenticado de Lybra y, opcionalmente, custodiar las claves de
  agente de Hygeia (plan `feature/acheron-hygeia-agent-key-vault.md`, sin fecha). Su hub debe
  explicar exactamente eso.
- **Iris — congelado hasta que haya ingesta IMAP.** Sin ingesta automática es una demo: nadie
  pega cabeceras a mano de forma habitual. Si alguna vez se decide invertir, la ingesta IMAP
  es lo primero y lo único que importa; hasta entonces, no ocupa espacio comercial ni tiempo
  de desarrollo. **Corrección (2026-07-22):** la afirmación anterior de que "las 37 reglas
  están bien hechas y no se tocan" no se sostiene — una auditoría completa
  (`plans/feature/iris/iris-mailbox-connector.md`, Fase 1) encontró un **bypass verificado de
  las 5 reglas de autenticación** (SPF/DKIM/DMARC/Domain Alignment/ARC ceden ante una segunda
  `Authentication-Results` inyectada por el propio atacante) y varios falsos positivos de
  calibración con impacto real en el veredicto (p.ej. el disclaimer legal estándar español
  dispara el gate BEC). El registro tiene 41 reglas, no 37. La Fase 1 de ese plan es
  bloqueante antes de construir la ingesta encima.

---

## 8. La vía comercial, mantenida viva al mínimo coste

Esta sección existe para que la opción no se cierre por descuido, no porque haya un plan de
ventas. Dada la premisa del §1, **no hay calendario aquí**.

### 8.1 Lo que objetivamente falta para poder cobrar un solo euro

Sin esto no hay producto vendible, por bueno que sea el motor:

1. **Registro público de usuarios** — hoy no existe ninguna ruta ni vista.
2. **Recuperación de contraseña** — ni endpoint ni correo transaccional. `herald` ya sabe
   enviar; falta el flujo.
3. **Cuotas por usuario** — solo Hygeia tiene una (`maxAssetsPerUser`). Sin cuotas, un solo
   usuario abusivo degrada a todos.
4. **Cobro** — Stripe Checkout, o Lemon Squeezy/Paddle si se prefiere que actúen como merchant
   of record y gestionen el IVA transfronterizo (más sensato para un fundador solo vendiendo a
   España y LatAm). Más el webhook que active los atributos ABAC al confirmar el pago.
5. **Página de precios y registro en la SPA.**
6. **Backups automatizados de Postgres** y monitorización de disponibilidad.
7. **Revertir `themis.areLocalIpsAllowed` a `false`** — no negociable antes de exponer nada.
8. **Export GDPR y baja autoservicio**, más completar las páginas legales (hoy preliminares).

Son entre 4 y 8 semanas de trabajo a este ritmo, y **ninguna de esas tareas es interesante**.
Esa es precisamente la razón objetiva por la que llevan un año sin hacerse, y la razón por la
que este documento no las programa.

### 8.2 El disparador

No se toca nada de §8.1 hasta que ocurra **una señal externa real**: alguien que no seas tú
pide usar Ellysia, o una consultora muestra interés concreto, o aparece un contexto (un
cliente del trabajo, un contacto del máster) donde encaje de forma natural.

Ese disparador es deliberadamente pasivo, y conviene ser explícito sobre lo que eso implica:
**sin actividad comercial, la probabilidad de que la señal llegue sola es baja.** No es un
plan de captación disfrazado; es reconocer que la captación no es el objetivo. Si en algún
momento quisieras invertir esa dinámica, la acción de mayor rendimiento por hora sería enseñar
el producto a tres personas del sector —no vender, solo enseñarlo y escuchar— porque
convertiría cero datos en datos. Queda anotado como opción disponible, no como tarea.

### 8.3 Distribución

Si llega el momento: **SaaS gestionado primero, self-hosted documentado como opción.** El
`docker-compose` ya levanta el stack completo, así que la vía autohospedada está a poca
distancia; y muchas PYMEs con datos sensibles la prefieren. No se invierte en ella hasta que
alguien la pida.

Infraestructura estimada si se desplegara: un VPS único (Hetzner, ~10–35 €/mes) con API,
worker, Postgres y Redis; Caddy como proxy inverso con TLS automático; Brevo para SMTP con
SPF/DKIM/DMARC configurados —sin esto las campañas de Aegis y las alertas de Hygeia van a
spam—; Ollama es opcional porque `scribe` ya usa OpenAI por defecto; OpenVAS no se despliega
(§6). Total por debajo de 50 €/mes.

---

## 9. Qué no construir

- **Un sexto módulo.** Cualquier idea nueva se escribe como plan y se deja quieta hasta que
  las prioridades 1–4 estén cerradas. Esta regla es la más importante del documento.
- **Los nueve planes de diseño sin implementar** (webhooks salientes, WebAuthn, vault de claves
  de agente, botón de reinicio del servidor, migración a Tailwind, escalado de BD, factory de
  decoradores N12…). Todos están correctamente analizados y ninguno es urgente. Que un plan
  esté bien escrito no es una razón para ejecutarlo.
- **Row-Level Security en Postgres, colas con prioridad, correlación cross-host, export
  SARIF/STIX.** Todos resuelven problemas que solo existen con tráfico real.
- **Precio por asiento** — un precio por cuenta o por tramo de activos es más honesto con la
  arquitectura actual (aislamiento por `user_id`, sin concepto de organización).
- **Free tier indefinido.**
- **Refactores sin síntoma.** Con 10–15 h/semana, un refactor que no desbloquea nada es tiempo
  que no va al roadmap.

---

## 10. Riesgos, con su nombre

| Riesgo | Probabilidad | Mitigación |
|---|---|---|
| **Dispersión en módulos nuevos** | Alta — es el patrón histórico del proyecto | La regla del §9; cerrar Fase R antes de abrir nada |
| **Fases a medias acumulándose** | Alta — R, F y T llevan tiempo parciales | Prioridades 2 y 3 existen exactamente por esto — U es lo que hace medible y cerrable a R |
| **Que la Fase U (Nuclei) se lea como el sexto módulo prohibido por el §9** | Baja, pero conviene nombrarla | No lo es: vive dentro de Themis, sigue el mismo patrón de escáner que Nmap/Nikto, y no abre superficie de producto nueva — amplía una ya existente |
| **El proyecto se queda sin usuarios nunca** | Alta, y **aceptada** por la premisa del §1 | Ninguna; no es un fallo si el objetivo es construir |
| **Deuda que muerde si algún día se despliega** | Media | `areLocalIpsAllowed`, lockfile de dependencias y backups son las tres únicas que importan |
| **Pérdida de datos del entorno propio** | Media | `CREATE_DATABASE=True` sigue siendo destructivo; los backups del §8.1 valen también para uso personal |
| **Quemarse por perseguir un objetivo comercial que no se desea** | Media | Este documento; el plan anterior tenía justamente ese defecto |

---

## 11. Punto de decisión

No hay fecha. Hay dos condiciones objetivas, y basta con revisar cuál se cumple cuando se
cumpla:

- **Si se cierran las prioridades 1–4 del §5** — inventario→Lybra, Nuclei (Fase U), Fase R y
  OSV/GHSA — Ellysia pasa a ser un producto técnicamente coherente y completo en su núcleo. Ese
  es el momento natural para reevaluar si la vía comercial merece las 4–8 semanas aburridas del
  §8.1, porque por primera vez habría algo redondo que enseñar.
- **Si aparece la señal externa del §8.2** antes que eso, §8.1 se activa y el roadmap técnico
  cede el paso.

Mientras no ocurra ninguna de las dos, el plan es el §5, en orden, sin prisa. Que el proyecto
no genere ingresos no lo convierte en fallido: genera un motor de detección propio, una
plataforma con cinco módulos integrados y 708 tests que pasan, construidos en el tiempo libre
de una persona. Medir eso con la vara de un SaaS sería aplicar un criterio que nadie ha
elegido.
