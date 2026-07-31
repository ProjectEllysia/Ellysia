# Lybra Engine — Roadmap del motor propio de vulnerabilidades

> **Premisa de esta revisión (2026-07-27):** este documento se reescribe alrededor de una única
> pregunta — **¿qué nos haría falta para prescindir de OpenVAS?** La respuesta corta es que hace
> falta menos de lo que la cifra "cien mil NVTs" sugiere, y que la mayor parte de lo que falta es
> exactamente el trabajo que este plan ya quería hacer. La respuesta larga es el resto del
> documento.
>
> Sustituye por completo a `vulnengineroadmap.md`, que queda eliminado.

Este documento describe el plan para construir un motor de detección de vulnerabilidades propio
dentro del módulo **Themis**. La meta ya no es "que Nmap, Nikto y OpenVAS pasen a corroboradores":
es más concreta y más asimétrica. **Nmap y Nikto se quedan** como corroboradores opcionales, porque
son binarios de línea de comandos cuya salida parseamos para construir nuestro propio modelo.
**OpenVAS se va**, porque no es una herramienta: es una plataforma completa ajena, y no hay forma de
aportar nada encima de ella.

No es un documento de análisis ni una lluvia de ideas: es un plan de ejecución. Cada fase dice qué
hay que construir, en qué orden conviene hacerlo y con qué criterio concreto podemos darla por
terminada. Hay un glosario al final con todos los términos técnicos que aparecen.

---

## 1. La premisa: por qué OpenVAS sale y Nmap y Nikto se quedan

La distinción no es de tamaño ni de calidad, es **de naturaleza**, y conviene enunciarla con
precisión porque es la que gobierna todo el documento.

Nmap y Nikto son **binarios de línea de comandos**. Ellysia los invoca, recoge su salida —XML en un
caso, texto estructurado en el otro—, la parsea y la traduce a su propio modelo de datos. El valor
que aporta Ellysia encima de ellos es real y medible: normaliza, deduplica, correlaciona en el
tiempo, puntúa por contexto y explica. La herramienta es una fuente de señal; el criterio es
nuestro.

OpenVAS/Greenbone es **una suite entera**: tiene su propio protocolo de gestión (GMP), su propio
ciclo de vida de escaneo (crear objetivo, crear tarea, arrancar, esperar, recoger informe), su
propia base de datos, su propio feed versionado y su propia noción de severidad y de QoD.
Integrarla no es parsear una salida: es **hacer de proxy autenticado hacia otro producto**. Todo lo
que Ellysia hace encima —normalizar a `Finding`, deduplicar, correlacionar— OpenVAS ya lo hacía por
dentro, con veinte años de ventaja. No hay margen para aportar nada, y eso contradice frontalmente
la razón de ser de Lybra.

A la incompatibilidad conceptual se le suma un coste operativo que ya está medido en el repositorio:

| Coste | Dato verificado |
|---|---|
| Peso en el `docker-compose` | Es el servicio más pesado: `shm_size: 1gb`, `NET_ADMIN` + `NET_RAW`, dos puertos publicados, volumen propio, healthcheck deshabilitado porque el del Dockerfile no sirve |
| Arranque en frío | ~15 minutos de sincronización del feed de NVTs (`FEED_SYNC: "true"`) |
| Acoplamiento | Tanto `api` como `worker` lo declaran en `depends_on` |
| Granularidad | Un solo host por escaneo, sin rangos CIDR |
| Duración | `themis.openvas.timeout` = 14.400 s (4 h); `maxWaitTimeout` = 28.800 s (8 h) |
| Dependencia Python | `python-gvm` (`requirements.txt:49`) |
| Secretos | Cuatro variables de entorno obligatorias (`OPENVAS_HOST`/`PORT`/`USERNAME`/`PASSWORD`) |

Y hay un dato de multiusuario que cierra la cuestión aunque todo lo demás se ignorase: una única
instancia de Greenbone compartida entre usuarios, con escaneos de cuatro horas y un host por
escaneo, es el problema del vecino ruidoso en su forma más aguda. No hay forma barata de arreglarlo:
la única salida sensata sería una instancia dedicada por usuario, que es precisamente el tipo de
coste que un side-project no puede sostener.

**La decisión, por tanto, se actualiza.** El documento de gobierno (`plans/roadmap-ellysia.md`, §6)
dejó OpenVAS *congelado*: se queda en el código, sale del producto, no recibe más trabajo. Este plan
da el paso siguiente: **se elimina**. El apartado 7 explica el desmontaje, y el apartado 8 explica
cómo se sustituye lo único que OpenVAS aportaba y que ningún otro componente aporta hoy.

---

## 2. Auditoría honesta: qué hace OpenVAS hoy en Ellysia

Antes de decidir qué hay que construir para sustituirlo conviene saber qué está sustituyéndose de
verdad, no qué dice el folleto. Esto está verificado contra el código, no contra planes anteriores.

**Lo que es.** OpenVAS es un `ScanType` más del registro polimórfico, con la misma estructura de
cuatro piezas que Nmap y Nikto: `OpenVASTask` (`services/tasks.py`), `OpenVASResultProcessor` y
`OpenVASPrintingStrategy` (`services/processors.py`), `OpenVASScanManager`
(`managers/thirdparty_scans_managers.py`). Persiste en tres tablas propias —`OpenVASScan`,
`OpenVASVulnerability`, `OpenVASScanResult` (`model.py`)— vía `persist_openvas_results`
(`repositories.py`), y desde la Fase 0 escribe además, de forma aditiva, un `Finding` normalizado
por resultado a través de `openvas_result_to_finding` (`lybra/adapters.py`). Tiene presencia en los
informes PDF (`services/reports.py`), en el CSV (`services/csv_logger.py`), en los analizadores
(`services/analyzers.py`), en el historial (`services/history.py`), en la programación
(`services/scheduling.py`), en los endpoints y schemas, y en seis componentes de la SPA.

**Dónde se invoca sin que el usuario lo pida.** En el análisis profundo de la Fase 6:
`LybraEngineManager._launch_deep_corroborators` lanza Nmap solo en modo autodescubrimiento, Nikto
solo si hay algún servicio HTTP, y **OpenVAS siempre**. Es el único punto del pipeline propio que lo
arranca por su cuenta, y por tanto el primer sitio donde hay que cortar.

**Lo que no es, pese a lo que el plan anterior afirmaba.** El §7 del roadmap viejo declaraba que
"las herramientas externas hacen de oráculo: Nmap es la verdad para el descubrimiento y el
fingerprinting, **OpenVAS lo es para la detección**". Eso nunca se implementó: `API/tests/oracle/`
—que contiene el banco diferencial real, `test_lybra_oracle_bench.py` y
`test_lybra_concordance_bench.py`, corriendo contra contenedores Docker de verdad— **no menciona
OpenVAS ni una sola vez**. El oráculo de detección era una promesa escrita, no una pieza en
funcionamiento.

Ese hallazgo importa mucho más de lo que parece, porque **reduce el coste real de la eliminación a
casi nada**. Si OpenVAS fuera hoy la vara de medir de la precisión de Lybra, quitarlo nos dejaría
ciegos y habría que construir el sustituto *antes*. Como no lo es, lo que se pierde al quitarlo es
exclusivamente capacidad de detección en producción —que es lo que el apartado 3 cuantifica— y no
capacidad de medición.

---

## 3. La brecha real: qué perderíamos de verdad

Aquí está el análisis que justifica todo el plan. La cifra que intimida —"más de cien mil NVTs"— es
engañosa si no se desglosa, porque el feed de OpenVAS no son cien mil comprobaciones activas
distintas.

La gran mayoría de los NVTs son **comprobaciones por versión**: leen un banner o un CPE, lo comparan
contra un rango de versiones afectado y emiten un hallazgo con su CVE y su CVSS. Eso es exactamente
lo que hacen las Fases 1 y 2 de Lybra, que están implementadas: `LybraEngine._version_findings`
resuelve el servicio a un CPE 2.3 y consulta la KB local (NVD + CPE Dictionary + KEV + EPSS) para
emitir un `Finding` por CVE aplicable. En el terreno de la detección por versión, **la cobertura de
Lybra no está limitada por el número de checks, sino por dos cosas distintas: cuántos servicios sabe
identificar y cuán completa está su KB.** Ésa es la reformulación clave del problema, y cambia por
completo dónde hay que invertir.

Desglosado, lo que OpenVAS aporta hoy y Lybra no cubre se reduce a cinco brechas:

| # | Brecha | Qué significa | ¿Se cierra? |
|---|---|---|---|
| **G1** | **Protocolos no-HTTP** | El fingerprint de Lybra habla HTTP, TLS y SSH (`lybra/fingerprinting/`). No habla SMB, RDP, SNMP, FTP, SMTP/IMAP, MySQL/PostgreSQL/MSSQL, LDAP, VNC, Telnet ni RPC. Sin fingerprint no hay CPE; sin CPE no hay detección por versión. **Un puerto 445 abierto hoy produce un hallazgo informativo y nada más.** | **Sí — Fase N.** Es la brecha nº 1 y la que de verdad decide si se puede prescindir |
| **G2** | **Escaneo autenticado (LSC)** | Leer las versiones reales de los paquetes instalados en vez de fiarse del banner. Es lo que resuelve de raíz los falsos positivos por backport | **Sí, y mejor — Fase I.** El agente de Hygeia ya está instalado en el host; el inventario de paquetes cubre esto sin credenciales nuevas y llega incluso a hosts tras NAT |
| **G3** | **Verdad del proveedor sobre backports** | El equivalente de Notus: saber que Debian parcheó sin subir el número de versión visible | **Sí — Fase O.** Feeds OVAL/CSAF de Debian/RHEL/SUSE en la KB, sin tocar el host |
| **G4** | **Credenciales por defecto y checks activos no-web** | Probar `tomcat/tomcat`, FTP anónimo, paneles de administración con credenciales de fábrica | **Sí — Fase D**, con las guardas de seguridad que la fase describe |
| **G5** | **Cola larga de appliances, ICS/SCADA y software empresarial de nicho** | Miles de NVTs para productos que no vamos a ver nunca | **No, y es deliberado.** Es una anti-meta explícita (§4) |

La conclusión operativa es que **cuatro de las cinco brechas se cierran con fases que este plan ya
contemplaba**, y la quinta se rechaza por diseño. Lo que la premisa de esta revisión cambia no es
*qué* hay que construir, sino **el orden y el criterio de prioridad**: a partir de ahora, una fase
vale más cuanto más brecha con OpenVAS cierra. El apartado 6 reordena el roadmap con ese criterio.

Y hay una brecha inversa que conviene nombrar, porque va en la otra dirección: hay cosas que Lybra
ya hace y OpenVAS no hace, o hace mal. El ciclo de vida por activo (`open`/`fixed`/`regressed`), la
deduplicación multi-fuente por `dedup_key`, el scoring contextual que combina CVSS con EPSS, KEV y
exposición de red, y la detección de cambios de superficie (`HostService`: puerto nuevo, versión
cambiada) sin que medie ninguna CVE. Eso no es "un OpenVAS peor": es otra cosa.

---

## 4. La apuesta: en qué compite Lybra (y en qué no)

Conviene ser honestos sobre una cosa: **Lybra no puede competir en cantidad de comprobaciones, y no
debe intentarlo.** Querer igualar el volumen de un feed comercial o comunitario en solitario no es
realista, y aunque lo fuera nos dejaría siendo "un OpenVAS peor": la misma propuesta de valor con
una fracción de la cobertura.

La pregunta correcta no es "¿cómo tengo más checks que ellos?", sino "¿qué sé hacer yo que ellos no
hacen bien?". Y ahí sí hay un hueco claro. Todas esas herramientas comparten el mismo defecto: te
devuelven una **lista plana de hallazgos por escaneo** y te dejan a ti la tarea de darle sentido.
Ninguna razona de forma nativa sobre qué importa *en tu contexto y esta semana*, ninguna mantiene el
estado de una vulnerabilidad a lo largo del tiempo por cada activo, y desde luego ninguna te lo
explica en lenguaje natural.

Ahí está la apuesta. **No competimos en volumen, competimos en síntesis.** El motor unifica
descubrimiento, detección y contexto en un único hallazgo que sabe de dónde viene (su procedencia) y
cómo ha evolucionado (su ciclo de vida), prioriza por riesgo real —combinando gravedad técnica,
probabilidad de explotación, existencia de exploits y exposición del activo— y lo cuenta de forma
comprensible, además de ser reproducible porque cada dato queda versionado.

**Por dónde clavamos la cuña.** El punto de entrada natural sigue siendo la **higiene y exposición
de los activos**: TLS y HTTP mal configurados, software desactualizado, vulnerabilidades que la CISA
marca como explotadas activamente. Es donde las comprobaciones activas cuestan poco y aportan mucha
señal. Con la premisa de esta revisión se le añade un segundo frente igual de barato y mucho más
diferencial: **los servicios de red que no son web**, que es donde la brecha G1 vive.

**Lo que Lybra deliberadamente no será.** Para no perdernos, conviene dejar por escrito las
tentaciones que vamos a rechazar: no será un clon de OpenVAS con un feed de cien mil comprobaciones;
no competirá por número de checks; no mantendrá un catálogo de CVEs curado a mano; no perseguirá la
cola larga de appliances industriales y software empresarial de nicho (la brecha G5); y no producirá
otra lista plana de hallazgos más. Cada vez que una decisión nos empuje hacia una de esas cinco
cosas, es señal de que nos estamos saliendo del plan.

---

## 5. Los cimientos de la arquitectura

### 5.1 Qué significa "bajo nivel" aquí

Cuando decimos que queremos un motor **de bajo nivel** no nos referimos a un lenguaje de bajo nivel
como C o Rust, sino a **independencia de terceros en tiempo de ejecución**: que cada capa del motor
—descubrimiento, fingerprinting, detección, correlación— tenga una implementación *propia* en lugar
de limitarse a invocar el binario o el servicio de otra persona.

El motor se construye en **Python**, el stack que ya usamos, con una excepción bien acotada para la
parte de red (la isla `asyncio` del apartado 5.4). Un componente nativo en C o Rust —al estilo de
`Lybra-AcheronMobile`— sigue existiendo como optimización futura y opcional, reservada a un único
cuello de botella de rendimiento y condicionada a tener evidencia de necesidad (Fase T).

### 5.2 El motor es, sencillamente, otro tipo de escaneo

La decisión de diseño más importante es también la menos glamurosa: el motor no es algo aparte, sino
un tipo de escaneo más, de primera clase. Cada escáner sigue el mismo patrón de cuatro piezas —una
tarea, un procesador de resultados y un gestor— y tras la eliminación la tabla queda así:

```
ScanType.NMAP    → NmapScanTask     → NmapResultProcessor   → NmapScanManager
ScanType.NIKTO   → NiktoScanTask    → NiktoResultProcessor  → NiktoScanManager
ScanType.NUCLEI  → NucleiScanTask   → NucleiResultProcessor → NucleiScanManager    ← Fase U
ScanType.LYBRA   → LybraEngineTask  → LybraResultProcessor  → LybraEngineManager   ← el motor
ScanType.OPENVAS → ✂ eliminado (§7)
```

Sobre la persistencia hay dos formas en el repositorio, y la Fase U elige a conciencia. Nmap, Nikto y
OpenVAS tienen **tablas de resultados propias** además del `Finding` aditivo; `LybraScan` es una
subclase fina de `Scan` **sin tabla de resultados ninguna**, y todo lo suyo vive en `Finding`.
`NucleiScan` sigue la forma de Lybra, por la razón que el §5.3 y el paso E3 del §7 ya demuestran: las
tablas nativas son andamiaje que este mismo plan está desmontando en otro sitio, y no tiene sentido
construirlo nuevo en 2026.

El registro por decorador (`@ScanManager.register(ScanType.LYBRA)`) sobre el modelo polimórfico
(`polymorphic_on=scan_type`) es lo que hace que el motor herede sin escribir una línea la cancelación
cooperativa, el reporte de progreso, la persistencia, la programación de escaneos, la organización en
carpetas, la generación de PDF y el enriquecimiento con IA.

### 5.3 El hallazgo unificado

Aquí está el corazón técnico de la apuesta. El modelo `Finding` (`themis/model.py`) es común a todos
los orígenes: qué se encontró (`title`, `category`, `port`, `service`, `cpe`), la correlación de la
vulnerabilidad (`cve_ids`, `cvss_score`, `cvss_vector`, `epss_score`, `in_kev`, `exploit_maturity`),
la calidad y procedencia (`source`, `check_id`, `feed_version`, `dedup_key`, `qod`, `confirmed`) y el
ciclo de vida (`first_seen_at`, `last_seen_at`, `state`).

Con este modelo los hallazgos de Lybra y de Nikto viven en la misma tabla: si dos fuentes detectan la
misma CVE en el mismo host y puerto, dejan de ser dos entradas inconexas y pasan a ser **un solo
`Finding`** con procedencia múltiple y una confianza más alta.

**Y es lo que hace barata la eliminación de OpenVAS.** Los hallazgos históricos de OpenVAS ya viven
en `Finding` gracias al adapter aditivo de la Fase 0. Cuando se eliminen las tres tablas nativas
(`OpenVASScan`, `OpenVASVulnerability`, `OpenVASScanResult`), **los hallazgos normalizados
sobreviven**, con su `source="openvas"` como registro histórico de procedencia. No se pierde
información de valor: se pierde el andamiaje que la producía.

### 5.4 Cómo conviven el bajo nivel asíncrono y un backend síncrono

Todo el motor de red —el sondeo concurrente de puertos, los dissectors, las comprobaciones activas—
quiere concurrencia de entrada/salida. Pero el stack actual es Python síncrono: Flask, RQ, `urllib`.
La solución es **encapsular** el asincronismo donde se necesita: el motor introduce `asyncio`
únicamente dentro del worker de RQ, y solo ahí.

```python
with job_context() as job:
    results = asyncio.run(engine.scan(target, cancel_check=job.cancelled, progress=job.progress))
    with UnitOfWork() as uow:               # se persiste de forma síncrona, ya fuera del loop
        ScanRepository(uow).persist_findings(scan, results)
```

Como los workers de RQ son procesos separados, ese event loop nace y muere sin contagiar al proceso
de Flask. La regla que mantiene la sencillez es no mezclar nunca `asyncio` con la sesión de
SQLAlchemy: el motor genera los `Finding` en memoria mientras escanea y los persiste al terminar.

Sobre permisos: preferimos otorgar al worker la capability `CAP_NET_RAW` antes que un `sudo`
completo. Con ella el transporte puede usar sondas SYN/UDP crudas; sin ella degrada a `connect-scan`.
La regla es tajante: **nunca fallar por falta de acceso raw, simplemente ir más despacio.** (Un
efecto colateral agradable de eliminar OpenVAS: desaparece el único contenedor del compose que exigía
`NET_ADMIN`.)

---

## 6. Las fases, reordenadas por brecha que cierran

### 6.1 Estado actual, verificado

La pista de **correlación** está completa; la de **bajo nivel** está a medias en sus tres fases.

| Fase | Pista | Estado |
|---|---|---|
| **0** — Cimientos (`Finding`, `ScanType.LYBRA`, CPE persistido) | Correlación | ✓ implementada |
| **1** — Matcher CPE→CVE (detección por versión) | Correlación | ✓ implementada |
| **2** — KB local (NVD, CPE Dictionary, KEV, EPSS) | Correlación | ✓ implementada |
| **5** — Dedup multi-fuente, ciclo de vida, scoring, `HostService` | Correlación | ✓ implementada |
| **6** — Pipeline orquestado | Convergencia | ✓ implementada |
| **U** — Nuclei: herramienta, corroborador y oráculo | Bajo nivel | ◐ parcial — U1, U2 y U3 hechas, U4 sin empezar. **U4 sigue siendo prerrequisito del cierre de R**. Detalle en la sección Fase U más abajo |
| **R** — Runtime de checks propio | Bajo nivel | ◐ parcial — 16 checks; los cuatro tipos activos (`http`/`tls`/`network`/`script`) existen, el feed vive en YAML y la ingesta está construida pero apagada. **Solo queda la precisión ≥0,9 medida**, que depende del banco (U3) y no de más código. Detalle actualizado en la sección Fase R más abajo |
| **F** — Fingerprinting propio | Bajo nivel | ◐ parcial — HTTP, SSH, TLS, y (Fase N) FTP, SMTP/IMAP/POP3, SMB, MySQL/MariaDB, Redis, VNC; falta JARM, SNMP (sin sonda UDP), PostgreSQL/MSSQL/MongoDB, RDP, LDAP, Telnet, RPC. Detalle actualizado en la sección Fase N más abajo |
| **T** — Transporte propio | Bajo nivel | ◐ parcial — `AsyncConnectScanner` sobre asyncio; faltan SYN sin estado, sondas UDP y control de tasa AIMD |
| **4**, DAST y Etapa 2 (P, E, C, O, A, B, D, G, S, X) | Ambas | ○ planificadas |

El feed actual (`lybra/feeds/checks_feed.json`, versión `lybra-checks-1`) tiene 13 checks en 3 familias:
`exposed_path` ×7, `security_header` ×3, `tls` ×3 — todos de tipo `http` o `tls`. Ése es literalmente
el mapa de la brecha G1: **el runtime no tiene ni un solo check que hable un protocolo que no sea
HTTP o TLS.**

### 6.2 El criterio de prioridad, actualizado

El plan anterior ordenaba por "capa que da identidad" (lidera L2, baja de nivel por evidencia). Ese
criterio sigue siendo válido, pero se le antepone otro: **cuánta brecha con OpenVAS cierra la fase.**
El resultado es esta reordenación, que es el cambio de fondo de esta revisión:

| Orden | Fase | Brecha que cierra | Por qué aquí |
|---|---|---|---|
| **0.º** | **0.9 — Contrato de entrada externa de servicios** (nueva, pre-fase) | — | No cierra ninguna brecha por sí sola; es el cable que hace posible que la Fase I lo haga. Barata, aislada, sin riesgo para lo que ya funciona |
| **1.º** | **N — Dissectors y checks de red no-HTTP** (nueva) | **G1** | Sin ella, "prescindir de OpenVAS" significa perder de verdad cobertura. Con ella, la detección por versión se extiende a toda la superficie no-web sin escribir un solo check por CVE |
| **2.º** | **I — Inventario de Hygeia → Lybra** (H0–H2) — ◐ parcial | **G2** | Es la prioridad nº 1 del documento de gobierno por razones de producto, y resulta que además es el sustituto del escaneo autenticado de OpenVAS. Dos motivos independientes apuntando al mismo trabajo. La tubería está construida (2026-07-28); falta la **resolución de nombre de paquete → CPE** (Fase I-b), sin la cual el motor recibe el inventario pero no sabe reconocerlo |
| **3.º** | **U — Nuclei como herramienta, corroborador y oráculo** (nueva) | G4 parcial, y **la vara de medir** | Entrega una herramienta de producto completa a coste bajo, sustituye a Nikto como corroborador con datos mucho mejores (CVE + CVSS frente a OSVDB), y da el oráculo de falsos positivos que el §8 admite que falta. Va antes que el cierre de R porque es quien lo hace medible |
| **4.º** | **R (cierre) — tipo `script`, feed en YAML, ingesta de plantillas** | G1, G4 | El tipo `network` **ya existe** (lo aportó la Fase N). Lo que queda —YAML, ingesta y el umbral de precisión— depende de la Fase U; `script` no |
| **5.º** | **O — Backports por feed de distribución** | **G3** | Ataca la causa nº 1 de falsos positivos sin tocar el host ni pedir credenciales |
| **6.º** | **D — Credenciales por defecto** | **G4** | Cobertura clásica de OpenVAS, con guardas propias (lockout, tasa, evidencia sin plaintext) |
| **7.º** | **F y T (cierre) — JARM, SYN sin estado, UDP, AIMD** | — | Independiza de Nmap, no de OpenVAS. Trabajo de identidad y disfrute, no de necesidad |
| resto | Etapa 2 (P, E, C, A, B, G, S, X) | — | Capacidades nuevas, ninguna condicionada por la salida de OpenVAS |

Las fases **4** (escaneo autenticado por SSH) y **DAST** bajan de prioridad de forma explícita: la
primera porque la Fase I la cubre mejor y sin credenciales nuevas, la segunda porque sigue siendo
opcional y dependiente del uso real.

---

### Fase N — Dissectors y checks de red no-HTTP · pista de bajo nivel · ◐ parcial · **la que cierra la brecha**

**El objetivo** es que Lybra sepa identificar y comprobar los servicios que no son web. Es la fase
que convierte "eliminamos OpenVAS" en una decisión sin pérdida de cobertura, y por eso lidera.

**Qué ya existe y qué falta.** `transport.py` descubre puertos abiertos y `engine.py` emite un
hallazgo informativo por cada uno, así que la superficie *se ve*. Lo que falta es leerla:
`lybra/fingerprinting/` (dividido en un módulo por protocolo — `http.py`, `ssh.py`, `tls.py`,
`concordance.py` — desde esta misma ronda) tiene `fingerprint_http`, `fingerprint_ssh` (banner +
HASSH) y `TlsProbe`, y nada más. Un puerto 445, 3389, 3306 o 161 abierto hoy produce un `Finding`
de categoría `open_port` con `qod=30` y se acaba ahí. Con un dissector que extraiga producto y
versión, ese mismo puerto entra automáticamente en la maquinaria de las Fases 1 y 2 y produce sus
CVEs sin que haya que escribir un check por vulnerabilidad — que es exactamente el apalancamiento
que hace viable esta fase.

**Qué construir.** Un módulo nuevo por protocolo dentro de `lybra/fingerprinting/` (el patrón que ya
sigue el paquete), priorizados por relación entre valor y coste sobre la superficie que de verdad
vamos a ver:

| Prioridad | Protocolo | Qué se extrae | Coste |
|---|---|---|---|
| 1 | **SMB/NetBIOS** (139, 445) | Dialecto negociado, nombre de dominio/host, firma requerida o no, versión de Windows/Samba | Medio — negociación binaria, pero muy documentada |
| 1 | **FTP** (21) | Banner de bienvenida, soporte de `AUTH TLS`, login anónimo permitido | Bajo — texto plano |
| 1 | **SMTP/IMAP/POP3** (25, 465, 587, 143, 993, 110) | Banner, `EHLO` capabilities, STARTTLS, relay abierto | Bajo — texto plano |
| 2 | **SNMP** (161/udp) | Comunidad por defecto (`public`), `sysDescr` — que suele traer el producto y la versión enteros | Bajo, pero necesita la sonda UDP de la Fase T |
| 2 | **MySQL / PostgreSQL / MSSQL / Redis / MongoDB** (3306, 5432, 1433, 6379, 27017) | Paquete de saludo con versión; autenticación no requerida (el caso Redis/Mongo abierto es un hallazgo por sí mismo) | Medio — protocolos binarios propios pero con saludo trivial |
| 3 | **RDP** (3389) | Versión del protocolo, nivel de seguridad, si NLA está exigido | Medio-alto |
| 3 | **LDAP, VNC, Telnet, RPC** | Banner y capacidades básicas | Bajo cada uno, poca frecuencia |

Cada dissector emite un `Service` con su `product`, `version` y confianza, exactamente como los tres
que ya existen, y a partir de ahí **no hay que hacer nada más**: `_resolve_cpe` lo normaliza, la KB
devuelve las CVEs y la Fase 5 lo correlaciona. Ése es el punto: la brecha G1 no se cierra escribiendo
checks, se cierra escribiendo *ojos*.

Encima de los dissectors, un conjunto pequeño de checks activos de configuración —los que un
dissector no puede deducir— aprovechando el tipo `network` que la Fase R aporta: SMB sin firma, SMBv1
habilitado, FTP anónimo, SMTP relay abierto, SNMP con comunidad por defecto, Redis/MongoDB sin
autenticación, Telnet habilitado. Son diez o doce checks con una relación valor/coste altísima,
porque cubren los hallazgos que de verdad aparecen en una red interna.

**Damos la fase por hecha cuando** un escaneo Lybra contra un host con SMB, FTP, SMTP y una base de
datos abiertos identifica producto y versión de los cuatro, emite sus CVEs por versión desde la KB
local, y detecta al menos tres hallazgos de configuración de red (por ejemplo SMB sin firma, FTP
anónimo y Redis sin auth) — todo sin Nmap `-sV` de por medio y sin OpenVAS existiendo.

**Estado (2026-07-28):** arrancada por el protocolo más barato, tal como proponía el apartado 12.
`lybra/fingerprinting/ftp.py` añade el dissector: `parse_ftp_banner` reconoce las dos formas de
banner más comunes (`"220 (vsFTPd 2.3.4)"` con paréntesis, `"220 ProFTPD 1.3.5 Server (Debian)..."`
en bruto) y deja sin identificar, a propósito, un banner sin versión como el de Pure-FTPd por
defecto — ninguna CPE inventada. `FtpProbe` lee el banner con un socket crudo, mismo patrón que
`SshProbe`. Está enchufado en `LybraEngineManager._fingerprint_services`, así que un puerto FTP
autodescubierto (Fase T, sin Nmap) ya rellena el hueco de CPE exactamente igual que HTTP/SSH.

El tipo de check `network` que el runtime (Fase R) todavía no tenía ya existe: `Request` gana un
campo `send` (el payload a escribir, `None` para solo leer), y `NetworkProbe`/`NetworkSession`
abren una única conexión TCP por check y encadenan cada petición sobre ella — lo que hace falta
para una secuencia de login como la de FTP. El primer check declarativo,
`ftp-anonymous-login` (`checks_feed.json`, `feedVersion` subido a `lybra-checks-2`), envía
`USER anonymous` → espera `331`, luego `PASS ...` → espera `230`, reutilizando el mismo sistema de
matchers `and`/`or` que ya tenían los checks HTTP, sin abstracción nueva.

**Estado (2026-07-28, continuación):** ampliada a seis protocolos más, siguiendo el mismo patrón
"volunteer un dato, léelo, no adivines" que FTP demostró. Antes de esta ronda, la selección de
dissector en `LybraEngineManager._fingerprint_services` era un `if`/`elif` por protocolo —
igual de rígido que el que el apartado 5.2 de este documento ya había señalado en el gestor de
origen de servicios (§0.9). Se sustituyó por un registro (`lybra/fingerprinting/dispatch.py`:
clase `Dissector` con `applies`/`probe`, más `default_dissectors()`), así que cada protocolo nuevo
es una entrada en una lista, no una rama nueva en el manager. El mismo criterio se aplicó al
`CheckRuntime.run` de `checks.py`, que tenía el mismo bucle triplicado una vez por tipo de check
(`http`/`tls`/`network`); ahora es un único bucle sobre `_CheckFamily`, con un tipo `script` futuro
(Fase R) entrando como una entrada más, no un cuarto bucle.

Protocolos añadidos, todos con dissector + test unitario con socket falso (mismo patrón que FTP —
sin red real):

- **SMTP/IMAP/POP3** (`lybra/fingerprinting/mail.py`) — banner sin negociar, igual que FTP. SMTP
  extrae `Producto Versión` tras `"ESMTP "` (`"Exim 4.94.2"`); Postfix omite versión a propósito y
  se respeta (sin CPE inventada). IMAP/POP3 solo dan producto (`"Dovecot ready."` → `Dovecot`), con
  una lista de palabras vacías (`"pop3"`, `"server"`...) para no confundir el nombre del protocolo
  con un producto.
- **SMB** (`lybra/fingerprinting/smb.py`) — el protocolo de mayor valor por frecuencia de puerto de
  la tabla, y el único de esta ronda que no se limita a leer: envía un `SMB2 NEGOTIATE` mínimo
  (dialectos `0x0202`–`0x0302`, sin `0x0311`/SMB 3.1.1 para evitar los "negotiate contexts" que esa
  versión exige) y parsea `DialectRevision`/`SecurityMode` de la respuesta. Cuando la firma no es
  obligatoria lo dice en el propio título del fingerprint (`"SMB2 (firma no requerida)"`) — un hecho
  observado directamente, no una inferencia. **Sin verificar contra un servidor real**: el offset de
  bytes sigue MS-SMB2 §2.2.3/§2.2.4 y el test cubre el formato con un fixture construido a mano, pero
  no hay Samba/Windows en este entorno para confirmarlo — pendiente antes de confiar en ello en
  producción. Las comprobaciones activas "SMB sin firma"/"SMBv1 habilitado" que la tabla original
  pedía siguen sin construirse: el runtime declarativo actual solo compara texto decodificado, y una
  respuesta SMB2 es binaria.
- **MySQL/MariaDB** (`lybra/fingerprinting/mysql.py`) — el paquete de saludo inicial (protocolo 10)
  trae la versión en claro sin autenticar; se reconoce y despoja el prefijo de compatibilidad
  `"5.5.5-"` que MariaDB antepone, para no reportar un MariaDB 10.6 como "MySQL 5.5.5".
- **Redis** (`lybra/fingerprinting/redis_probe.py`, nombrado así para no coincidir con el paquete
  `redis` de terceros) — a diferencia de los anteriores, Redis no ofrece nada sin pedirlo: se envía
  `INFO` (de solo lectura, misma clase de acción que un `GET /` HTTP) y se lee `redis_version:` de
  la respuesta. Ese mismo patrón, declarativo esta vez, es el check activo nuevo
  `redis-unauthenticated-access` (`checks_feed.json`, `feedVersion` subido a `lybra-checks-3`): si
  `INFO` responde sin pedir credenciales, es un hallazgo por sí mismo.
- **VNC** (`lybra/fingerprinting/vnc.py`) — el banner de versión RFB (`"RFB 003.008\n"`, 12 bytes
  fijos) es la excepción a la regla "sin valor sin frecuencia" del apartado siguiente: no hay
  producto/vendor que leer, pero la versión de protocolo en sí ya distingue un respondedor legado.

Lo que sigue fuera, documentado y no descubierto por sorpresa: **SNMP** (necesita la sonda UDP que
la Fase T todavía no construye — no hay con qué probar hasta que eso exista); **PostgreSQL, MSSQL,
MongoDB** (a diferencia de MySQL/Redis, exigen un handshake negociado en vez de un banner ofrecido,
mayor coste/riesgo que valor añadido en esta ronda); **RDP, LDAP, Telnet, RPC** — Telnet en concreto
se evaluó y se descartó explícitamente: su negociación IAC no deja un texto identificable de forma
fiable sin inventar patrones, así que un dissector ahí no aportaría nada sobre el `open_port` que ya
existe. Tampoco se ha ampliado el catálogo Docker del banco de concordancia
(`test_lybra_concordance_bench.py`) con contenedores de los protocolos nuevos — sigue sin haber un
número de concordancia no-HTTP propio, solo los tests unitarios/de integración verificando la
mecánica, igual que quedó FTP.

---

### Fase 0.9 — El contrato de entrada externa de servicios · pista de correlación · ✓ implementada · **pre-fase para Hygeia**

**El objetivo** no es detectar nada nuevo: es terminar una promesa que la Fase 0 dejó a medias. Su
texto original decía que la lista de servicios que alimenta al motor "puede venir de un escaneo Nmap
anterior, de parámetros directos, o de cualquier otra fuente". Verificado contra el código, eso es
solo parcialmente cierto hoy: `LybraEngine.analyze()` (`lybra/engine.py`) ya es agnóstico al origen
—recibe un `Iterable[Service]` y no le importa quién lo llenó—, pero la capa que hay encima,
`LybraEngineManager._run_lybra()` (`managers/lybra_engine.py`), solo sabe construir esa lista de dos
formas: leyendo filas `OpenPort` de un escaneo Nmap ya guardado (`source_scan_id`), o descubriendo
puertos por su cuenta (`target`, la Fase T). No existe una tercera vía de "aquí tienes ya la lista,
analízala". Es un hueco pequeño —vive enteramente en la capa de orquestación, no en el motor— pero es
el que bloquea a la Fase I: su descripción actual da por hecho un punto de entrada que todavía no
existe.

**Por qué es una fase aparte y no un detalle de la Fase I.** El payload de la Fase I —un inventario de
paquetes de Hygeia— es solo *un* productor posible de esta lista. El contrato de entrada en sí es más
general: cualquier dato ya resuelto sobre los servicios de un host, venga de donde venga —un
`fingerprint` propio de Themis ejecutado fuera del flujo normal, la salida ya parseada de otra
herramienta, o el inventario de un agente—, debería poder alimentar el motor sin pasar por una fila de
Nmap en la base de datos. Separarlo deja a la Fase I con una sola responsabilidad: el adaptador
específico de Hygeia, no el mecanismo genérico de entrada.

**Alcance de esta pre-fase, decidido explícitamente:**

- **Solo interno.** No se añade ningún endpoint REST nuevo. El nuevo parámetro es invocable únicamente
  desde código Python del propio backend —hoy sin ningún llamador real, mañana el trigger de la Fase
  I—, así que no hace falta un schema Marshmallow de validación HTTP: el contrato es un tipo Python
  (`List[Service]`), no un formato de red. Si más adelante aparece un caso de uso externo genuino
  (un script que quiera enviar un dataset por HTTP), se añade el endpoint entonces, como una capa fina
  encima de este mismo mecanismo.
- **La procedencia se modela ya, no se pospone.** Un servicio que viene de un inventario de paquetes es
  un hecho verificado —el paquete está instalado—; uno que viene de un fingerprint de red es una
  inferencia sobre un banner. Hoy el motor no distingue: todo hallazgo por versión nace con `qod=70` y
  `confirmed=false` sin importar de dónde salió el dato. Congelar el contrato sin esta distinción
  obligaría a Fase I a reabrirlo para meterla con calzador; se resuelve aquí, cuando el contrato
  todavía es nuevo.

**Qué construir.**

1. `Service` (`lybra/engine.py`) gana un campo de procedencia, con vocabulario cerrado a dos valores
   —no una puntuación numérica, que invitaría a calibrar un número sin datos que lo respalden—:

   ```python
   @dataclass(frozen=True)
   class Service:
       port: Optional[int]
       protocol: str
       name: str = ""
       product: str = ""
       version: str = ""
       cpe: Optional[str] = None
       origin: str = "network"   # "network" (inferido: banner/CPE) | "inventory" (verificado: paquete instalado)
   ```

   Los dos productores existentes (`services_from_open_ports`, `services_from_discovered_ports`) no
   cambian: al no pasar `origin`, siguen valiendo por defecto `"network"`, que es exactamente lo que son
   hoy. Ningún llamador existente se entera del cambio.

2. `LybraEngine._version_finding` deja de fijar `qod`/`confirmed` a un valor constante y los deriva del
   `origin` del servicio:

   ```python
   QOD_INVENTORY_MATCH = 95   # dato verificado del propio host, no una hipótesis por banner

   def _version_finding(self, service: Service, cve, cpe23: str) -> dict:
       verified = service.origin == "inventory"
       return {
           ...
           "qod":       QOD_INVENTORY_MATCH if verified else QOD_VERSION_MATCH,
           "confirmed": verified,
           ...
       }
   ```

   Y `_informational_finding` deja de asumir que todo servicio tiene un puerto: cuando
   `origin == "inventory"` y `port is None` —el caso normal de un paquete de biblioteca sin proceso
   escuchando—, el título deja de decir "Puerto ... abierto" (que no tiene sentido ahí) y pasa a
   "Paquete instalado — {label}", con `category="installed_package"` en vez de `"open_port"`. El `qod`
   informativo se mantiene igual de bajo (30): que un paquete esté instalado no es, por sí mismo, más
   que un dato de inventario.

3. Un traductor nuevo, simétrico a los dos que ya existen, para productores que tienen los datos como
   diccionarios sueltos en vez de objetos `Service` ya construidos (el caso típico de un adaptador que
   lee filas de un modelo ORM propio, como hará el de Hygeia):

   ```python
   def services_from_payload(raw: Iterable[dict]) -> List[Service]:
       """Construye Service a partir de un dataset externo ya resuelto.

       A diferencia de los otros dos traductores, respeta el "origin" que el
       propio payload declare (por defecto "network", para no romper a un
       productor que aún no lo setea).
       """
   ```

   Es opcional para un productor que ya construye `Service` directamente (el traductor solo ahorra el
   paso de desempaquetar diccionarios); el contrato real de entrada al manager es `List[Service]`, no
   un formato serializado.

4. `LybraEngineManager.run_scan` / `execute_lybra_scan` / `_run_lybra` ganan un tercer modo, aditivo a
   los dos existentes —ninguna firma ni comportamiento actual cambia—:

   ```python
   def run_scan(self, user_id: int,
       source_scan_id: Optional[int] = None,
       target: Optional[str] = None,
       services: Optional[List[Service]] = None,   # NUEVO — tercer modo
       discover_ports: Optional[list] = None,
       deep: bool = False, timeout: int = 120,
       programed_scan_id: Optional[int] = None,
   ) -> int:
   ```

   Dentro de `_run_lybra`, el nuevo modo se resuelve como una tercera rama junto a
   `uses_existing_source` y el autodescubrimiento: `target` sigue siendo obligatorio —es la identidad
   del host que ata los hallazgos a un `Host` vía `get_host_by_ip`/`get_or_create_host`, ya reutilizados
   tal cual—, pero `_discover_ports` no se llama nunca. Dos consecuencias de diseño, no accidentes:

   - **El fingerprinting propio (Fase F, `_fingerprint_services`) y las comprobaciones activas (Fase R,
     `_run_active_checks`) se saltan siempre en este modo**, sin mirar siquiera el registro de objetivos
     autorizados. La razón no es una restricción de permisos: es que el modo payload existe
     *precisamente* para los casos en los que no hace falta, ni a veces se puede, tocar la red del
     objetivo —un host tras NAT que Hygeia ve pero Themis nunca podría escanear es el caso de uso que
     motiva toda la Fase I—. Reactivar el fingerprinting encima de un dato ya verificado sería, además
     de redundante, potencialmente incorrecto: sobrescribiría un hecho con una inferencia peor.
   - **El seguimiento de superficie (Fase 5, `_detect_surface_changes` sobre `HostService`) sigue
     activo sin cambios**, porque ya opera solo sobre `services` + `source_host_id` y es agnóstico al
     origen. Esto es, de hecho, el motivo por el que vale la pena señalarlo: un paquete nuevo en el
     inventario o un cambio de versión se detecta como evento de superficie exactamente igual que un
     puerto nuevo, sin escribir nada adicional.
   - **Los corroboradores del análisis profundo (`deep=True`) sí tocan la red**, así que para este modo
     exigen explícitamente que `target` esté en el registro de objetivos autorizados antes de lanzarse
     —a diferencia del modo `source_scan_id`, donde el objetivo ya fue validado por el escaneo Nmap
     previo—. Es la misma regla que ya aplica al autodescubrimiento, aplicada aquí por primera vez a
     este modo.

**Qué NO incluye esta pre-fase**, para que no se disperse: ningún colector de datos nuevo (eso es el H0
de Hygeia, en su propio repositorio), ningún adaptador inventario→`Service` (eso es la Fase I), ningún
endpoint público, y ninguna columna nueva en `LybraScan` para registrar el modo de entrada del escaneo
—se puede añadir después como observabilidad pura, sin que nada de lo anterior dependa de ella—.

**Damos la fase por hecha cuando** un test de integración construye una lista de `Service` a mano con
`origin="inventory"`, la pasa a `LybraEngineManager().run_scan(user_id=..., target=..., services=...)`,
y el escaneo resultante produce `Finding` con `confirmed=true`/`qod=95` para los que tienen CVE
conocida y `category="installed_package"` para los informativos sin puerto — sin que se dispare ninguna
llamada de red hacia el objetivo. Ese test es, literalmente, la Fase I simulada sin que Hygeia exista
todavía.

**Estado (2026-07-28):** implementada tal como se diseñó. `Service.origin` existe con sus dos
valores; `_version_finding`/`_informational_finding` derivan `qod`/`confirmed`/`category` de él;
`services_from_payload` traduce diccionarios sueltos; `run_scan`/`execute_lybra_scan`/`_run_lybra`
tienen el tercer modo, con los tres guardas de red descritos (fingerprinting y comprobaciones
activas nunca corren en este modo; los corroboradores profundos exigen autorización explícita). Un
hallazgo real durante la implementación, no anticipado en el diseño: `HostService` (Fase 5) y
`compute_dedup_key` (Fase 5) identificaban un servicio por `(host, puerto, protocolo)` — una
identidad que colapsa para dos servicios de inventario distintos, ambos con `puerto=None`. Se
corrigió en ambos sitios (clave de respaldo por `product`/`service` cuando el puerto falta; migración
de `HostService.port` a nullable) antes de dar la fase por cerrada — sin este arreglo, un segundo
paquete instalado en el mismo host habría sobrescrito silenciosamente el hallazgo del primero.

---

### Fase I — El inventario de Hygeia como escaneo autenticado · pista de correlación · ◐ parcial

**El objetivo** es sustituir el escaneo autenticado de OpenVAS (los Local Security Checks) por algo
que Ellysia ya tiene medio construido y que además es estrictamente mejor. Es la fase **H0–H2** del
plan de Hygeia (`plans/feature/hygeia/hygeia-backend.md`) y la prioridad nº 1 del documento de
gobierno; aquí se registra su segunda justificación, independiente de la de producto: **es lo que
cierra la brecha G2.** Depende de la Fase 0.9: sin el modo de entrada por payload, no hay dónde
enchufar el adaptador que describe esta fase.

**Por qué es mejor que el escaneo autenticado clásico.** OpenVAS (y la Fase 4 de este plan) resuelven
los backports entrando en la máquina por SSH con una credencial guardada. Eso exige gestionar
credenciales privilegiadas, abrir SSH desde el escáner al objetivo, y solo funciona si el host es
alcanzable. El agente de Hygeia **ya está instalado y ya está empujando telemetría**: leer
`dpkg -l` / `rpm -qa` / `winget list` y enviarlo es una capacidad marginal sobre algo que ya existe,
no necesita credencial nueva ninguna, y funciona igual de bien **en hosts tras NAT que Themis no
podría escanear jamás**. Es una ventaja estructural sobre el modelo de OpenVAS, no un apaño.

**Qué construir.** Endpoint `POST /hygeia/inventory` con la misma auth de agente y las mismas guardas
de payload que la ingesta actual · columna `MonitoredAsset.host_id` con resolución o creación del
`Host` de Themis (reutilizando `ScanRepository.get_host_by_ip`, que ya existe precisamente para que un
mismo dispositivo visto por IP y por hostname no se duplique) · un adaptador inventario→`Service`
—simétrico a los de Nikto que ya existen, pero con puerto opcional, y que marca cada `Service` con
`origin="inventory"` (Fase 0.9) para que el motor lo trate como dato verificado— · disparo de
`LybraEngineManager.run_scan(..., services=...)` (el modo de la Fase 0.9, no uno nuevo) vía TaskQueue ·
envío diferencial por hash del listado para no repetir el payload entero cada vez. Requiere trabajo en
el repositorio del agente además de en éste.

Los hallazgos caen en el mismo árbol `Host → Service → Finding` y heredan gratis la deduplicación
multi-fuente, el ciclo de vida y el scoring de la Fase 5. Gracias a la Fase 0.9, un `Finding`
procedente del inventario nace con `confirmed=true` y `qod=95` sin lógica adicional aquí: la
distinción ya vive en el motor, esta fase solo tiene que marcar correctamente el `origin` al construir
cada `Service`.

**Damos la fase por hecha cuando** un host con agente instalado produce hallazgos de CVE a partir de
su inventario de paquetes, sin escaneo de red de por medio, y esos hallazgos se funden por
`dedup_key` con los que el escaneo remoto ya producía sobre el mismo activo.

**Estado (2026-07-28): ◐ parcial.** La *tubería* está construida y probada de extremo a extremo —
un inventario de Hygeia llega al motor, produce `Finding` y se navega por agente. Lo que **no**
está resuelto es el último eslabón, y sin él la fase no cumple su propia Definición de Hecho: el
motor no sabe *reconocer* el software que Hygeia le entrega. Ver "La brecha que queda" más abajo.

Cinco decisiones de lo construido que se apartan del diseño de arriba, cada una respondiendo a algo
que se verificó contra el código:

1. **El H0 ya estaba hecho.** El `POST /hygeia/inventory` que este apartado pedía no hacía falta:
   el inventario ya viaja dentro del heartbeat (campo opcional `inventory` de `IngestRequestSchema`)
   y está persistido en `MonitoredAsset.inventory`/`inventory_collected_at`. No se construyó
   endpoint de ingesta nuevo.
2. **El disparo es manual, no automático.** El diseño encolaba el análisis al persistir un
   inventario nuevo. En su lugar hay un botón en la pestaña de inventario del panel de Hygeia
   (`POST /hygeia/assets/<id>/analyze`). El automático puede añadirse después encima de este mismo
   mecanismo; de momento nada se ejecuta sin que el usuario lo pida.
3. **`MonitoredAsset.host_id` (el H1) queda diferido.** El modo payload ya resuelve o crea el
   `Host` por hostname él solo, que es cuanto necesita esta funcionalidad. `host_id` solo aporta
   cuando el *mismo* host físico se ha visto además por IP desde un Nmap, y fundir esas dos
   identidades necesita su propia UX ("¿qué IP es este hostname?"). Deuda consciente, no olvido.
4. **Procedencia y feed propia.** `LybraScan` gana `asset_id` (Integer nullable indexado, **sin
   ForeignKey**, para no acoplar el esquema de Themis al de Hygeia). No nulo ⇒ vino de un agente ⇒
   fuera de la feed de Lybra del panel, y agrupado bajo la tarjeta de ese agente en el tercer mundo
   de `ThemisView` ("Agentes"), que reutiliza `LybraResults.vue` tal cual. Como no hay cascada de
   base de datos, borrar un activo limpia sus escaneos explícitamente
   (`HygeiaAssetManager.delete_asset` → `LybraEngineManager.delete_scans_for_asset`, que pasa por
   `delete_scan` para no dejar PDFs huérfanos).
5. **Un escaneo de inventario se puntúa como `private`.** `classify_exposure` reconoce sufijos
   internos (`.local`, `.lan`...) pero no un hostname pelado tipo `DESKTOP-ABC`, así que lo habría
   llamado "public" e inflado una banda toda la prioridad por un artefacto del nombre. La regla
   vive en `LybraEngineManager.exposure_for(scan)`, que sustituye a las tres llamadas sueltas a
   `classify_exposure` que había (manager, `analyzers.py` y el PDF de `reports.py`) — repartida
   por tres sitios se habría olvidado en uno.

**Dos cosas que "volver a analizar" NO hace, a propósito:** no borra el análisis anterior (sin el
escaneo previo, `get_previous_lybra_findings` no encuentra nada y el ciclo de vida `fixed`/
`regressed` queda muerto — hay un test que se cae si alguien reintroduce el borrado), y no descarta
paquetes por estar repetidos. Sí se descartan los que no traen versión: sin versión no hay CPE que
resolver, así que solo producirían un `installed_package` informativo cada uno, y un inventario de
Windows trae cientos.

**Nota arquitectónica.** El import `hygeia.managers → themis.managers.LybraEngineManager` es el
**primer y único import entre módulos de `features/`** de todo el backend (verificado por `grep`
antes de escribirlo). Es unidireccional y así debe seguir: Themis no importa nada de Hygeia ni sabe
que existe. Está comentado en el propio fichero para que no se lea como precedente libre. Del lado
del frontend no hay acoplamiento nuevo en backend: `ThemisView` consume `hygeiaStore` para pintar
las tarjetas de agentes.

**Lo que queda fuera:** el envío diferencial por hash (H3), el disparo automático, `host_id` (H1),
y la fusión por `dedup_key` con los hallazgos de red del *mismo* activo — que depende de H1, porque
hoy un mismo host visto por IP (Nmap) y por hostname (Hygeia) son dos filas de `Host` distintas.

#### La brecha que queda: Themis no entiende el vocabulario de Hygeia (Fase I-b)

**El síntoma, medido.** Primer análisis real, sobre un escritorio Windows (`PC-Gabriel`,
escaneo #2): **242 paquetes, 242 hallazgos, todos `INFO`/`installed_package`, cero CVEs, cero
confirmados**. Un informe que a primera vista se lee como "equipo limpio" y que en realidad no
comprobó absolutamente nada.

**Las dos causas, que son independientes** y conviene no confundir, porque una es operativa y la
otra es trabajo de ingeniería:

1. **La KB local estaba vacía.** Verificado en Postgres el 2026-07-28: `CveEntry` = 0,
   `CpeMatch` = 0, `KevEntry` = 0, `EpssScore` = 0. Con la KB vacía **ningún** escaneo Lybra puede
   detectar nada, venga de Hygeia o de Nmap — no es un problema de la Fase I, pero conviene
   resolverlo antes de medir cuánto pesa la brecha I-b de verdad.

   **Ojo con la trampa operativa:** el job programado (`themis.kb.syncCron`, 03:00, ya
   `enabled: true`) llama a `KbSyncManager.sync_all()`, pero eso ejecuta `sync_nvd(window_days=8)`
   — el sync **incremental**, que solo trae CVEs *modificadas* en los últimos 8 días. Dejar que el
   cron corra no rellena el catálogo histórico (no habría dado con CVE-2021-41773, por ejemplo).
   Hace falta `KbSyncManager().sync_nvd_backfill(base_url, start=<fecha antigua>)` — el propio
   docstring del método lo llama "an operational one-off... meant to be run manually", y no hay
   endpoint ni UI para lanzarlo, solo una llamada de consola dentro del contexto de la app. NVD
   limita las ventanas seguras a 14 días con una pausa de 6s entre cada una
   (`KbSyncManager._NVD_MAX_WINDOW_DAYS`), así que un backfill de todo el histórico (CVEs desde
   1999) son varios cientos de tramos — cuenta con que tarde del orden de una hora o más, no algo
   instantáneo.

   **Estado (2026-07-29): ejecutado.** Se lanzó un backfill pensado para los últimos 3 años
   (`start = hoy - 3 años`), pero el primer tramo de 14 días disparó la trampa que el propio
   docstring de `_NVD_MAX_WINDOW_DAYS` ya documentaba como riesgo por encima de 20-25 días — NVD
   descartó el filtro de fecha igualmente y devolvió el catálogo histórico completo. Verificado en
   Postgres mientras corría (dos lecturas con 60s de diferencia, para confirmar que avanzaba y no
   estaba colgado): `CveEntry` subiendo en bloques de 2.000 cada 20-30s, hasta terminar en
   **~350.000 CVEs / ~2 M de filas `CpeMatch`** — el histórico completo de NVD, no solo 3 años. Tardó
   más de una hora en total (~5 min de CPU real; el resto son las pausas obligatorias del
   rate-limit sin API key).

   **⚠️ No resetear la base de datos de desarrollo** (nada de `CREATE_DATABASE=True`, ni un
   `docker compose down -v` sobre el volumen de Postgres) sin ser consciente de que eso borra este
   backfill entero — repetirlo cuesta más de una hora de nuevo. Aviso gemelo en el `CLAUDE.md` raíz,
   sección "Things that bite".
2. **El matcher no sabe resolver nombres de software de escritorio a un CPE.** Ésta sí es la
   brecha de la Fase I, y es la que este apartado documenta.

**Por qué falla la resolución.** `LybraEngine._resolve_cpe` (`lybra/engine.py`) solo tiene dos
estrategias, y ninguna sirve para un inventario:

| # | Estrategia | Por qué no aplica al inventario de Hygeia |
|---|---|---|
| 1 | Confiar en el CPE que traiga el propio servicio | El inventario nunca trae CPE: el contrato de ingesta (`SoftwareSchema`) tiene `name`, `vendor`, `version`, `guid`… pero no `cpe`. El adaptador no puede inventar uno |
| 2 | Buscar el producto en `CPE_PRODUCT_OVERRIDES` | Es una tabla escrita a mano de **13 entradas**, todas demonios de red de servidor (`apache httpd`, `nginx`, `openssh`, `mysql`, `vsftpd`…). Ni una sola aparece en un inventario de escritorio |

Sin CPE, `_version_findings` corta antes de consultar la KB. El paquete no se "aprueba": no se
examina. Y como `_informational_finding` emite un `installed_package` por **cada** paquete —se le
haya resuelto CPE o no—, el resultado es indistinguible de un análisis que sí comprobó y no
encontró nada. De ahí la nota de cobertura que se añadió al PDF y a la UI: no arregla la brecha,
pero impide que se lea como una garantía que no es.

Esta brecha existía desde la Fase 1, pero era **invisible**: un escaneo de red identifica servicios
por banner/CPE de Nmap, que casi siempre caen dentro de esos 13 productos de servidor. Al enchufar
Hygeia, el caso excepcional pasó a ser el caso normal.

**Qué hay que construir — tres pasos, del más barato al más completo.** Son acumulativos: cada uno
funciona por sí solo y deja al siguiente menos trabajo.

**Paso 1 — Normalización de nombres (barato, alto retorno inmediato).**
El problema no es solo qué productos conocemos, sino cómo se escriben. Hygeia reporta
`"7-Zip 25.01 (x64)"`; NVD lo conoce como `7-zip:7-zip`. Hace falta una función pura
—en `lybra/kb.py`, junto al resto de lógica de CPE— que canonice un nombre de paquete antes de
buscarlo: minúsculas, quitar sufijos de arquitectura (`(x64)`, `(x86)`, `64-bit`), quitar la
versión repetida dentro del nombre, quitar palabras de relleno (`Redistributable`, `Runtime`,
`Setup`), colapsar separadores (` `, `-`, `_`) a uno solo. Es una función pura, así que se prueba
con una tabla de casos reales sacados del inventario de un equipo de verdad. Sin esto, los dos
pasos siguientes fallan igual aunque el producto sí esté en la base.

**Paso 2 — Índice de productos derivado de `CpeMatch` (el atajo que evita espejar el CPE Dictionary).**
La observación clave: **no hace falta el CPE Dictionary completo de NVD** (~1,4 M de entradas,
un espejo caro de mantener). El único vocabulario que importa es el de productos que *tienen al
menos una CVE*, y ése ya está en la base de datos: `CpeMatch` guarda `(vendor, product)` por cada
regla de aplicabilidad de cada CVE espejada. Un producto que no aparezca ahí jamás podría producir
un hallazgo, así que resolverlo no aportaría nada.

El trabajo, entonces, es una tercera estrategia en `_resolve_cpe`: normalizar el nombre del paquete
(paso 1) y buscarlo contra los `product` distintos de `CpeMatch`, también normalizados. Conviene
materializarlo en una tabla-índice propia (`CpeProductAlias`: `normalized_name` → `(vendor,
product)`, con índice único) reconstruida al final de cada `sync_nvd`, en vez de normalizar en
cada consulta: son cientos de miles de filas y la resolución ocurre una vez por paquete y escaneo.

Reglas de seguridad que **no** se pueden saltar aquí, porque un falso positivo por mala resolución
es peor que no detectar:
- Coincidencia **exacta sobre el nombre normalizado**, nunca parcial ni por subcadena. `"Java"`
  no debe casar con `oracle:jdk` por que una contenga a la otra.
- Un nombre normalizado que resuelva a **más de un `(vendor, product)`** se descarta (o se marca
  como ambiguo y no se usa), en vez de elegir uno. Ambigüedad conocida ≠ licencia para adivinar.
- El `vendor` que reporta Hygeia (`"Microsoft Corporation"`) se usa como **desempate** cuando lo
  hay, no como parte obligatoria de la clave: muchos inventarios lo traen vacío o inconsistente.

**Paso 3 — Alias curados para lo que la normalización no alcanza (cola larga).**
Siempre quedará software cuyo nombre comercial no se parece a su CPE (`"Microsoft Visual C++ 2022
X64 Runtime"` → `microsoft:visual_c++`). Eso es un fichero de alias en `lybra/feeds/`, con la misma
filosofía de feed versionado que `tech_signatures.json` y `checks_feed.json`: una entrada JSON, no
un cambio de código, cada vez que un inventario real destape un producto frecuente sin resolver.
Es también donde `CPE_PRODUCT_OVERRIDES` debería acabar mudándose, para no tener dos tablas de
alias haciendo lo mismo en sitios distintos.

**Observabilidad, que hoy no existe y hace falta para dirigir el paso 3.** El motor debe registrar
*por qué* un paquete no produjo detección. Basta con distinguir en el propio `Finding` informativo
entre "CPE resuelto, KB consultada, sin CVEs" y "CPE no resuelto" — un campo en el snapshot, o dos
categorías distintas. Con eso, la nota de cobertura puede dejar de enumerar causas posibles y decir
la real, y sobre todo se puede sacar la lista de los productos sin resolver más frecuentes, que es
exactamente el orden en el que conviene rellenar el feed de alias.

**Damos la Fase I por cerrada (✓) cuando** un análisis del inventario de un escritorio Windows real,
con la KB sincronizada, resuelve a CPE una mayoría de sus paquetes y emite al menos una detección
por versión verificable a mano contra NVD — y cuando un paquete sin resolver se distingue en los
datos de uno comprobado y limpio.

**Estado (2026-07-29): pasos 1–3 implementados y verificados contra un inventario real.**

- **Paso 1** — `normalize_product_name`/`extract_trailing_version` en `lybra/kb.py`: quita
  paréntesis/corchetes, ruido de arquitectura (`x64`, `x86`, `setup`, `installer`…), colapsa
  separadores y recorta la versión final repetida en el nombre.
- **Paso 2** — `CpeProductAlias` (tabla nueva, migración `e6f7a8b9c0d1`) + `rebuild_cpe_product_index`
  en `KbRepository`, enganchado al final de `KbSyncManager.sync_all()`. Descarta cualquier nombre
  normalizado que resuelva a más de un `(vendor, product)` en vez de adivinar. Reconstruido una vez
  contra el backfill completo: **107.519 alias inequívocos**.
- **Paso 3** — `lybra/feeds/product_aliases.json` (`feedVersion: "lybra-aliases-2"`), migrando las
  13 entradas de servidor de `CPE_PRODUCT_OVERRIDES` más ~15 curadas a mano, incluida `"7 zip"` y
  `"git"` — casos donde el propio NVD tiene más de un vendor para el mismo producto y el paso 2 los
  descarta correctamente por ambiguos; se resuelven aquí porque un humano sí sabe cuál es.

`_resolve_cpe` (`engine.py`) encadena las tres estrategias sobre la **misma** clave normalizada
(antes el paso 3 comparaba contra el string crudo en minúsculas, lo que lo dejaba casi inútil para
nombres de escritorio con versión embebida — corregido en esta pasada).

**Verificado contra el inventario real de `PC-Gabriel`** (289 paquetes, 255 con versión utilizable,
escaneo #6): **29 hallazgos vulnerables en 6 productos** — 7-Zip×9, IntelliJ IDEA×12, WireGuard×2,
Git×1, Java SE JDK×1, WSL×4. Un CVE espoteado a mano (`CVE-2025-68269` sobre IntelliJ,
`CVE-2026-64812` sobre `2025.2.2` sí, rango `version_end_excluding=2026.2`) confirmado correcto
contra el rango real de NVD por `psql`.

Probar contra datos reales, no sintéticos, encontró dos bugs genuinos que la suite de tests no
había previsto:

1. **La normalización no recortaba la versión final del nombre** (`"7-Zip 25.01 (x64)"` →
   `"7 zip 25.01"` en vez de `"7 zip"`) — corregido con `_TRAILING_VERSION_RE`.
2. **JetBrains registra el build interno como `DisplayVersion` de Windows** (`"252.26199.169"`),
   no la versión de marketing contra la que NVD expresa sus rangos (`"2025.2.2"`, visible solo
   dentro del propio nombre). Sin corregirlo, IntelliJ IDEA producía **~50 CVEs** arrastrados desde
   2009 hasta 2026 — un falso positivo masivo por comparar contra la versión equivocada. Corregido
   en `services_from_inventory` (`hygeia/services/inventory_adapter.py`): prefiere la versión
   embebida en el nombre cuando existe (`extract_trailing_version`), cae al campo `version` si no.
   Bajó a **12 CVEs**, verificados uno a uno como genuinos. Comprobado que no es un patrón general
   muestreando el resto del inventario (name/version coinciden en casi todos los demás casos) antes
   de generalizar el fix.

#### Observabilidad: `Finding.cpe_resolved` (implementado)

La brecha que el apartado anterior dejaba pendiente ya está cerrada. `Finding` gana una columna
`cpe_resolved` (Boolean nullable, migración `2d58f913333b`) que el motor rellena en el hallazgo
informativo de **cada** paquete: `True` si `_resolve_cpe` encontró un CPE, `False` si no, `None`
para las fuentes que ni lo intentan (Nikto, OpenVAS). La resolución se calcula una sola vez por
servicio en `analyze()` y se comparte entre el hallazgo informativo y el de detección.

Con eso, "comprobado y limpio" y "ni se llegó a identificar" dejan de ser indistinguibles en los
datos, y la nota de cobertura del PDF, del modal de Hygeia y del desglose de Themis pasa de una
heurística que enumeraba causas posibles ("puede que la KB no esté sincronizada, puede que el
nombre no se reconozca") a un número exacto: *N de M paquetes no se pudieron identificar*.
`get_analysis_summary` lo expone como `unresolvedCount`.

#### Dos bugs sistémicos que la observabilidad destapó (2026-07-29)

Poder *contar* los no resueltos convirtió "parece poco" en una pregunta contestable, y al tirar del
hilo aparecieron dos fallos independientes, ambos de alcance global y ninguno específico de Hygeia:

**1. El índice no podía casar nombres con el vendor como prefijo.** Windows escribe "Microsoft
Edge", "Adobe Acrobat", "GitHub CLI", "Oracle VirtualBox"; la columna `product` de NVD casi nunca
repite el vendor (`edge`, `acrobat`, `cli`, `virtualbox`). El índice del paso 2 solo indexaba por
`normalize_product_name(product)`, así que esas dos formas no podían encontrarse jamás.
`rebuild_cpe_product_index` pasa a indexar cada par bajo **dos** claves —el producto solo y
`vendor + product`—, con la clave directa ganando en caso de colisión y el descarte por ambigüedad
aplicado dentro de cada espacio de claves por separado. Medido sobre el espejo completo de NVD:
**+118.648 claves (107.459 → 226.132), cero pérdidas**. Sobre el inventario real, paquetes
resueltos **10 → 21**.

> La precedencia importa y se midió: fundir ambas claves en un mismo espacio con descarte por
> ambigüedad destruía 626 claves que hoy funcionan (`adobe reader`, `apache tomcat`… donde NVD
> nombra el mismo software de las dos formas). Con la clave directa ganando, el cambio es
> aditivo puro.

**2. Una regla de aplicabilidad sin ningún límite de versión casaba con todo.** `version_in_range`
devolvía `True` cuando la regla no traía ni versión exacta ni ninguno de los cuatro límites. NVD
lee eso como "todas las versiones", pero **el 14,6% del espejo completo (370.855 de 2,5 M de filas)
es así**, y se concentra justo en el software de escritorio autoactualizable que llena un
inventario. El efecto medido: **695 CVEs para un único Microsoft Edge al día**, 9 para OneDrive, y
`CVE-2009-1099` resucitada contra un JDK de 2026. Ahora devuelve `False`: una regla sin información
de versión no puede sostener la única afirmación que un `outdated_software` hace —que *esta*
versión es vulnerable—. Coste medido: **708 hallazgos falsos fuera, 0 detecciones legítimas
perdidas** (las 22 que venían de rangos reales siguen intactas).

**Resultado final sobre el inventario real** (`PC-Gabriel`, 289 paquetes → 242 hallazgos
informativos, 21 resueltos): **32 hallazgos abiertos** en 8 productos — IntelliJ IDEA×12,
7-Zip×9, Adobe Acrobat×4, WireGuard×2, WSL×2, GIGABYTE Control Center×1, GIGABYTE Performance
Library×1, Git×1.

#### Limitación conocida, no resuelta: NVD mezcla esquemas de versión bajo un mismo CPE

De esos 32, **4 son falsos positivos y la causa está en los datos de NVD, no en el motor**. Los
cuatro hallazgos de Adobe Acrobat corresponden a componentes de Acrobat *embebidos en un
navegador* —"Acrobat for Edge", "Adobe Acrobat PDF Extension (Chrome)"—, que NVD archiva bajo
`adobe:acrobat` pero versiona con el número del **navegador** (`120.0.2210.91`, `126.0.2592.81`),
no con el de Acrobat (`24.001.30235`). El Acrobat de escritorio instalado (`26.001.21691`) compara
numéricamente por debajo de esos techos y entra en el rango.

No se ha intentado arreglar, deliberadamente. La única señal disponible sería heurística
(desajuste en el número de segmentos de la versión, o en la escala del major), y aplicarla de
forma global suprimiría detecciones legítimas en todo el software que mezcla `1.2.3` y `1.2.3.4`
para el mismo producto — cambiar un falso positivo acotado por un falso negativo de alcance
desconocido. Queda documentado como límite del espejo de NVD; si algún día molesta lo bastante, el
sitio natural para tratarlo es el feed curado (paso 3), que ya existe precisamente para corregir a
mano lo que la automatización no puede saber.

#### El análisis de "casi-aciertos": dirigir el feed curado con datos (2026-07-30)

El apartado anterior daba por hecho que medir la cobertura exigía varios inventarios. Es falso: con
**uno solo** se puede contestar la pregunta que de verdad importa, que no es *"¿qué se repite entre
equipos?"* sino ***"¿qué hay aquí que debería resolver y no resuelve?"***. Basta recortar palabras
por los extremos de cada nombre sin resolver y ver si alguna forma más corta existe en el índice.

De los 221 sin resolver, **58 quedan a un recorte de una clave del índice**. El resultado es, sobre
todo, **la validación empírica de la regla "coincidencia exacta, nunca por subcadena"** que este
documento fijó por intuición en el paso 2. Relajarla habría producido esto:

| Paquete real | A lo que habría casado |
|---|---|
| `ENE_MousePad_HAL` | `cnrs:hal` — el repositorio académico francés |
| `NVIDIA Container` | `apple:container` |
| `Windows SDK for Windows Store Apps Contracts` | `openzeppelin:contracts` — contratos de Solidity |
| `LockHunter 3.4, 32/64 bit` | `bit_project:bit` |
| `WD P40 Game Drive` | `google:drive` |
| `Epic Games Launcher` | `organizedthemes:epic` — un tema de WordPress |

**Lo añadido al feed** (`lybra-aliases-3`), tras verificar cada uno contra la KB:

| Alias | Resuelve a | Por qué |
|---|---|---|
| `mysql workbench 8.0 ce` | `oracle:mysql_workbench` | El sufijo comercial "CE" impedía la coincidencia. 42 reglas en NVD, todas acotadas |
| `microsoft .net runtime` | `microsoft:.net` | La versión del runtime (`8.0.19`) es exactamente la que NVD usa en sus rangos |
| `microsoft windows desktop runtime` | `microsoft:.net` | Es el .NET Desktop Runtime; NVD no le da producto propio y versiona igual (`8.0.19`) |

**Lo descartado, y por qué** — importa más que lo añadido, porque son trampas:

- **`.NET SDK` (`8.0.413`) y `.NET Standard Targeting Pack` (`2.1.0`)**: sus versiones pertenecen a
  *otra escala* que la que `microsoft:.net` usa en sus rangos (el SDK 8.0.413 lleva dentro el
  runtime 8.0.19; .NET Standard 2.1 no es .NET 2.1). Aliasarlos repetiría exactamente el fallo de
  esquemas mezclados documentado arriba con Acrobat, pero esta vez por decisión propia.
- **`ASP.NET Core`**: su nombre en Windows lleva la versión *incrustada en medio*
  (`Microsoft ASP.NET Core 8.0.19 Shared Framework`), y `normalize_product_name` solo recorta la
  del final. La clave resultante sería específica de la versión y habría que añadir una nueva con
  cada parche — un alias que se pudre solo. Queda pendiente de que la normalización sepa recortar
  versiones intercaladas, que es un cambio de radio mucho mayor y no se hace de pasada.

Nota operativa: MySQL Workbench 8.0.45 está por encima del techo más alto que NVD registra (8.0.28),
así que el alias **no produce hallazgos hoy** — y es justo lo que se busca: el paquete pasa de
"sin identificar" a "comprobado y limpio", que es la distinción entera que `cpe_resolved` existe
para poder hacer.

Resultado: paquetes resueltos **21 → 24**, y **32 hallazgos nuevos legítimos** en .NET — verificados
a mano contra los rangos reales (`[8.0.0, 8.0.21)`, `[8.0.0, 8.0.24)`, `[8.0.0, 8.0.26)`…, con el
8.0.19 instalado dentro de todos ellos, y descartando correctamente los tramos `9.0.x`/`10.0.x` de
las mismas CVEs).

**Efecto secundario conocido: los dos alias de .NET duplican sus hallazgos.** `.NET Runtime` y
`Windows Desktop Runtime` son dos paquetes instalados por separado que resuelven al mismo
`microsoft:.net:8.0.19`, así que cada CVE sale dos veces (64 filas donde 32 bastarían).
`compute_dedup_key` no los fusiona, y **no es un fallo**: incluye el nombre del paquete a propósito
(ver el docstring de `_surface_finding`) para que dos paquetes *distintos* sin puerto no colisionen
todos bajo la misma identidad `port=None` — una decisión de la Fase 0.9. La tensión es real y no
tiene solución obvia: afinar la clave para fusionar estos dos arriesga fusionar paquetes que no lo
son. Se conservan ambos alias porque el coste de quitarlos sería no detectar nada en un equipo que
solo tenga el Desktop Runtime; duplicar es cosmético, no detectar no lo es.

**¿Se cumple el criterio de cierre?** Ahora sí es medible, y el resultado es honesto pero no
redondo: **21 de 242 paquetes resuelven a CPE (8,7%)** — muy lejos de "una mayoría". Ahora bien,
inspeccionados a mano, la gran mayoría de los 221 restantes son drivers OEM (AMD, GIGABYTE, ENE),
redistribuibles de Visual C++ y componentes del SDK de .NET que **no existen como producto en
NVD**: resolverlos no es posible ni útil, porque jamás podrían producir un hallazgo. El criterio
"mayoría resuelta" estaba mal formulado: lo que importa no es qué fracción del inventario resuelve,
sino que no quede fuera nada que *sí* tenga CVEs publicadas. Se deja la fase en **◐ parcial** con
esa corrección anotada, y el siguiente paso natural —ya barato con `cpe_resolved` en su sitio— es
sacar el ranking de nombres sin resolver más frecuentes entre varios inventarios reales para dirigir
el feed curado con datos en vez de por intuición.

---

### Fase U — Nuclei como herramienta, corroborador y oráculo · pista de bajo nivel · ◐ parcial (U1 hecha) · **prerrequisito del cierre de la Fase R**

**El objetivo** es incorporar Nuclei a Ellysia en sus cuatro papeles posibles de una vez, porque los
cuatro comparten la misma pieza de trabajo y separarlos sería escribirla cuatro veces. Es la única
fase de este documento que **añade** una dependencia externa en lugar de retirarla, y por eso conviene
justificar primero por qué no contradice la premisa.

**Por qué Nuclei sí y OpenVAS no.** El §1 estableció que la distinción no es de tamaño ni de calidad,
sino **de naturaleza**: un binario de línea de comandos cuya salida parseamos frente a una plataforma
entera con su protocolo, su ciclo de vida y su base de datos. Nuclei pasa ese examen con holgura y por
el mismo lado que Nmap y Nikto: se invoca, escupe JSONL, se parsea, se traduce a `Finding`, se
descarta el proceso. Sin daemon, sin puertos publicados, sin `NET_ADMIN`, sin `shm_size`, sin
`depends_on` en `api` y `worker`, sin quince minutos de sincronización en frío, sin cuatro secretos de
entorno, sin el problema del vecino ruidoso. Comparado con la tabla de costes del §1, no está en la
misma categoría. El §8 ya lo había anticipado en una frase —*"Nuclei es un binario de línea de
comandos con un feed de datos, no una plataforma"*—; esta fase se limita a ejecutar esa conclusión.

**Los cuatro papeles, y qué comparten.**

| # | Papel | Dónde vive | Qué necesita |
|---|---|---|---|
| **U1** | **Herramienta de primera clase** — `ScanType.NUCLEI`, lanzable solo desde el panel, con su PDF, su vista previa, su historial y su programación | Junto a Nmap y Nikto | El patrón de 4 piezas + el traductor a `Finding` |
| **U2** | **Corroborador del análisis profundo** de Lybra (Fase 6) | `_launch_deep_corroborators` | Una línea, si U1 existe |
| **U3** | **Oráculo diferencial** del banco: medir falsos positivos y hallazgos que se nos escapan | `tests/oracle/` | El mismo traductor de U1, en un contenedor efímero |
| **U4** | **Fuente de plantillas ingeribles** al `CheckRuntime` propio | Fase R | El subconjunto del lenguaje de Nuclei — **caro, y por eso queda en R** |

La observación que ordena la fase: **U1, U2 y U3 comparten el traductor de la salida de Nuclei a
`Finding`, y esa pieza es pequeña.** U4 es el único caro, es el único que necesita entender el
*lenguaje* de las plantillas en vez de la *salida* del binario, y es el que se queda en la Fase R como
su trabajo pendiente. Esta fase entrega los tres primeros y deja al cuarto medido y decidible.

#### U1 — Nuclei como escaneo de primera clase

**Por qué encaja mejor que Nikto en el modelo `Finding`.** Ésta es la razón de fondo por la que la
fase merece la pena más allá del producto. Lo que `nikto_incident_to_finding` (`lybra/adapters.py`)
tiene para trabajar es `osvdb_id` —una base de datos muerta desde 2016—, `method`, `url`,
`description` y `severity`: sin CVE, sin CVSS, sin CPE. Ese `Finding` entra en la maquinaria de la
Fase 5 prácticamente vacío. La salida JSONL de Nuclei trae `template-id`, `info.severity`,
`info.classification.cve-id`, `cvss-score`, `cvss-metrics`, `info.tags`, `matched-at` y
`extracted-results`. El mapeo es casi 1:1 con el `Finding`, **incluidos `cve_ids`, `cvss_score` y
`check_id`**, lo que significa que un escaneo de Nuclei entra gratis en la deduplicación multifuente,
el ciclo de vida `open`/`fixed`/`regressed`, el scoring contextual con EPSS/KEV y la clasificación de
exposición de la Fase 5. Nikto nunca pudo. **El escaneo individual que el usuario lanza desde el panel
es, simultáneamente, el mejor alimentador de `Finding` que va a tener el sistema**, y no hay tensión
entre las dos cosas: Nikto ya funciona exactamente así hoy —el usuario lo lanza solo y el adapter
escribe en `Finding` de forma aditiva, sin que Lybra intervenga.

**La decisión de diseño que gobierna el resto: sin tablas nativas.** El repositorio contiene hoy dos
formas de añadir un `ScanType`, y hay que elegir a conciencia:

| Forma | Ejemplo | Qué persiste |
|---|---|---|
| **Nikto/OpenVAS** | `NiktoScan` + `NiktoIncident` (`model.py`) | Tablas de resultados propias **más** un `Finding` aditivo — doble persistencia |
| **Lybra** | `LybraScan` (`model.py`), una subclase fina de `Scan` sin tabla de resultados | Solo `Finding` |

**Se adopta la forma Lybra**, y la razón es que el propio documento ya la demostró: el paso **E3 del
desmontaje** (§7) consiste literalmente en borrar las tres tablas nativas de OpenVAS y quedarse con
los `Finding`, con la conclusión de que *"no se pierde información de valor: se pierde el andamiaje
que la producía"* (§5.3). Construir `NucleiScan` + `NucleiFinding` sería crear a sabiendas, en una
fase nueva, exactamente el andamiaje que otra fase de este mismo plan está desmontando. `NucleiScan`
es por tanto una subclase de `Scan` con poco más que su `id`, y todos sus resultados viven en
`Finding` desde el primer día. Beneficio colateral nada menor: **el PDF puede reutilizar el
renderizador de `Finding` que Lybra ya tiene** en vez de escribir un bloque específico, que es la
parte más tediosa de dar de alta un escáner.

**Qué construir.** El patrón de cuatro piezas, con la plantilla ya escrita dos veces:

- `NucleiScanTask` (`services/tasks.py`) — comando, fichero temporal de salida, progreso. Modelar
  sobre `NiktoScanTask`.
- `NucleiResultProcessor` + `NucleiPrintingStrategy` (`services/processors.py`) — parseo de JSONL
  (una línea por hallazgo, no un documento XML: más simple que Nikto).
- `NucleiScanManager` (`managers/thirdparty_scans_managers.py`) — orquestación y persistencia vía
  `nuclei_result_to_finding` (`lybra/adapters.py`) + `ScanRepository.persist_findings`.
- `NucleiScan` + `ScanType.NUCLEI` (`model.py`), con su migración de Alembic.

Más el registro y la lectura: endpoint y schema, `worker.py`, `config_reading.py` y `SecOpsConfig.json`
(`themis.nuclei.*`), y del lado de lectura `reports.py`, `csv_logger.py`, `analyzers.py`, `history.py`
y `scheduling.py`. En la SPA, **una entrada nueva en `constants/scanTypes.js`** cubre la mayor parte:
ese registro existe precisamente para esto —lo dice su propio comentario de cabecera, escrito cuando
añadir Lybra dejó claro el problema de las listas duplicadas—, y los componentes restantes leen de él.

**Las cuatro cosas que van a morder, nombradas por adelantado:**

1. **El tiempo de escaneo y la presión sobre el objetivo.** Nuclei con el feed completo contra un solo
   host son miles de peticiones. Hace falta un **perfil acotado por defecto** —por `-severity`, por
   `-tags`, o un subconjunto curado— expuesto en el formulario de lanzamiento, más `-rate-limit`. Nikto
   no obligaba a pensar esto; Nuclei sí, y no es un detalle de afinado: es la diferencia entre una
   herramienta usable y una que satura al objetivo en su primer uso.
2. **La actualización del feed de plantillas.** Nuclei se autoactualiza por red al arrancar. Dentro de
   un worker eso es una llamada saliente en mitad de un escaneo, con su latencia y su fallo posible:
   se desactiva (`-duc`) y el feed pasa a tener su propio ciclo de sincronización, del mismo modo que
   `KbSyncManager` lo tiene para la KB. Dónde vive y quién lo refresca es una decisión de esta fase,
   no una que se descubra en producción.
3. **El gate de objetivos autorizados** (§9). Nuclei toca el objetivo bastante más que Nikto. Nace
   sujeto al registro de autorizados desde el día uno, no se le añade después.
4. **`feed_version`.** El `Finding` debe registrar la versión del feed de plantillas con la que se
   produjo, igual que `CHECKS_FEED_VERSION` hace para los checks propios. Sin eso, el escaneo no es
   reproducible y se rompe la garantía del §9.

**Damos U1 por hecho cuando** un usuario lanza un escaneo de Nuclei desde el panel sin que Lybra
intervenga, obtiene su PDF, y los hallazgos resultantes aparecen deduplicados por `dedup_key` junto a
los de un escaneo previo del mismo activo, con su `cve_ids` y su `cvss_score` poblados desde la
salida de la herramienta.

**Estado (2026-07-30): ✓ hecha**, en la rama `feature/themis/nuclei-engine`. `ScanType.NUCLEI` +
`NucleiScan` siguen la forma Lybra (sin tabla de resultados propia); `nuclei_result_to_finding`
(`lybra/adapters.py`) normaliza las CVE de Nuclei a mayúsculas —sin eso la fusión por `dedup_key` con
Lybra/OpenVAS nunca ocurriría— y marca cada hallazgo `confirmed=True` con un QoD fijo, por ser una
aserción de un matcher estructurado y no un patrón de texto como el de Nikto. `NucleiScanTask` corre
con un perfil de severidad acotado por defecto (excluye `info` a propósito), `-duc` (plantillas
horneadas en el Dockerfile, sin red a mitad de escaneo) y lee la versión real del feed del propio
banner de arranque del binario. `NucleiScanManager` fusiona los hallazgos dentro del escaneo (Nuclei
repite la misma plantilla por cada `matched-at`) y aplica el ciclo de vida contra el Nuclei anterior
del mismo objetivo. El gate de objetivos autorizados (punto 3 de arriba) está aplicado desde el
endpoint `POST /themis/nuclei`, reutilizando `TargetNotAuthorizedError`. El renderizador de PDF de
Lybra se generalizó a una `FindingsPrintingStrategy` compartida (Lybra queda con el mismo
comportamiento exacto) de la que `NucleiPrintingStrategy` es una subclase fina — el "beneficio
colateral" que este mismo apartado anticipaba. En el frontend, Nuclei es una cuarta pestaña del
mundo de escáneres externos, registrada en `constants/scanTypes.js`.

Lo que esta pasada **no** cierra, a propósito: **U2** (Nuclei como corroborador del análisis
profundo — cerrada en una pasada posterior, ver más abajo), **U3** (el oráculo diferencial de
`tests/oracle/`) y **U4** (ingesta de plantillas). Tampoco hay cron de
sincronización del feed de plantillas: se hornean en la imagen y envejecen hasta el siguiente build;
el patrón a seguir cuando se aborde es el de `KbSyncManager` + `ThemisScheduler._schedule_kb_sync`.

#### U2 — Corroborador del análisis profundo

Una vez existe U1, `LybraEngineManager._launch_deep_corroborators` gana a Nuclei con la misma
condición que hoy dispara a Nikto (hay algún servicio HTTP). Es una línea.

**Estado (2026-07-30): ✓ hecha.** Literalmente una línea más un `try/except` a juego con el resto de
corroboradores (`_launch_deep_corroborators`, `managers/lybra_engine.py`): Nuclei se lanza dentro del
mismo `if any(is_http_service(s) for s in services)` que ya gobierna a Nikto, con el mismo perfil de
severidad acotado por defecto que U1 le dio (`severities=None` → `CR.get_nuclei_default_severities()`
dentro de `NucleiScanTask`), y el mismo blindaje *best-effort*: un fallo al lanzarlo no hunde el
escaneo Lybra ni a los demás corroboradores. La autorización del objetivo no se re-comprueba aquí
porque `_launch_deep_corroborators` solo se invoca cuando `is_target_authorized` ya es verdad en la
llamada — el mismo tratamiento que Nikto ya tenía, no una excepción nueva para Nuclei.

Los tests de `test_lybra_deep_analysis.py` pasaron de fijar el conjunto de corroboradores a tres
(`{nmap, nikto, openvas}`) a cuatro, y el escenario "sin servicio HTTP" ahora comprueba que Nikto
**y** Nuclei se saltan igual, no solo Nikto.

**Y aquí aparece una consecuencia de producto que conviene afrontar en vez de dejarla implícita: en
cuanto Nuclei está en el pool, Nikto se queda sin trabajo.** Cubre menos superficie, con datos de peor
calidad (OSVDB frente a CVE + CVSS), y deja de ser el corroborador web. El glosario decía que Nikto
"se queda como corroborador hasta que la Fase R alcance su umbral de precisión"; esta fase adelanta
esa fecha por una vía que no estaba prevista. **La retirada de Nikto no se ejecuta en esta fase** —no
hay prisa y no cuesta nada mantenerlo mientras se compara—, pero sí se declara la intención: el pool
objetivo de herramientas externas es **Nmap + Nuclei**, más limpio que los tres actuales. La decisión
se toma con el número de U3, no con una fecha.

#### U3 — El oráculo diferencial

Es la segunda pata del §8, y con U1 hecha es casi gratis: el traductor ya existe, solo hay que
ejecutarlo en un contenedor efímero del banco y comparar. Mide lo que la verdad por etiqueta conocida
no puede medir: **falsos positivos** en objetivos sin etiqueta previa, y hallazgos que se nos escapan.
Nunca corre en producción como oráculo; el binario que sí corre en producción es el de U1, que es otro
uso y otro riesgo.

**Estado (2026-07-30): ✓ hecha**, `tests/oracle/test_lybra_nuclei_differential_bench.py`. Requiere
Docker y un binario `nuclei` real con plantillas ya descargadas (`nuclei -update-templates`, una vez);
se salta entero si falta cualquiera de los dos, igual que el resto del paquete `oracle`. El método:
lanzar un escaneo Lybra de autodescubrimiento y, por separado, el binario real de Nuclei —ambos contra
el mismo contenedor, por la red real— y comparar el conjunto de CVE que cada uno reporta. El traductor
es literalmente el mismo `nuclei_result_to_finding` de U1 (`lybra/adapters.py`), invocado directo sobre
el JSONL sin pasar por `NucleiScanManager`/TaskQueue — el mismo criterio que el resto de tests evita
Redis real (`conftest.py`, T5).

**Los objetivos son los tres que `test_lybra_oracle_bench.py` ya levanta** (`httpd:2.4.49`, el nginx
con `.git/config` expuesto, el nginx TLS autofirmado) — reimportados como fixtures tal cual, sin
duplicar contenedores. "Sin etiqueta previa" (§8) describe el **método**, no una exigencia de
contenedor nuevo: la comparación deriva su propia verdad de Nuclei en tiempo real, sin consultar la
lista de CVEs que el otro módulo ya conoce de antemano.

**El número, medido:** sobre los tres objetivos, **0 CVE corroborados, 0 hallazgos de Nuclei que se
escapan, 1 posible falso positivo** (`CVE-2021-41773` en `httpd_2449_port`, solo del lado de Lybra).

Ese resultado no es un fallo del banco ni del motor — es el hallazgo real que motivó reescribir la
guarda de cordura del módulo. La aserción original esperaba que Nuclei corroborase `CVE-2021-41773`
contra el mismo `httpd:2.4.49` que el banco de verdad-por-etiqueta usa, y falló. Investigado a mano
(`nuclei -id CVE-2021-41773 -debug`): la plantilla de Nuclei para esa CVE es una **explotación activa**
(RCE vía `mod_cgi`, un `POST /cgi-bin/../../../bin/sh`) que exige `ExecCGI` habilitado — algo que ni
`httpd:2.4.49` vanilla ni siquiera `vulhub/httpd:2.4.49` traen listo con un `docker run` suelto (vulhub
monta configuración extra vía `docker-compose`, que este banco no reproduce). La detección de Lybra,
en cambio, es por versión/banner vía la KB — nunca intenta explotar nada. Son **señales distintas que
no tienen por qué coincidir**: una CVE puede estar presente por versión sin que el contenedor concreto
esté configurado de forma explotable. Descubrir esto es exactamente el trabajo que un oráculo
diferencial promete, aunque el resultado no fuera el esperado de entrada.

La guarda de cordura del módulo (que si fallara apuntaría a un banco roto, no a un motor que falla en
silencio) se reescribió sobre una señal que sí es puramente pasiva en ambos lados: la exposición de
`.git/config`. Nuclei tiene una plantilla (`git-config`) que solo hace un `GET` y compara contenido,
igual que el check propio de Lybra — sin condición de explotación de por medio. Verificado por separado
que dispara de forma fiable contra el fixture (`test_nuclei_translator_pipeline_corroborates_a_real_exposure`),
confirmando que el subproceso, el parseo del JSONL y el traductor funcionan de punta a punta — el "1
falso positivo" de arriba es limpio: no es un artefacto de la tubería de medición.

**Consecuencia para U4 y para el pool objetivo declarado en U2.** El único CVE con explotación activa
disponible en el banco actual no era genuinamente explotable, así que esta pasada no aporta evidencia
sobre cuántas CVE activas Nuclei y Lybra coinciden de verdad — el banco necesita al menos un contenedor
correctamente configurado como explotable (siguiendo el `docker-compose.yml` real de vulhub, no un
`docker run` suelto) antes de que el número de falsos positivos sea representativo. Es deuda anotada,
no bloqueante: la mecánica completa (banco, traductor, comparación, guarda de cordura) ya está
verificada y funcionando; lo que falta es un catálogo de objetivos más rico, el mismo "hay que
escalar" que el §8 ya señalaba para la primera pata.

#### U4 — La ingesta de plantillas, medida antes de decidirse

Éste es el papel que **no** entrega esta fase, y conviene ser explícito sobre por qué. El
`CheckRuntime` actual (`lybra/checks.py`) entiende un subconjunto pequeño del lenguaje de Nuclei:

| Nuclei | `CheckRuntime` hoy |
|---|---|
| Matchers `status`, `word`, `regex` | ✓ |
| Matchers `binary`, `size`, `dsl`, `favicon` | ✗ — `dsl` es un lenguaje de expresiones entero |
| `extractors` + interpolación `{{var}}` | ✗ |
| `payloads` + `attack: batteringram/pitchfork/clusterbomb` | ✗ |
| `condition: and` **dentro** de un matcher de words | ✗ — `Matcher._raw_match` fija `any()` |
| `req-condition`, `stop-at-first-match` entre peticiones | ✗ — `_run_check` combina siempre con AND |
| `interactsh` (out-of-band) | ✗, y debe seguir así |
| `code:`, `flow:` (JavaScript) | ✗, y debe seguir así — ya descartado en la Fase R |
| `network` con `inputs`/`type: hex` (payload binario) | ✗ — `Request.send` es `str` y se codifica en UTF-8 |

Esa última fila tiene premio, y es la convergencia que justifica tratar U y R como piezas del mismo
trabajo: la Fase N dejó registrado que los checks "SMB sin firma" y "SMBv1 habilitado" **no se pudieron
construir** porque *"el runtime declarativo actual solo compara texto decodificado, y una respuesta
SMB2 es binaria"*. **Adoptar el esquema `network` de Nuclei —`inputs` con `type: hex` más un matcher
`binary`— desbloquea exactamente ese hueco ya documentado.** No es una coincidencia forzada: es la
misma carencia vista desde dos sitios.

Por tanto, "ingerir el feed de Nuclei" nunca va a significar ingerirlo entero, sino **la fracción que
use solo el subconjunto que soportemos**, descartando el resto. Y esa fracción hoy no la sabemos. El
entregable de U4 en esta fase no es código de producto: es **la medición**. Un script que lea el
árbol de plantillas **ya instalado** —el mismo que el binario de U1 usa, ver la subsección de la
copia única más abajo; no un clon aparte de `projectdiscovery/nuclei-templates`—, parsee las
plantillas y las clasifique por las características que requieren, produciendo un histograma —cuántas se ingieren hoy tal cual, cuántas necesitan
`extractors`, cuántas `dsl`, cuántas son `code`/`flow` y quedan descartadas por diseño—. Ese número
decide la Fase R:

- **Fracción alta** → la migración del feed a YAML y la ingesta selectiva valen la pena, y R las
  acomete con el esquema de Nuclei como referencia.
- **Fracción baja** → R renuncia a ingerir, se queda con `network` y `script`, y sigue siendo un buen
  resultado. El feed propio puede migrar a YAML igualmente, por legibilidad, pero deja de ser una
  promesa de compatibilidad.

Dos cautelas que no se descuidan: **auditar la licencia** del repositorio de plantillas antes de
redistribuir nada en un feed propio, y **ingerir en tiempo de sincronización, no vendorizar** — el
repositorio cambia a diario y meterlo en el checkout es peso y superficie de suministro que no
queremos; el patrón de `KbSyncManager` ya existe para esto.

**Estado (2026-07-31): el instrumento está construido; falta pasarlo.**
`tools/nuclei_template_census.py` clasifica el árbol y emite el histograma, apoyado en
`lybra/ingest/classifier.py`. Tres decisiones de lo construido:

1. **El censo no clona el repositorio upstream**, al contrario de lo que este mismo apartado daba
   por hecho al escribirse. Lee el árbol que el binario usa en producción, vía el getter único de
   la ruta — que es la consecuencia directa de la restricción de copia única. El número medido pasa
   a corresponder a la versión que de verdad corre, no a `main` del día del clon.
2. **El clasificador es la misma pieza que usará la ingesta** (`is_ingestible`). Si el censo y la
   ingesta midieran con criterios distintos, el número no describiría lo que la ingesta acabaría
   haciendo; compartiendo módulo no pueden discrepar.
3. **El umbral se fijó por escrito antes de medir**, que era la cautela que este plan se había
   impuesto: **≥ 25 % de las plantillas HTTP en el cubo `ingestible_now`**. Está en el docstring y
   en una constante, y el script imprime el veredicto él solo — no hay margen para racionalizar el
   resultado a posteriori.

Los cubos son cinco, ordenados por esfuerzo, y una plantilla cae en el del *peor* obstáculo que
presenta: `ingestible_now` · `needs_extractors` (extractors e interpolación real — `{{BaseURL}}` no
cuenta, aparece en casi todas y el runtime ya la resuelve) · `needs_payloads_or_binary` (payloads,
matchers `binary`/`size`/`dsl`, `inputs` con `type: hex`, `condition` dentro de un matcher,
`req-condition`) · `rejected_by_design` (`code`, `flow`, `javascript`) · `out_of_scope` (`dns`,
`headless`, `whois`...). El histograma cuenta además cada obstáculo por separado, así que dirá no
solo cuántas plantillas fallan sino **por qué** — y en particular cuántas usan `input-hex`, que es
la señal que decide si el camino binario de la Fase N merece la pena.

⚠ **El número sigue pendiente del equipo completo**: exige el feed instalado. Los tests de aquí
cubren el criterio de clasificación (25 casos con plantillas escritas a mano), no el resultado del
censo. El quinto criterio de la Definición de Hecho de esta fase sigue abierto hasta que alguien
ejecute el script en esa máquina y anote el veredicto.

#### Una sola copia de las plantillas, y qué no se puede verificar en este equipo

Dos restricciones que gobiernan cómo se ejecutan U4 y el cierre de R, anotadas antes de escribir
nada para que no se descubran a mitad.

**La primera es de diseño: Themis tiene una única copia de las plantillas de Nuclei.** Con U1 ya
entregada, el binario que el usuario lanza desde el panel y la ingesta que la Fase R contempla
apuntan al *mismo* árbol de ficheros — no a dos, y desde luego no a uno copiado del otro. Hoy la
ubicación ya tiene un único punto de verdad, `CR.get_nuclei_templates_dir()`, pero su valor por
defecto es la cadena vacía, que significa "deja que el binario use su ubicación propia": un
contrato que el binario entiende y que Python no puede resolver. En cuanto haya un segundo
consumidor que necesite *leer* las plantillas en vez de solo pasárselas por `-templates`, ese
vacío deja de valer.

**Estado (2026-07-31): el almacén está construido.**
`themis/services/nuclei_templates.py` (`NucleiTemplateStore` + `resolve_templates_dir`) es la
autoridad única, y `NucleiScanTask` ya le pide la ruta en vez de leer la configuración por su
cuenta. La resolución no obligó a tocar el `Dockerfile`: la tercera prioridad
(`~/.local/nuclei-templates`) es exactamente donde su `nuclei -update-templates` deja las
plantillas cuando corre como root, así que el árbol horneado se encuentra solo. Fijar
`templatesDir` explícitamente sigue siendo endurecimiento recomendable, pero exige verificar el
nombre del flag de descarga contra el binario fijado (convención `Q_NUCLEI` del propio Dockerfile),
y por eso no se hizo a ciegas desde un equipo sin la imagen. `PyYAML` pasa a estar declarado en
`requirements.txt`: estaba disponible de forma transitiva, y ahora hay código de primera parte que
lo importa.

De ahí sale una pieza pequeña y previa a todo lo demás: un **almacén de plantillas** con tres
consumidores y ningún duplicado — `NucleiScanTask`, que le pide la ruta efectiva; la ingesta de
Lybra, que itera y parsea esa misma ruta; y el censo de U4, que mide sobre esa misma ruta. Cuatro
consecuencias, cada una decidida aquí y no más adelante:

1. **El censo de U4 no clona el repositorio de plantillas**, al contrario de lo que la primera
   redacción de U4 daba por hecho: lee el árbol ya instalado. El número medido pasa a
   corresponder a la versión que corre de verdad en producción, no a `main` del día del clon.
2. **`templatesDir` deja de poder estar vacío.** El almacén necesita resolución explícita, y lo
   limpio es fijarla en el `Dockerfile`/`SecOpsConfig.json` para que el binario y el lector no
   puedan discrepar nunca en silencio.
3. **La ingesta traduce en memoria; no escribe plantillas traducidas.** `checks_feed.json` sigue
   siendo *solo* el feed propio. Como mucho, una caché de índice invalidada por versión de
   plantillas — nunca el cuerpo de una plantilla ajena copiado a nuestro lado.
4. **La procedencia se separa, lo que resuelve de paso el `feed_version` global.** Los checks
   propios siguen siendo `lybra:{id}@{v}` + `CHECKS_FEED_VERSION`; los ingeridos son
   `nuclei:{template-id}@{templatesVersion}` + `get_nuclei_templates_version()`. Dos orígenes, dos
   versiones, un solo árbol en disco.

Y una decisión de producto que la copia única destapa y que **se toma con el número de U4, no
antes**: si Lybra ingiere las mismas plantillas que el binario ejecuta como corroborador (U2), en
un `deep=True` el mismo check toca el objetivo dos veces. `dedup_key` fundirá los hallazgos, pero
el tráfico se duplica igual. Las dos salidas razonables son que el subconjunto ingerido sea el
complementario de lo que el binario ya cubre, o que la ingesta sirva sobre todo a despliegues sin
binario.

*(Nota de infraestructura: hoy `api` y `ellysia-worker` construyen del mismo Dockerfile y hornean
copias idénticas en build, así que son coherentes por construcción. Si el refresco de plantillas
pasa algún día a tiempo de ejecución —la deuda del cron que el propio Dockerfile documenta—,
`templatesDir` **tiene que** ser un volumen nombrado compartido entre ambos, o los dos contenedores
divergen sin que nada avise.)*

**La segunda restricción es de entorno.** El checkout de trabajo es Windows, sin binario `nuclei`,
sin las plantillas horneadas y **sin la KB poblada**. Eso no impide avanzar, pero sí obliga a saber
qué se está verificando de verdad en cada sitio:

| Trabajo | Verificable en el equipo de desarrollo | ⚠ Requiere el equipo completo |
|---|---|---|
| **R — tipo de check `script`** | Runtime, registro y tests con socket falso (el patrón que `smb.py` ya usa) | Disparo real contra Samba/Windows — el dissector SMB **ya estaba sin verificar** contra un servidor real |
| **U4 — el censo** | La lógica del clasificador, con plantillas de muestra escritas a mano (✓ hecho) | ⚠ **El número en sí**: exige el árbol de plantillas real. Ejecutar `python tools/nuclei_template_census.py` y anotar el veredicto |
| **El almacén de plantillas** | Resolución de rutas y parseo contra un directorio de prueba | ⚠ Que la ruta resuelta sea la misma que el binario usa de verdad |
| **R — migración del feed a YAML** | Todo (parseo, equivalencia con el JSON actual) — ✓ hecho | — |
| **R — ingesta de plantillas** | Traductor plantilla→`Check`, índice de selección (✓ hecho, apagado por defecto) | ⚠ Ejecución de los checks ingeridos contra objetivos reales, y la decisión de encender el flag (depende del censo) |
| **R — precisión ≥ 0,9 medida** | Nada | ⚠ **Todo**: `tests/oracle/` exige Docker y un `nuclei` con plantillas |
| **Cualquier CPE→CVE de extremo a extremo** | Nada | ⚠ **Todo**: sin KB poblada el motor no falla, devuelve vacío — que es peor, porque se lee como "objetivo limpio" |
| **`nuclei_templates_version.txt`** | Nada | ⚠ El `Dockerfile` vuelca ahí la salida de `nuclei -version`, que es la versión **del motor**, no la de plantillas — mientras que el regex de `_check_output_line` sí captura la de plantillas. Probable etiqueta equivocada en el *fallback*; sin la imagen no se puede confirmar |

La consecuencia práctica de la fila de la KB gobierna a todas las demás: **un test que aquí dé
"0 hallazgos" no es evidencia de nada.** Lo que se escriba en el equipo de desarrollo asevera sobre
mocks de KB o sobre la mecánica —¿se seleccionó el check?, ¿se parseó la plantilla?—, nunca sobre el
recuento final de CVEs.

#### Qué NO incluye esta fase

Para que no se disperse: no incluye la ingesta real de plantillas (es U4→Fase R, condicionada a la
medición), no incluye la migración del feed propio a YAML (Fase R), no incluye la retirada de Nikto
(se declara la intención, se ejecuta con el número de U3), y no incluye ninguna tabla de resultados
nativa para Nuclei — por decisión, no por omisión.

#### Definición de hecho

**Damos la Fase U por hecha cuando** (1) un usuario lanza un escaneo de Nuclei desde el panel, con
perfil acotado y objetivo autorizado, y descarga su PDF — **✓**; (2) sus hallazgos llegan a `Finding`
con `cve_ids`, `cvss_score`, `check_id` y `feed_version` poblados, y se deduplican con los de otras
fuentes sobre el mismo activo — **✓**; (3) el análisis profundo de Lybra lo dispara como corroborador
— **✓**; (4) el banco produce un número de falsos positivos frente a Nuclei sobre al menos tres
objetivos sin etiqueta previa — **✓, medido: 0 corroborados / 0 se escapan / 1 posible falso positivo,
con la salvedad anotada arriba de que el catálogo de objetivos explotables sigue siendo pobre**; y (5)
existe el histograma de ingestibilidad del feed de plantillas, con una recomendación escrita de sí o no
para U4 — **el instrumento existe y el umbral está fijado (2026-07-31); falta ejecutarlo en la máquina
con el feed instalado y anotar el veredicto**.

La Fase U completa sigue en ◐ parcial: los cuatro primeros criterios están cerrados, mide una vara real
— pero el quinto es U4, y U4 explícitamente no entrega código de producto en esta pasada, solo la
medición que decide si vale la pena.

---

### Fase R — El runtime de detección propio · pista de bajo nivel · ◐ parcial · **su cierre depende de la Fase U**

Ésta es la capa de identidad, la L2. Es lo que convierte a Lybra de un correlacionador en un motor
con criterio propio de detección: un runtime único de comprobaciones —versionado, extensible y
reproducible— que decide qué comprobar y produce `Finding` normalizados sin depender de Nikto.

El runtime maneja cinco tipos de comprobación bajo el mismo motor:

| `type` | Para qué sirve | Con qué lo hace | Estado |
|---|---|---|---|
| `version` | Detección por CPE→CVE (Fase 1) | La KB local, sin tocar el objetivo | ✓ |
| `http` | Petición más matchers (el 90 % de web/banner) | Cliente HTTP propio, declarativo | ✓ 10 checks |
| `ssl` | Higiene de TLS | Python de primera parte (`ssl`/`cryptography`) | ✓ 3 checks |
| `network` | **Sondas de protocolo crudas** | Socket propio, declarativo | ✓ 2 checks (lo aportó la Fase N) |
| `script` | Lógica compleja, multipaso o binaria | Plugin en Python, de primera parte y revisado | ✓ 1 check (2026-07-31) |

El grueso de las comprobaciones debe escribirse de forma **declarativa**, con un esquema
razonablemente compatible con las plantillas de Nuclei. El feed actual es JSON; el diseño pide YAML.
Así se lee un check típico:

```yaml
id: apache-2449-path-traversal
version: 3                            # junto con el id forma "lybra:apache-2449-path-traversal@3"
type: http
category: exposed_path
severity: HIGH
service: http
cpe: "cpe:2.3:a:apache:http_server:2.4.49:*"   # así se encadena desde un check de versión
mode: aggressive                      # safe | aggressive — respeta el gate de autorización (§9)
requests:
  - method: GET
    path: "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers-condition: and
    matchers:
      - { type: status, value: [200] }
      - { type: word, part: body, words: ["root:x:0:0:"] }
finding:
  title: "Apache 2.4.49 — Path Traversal (CVE-2021-41773)"
  cve_ids: ["CVE-2021-41773"]
  qod: 99
  confirmed: true
```

El lenguaje ofrece **matchers** (`status`, `word`, `regex`, `binary`, `size`, `time`, `dsl`,
combinables con `and`/`or` y negables), **extractors** (`regex`, `kval`, `json`, `xpath`) cuyos
resultados se interpolan con `{{var}}`, y conjuntos de **payloads** para fuzzing con las estrategias
`batteringram`, `pitchfork` y `clusterbomb`.

La verdadera novedad frente a Nuclei son los **workflows de tipo versión→confirmador**. Un check de
versión que da positivo encadena automáticamente su confirmador activo: si el confirmador tiene
éxito, el hallazgo asciende de `qod=70` a `qod=99` y de `confirmed=false` a `true`. Esa distinción
entre la hipótesis (te veo la versión, probablemente eres vulnerable) y el hecho (lo he comprobado)
es la filosofía "Controls, Not Counts", y es lo que ninguna lista plana de hallazgos captura.

La compatibilidad con Nuclei es un **multiplicador de fuerza**: permite ingerir su feed comunitario
como equivalente a un NVT feed, pero para comprobaciones activas y con una diferencia decisiva
respecto a OpenVAS — **Nuclei es un feed de datos, no un servicio**. Ingerir plantillas YAML no nos
acopla a ningún proceso ajeno en tiempo de ejecución; traducirlas en el momento de la ingesta nos
deja el criterio a nosotros. Se descartan las plantillas que ejecutan código arbitrario (`code:`) y
las de protocolos que no soportemos. Como Nuclei no tiene `qod` ni `confirmed`, los derivamos por
heurística del matcher. Toda plantilla externa entra en modo `safe` por defecto, y hay que auditar su
licencia y registrar su procedencia antes de redistribuir nuestro feed.

Sobre los checks de tipo `script`: solo se admiten los de **primera parte**, escritos y revisados por
nosotros, ejecutándose en proceso con una API restringida (primitivas `http`, `tls`, `probe`, límites
de tiempo y tasa, gate safe/aggressive). No ejecutamos código Python de terceros en proceso, porque
Python no se puede aislar con garantías dentro del mismo proceso. Si algún día quisiéramos aceptar
plugins de terceros, la vía es aislarlos en un subproceso con `rlimit`/seccomp e IPC estrecho.

**Damos la fase por hecha cuando** el motor detecta por versión y confirma activamente al menos las
tres primeras familias, existen los tipos `network` y `script`, el feed vive en YAML, y el `qod` sube
de 70 a 99 en lo confirmado.

**Estado (2026-07-31): el feed vive en YAML y la ingesta está construida (apagada).**

*La migración a YAML* fue un cambio de formato y no de comportamiento, y eso se verificó en vez de
suponerse: ambos deserializadores alimentan el mismo `_parse_check`, así que se comprobó que el JSON
antiguo y el YAML nuevo producen objetos `Check` **idénticos campo a campo** antes de retirar el
JSON. El cargador conserva las dos rutas (despacha por extensión) porque un feed externo puede venir
en cualquiera de los dos formatos. La razón de fondo de la migración, más allá de la compatibilidad
con Nuclei, es que **YAML admite comentarios** — en un feed de reglas de detección, eso es la
diferencia entre poder explicar por qué existe un check y no poder.

*La ingesta* son tres piezas en `lybra/ingest/`: el clasificador (compartido con el censo de U4), el
traductor y el selector. Tres decisiones que conviene dejar escritas:

1. **Traducir a medias no es una opción.** Una plantilla con extractors o payloads podría "casi"
   traducirse ignorando esas partes, y el resultado sería un check que corre, no falla, y comprueba
   algo distinto de lo que la plantilla dice — la peor clase de error en un motor de detección,
   porque produce hallazgos con la confianza de un check confirmado. Ante la duda se descarta. El
   mismo criterio retira las plantillas HTTP **multi-ruta**: Nuclei dispara si *alguna* ruta casa y
   el runtime combina con AND, así que traducirla la volvería más estricta que el original.
2. **Procedencia, no autoría.** `Check` gana `namespace` y `feed_version` (con defaults que no
   cambian nada de lo existente). Un check traducido nace `nuclei:git-config@1`, no `lybra:...`, y
   sella la versión del árbol de plantillas en vez del `CHECKS_FEED_VERSION` propio — que era el
   problema real que se había identificado: un único global deja de ser verdad en cuanto hay dos
   feeds con líneas de versión independientes. Y toda plantilla externa entra en `mode="safe"` sin
   excepción, porque no las hemos revisado una a una.
3. **El selector, que el diseño original no había estimado.** `CheckRuntime.run` es
   O(servicios × checks) y el limitador impone 0,2 s por petición y host: 3.000 plantillas contra un
   solo servicio son más de diez minutos de tráfico, y contra un host con cuatro puertos web, casi
   una hora. Sin esta capa, activar la ingesta no sería una mejora sino un disparo en el pie. Filtra
   por severidad mínima, por relevancia de etiqueta (un check de WordPress no se lanza contra un
   nginx; uno *sin* etiquetas de producto sí, porque es genérico y son justo los más aplicables) y
   por un tope duro, ordenando por severidad para que lo que el tope recorte sea lo menos grave. Se
   aplica **antes** de construir el runtime, así que el feed propio no paga nada por que exista.

**Está apagada por defecto (`themis.lybra.ingest.enabled = false`), y a conciencia:** el flag decide
la *activación*, no la existencia del código. Quien la enciende es el número del censo de U4, que
sigue pendiente del equipo con el feed instalado. ⚠ La ejecución real de checks ingeridos contra
objetivos tampoco se ha probado aquí — los tests cubren traducción, procedencia y selección.

**El prerrequisito de la Fase U, delimitado con precisión.** Tres de los cuatro entregables que quedan
para cerrar esta fase dependen de que la Fase U se haya hecho antes, y uno no:

| Lo que falta de R | ¿Depende de U? | Por qué |
|---|---|---|
| **Migración del feed a YAML** | **Sí** | El esquema al que se migra es el de Nuclei; migrar antes de saber qué fracción del lenguaje vamos a soportar (U4) es elegir la forma a ciegas y arriesgarse a migrar dos veces |
| **Ingesta de plantillas externas** | **Sí** | Es literalmente U4. Sin el histograma de ingestibilidad no se sabe si vale la pena construirla |
| **Precisión ≥ 0,9 medida** | **Sí** | El numerador de falsos positivos lo da el oráculo diferencial (U3). Sin él, "precisión 0,9" sigue siendo una frase, como reconoce el §8 |
| **El tipo de check `script`** | **No** | Es un plugin de primera parte en Python, sin relación con Nuclei. Se puede construir en cualquier momento — **✓ hecho el 2026-07-31**, ver nota de estado |

Y una delimitación en la otra dirección, para que el prerrequisito no estrangule al roadmap: **la Fase
U no bloquea a la Fase N.** El tipo de check `network` que N necesitaba como vehículo declarativo **ya
está construido** (lo aportó la propia Fase N, ver su nota de estado), así que N puede seguir avanzando
—dissectors nuevos, checks de configuración de red— sin esperar a nada de esto. Lo único que la Fase U
condiciona es el **cierre** de R, no su existencia ni la fase prioritaria que se apoya en ella.

**Estado (2026-07-31): el tipo `script` existe.** `lybra/script_checks.py` aporta los plugins de
primera parte y `CheckRuntime` los recibe **por inyección** (`script_plugins=`), no por importación:
`checks.py` no puede importar `fingerprinting` sin cerrar un ciclo, porque los dissectors importan de
él sus predicados de aplicabilidad. El reparto acabó siendo el mismo que ya existía para los
dissectors — la clase base (`ScriptPlugin`) y su contexto restringido (`ScriptContext`) viven junto al
runtime, igual que `Dissector` vive en `dispatch.py`; los plugins concretos viven aparte, igual que
`SmbDissector` vive en `smb.py`.

El primer plugin, `smb-signing-not-required` (feed subido a `lybra-checks-4`), cierra **la mitad** del
hueco que la Fase N había dejado anotado: el dissector de SMB ya negociaba y ya leía el `SecurityMode`
del servidor, así que el hecho estaba observado y solo faltaba un vehículo para convertirlo en
hallazgo — sin necesitar el matcher `binary` ni el esquema `type: hex`, que dependen de la medición de
U4. **La otra mitad, "SMBv1 habilitado", sigue sin construirse y no salía gratis aquí:** `SmbProbe`
solo ofrece dialectos SMB2, y detectar SMBv1 exige un paquete `NEGOTIATE` de SMB1 que es trabajo nuevo
en `smb.py`.

Un plugin que lance una excepción se contiene en su propio check en vez de hundir el escaneo: son de
primera parte, pero ejecutan lógica de protocolo multipaso, y que uno reviente ante la respuesta
malformada de algún appliance debe costar ese check y nada más. Los tests cubren la mecánica con una
sonda falsa (dispara sin firma obligatoria, calla con ella, calla sin negociación, calla ante un
dialecto desconocido, y el feed y el registro concuerdan). ⚠ **El disparo contra un Samba/Windows real
sigue pendiente del equipo completo** — la misma deuda que el dissector ya arrastraba.

**Estado (2026-07-11, sigue vigente en lo demás):** la mecánica está completa — hoy son **16 checks
en 5 familias** (`exposed_path` ×7, `security_header` ×3, `tls` ×3, `network` ×2, `script` ×1;
el recuento de "13 en 3 familias" de esta nota se quedó desfasado al añadirse `network` y `script`),
todas bajo el mismo `CheckRuntime`, todas `confirmed=true`/`qod=99` cuando disparan, feed versionado
(`lybra-checks-1`). La familia `tls` tiene banco automatizado: dos fixtures de contenedor local
(nginx con certificado autofirmado generado en el arranque, sin bind-mount) cubren
`tls-self-signed-cert` y `tls-expired-cert` con aserciones contra un handshake real — el segundo
genera el certificado bajo `libfaketime` con el reloj adelantado a 2020 (sin necesitar
`CAP_SYS_TIME`) para producirlo ya caducado. La fixture "sana" sirve de control negativo.
`tls-deprecated-protocol` queda sin cubrir a propósito: el OpenSSL moderno de la imagen base rechaza
negociar SSLv3/TLSv1.0/TLSv1.1 aunque se fuerce por configuración — hueco documentado, no descubierto
por sorpresa. Lo que falta para cerrarla es la medición formal de precisión ≥0,9 a escala, más los
dos tipos de check pendientes y la migración a YAML.

---

### Fase O — Verificación de backports con feeds de distribución · pista de correlación · ○ planificada

**El objetivo** es reducir los falsos positivos de la detección por versión **sin entrar en el
host**. El problema de los backports —una distro parchea sin subir el número de versión visible— es
la causa nº 1 de falsos positivos; el `qod=70` y `confirmed=false` de la Fase 1 son un paliativo. La
Fase O lo ataca de raíz consultando la *verdad del proveedor*: los avisos de Debian (DSA/USN), Red
Hat (RHSA) y SUSE, que dicen exactamente qué paquete y versión ya está corregido. Es el equivalente
propio de Notus, la pieza de Greenbone que hace este mismo trabajo.

**Qué ya existe y qué falta.** La Fase 2 mantiene un espejo de NVD/KEV/EPSS en `kb.py`, pero no de
OVAL ni de advisories de distribución.

**Qué construir.** Dos modelos nuevos en `model.py`: `DistroAdvisory` (`advisory_id` como `DSA-1234`,
`vendor`, `product`, `fixed_version`, `published`) y `DistroPkgStatus` (`vendor`, `release` —p. ej.
`debian-12`—, `package`, `version_installed`, `fixed_in`, `status` —`fixed`|`vulnerable`|`unknown`—).
Un ingestor `kb.py::ingest_oval` que parsea los feeds OVAL/CSAF (mismo patrón que `ingest_nvd_cve`), y
un `KbSyncManager.sync_oval` con su fuente en `themis.kb.sources.oval`. La consulta clave: dado un
`Finding` de categoría `outdated_software` con CPE y versión resueltos, si el feed del proveedor marca
esa `product@version` como `fixed` en la distribución inferida, el hallazgo se *desciende* a
`state="fixed"` y `confirmed=false` **sin re-escanear**, registrando `check_id="lybra:oval-backport"`.
Si lo marca como `vulnerable`, *asciende* a `confirmed=true` y `qod=90`, porque hay dos fuentes
independientes que coinciden. El manager aplica este paso en `_run_lybra` tras `engine.analyze`.

Nota de sinergia con la Fase I: el inventario del agente da la distribución y la versión exacta del
paquete, que es justo la entrada que esta fase necesita. Juntas, las Fases I y O cubren el problema
de los backports mejor de lo que OpenVAS lo cubría, por dos caminos independientes.

**Damos la fase por hecha cuando** un hallazgo por versión sobre un paquete parcheado por backport se
marca automáticamente como `fixed` sin escaneo autenticado, y la tasa de falsos positivos del banco
(§10) baja al menos un 40 % en imágenes Debian/RHEL.

---

### Fase D — Motor de credenciales débiles y por defecto · pista de bajo nivel · ○ planificada

**El objetivo** es elevar las credenciales por defecto a un **subsistema propio** con criterio de
seguridad. Probar `admin/admin` no es un check HTTP más: es una operación que *escribe* en el
objetivo, que puede bloquear cuentas, que genera ruido en el SIEM del objetivo y que exige un control
de tasa y un presupuesto muy distintos a un GET de `.git/config`.

**Qué construir.** Un `CredentialRuntime` (en `lybra/credentials.py`) que recibe un `Service` y un
*credential pair set* versionado (`credentials_feed.json`: Tomcat, Jenkins, routers por defecto, FTP
anónimo, paneles web comunes). Reglas de seguridad obligatorias: (1) solo corre en modo `aggressive`
y contra objetivos del registro de autorización (§9); (2) máximo *N* intentos por servicio y escaneo
(`themis.lybra.credentials.maxAttempts`, por defecto 3) para no provocar lockout; (3) parada inmediata
al primer éxito; (4) reutiliza el `HostRateLimiter` con un intervalo mayor. Un éxito produce un
`Finding` con `category="default_credentials"`, `confirmed=true`, `qod=99`, y dispara captura de
evidencia (Fase E) que incluye *qué par* funcionó **sin persistir la contraseña en claro**. Reutiliza
los dissectors de la Fase N para llegar a servicios no-HTTP (FTP, SSH, Telnet, bases de datos).

**Damos la fase por hecha cuando** un escaneo agresivo autorizado detecta credenciales por defecto en
un panel Tomcat/Jenkins de laboratorio, respeta el límite de intentos, y el plaintext nunca aparece en
la base de datos ni en la evidencia.

---

### Fase F — El fingerprinting propio · pista de bajo nivel · ◐ parcial

**El objetivo** es identificar servicio, producto y versión con criterio propio, sin depender de
`nmap -sV`, y con una confianza medible. Es el ojo del motor. La Fase N es, en rigor, su extensión a
protocolos no-web; esta fase cubre lo que queda del lado web y de calibración.

Lo pendiente aquí es **JARM** —un fingerprint del lado del servidor que envía diez ClientHello
deliberadamente distintos y hashea el conjunto de respuestas— y, con mucho menos peso porque su
retorno es bajo, un fingerprint de sistema operativo basado en detalles del stack TCP/IP (TTL inicial,
tamaño de ventana, orden de las opciones TCP). El principio que gobierna esta capa es la calibración
por oráculo: Nmap `-sV` es la verdad de referencia en el laboratorio.

**Damos la fase por hecha cuando** para los servicios comunes la concordancia con Nmap alcanza 0,90
por familia, medido en el banco de laboratorio **y** en objetivos reales autorizados (paridad
laboratorio/real, §9).

**Estado (2026-07-11):** el lado de laboratorio está automatizado —
`tests/oracle/test_lybra_concordance_bench.py` reutiliza las funciones puras de
`scripts/lybra_concordance_bench.py` contra 6 contenedores Docker variados: Apache con versión en
`Server`, nginx con versión, nginx con `server_tokens off`, HTTPS con certificado autofirmado, SSH
(banner + HASSH real) y un caso límite sin cabecera `Server`. Concordancia 1.00 sobre los 5 objetivos
con señal identificable. El sexto se mide y documenta aparte: tanto Lybra como el propio Nmap fallan
en identificarlo, así que es un punto ciego compartido, no una derrota frente al oráculo. El lado
"real" sigue en N=3 (`scanme.nmap.org` + dos objetivos autorizados, 1.00) — no se ha vuelto a correr
porque requiere que el usuario amplíe su registro de objetivos autorizados. El dissector HTTP tiene
15 firmas de tecnología externalizadas en `tech_signatures.json` (incluyendo 10 fabricantes de red:
SonicWall, pfSense, MikroTik, Fortinet, Cisco, Ubiquiti, Palo Alto, Netgear, TP-Link, Synology), con
soporte para firmas que solo aparecen en la página de error.

---

### Fase T — El transporte propio · pista de bajo nivel · ◐ parcial

**El objetivo** es que Lybra descubra los puertos por su cuenta. Son las manos del motor.

La base siempre disponible es el `connect-scan` sobre `asyncio`, que no requiere privilegios y ya
existe. Por encima, cuando el worker tiene `CAP_NET_RAW`, un escaneo **SYN sin estado** al estilo de
masscan: el número de secuencia del SYN se *deriva* del objetivo mediante una cookie
(`seq = SipHash(clave, ip_destino‖puerto_destino‖puerto_origen)`), de modo que al llegar un SYN/ACK
basta recomputar la cookie para saber si es respuesta legítima a *nuestro* sondeo, sin haber
almacenado nada.

El **UDP merece trato aparte** y sube de prioridad con esta revisión, porque la Fase N lo necesita:
SNMP (161) es uno de los dissectors de mayor valor y solo responde a una sonda con payload válido. Un
conjunto curado de cinco a diez protocolos de alto valor (DNS, SNMP, NTP, mDNS, IKE), no un barrido
de todos los puertos UDP.

Sea cual sea el modo, el control de ritmo es imprescindible: token-bucket por host más AIMD, que sube
el ritmo linealmente y lo recorta a la mitad ante pérdidas o ICMP de inalcanzable. Siempre se respeta
el gate de autorización.

Aquí es donde —y solo aquí— cobra sentido el repositorio nativo. Si el laboratorio demuestra que el
techo de Python no basta para nuestra superficie real (rangos del tamaño de un `/16`, más de ~50.000
a 100.000 paquetes por segundo sostenidos), se justifica un núcleo en C o Rust consumido por FFI, con
el mismo patrón "núcleo nativo + capa Python verificada" que ya usa Acheron y manteniendo siempre el
fallback en Python puro. Por debajo de ese umbral, no.

**Damos la fase por hecha cuando** la concordancia de puertos con Nmap alcanza 0,95 en laboratorio
**y** en objetivos reales, y la degradación a `connect-scan` sin la capability está probada.

**Estado (2026-07-11):** 1.00 de concordancia de puertos en los 6 objetivos del catálogo de
laboratorio; el lado real sigue en los mismos 3 objetivos (también 1.00), misma reserva sobre la N.
La degradación sin `CAP_NET_RAW` está satisfecha por construcción: no existe ningún camino con socket
raw en el repositorio, así que no hay nada de lo que degradar. El camino SYN sin estado sigue
aparcado a propósito, sin evidencia de que el techo de Python no baste.

---

### Fase 5 — Correlación, ciclo de vida y scoring · pista de correlación · ✓ implementada

**El objetivo** era dar el salto de "listas de hallazgos por escaneo" a "estado de la vulnerabilidad
de cada activo a lo largo del tiempo". Es donde el producto se vuelve claramente superior a lanzar
herramientas sueltas.

La **deduplicación multi-fuente** usa el `dedup_key`: si dos fuentes reportan la misma CVE en el
mismo host y puerto, se funden en un solo `Finding` con procedencia múltiple y un `qod` consolidado.
El **ciclo de vida**, apoyado en `ScanHistoryManager`, compara el escaneo actual con el anterior y
etiqueta cada hallazgo como `open`, `fixed`, `regressed` o `accepted`. Y el **scoring contextual** va
más allá del CVSS crudo: combina gravedad técnica (CVSS), probabilidad real de explotación (EPSS),
existencia de exploits (KEV y `exploit_maturity`) y exposición del activo, que `_classify_network_context`
ya distingue entre LAN privada e Internet pública.

**Estado (2026-07-11):** dedup, ciclo de vida y scoring funcionan. El cambio de sujeto está resuelto:
`HostService` (una fila por host+puerto, actualizada en cada escaneo) permite detectar "puerto nuevo"
y "cambio de versión" como eventos de superficie independientes de cualquier CVE.

**Decisión de diseño (2026-07-11): no se crea una entidad `Asset` separada — `Host` es el activo.**
`HostService.host_id` y `Finding.host_id` ya apuntan a `Host.id`, así que el árbol
`Host → Service → Finding` ya existe en los FKs. Y `Host` ya cumple de forma explícita el trabajo de
identidad de activo: `ScanRepository.get_host_by_ip` existe específicamente para que un mismo
dispositivo visto por IP y por hostname no se duplique. Renombrar `Host` a `Asset` tocaría ~40
referencias en 9 ficheros más el histórico de migraciones, todo para un cambio cosmético. La Fase C
no depende de ese renombrado: su `AssetGroup` puede agrupar filas de `Host` directamente.

---

### Fase 6 — La orquestación: el motor como pipeline por defecto · ✓ implementada

El pipeline completo, con la corroboración ya sin OpenVAS:

```
Lybra Scan
  1. Descubrimiento   → Transporte propio (L0)                          [Fase T]
  2. Fingerprinting   → Dissectors propios, web y no-web (L1)           [Fases F y N]
  3. Detección        → Runtime de checks (L2): por versión y activa    [Fases R + 1 + 2]
  4. Correlación      → dedup, ciclo de vida y scoring                  [Fase 5]
  5. (opcional) Deep  → lanzar Nmap/Nikto y fusionar sus hallazgos      [corroboración]
  6. Enriquecimiento  → scribe/IA genera el análisis y el PDF           [ya existe]
```

El paso 5 es opcional: si el usuario lo solicita, se lanzan las herramientas externas como segunda
opinión que se fusiona en los mismos `Finding`. **El cambio que introduce esta revisión es en ese
paso**: `_launch_deep_corroborators` lanzaba Nmap condicionalmente, Nikto condicionalmente y OpenVAS
*siempre*. Tras el desmontaje (§7, paso E0) solo quedan los dos primeros, ambos condicionales.

**Estado (2026-07-11):** el pipeline técnico cumple esto (autodescubrimiento por defecto,
corroboradores externos apagados por defecto) y la SPA arranca en el mundo `'lybra'`. Rondas
anteriores cerraron los huecos donde el motor propio seguía siendo ciudadano de segunda: los escaneos
programados (`ProgramedScanManager._REQUIRED_ARGS` y `Scheduler._TASK_MAPPING` no tenían entrada para
Lybra y programar uno reventaba con un `KeyError` sin capturar), el historial y las métricas
(`LybraMetricExtractor` + relación `Scan.findings` viewonly), el filtro de documentos (derivado de
`ScanType` en vez de una lista escrita a mano) y la copia de la landing. La generalización que evita
repetir esa arqueología es el registro único del frontend
(`web/app/src/constants/scanTypes.js`: etiquetas, color de gráfico, campos de formulario, formateo de
argumentos), que sustituyó a cuatro mapas duplicados uno por componente — y que es también el sitio
donde el desmontaje de OpenVAS en el frontend se hace de una sola vez.

---

### Etapa 2 — Más allá del host único

Las fases que siguen no están condicionadas por la salida de OpenVAS: son capacidades nuevas que
llevan a Lybra más allá del host único y del escaneo activo. Se enumeran en orden de dependencia, no
de prioridad; todas están **○ planificadas**. Se construyen sobre el código que ya existe en
`themis/lybra/`, respetando las convenciones del proyecto (`UnitOfWork` + repositorios, managers en
`themis/managers/`, endpoints con `@require_oauth_token` y `@require_attributes`, tareas en RQ con
`category` y `external_id`, configuración en `SecOpsConfig.json` bajo `themis.lybra.*`).

**Fase P — Inteligencia pasiva y enriquecimiento OSINT.** Que Lybra *sepa cosas* del objetivo sin
tocarlo. Un tipo de check `passive` que, en lugar de un `fetch` contra el objetivo, llama a un OSINT
fetcher inyectado (mismo patrón que el `cve_lookup` inyectable de `LybraEngine`), consumiendo
Certificate Transparency (`crt.sh`), Shodan/Censys y SecurityTrails/DNSDB con el mismo `urllib` +
backoff de `kb._http_get`. Produce `Finding` de categoría `passive_exposure` (subdominio nuevo,
certificado recién emitido) y enriquece `Service` existentes con un CPE sugerido cuando el fingerprint
propio no lo resolvió. Tarea de RQ con `category="themis.osint"`. El gate de autorización no aplica
—no se toca el objetivo, que es justamente su valor—; sí aplican los términos de servicio de cada
fuente y una caché con TTL.

**Fase E — Captura de evidencia y traza forense.** Que cada `Finding` confirmado lleve detrás la
prueba cruda. Hoy `feed_version` + `check_id` dan reproducibilidad lógica, pero no guardan *lo que el
objetivo respondió*. Un modelo `FindingEvidence` (`finding_id`, `kind` —`http_response`|`ssh_banner`|
`tls_cert`|`probe_output`—, `payload` JSONB, `captured_at`, `content_hash` SHA-256), un
`FindingEvidenceRepository`, y un *evidence recorder* inyectable `(kind, payload) -> None` que el
manager conecta a una lista en memoria volcada en la fase de persistencia. Body truncado a
`themis.lybra.evidence.maxBodyBytes` (8 KiB por defecto); solo se guarda evidencia de hallazgos
`confirmed=true` o de categoría `exposed_path`/`tls`. Endpoint `GET /themis/findings/<id>/evidence`.

**Fase C — Correlación cross-host y riesgo de movimiento lateral.** Razonar por red y no solo por
host. Un `AssetGroup` que agrupa `Host` por CIDR o etiqueta, y un módulo `lybra/lateral.py` (puro,
como `correlation.py`) que identifica patrones de propagación: servicio vulnerable expuesto a la red
(SMB/RDP/WinRM — que la Fase N por fin sabrá identificar), credenciales reutilizadas (cruzando con la
Fase D), host pivot multi-homed (detectable con el `TracerouteManager` existente). Produce un
`Finding` con `category="lateral_risk"`, `host_id=NULL` y `port=NULL`, cuyo score combina el CVSS base
con un factor de propagación. Endpoint `GET /themis/network-risk`.

**Fase A — Detección de exposición de APIs.** Un subtipo `api` sobre `type: http` que extiende el
`Request` con `body` JSON, cabeceras custom y variables de sesión para encadenar login → endpoint.
Familias iniciales: GraphQL (introspection query, field suggestion), REST (endpoints sin auth, spec
OpenAPI expuesta en `/openapi.json`, `/swagger.json`, `/api-docs`) y mass assignment (envío de `role`
o `isAdmin` en un PUT y match del refresco del recurso). Introspección `safe`, mass assignment
`aggressive`. Endpoint `GET /themis/scan/<id>/api-surface`.

**Fase B — Detección de exposición cloud y SaaS.** Un tipo `cloud` con subtipos por proveedor (`s3`,
`azure_blob`, `gcs`, `firebase`, `takeover`) y un `CloudProbe` en `lybra/cloud.py` que lista objetos
de un bucket S3 anónimo, lee un contenedor Blob público, o resuelve un CNAME y comprueba la firma de
un takeover. Los targets no vienen de un escaneo de puertos: el usuario los declara o se descubren por
OSINT (Fase P). `LybraScan` gana un modo `cloud`; el endpoint acepta `cloudResources`.

**Fase G — Respuesta accionable: píldoras de Aegis y planes de remediación.** Cerrar el bucle entre
detectar y actuar. (1) *Auto-pill*: los hallazgos que superen un umbral (`in_kev=true` o
`priority=CRITICAL` en host público) disparan `AegisManager.run_scan` con un prompt derivado del
`Finding`, referenciado desde una columna `aegis_doc_id` nullable. (2) *Remediation plan*: una tabla
`FindingRemediation` (`command`, `advisory_url`, `effort`, `aegis_doc_id`) generada por `scribe` o
derivada directamente del feed OVAL de la Fase O, que ya trae la `fixed_version` y el paquete.
Endpoint `GET /themis/findings/<id>/remediation`.

**Fase S — Re-escaneo inteligente.** Que Lybra decida *qué no volver a comprobar*. Un `CheckPlanner`
(en `lybra/planner.py`, puro) que, dados los `Service` actuales y el mapa
`dedup_key -> {state, last_seen_at, qod}` del escaneo anterior (ya construido por
`_previous_findings_map`), produce el subconjunto de checks a ejecutar: un check `version` cuyo
CPE+versión no ha cambiado no se re-corre; un check confirmado sobre un path estable se re-corre a
ritmo reducido; los `aggressive` solo si la superficie cambió. Presupuesto en
`themis.lybra.planner.budget`.

**Fase X — Exportación a estándares.** Un módulo `lybra/exporters.py` con tres funciones puras
(`to_sarif`, `to_stix`, `to_ocsf`) sobre la lista de dicts de `format_scan`, y
`GET /themis/scan/<id>/export?format=sarif|stix|ocsf`. SARIF para un futuro CI-gate, STIX para
publicar a un TIP, OCSF para ingerir en un SIEM. Ninguno requiere cambiar el modelo.

**Fase 4 — El escaneo autenticado por SSH · degradada a opcional.** Entrar en el host por SSH o WinRM
con una credencial del vault de Acheron para leer `dpkg -l` / `rpm -qa`. Esta revisión la **baja de
prioridad de forma explícita**: la Fase I cubre el mismo problema sin credenciales privilegiadas, sin
abrir SSH desde el escáner, y llegando a hosts tras NAT. Queda como capacidad de nicho para activos
sin agente.

**Análisis web activo (DAST-lite) · opcional.** Solo si el uso real es sobre todo web: un rastreo del
mismo origen con presupuesto limitado que descubre formularios y parámetros y alimenta los payloads
del DSL de la Fase R, más un conjunto de sondas acotadas (XSS reflejado con marcador único, SQLi por
error y por tiempo, inyección de plantillas por marcador aritmético, redirecciones abiertas). Gate
safe/aggressive fuerte, sin payloads destructivos. No pretende ser Burp ni ZAP.

---

## 7. El desmontaje de OpenVAS

La eliminación se hace en cinco pasos, ordenados de menor a mayor irreversibilidad, cada uno
entregable y verificable por su cuenta. La razón de ese orden es que los dos primeros son baratos y
reversibles y ya entregan casi todo el beneficio operativo, mientras que el quinto es el único que
toca datos.

**¿Antes o después de cerrar las brechas?** La respuesta honesta es **ahora**, y conviene justificarla
en vez de asumirla. Si Ellysia tuviera usuarios apoyándose en la cobertura de OpenVAS, el orden
correcto sería cerrar G1 primero y desmontar después. No los tiene (§1 del documento de gobierno:
cero contacto comercial, el proyecto se construye por disfrute), así que nadie pierde cobertura. Y
mantenerlo conectado sí tiene coste presente: quince minutos de arranque en frío cada vez que se
levanta el compose de desarrollo, un servicio de 1 GiB de memoria compartida corriendo en la máquina
del desarrollador, y un corroborador de cuatro horas disparándose *siempre* en cada análisis profundo.
**Se desconecta ya; las brechas se cierran según el orden del §6.2.**

### E0 — Desconectar (barato, reversible, cero pérdida)

El paso que entrega el 80 % del beneficio con el menor riesgo. Consiste en dejar de ejecutarlo sin
borrar nada:

1. En `LybraEngineManager._launch_deep_corroborators` (`managers/lybra_engine.py`), eliminar el bloque
   que lanza OpenVAS. Es la única invocación automática del pipeline propio, y la que hoy dispara un
   escaneo de hasta cuatro horas en cada análisis profundo. El docstring que dice "OpenVAS always"
   pasa a describir solo Nmap (condicional) y Nikto (condicional).
2. En `docker-compose.yml`, eliminar el servicio `openvas` y las dos entradas `depends_on` de `api` y
   `worker`. Desaparece el único contenedor que pedía `NET_ADMIN`.
3. En el `.env` raíz, retirar `OPENVAS_USERNAME` y `OPENVAS_PASSWORD`.

**Hecho cuando** un `docker compose --profile dev up -d` levanta en segundos en vez de en quince
minutos, y un análisis profundo lanza como mucho dos corroboradores.

### E1 — Retirar del producto (superficie de usuario)

Que el tipo de escaneo deje de existir de cara al usuario, aunque el código siga ahí:

1. `ScanType.OPENVAS` sale del enum (`model.py`). Esto es lo que hace que el resto caiga en cascada,
   porque varias superficies ya derivan sus listas del enum en vez de escribirlas a mano —
   `DocumentsQuerySchema.scan_type` es el ejemplo, arreglado en una ronda anterior precisamente para
   esto.
2. Endpoints y schemas de `/themis` que exponen escaneos OpenVAS (`endpoints.py`, `schemas.py`).
3. Programación: la entrada de OpenVAS en `ProgramedScanManager._REQUIRED_ARGS` y en
   `Scheduler._TASK_MAPPING` (`services/scheduling.py`).
4. Frontend: `web/app/src/constants/scanTypes.js` es el registro único, así que **una sola edición**
   cubre etiquetas, color de gráfico, campos de formulario de programado y formateo de argumentos.
   Después, repasar `ScanForm.vue`, `ScanTabs.vue`, `ScanTable.vue`, `ScanPreviewModal.vue`,
   `ScheduledScansPanel.vue`, `StatsRow.vue`, `ConfigView.vue`, `ThemisView.vue`, `ThemisHubView.vue`
   y `themisStore.js` por si alguno lo menciona fuera del registro. También la copia de la landing
   (`landing/js/main.js`, `LandingView.vue`).

**Hecho cuando** no hay forma de lanzar ni de programar un escaneo OpenVAS desde la API ni desde la
SPA, y la suite de tests pasa entera.

### E2 — Retirar el código

1. `OpenVASScanManager` (`managers/thirdparty_scans_managers.py`), `OpenVASTask` (`services/tasks.py`),
   `OpenVASResultProcessor` y `OpenVASPrintingStrategy` (`services/processors.py`).
2. `openvas_result_to_finding` (`lybra/adapters.py`) y `persist_openvas_results`
   (`repositories.py`), con sus tests (`tests/unit/test_lybra_adapters.py`,
   `tests/integration/test_scanner_finding_adapters.py`, y las partes correspondientes de
   `test_themis.py`, `test_lybra_deep_analysis.py`, `test_scan_delete_guard.py`, `conftest.py`).
3. Las ramas de OpenVAS en `services/reports.py` (25 referencias, el mayor bloque tras el manager),
   `services/csv_logger.py`, `services/analyzers.py`, `services/history.py`, `services/parsing.py`.
4. Configuración: el bloque `themis.openvas` de `SecOpsConfig.json` y los getters
   `CR.get_openvas_*` de `system/config_reading.py` (incluida la lectura de las cuatro variables de
   entorno).
5. Dependencia: `python-gvm` de `requirements.txt:49`.

**Hecho cuando** `grep -ri openvas API/src` no devuelve nada, `pylint src` pasa y la suite entera
pasa.

### E3 — Retirar los datos (el único paso irreversible)

Una migración de Alembic que **archiva antes de borrar**. El orden importa:

1. Verificar que todo `OpenVASScanResult` histórico tiene su `Finding` correspondiente. El adapter
   aditivo de la Fase 0 los venía escribiendo, pero conviene comprobarlo en vez de asumirlo: los
   escaneos anteriores a la Fase 0 no lo tienen. Para esos, un paso de backfill dentro de la propia
   migración que reproduzca el mapeo del adapter.
2. Solo entonces, `drop_table` de `OpenVASScanResult`, `OpenVASVulnerability` y `OpenVASScan`, en ese
   orden (respetando las FKs).
3. Los `Finding` con `source="openvas"` **se conservan** como registro histórico de procedencia. La
   dedup y el ciclo de vida siguen funcionando con ellos; simplemente ya nadie produce más.

**Hecho cuando** `alembic upgrade head` y `alembic downgrade -1` corren limpios sobre una base con
datos históricos, y el conteo de `Finding` con `source="openvas"` antes y después de la migración
coincide.

### E4 — Documentación

`README.md`, `AGENTS.md`, `CLAUDE.md` (la nota sobre herramientas Linux-native, la de "OpenVAS acepta
un host por escaneo" en *things that bite*, el perfil de `docker compose`), `plans/roadmap-ellysia.md`
§6 —que pasa de "congelado" a "eliminado", con puntero a este documento— y los planes que lo
mencionan de pasada (`plans/feature/hygeia/hygeia-backend.md`,
`plans/improvements/webhooks-salientes.md`, `plans/feature/general/reset-server-button.md`).

**Hecho cuando** ningún documento vivo describe OpenVAS como una capacidad presente.

---

## 8. El oráculo sin OpenVAS

El plan anterior declaraba a OpenVAS "la verdad para la detección" en su banco de pruebas. Como el
apartado 2 estableció, eso nunca se implementó — pero la necesidad que describía es real: sin una
vara de medir, "precisión ≥ 0,9" es una frase, no un número. El sustituto tiene dos patas, y ninguna
reintroduce una suite ajena.

**La primera es la verdad por etiqueta conocida**, y es la más sólida de las dos. Las imágenes
vulnerables de laboratorio —VulHub, DVWA, OWASP Juice Shop, Metasploitable 2 y 3— **vienen con su CVE
documentada de antemano**. `vulhub/httpd:2.4.49` es vulnerable a CVE-2021-41773 por construcción; no
hace falta preguntárselo a otra herramienta. El banco se escribe como "el motor debe encontrar la CVE
tal en la imagen cual", que es una aserción más fuerte que la concordancia con un tercero, porque un
tercero también se equivoca. Esto es exactamente lo que `tests/oracle/test_lybra_oracle_bench.py` ya
hace, y lo que hay que escalar: hoy son 6 aserciones sobre 3 familias, y hace falta un catálogo.

**La segunda es Nuclei como oráculo diferencial**, para lo que la primera no cubre: medir *falsos
positivos* y descubrir hallazgos que se nos escapan en objetivos sin etiqueta previa. Y encaja donde
OpenVAS no encajaba, por la misma razón que gobierna todo este documento: **Nuclei es un binario de
línea de comandos con un feed de datos**, no una plataforma con su propio protocolo, su ciclo de vida
y su base de datos. Se ejecuta en un contenedor efímero del banco de pruebas, se compara su salida
con la nuestra, y se descarta.

**Esa segunda pata es ahora el papel U3 de la Fase U**, y conviene señalar el cambio de encuadre que
esa fase introduce: cuando este apartado se escribió, "Nuclei nunca corre en producción" era una
propiedad del diseño. Con la Fase U deja de serlo — Nuclei pasa a ser también una herramienta de
primera clase que el usuario lanza (U1) y un corroborador del análisis profundo (U2). **La distinción
que se mantiene no es "en producción sí o no", sino "dependencia de tiempo de ejecución del motor sí o
no"**: Lybra sigue sin necesitar a Nuclei para funcionar, exactamente igual que no necesita a Nmap ni
a Nikto. Lo que se gana a cambio es que el traductor de la salida de Nuclei a `Finding` se escribe una
sola vez y sirve para los tres papeles, y que el número de falsos positivos deja de ser un ejercicio
de laboratorio para medirse sobre los mismos objetivos que el usuario escanea de verdad. El feed de
plantillas es además el mismo que la Fase R quiere ingerir (U4) — así que el trabajo se aprovecha
cuatro veces, no dos.

**Nmap sigue siendo el oráculo de descubrimiento y fingerprinting**, exactamente como hasta ahora, y
sigue midiéndose con `test_lybra_concordance_bench.py`. Con la Fase N, el catálogo de ese banco tiene
que crecer para incluir contenedores de SMB (Samba), FTP (vsftpd), SMTP (Postfix), SNMP y una base de
datos, porque medir la concordancia de fingerprint solo sobre HTTP/SSH/TLS dejaría de ser
representativo justo cuando la superficie se amplía.

---

## 9. Cuestiones que atraviesan todas las fases

**Autorización y alcance legal.** Escanear solo objetivos autorizados no es negociable. Ya validamos
IPs y rechazamos las privadas, pero antes de habilitar comprobaciones activas y transporte propio
—que sí *tocan* el objetivo— hay que formalizar un registro de "objetivos autorizados" por usuario.
La Fase N amplía la superficie de contacto (sondas a puertos de servicios internos) y la Fase D
escribe en el objetivo, así que el registro deja de ser conveniente y pasa a ser prerrequisito de
ambas.

**Privilegios.** `CAP_NET_RAW` antes que `sudo` completo, con la matriz de degradación de raw a
`connect-scan` siempre presente, y la regla de no fallar nunca por falta de acceso raw.

**Seguridad de las propias comprobaciones.** Modo safe/aggressive, límite de tasa por host, y la deuda
consciente del sandbox para plugins de terceros. La Fase D añade su propio presupuesto de intentos
para no provocar lockouts.

**Gestión de falsos positivos.** El par `qod`/`confirmed` es la herramienta principal: el usuario
puede marcar un hallazgo como `accepted` o como falso positivo, y el sistema lo recuerda entre
escaneos a través de `state`. La Fase O ataca la causa raíz.

**Versionado.** `feed_version` y `check_id` garantizan que cualquier informe sea reproducible.

**Rendimiento.** La concurrencia entre trabajos la resuelve RQ, la concurrencia de E/S dentro de cada
escaneo la da la isla asyncio, y tanto las comprobaciones activas como el transporte deben ir con un
pool acotado por host para no saturar al objetivo.

**Paridad laboratorio/real.** No negociable para dar la Etapa 1 por cerrada. El banco usa imágenes
controladas porque son reproducibles y deterministas, pero eso no puede convertirse en la excusa de
"el objetivo real es más difícil" cuando Nmap identifica con soltura servicios en hosts públicos
reales. Ningún umbral de las Fases F, T y N se da por cumplido solo con el banco de laboratorio: hay
que repetir la medición contra objetivos reales autorizados y variados (con y sin CDN/WAF, con y sin
TLS, con cabecera `Server` presente o suprimida). Si aparece un caso como "en localhost identificamos
producto y versión, pero en un host público real solo vemos puertos abiertos", no es un resultado
aceptable por ser "un objetivo más duro": es una brecha concreta que hay que cerrar antes de dar la
fase por terminada.

---

## 10. Cómo se mide todo esto

Las "definiciones de hecho" de cada fase no son prosa, sino números en un banco de pruebas.

El `qod` se deriva del método de detección empleado:

| Cómo se ha detectado | `qod` | `confirmed` |
|---|---|---|
| Inventario de paquetes del agente (Fase I) | 95 | `true` |
| Confirmador activo inocuo | 99 | `true` |
| Banner que coincide con un patrón específico del producto | 80 | `false` |
| CPE directo de Nmap, o fingerprint propio concordante, o alias manual | 70 | `false` |
| CPE por índice de tokens del CPE Dictionary | `50 + score*20` | `false` |
| Solo el puerto abierto (informativo) | 30 | `false` |

Los umbrales de la Fase 1 (`score >= 0.6` y el factor `* 0.8`) se calibran con datos de precisión y
recall del laboratorio, no a ojo.

Los números que dan cada fase por hecha:

| Fase | El número |
|---|---|
| **N** | Producto y versión extraídos en ≥ 4 protocolos no-HTTP con concordancia ≥ 0,90 frente a `nmap -sV`, en laboratorio **y** en objetivos reales; ≥ 3 checks de configuración de red disparando con `qod=99` |
| **I** | Hallazgos de CVE producidos desde el inventario de un host con agente, fusionados por `dedup_key` con los del escaneo remoto del mismo activo |
| **U** | Un escaneo de Nuclei lanzable solo, con PDF, cuyos `Finding` traen `cve_ids`/`cvss_score`/`feed_version` y deduplican con los de otras fuentes; falsos positivos medidos sobre ≥ 3 objetivos sin etiqueta; histograma de ingestibilidad del feed de plantillas con recomendación escrita |
| **R** | Familias de TLS, cabeceras y paths con precisión ≥ 0,9 medida contra el catálogo de imágenes etiquetadas **y contra el oráculo diferencial de la Fase U**; tipos `network` y `script` existentes; feed en YAML |
| **O** | Falsos positivos del banco −40 % en imágenes Debian/RHEL |
| **D** | Detección en laboratorio con límite de intentos respetado y cero plaintext persistido |
| **F** | Concordancia de fingerprint ≥ 0,90 con Nmap por familia, laboratorio **y** real |
| **T** | Concordancia de puertos ≥ 0,95 con Nmap, laboratorio **y** real; degradación sin `CAP_NET_RAW` probada |

Y las decisiones grandes se toman con un umbral, no con una fecha. ¿Retiramos Nikto? Cuando la Fase U
demuestre con el número de U3 que Nuclei lo cubre —una vía más rápida que la prevista, que era esperar
a la precisión 0,9 de las tres primeras familias de la Fase R. ¿Ingerimos plantillas de Nuclei
(U4/Fase R)? Solo si el histograma de ingestibilidad de la Fase U da una fracción que lo justifique.
¿Construimos el repositorio nativo? Solo
cuando el laboratorio demuestre el techo de rendimiento en Python. ¿Abrimos el análisis web activo?
Solo si el uso real es web y existe el registro de autorización.

**Estado de estos números (2026-07-11).** F y T tienen medición automatizada del lado de laboratorio
—1.00 de concordancia en ambos, sobre 6 objetivos Docker variados— más el lado real anterior
(`scanme.nmap.org` + 2 reales, también 1.00). Con N modesto, el número prueba sobre todo que el
mecanismo de medición funciona, más que la confianza de fondo que pide un 0,90/0,95 robusto — pero ya
no es una medición manual de una vez: es una suite repetible que puede crecer. R tiene las 3 familias
con banco automatizado (incluida `tls`), pero sin precisión medida formalmente contra un catálogo. Lo
que falta es escala, y —para F, T y N— el lado real de la paridad, que requiere que el usuario amplíe
su registro de objetivos autorizados.

---

## 11. Riesgos y el orden en que recortaríamos

| Riesgo | Cómo lo mitigamos |
|---|---|
| **Pérdida de cobertura al eliminar OpenVAS antes de cerrar G1** | Aceptada conscientemente: no hay usuarios apoyándose en ella (§7). La Fase N lidera el roadmap precisamente por esto |
| Falsos positivos por versión (backports) | El par `qod`/`confirmed`; los confirmadores de la Fase R; las Fases O e I, que lo atacan por dos caminos independientes |
| La Fase N se convierte en un pozo sin fondo de protocolos | Lista priorizada y cerrada (7 familias, 3 niveles); la cola larga de appliances es anti-meta declarada (G5) |
| Coste de mantenimiento del diccionario de CPE y los checks | Los alias como "una línea nueva"; la ingesta de plantillas de Nuclei (U4); el feed versionado con CI |
| **Que la Fase U reintroduzca por la puerta de atrás la dependencia que el §1 expulsa** | Nuclei pasa el examen de naturaleza del §1 (binario + feed, no plataforma) y no es dependencia de tiempo de ejecución del motor: Lybra funciona sin él igual que sin Nmap. La señal de alarma sería que Lybra dejase de detectar por su cuenta y se limitase a envolver la salida de Nuclei — el §4 ya lo nombra como anti-meta |
| **Que Nuclei haga irrelevante al `CheckRuntime` propio (Fase R)** | Riesgo real y asumido: Nuclei es abrumadoramente HTTP, y lo que R aporta que él no tiene es el encadenamiento versión→confirmador contra la KB local, el tipo `network` sobre los dissectors de la Fase N y el tipo `script`. Si el histograma de U4 sale bajo, R se estrecha a eso y renuncia a competir en la familia `http` — un resultado más honesto que mantener 10 checks frente a un feed comunitario vivo |
| **Escaneos de Nuclei que saturan al objetivo o tardan una eternidad** | Perfil acotado por defecto (`-severity`/`-tags`/subconjunto curado) más `-rate-limit`, decididos en la propia Fase U y no descubiertos en producción; el registro de objetivos autorizados como prerrequisito |
| Riesgo legal: las Fases N, R, T y D tocan el objetivo | El registro de objetivos autorizados como prerrequisito; el modo `safe` por defecto; el presupuesto de intentos de la Fase D |
| Deriva de alcance hacia "clonar OpenVAS" | Las anti-metas del §4; el beachhead estrecho; la disciplina del 80/20 |
| Coste del repositorio nativo | Aparcado hasta tener evidencia de rendimiento; el fallback en Python siempre presente |
| Frescura del feed | Deltas diarios y el `feed_version` registrado en cada escaneo |
| Sesgo del banco de laboratorio | Paridad laboratorio/real obligatoria (§9); ningún umbral se da por cumplido solo con el banco controlado |
| Que el desmontaje E3 pierda datos históricos | El backfill verificado antes del `drop_table`; los `Finding` con `source="openvas"` se conservan |

Si hubiera que recortar por falta de recursos, el orden de sacrificio sería: primero el análisis web
activo, luego el fingerprint de sistema operativo, después el transporte raw nativo, y por último la
Fase 4 (que la Fase I ya deja como nicho). Lo que no se recorta nunca, porque es el esqueleto de la
identidad y de la confianza, son tres cosas: el modelo `Finding` unificado, la KB local con la señal
de explotabilidad, y el banco de pruebas con integración continua.

---

## 12. Por dónde empezar

El camino crítico, en orden, para el primer resultado tangible bajo esta premisa:

1. **E0 completo** (§7). Es media sesión de trabajo y devuelve un compose que arranca en segundos y
   un análisis profundo que ya no dispara un escaneo de cuatro horas. Empezar por aquí porque el
   beneficio es inmediato y el riesgo es nulo.
2. **Un dissector de la Fase N, el más barato: FTP.** Texto plano, banner en la primera línea, y
   `vsftpd 2.3.4` es una de las imágenes de laboratorio más conocidas que existe (con su backdoor
   documentada, es decir, verdad por etiqueta conocida servida en bandeja). Escribirlo demuestra el
   patrón entero: dissector → `Service` con producto y versión → `_resolve_cpe` → KB → `Finding` con
   CVE, sin escribir un solo check. Si ese camino funciona de extremo a extremo para FTP, funciona
   para los otros seis protocolos y la brecha G1 deja de ser una incógnita para pasar a ser trabajo.
3. **El tipo de check `network` en el runtime** (Fase R), con un solo check declarativo encima —FTP
   anónimo permitido— para validar que el vehículo declarativo sirve y que no hace falta código por
   sonda.
4. **Ampliar el banco** (`test_lybra_concordance_bench.py`) con un contenedor de vsftpd, para que la
   concordancia no-HTTP tenga un número desde el primer día y no se mida a posteriori.
5. Y solo entonces, **E1 y E2** del desmontaje, con la tranquilidad de que la primera pieza del
   sustituto ya está en pie.

A partir de ahí, el orden del §6.2: el resto de dissectors de la Fase N, la Fase I, **la Fase U**, el
cierre de la Fase R, la Fase O y la Fase D.

**Una nota sobre por dónde entrar en la Fase U**, porque tiene un orden interno que no es obvio. Lo
tentador es empezar por el histograma de ingestibilidad (U4), que es lo intelectualmente interesante;
lo correcto es empezar por **U1**, que es lo que entrega producto. El traductor de la salida de Nuclei
a `Finding` es la pieza de la que cuelgan U2 y U3 casi gratis, y el histograma se puede hacer en
cualquier momento porque no depende de nada del backend — es un script suelto sobre un clon del
repositorio de plantillas. Orden: U1 (herramienta + PDF) → U2 (una línea en el corroborador) → U3 (el
banco, reusando el traductor) → U4 (el histograma y su recomendación).

---

## 13. Resumen de entregables

**Etapa 1 — el motor nativo**

| Fase | Pista | Capa | Qué entrega | Brecha / independencia |
|---|---|---|---|---|
| 0 | Correlación | — | CPE persistido, `ScanType.LYBRA`, modelo `Finding` | ✓ hecha |
| **0.9** | Correlación | — | **Modo de entrada por payload en `run_scan`; `Service.origin`; qod/confirmed derivados** | **✓ implementada — desbloquea la Fase I** |
| 1 | Correlación | L3 | El matcher de CPE a CVE (detección por versión) | ✓ hecha |
| 2 | Correlación | L3 | La KB local (NVD, KEV, EPSS, CPE Dictionary) | ✓ hecha — CIRCL/NVD en tiempo de escaneo |
| 5 | Correlación | L3 | Dedup multi-fuente, ciclo de vida, scoring, `HostService` | ✓ hecha |
| 6 | — | L4 | El pipeline orquestado | ✓ hecha |
| **N** | Bajo nivel | L1+L2 | **Dissectors y checks no-HTTP (SMB, FTP, SMTP, SNMP, BD, RDP…)** | **G1 — la brecha decisiva** |
| **I** | Correlación | L3 | **Inventario de Hygeia → `Service` → motor** | **G2 — mejor que el escaneo autenticado** |
| **U** | Bajo nivel | L2 | **`ScanType.NUCLEI` de primera clase (sin tablas nativas), corroborador, oráculo diferencial y medición de ingestibilidad** | **La vara de medir de R; jubila a Nikto** |
| R | Bajo nivel | L2 | Runtime de checks; faltan `script` y el YAML (`network` ya hecho) — **su cierre requiere U** | G1, G4 — **Nikto** |
| O | Correlación | L3 | Backports por feeds OVAL/CSAF de distribución | **G3 — el Notus propio** |
| D | Bajo nivel | L2 | Credenciales por defecto, lockout-safe, sin plaintext | **G4** |
| F | Bajo nivel | L1 | Fingerprint propio; falta JARM | `nmap -sV`, que pasa a oráculo |
| T | Bajo nivel | L0 | Transporte propio; faltan SYN sin estado, UDP, AIMD | El descubrimiento de Nmap |
| 4 | Correlación | L2 | Escaneo autenticado por SSH — **degradado a nicho** | Cubierto mejor por la Fase I |
| DAST | Bajo nivel | L2 | Análisis web activo y acotado — opcional | ZAP/Nikto para webapp |

**Etapa 2 — más allá del host único** (todas ○ planificadas)

| Fase | Pista | Qué entrega |
|---|---|---|
| P | Bajo nivel | Checks pasivos OSINT (CT, Shodan, DNS history) + enriquecimiento |
| E | Correlación | Evidencia cruda firmada por hallazgo (`FindingEvidence`) + endpoint |
| C | Correlación | Correlación cross-host y riesgo de movimiento lateral (`AssetGroup`) |
| A | Bajo nivel | Checks de exposición de APIs (GraphQL/REST/OpenAPI/mass assignment) |
| B | Bajo nivel | Checks de exposición cloud/SaaS (S3/Blob/takeover) |
| G | Correlación | Auto-píldoras de Aegis + planes de remediación con comando exacto |
| S | Correlación | Planificador de re-escaneo por estabilidad |
| X | Correlación | Exportación a SARIF / STIX / OCSF |

**El desmontaje** (§7): E0 desconectar · E1 retirar del producto · E2 retirar el código · E3 retirar
los datos con backfill previo · E4 documentación.

Este es un documento vivo. La regla que no cambia: lidera por la capa que da identidad; baja de nivel
solo cuando la evidencia del oráculo lo respalde con un umbral numérico; retira cada dependencia
externa cuando tu capa propia la iguale —salvo cuando la dependencia sea una suite ajena entera, en
cuyo caso la pregunta no es "¿ya la igualo?" sino "¿por qué la tenía?".

---

## Glosario

**Themis** — El módulo de la API encargado de los escaneos. Es donde vive el motor Lybra.

**Lybra Engine** — El motor de detección de vulnerabilidades propio que describe este plan.

**Orquestador** — Un sistema que se limita a invocar herramientas externas y recoger su salida, sin
lógica de detección propia. Es lo que Themis era, y lo que este plan supera.

**Nmap** — Escáner de red estándar de la industria, usado para descubrir puertos y, con `-sV`,
identificar servicios y versiones. **Se queda** como corroborador y como oráculo del banco.

**Nikto** — Escáner de vulnerabilidades web que comprueba rutas y configuraciones peligrosas
conocidas. **Se queda** como corroborador, pero con fecha de caducidad más cercana de lo previsto: la
Fase U introduce a Nuclei, que cubre la misma superficie con datos mucho mejores (CVE y CVSS frente al
OSVDB de Nikto, muerto desde 2016). El pool objetivo de herramientas externas es **Nmap + Nuclei**; la
retirada se decide con el número del oráculo (U3), no con una fecha.

**OpenVAS / Greenbone** — Suite completa de gestión de vulnerabilidades, con protocolo propio (GMP),
ciclo de escaneo propio y feed de NVTs. **Se elimina** (§7): es una plataforma, no una herramienta.

**NVT** *(Network Vulnerability Test)* — Cada comprobación del feed de OpenVAS. La mayoría son checks
por versión, que es lo que las Fases 1 y 2 ya cubren.

**LSC** *(Local Security Checks)* — El escaneo autenticado de OpenVAS: entra en la máquina para leer
las versiones reales de los paquetes. Lo sustituye la Fase I.

**Notus** — El componente de Greenbone que resuelve backports cruzando versiones contra los avisos de
cada distribución. Su equivalente propio es la Fase O.

**Nuclei** — Motor que ejecuta plantillas de detección declarativas en YAML, con un gran feed
comunitario. Es un binario CLI con un feed de datos, no una plataforma: por eso sí encaja, y la
**Fase U** lo incorpora en sus cuatro papeles — herramienta de primera clase lanzable por el usuario
(U1), corroborador del análisis profundo (U2), oráculo diferencial del banco (U3, el §8) y fuente de
plantillas ingeribles (U4, que queda en la Fase R condicionado a una medición previa).

**CVE** — El identificador estándar de una vulnerabilidad concreta, p. ej. CVE-2021-41773.

**CVSS** — La puntuación estándar de gravedad técnica de una CVE, de 0 a 10.

**CPE** — El identificador estándar de un producto y versión, p. ej.
`cpe:2.3:a:apache:http_server:2.4.49`. Existe una forma antigua (2.2, `cpe:/a:...`) que emite Nmap y
una moderna (2.3) que usa NVD; hay que convertir de una a otra.

**NVD** — La base de datos de vulnerabilidades del NIST, fuente canónica de CVEs, CVSS y CPE.

**KEV** *(Known Exploited Vulnerabilities)* — La lista de la CISA con las vulnerabilidades que se
están explotando activamente. Una señal muy fuerte de prioridad.

**EPSS** — Puntuación de FIRST que estima la probabilidad de que una CVE sea explotada en los
próximos 30 días.

**OSV.dev / GHSA** — Fuentes de vulnerabilidades centradas en ecosistemas de paquetes y en advisories
de GitHub, a menudo más rápidas que NVD.

**OVAL / CSAF** — Formatos en que Debian, Red Hat y SUSE publican qué paquete y versión está
realmente corregido en cada release. La fuente de verdad de la Fase O.

**Backport** — La práctica de las distribuciones de aplicar el parche de una vulnerabilidad sin subir
el número de versión visible. Causa principal de los falsos positivos por versión.

**`Service.origin`** — El campo que la Fase 0.9 añade a `Service` para distinguir un dato inferido de
la red (`"network"`, el único valor que existía hasta ahora) de un dato verificado en el propio host
(`"inventory"`, el caso de un inventario de paquetes). Es lo que permite que un hallazgo por inventario
nazca `confirmed=true` en vez de compartir el `qod=70` genérico de una hipótesis por banner.

**Finding** *(hallazgo)* — El modelo de datos normalizado que unifica los resultados de todas las
fuentes en una sola tabla. La pieza central de la arquitectura, y lo que hace que eliminar OpenVAS no
pierda su histórico.

**QoD** *(Quality of Detection)* — Medida de 0 a 100 de la confianza en un hallazgo, tomada
conceptualmente de OpenVAS. Un 70 es "detectado por banner"; un 99 es "confirmado activamente".

**confirmed** — El booleano que distingue una hipótesis (te veo la versión) de un hecho (lo he
comprobado). Va de la mano del `qod`.

**exploit_maturity** — Indica si existe un exploit público para una CVE y de qué tipo (de `none` a
`in_the_wild`). Señal diferencial de nuestra priorización.

**dedup_key** — Clave hash que permite fusionar en un solo `Finding` los hallazgos de varias fuentes
sobre la misma vulnerabilidad, host y puerto.

**Lybra Feed** — Nuestro conjunto propio de checks y de base de conocimiento, versionado y firmado,
tratado como artefacto de producto. El equivalente propio del NVT feed.

**Check declarativo** — Una comprobación escrita en YAML (petición más matchers), segura de ingerir
de terceros. Cubre el 90 % de los casos de web y banner.

**Check de tipo `network`** — Comprobación declarativa sobre una sonda de protocolo cruda, no HTTP.
El vehículo de la Fase N y el tipo que hoy falta en el runtime.

**Matcher** — La regla de un check que decide si una respuesta coincide (estado, palabra, regex,
tiempo…).

**Extractor** — La parte de un check que captura datos de una respuesta para guardarlos en variables
reutilizables.

**Workflow versión→confirmador** — El encadenamiento por el que un check de versión positivo dispara
una comprobación activa que, si tiene éxito, asciende el hallazgo de hipótesis a hecho.

**Fingerprinting** — La identificación de servicio, producto y versión a partir de cómo responde a la
red. La capa L1 del motor.

**Dissector** — El componente que analiza un protocolo concreto (TLS, HTTP, SSH, SMB, FTP…) para
producir ese fingerprint. La Fase N es, esencialmente, escribir siete dissectors más.

**JARM** — Técnica de fingerprinting del lado del servidor para TLS: envía diez saludos distintos y
hashea el conjunto de respuestas. (No confundir con JA3/JA4, que fingerprintean al cliente.)

**HASSH** — El equivalente de JARM para SSH: fingerprintea el servidor por su lista de algoritmos de
intercambio de claves. Ya implementado.

**Hash de favicon** — Técnica popularizada por Shodan de identificar tecnología por el hash (`mmh3`)
del icono del sitio. Ya implementado.

**Transporte** — La capa L0 del motor: el descubrimiento de puertos propiamente dicho.

**connect-scan** — Escaneo de puertos que abre una conexión completa; no necesita privilegios pero es
más lento. Es el modo base y el fallback, y hoy el único implementado.

**SYN sin estado** — Escaneo rápido, al estilo de masscan, que no guarda estado por conexión porque
deriva el número de secuencia del propio objetivo.

**Cookie SipHash** — El truco que hace posible el SYN sin estado: codifica el objetivo en el número
de secuencia para validar respuestas sin haber almacenado nada.

**AIMD** — Estrategia de control de ritmo que sube la velocidad linealmente y la recorta a la mitad
ante saturación, para no tumbar el objetivo.

**CAP_NET_RAW** — Capability de Linux que permite enviar paquetes crudos. Preferible a `sudo`
completo.

**Hygeia** — El módulo de telemetría de activos. Su agente, ya instalado en el host, es lo que hace
posible la Fase I.

**Acheron** — El módulo del vault cifrado. La Fase 4 lo usaría para el escaneo autenticado por SSH.

**Oráculo diferencial** — Usar una herramienta externa como verdad de referencia contra la que medir
la concordancia de nuestra capa propia en el laboratorio. Nmap para descubrimiento y fingerprinting;
Nuclei para detección (§8).

**Verdad por etiqueta conocida** — Medir contra imágenes vulnerables cuya CVE está documentada de
antemano, sin necesidad de un tercero que opine. Más fuerte que el oráculo diferencial, porque un
tercero también se equivoca.

**Beachhead** — El vertical estrecho y ganable por el que empezamos (higiene y exposición de activos,
más servicios de red no-web) antes de expandirnos.

**Controls, Not Counts** — La filosofía, ya aplicada en `analyzers.py`, de valorar la comprobación
confirmada sobre el mero recuento de hallazgos potenciales.

**OSINT pasivo** — Inteligencia sobre un activo recogida de fuentes públicas sin enviarle tráfico. La
Fase P.

**Movimiento lateral** — El riesgo de que una vulnerabilidad en un host permita propagarse a otros de
la misma red. La Fase C.

**Mass assignment** — Vulnerabilidad de API donde un endpoint acepta campos privilegiados (`role`,
`isAdmin`) que el cliente no debería poder fijar. La Fase A.

**Subdomain takeover** — Exposición cloud en la que un dominio apunta por CNAME a un servicio dado de
baja, permitiendo a un atacante reclamarlo. La Fase B.

**SARIF / STIX / OCSF** — Estándares de exportación de hallazgos: SARIF para CI/CD, STIX para threat
intel, OCSF como esquema unificado de SIEM. La Fase X.

**RQ** *(Redis Queue)* — El sistema de colas de trabajos en segundo plano, con workers en procesos
separados, que ya usa la API.

**UnitOfWork** — El patrón transaccional con el que la aplicación persiste en la base de datos. El
motor lo usa de forma síncrona, fuera del event loop.

**Isla asyncio** — La forma de encapsular la concurrencia asíncrona del motor dentro del worker de
RQ, sin convertir el resto de la aplicación, que sigue siendo síncrona.
