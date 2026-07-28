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
ScanType.LYBRA   → LybraEngineTask  → LybraResultProcessor  → LybraEngineManager   ← el motor
ScanType.OPENVAS → ✂ eliminado (§7)
```

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
| **R** — Runtime de checks propio | Bajo nivel | ◐ parcial — 13 checks, tipos `http` y `tls`; faltan `network` y `script`; el feed es JSON, no el YAML estilo Nuclei del diseño |
| **F** — Fingerprinting propio | Bajo nivel | ◐ parcial — HTTP (cabecera `Server`, título, favicon, 15 firmas de tecnología), SSH (banner + HASSH), TLS (certificado); falta JARM y **todo lo no-HTTP** |
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
| **2.º** | **I — Inventario de Hygeia → Lybra** (H0–H2) | **G2** | Es la prioridad nº 1 del documento de gobierno por razones de producto, y resulta que además es el sustituto del escaneo autenticado de OpenVAS. Dos motivos independientes apuntando al mismo trabajo — bloqueada por la Fase 0.9 |
| **3.º** | **R (cierre) — tipos `network` y `script`, feed en YAML** | G1, G4 | El tipo `network` es el vehículo declarativo de la Fase N; sin él, cada sonda nueva es código |
| **4.º** | **O — Backports por feed de distribución** | **G3** | Ataca la causa nº 1 de falsos positivos sin tocar el host ni pedir credenciales |
| **5.º** | **D — Credenciales por defecto** | **G4** | Cobertura clásica de OpenVAS, con guardas propias (lockout, tasa, evidencia sin plaintext) |
| **6.º** | **F y T (cierre) — JARM, SYN sin estado, UDP, AIMD** | — | Independiza de Nmap, no de OpenVAS. Trabajo de identidad y disfrute, no de necesidad |
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

Lo que falta, documentado y no descubierto por sorpresa: los otros seis protocolos de la tabla
(SMB, SMTP/IMAP/POP3, SNMP, las bases de datos, RDP, LDAP/VNC/Telnet/RPC) — FTP demuestra el patrón
completo de extremo a extremo, pero cada protocolo nuevo sigue siendo trabajo por hacer, no un
efecto colateral gratuito. Tampoco se ha ampliado todavía el catálogo Docker del banco de
concordancia (`test_lybra_concordance_bench.py`) con un contenedor `vsftpd` — la Fase N no tiene
todavía un número de concordancia no-HTTP propio, solo los tests unitarios/de integración
verificando la mecánica.

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

### Fase I — El inventario de Hygeia como escaneo autenticado · pista de correlación · ○ planificada

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

---

### Fase R — El runtime de detección propio · pista de bajo nivel · ◐ parcial

Ésta es la capa de identidad, la L2. Es lo que convierte a Lybra de un correlacionador en un motor
con criterio propio de detección: un runtime único de comprobaciones —versionado, extensible y
reproducible— que decide qué comprobar y produce `Finding` normalizados sin depender de Nikto.

El runtime maneja cinco tipos de comprobación bajo el mismo motor:

| `type` | Para qué sirve | Con qué lo hace | Estado |
|---|---|---|---|
| `version` | Detección por CPE→CVE (Fase 1) | La KB local, sin tocar el objetivo | ✓ |
| `http` | Petición más matchers (el 90 % de web/banner) | Cliente HTTP propio, declarativo | ✓ 10 checks |
| `ssl` | Higiene de TLS | Python de primera parte (`ssl`/`cryptography`) | ✓ 3 checks |
| `network` | **Sondas de protocolo crudas** | Socket propio, declarativo | ✗ **— vehículo de la Fase N** |
| `script` | Lógica compleja, multipaso o binaria | Plugin en Python, de primera parte y revisado | ✗ |

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

**Estado (2026-07-11, sigue vigente):** la mecánica está completa — 13 checks activos en 3 familias,
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
con la nuestra, y se descarta. Nunca corre en producción, nunca es una dependencia de tiempo de
ejecución, y su feed es además el mismo que la Fase R quiere ingerir como plantillas — así que el
trabajo se aprovecha dos veces.

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
| **R** | Familias de TLS, cabeceras y paths con precisión ≥ 0,9 medida contra el catálogo de imágenes etiquetadas; tipos `network` y `script` existentes; feed en YAML |
| **O** | Falsos positivos del banco −40 % en imágenes Debian/RHEL |
| **D** | Detección en laboratorio con límite de intentos respetado y cero plaintext persistido |
| **F** | Concordancia de fingerprint ≥ 0,90 con Nmap por familia, laboratorio **y** real |
| **T** | Concordancia de puertos ≥ 0,95 con Nmap, laboratorio **y** real; degradación sin `CAP_NET_RAW` probada |

Y las decisiones grandes se toman con un umbral, no con una fecha. ¿Retiramos Nikto? Solo cuando las
tres primeras familias de la Fase R alcancen precisión 0,9. ¿Construimos el repositorio nativo? Solo
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
| Coste de mantenimiento del diccionario de CPE y los checks | Los alias como "una línea nueva"; la ingesta de plantillas de Nuclei; el feed versionado con CI |
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

A partir de ahí, el orden del §6.2: el resto de dissectors de la Fase N, la Fase I, el cierre de la
Fase R, la Fase O y la Fase D.

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
| R | Bajo nivel | L2 | Runtime de checks; faltan `network`, `script` y el YAML | G1, G4 — **Nikto** |
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
conocidas. **Se queda** como corroborador hasta que la Fase R alcance su umbral de precisión.

**OpenVAS / Greenbone** — Suite completa de gestión de vulnerabilidades, con protocolo propio (GMP),
ciclo de escaneo propio y feed de NVTs. **Se elimina** (§7): es una plataforma, no una herramienta.

**NVT** *(Network Vulnerability Test)* — Cada comprobación del feed de OpenVAS. La mayoría son checks
por versión, que es lo que las Fases 1 y 2 ya cubren.

**LSC** *(Local Security Checks)* — El escaneo autenticado de OpenVAS: entra en la máquina para leer
las versiones reales de los paquetes. Lo sustituye la Fase I.

**Notus** — El componente de Greenbone que resuelve backports cruzando versiones contra los avisos de
cada distribución. Su equivalente propio es la Fase O.

**Nuclei** — Motor que ejecuta plantillas de detección declarativas en YAML, con un gran feed
comunitario. Es un binario CLI con un feed de datos, no una plataforma: por eso sí encaja, como
oráculo diferencial del banco (§8) y como fuente de plantillas ingeribles (Fase R).

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
