# Lybra Engine — Roadmap del motor propio de vulnerabilidades

Este documento describe el plan para construir un motor de detección de vulnerabilidades propio dentro
del módulo **Themis**. La meta a largo plazo es sencilla de enunciar y ambiciosa de cumplir: que
Nmap, Nikto y OpenVAS/Greenbone dejen de ser *el motor* de nuestros escaneos y pasen a ser
*corroboradores opcionales*, herramientas externas que contrastan y refuerzan lo que Lybra ya ha
encontrado por su cuenta.

No es un documento de análisis ni una lluvia de ideas: es un plan de ejecución. Cada fase dice qué hay
que construir, en qué orden conviene hacerlo y con qué criterio concreto podemos darla por terminada.
Si es la primera vez que lo lees, hay un glosario al final con todos los términos técnicos que
aparecen.

---

## 1. La apuesta: en qué compite Lybra (y en qué no)

Conviene ser honestos desde el principio sobre una cosa: **Lybra no puede competir en cantidad de
comprobaciones, y no debe intentarlo.** OpenVAS acumula unos veinte años de ingeniería y más de cien
mil plugins NASL; Nessus ofrece una amplitud pensada para grandes empresas; Nuclei se apoya en un feed
comunitario gigantesco orientado a la web. Querer igualar ese volumen en solitario y en unos meses no
es realista, y aunque lo fuera, nos dejaría siendo "un OpenVAS peor": la misma propuesta de valor con
una fracción de la cobertura. Esa carrera está perdida de antemano.

La pregunta correcta no es "¿cómo tengo más checks que ellos?", sino "¿qué sé hacer yo que ellos no
hacen bien?". Y ahí sí hay un hueco claro. Todas esas herramientas comparten el mismo defecto: te
devuelven una **lista plana de hallazgos por escaneo** y te dejan a ti la tarea de darle sentido.
Ninguna razona de forma nativa sobre qué importa *en tu contexto y esta semana*, ninguna mantiene el
estado de una vulnerabilidad a lo largo del tiempo por cada activo, y desde luego ninguna te lo
explica en lenguaje natural.

Ahí está la apuesta de Lybra. **No competimos en volumen, competimos en síntesis.** El motor unifica
descubrimiento, detección y contexto en un único hallazgo que sabe de dónde viene (su procedencia) y
cómo ha evolucionado (su ciclo de vida), prioriza por riesgo real —combinando gravedad técnica,
probabilidad de explotación, existencia de exploits y exposición del activo— y lo cuenta de forma
comprensible, además de ser reproducible porque cada dato queda versionado. Esa capacidad de *ordenar
la información* es precisamente lo que las demás herramientas dejan en manos del analista.

**Por dónde empezamos a clavar la cuña.** No se ataca todo a la vez. El punto de entrada natural es la
**higiene y exposición de los activos expuestos a Internet**: TLS y HTTP mal configurados, software
desactualizado, vulnerabilidades que la CISA marca como explotadas activamente. Es el terreno donde
las comprobaciones activas cuestan poco y aportan mucha señal, donde ya tenemos código aprovechable
(la clasificación de amenazas de Nikto y el análisis de contexto de red que ya vive en `analyzers.py`)
y donde los resultados son fáciles de medir. Una vez que ese primer vertical sea sólido y defendible,
se expande hacia el inventario de red y servidores (Fases 1 y 2) y, si el uso real lo pide, hacia el
análisis activo de aplicaciones web.

**Lo que Lybra deliberadamente no será.** Para no perdernos, conviene dejar por escrito las
tentaciones que vamos a rechazar: no será un clon de OpenVAS con un feed de cien mil comprobaciones;
no competirá por número de checks; no mantendrá un catálogo de CVEs curado a mano; y no producirá otra
lista plana de hallazgos más. Cada vez que una decisión nos empuje hacia una de esas cuatro cosas, es
señal de que nos estamos saliendo del plan.

---

## 2. Qué significa "bajo nivel" en este documento

Merece la pena aclarar un término que puede llevar a engaño. Cuando aquí decimos que queremos un motor
**de bajo nivel**, no nos referimos a un lenguaje de programación de bajo nivel como C o Rust. Nos
referimos a **independencia de terceros en tiempo de ejecución**: que cada capa del motor
—descubrimiento, fingerprinting, detección, correlación— tenga una implementación *propia*, en lugar
de limitarse a invocar el binario o el servicio de otra persona.

Hoy Themis es esencialmente un orquestador: lanza Nmap, lanza Nikto, consulta la API de CIRCL en
vivo. El objetivo de este plan es que Lybra **posea sus primitivas**, y que esas herramientas
externas queden relegadas al papel de oráculos con los que comparar y a los que recurrir como
respaldo. El lenguaje en el que se escriba todo eso es secundario. El motor se construye en **Python**,
el stack que ya usamos, con una excepción bien acotada para la parte de red (una isla `asyncio` que se
explica en el apartado 3.4). La posibilidad de un componente nativo en C o Rust —un repositorio
hermano al estilo de `Lybra-AcheronMobile`— existe, pero es una optimización futura y opcional
reservada a un único cuello de botella de rendimiento, no un cimiento del que dependa nada. Se detalla
en la Fase T.

En una frase: bajo nivel aquí significa "no dependemos de nadie mientras escaneamos", no "lo
escribimos en ensamblador".

---

## 3. Los cimientos de la arquitectura

### 3.1 El motor es, sencillamente, otro tipo de escaneo

La decisión de diseño más importante es también la menos glamurosa: no tratar el motor como algo
aparte, sino como un tipo de escaneo más, de primera clase, que encaja en las abstracciones que ya
tenemos. Hoy cada escáner sigue el mismo patrón de cuatro piezas —una tarea, un procesador de
resultados y un gestor— y Lybra se limita a añadir una fila a esa tabla:

```
ScanType.NMAP        → NmapScanTask        → NmapResultProcessor    → NmapScanManager
ScanType.NIKTO       → NiktoScanTask       → NiktoResultProcessor   → NiktoScanManager
ScanType.OPENVAS     → OpenVASTask         → OpenVASResultProcessor → OpenVASScanManager
ScanType.LYBRA (★) → LybraEngineTask   → LybraResultProcessor → LybraEngineManager   ← NUEVO
```

Añadir esa fila es un trámite mecánico gracias al registro por decorador
(`@ScanManager.register(ScanType.LYBRA)`, en `managers.py:603`) montado sobre el modelo polimórfico
(`polymorphic_on=scan_type`, en `model.py`). Y no es un trámite menor por lo que nos regala: el motor
hereda sin escribir una línea la cancelación cooperativa, el reporte de progreso, la persistencia, la
programación de escaneos, la organización en carpetas, la generación de PDF y el enriquecimiento con
IA. Toda esa fontanería ya funciona.

### 3.2 Dentro de esa fila, un stack vertical construido de abajo arriba

La fila del `ScanType` es solo el envoltorio. La sustancia está en que, dentro de ella, Lybra
construye su propio stack por capas, y cada capa que completamos nos permite retirar una dependencia
externa. Visto de abajo arriba:

```
L4  Orquestación / pipeline           (Fase 6)      OpenVAS pasa a corroborador opcional
L3  Correlación · KB · ciclo de vida  (Fases 2 y 5) Nos independiza de CIRCL/NVD en tiempo de escaneo
L2  ★ Runtime de detección propio     (Fase R)      IDENTIDAD — reemplaza a Nikto
L1  Fingerprinting propio             (Fase F)      Reemplaza a "nmap -sV"
L0  Transporte / sondeo propio        (Fase T)      Reemplaza al descubrimiento de Nmap
```

La regla que gobierna todo el orden de trabajo es esta: **se lidera por la capa L2**, el runtime de
detección, porque es la que da identidad tangible y la que puede montarse sobre el Nmap que ya
tenemos para dar valor en cuestión de días. Las capas inferiores (el fingerprinting propio y el
transporte propio) se construyen *al lado* de Nmap, usándolo como vara de medir, y solo lo desplazan
cuando demuestran en el laboratorio que lo igualan. Se baja de nivel por evidencia, nunca por ambición.

### 3.3 El hallazgo unificado: la pieza que hace posible la síntesis

Aquí está el corazón técnico de la apuesta del apartado 1. Hoy cada escáner guarda sus resultados en
su propia tabla: Nmap escribe puertos en `OpenPort`, Nikto sus incidencias en `NiktoIncident`, OpenVAS
sus vulnerabilidades en la suya. El resultado es que tenemos tres escáneres devolviendo tres listas
que no se hablan entre sí. Para un motor que aspira a *sintetizar*, eso no vale: necesitamos un modelo
de hallazgo **normalizado**, común a todos los orígenes, que viva en `themis/model.py`:

```python
class Finding(Base):
    __tablename__ = "Finding"
    id            = Column(Integer, primary_key=True)
    scan_id       = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), index=True)
    host_id       = Column(Integer, ForeignKey("Host.id"), index=True)

    # Qué se encontró
    title         = Column(Text, nullable=False)
    category      = Column(String(64))       # "outdated_software" | "tls" | "exposed_path" | ...
    port          = Column(Integer)
    service       = Column(String(128))
    cpe           = Column(String(255), index=True)

    # Correlación de la vulnerabilidad
    cve_ids           = Column(JSONB)
    cvss_score        = Column(Float)
    cvss_vector       = Column(String(255))
    epss_score        = Column(Float)                  # probabilidad de explotación (FIRST/EPSS)
    in_kev            = Column(Boolean, default=False) # ¿está en la lista de la CISA de vulns explotadas?
    exploit_maturity  = Column(String(16))             # none|poc|functional|weaponized|in_the_wild (Fase 2)

    # Calidad y procedencia (lo que permite deduplicar y confiar)
    source        = Column(String(32))       # "lybra" | "nikto" | "openvas" | "nmap"
    check_id      = Column(String(128))      # "lybra:git-config-exposure@3" — trazabilidad del feed
    feed_version  = Column(String(32))       # qué versión de KB/checks lo produjo (reproducibilidad)
    dedup_key     = Column(String(64), index=True)  # hash(host,port,cpe|check_id,cve) para fusionar
    qod           = Column(Integer)          # Quality of Detection, 0–100
    confirmed     = Column(Boolean, default=False)  # ¿comprobación activa, o solo deducción por versión?

    # Ciclo de vida
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at  = Column(DateTime, default=datetime.utcnow)
    state         = Column(String(20), default="open")  # open | fixed | regressed | accepted
```

Con este modelo, los hallazgos de Lybra, de Nikto y de OpenVAS viven en la misma tabla, y eso lo
cambia todo. Si las tres fuentes detectan la misma CVE en el mismo host y puerto, dejan de ser tres
entradas inconexas y pasan a ser **un solo `Finding`** con una procedencia múltiple y una confianza
más alta, precisamente porque tres herramientas independientes coinciden. Ese es el salto cualitativo
frente a "lanzo tres escáneres y leo tres informes". Los campos `check_id` y `feed_version` añaden
trazabilidad: cada hallazgo sabe qué comprobación exacta, de qué versión del feed, lo generó.

### 3.4 Cómo conviven el bajo nivel asíncrono y un backend síncrono

Hay una tensión técnica que conviene resolver de entrada. Todo el motor de red —el sondeo concurrente
de miles de puertos, los dissectors, las comprobaciones activas— quiere concurrencia de entrada/salida:
muchísimos sockets abiertos a la vez. Pero el stack actual es Python síncrono: Flask, threading, RQ y
`urllib`, sin nada de `asyncio`. La buena noticia es que no hace falta reescribir la aplicación; basta
con **encapsular** el asincronismo donde de verdad se necesita.

El resto de la aplicación no se toca y sigue siendo síncrona. El motor introduce `asyncio` únicamente
dentro del worker de RQ, y solo ahí. El punto de entrada del escaneo —el `@staticmethod`
`LybraEngineManager.execute_lybra_scan`, que corre en el worker— abre y cierra el event loop dentro
de ese proceso aislado:

```python
with job_context() as job:
    results = asyncio.run(engine.scan(target, cancel_check=job.cancelled, progress=job.progress))
    with UnitOfWork() as uow:               # se persiste de forma síncrona, ya fuera del loop
        ScanRepository(uow).persist_findings(scan, results)
```

Como los workers de RQ son procesos separados, ese event loop nace y muere sin contagiar al proceso de
Flask ni a otros trabajos. La regla que mantiene la sencillez es no mezclar nunca `asyncio` con la
sesión de SQLAlchemy: el motor genera los `Finding` en memoria mientras escanea y los persiste al
terminar, con el `UnitOfWork` de siempre, en código síncrono normal.

Queda un detalle de permisos. Nmap hoy se ejecuta con `sudo -n`. Para el motor propio preferimos
otorgar al contenedor del worker la capability `CAP_NET_RAW`, que es mucho menos privilegio que un
`sudo` completo. Con ella, el transporte usa sondas SYN/UDP crudas; sin ella, degrada elegantemente a
un escaneo por conexión (`connect-scan`). La regla es tajante y vale la pena repetirla: nunca fallar
por falta de acceso raw, simplemente ir más despacio.

---

## 4. La secuencia: dos pistas que avanzan en paralelo y convergen

Cada fase es entregable y aporta valor por sí sola, así que en lugar de una lista lineal conviene verlo
como dos pistas de trabajo que corren a la vez y terminan uniéndose. La regla de oro que las gobierna a
ambas es que **no se arranca por Nmap, pero sí se arranca con datos de Nmap.** Se lidera con el runtime
de detección sobre los servicios que ya conocemos —lo que nos da identidad en días— y el transporte y el
fingerprinting propios se van construyendo al lado, usando Nmap como oráculo, hasta el momento en que
Lybra es completamente autónomo.

La primera pista, la de **correlación**, es la columna vertebral: va de la Fase 0 (cimientos) a la
Fase 1 (el matcher de versión), sigue por la Fase 2 (la base de conocimiento local) y culmina en la
Fase 5 (deduplicación, ciclo de vida y scoring). La segunda pista, la de **bajo nivel**, es la que da
carácter al producto: empieza por la Fase R (el runtime de detección, que es la que lidera), continúa
con la Fase F (el fingerprinting propio) y termina en la Fase T (el transporte propio). Ambas pistas
convergen en la Fase 6, el pipeline orquestado, donde el motor propio es el protagonista y Nmap, Nikto
y OpenVAS quedan como segundas opiniones.

Verás que las fases mezclan números y letras. Es intencionado: los números marcan la pista de
correlación (0, 1, 2, 4, 5, 6) y las letras la pista de bajo nivel (R de *runtime*, F de
*fingerprinting*, T de *transporte*). No es un orden estrictamente secuencial, sino el reflejo de esas
dos pistas entrelazadas.

---

## 5. Las fases, una a una

### Fase 0 — Los cimientos · pista de correlación

**El objetivo** de esta fase es puramente estructural: conseguir que "el motor" sea una fila más de la
tabla del apartado 3.1 y que persista sus `Finding`, todavía sin ninguna lógica de detección real.

**Una nota importante sobre la arquitectura en estas fases.** Mientras Lybra no tenga su propio
transporte de red (lo que llega en la Fase T), recibe como entrada una lista de servicios ya
identificados. Esa lista puede venir de un escaneo Nmap anterior del usuario, de parámetros directos,
o de cualquier otra fuente. Lybra no descubre puertos por su cuenta en estas fases; recibe los
servicios y los analiza. Esto tiene dos ventajas claras: simplifica la arquitectura (no hay capas
internas invisibles) y mantiene el historial de escaneos limpio (Nmap es un escaneo, Lybra es otro
escaneo independiente, ambos visibles en la BD). El descubrimiento propio de Lybra llega en la Fase
T, cuando tenga su propio transporte.

Dado esto, el primer trabajo, y el primer cambio de código de todo el proyecto, es **capturar y persistir
el CPE que Nmap ya nos entrega**. Hoy hay una fuga silenciosa que conviene entender: Nmap corre con
`-sV`, y eso hace que emita el elemento `<cpe>` de cada servicio que reconoce; nuestro parser incluso lo
lee correctamente (en `processors.py:226-230`). El problema es que, un par de pasos más adelante, al
re-estructurar los datos en una tupla de seis campos, el CPE se cae por el camino, y aunque no se
cayera, tampoco habría columna donde guardarlo. Recogemos el dato en la mano y lo tiramos justo antes
de llegar a la base de datos. El arreglo es pequeño y muy localizado, cuatro toques:

1. En `model.py`, añadir la columna `cpe = Column(String(255), nullable=True)` al modelo `OpenPort` y
   generar la migración de Alembic correspondiente.
2. En `_parse_nmap_structure` (`processors.py`), dejar de descartar el CPE. Lo más limpio es pasar de
   la tupla posicional de seis campos a un diccionario que propague `"cpe": port_info.get("cpe", "")`;
   el dato ya está en `port_info`, solo hay que dejar de ignorarlo.
3. En `process()` (`processors.py`), incluir el `cpe` en cada diccionario de `ports_data`.
4. En `persist_nmap_results` (`repositories.py:450`), pasarlo al modelo con
   `cpe = port_info.get("cpe") or None`.

Hay tres matices honestos que no bloquean este cambio pero sí condicionan la Fase 1. Primero, `-sV`
solo emite `<cpe>` para los servicios que Nmap reconoce contra su propia base de firmas, así que habrá
puertos sin CPE y para ellos necesitaremos un mecanismo de respaldo que lo construya a partir de
`product` y `version` (se explica en la Fase 1). Segundo, Nmap emite la forma antigua del CPE
(`cpe:/a:apache:http_server:2.4.49`, llamada 2.2) mientras que NVD usa la moderna (`cpe:2.3:...`), así
que hay que convertir antes de casar contra el feed. Y tercero, un mismo servicio puede traer varios
`<cpe>` (el de la aplicación y el del sistema operativo), por lo que conviene usar `findall` y guardar
una lista en lugar de quedarnos con el primero.

El resto de la fase es fontanería: añadir `ScanType.LYBRA = "lybra"` como nuevo valor del enum y
su `polymorphic_identity`; crear el modelo `Finding` del apartado 3.3 con su migración; escribir un
`LybraEngineTask` que reciba como parámetros un host, puerto, protocolo, servicio, versión y CPE (la
información del puerto ya descubierto); un `LybraEngineManager` registrado con el decorador; y un
endpoint `POST /themis/lybra` que acepte esos parámetros y lance el escaneo.

La entrada a un escaneo Lybra en estas fases es una lista de servicios con sus detalles. El usuario
puede obtenerla de un Nmap Scan anterior (leyendo sus `OpenPort`), o proporcionarla manualmente, o desde
otra fuente. Lybra recibirá esa entrada y la procesará.

**Damos la fase por hecha cuando** podemos lanzar un "escaneo Lybra" proporcionándole una lista de
servicios, y el motor persiste `Finding` informativos (uno de tipo "puerto abierto" por cada servicio
recibido). Todavía no detecta ninguna vulnerabilidad, pero toda la fontanería de persistencia y
correlación funciona de extremo a extremo.

### Fase 1 — Detección por versión: el matcher de CPE a CVE · pista de correlación

**El objetivo** es dar el primer paso de detección real: dado un servicio con su producto y su versión
—que ya hemos recibido como entrada—, decir qué CVEs conocidas le afectan y con qué gravedad.
Conceptualmente es lo que hace una buena parte de OpenVAS. (Más adelante, en la Fase R, este matcher no
será una pieza aparte sino un tipo de comprobación más dentro del runtime; lo describimos por separado
aquí porque es el producto mínimo viable de la correlación y se puede montar antes que el runtime
completo.)

El flujo es directo. Tomamos el servicio que ya tenemos de entrada; normalizamos su producto y versión a
un CPE en formato 2.3; consultamos la base de conocimiento local (que construiremos en la Fase 2)
respetando los rangos de versión que NVD define; y por cada CVE aplicable emitimos un `Finding` con
`qod=70` y `confirmed=false`.

El punto delicado es esa normalización a CPE cuando Nmap no nos da uno limpio. La tentación de escribir
a mano un `if "Apache" in product` gigantesco hay que resistirla: se vuelve inmantenible y, peor,
puede inventar un CPE que no exista en el diccionario oficial de NVD, en cuyo caso el matcher no
devuelve ninguna CVE y falla en silencio. La estrategia sana tiene tres capas, ordenadas de mayor a
menor confianza, y su principio rector es que **nunca se inventa un CPE que NVD no reconozca**:

```python
def normalize_product_to_cpe(product, version) -> tuple[str | None, float]:
    key = product.strip().lower()
    if key in CPE_PRODUCT_OVERRIDES:                    # 1) alias conocido, curado a mano → confianza 0.95
        vendor, prod = CPE_PRODUCT_OVERRIDES[key]
        return _build_cpe23(vendor, prod, version), 0.95
    match, score = _best_cpe_dictionary_match(key)      # 2) búsqueda por tokens en el CPE Dictionary
    if match and score >= 0.6:
        return _build_cpe23(match.vendor, match.product, version), score * 0.8
    return None, 0.0                                     # 3) sin coincidencia buena → no se inventa nada
```

La primera capa es una tabla pequeña y versionada de alias frecuentes —cosas como que Nmap dice
"OpenSSH" pero el CPE oficial es `openbsd:openssh`, o que "Apache httpd" es `apache:http_server`— que
crece a razón de una línea por cada falso negativo que detectemos en producción. La segunda es un
índice de tokens construido sobre el campo `title` del CPE Dictionary de NVD, que es el mismo mirror
que vamos a mantener en la Fase 2, así que no supone trabajo nuevo. La tercera capa es no hacer nada:
si no hay coincidencia suficientemente buena, preferimos no generar un hallazgo por versión antes que
generar uno falso. Conviene registrar en el log (a nivel `debug`) cada vez que la función devuelve
`None`, porque esa es la lista priorizada de qué alias añadir a mano primero.

La confianza que devuelve la función se traduce después en el `qod` del hallazgo, según la tabla del
apartado 7. Y aquí toca un aviso importante sobre falsos positivos: la detección por versión sufre el
problema de los *backports*. Distribuciones como Debian o Red Hat parchean una vulnerabilidad sin
cambiar el número de versión visible, de modo que un servicio puede parecer vulnerable por su banner y
estar en realidad corregido. Por eso el `qod` es menor que 100 y el `confirmed` es `false`: un hallazgo
por versión significa "potencialmente vulnerable", no "vulnerable confirmado". La Fase R es la que lo
asciende a confirmado cuando lo comprueba activamente.

**Damos la fase por hecha cuando** un escaneo Lybra sobre un host con software desactualizado produce
hallazgos con CVEs reales y su CVSS, visibles tanto en la interfaz web como en el PDF.

### Fase R — El runtime de detección propio · pista de bajo nivel · la que lidera

Esta es la capa de identidad, la L2, y por tanto la más importante de todo el plan. Es lo que convierte
a Lybra de un simple correlacionador en un motor con criterio propio de detección. La idea es un
runtime único de comprobaciones —versionado, extensible y reproducible— que, dado el conjunto de
servicios que ya hemos recibido, decide qué comprobar y produce `Finding` normalizados, todo ello sin
depender de Nikto.

El runtime maneja cinco tipos de comprobación, pero todos bajo el mismo motor:

| `type`    | Para qué sirve                              | Con qué lo hace                          |
|-----------|---------------------------------------------|------------------------------------------|
| `version` | Detección por CPE→CVE (la Fase 1)           | La base de conocimiento local, sin tocar el objetivo |
| `http`    | Petición más matchers (el 90% de web/banner)| Cliente HTTP propio, declarativo en YAML |
| `ssl`     | Higiene de TLS                              | Python de primera parte (`ssl`/`cryptography`) |
| `network` | Sondas de protocolo crudas                  | Socket propio, declarativo               |
| `script`  | Lógica compleja, multipaso o binaria        | Plugin en Python, de primera parte y revisado |

El grueso de las comprobaciones se escribe de forma **declarativa en YAML**, con un esquema diseñado
para ser razonablemente compatible con las plantillas de Nuclei. Así se lee un check típico:

```yaml
id: apache-2449-path-traversal
version: 3                            # junto con el id forma el check_id "lybra:apache-2449-path-traversal@3"
type: http
category: exposed_path
severity: HIGH
service: http
cpe: "cpe:2.3:a:apache:http_server:2.4.49:*"   # así se encadena desde un check de versión
mode: aggressive                      # safe | aggressive — respeta el gate de autorización del apartado 6
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

El lenguaje ofrece las piezas habituales: **matchers** para decidir si algo coincide (`status`, `word`,
`regex`, `binary`, `size`, `time` y `dsl`, combinables con `and`/`or` y negables), **extractors** para
capturar datos de la respuesta (`regex`, `kval`, `json`, `xpath`) que se guardan en variables
interpolables con `{{var}}`, y conjuntos de **payloads** para fuzzing con las estrategias `batteringram`,
`pitchfork` y `clusterbomb` que también usa Nuclei, y que serán la base del análisis web activo.

La verdadera novedad frente a Nuclei son los **workflows de tipo versión→confirmador**. Un check de
versión que da positivo puede encadenar automáticamente su confirmador activo: si el confirmador tiene
éxito, el hallazgo asciende de `qod=70` a `qod=99` y de `confirmed=false` a `true`. Esa distinción
entre la hipótesis (te veo la versión, probablemente eres vulnerable) y el hecho (lo he comprobado, lo
eres) es la filosofía "Controls, Not Counts" que ya aplicamos en `analyzers.py`, y es lo que ninguna
lista plana de hallazgos captura.

La compatibilidad con Nuclei no es un capricho estético, es un **multiplicador de fuerza**: nos permite
ingerir su feed comunitario de miles de plantillas como equivalente a un NVT feed, pero para
comprobaciones activas. Un adapter traduce cada plantilla de Nuclei a nuestro formato en el momento de
la ingesta, ya que los tipos `http`, `network` y `ssl` mapean casi uno a uno. Se descartan las
plantillas que ejecutan código arbitrario (`code:`) y las de protocolos que aún no soportemos. Como
Nuclei no tiene los conceptos de `qod` ni `confirmed`, los derivamos por heurística del propio matcher:
si es confirmatorio, `confirmed=true`; si solo mira el banner, `false`. Toda plantilla externa entra en
modo `safe` por defecto, y hay que auditar su licencia y registrar su procedencia antes de
redistribuir nuestro feed.

Sobre los checks de tipo `script`, que son código Python, hay que ser honestos con un límite consciente:
solo se admiten los de **primera parte, escritos y revisados por nosotros**, ejecutándose en proceso con
una API restringida (primitivas `http`, `tls`, `probe`, límites de tiempo y tasa, y el gate
safe/aggressive). No ejecutamos código Python de terceros en proceso, sencillamente porque Python no se
puede aislar con garantías dentro del mismo proceso. Si algún día quisiéramos aceptar plugins de
terceros, la vía de mejora es aislarlos en un subproceso con `rlimit`/seccomp e IPC estrecho, no
reescribir el runtime.

Un apunte agradable: no partimos de cero con el catálogo de checks. El método
`_classify_threat_level` de `NiktoResultProcessor` (`processors.py:294`) ya contiene un catálogo
enorme de patrones peligrosos —`.git/`, `.env`, `wp-config.php`, cifras débiles, métodos HTTP
peligrosos— que es la semilla perfecta para el primer conjunto de checks declarativos. La diferencia es
que, en lugar de clasificar la salida de Nikto, ahora somos nosotros quienes hacemos la petición y
evaluamos. Las familias por las que conviene empezar, por su alta relación entre valor y coste, son la
higiene de TLS/SSL, las cabeceras de seguridad HTTP, los paths sensibles expuestos, las credenciales por
defecto y los confirmadores de las CVEs que la CISA marca como explotadas.

Todo esto se distribuye como un feed propio y versionado —el formato "Lybra Check" en `.yaml`— cuya
versión queda registrada en cada escaneo a través de `feed_version` y `check_id`. Esa reproducibilidad
es exactamente lo que hace Greenbone con su NVT feed, y es una parte tangible de nuestra identidad.

**Damos la fase por hecha cuando** el motor detecta por versión y además confirma activamente al menos
las tres primeras familias, todo bajo el mismo runtime y con feed versionado, y el `qod` sube de 70 a
99 en lo confirmado. En ese punto, Nikto deja de ser necesario para el caso web típico.

### Fase 2 — La base de conocimiento local y la inteligencia de amenazas · pista de correlación

**El objetivo** es dejar de depender de consultas en vivo a `cve.circl.lu` y tener nuestro propio
espejo local, rápido y consultable sin conexión: el equivalente a un NVT feed propio, que aquí llamamos
el **Lybra Feed**.

Las fuentes que reflejamos son todas públicas y gratuitas, y cada una aporta algo que las demás no
tienen:

| Fuente                          | Qué aporta                                          | Con qué frecuencia |
|---------------------------------|-----------------------------------------------------|--------------------|
| NVD CVE JSON 2.0                | CVEs, applicability de CPE y CVSS                    | diaria (delta)     |
| CPE Dictionary (NVD)            | la normalización de producto a CPE de la Fase 1     | semanal            |
| CISA KEV                        | qué CVEs se están explotando activamente            | diaria             |
| EPSS (FIRST)                    | la probabilidad de explotación en los próximos 30 días | diaria          |
| OSV.dev y GHSA                  | vulns de ecosistemas de paquetes; advisories tempranos | diaria          |
| OVAL y feeds de distribución    | la verdad sobre los backports (Debian, RHEL, USN)   | según proveedor    |
| ExploitDB, Metasploit, Nuclei   | si existe un exploit público (como señal, no como check) | continua       |

De todas ellas, la que marca la diferencia respecto a la competencia es la **señal de explotabilidad**.
El campo `exploit_maturity` del `Finding` se deriva combinando varias fuentes: si está en la lista KEV
sabemos que se explota en el mundo real; si existe un módulo de Metasploit o una plantilla de Nuclei,
está weaponizado o es funcional; si aparece en ExploitDB, hay al menos una prueba de concepto; y el
EPSS da la probabilidad continua. Ese campo es lo que convierte el scoring de la Fase 5 en algo
accionable: la diferencia entre decir "CVSS 9.8" y decir "CVSS 9.8, con exploit weaponizado y en la
lista de explotación activa, en una IP pública, así que parchéalo hoy".

Conviene tratar la base de conocimiento no como una tabla interna cualquiera, sino como un artefacto de
producto. Está **versionada** (cada escaneo registra su `feed_version`, lo que da reproducibilidad
total: "este informe usó la KB del 4 de julio de 2026"), **firmada** (un hash y una firma garantizan
su integridad) y se actualiza con **deltas diarios** en lugar de descargas completas.

La implementación reutiliza patrones que ya tenemos. Los modelos `CveEntry`, `CpeMatch`, `KevEntry` y
`EpssScore` viven en un submódulo nuevo, `themis/services/kb/`, sobre el mismo `BaseRepository` y
`UnitOfWork` de siempre. El trabajo de sincronización es una tarea de RQ programada con APScheduler, en
una categoría nueva `themis.kb`, y el fetcher puede calcarse del `AegisAlertFetcher` de `pills.py`,
que ya resuelve el fetch concurrente, la caché con TTL, el reintento con backoff y el fallback entre
fuentes. La consulta central del matcher es sencilla:

```python
def cves_for_cpe(session, vendor, product, version) -> list[CveEntry]:
    candidates = session.query(CpeMatch).filter_by(vendor=vendor, product=product).all()
    return [c.cve for c in candidates if version_in_range(version, c)]
    # version_in_range respeta versionStartIncluding / versionEndExcluding y demás rangos de NVD
```

**Damos la fase por hecha cuando** la detección por versión ya no hace ninguna llamada de red por cada
objetivo, sino que consulta la base local, y un trabajo nocturno la mantiene al día con deltas
verificados. En ese momento nos hemos independizado de CIRCL y NVD en tiempo de escaneo, que era
justamente el objetivo declarado.

### Fase F — El fingerprinting propio · pista de bajo nivel

**El objetivo** es identificar el servicio, su producto y su versión con criterio propio, sin depender
de `nmap -sV`, y con una confianza que podamos medir. Es, por así decirlo, el ojo del motor.

El trabajo consiste en escribir dissectors de protocolo propios, priorizados por su relación entre
valor y coste. El más rentable es el de TLS, que se apoya en la técnica **JARM** —un fingerprint del
lado del servidor que envía diez ClientHello deliberadamente distintos y hashea el conjunto de
respuestas— más el parseo de la versión, las cifras y el certificado (emisor, nombres alternativos,
caducidad, autofirma), datos que de por sí ya son hallazgos de la familia TLS de la Fase R. Le sigue el
dissector de HTTP, que combina el orden de las cabeceras, el `Server`, el `<title>`, el hash del favicon
(al estilo de Shodan, con `mmh3`) y firmas de tecnología del tipo Wappalyzer. El de SSH usa la técnica
HASSH, que fingerprintea el servidor por su lista de algoritmos de intercambio de claves, además del
banner de versión. Y por último, con mucho menos peso porque su retorno es bajo, un fingerprint de
sistema operativo basado en detalles del stack TCP/IP (el TTL inicial, el tamaño de ventana, el orden
de las opciones TCP, el muestreo de números de secuencia).

Cada dissector emite un `Service` con una confianza asociada, que se traduce al `qod` según la tabla del
apartado 7. El principio que gobierna esta capa es la calibración por oráculo: Nmap `-sV` es la verdad
de referencia en el laboratorio, y solo confiamos en nuestra firma allí donde concuerda con Nmap.

**Damos la fase por hecha cuando** para los servicios comunes la concordancia de nuestro fingerprint con
el de Nmap alcanza el 0,90 por familia de servicio. A partir de ahí, `nmap -sV` pasa a ser oráculo y
respaldo, no motor.

### Fase T — El transporte propio · pista de bajo nivel

**El objetivo** es que Lybra descubra los puertos por su cuenta, con una implementación propia, en
lugar de recibirlos como entrada. Son, siguiendo la metáfora, las manos del motor. Cuando esta fase esté
lista, un escaneo Lybra puede recibir solo el host objetivo y hacer todo el trabajo: descubrir,
fingerprinting, detección.

La base siempre disponible es un scanner por conexión (`connect-scan`) sobre `asyncio`, que no requiere
privilegios. Por encima de él, cuando el worker tiene la capability `CAP_NET_RAW`, se activa un camino
rápido: un escaneo **SYN sin estado** al estilo de masscan. La idea, que es elegante, consiste en no
guardar estado por cada conexión pendiente. En lugar de mantener una tabla de sockets esperando
respuesta, el número de secuencia del SYN se *deriva* del objetivo mediante una cookie
(`seq = SipHash(clave, ip_destino‖puerto_destino‖puerto_origen)`), de modo que cuando llega un SYN/ACK
basta recomputar la cookie a partir de sus campos para saber si es una respuesta legítima a *nuestro*
sondeo y a qué objetivo pertenece, todo sin haber almacenado nada. Eso es lo que permite a masscan
escanear millones de direcciones con memoria constante. El emisor y el receptor funcionan como dos
tareas desacopladas sobre un mismo raw socket dentro de la isla asyncio.

El UDP merece un trato aparte, porque no es simplemente "SYN pero sin conexión": muchos servicios solo
responden si les mandas un estímulo válido, así que necesita sondas con payload real por protocolo
(DNS, SNMP, NTP, mDNS, IKE). Conviene empezar por un conjunto curado de cinco a diez protocolos de alto
valor, no por barrer todos los puertos UDP.

Sea cual sea el modo, el control de ritmo es imprescindible para no tumbar el objetivo: un token-bucket
por host combinado con una estrategia AIMD, que sube el ritmo de forma lineal y lo recorta a la mitad en
cuanto detecta pérdidas o mensajes ICMP de inalcanzable. Y siempre se respeta el gate de autorización
(`validate_ip`, el rechazo de IPs privadas, `is_host_reachable`). El soporte de IPv6 encaja por diseño,
porque la lógica de la cookie es idéntica y solo cambia la cabecera.

Aquí es donde, y solo aquí, cobra sentido la idea del repositorio nativo del apartado 2. El escaneo en
Python tiene un techo real de rendimiento, así que si el laboratorio demuestra que ese techo no basta
para nuestra superficie real —pensemos en inventariar rangos del tamaño de un `/16` o mayores, donde se
necesitan más de unos 50.000 a 100.000 paquetes por segundo sostenidos— entonces se justifica compilar
un núcleo nativo en C o Rust, consumido por FFI, con el mismo patrón "núcleo nativo más capa Python
verificada" que ya usa Acheron y manteniendo siempre el fallback en Python puro. Por debajo de ese
umbral, no se justifica, y por eso queda aparcado hasta tener evidencia de necesidad.

**Damos la fase por hecha cuando** la concordancia de puertos con Nmap alcanza el 0,95 y hemos probado
que la degradación a `connect-scan` funciona sin la capability. Nmap queda como respaldo conmutable.

### Fase 5 — Correlación, ciclo de vida y scoring · pista de correlación

**El objetivo** de esta fase es dar el salto de "listas de hallazgos por escaneo" a "estado de la
vulnerabilidad de cada activo a lo largo del tiempo". Es aquí donde el producto se vuelve claramente
superior a lanzar herramientas sueltas.

El primer ingrediente es un cambio de sujeto. Hasta ahora hemos hablado de hallazgos, pero el sujeto
real del producto no es el hallazgo, es el activo. Conviene por tanto hacer explícito un modelo
`Asset → Service → Finding`, donde un `Scan` no es la entidad principal sino una *observación* de ese
árbol en un instante concreto. Esa inversión, que es una extensión pequeña del historial que ya
tenemos, habilita algo que ni Nmap ni Nuclei ofrecen: alertas de "se ha abierto un puerto nuevo" o "ha
cambiado la versión de un servicio", es decir, cambios de la superficie de ataque y no solo de las
vulnerabilidades.

Sobre esa base se apoyan las tres capacidades de la fase. La **deduplicación multi-fuente** usa el
`dedup_key`: si Lybra, Nikto y OpenVAS reportan la misma CVE en el mismo host y puerto, se funden en
un solo `Finding` con procedencia múltiple y un `qod` consolidado, más alto por el propio hecho de que
varias fuentes coinciden. El **ciclo de vida**, apoyado en el `ScanHistoryManager` que ya existe,
compara el escaneo actual con el anterior del mismo objetivo y etiqueta cada hallazgo como `open`
(nuevo), `fixed` (estaba y ya no), `regressed` (había desaparecido y ha vuelto) o `accepted` (un riesgo
que el usuario ha decidido asumir). Y el **scoring de riesgo contextual** va más allá del CVSS crudo:
combina la gravedad técnica (CVSS), la probabilidad real de explotación (EPSS), la existencia de
exploits (KEV y `exploit_maturity`) y la exposición del activo, que ya sabemos distinguir con
`_classify_network_context` (`analyzers.py:70`) entre una LAN privada y la Internet pública. Un CVSS 9.8
weaponizado y en KEV sobre una IP pública es una prioridad crítica e inmediata; ese mismo CVSS sin
prueba de concepto conocida en una LAN aislada es una prioridad media que puede incluso ser un falso
positivo por backport.

### Fase 4 — El escaneo autenticado · pista de correlación · avanzado y opcional

**El objetivo** es lo que OpenVAS llama *authenticated scan*: entrar en el host por SSH o WinRM para
comprobar las versiones reales de los paquetes del sistema operativo, en lugar de fiarnos del banner.
Es lo que resuelve de raíz el problema de los backports de la Fase 1, porque lees la versión real del
paquete instalado.

El trabajo consiste en un conector SSH que use una credencial guardada en el vault cifrado de Acheron
(`Vault`, `VaultManager`, que ya tenemos), la lectura de paquetes con `dpkg -l` o `rpm -qa`, y la
correlación de esas versiones con los avisos del proveedor (OVAL y feeds de distribución). Se implementa
como una familia de plugins Python de la Fase R, checks "locales" en vez de "remotos". Es un terreno de
nicho —muchos productos comerciales lo cobran aparte— así que conviene dejarlo para cuando el motor
remoto esté maduro.

### Análisis web activo (DAST-lite) · pista de bajo nivel · opcional

**El objetivo**, solo si el uso real es sobre todo web, es una comprobación activa ligera de la
aplicación. Hay que ser claros con las expectativas: esto no pretende ser Burp ni ZAP, es un análisis
activo *acotado*.

Consta de un rastreo (`crawl`) del mismo origen y con presupuesto limitado de páginas y tiempo, que
descubre formularios y parámetros y alimenta los payloads del DSL de la Fase R, y de un conjunto de
sondas seguras y acotadas: XSS reflejado con un marcador único, SQLi por error y por tiempo (usando el
matcher `time`), inyección de plantillas por marcador aritmético, y redirecciones abiertas. Todo ello
con un gate safe/aggressive fuerte, sin payloads destructivos, con límite de tasa por host y respetando
el registro de objetivos autorizados. El techo consciente es que al principio no habrá motor de
navegador headless ni soporte de autenticación de aplicación compleja.

### Fase 6 — La orquestación: el motor como pipeline por defecto · el punto de convergencia

**El objetivo** final es unir todas las piezas en un único flujo donde el motor propio es el
protagonista. La forma exacta del pipeline depende de en qué fase nos encontremos.

**En Fases 0 a T-1** (antes de tener transporte propio), el usuario lanza un Lybra Scan proporcionando
una lista de servicios ya conocidos (de un Nmap Scan anterior, o proporcionados manualmente):

```
Lybra Scan (Fases 0–T-1: analizador de vulnerabilidades)
  1. Entrada        → lista de servicios (host, puerto, servicio, versión, CPE)
  2. Detección      → Runtime de checks (L2): por versión y activa         [Fase R + 1/2]
  3. Correlación    → dedup, ciclo de vida y scoring                       [Fase 5]
  4. (opcional) Deep → lanzar Nmap/Nikto/OpenVAS y fusionar sus hallazgos  [corroboración]
  5. Enriquecimiento → scribe/IA genera el análisis y el PDF               [ya existe]
```

**A partir de Fase T** (con transporte propio), el pipeline es completo y autónomo:

```
Lybra Scan (Fase T+: escáner completo)
  1. Descubrimiento   → Transporte propio (L0)                               [Fase T]
  2. Fingerprinting   → Dissectors propios (L1)                              [Fase F]
  3. Detección        → Runtime de checks (L2): por versión y activa         [Fase R + 1/2]
  4. Correlación      → dedup, ciclo de vida y scoring                       [Fase 5]
  5. (opcional) Deep  → lanzar Nmap/Nikto/OpenVAS y fusionar sus hallazgos   [corroboración]
  6. Enriquecimiento  → scribe/IA genera el análisis y el PDF                [ya existe]
```

El paso de "análisis profundo" es opcional en ambos casos: si el usuario lo solicita, se lanzan las
herramientas externas como una segunda opinión que se fusiona en los mismos `Finding`. Así es como
Nmap, Nikto y OpenVAS terminan siendo complementos de nuestro motor, y no al revés.

---

## 6. Cuestiones que atraviesan todas las fases

Hay varios asuntos que no pertenecen a una fase concreta sino que aplican a lo largo de todo el plan, y
conviene tenerlos presentes desde el principio.

El primero es la **autorización y el alcance legal**. Escanear solo objetivos autorizados no es
negociable. Ya validamos IPs y rechazamos las privadas, pero antes de habilitar las comprobaciones
activas de la Fase R y el transporte propio de la Fase T —que sí *tocan* el objetivo, a diferencia de la
detección por versión— hay que formalizar un registro de "objetivos autorizados" por usuario. El
segundo son los **privilegios**: preferimos `CAP_NET_RAW` a un `sudo` completo, con la matriz de
degradación de raw a `connect-scan` siempre presente, y la regla de no fallar nunca por falta de acceso
raw. El tercero es la **seguridad de las propias comprobaciones**, que se traduce en el modo
safe/aggressive, el límite de tasa por host y la deuda consciente del sandbox para plugins de terceros.

El cuarto es la **gestión de falsos positivos**, para la que el par `qod`/`confirmed` es la herramienta
principal: el usuario puede marcar un hallazgo como `accepted` o como falso positivo, y el sistema lo
recuerda entre escaneos a través del campo `state`. El quinto es el **versionado**, que a través de
`feed_version` y `check_id` garantiza que cualquier informe sea reproducible. Y el sexto es el
**rendimiento**: la concurrencia entre trabajos ya la resuelve RQ, la concurrencia de entrada/salida
dentro de cada escaneo la da la isla asyncio, y tanto las comprobaciones activas como el transporte
deben ir con un pool acotado por host para no saturar al objetivo.

---

## 7. Cómo se mide todo esto (y cómo se decide invertir el default)

Un plan ambicioso sin forma de medirlo es indistinguible de un plan roto. Por eso las "definiciones de
hecho" de cada fase no son prosa, sino números en un banco de pruebas. Sin ellos, la regla de "lidera
con L2 y baja de nivel por evidencia" no sería accionable.

Empieza por el `qod`, que deja de ser un número mágico para derivarse del método de detección empleado:

| Cómo se ha detectado                                                    | `qod`         | `confirmed` |
|-------------------------------------------------------------------------|---------------|-------------|
| Confirmador activo inocuo                                                | 99            | `true`      |
| Banner que coincide con un patrón específico del producto               | 80            | `false`     |
| CPE directo de Nmap, o fingerprint propio concordante, o alias manual   | 70            | `false`     |
| CPE por índice de tokens del CPE Dictionary                             | `50 + score*20` | `false`   |
| Solo el puerto abierto (informativo)                                    | 30            | `false`     |

Los dos umbrales que aparecen en la Fase 1 (el `score >= 0.6` y el factor `* 0.8`) no son arbitrarios:
se calibran con datos de precisión y recall del laboratorio, no a ojo.

El instrumento de medición es un **banco de pruebas con oráculo diferencial**, que además funciona como
puerta de CI. Se monta con imágenes vulnerables conocidas —DVWA, OWASP Juice Shop, Metasploitable 2 y 3,
imágenes de VulHub— y se escriben tests del tipo "el motor debe encontrar la CVE tal en la imagen cual".
Las herramientas externas hacen de oráculo: Nmap es la verdad para el descubrimiento y el
fingerprinting, OpenVAS lo es para la detección. La concordancia contra ese oráculo se expresa como
aserciones numéricas, y son precisamente esos números los que deciden cuándo podemos invertir el valor
por defecto en cada fase:

| Fase | El número que la da por hecha                                                        |
|------|--------------------------------------------------------------------------------------|
| 1    | Al menos N CVEs reales con su CVSS correcto en el banco; el FP por backport, medido   |
| R    | Las familias de TLS, cabeceras y paths con precisión ≥ 0,9; el `qod` sube de 70 a 99  |
| 2    | Cero llamadas de red por objetivo en la detección por versión; delta diario verificado |
| F    | Concordancia de fingerprint ≥ 0,90 con Nmap por familia; Nmap pasa a oráculo          |
| T    | Concordancia de puertos ≥ 0,95 con Nmap; degradación sin `CAP_NET_RAW` probada        |

Y las decisiones más grandes se toman igual, con un umbral y no con una fecha. ¿Retiramos Nikto? Solo
cuando las tres primeras familias de la Fase R alcancen una precisión de 0,9. ¿Construimos el
repositorio nativo? Solo cuando el laboratorio demuestre el techo de rendimiento en Python. ¿Abrimos el
análisis web activo? Solo si el uso real es web y existe el registro de autorización.

---

## 8. Riesgos y el orden en que recortaríamos

Ningún plan ambicioso sobrevive sin nombrar sus riesgos y cómo pensamos mitigarlos:

| Riesgo                                                     | Cómo lo mitigamos                                                          |
|-----------------------------------------------------------|---------------------------------------------------------------------------|
| Falsos positivos por versión (backports)                  | El par `qod`/`confirmed`; los confirmadores de la Fase R; el escaneo autenticado de la Fase 4 |
| Coste de mantenimiento del diccionario de CPE y los checks | Los alias como "una línea nueva"; la ingesta de Nuclei; el feed versionado con CI |
| Riesgo legal, porque las Fases R y T tocan el objetivo    | El registro de objetivos autorizados como prerrequisito; el modo `safe` por defecto |
| Deriva de alcance hacia "clonar OpenVAS"                  | Las anti-metas del apartado 1; el beachhead estrecho; la disciplina del 80/20 |
| Coste del repositorio nativo                              | Aparcado hasta tener evidencia de rendimiento; el fallback en Python siempre presente |
| Frescura del feed                                         | Deltas diarios y el `feed_version` registrado en cada escaneo             |

Y si en algún momento hubiera que recortar por falta de recursos, el orden de sacrificio sería este:
primero el análisis web activo, luego el fingerprint de sistema operativo, después el transporte raw
nativo, y por último el escaneo autenticado. Lo que no se recorta nunca, porque es el esqueleto de la
identidad y de la confianza, son tres cosas: el modelo `Finding` unificado, la base de conocimiento
local con la señal de explotabilidad, y el banco de pruebas con integración continua.

---

## 9. Por dónde empezar esta misma semana

Si quieres un primer resultado tangible con el mínimo esfuerzo, este es el camino crítico. Empieza por
una Fase 0 ligera: el refactor del CPE (los cuatro toques), luego `ScanType.LYBRA`, el modelo
`Finding` con su migración, y un `LybraEngineManager` que acepte como entrada una lista de servicios
(host, puerto, servicio, versión, CPE). No lances Nmap internamente; recibe los servicios como
parámetro. El usuario puede obtenerlos de un Nmap Scan anterior.

A continuación monta una Fase R en pequeño, con un solo check declarativo —por ejemplo el de
`.git/config` expuesto— y un check de versión que, de momento, consulte la API de CIRCL que ya usa
Aegis. Con eso tienes un motor propio de detección funcionando en cuestión de días, reutilizando código
existente, sin descubrimiento propio aún.

Demuéstralo contra servicios conocidos: toma `vulhub/httpd:2.4.49`, haz un Nmap para obtener el CPE,
luego lanza un Lybra Scan pasando esos servicios de entrada, y valida que detecta la CVE-2021-41773.
Toma una imagen con `.git` expuesto, haz lo mismo, y valida que el check activo lo encuentra. Y solo
entonces invierte en la Fase 2 (la base de conocimiento local, que quita la dependencia de red), en las
Fases F y T (el fingerprint y el transporte propios, con Nmap como oráculo) y en ampliar el conjunto de
checks. Esa secuencia te da un MVP defendible muy pronto y convierte la independencia de Nmap, Nikto y
OpenVAS en un proceso incremental, no en un big-bang.

---

## 10. Resumen de entregables por fase

| Fase | Pista       | Capa | Qué entrega                                                          | De qué nos independiza          |
|------|-------------|------|---------------------------------------------------------------------|---------------------------------|
| 0    | Correlación | —    | CPE persistido, `ScanType.LYBRA`, modelo `Finding`, fontanería completa | —                          |
| 1    | Correlación | L3   | El matcher de CPE a CVE (detección por versión)                     | La lógica de detección, ya propia |
| R    | Bajo nivel  | L2   | El runtime de checks (declarativos y Python), con feed versionado   | **Nikto**                       |
| 2    | Correlación | L3   | La KB local (NVD, KEV, EPSS, CPE, OSV/GHSA, explotabilidad), firmada | CIRCL/NVD en tiempo de escaneo  |
| F    | Bajo nivel  | L1   | El fingerprinting propio (JARM, favicon, HASSH), con oráculo Nmap    | `nmap -sV`, que pasa a oráculo  |
| T    | Bajo nivel  | L0   | El transporte propio (connect asyncio, SYN sin estado, sondas UDP)  | El descubrimiento de Nmap       |
| 5    | Correlación | L3   | El modelo de activo, la dedup multi-fuente, el ciclo de vida y el scoring | Las herramientas sueltas   |
| 4    | Correlación | L2   | El escaneo autenticado de paquetes del SO, vía el vault de Acheron   | Cubre los backports (nicho)     |
| DAST | Bajo nivel  | L2   | El análisis web activo y acotado (crawl y sondas seguras)            | ZAP/Nikto para webapp (opcional) |
| 6    | —           | L4   | El pipeline orquestado; Nmap/Nikto/OpenVAS como corroboradores       | **Objetivo cumplido**           |

Este es un documento vivo. Ajusta el orden de las fases a tu superficie real de objetivos: si tu uso es
sobre todo web, prioriza la Fase R y el análisis activo; si es sobre todo inventario de red y
servidores, prioriza las Fases 1 y 2 y luego F y T. La regla que no cambia es siempre la misma: lidera
por la capa L2, que es la que da identidad; baja de nivel solo cuando la evidencia del oráculo lo
respalde con un umbral numérico; y retira cada dependencia externa únicamente cuando tu capa propia la
iguale en el laboratorio.

---

## Glosario

Términos técnicos que aparecen en el documento, en orden aproximado de aparición.

**Themis** — El módulo de la API encargado de los escaneos. Es donde vive el motor Lybra.

**Lybra Engine** — El motor de detección de vulnerabilidades propio que describe este plan.

**Orquestador** — Un sistema que se limita a invocar herramientas externas y recoger su salida, sin
lógica de detección propia. Es lo que Themis es hoy, y lo que este plan pretende superar.

**Nmap** — Escáner de red estándar de la industria, usado para descubrir puertos y, con la opción
`-sV`, identificar servicios y versiones.

**Nikto** — Escáner de vulnerabilidades web que comprueba rutas y configuraciones peligrosas conocidas.

**OpenVAS / Greenbone** — Escáner de vulnerabilidades de código abierto, maduro y muy amplio, con un
feed de más de cien mil comprobaciones (NVTs).

**Nuclei** — Motor que ejecuta plantillas de detección declarativas (en YAML), con un gran feed
comunitario orientado a la web. Diseñamos nuestro DSL para poder ingerir sus plantillas.

**CVE** *(Common Vulnerabilities and Exposures)* — El identificador estándar de una vulnerabilidad
concreta, por ejemplo CVE-2021-41773.

**CVSS** *(Common Vulnerability Scoring System)* — La puntuación estándar de gravedad técnica de una
CVE, de 0 a 10.

**CPE** *(Common Platform Enumeration)* — El identificador estándar de un producto y versión de
software, por ejemplo `cpe:2.3:a:apache:http_server:2.4.49`. Existe una forma antigua (2.2,
`cpe:/a:...`) que emite Nmap y una moderna (2.3) que usa NVD; hay que convertir de una a otra.

**NVD** *(National Vulnerability Database)* — La base de datos de vulnerabilidades del NIST, fuente
canónica de CVEs, CVSS y CPE.

**CIRCL** — Un servicio (`cve.circl.lu`) que expone datos de CVEs por API. Hoy lo consultamos en vivo;
la Fase 2 nos independiza de él.

**KEV** *(Known Exploited Vulnerabilities)* — La lista que publica la CISA con las vulnerabilidades que
se están explotando activamente en el mundo real. Una señal muy fuerte de prioridad.

**EPSS** *(Exploit Prediction Scoring System)* — Una puntuación de FIRST que estima la probabilidad de
que una CVE sea explotada en los próximos 30 días.

**OSV.dev / GHSA** — Fuentes de vulnerabilidades centradas en ecosistemas de paquetes de software
(OSV) y en advisories de GitHub (GHSA), a menudo más rápidas que NVD.

**OVAL** — Un formato y unos feeds, mantenidos por las distribuciones de Linux, que permiten saber si un
paquete concreto está realmente parcheado. Es la "verdad" sobre los backports.

**Backport** — La práctica de las distribuciones de aplicar el parche de una vulnerabilidad sin subir el
número de versión visible del software. Es la causa principal de los falsos positivos en la detección
por versión.

**Finding** *(hallazgo)* — El modelo de datos normalizado que unifica los resultados de todos los
escáneres en una sola tabla. La pieza central de la arquitectura.

**QoD** *(Quality of Detection)* — Una medida de 0 a 100 de la confianza en un hallazgo, tomada
conceptualmente de OpenVAS. Un 70 es "detectado por banner"; un 99 es "confirmado activamente".

**confirmed** — El campo booleano que distingue una hipótesis (te veo la versión) de un hecho (lo he
comprobado). Va de la mano del `qod`.

**exploit_maturity** — El campo que indica si existe un exploit público para una CVE y de qué tipo
(desde `none` hasta `in_the_wild`). Es la señal diferencial de nuestra priorización.

**dedup_key** — Una clave hash que permite fusionar en un solo `Finding` los hallazgos de varias fuentes
sobre la misma vulnerabilidad, host y puerto.

**NVT feed** — El conjunto versionado de comprobaciones de OpenVAS/Greenbone. Nuestro equivalente propio
es el "Lybra Feed".

**Lybra Feed** — Nuestro conjunto propio de checks y de base de conocimiento, versionado y firmado,
tratado como un artefacto de producto.

**Check declarativo** — Una comprobación escrita en YAML (petición más matchers), segura de ingerir de
terceros. Cubre el 90% de los casos de web y banner.

**Check de tipo script** — Una comprobación escrita en Python para lógica compleja. Solo se admiten los
de primera parte, revisados por nosotros.

**Matcher** — La regla de un check que decide si una respuesta coincide (por código de estado, por
palabra, por regex, por tiempo, etc.).

**Extractor** — La parte de un check que captura datos de una respuesta para guardarlos en variables
reutilizables.

**Workflow versión→confirmador** — El encadenamiento por el que un check de versión que da positivo
dispara una comprobación activa que, si tiene éxito, asciende el hallazgo de hipótesis a hecho. La
novedad clave frente a Nuclei.

**Fingerprinting** — La identificación de un servicio, producto y versión a partir de cómo responde a la
red. La capa L1 del motor.

**Dissector** — El componente que analiza un protocolo concreto (TLS, HTTP, SSH…) para producir ese
fingerprint.

**JARM** — Una técnica de fingerprinting del lado del servidor para TLS: envía diez saludos distintos y
hashea el conjunto de respuestas. (No confundir con JA3/JA4, que fingerprintean al cliente.)

**HASSH** — El equivalente de JARM para SSH: fingerprintea el servidor por su lista de algoritmos de
intercambio de claves.

**Hash de favicon** — La técnica, popularizada por Shodan, de identificar tecnología por el hash
(`mmh3`) del icono del sitio.

**Transporte** — La capa L0 del motor: el descubrimiento de puertos propiamente dicho.

**connect-scan** — Un escaneo de puertos que abre una conexión completa; no necesita privilegios pero es
más lento. Es nuestro modo base y nuestro fallback.

**SYN sin estado (stateless)** — Un escaneo rápido, al estilo de masscan, que no guarda estado por
conexión porque deriva el número de secuencia del propio objetivo.

**Cookie SipHash** — El truco criptográfico que hace posible el SYN sin estado: codifica el objetivo en
el número de secuencia para poder validar las respuestas sin haber almacenado nada.

**AIMD** *(Additive Increase, Multiplicative Decrease)* — La estrategia de control de ritmo que sube la
velocidad de forma lineal y la recorta a la mitad ante señales de saturación, para no tumbar el objetivo.

**CAP_NET_RAW** — Una capability de Linux que permite enviar paquetes crudos (raw). La preferimos a
`sudo` completo por ser mucho menos privilegio.

**masscan** — Un escáner de puertos de altísima velocidad cuyo modelo sin estado inspira nuestra Fase T.

**DAST** *(Dynamic Application Security Testing)* — El análisis de seguridad de una aplicación web en
ejecución. Nuestra versión es acotada y opcional, no un Burp o un ZAP completos.

**RQ** *(Redis Queue)* — El sistema de colas de trabajos en segundo plano, con workers en procesos
separados, que ya usa la API.

**UnitOfWork** — El patrón transaccional con el que la aplicación persiste en la base de datos. El motor
lo usa de forma síncrona, fuera del event loop.

**Isla asyncio** — La forma de encapsular la concurrencia asíncrona del motor dentro del worker de RQ,
sin convertir el resto de la aplicación, que sigue siendo síncrona.

**Acheron** — El módulo del vault cifrado que guarda credenciales. La Fase 4 lo usa para el escaneo
autenticado.

**Oráculo diferencial** — La técnica de usar una herramienta externa (Nmap, OpenVAS) como "verdad de
referencia" contra la que medir la concordancia de nuestra capa propia en el laboratorio.

**Beachhead** — El vertical estrecho y ganable por el que empezamos (la higiene y exposición de activos
expuestos a Internet) antes de expandirnos.

**Controls, Not Counts** — La filosofía, que ya aplicamos en `analyzers.py`, de valorar la comprobación
confirmada sobre el mero recuento de hallazgos potenciales.
