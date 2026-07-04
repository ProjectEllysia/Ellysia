# Ellysia — Motor propio de análisis de vulnerabilidades

> Plan a largo plazo para construir un motor de detección de vulnerabilidades nativo
> dentro del módulo **Sentinel**, de forma que Nmap, Nikto y OpenVAS/Greenbone pasen de ser
> **el motor** a ser **complementos opcionales** que corroboran los hallazgos del motor
> propio (al que en este documento llamamos provisionalmente **Ellysia Engine**).
>
> Documento de diseño. No describe código existente, sino el camino para llegar a él.

---

## 0. Qué significa "bajo nivel" en este documento

Cuando este plan dice **bajo nivel** no se refiere a un lenguaje de programación de bajo nivel
(C/C++/Rust), sino a **independencia de terceros**: que Ellysia **posea la primitiva** en vez de
invocar el binario o el servicio de otro. Hoy Sentinel *orquesta* herramientas ajenas (Nmap, Nikto,
OpenVAS) y consulta feeds ajenos en runtime (CIRCL). El norte de este documento es que cada capa del
motor —descubrimiento, fingerprinting, detección, correlación— tenga una **implementación propia**,
y que esas herramientas externas se conviertan en **oráculos de contraste y fallback**, no en el
corazón del producto.

El lenguaje es secundario a ese objetivo. El plan se construye en **Python** (el stack actual), con
un enfoque **híbrido pragmático** para la parte de red. Un componente nativo (repo hermano estilo
`Ellysia-AcheronMobile`) es **viable pero opcional**, reservado para un único cuello real de
rendimiento; se evalúa en §2.3. En una frase: *bajo nivel = "no dependemos de nadie en runtime", no
"lo escribimos en ensamblador".*

---

## 1. Veredicto de factibilidad

**Es factible, pero la pregunta correcta no es "¿puedo reescribir OpenVAS?".** OpenVAS/Greenbone
son ~20 años de ingeniería y más de 100.000 plugins NASL. Replicar eso desde cero, en solitario,
no es realista ni necesario.

Lo que **sí** es realista —y de hecho de muy alto valor— es construir un motor con **capas propias**
que:

1. **Reutilice lo que ya recolectas.** Tu escaneo Nmap ya corre con `-sV` y tu parser de XML
   **ya lee el elemento `<cpe>`** (`processors.py:228`). El dato *se obtiene*, pero hoy **se
   descarta** antes de llegar a la base de datos (ver §2.1). Es la entrada natural para un motor
   basado en versiones, pero requiere un refactor pequeño y acotado antes de poder usarlo.
2. **Empiece por el 80/20:** un *matcher* CPE → CVE (detección por versión). Esto cubre una
   fracción enorme de lo que hace OpenVAS (las comprobaciones tipo *"remote_banner"*, que en
   OpenVAS son QoD ~30–80%) con una fracción mínima del esfuerzo.
3. **Crezca hacia un runtime de detección propio** (checks declarativos + plugins Python), y luego
   hacia **transporte y fingerprinting propios**, retirando dependencias externas una a una.
4. **Mantenga Nmap, Nikto y OpenVAS como corroboradores/oráculos opcionales**, no como el corazón
   del producto.

Esta es, literalmente, la trayectoria que siguieron los escáneres reales: primero detección por
banner/versión, después comprobaciones activas, después descubrimiento y fingerprinting propios,
después escaneo autenticado. Vamos a recorrer ese mismo camino, pero apoyándonos en infraestructura
que **ya tienes**.

### Reencuadre: de "correlación" a "motor con capas propias"

La versión anterior de este documento se detenía —con buen criterio— en una capa **alta**:
correlación CPE→CVE apoyada en Nmap para descubrir y en CIRCL para los CVE. Eso ya es un motor de
detección propio *en la lógica de vulnerabilidad*, pero sigue **prestando** el descubrimiento y el
fingerprinting a terceros. La ambición de este plan es hacer propias también esas capas inferiores,
porque es ahí donde nace la **identidad** del producto: un criterio propio de identificar servicios
y de comprobar vulnerabilidades, versionado y reproducible, que no depende de que un binario ajeno
esté instalado.

### Lo que ya tienes a favor (no partes de cero)

| Pieza que necesita el motor | Dónde ya existe en tu repo |
|---|---|
| Descubrimiento de servicios + versión (`-sV`) | `NmapScanTask` (`tasks.py:271`) + `NmapResultProcessor` |
| Lectura del `<cpe>` desde el XML de Nmap | `_parse_nmap_xml` lo parsea (`processors.py:226-230`) — ⚠️ **pero se descarta después; ver §2.1** |
| Consumo de feeds CVE (NVD/CIRCL, INCIBE) | `aegis/services/pills.py` (`AegisAlertFetcher`, `cve.circl.lu`) |
| Clasificación de severidad CVSS | `sentinel/services/processors.py` (`_categorize_severity`) |
| Heurística de detección web (paths peligrosos, headers…) | `sentinel/services/processors.py:294` (`_classify_threat_level` de Nikto) |
| Abstracción de "ejecutar un escáner asíncrono" | `sentinel/services/tasks.py` (`_Task`, ABC) |
| Modelo de escaneo extensible (polimórfico) | `sentinel/model.py` (`Scan` + `polymorphic_on=scan_type`) |
| Registro dinámico de escáneres | `@ScanManager.register(ScanType.X)` (`managers.py:603-620`) |
| Persistencia transaccional | `infrastructure` (`UnitOfWork`, `BaseRepository`, `ScanRepository`) |
| Cola de trabajos / aislamiento de procesos | `system/taskqueue` (RQ + Redis, workers en procesos separados) |
| Programación de escaneos | `sentinel/services/scheduling.py` (APScheduler) |
| Enriquecimiento y reporte con IA | `scribe` + `sentinel/services/analyzers.py` |
| Historial por host (para ciclo de vida de vulns) | `ScanHistoryManager` (`sentinel/services/history.py`) |
| Contexto de exposición (IP privada vs pública) | `analyzers.py:70` (`_classify_network_context`) |
| Vault cifrado para credenciales (escaneo autenticado) | `acheron` (`Vault`, `VaultManager`) |
| Convención de config y feeds | `SecOpsConfig.json` + `config_reading.py` (patrón `CR.get_*`) |

El trabajo, por tanto, es **integración, correlación y construcción incremental de capas propias**,
no construir cada ladrillo de cero.

### Lo que NO conviene construir (trampas de alcance) — y las dos que este plan cruza a propósito

La versión anterior listaba estas trampas. Dos de ellas **este plan las cruza deliberadamente**,
porque son la fuente de la identidad — pero **con guardarraíles**, no a lo loco:

- ~~Tu propio motor de fingerprinting de red~~ → **Sí, pero calibrado por oráculo.** Se construye una
  base de firmas **pequeña y curada** (§Fase F), y **Nmap `-sV` es la verdad de referencia** en el
  laboratorio: solo se confía en la firma propia donde concuerda con Nmap. Crece por evidencia, no
  por ambición.
- ~~Un intérprete NASL completo~~ → **No un NASL; un runtime moderno y acotado.** No se reimplementa
  NASL. Se diseña algo **más pequeño y sano**: DSL declarativo (YAML) + plugins Python de primera
  parte (§Fase R). El objetivo no es cobertura total, sino un runtime propio, versionado y
  extensible.

Las que **siguen siendo trampas** y no se cruzan:

- Tu propio feed de CVEs curado a mano. Refleja (mirror) NVD/CISA-KEV/EPSS (§Fase 2).
- Cobertura "completa" comparable a OpenVAS. Apunta al 80/20 de tu superficie real.

---

## 2. Principio de arquitectura: el motor es **otro `ScanType`**… y un **stack vertical propio**

La decisión de diseño más importante sigue siendo no tratar el motor como algo "aparte", sino como un
nuevo tipo de escaneo de primera clase que encaja en tus abstracciones actuales:

```
ScanType.NMAP     → NmapScanTask     → NmapResultProcessor     → NmapScanManager
ScanType.NIKTO    → NiktoScanTask    → NiktoResultProcessor    → NiktoScanManager
ScanType.OPENVAS  → OpenVASTask      → OpenVASResultProcessor  → OpenVASScanManager
ScanType.ELLYSIA (★) → EllysiaEngineTask → EllysiaResultProcessor → EllysiaEngineManager   ← NUEVO
```

Añadir esa fila es mecánico gracias al registro por decorador
(`@ScanManager.register(ScanType.ELLYSIA)`, `managers.py:603`) sobre el modelo polimórfico
(`polymorphic_on=scan_type`, `model.py`). El motor hereda "gratis": cancelación cooperativa,
progreso, persistencia, programación, carpetas, generación de PDF y enriquecimiento IA.

### El motor como **stack vertical** (la novedad conceptual)

Pero un `ScanType` es solo el envoltorio. La sustancia es que, **dentro** de esa fila, Ellysia
construye un **stack propio de abajo a arriba**, y cada capa retira una dependencia externa:

```
L4  Orquestación / pipeline              (Fase 6)            — OpenVAS pasa a corroborador opcional
L3  Correlación · KB · ciclo de vida     (Fases 2 y 5)       — independiza de CIRCL/NVD en runtime
L2  ★ Runtime de detección propio        (Fase R) ← IDENTIDAD — reemplaza a Nikto  [checks DSL + Python]
L1  Fingerprinting propio                (Fase F)            — reemplaza a Nmap -sV  [dissectors + firmas]
L0  Transporte / sondeo propio           (Fase T)            — reemplaza al descubrimiento de Nmap
```

El motor del roadmap original vive en **L3/L4** y toma **L0/L1 prestados de Nmap**. La ampliación de
este documento es **construir L0, L1 y —sobre todo— L2 como propios**, y hacer que Nmap/Nikto se
deslicen de "motor" a "oráculo/fallback" de forma incremental, sin big-bang. **La capa por la que se
lidera es L2** (el runtime de detección): es la que da identidad tangible y la que se puede montar
sobre el Nmap existente para obtener valor en días.

### Un modelo de hallazgo (`Finding`) unificado — la pieza que falta

Hoy cada escáner tiene su propia tabla de resultados (`OpenPort`, `NiktoIncident`,
`OpenVASScanResult` + `OpenVASVulnerability`). Para un motor propio necesitas un modelo de hallazgo
**normalizado**, común a todos los orígenes. Propuesta (en `sentinel/model.py`):

```python
class Finding(Base):
    """Hallazgo normalizado, independiente del escáner que lo produjo."""
    __tablename__ = "Finding"

    id              = Column(Integer, primary_key=True)
    scan_id         = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), index=True)
    host_id         = Column(Integer, ForeignKey("Host.id"), index=True)

    # Qué se encontró
    title           = Column(Text, nullable=False)
    category        = Column(String(64))      # "outdated_software" | "tls" | "exposed_path" | ...
    port            = Column(Integer)
    service         = Column(String(128))     # "http", "ssh"...
    cpe             = Column(String(255), index=True)  # cpe:2.3:a:apache:http_server:2.4.49:...

    # Correlación de vulnerabilidad
    cve_ids         = Column(JSONB)           # ["CVE-2021-41773", ...]
    cvss_score      = Column(Float)
    cvss_vector     = Column(String(255))
    epss_score      = Column(Float)           # probabilidad de explotación (FIRST/EPSS)
    in_kev          = Column(Boolean, default=False)  # CISA Known Exploited Vulnerabilities

    # Calidad / procedencia (clave para deduplicar y para confianza)
    source          = Column(String(32))      # "ellysia" | "nikto" | "openvas" | "nmap"
    check_id        = Column(String(128))     # qué check propio lo produjo (trazabilidad del feed)
    qod             = Column(Integer)         # Quality of Detection 0–100 (idea de OpenVAS)
    confirmed       = Column(Boolean, default=False)  # comprobación activa vs sólo versión

    # Ciclo de vida
    first_seen_at   = Column(DateTime, default=datetime.utcnow)
    last_seen_at    = Column(DateTime, default=datetime.utcnow)
    state           = Column(String(20), default="open")  # open | fixed | regressed | accepted
```

Con esto, los hallazgos de tu motor, de Nikto y de OpenVAS viven en la **misma tabla** y se pueden
correlacionar: si los tres detectan la misma CVE en el mismo host:puerto, es un único `Finding`
con `qod` alto y `source` múltiple. Ése es exactamente el salto cualitativo respecto a "tres
escáneres que devuelven tres listas inconexas". El campo `check_id` añade **trazabilidad al feed
propio**: cada hallazgo sabe qué versión de qué check lo generó.

---

## 2.1 Pre-requisito crítico: hoy el CPE se obtiene… pero se descarta

> Esta sección responde directamente a la duda *"con lo que tengo en Nmap, ¿de verdad obtengo el
> CPE?, ¿no hace falta un refactor?"*. La respuesta corta es: **lo obtienes, pero lo tiras — y sí,
> hace falta un refactor (pequeño).**

**Hoy NO puedes recuperar el CPE de un servicio escaneado**, aunque Nmap te lo entrega y tu parser
de XML lo lee. El dato recorre casi todo el camino y se cae en los dos últimos pasos. El arreglo es
**pequeño y muy acotado**: 3 cambios de código + 1 migración. No es un rediseño; es "dejar de tirar
un dato que ya tienes en la mano".

> **Nota (con L1 propio):** una vez exista el fingerprinting propio (Fase F), el CPE dejará de venir
> *solo* de Nmap — también lo producirán tus dissectors. Pero este refactor sigue siendo el punto de
> entrada y el fallback natural, así que se hace igual y primero.

### El recorrido real del CPE en tu código

| Paso | Fichero | ¿El CPE sobrevive? |
|---|---|---|
| 1. Comando Nmap usa `-sV` | `tasks.py:271` (`NmapScanTask._build_command`) | ✅ `-sV` hace que Nmap emita `<cpe>` cuando reconoce el servicio |
| 2. Parseo del XML | `processors.py:226-230` (`_parse_nmap_xml`) | ✅ Lee `<cpe>` y lo guarda en `port_data["cpe"]` |
| 3. Re-estructuración | `_parse_nmap_structure` (`processors.py`) | ❌ **Se descarta**: arma una tupla de 6 campos `(protocolo, state, reason, product, version, name)` que **no incluye cpe** |
| 4. `process()` → `ports_data` | `processors.py` | ❌ Consecuencia del paso 3: los dicts ya no llevan `cpe` |
| 5. Persistencia | `repositories.py:450` (`persist_nmap_results`) | ❌ Crea `OpenPort(reason, product, version, given_use)` |
| 6. Modelo | `model.py` (`OpenPort`) | ❌ **No existe columna `cpe`** donde guardarlo |

Es decir: el escaneo SÍ produce el CPE (paso 1) y tu código SÍ lo parsea (paso 2), pero la tupla
del paso 3 lo tira y, aunque no lo tirara, el modelo del paso 6 no tiene dónde guardarlo.

### El refactor necesario (4 toques)

1. **Modelo `OpenPort`** (`model.py`): añadir columna y generar migración Alembic.
   ```python
   cpe = Column(String(255), nullable=True)   # cpe:/a:apache:http_server:2.4.49 (forma 2.2 de Nmap)
   ```
   ```bash
   alembic revision --autogenerate -m "add cpe to OpenPort"
   ```

2. **`_parse_nmap_structure`** (`processors.py`): dejar de descartar el `cpe` que ya está en
   `port_info`. Lo más limpio es pasar de tupla posicional a dict:
   ```python
   for port_number, port_info in tcp_ports.items():
       ports.append({
           "protocol":  f"{port_number}/tcp",
           "state":     port_info.get("state", "unknown"),
           "reason":    port_info.get("reason", ""),
           "product":   port_info.get("product", ""),
           "version":   port_info.get("version", ""),
           "given_use": port_info.get("name", ""),
           "cpe":       port_info.get("cpe", ""),   # ← ya existe en port_info, sólo hay que propagarlo
       })
   ```

3. **`process()`** (`processors.py`): incluir `'cpe': ...` en cada dict de `ports_data`
   (si adoptas dicts en el paso 2, desaparece el desempaquetado de 6 campos y queda más limpio).

4. **`persist_nmap_results`** (`repositories.py:450`): pasar el valor al modelo:
   ```python
   open_port = OpenPort(
       ...,
       given_use = port_info["given_use"],
       cpe       = port_info.get("cpe") or None,   # ← nuevo
   )
   ```

Con esos 4 toques, cada `OpenPort` queda con su CPE persistido y el matcher de la Fase 1 ya tiene
de dónde leer.

### Tres matices honestos (no bloquean, pero condicionan la Fase 1)

- **Cobertura parcial.** `-sV` sólo emite `<cpe>` cuando reconoce el servicio contra su base
  `nmap-service-probes`. Habrá puertos sin CPE (servicio mudo o banner no reconocido). Para ésos el
  motor debe **construir el CPE desde `product`+`version`** con un diccionario de normalización (ya
  previsto en la Fase 1). Resumen: capturar el CPE de Nmap cubre el caso fácil; el fallback por
  `product`/`version` cubre el resto.
- **Formato 2.2 vs 2.3.** Nmap emite la forma URI antigua (`cpe:/a:apache:http_server:2.4.49`);
  NVD usa la 2.3 (`cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`). La conversión 2.2 → 2.3 es
  trivial pero hay que hacerla antes de casar contra el feed.
- **Múltiples CPE por servicio.** Un servicio puede traer varios `<cpe>` (app + SO). Hoy
  `_parse_nmap_xml` hace `service_el.find("cpe")` y se queda con el **primero**. Para un motor de
  vulnerabilidades conviene `findall` y, si lo quieres bien hecho, guardar una **lista** (columna
  `JSONB` o tabla relacionada) en lugar de un único `String(255)`.

### Detalle del matiz (a): el diccionario de normalización `product`/`version` → CPE

Este es, de los tres matices, el que más trabajo de mantenimiento implica a largo plazo, así que
merece su propio desglose.

**¿Cuándo entra en juego?** Nmap sólo rellena `<cpe>` cuando el banner que detecta coincide con una
entrada de su propia base `nmap-service-probes` que además tiene un CPE asociado. En la práctica,
con `-sV` te vas a encontrar tres situaciones:

| Situación | Ejemplo de salida Nmap | ¿Hay `<cpe>`? |
|---|---|---|
| Servicio muy común, bien fingerprinteado | `Apache httpd 2.4.49` | Sí — `cpe:/a:apache:http_server:2.4.49` |
| Servicio reconocido pero variante rara / banner parcial | `nginx (reverse proxy)`, sin versión exacta | A veces no, o CPE sin versión |
| Banner genérico, custom o mal identificado | `product="ssh"`, `version=""` | No |

Para el segundo y tercer caso, el motor tiene que **construir** el CPE a partir de los strings
`product` y `version` que Nmap sí entrega casi siempre, aunque no entregue el `<cpe>`. Eso es lo que
hace el diccionario de normalización.

**Qué NO conviene hacer:** escribir a mano un `if "Apache" in product: vendor="apache"` gigante y
quebradizo. Con cientos de productos distintos eso se vuelve inmantenible y, peor, **inventa** un
CPE que puede no existir en el diccionario oficial de NVD, lo que rompería el matcher de la Fase 1
(un CPE que no aparece en `CpeMatch` simplemente no devuelve CVEs, en silencio).

**Lo que sí conviene: apoyarse en la fuente oficial.**

1. **Fuente canónica:** el [CPE Dictionary de NVD](https://nvd.nist.gov/products/cpe) (oficial,
   gratuito, descargable como XML/JSON) contiene todas las combinaciones `vendor:product` válidas,
   más sus nombres "humanos" (`title`). Es el mismo feed que ya planeas mirrorar en la Fase 2 (tabla
   de §3, fila "CPE Dictionary (NVD)"), así que **no es trabajo nuevo: es reutilizar el mirror que
   ya vas a tener**.
2. **Índice invertido, no diccionario plano.** En vez de mapear "string exacto de Nmap" →
   "CPE", se construye un índice de **tokens** sobre el campo `title` de cada entrada del CPE
   Dictionary (p.ej. `apache:http_server` tiene title "Apache HTTP Server"). Al normalizar un
   `product` de Nmap, se tokeniza igual y se buscan los `vendor:product` cuyos tokens tengan mayor
   solape.
3. **Tabla de excepciones manual, pequeña y versionada.** El índice automático falla con alias
   conocidos (Nmap dice "OpenSSH", el CPE oficial es `openbsd:openssh`; dice "MySQL", el CPE es
   `mysql:mysql` salvo que sea MariaDB, que es `mariadb:mariadb`). Para esos casos frecuentes, una
   tabla de overrides explícita gana siempre al índice automático.

**Ejemplo de la tabla de overrides** (la semilla, no la lista completa — crece con cada falso
negativo que se detecte en producción):

```python
# sentinel/services/kb/cpe_overrides.py
# Mapea el `product` tal como lo emite Nmap (lowercased) a (vendor, product) CPE.
# Se consulta ANTES que el índice automático del CPE Dictionary.
CPE_PRODUCT_OVERRIDES: dict[str, tuple[str, str]] = {
    "apache httpd":              ("apache", "http_server"),
    "openssh":                   ("openbsd", "openssh"),
    "nginx":                     ("nginx", "nginx"),
    "microsoft iis httpd":       ("microsoft", "internet_information_services"),
    "mysql":                     ("mysql", "mysql"),
    "mariadb":                   ("mariadb", "mariadb"),
    "vsftpd":                    ("vsftpd_project", "vsftpd"),
    "proftpd":                   ("proftpd", "proftpd"),
    "postfix smtpd":             ("postfix", "postfix"),
    "dovecot imapd":             ("dovecot", "dovecot"),
    "pure-ftpd":                 ("pureftpd", "pure-ftpd"),
    "exim smtpd":                ("exim", "exim"),
}
```

**Función de normalización, con las tres capas en orden de confianza decreciente:**

```python
# sentinel/services/kb/cpe_normalizer.py
import re
from difflib import SequenceMatcher

def normalize_product_to_cpe(product: str, version: str | None) -> tuple[str | None, float]:
    """
    Devuelve (cpe_2_3_o_None, confidence) donde confidence ∈ [0, 1].
    confidence se usa luego para calibrar el `qod` del Finding (ver Fase 1).
    """
    key = product.strip().lower()

    # 1) Override manual exacto → confianza máxima.
    if key in CPE_PRODUCT_OVERRIDES:
        vendor, prod = CPE_PRODUCT_OVERRIDES[key]
        return _build_cpe23(vendor, prod, version), 0.95

    # 2) Búsqueda por tokens contra el CPE Dictionary mirrorado (Fase 2).
    match, score = _best_cpe_dictionary_match(key)  # similitud de tokens, 0..1
    if match and score >= 0.6:
        return _build_cpe23(match.vendor, match.product, version), score * 0.8

    # 3) Sin match suficientemente bueno → no se inventa un CPE.
    return None, 0.0


def _build_cpe23(vendor: str, product: str, version: str | None) -> str:
    v = _normalize_version(version) if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def _normalize_version(version: str) -> str:
    # Nmap a veces añade sufijos tipo "2.4.49 ((Unix))" — nos quedamos con el
    # número de versión limpio que NVD espera en el campo `version` del CPE.
    m = re.match(r"^[\d][\w.\-]*", version.strip())
    return m.group(0) if m else "*"
```

**Tres niveles de confianza, y por qué importan para la Fase 1:**

| Vía | Confianza | Efecto en el `Finding` |
|---|---|---|
| CPE directo del XML de Nmap (`<cpe>`) | Alta (es Nmap quien lo afirma) | `qod=70` |
| Fingerprint propio (Fase F) concordante con oráculo | Alta (curado + calibrado) | `qod=70` |
| Override manual (tabla de excepciones) | Alta (curado a mano) | `qod=70` |
| Match por índice de tokens del CPE Dictionary | Media, proporcional al `score` | `qod` escalado, p.ej. `round(50 + score*20)` |
| Sin match | — | No se genera `Finding` por versión para ese puerto; sólo el informativo de "puerto abierto" de Fase 0 |

Esto es importante: **un CPE de baja confianza no debe tratarse igual que uno de Nmap directo**. Si
en algún momento quieres ser más estricto, basta con subir el umbral `score >= 0.6` o con bajar el
factor `* 0.8` — son dos números, no un rediseño.

**Ejemplo de principio a fin con fallback:**

```
Nmap detecta:  product="OpenSSH", version="7.4", sin <cpe> (banner truncado)
Override hit:  "openssh" → ("openbsd", "openssh")        confidence=0.95
CPE construido: cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*
Finding:       qod=70, source="ellysia", confirmed=false
```

**Mantenimiento real:** este diccionario no se escribe una vez y se olvida. El patrón sano es:
cuando el matcher de Fase 1 falla en detectar algo que un escaneo manual sí encuentra, la causa raíz
casi siempre es "el product de Nmap no mapeaba a ningún CPE" — y la corrección es **una línea nueva**
en `CPE_PRODUCT_OVERRIDES`, no un cambio de arquitectura. Merece la pena loguear (a nivel `debug`)
cada vez que `normalize_product_to_cpe` devuelve `None`, para tener una lista priorizada de qué
overrides añadir primero.

**En una frase:** el escaneo y el parser ya hacen el 80% del trabajo; el refactor que falta es
pequeño y localizado, pero **sí es necesario** — sin él, hoy el CPE no llega a la base de datos y no
podrías alimentar el matcher.

---

## 2.2 Reconciliar un núcleo `asyncio` de bajo nivel con un backend síncrono

Todo el motor de bajo nivel (sondeo concurrente, dissectors, checks) quiere **concurrencia de I/O**:
miles de sockets a la vez. El stack actual es **Python 3.14 síncrono** (threading + `urllib`, **sin
asyncio**). No hay que convertir la app: hay que **encapsular**.

- **El resto de la app no se toca.** Sigue síncrona: Flask, threading, RQ, `urllib`. Nada de
  `async def` en repositorios, managers de otros escáneres, ni endpoints.
- **El motor introduce `asyncio` dentro del RQ worker, y solo ahí.** El punto de entrada del escaneo
  (`EllysiaEngineManager.execute_ellysia_scan`, `@staticmethod` que corre en el worker) hace:
  ```python
  with job_context() as job:                     # progreso/cancelación, igual que los demás escáneres
      results = asyncio.run(engine.scan(target, cancel_check=job.cancelled,
                                         progress=job.progress))
      # persistir de forma síncrona, fuera del loop:
      with UnitOfWork() as uow:
          ScanRepository(uow).persist_findings(scan, results)
  ```
  El event loop **nace y muere dentro del proceso worker**, aislado. Como los workers RQ son procesos
  separados, no hay contagio al proceso Flask ni a otros jobs.
- **SQLAlchemy fuera del loop.** No se mezcla `asyncio` con la sesión ORM (síncrona). El motor
  produce `Finding`s en memoria durante el escaneo y **persiste al terminar**, en código síncrono
  normal con `UnitOfWork`. Nada de ORM async.
- **Privilegios y degradación.** Nmap hoy corre con `sudo -n`. Para el motor propio, preferir
  otorgar **`CAP_NET_RAW`** al contenedor del worker (menos privilegio que `sudo` completo). El
  transporte (Fase T) usa **raw SYN/UDP cuando la capability está** y **degrada elegantemente a
  connect-scan** cuando no. Regla dura: *nunca fallar por falta de raw; solo ir más lento.*

En resumen: el bajo nivel vive en una **isla asyncio dentro del worker**, con fronteras síncronas
limpias a ambos lados (submit vía RQ; persistencia vía `UnitOfWork`). Es el cambio mínimo que hace
realista todo lo demás sin reescribir el backend.

---

## 2.3 La idea del repo nativo (C/C++/Rust) estilo `Ellysia-AcheronMobile`

El usuario baraja crear un repo hermano con código nativo (C/C++) que extraiga y procese información
de seguridad de un endpoint, siguiendo el patrón de `Ellysia-AcheronMobile`. Evaluación honesta:

- **Qué resolvería de verdad.** Un **único** cuello justifica código nativo: el **motor de paquetes
  de alto rendimiento** — SYN/UDP *stateless* a gran escala (estilo masscan/zmap), timing fino de
  red y parseo de respuestas crudas. Ahí Python tiene techo real. El resto del motor (runtime de
  checks, correlación, KB, informes, fingerprinting a escala normal) **no gana nada** en C/C++ y sí
  pierde velocidad de desarrollo.
- **Recomendación: no es el cimiento.** La independencia de terceros —el objetivo real de "bajo
  nivel"— **ya se logra con el híbrido Python**. Un `connect`-scan asyncio y dissectors en Python no
  dependen de Nmap. El repo nativo entra **solo si** el laboratorio demuestra que el escaneo Python
  no da el throughput que tu superficie real necesita. Es una **optimización de la Fase T**, no un
  pre-requisito de nada.
- **Si se hace, cómo encaja.** Exactamente como Acheron: repo hermano (`Ellysia-Probe` o similar)
  que compila una librería nativa consumida desde el worker vía **FFI (`ctypes`/`cffi`) o PyO3**, con
  un **fallback Python puro siempre presente** — para desarrollo en Windows/macOS y para entornos sin
  la librería compilada. Es el mismo patrón "núcleo nativo + capa Python verificada por vectores
  compartidos" que ya usa Acheron.
- **Coste a asumir con los ojos abiertos.** Toolchain nativa + CI cross-compile + empaquetado por
  plataforma + mantener la paridad con el fallback Python. Por eso se **aparca hasta tener evidencia
  de necesidad**. Queda escrito aquí como *vía de upgrade con techo conocido*, no como trabajo
  comprometido.

**En una frase:** el repo nativo es una palanca de rendimiento futura y opcional, no la definición
de "bajo nivel". La identidad la da poseer las capas (L0–L2), no el lenguaje en que estén escritas.

---

## 3. Hoja de ruta: dos tracks entrelazados

Cada fase es entregable y útil por sí sola. En vez de una lista lineal, conviene verlo como **dos
pistas que avanzan en paralelo y convergen**. Regla de oro: **no se arranca Nmap primero.** Se lidera
con el runtime de detección (L2) sobre el Nmap existente —identidad rápida—, y se hace crecer el
transporte/fingerprinting propio (L0/L1) *al lado* de Nmap usándolo como oráculo, hasta invertir el
default.

- **Track A — Correlación (la columna vertebral del roadmap original):**
  Fase 0 (cimientos + CPE) → Fase 1 (matcher CPE→CVE) → Fase 2 (KB local) → Fase 5 (dedup + ciclo de
  vida + scoring).
- **Track B — Motor de bajo nivel (la ampliación):**
  Fase R (runtime de detección, **lidera**) → Fase F (fingerprinting propio) → Fase T (transporte
  propio).

Convergen en la **Fase 6** (pipeline), donde el motor propio es el protagonista y Nmap/Nikto/OpenVAS
son corroboradores.

### Fase 0 — Cimientos (refactor, ~1–2 semanas) · Track A

**Objetivo:** que "el motor" sea una fila más de la tabla de §2, sin lógica de detección todavía.

- **Capturar y persistir el CPE de Nmap (ver §2.1).** Es el **primer cambio de código del
  proyecto**: columna `cpe` en `OpenPort` + propagarlo en `_parse_nmap_structure`/`process` +
  guardarlo en `persist_nmap_results`. Sin esto, la Fase 1 no tiene de dónde leer el CPE.
- Añadir `ScanType.ELLYSIA = "ellysia"` en `sentinel/model.py` (enum + `polymorphic_identity`).
- Crear el modelo `Finding` y su migración Alembic (`alembic revision --autogenerate`).
- Esqueleto `EllysiaEngineTask(_Task)` en `tasks.py` que de momento sólo envuelva una llamada a Nmap
  ya existente y devuelva sus puertos (sin detección aún).
- `EllysiaEngineManager(ScanManager)` registrado con `@ScanManager.register(ScanType.ELLYSIA)`.
- Endpoint `POST /sentinel/ellysia` (espejo de `/sentinel/nmap`, en `endpoints.py`).

**Definición de hecho:** puedes lanzar un "escaneo Ellysia" que internamente hace un Nmap y persiste
`Finding`s informativos (un finding "puerto abierto" por servicio). Cero detección real todavía,
pero toda la fontanería funciona end-to-end.

---

### Fase 1 — Detección por versión: el *matcher* CPE → CVE (el MVP de correlación) · Track A

**Objetivo:** dado un servicio con producto+versión (que Nmap ya te da), decir qué CVEs conocidas le
afectan, con su CVSS. Conceptualmente, es lo que hace una gran parte de OpenVAS.

**Flujo:**

1. Nmap detecta el servicio. Ej.: `product="Apache httpd"`, `version="2.4.49"`,
   `cpe="cpe:/a:apache:http_server:2.4.49"`.
2. Normalizar a **CPE 2.3**: `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` (con el fallback
   `product`+`version` de §2.1 cuando Nmap no da CPE limpio).
3. Consultar la **base de conocimiento local** (Fase 2) por CPE, respetando los rangos de versión
   de NVD (`versionStartIncluding`, `versionEndExcluding`, etc.).
4. Emitir un `Finding` por CVE con `source="ellysia"`, `cvss_score`, `epss_score`, `in_kev`,
   `qod=70` (detección por banner: fiable pero no confirmada activamente).

**Ejemplo concreto:**

```
Target: 10.0.0.5
Nmap   → 80/tcp open  http  Apache httpd 2.4.49
CPE    → cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Match  → CVE-2021-41773  (Path Traversal / RCE)   CVSS 9.8   EPSS 0.97   KEV=sí
Finding→ {
  "title": "Apache HTTP Server 2.4.49 — Path Traversal / RCE (CVE-2021-41773)",
  "category": "outdated_software", "port": 80, "service": "http",
  "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
  "cve_ids": ["CVE-2021-41773"], "cvss_score": 9.8,
  "epss_score": 0.97, "in_kev": true,
  "source": "ellysia", "qod": 70, "confirmed": false
}
```

> **Cómo encaja con la Fase R:** en el motor unificado, este matcher **no es una pieza aparte**: es
> un *tipo de check* ("version-check") dentro del runtime de detección. Lo describimos aquí porque es
> el MVP de correlación y se puede montar antes que el runtime completo, pero al llegar la Fase R se
> **absorbe** en él.

**Aviso de calibración (falsos positivos):** la detección por versión sufre del problema de los
*backports* — Debian/RHEL parchean CVEs manteniendo el número de versión. Por eso `qod` < 100 y
`confirmed=false`: un hallazgo por versión es "potencialmente vulnerable", no "vulnerable
confirmado". La Fase R (comprobación activa) es la que sube ese hallazgo a `confirmed=true`,
`qod=99`. Esta distinción es exactamente la filosofía "Controls, Not Counts" que ya aplicas en
`analyzers.py`.

**Definición de hecho:** un escaneo Ellysia sobre un host con software desactualizado produce findings
con CVEs reales y CVSS, visibles en la SPA y en el PDF.

---

### Fase R — Runtime de detección propio ("NASL hecho bien") · Track B · ★ LIDERA

**Esta es la capa de identidad (L2).** Absorbe el matcher de versión (Fase 1) y las comprobaciones
activas en **un único motor de checks**, en vez de dejarlos como piezas sueltas. Es lo que convierte
a Ellysia de "correlacionador" en "motor con criterio propio de detección".

**Objetivo:** un runtime propio, versionado y extensible, que dado el conjunto de servicios de un
host decide qué comprobaciones ejecutar y produce `Finding`s normalizados — sin depender de Nikto.

**Diseño: dos niveles de check, por confianza y por quién los escribe.**

1. **Checks declarativos (YAML)** — para el 90% de casos web/banner (petición + matchers). Seguros
   de ingerir de terceros. Diseñar el esquema **razonablemente compatible con plantillas Nuclei**
   para poder ingerir su feed comunitario (miles de plantillas, licencia permisiva) como
   multiplicador de fuerza: tu equivalente al NVT feed, pero para comprobaciones activas.

   ```yaml
   id: git-config-exposure
   version: 1
   category: exposed_path
   severity: HIGH
   service: http
   request:
     method: GET
     path: /.git/config
   matchers:
     - type: status
       value: 200
     - type: word
       part: body
       words: ["[core]", "repositoryformatversion"]
   finding:
     title: "Repositorio Git expuesto (.git/config accesible)"
     qod: 99          # confirmado activamente
     confirmed: true
   ```

2. **Plugins Python de primera parte** — para lógica compleja (TLS, protocolos binarios, secuencias
   multi-paso). **Código propio y revisado**, corre in-process con una **API restringida** del motor
   (primitivas `http`/`tls`/`probe`, límite de tiempo/tasa, gate safe-vs-aggressive). Un plugin
   recibe un `Service` y devuelve `Finding`s.

**Ceiling honesto (deuda consciente):** *no* se construye el día 1 un sandbox que ejecute código
Python de **terceros** — Python no es sandboxeable in-process con garantías. Se lidera con:
declarativos (aptos para community feed) + Python **solo de primera parte, revisado**. Si algún día
se aceptan plugins Python de terceros, la vía de upgrade es **aislarlos en subproceso** con
`rlimit`/seccomp e IPC estrecho — no reescribir el runtime.

**El matcher de versión es un tipo de check más.** El "version-check" de la Fase 1 se implementa como
una clase de check alimentada por la KB (Fase 2). Así, detección pasiva (por versión) y activa
(confirmadores) comparten runtime, modelo `Finding` y feed versionado.

**Motor de aplicación (orden de dependencias):** dado el conjunto de servicios/CPE de un host, el
runtime selecciona qué checks disparar (matching por `service`/`cpe`) y respeta encadenamientos: un
version-check positivo puede **encadenar su confirmador activo** (p.ej. la prueba de path traversal
de CVE-2021-41773 confirma el hallazgo por versión), elevando `qod=70`→`qod=99`,
`confirmed=false`→`true`.

**Semilla gratis:** `NiktoResultProcessor._classify_threat_level` (`processors.py:294`) **ya
contiene** un catálogo enorme de patrones peligrosos (`.git/`, `.env`, `wp-config.php`; cifrados
débiles; métodos HTTP peligrosos…). Es la base del primer set de checks declarativos: en vez de
*clasificar la salida de Nikto*, ahora **tú haces la petición y evalúas**.

**Familias por las que empezar (alto valor, bajo coste):**

1. **Higiene TLS/SSL:** versiones de protocolo (SSLv3/TLS1.0), cifrados débiles, cert
   caducado/autofirmado. (Python + `ssl`/`cryptography`.)
2. **Cabeceras de seguridad HTTP:** HSTS, CSP, X-Frame-Options, cookies sin `Secure`/`HttpOnly`.
3. **Paths sensibles expuestos:** `.git/`, `.env`, `/server-status`, backups, paneles de admin.
4. **Credenciales por defecto:** en servicios identificados (router, phpMyAdmin, Tomcat…).
5. **Confirmadores de CVE muy explotadas (KEV):** convierten un hallazgo por versión en confirmado.

**Feed propio de checks, versionado.** Formato "Ellysia Check" (`.yaml`) + versión del set registrada
en cada escaneo (reproducibilidad, como el NVT feed de Greenbone). El `Finding.check_id` traza qué
check produjo cada hallazgo. **Esto es la identidad tangible del producto.**

**Seguridad de los checks:** tocan el objetivo. Necesitan límite de tasa, modo "safe" (no
destructivo) vs "aggressive", y respetar el gate de autorización que ya tienes (`validate_ip`,
rechazo de IPs privadas, `is_host_reachable`).

**Definición de hecho:** el motor detecta por versión *y* confirma activamente al menos las familias
1–3, todo bajo el mismo runtime y con feed versionado; `qod` sube de 70 a 99 en lo confirmado. En
este punto, **Nikto deja de ser necesario** para el caso web típico.

---

### Fase 2 — Base de conocimiento local de vulnerabilidades (el "feed" propio) · Track A

**Objetivo:** dejar de depender de consultas en vivo a `cve.circl.lu` y tener tu propio espejo
local, rápido y consultable offline — el equivalente al *NVT feed* de Greenbone.

**Fuentes a reflejar (mirror), todas públicas y gratuitas:**

| Fuente | Qué aporta | Frecuencia |
|---|---|---|
| **NVD CVE JSON 2.0** (feeds oficiales) | CVEs + CPE applicability + CVSS | diaria (delta) |
| **CPE Dictionary (NVD)** | normalización producto → CPE | semanal |
| **CISA KEV** | qué CVEs están siendo explotadas activamente | diaria |
| **EPSS (FIRST)** | probabilidad de explotación a 30 días | diaria |
| (opcional) **INCIBE/CIRCL** | ya integradas en `aegis/services/pills.py` | continua |

**Implementación (reutiliza patrones que ya tienes):**

- Modelos `CveEntry`, `CpeMatch`, `KevEntry`, `EpssScore` en un nuevo submódulo
  `sentinel/services/kb/` (o un módulo `intel/` si prefieres separarlo de Sentinel), heredando de
  `BaseRepository` y persistiendo vía `UnitOfWork`.
- Job de sincronización incremental como **tarea RQ programada** con APScheduler — el mismo
  mecanismo de `scheduling.py` (`Scheduler.schedule`) que ya usas para escaneos. Categoría nueva
  `sentinel.kb` registrada en el `QueueRegistry`; entry point envuelto en `job_context()`.
- El *fetcher* puede calcarse de `AegisAlertFetcher` (`pills.py`): mismo estilo de fetch concurrente
  (`ThreadPoolExecutor`), caché con TTL (`threading.Lock`), retry con backoff, y *fallback* entre
  fuentes. Config de fuentes/intervalo en `SecOpsConfig.json` vía `CR.get_*` (patrón
  `config_reading.py`).

**Ejemplo de la consulta central del matcher:**

```python
# Dado un CPE detectado, devolver CVEs aplicables respetando rangos de versión.
def cves_for_cpe(session, vendor, product, version) -> list[CveEntry]:
    candidates = session.query(CpeMatch).filter_by(vendor=vendor, product=product).all()
    return [c.cve for c in candidates if version_in_range(version, c)]

def version_in_range(v, match) -> bool:
    # Respeta versionStartIncluding / versionStartExcluding /
    # versionEndIncluding / versionEndExcluding del JSON de NVD.
    ...
```

**Definición de hecho:** la detección por versión ya no hace llamadas de red por target; consulta
tu base local. Un `sentinel.kb` nocturno mantiene el feed al día. Esto te **independiza de CIRCL/NVD
en tiempo de escaneo** (justo tu objetivo declarado).

---

### Fase F — Fingerprinting propio (L1) · Track B

**Objetivo:** identificar servicio, producto y versión con **criterio propio**, sin depender de
`nmap -sV`. Es el "ojo" del motor.

- **Dissectors de protocolo propios:** TLS (parseo de ClientHello/ServerHello, cert, versiones,
  cifras; fingerprint tipo **JARM**), HTTP (headers, título, hash de favicon), SSH (banner + kex),
  SMTP/FTP/etc. Emiten un `Service` normalizado con `product`/`version`/candidato-CPE + **confianza**.
- **Base de firmas propia**, pequeña y curada, que crece por evidencia del laboratorio.
- **Oráculo = Nmap `-sV`:** correr ambos y **solo confiar en la firma propia donde concuerda con
  Nmap** en el laboratorio. La concordancia es la métrica de madurez de esta capa.
- Alimenta el CPE del motor junto al `<cpe>` de Nmap y los overrides (§2.1); su nivel de confianza
  mapea a `qod` con el mismo esquema de tres niveles.

**Definición de hecho:** para servicios comunes, el fingerprint propio iguala a Nmap y produce CPE
con confianza medible; el `qod` refleja esa confianza. **Nmap `-sV` pasa a oráculo/fallback.**

---

### Fase T — Transporte propio (L0) · Track B

**Objetivo:** descubrir puertos con implementación propia, sin depender del descubrimiento de Nmap.
Son las "manos" del motor.

- Scanner **asyncio connect** (sin privilegios) como base siempre disponible.
- **Raw SYN stateless** (estilo masscan: enviar todos los SYN, recoger SYN/ACK) como *fast-path*
  bajo `CAP_NET_RAW`; **probes UDP** para un set curado (DNS, SNMP, NTP…).
- **Rate-limit / token-bucket por host** y pool de concurrencia acotado; respetar el gate de
  autorización (`validate_ip`, rechazo de IP privadas, `is_host_reachable`).
- **Nmap como oráculo y fallback:** medir concordancia en el laboratorio; conmutar a Nmap donde el
  scanner propio aún no llegue. **Aquí es donde, si el throughput Python no basta, entraría el repo
  nativo opcional de §2.3** — no antes.

**Definición de hecho:** el motor descubre puertos sin Nmap, con concordancia ≥ umbral medido contra
Nmap; Nmap conmutable como fallback.

---

### Fase 4 — Escaneo autenticado / checks locales (avanzado, opcional) · Track A

**Objetivo:** lo que OpenVAS llama *authenticated scan* — entrar al host (SSH/WinRM) para comprobar
versiones de paquetes del SO contra avisos del proveedor. Resuelve el problema de los *backports* de
la Fase 1 (lees la versión real del paquete, no el banner).

- Conector SSH (clave o credencial del vault **Acheron**, que ya tienes cifrado: `Vault`,
  `VaultManager` en `acheron/`).
- Lectura de paquetes (`dpkg -l`, `rpm -qa`) → correlación con avisos (OVAL/distro feeds).
- Opcional y de nicho; muchos productos comerciales lo cobran aparte. Déjalo para cuando el motor
  remoto esté maduro. Se implementa como una familia de plugins Python de la Fase R (checks
  "locales" en vez de "remotos").

---

### Fase 5 — Correlación, deduplicación y ciclo de vida · Track A

**Objetivo:** convertir "listas de hallazgos por escaneo" en "estado de vulnerabilidad por activo a
lo largo del tiempo". Aquí el producto se vuelve claramente superior a lanzar herramientas sueltas.

- **Deduplicación multi-fuente:** si Ellysia, Nikto y OpenVAS reportan la misma CVE en el mismo
  `host:puerto`, fusionar en un `Finding` con `source` múltiple y `qod` consolidado (varias fuentes
  ⇒ mayor confianza). Esta es la razón de ser del modelo `Finding` unificado de §2.
- **Ciclo de vida** sobre el historial que **ya tienes** (`ScanHistoryManager`): comparar el escaneo
  actual con el anterior del mismo target → `open` (nuevo), `fixed` (estaba y ya no), `regressed`
  (volvió tras estar `fixed`), `accepted` (riesgo aceptado por el usuario).
- **Scoring de riesgo contextual** más allá del CVSS crudo, combinando CVSS (gravedad técnica),
  **EPSS** (probabilidad real de explotación), **KEV** (¿se explota ya?), y **exposición del
  activo**: tu `_classify_network_context` (`analyzers.py:70`) ya distingue LAN privada vs Internet
  pública. Un CVSS 9.8 en una IP pública en KEV no es lo mismo que en una LAN aislada. Encaja con tu
  filosofía "Controls, Not Counts".

**Ejemplo de prioridad resultante:**

```
CVE-2021-41773 en 10.0.0.5:80
  CVSS 9.8 · EPSS 0.97 · KEV=sí · exposición=pública · confirmado=sí
  → Prioridad Ellysia: CRÍTICA-INMEDIATA (parchear hoy)

CVE-2019-XXXX en 192.168.1.50:443
  CVSS 7.5 · EPSS 0.02 · KEV=no · exposición=LAN privada · confirmado=no(versión)
  → Prioridad Ellysia: MEDIA (planificar; posible falso positivo por backport)
```

---

### Fase 6 — Orquestación: el motor como pipeline por defecto · convergencia

**Objetivo:** unificarlo todo en un único flujo donde el motor propio es el protagonista y Nmap/
Nikto/OpenVAS son corroboradores opcionales.

```
Ellysia Scan (pipeline)
  1. Descubrimiento    → Transporte propio (L0), Nmap como fallback     [Fase T]
  2. Fingerprinting    → Dissectors propios (L1), Nmap -sV como oráculo  [Fase F]
  3. Detección         → Runtime de checks (L2): versión + activa        [Fase R + Fase 1/2]
  4. (opcional) Deep   → lanzar Nmap/Nikto/OpenVAS y fusionar            [corroboración]
  5. Correlación       → dedup + ciclo de vida + scoring                 [Fase 5]
  6. Enriquecimiento   → scribe/IA genera análisis y PDF                 [ya lo tienes]
```

El paso 4 es lo que materializa tu objetivo: **"que Nmap, Nikto y OpenVAS sean complementos de mi
propio motor"**. El usuario lanza un "Ellysia Scan"; por defecto corre el motor nativo (propio, sin
dependencias externas pesadas) y, si marca "análisis profundo", se añaden las herramientas externas
como una segunda opinión que se fusiona en los mismos `Finding`s.

---

## 4. Aspectos transversales (válidos en todas las fases)

- **Autorización y alcance legal.** Escanear sólo objetivos autorizados. Ya validas IPs y rechazas
  privadas; formaliza un registro de "targets autorizados" por usuario antes de habilitar checks
  activos (Fase R) y transporte propio (Fase T), que sí *tocan* el objetivo.
- **Privilegios y capabilities.** Preferir `CAP_NET_RAW` en el worker frente a `sudo` completo.
  Matriz de degradación: raw SYN/UDP con capability → connect-scan sin ella. Nunca fallar por falta
  de raw.
- **Seguridad del runtime de checks.** Modo safe/aggressive, límite de tasa por host, y la deuda
  consciente del sandbox: plugins Python de terceros → subproceso aislado como vía futura (§Fase R).
- **Gestión de falsos positivos.** El par `qod` + `confirmed` es tu herramienta principal. Permite
  al usuario marcar findings como `accepted`/falso positivo y recuérdalo entre escaneos (`state`).
- **Versionado de feeds y checks.** Igual que OpenVAS versiona su NVT feed, registra qué versión de
  KB **y de set de checks propio** produjo cada escaneo (`Finding.check_id`) → reproducibilidad de
  informes.
- **Rendimiento.** Concurrencia de jobs ya resuelta por RQ; concurrencia de I/O dentro del motor por
  la isla asyncio (§2.2). Los checks activos y el transporte deben ir con límite de tasa y *pool*
  acotado por host para no tumbar el objetivo.
- **Banco de pruebas + oráculo diferencial (imprescindible).** Monta un laboratorio de objetivos
  vulnerables conocidos (DVWA, OWASP Juice Shop, Metasploitable2/3, imágenes de VulHub) y escribe
  **tests de detección**: "el motor debe encontrar CVE-X en la imagen Y". Además, usa las
  herramientas externas como **oráculos**: Nmap es la verdad para L0/L1 (concordancia de puertos y
  fingerprint); OpenVAS es la verdad para L2 ("el check propio debe encontrar lo que OpenVAS
  encuentra para el CVE sembrado"). Sin esto no puedes medir regresiones cuando cambien feeds o
  checks. Encaja con tu carpeta `API/tests/`.
- **Calidad de datos CPE.** El eslabón débil del matcher por versión es normalizar `product`/
  `version` a CPE correcto. Invierte en el diccionario de alias (§2.1) y mídelo con el laboratorio.

---

## 5. Por dónde empezar esta semana (rebanada mínima)

Si quieres un primer resultado tangible con el mínimo esfuerzo, este es el camino crítico:

1. **Fase 0 ligera, empezando por el CPE:** primero el refactor de §2.1 (capturar/persistir el CPE
   de Nmap — 4 toques). Luego `ScanType.ELLYSIA`, el modelo `Finding` + migración, y un
   `EllysiaEngineManager` que reutilice tu `NmapScanTask` existente.
2. **Fase R ligera (el runtime, en pequeño):** monta el motor con **un solo check declarativo**
   (p.ej. `git-config-exposure`) + un **version-check** que, de momento, consulte la API de CIRCL
   que **ya usas en Aegis** (`cve.circl.lu`). Motor propio de detección funcionando en días,
   reutilizando código existente, sobre el Nmap actual.
3. **Demuéstralo** contra `vulhub/httpd:2.4.49` (version-check) y una imagen con `.git` expuesto
   (check declarativo activo).
4. Sólo entonces invierte en la **Fase 2** (KB local, quita la dependencia de red), en la
   **Fase F/T** (fingerprint y transporte propios, con Nmap como oráculo), y amplía el set de checks
   de la **Fase R**.

Esa secuencia te da un MVP defendible muy pronto y convierte la independencia de Nmap/Nikto/OpenVAS
en un proceso incremental, no en un big-bang.

---

## 6. Resumen de entregables por fase

| Fase | Track | Capa | Entregable | Terceros de los que independiza |
|---|---|---|---|---|
| 0 | A | — | Captura de CPE (§2.1) + `ScanType.ELLYSIA` + modelo `Finding` + fontanería end-to-end | — |
| 1 | A | L3 | Matcher CPE→CVE (detección por versión) | Detección de vulns **propia** (lógica) |
| **R** | **B** | **L2** | **Runtime de checks propio (decl. + Python), feed versionado** | **Reemplaza a Nikto** |
| 2 | A | L3 | KB local (NVD + KEV + EPSS + CPE dict) con sync programado | **CIRCL/NVD en runtime** |
| F | B | L1 | Fingerprinting propio (dissectors + firmas, oráculo=Nmap) | **Nmap `-sV`** → oráculo/fallback |
| T | B | L0 | Transporte propio (asyncio connect + raw SYN/UDP) | **Descubrimiento de Nmap** → fallback |
| 4 | A | L2 | Escaneo autenticado (paquetes SO) vía vault Acheron | Cubre *backports*; nicho avanzado |
| 5 | A | L3 | Dedup multi-fuente + ciclo de vida + scoring contextual | Producto **superior** a herramientas sueltas |
| 6 | — | L4 | Pipeline orquestado; Nmap/Nikto/OpenVAS como corroboradores | **Objetivo cumplido**: complementos, no motor |

---

*Documento vivo. Ajusta el orden de las fases a tu superficie real de objetivos: si tu uso es
sobre todo web, prioriza Fase R; si es sobre todo inventario de red/servidores, prioriza Fase 1+2 y
luego F+T. La regla que no cambia: lidera con L2 (identidad), baja de nivel por evidencia (oráculo),
y retira cada dependencia externa solo cuando tu capa propia la iguala en el laboratorio.*
