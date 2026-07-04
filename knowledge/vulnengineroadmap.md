# Ellysia — Motor propio de análisis de vulnerabilidades

> Plan a largo plazo para construir un motor de detección de vulnerabilidades nativo
> dentro del módulo **Sentinel**, de forma que Nikto y OpenVAS/Greenbone pasen de ser
> dependencias a ser **complementos opcionales** que corroboran los hallazgos del motor
> propio (al que en este documento llamamos provisionalmente **Ellysia Engine**).
>
> Documento de diseño. No describe código existente, sino el camino para llegar a él.

---

## 1. Veredicto de factibilidad

**Es factible, pero la pregunta correcta no es "¿puedo reescribir OpenVAS?".** OpenVAS/Greenbone
son ~20 años de ingeniería y más de 100.000 plugins NASL. Replicar eso desde cero, en solitario,
no es realista ni necesario.

Lo que **sí** es realista —y de hecho de muy alto valor— es construir un motor de
**correlación y detección de vulnerabilidades** que:

1. **Reutilice lo que ya recolectas.** Tu escaneo Nmap ya corre con `-sV` y tu parser de XML
   **ya lee el elemento `<cpe>`** (`processors.py:228`). El dato *se obtiene*, pero hoy **se
   descarta** antes de llegar a la base de datos (ver §2.1). Es la entrada natural para un motor
   basado en versiones, pero requiere un refactor pequeño y acotado antes de poder usarlo.
2. **Empiece por el 80/20:** un *matcher* CPE → CVE (detección por versión). Esto cubre una
   fracción enorme de lo que hace OpenVAS (las comprobaciones tipo *"remote_banner"*, que en
   OpenVAS son QoD ~30–80%) con una fracción mínima del esfuerzo.
3. **Crezca hacia comprobaciones activas** (plugins/checks ligeros estilo Nuclei/Nikto) poco a poco.
4. **Mantenga Nikto y OpenVAS como corroboradores opcionales**, no como el corazón del producto.

Esta es, literalmente, la trayectoria que siguieron los escáneres reales: primero detección por
banner/versión, después comprobaciones activas, después escaneo autenticado. Vamos a recorrer ese
mismo camino, pero apoyándonos en infraestructura que **ya tienes**.

### Lo que ya tienes a favor (no partes de cero)

| Pieza que necesita el motor | Dónde ya existe en tu repo |
|---|---|
| Descubrimiento de servicios + versión (`-sV`) | `NmapScanTask` (`tasks.py:287`) + `NmapResultProcessor` |
| Lectura del `<cpe>` desde el XML de Nmap | `_parse_nmap_xml` lo parsea (`processors.py:228`) — ⚠️ **pero se descarta después; ver §2.1** |
| Consumo de feeds CVE (NVD/CIRCL, INCIBE) | `aegis/services/pills.py` (`AegisAlertFetcher`, `cve.circl.lu`) |
| Clasificación de severidad CVSS | `sentinel/services/processors.py:556` (`_categorize_severity`) |
| Heurística de detección web (paths peligrosos, headers…) | `sentinel/services/processors.py:294` (`_classify_threat_level` de Nikto) |
| Abstracción de "ejecutar un escáner asíncrono" | `sentinel/services/tasks.py` (`_Task`, ABC) |
| Modelo de escaneo extensible (polimórfico) | `sentinel/model.py` (`Scan` + `polymorphic_on`) |
| Persistencia transaccional | `infrastructure` (`UnitOfWork`, `ScanRepository`) |
| Cola de trabajos / aislamiento de procesos | `system/taskqueue` (RQ + Redis) |
| Programación de escaneos | `sentinel/services/scheduling.py` (APScheduler) |
| Enriquecimiento y reporte con IA | `scribe` + `sentinel/services/analyzers.py` |
| Historial por host (para ciclo de vida de vulns) | `ScanHistoryManager` en `sentinel/managers.py` |
| Contexto de exposición (IP privada vs pública) | `analyzers.py:70` (`_classify_network_context`) |

El trabajo, por tanto, es **integración y correlación**, no construir cada ladrillo de cero.

### Lo que NO conviene construir (trampas de alcance)

- Un intérprete NASL completo. No lo necesitas.
- Cobertura "completa" comparable a OpenVAS. Apunta al 80/20 de tu superficie real.
- Tu propio motor de fingerprinting de red. Nmap ya lo hace mejor de lo que lo harás tú.
- Tu propio feed de CVEs curado a mano. Refleja (mirror) NVD/CISA-KEV/EPSS.

---

## 2. Principio de arquitectura: el motor es **otro `ScanType`**

La decisión de diseño más importante es no tratar el motor como algo "aparte", sino como un
nuevo tipo de escaneo de primera clase que encaja en tus abstracciones actuales:

```
ScanType.NMAP     → NmapScanTask     → NmapResultProcessor     → NmapScanManager
ScanType.NIKTO    → NiktoScanTask    → NiktoResultProcessor    → NiktoScanManager
ScanType.OPENVAS  → OpenVASTask      → OpenVASResultProcessor  → OpenVASScanManager
ScanType.ELLYSIA (★) → EllysiaEngineTask → EllysiaResultProcessor → EllysiaEngineManager   ← NUEVO
```

Así, el motor hereda "gratis": cancelación cooperativa, progreso, persistencia, programación,
carpetas, generación de PDF y enriquecimiento IA. Cada fase del plan rellena una parte de esa fila.

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
    source          = Column(String(32))      # "seq-engine" | "nikto" | "openvas"
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
escáneres que devuelven tres listas inconexas".

---

## 2.1 Pre-requisito crítico: hoy el CPE se obtiene… pero se descarta

> Esta sección responde directamente a la duda *"con lo que tengo en Nmap, ¿de verdad obtengo el
> CPE?, ¿no hace falta un refactor?"*. La respuesta corta es: **lo obtienes, pero lo tiras — y sí,
> hace falta un refactor (pequeño).**

**Hoy NO puedes recuperar el CPE de un servicio escaneado**, aunque Nmap te lo entrega y tu parser
de XML lo lee. El dato recorre casi todo el camino y se cae en los dos últimos pasos. El arreglo es
**pequeño y muy acotado**: 3 cambios de código + 1 migración. No es un rediseño; es "dejar de tirar
un dato que ya tienes en la mano".

### El recorrido real del CPE en tu código

| Paso | Fichero | ¿El CPE sobrevive? |
|---|---|---|
| 1. Comando Nmap usa `-sV` | `tasks.py:287` (`NmapScanTask._build_command`) | ✅ `-sV` hace que Nmap emita `<cpe>` cuando reconoce el servicio |
| 2. Parseo del XML | `processors.py:226-230` (`_parse_nmap_xml`) | ✅ Lee `<cpe>` y lo guarda en `port_data["cpe"]` |
| 3. Re-estructuración | `processors.py:118-127` (`_parse_nmap_structure`) | ❌ **Se descarta**: arma una tupla de 6 campos `(protocolo, state, reason, product, version, name)` que **no incluye cpe** |
| 4. `process()` → `ports_data` | `processors.py:62-70` | ❌ Consecuencia del paso 3: los dicts ya no llevan `cpe` |
| 5. Persistencia | `repositories.py:459` (`persist_nmap_results`) | ❌ Crea `OpenPort(reason, product, version, given_use)` |
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

3. **`process()`** (`processors.py:62-70`): incluir `'cpe': ...` en cada dict de `ports_data`
   (si adoptas dicts en el paso 2, desaparece el desempaquetado de 6 campos y queda más limpio).

4. **`persist_nmap_results`** (`repositories.py:459`): pasar el valor al modelo:
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
| CPE directo del XML de Nmap (`<cpe>`) | Alta (es Nmap quien lo afirma) | `qod=70` (igual que hoy en el plan) |
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
Finding:       qod=70, source="seq-engine", confirmed=false
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

## 3. Hoja de ruta por fases

Cada fase es entregable y útil por sí sola. No necesitas terminar la fase N para sacar valor de la
fase N−1. El orden está pensado para maximizar valor por unidad de esfuerzo.

### Fase 0 — Cimientos (refactor, ~1–2 semanas)

**Objetivo:** que "el motor" sea una fila más de la tabla de arriba, sin lógica de detección todavía.

- **Capturar y persistir el CPE de Nmap (ver §2.1).** Es el **primer cambio de código del
  proyecto**: columna `cpe` en `OpenPort` + propagarlo en `_parse_nmap_structure`/`process` +
  guardarlo en `persist_nmap_results`. Sin esto, la Fase 1 no tiene de dónde leer el CPE.
- Añadir `ScanType.ELLYSIA = "seq"` en `sentinel/model.py`.
- Crear el modelo `Finding` y su migración Alembic (`alembic revision --autogenerate`).
- Esqueleto `EllysiaEngineTask(_Task)` en `tasks.py` que de momento sólo envuelva una llamada a Nmap
  ya existente y devuelva sus puertos (sin detección aún).
- `EllysiaEngineManager(ScanManager)` registrado con `@ScanManager.register(ScanType.ELLYSIA)`.
- Endpoint `POST /sentinel/seq` (espejo de `/sentinel/nmap`).

**Definición de hecho:** puedes lanzar un "escaneo Ellysia" que internamente hace un Nmap y persiste
`Finding`s informativos (un finding "puerto abierto" por servicio). Cero detección real todavía,
pero toda la fontanería funciona end-to-end.

---

### Fase 1 — Detección por versión: el *matcher* CPE → CVE (el MVP de verdad)

**Esto es el corazón del producto mínimo viable y donde recomiendo empezar de verdad.**

**Objetivo:** dado un servicio con producto+versión (que Nmap ya te da), decir qué CVEs conocidas le
afectan, con su CVSS. Esto es, conceptualmente, lo que hace una gran parte de OpenVAS.

**Flujo:**

1. Nmap detecta el servicio (ya lo hace). Ejemplo de salida real que tu `processors.py` ya parsea:
   - `product="Apache httpd"`, `version="2.4.49"`, `cpe="cpe:/a:apache:http_server:2.4.49"`
2. Normalizar a **CPE 2.3**: `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`.
   - Cuando Nmap no da CPE limpio, construirlo desde `product`+`version` con un diccionario de
     normalización (mapear "Apache httpd" → `apache:http_server`).
3. Consultar la **base de conocimiento local** (Fase 2) por CPE, respetando los rangos de versión
   de NVD (`versionStartIncluding`, `versionEndExcluding`, etc.).
4. Emitir un `Finding` por CVE con `source="seq-engine"`, `cvss_score`, `epss_score`, `in_kev`,
   `qod=70` (detección por banner: fiable pero no confirmada activamente).

**Ejemplo concreto, de principio a fin:**

```
Target: 10.0.0.5
Nmap   → 80/tcp open  http  Apache httpd 2.4.49
CPE    → cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Match  → CVE-2021-41773  (Path Traversal / RCE)   CVSS 9.8   EPSS 0.97   KEV=sí
Finding→ {
  "title": "Apache HTTP Server 2.4.49 — Path Traversal / RCE (CVE-2021-41773)",
  "category": "outdated_software",
  "port": 80, "service": "http",
  "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
  "cve_ids": ["CVE-2021-41773"], "cvss_score": 9.8,
  "epss_score": 0.97, "in_kev": true,
  "source": "seq-engine", "qod": 70, "confirmed": false
}
```

Con esto solo, ya tienes un motor que **detecta vulnerabilidades de forma nativa**, sin Nikto ni
OpenVAS. Y como reutiliza el escaneo Nmap que ya haces, el coste marginal por target es bajísimo.

**Aviso de calibración (falsos positivos):** la detección por versión sufre del problema de los
*backports* — Debian/RHEL parchean CVEs manteniendo el número de versión. Por eso `qod` < 100 y
`confirmed=false`: un hallazgo por versión es "potencialmente vulnerable", no "vulnerable
confirmado". La Fase 3 (comprobación activa) es la que sube ese hallazgo a `confirmed=true`,
`qod=99`. Esta distinción es exactamente la filosofía "Controls, Not Counts" que ya aplicas en
`analyzers.py`.

**Definición de hecho:** un escaneo Ellysia sobre un host con software desactualizado produce findings
con CVEs reales y CVSS, visibles en la SPA y en el PDF.

---

### Fase 2 — Base de conocimiento local de vulnerabilidades (el "feed" propio)

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
  `sentinel/services/kb/` (o un módulo `intel/` si prefieres separarlo de Sentinel).
- Job de sincronización incremental como **tarea RQ programada** con APScheduler — el mismo
  mecanismo de `scheduling.py` que ya usas para escaneos. Categoría nueva `intel.sync`.
- El *fetcher* puede calcarse de `AegisAlertFetcher` (`pills.py`): mismo estilo de fetch concurrente
  con caché y *fallback* entre fuentes.

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

**Definición de hecho:** la detección de la Fase 1 ya no hace llamadas de red por target; consulta
tu base local. Un `intel.sync` nocturno mantiene el feed al día. Esto te independiza de servicios
externos en tiempo de escaneo (justo tu objetivo declarado).

---

### Fase 3 — Comprobaciones activas (sistema de *plugins/checks*)

**Objetivo:** pasar de "potencialmente vulnerable por versión" a "**confirmado** mediante una prueba
activa". Aquí es donde absorbes lo que hoy te da Nikto y empiezas a igualar el valor de OpenVAS para
tu superficie concreta.

**Diseño: un framework de checks declarativos + Python**, estilo Nuclei/Nikto.

- **Checks declarativos (YAML/JSON):** para el 90% de casos web (peticiones HTTP + matchers).
- **Checks en Python:** para lógica compleja (TLS, protocolos binarios, secuencias multi-paso).

Tu `NiktoResultProcessor._classify_threat_level` (`processors.py:294`) **ya contiene** un catálogo
enorme de patrones peligrosos (paths como `.git/`, `.env`, `wp-config.php`; cifrados débiles;
métodos HTTP peligrosos…). Eso es, esencialmente, la base de tu primer conjunto de checks nativos:
en lugar de *clasificar la salida de Nikto*, ahora **tú** haces la petición y evalúas.

**Ejemplo de check declarativo** (reproduce nativamente una comprobación tipo Nikto):

```yaml
id: git-config-exposure
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

**Familias de checks por las que empezar (alto valor, bajo coste):**

1. **Higiene TLS/SSL:** versiones de protocolo (SSLv3/TLS1.0), cifrados débiles, certificado
   caducado/autofirmado. (Python + `ssl`/`cryptography`.)
2. **Cabeceras de seguridad HTTP:** HSTS, CSP, X-Frame-Options, cookies sin `Secure`/`HttpOnly`.
3. **Paths sensibles expuestos:** `.git/`, `.env`, `/server-status`, backups, paneles de admin.
4. **Credenciales por defecto:** en servicios identificados (router, phpMyAdmin, Tomcat…).
5. **Confirmadores de CVE concretas y muy explotadas (KEV):** p. ej. la prueba de path traversal de
   CVE-2021-41773 para *confirmar* el hallazgo por versión de la Fase 1.

**Multiplicador de fuerza:** considera ingerir **plantillas de Nuclei** (miles, comunidad,
licencia permisiva) como un "feed de checks", igual que reflejas CVEs. Mapear su formato YAML a tu
modelo `Finding` te daría cobertura enorme sin escribir cada check a mano. Sería tu equivalente al
NVT feed pero para comprobaciones activas.

**Seguridad de los checks:** los checks activos *tocan* el objetivo. Necesitan: límite de tasa,
modo "safe" (no destructivo) vs "aggressive", y respetar el gate de autorización que ya tienes
(`validate_ip`, rechazo de IPs privadas, `is_host_reachable`).

**Definición de hecho:** el motor confirma activamente al menos las familias 1–3 y eleva findings de
`qod=70` a `qod=99`. En este punto, **Nikto deja de ser necesario** para tu caso de uso típico.

---

### Fase 4 — Escaneo autenticado / checks locales (avanzado, opcional)

**Objetivo:** lo que OpenVAS llama *authenticated scan* — entrar al host (SSH/WinRM) para comprobar
versiones de paquetes del SO contra avisos del proveedor. Resuelve el problema de los *backports* de
la Fase 1 (lees la versión real del paquete, no el banner).

- Conector SSH (clave o credencial del vault **Acheron**, que ya tienes cifrado).
- Lectura de paquetes (`dpkg -l`, `rpm -qa`) → correlación con avisos (OVAL/distro feeds).
- Esto es opcional y de nicho; muchos productos comerciales lo cobran aparte. Déjalo para cuando el
  motor remoto esté maduro.

---

### Fase 5 — Correlación, deduplicación y ciclo de vida

**Objetivo:** convertir "listas de hallazgos por escaneo" en "estado de vulnerabilidad por activo a
lo largo del tiempo". Aquí el producto se vuelve claramente superior a lanzar herramientas sueltas.

- **Deduplicación multi-fuente:** si Ellysia Engine, Nikto y OpenVAS reportan la misma CVE en el mismo
  `host:puerto`, fusionar en un `Finding` con `source` múltiple y `qod` consolidado (varias fuentes
  ⇒ mayor confianza). Esta es la razón de ser del modelo `Finding` unificado de la sección 2.
- **Ciclo de vida** sobre el historial que **ya tienes** (`ScanHistoryManager`): comparar el escaneo
  actual con el anterior del mismo target →
  - `open` (nuevo), `fixed` (estaba y ya no), `regressed` (volvió tras estar `fixed`), `accepted`
    (riesgo aceptado por el usuario).
- **Scoring de riesgo contextual** más allá del CVSS crudo, combinando:
  - CVSS (gravedad técnica),
  - **EPSS** (probabilidad real de explotación),
  - **KEV** (¿se explota ya en la práctica?),
  - exposición del activo: tu `_classify_network_context` (`analyzers.py:70`) ya distingue
    LAN privada vs Internet pública. Un CVSS 9.8 en una IP pública en KEV no es lo mismo que en una
    LAN aislada. Esto encaja con tu filosofía "Controls, Not Counts".

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

### Fase 6 — Orquestación: el motor como pipeline por defecto

**Objetivo:** unificarlo todo en un único flujo donde el motor propio es el protagonista y Nikto/
OpenVAS son corroboradores opcionales.

```
Ellysia Scan (pipeline)
  1. Descubrimiento    → Nmap (servicios + versión + CPE)        [ya lo tienes]
  2. Detección pasiva  → matcher CPE→CVE contra KB local         [Fase 1+2]
  3. Confirmación      → checks activos sobre servicios vivos    [Fase 3]
  4. (opcional) Deep   → lanzar Nikto y/o OpenVAS y fusionar      [corroboración]
  5. Correlación       → dedup + ciclo de vida + scoring          [Fase 5]
  6. Enriquecimiento   → scribe/IA genera análisis y PDF          [ya lo tienes]
```

El paso 4 es lo que materializa tu objetivo: **"que Nikto y OpenVAS sean complementos de mi propio
motor"**. El usuario lanza un "Ellysia Scan"; por defecto corre el motor nativo (rápido, sin
dependencias externas pesadas) y, si marca "análisis profundo", se añaden Nikto/OpenVAS como una
segunda opinión que se fusiona en los mismos `Finding`s.

---

## 4. Aspectos transversales (válidos en todas las fases)

- **Autorización y alcance legal.** Escanear sólo objetivos autorizados. Ya validas IPs y rechazas
  privadas (`_reject_private_ips`); formaliza un registro de "targets autorizados" por usuario antes
  de habilitar checks activos (Fase 3), que sí *tocan* el objetivo.
- **Gestión de falsos positivos.** El par `qod` + `confirmed` es tu herramienta principal. Permite
  al usuario marcar findings como `accepted`/falso positivo y recuérdalo entre escaneos.
- **Versionado de feeds y checks.** Igual que OpenVAS versiona su NVT feed, registra qué versión de
  KB/checks produjo cada escaneo (reproducibilidad de informes).
- **Rendimiento.** Concurrencia ya resuelta por RQ. Los checks activos deben ir con límite de tasa y
  *pool* acotado por host para no tumbar el objetivo.
- **Banco de pruebas (imprescindible).** Monta un laboratorio de objetivos vulnerables conocidos
  (DVWA, OWASP Juice Shop, Metasploitable2/3, imágenes de VulHub) y escribe **tests de detección**:
  "el motor debe encontrar CVE-X en la imagen Y". Sin esto no puedes medir regresiones cuando
  cambien feeds o checks. Encaja con tu carpeta `API/tests/`.
- **Calidad de datos CPE.** El eslabón débil del matcher por versión es normalizar `product`/
  `version` de Nmap a CPE correcto. Invierte en un diccionario de alias y mídelo con el laboratorio.

---

## 5. Por dónde empezar esta semana (rebanada mínima)

Si quieres un primer resultado tangible con el mínimo esfuerzo, este es el camino crítico:

1. **Fase 0 ligera, empezando por el CPE:** primero el refactor de §2.1 (capturar/persistir el CPE
   de Nmap — 4 toques). Luego `ScanType.ELLYSIA`, el modelo `Finding` + migración, y un
   `EllysiaEngineManager` que reutilice tu `NmapScanTask` existente.
2. **Fase 1 ligera, sin KB propia todavía:** para cada servicio con versión, consulta la API de
   CIRCL que **ya usas en Aegis** (`cve.circl.lu`) y crea `Finding`s con las CVEs. Esto te da un
   motor de detección funcionando en días, reutilizando código existente.
3. **Demuéstralo** contra una imagen Docker de Metasploitable o `vulhub/httpd:2.4.49`.
4. Sólo entonces invierte en la **Fase 2** (KB local) para quitarte la dependencia de red en tiempo
   de escaneo, y en la **Fase 3** (checks activos) para confirmar y reemplazar a Nikto.

Esa secuencia te da un MVP defendible muy pronto y convierte la independencia de Nikto/OpenVAS en
un proceso incremental, no en un big-bang.

---

## 6. Resumen de entregables por fase

| Fase | Entregable | Independencia lograda |
|---|---|---|
| 0 | Captura de CPE (§2.1) + `ScanType.ELLYSIA` + modelo `Finding` + fontanería end-to-end | — |
| 1 | Matcher CPE→CVE (detección por versión) | Detección de vulns **propia** (vía CVE) |
| 2 | KB local (NVD + KEV + EPSS + CPE dict) con sync programado | Independiente de feeds externos en runtime |
| 3 | Framework de checks activos (decl. + Python) | **Reemplaza a Nikto** en tu caso de uso |
| 4 | Escaneo autenticado (paquetes SO) | Cubre *backports*; nicho avanzado |
| 5 | Dedup multi-fuente + ciclo de vida + scoring contextual | Producto **superior** a herramientas sueltas |
| 6 | Pipeline orquestado; Nikto/OpenVAS como corroboradores | **Objetivo cumplido**: complementos, no dependencias |

---

*Documento vivo. Ajusta el orden de las fases a tu superficie real de objetivos: si tu uso es
sobre todo web, prioriza Fase 3; si es sobre todo inventario de red/servidores, prioriza Fase 1+2.*
