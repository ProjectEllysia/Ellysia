# Ellysia — Deuda técnica y calidad del código

> Documento hermano de `roadmap-ellysia.md` (el documento de gobierno). Aquél decide **qué se
> construye**; éste decide **qué se arregla de lo ya construido**. No añade funcionalidad: todo lo
> que hay aquí es reducción de deuda, eliminación de fuentes de verdad duplicadas, unificación de
> patrones y limpieza de nomenclatura.
>
> Verificado directamente contra el código en la rama `feature/aegis/campaignes`
> (2026-08-03), no contra planes anteriores. Cada punto cita fichero y línea.

---

## 0. Cómo leer este documento

### 0.1 Escalas

**Impacto** — cuánto cambia la salud del codebase a largo plazo:

| Nivel | Significado |
|---|---|
| **Alto** | Afecta a más de un módulo, o a una decisión que se toma repetidamente. Dejarlo pudre algo con el tiempo: cada escáner/módulo nuevo paga el impuesto otra vez, o alguien toma una decisión equivocada leyendo una fuente falsa. |
| **Medio** | Duplicación real y localizada, o una convención rota que confunde al leer pero no se degrada sola. |
| **Bajo** | Ruido: código muerto, un nombre malo, un docstring caducado. Cuesta cero y limpia. |

**Velocidad** — coste de implementación *incluyendo* dejar los tests en verde:

| Símbolo | Significado |
|---|---|
| ⚡ | ≤ 1 hora. Cambio mecánico o de un solo fichero. |
| ◐ | 2–6 horas. Toca varios ficheros; requiere leer antes de tocar. |
| ○ | ≥ 1 día. Reestructuración con superficie amplia. |

### 0.2 Regla de ordenación

La tabla maestra (§1) está ordenada por **prioridad primero, velocidad después**, con este
criterio explícito:

```
Alto+⚡  →  Alto+◐  →  Medio+⚡  →  Alto+○  →  Medio+◐  →  Bajo+⚡  →  resto
```

La lógica: lo que más daño hace y menos cuesta va primero; un `Alto+○` se pospone por detrás de
todo el `Medio+⚡` porque quince arreglos rápidos entregados valen más que uno grande a medias.

### 0.3 Lo que este documento NO propone

- **Factory de decoradores para endpoints.** Ya está evaluado y aparcado con argumentos válidos en
  `improvements/n12-decorator-factory.md`. No se reabre aquí.
- **Compartir una única instancia de APScheduler entre Themis/Hygeia/Iris.** Los tres ficheros
  documentan por qué no, y el argumento (no acoplar módulos hermanos solo por compartir mecanismo)
  se sostiene. Lo que sí se propone es que los tres usen el helper común que ya existe (→ **B6**).
- **Reescribir `lybra/`.** Es la pieza mejor construida del repositorio y la que mejor respeta sus
  propias invariantes (libre de ORM, libre de efectos de red). Se usa como referencia, no como
  objetivo.

---

## 1. Tabla maestra ordenada

| # | Mejora | Bloque | Impacto | Velocidad |
|---|---|---|---|---|
| 1 | **A14** — `CLAUDE.md` afirma una vulnerabilidad SSRF que ya no existe | Verdad | Alto | ⚡ |
| 2 | **A1** — El catálogo de escáneres vive en 8 sitios distintos | Verdad | Alto | ◐ |
| 3 | **B1** — El scheduler de Themis tiene su propio despacho paralelo al registro | Registro | Alto | ◐ |
| 4 | **A3** — `ThemisReportManager` e `IrisReportManager` son el mismo manager | Verdad | Alto | ◐ |
| 5 | **B2** — La clase base ramifica sobre `scan_type == "nmap"` | Registro | Medio | ⚡ |
| 6 | **A2** — `ThemisTool` es un duplicado exacto de `ScanType` | Verdad | Medio | ⚡ |
| 7 | **A10** — `self._tq = task_queue or TaskQueue.get_instance()` ×7 | Verdad | Medio | ⚡ |
| 8 | **E5** — `assert_owned` no sirve dentro de un `UnitOfWork` → 11 comprobaciones a mano | Diseño | Medio | ⚡ |
| 9 | **E4** — Comprobaciones de propiedad dentro de `endpoints.py` | Diseño | Medio | ⚡ |
| 10 | **A4** — `_create_scan_record` triplicado, idéntico salvo la clase | Verdad | Medio | ⚡ |
| 11 | **A5** — El diccionario de `finding` se serializa dos veces, con 15 claves | Verdad | Medio | ⚡ |
| 12 | **E1** — Ciclo de imports `lybra_engine` ↔ `lybra_sources` + acceso a privados | Diseño | Medio | ⚡ |
| 13 | **D1** — `lybra_sources.py` está en el directorio equivocado | Ubicación | Medio | ⚡ |
| 14 | **B4** — `_build_strategy` de scribe y herald son cadenas `if/elif` | Registro | Medio | ⚡ |
| 15 | **B6** — `ThemisScheduler.execute` reimplementa `@scheduler_job` a mano | Registro | Medio | ⚡ |
| 16 | **C2** — Booleanos sin `is`/`are`, y nombres booleanos para cosas que no lo son | Nombres | Medio | ⚡ |
| 17 | **A13** — `requirements.txt` duplica dev-deps y declara 5 paquetes sin usar | Verdad | Medio | ⚡ |
| 18 | **A12** — La semántica de horarios está implementada dos veces | Verdad | Medio | ⚡ |
| 19 | **A11** — Cada clave de configuración hay que tocarla en 3 sitios | Verdad | Alto | ○ |
| 20 | **D5** — `themis/services/reports.py`: 85 KB en un fichero | Ubicación | Alto | ○ |
| 21 | **A7** — ≈15 excepciones `XNotFoundError` clonadas | Verdad | Medio | ◐ |
| 22 | **A9** — Los tres repositorios de documentos repiten las mismas 3 consultas | Verdad | Medio | ◐ |
| 23 | **C1** — Abreviaturas y siglas en nombres de variables | Nombres | Medio | ◐ |
| 24 | **E7** — Dos idiomas HTTP conviviendo (`requests` y `urllib.request`) | Diseño | Medio | ◐ |
| 25 | **E8** — El SPA reimplementa el polling en 6 sitios | Diseño | Medio | ◐ |
| 26 | **D4** — `iris/managers.py` (64 KB) + `mailbox_managers.py` sueltos | Ubicación | Medio | ◐ |
| 27 | **D3** — `aegis/managers.py`: tres managers en un fichero | Ubicación | Medio | ◐ |
| 28 | **E3** — 23 imports sin usar | Diseño | Bajo | ⚡ |
| 29 | **E2** — `_strategy_class` declarado 4 veces y leído nunca | Diseño | Bajo | ⚡ |
| 30 | **A8** — `__init__` de repositorio repetido 24 veces | Verdad | Bajo | ⚡ |
| 31 | **A6** — `_previous_findings_map` duplicado | Verdad | Bajo | ⚡ |
| 32 | **B3** — `ScanLoggerFactory.register_defaults()` imperativo | Registro | Bajo | ⚡ |
| 33 | **B5** — `MAILBOX_CONNECTORS` es un dict literal, no un registro | Registro | Bajo | ⚡ |
| 34 | **B7** — Mapa nombre-de-clase → herramienta en `reports.py` | Registro | Bajo | ⚡ |
| 35 | **C3** — `thirdparty_scans_managers.py`: nombre malo | Nombres | Bajo | ⚡ |
| 36 | **C4** — Colisión de nombres: `managers/kb.py` vs `lybra/kb.py` | Nombres | Bajo | ⚡ |
| 37 | **C5** — TODO obsoleto en `lybra_sources.py:101` | Nombres | Bajo | ⚡ |
| 38 | **C6** — Docstring de `shared/_endpoints.py` lista 3 helpers inexistentes | Nombres | Bajo | ⚡ |
| 39 | **D2** — `thirdparty_scans_managers.py` debería ser tres ficheros | Ubicación | Bajo | ⚡ |
| 40 | **D6** — `iris/services/shared.py`: 43 KB de dos cosas distintas | Ubicación | Bajo | ⚡ |
| 41 | **E6** — `AegisManager._lock` promete una garantía que no da | Diseño | Bajo | ⚡ |

---

## Bloque A — Fuentes de verdad duplicadas

### A14 · `CLAUDE.md` afirma una vulnerabilidad SSRF que ya no existe
**Impacto: Alto · Velocidad: ⚡**

`CLAUDE.md`, sección «Things that bite», dice literalmente que los escáneres supervivientes
«**don't have the same self-validation in their own `run_scan()`**» y que el flujo programado
«bypasses that». Es falso a día de hoy:

| Escáner | Dónde se auto-valida |
|---|---|
| Nmap | `managers/thirdparty_scans_managers.py:91` — `ScanManager.reject_private_ip(target_host)` |
| Nikto | `managers/thirdparty_scans_managers.py:219-221` — resuelve y rechaza |
| Nuclei | `managers/thirdparty_scans_managers.py:392-397` — rechaza **y** exige objetivo autorizado |
| Lybra | `managers/lybra_sources.py:227-229` — `SelfDiscovery.scan_target` rechaza y exige autorización |

Es el peor tipo de deuda posible: documentación que describe un agujero de seguridad inexistente.
Alguien (persona o agente) que lea eso o bien se pone a «arreglar» algo ya arreglado, o bien deja
de confiar en el resto del fichero. Y el fichero es la primera cosa que lee cualquiera que toque
el repo.

**Acción:** reescribir la entrada. Lo que sí queda por auditar y debe decirse en su lugar es el
único modo que efectivamente no valida nada: `ExternalPayload` (`lybra_sources.py:173`) acepta un
`target` que nadie ha validado — es correcto mientras `probes_target_network = False`, y ese es el
hecho que hay que documentar, no un hueco inventado.

**Comprobación:** un test que llame a `run_scan()` de cada uno de los cuatro managers con
`127.0.0.1` y `areLocalIpsAllowed=false`, esperando `PrivateIPRequested`. Convierte la afirmación
del `CLAUDE.md` en algo que el CI mantiene cierto.

---

### A1 · El catálogo de escáneres vive en 8 sitios distintos
**Impacto: Alto · Velocidad: ◐**

Añadir un quinto escáner hoy obliga a tocar, como mínimo:

| # | Lugar | Forma |
|---|---|---|
| 1 | `themis/model.py:111` | `ScanType` enum — **la fuente legítima** |
| 2 | `themis/services/reports.py:57` | `ThemisTool` enum — copia literal (→ **A2**) |
| 3 | `system/config_reading.py:560` | `THEMIS_SCANNERS = ("nmap", "nikto", "lybra", "nuclei")` |
| 4 | `themis/services/scheduling.py:118` | `_TASK_MAPPING` (→ **B1**) |
| 5 | `themis/services/csv_logger.py:262` | `register_defaults()` (→ **B3**) |
| 6 | `themis/schemas.py:93` | `validate.OneOf(["nmap","nikto","lybra","nuclei","all"])` |
| 7 | `themis/repositories.py:275` | `counts = {"nmap": 0, "nikto": 0, "lybra": 0, "nuclei": 0}` |
| 8 | `themis/services/reports.py:393` | `{'NmapScan':'nmap', ...}` (→ **B7**) |

Solo 1, 4 y 5 tienen registro con `@register`. Los otros cinco son literales que nadie sincroniza:
el `test_config_shape.py` cubre la relación 1↔3, pero 6, 7 y 8 fallan en silencio (una tupla
desactualizada no rompe nada, simplemente deja el nuevo escáner fuera del filtro, fuera de las
estadísticas y con la paleta de colores de Nmap).

**Acción:** que los cinco literales se deriven del enum y del registro:

- 3 → `THEMIS_SCANNERS = tuple(t.value for t in ScanType)`
- 6 → `validate.OneOf([*(t.value for t in ScanType), "all"])`
- 7 → `counts = {t.value: 0 for t in ScanType}`
- 2 y 8 → eliminar (**A2**, **B7**)

**Comprobación:** un test parametrizado sobre `ScanType` que verifique, para cada miembro, que
existe manager registrado, logger CSV registrado, estrategia de impresión registrada y bloque
`features.themis.scanners.<tool>` en `SecOpsConfig.json`. Ese test es lo que convierte «añadir un
escáner» de un checklist mental a un fallo de CI.

---

### B1 · El scheduler de Themis tiene su propio despacho paralelo al registro
**Impacto: Alto · Velocidad: ◐**

`themis/services/scheduling.py:42-118` define cuatro funciones `_run_nmap_scan`,
`_run_nikto_scan`, `_run_nuclei_scan`, `_run_lybra_scan` y un `_TASK_MAPPING` que las asocia a
`ScanType`. Cada una repite lo que el manager ya sabe: qué argumentos exige, cómo se llaman, y
cómo se pasan a `run_scan()`. Es decir, la firma de `run_scan` está escrita dos veces, en dos
ficheros, sin nada que las ate.

Contraste con lo que ya funciona: `@ScanManager.register(ScanType.NMAP)` hace que
`resolve_manager`, `get_manager_for_type`, `all_managers` y `get_scan_rich` no necesiten tocarse
nunca al añadir un escáner. El scheduler es el único consumidor de `ScanType` que se quedó fuera.

**Acción:** declarar en cada manager los argumentos programables y dejar que el scheduler use el
registro:

```python
class NmapScanManager(ScanManager):
    SCHEDULED_REQUIRED_ARGS = ("target_host", "target_ports")
    SCHEDULED_OPTIONAL_ARGS = ()
```

y en el scheduler, una sola función:

```python
manager_class = ScanManager._registry[ScanType(scan_type)]
_require_args(arguments, manager_class.SCHEDULED_REQUIRED_ARGS, scan_type)
manager_class().run_scan(**selected_args, user_id=user_id, programed_scan_id=programed_scan_id)
```

Los cuatro `_run_*` desaparecen, `_TASK_MAPPING` desaparece, y el sitio donde se declara qué
argumentos acepta un escáner programado pasa a ser el mismo sitio donde se declara `run_scan`.

**Comprobación:** los tests de `tests/integration/test_scheduling.py` ya existen; basta con que
sigan pasando. Añadir uno que verifique que todo `ScanType` registrado tiene
`SCHEDULED_REQUIRED_ARGS` definido.

---

### A3 · `ThemisReportManager` e `IrisReportManager` son el mismo manager
**Impacto: Alto · Velocidad: ◐**

`themis/managers/reports.py:22-180` e `iris/managers.py:1194-1320` son el mismo código con los
nombres cambiados. Coinciden, método a método:

| Método | Themis | Iris | Diferencia real |
|---|---|---|---|
| `__init__` | :33 | :1206 | ninguna |
| `_create_document` | :36 | :1210 | las columnas del modelo |
| `get_document_by_id` | :59 | :1228 | ninguna |
| `get_latest_document_by_*` | :64 | :1232 | el nombre del parámetro |
| `get_documents_for_user` | :70 | :1236 | ninguna |
| `get_documents_by_*` | :77 | :1240 | el nombre del parámetro |
| `delete_document` | :83 | :1244 | la excepción lanzada |
| `assert_document_ownership` | :99 | :1257 | la excepción lanzada |
| `generate_report` | :118 | :1266 | la precondición |
| `execute_report_generation` | :144 | :1297 | ninguna |
| `_generate_pdf_async` | :150 | :1302 | el `render` que se pasa |

Ya existe media solución: `shared/_documents.py` extrajo `run_report_generation` y
`delete_document_with_file` precisamente porque «antes estaba duplicado en ambos managers». El
trabajo se dejó a medias — se extrajeron las dos funciones y se dejaron los dos managers.

Peor: **Themis se quedó fuera del `TaskTrackingMixin`.** Iris hace
`external_id=self.external_id_for(doc_id)`; Themis escribe `external_id=f"themis-doc:{doc_id}"` y
`category="themis.report"` a mano (`reports.py:137-141`). Es decir, hay dos formatos de
`external_id` conviviendo, uno derivado del mixin y otro literal. Si alguien cambia el prefijo en
un sitio, el `find_task` del otro deja de encontrar nada — silenciosamente, porque un
`get_task_by_external_id` que no encuentra devuelve `None`, que es indistinguible de «la tarea ya
expiró».

**Acción:** `shared/_documents.py::DocumentManager(TaskTrackingMixin)` con todo lo común,
parametrizado por cuatro atributos de clase: `_REPOSITORY`, `_MODEL`, `_NOT_FOUND_ERROR`,
`EXTERNAL_ID_PREFIX`/`TASK_CATEGORY`. Themis e Iris quedan en `_create_document` (columnas
propias) y `_render` (PDF propio). Aegis tiene su propio ciclo de documentos con forma distinta
(genera contenido, no informes): se evalúa después, no se fuerza.

**Comprobación:** `tests/integration/test_iris_documents.py` y los tests de documentos de Themis
ya cubren ambos caminos.

---

### A2 · `ThemisTool` es un duplicado exacto de `ScanType`
**Impacto: Medio · Velocidad: ⚡**

`themis/services/reports.py:57-62` define `ThemisTool` con exactamente los mismos cuatro miembros
y los mismos cuatro valores que `ScanType` (`model.py:111`). Su único uso son tres llamadas a
`CR.get_tool_color_palette(...)` (:1119, :1283, :1966, :1995) — y ese getter ya acepta un string o
un enum indistintamente (`config_reading.py:872` lo documenta explícitamente).

**Acción:** borrar `ThemisTool`, sustituir `ThemisTool.NMAP` por `ScanType.NMAP`, ajustar la
anotación `_TOOL: "ThemisTool"` (:1604).

---

### A10 · `self._tq = task_queue or TaskQueue.get_instance()` ×7
**Impacto: Medio · Velocidad: ⚡**

La misma línea, letra por letra, en:
`themis/managers/scan.py:83`, `themis/managers/reports.py:33`,
`themis/managers/traceroute.py:58`, `aegis/managers.py:104`, `aegis/managers.py:730`,
`iris/managers.py:97`, `iris/managers.py:1207`, `iris/mailbox_managers.py:84`.

`TaskTrackingMixin` (`system/taskqueue/tracking.py`) existe exactamente para centralizar este
patrón y declara `_tq: ITaskQueue` como contrato… pero deja que cada subclase lo construya.

**Acción:** dar un `__init__` al mixin:

```python
def __init__(self, task_queue: ITaskQueue | None = None) -> None:
    self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()
```

Los managers que además reciben `user`/`alert_fetcher`/`mailer` llaman a `super().__init__(task_queue)`.
Al hacerlo, `ThemisReportManager` entra por fin en el mixin y **A3** se cierra sola en su parte de
`external_id`.

---

### E5 · `assert_owned` no sirve dentro de un `UnitOfWork` → 11 comprobaciones a mano
**Impacto: Medio · Velocidad: ⚡**

`shared/_ownership.py` centraliza el patrón «obtener por ID y verificar propietario, lanzando la
misma excepción en ambos casos para no permitir enumerar IDs ajenos». Lo usan 8 sitios. Pero
**resuelve el repositorio con `build_repository`**, es decir, el camino de lectura — así que dentro
de un `UnitOfWork` no se puede usar, y por eso hay otras 11 comprobaciones escritas a mano:

`acheron/managers.py:98`, `aegis/managers.py:763`, `aegis/managers.py:795`,
`hygeia/managers.py:403`, `iris/endpoints.py:399`, `themis/endpoints.py:854`,
`themis/managers/lybra_engine.py:666`, `themis/managers/programed.py:145` y `:158`,
`themis/managers/scan_folder.py:49` y `:55`.

No todas son evitables por la misma razón (dos están en endpoints, → **E4**), pero la mayoría lo
son y cada una es una oportunidad de escribir `raise NotFound` en una rama y olvidarlo en la otra
— que es precisamente el fallo de privacidad que el helper existe para impedir.

**Acción:** un parámetro opcional `repository=` (o `uow=`) que, cuando se pasa, evita el
`build_repository`. Firma retrocompatible; migrar las 9 comprobaciones internas.

```python
def assert_owned(repo_cls, entity_id, user_id, not_found_error, *, uow=None):
    repository = repo_cls(uow) if uow is not None else build_repository(repo_cls)
    ...
```

---

### E4 · Comprobaciones de propiedad dentro de `endpoints.py`
**Impacto: Medio · Velocidad: ⚡**

La convención del proyecto (`CLAUDE.md`, `API/CLAUDE.md`) es explícita: `endpoints.py` es
«auth + schema validation only, no business logic». Dos endpoints la rompen con la misma línea:

- `themis/endpoints.py:854` — `if doc.user_id != user.id:`
- `iris/endpoints.py:399` — `if doc.user_id != user.id:`

Ambos managers ya exponen `assert_document_ownership`. Son dos líneas movidas de sitio, pero el
motivo para moverlas no es estético: una regla de autorización escrita en la capa HTTP no se aplica
a ningún otro llamante del manager.

**Acción:** sustituir por la llamada al manager. Va junto con **E5**.

---

### A4 · `_create_scan_record` triplicado, idéntico salvo la clase
**Impacto: Medio · Velocidad: ⚡**

`thirdparty_scans_managers.py:130`, `:259` y `:445`. Los tres cuerpos son:

```python
scan = <XScan>(target=target, user_id=user_id, started_at=utcnow_naive(), programed_scan_id=programed_scan_id)
with UnitOfWork() as uow:
    ScanRepository(uow).save(scan)
    uow.commit_for_handoff()
return scan
```

La única variación es el nombre de la clase, que **ya está declarado** en `_MODEL` justo encima de
cada uno. Cada copia lleva además su propio `# pylint: disable=arguments-differ`.

**Acción:** implementación por defecto en `ScanManager`, usando `self._MODEL`. Los tres overrides
desaparecen; `LybraEngineManager._create_scan_record` (`lybra_engine.py:672`) conserva el suyo
porque añade `source_scan_id`/`asset_id` — y ahí llama a `super()` con kwargs extra en vez de
repetir el bloque.

---

### A5 · El diccionario de `finding` se serializa dos veces, con 15 claves
**Impacto: Medio · Velocidad: ⚡**

`thirdparty_scans_managers.py:576-594` (Nuclei) y `lybra_engine.py:799-818` (Lybra) construyen el
mismo objeto JSON campo por campo: `id, title, category, port, service, cpe, cveIds, cvssScore,
epssScore, inKev, qod, confirmed, source, state, dedupKey, priority`. Lybra añade
`cpeResolved`; por lo demás son idénticos, incluida la función local `_priority` (duplicada
literalmente en ambos, `:553-558` y `:779-784`).

Es una **fuente de verdad del contrato de la API**: si mañana se añade `firstSeenAt` al finding,
hay que acordarse de los dos sitios, y el que se olvide produce dos respuestas con forma distinta
para el mismo tipo de objeto.

**Acción:** `lybra/adapters.py::finding_to_json(finding_dict, exposure)` — el módulo ya es el sitio
donde vive la traducción entre formas de finding, y es ORM-free, que es lo que esto necesita. Los
dos `format_scan` pasan a ser una comprensión de lista sobre esa función.

---

### E1 · Ciclo de imports `lybra_engine` ↔ `lybra_sources` + acceso a privados
**Impacto: Medio · Velocidad: ⚡**

`lybra_sources.py:25` importa `LybraEngineManager` en el nivel de módulo. `lybra_engine.py` no
puede devolver el favor, así que importa `ServiceSource` **dentro de dos funciones** (`:137` y
`:197`), con el comentario `# ciclo de imports: lybra_sources importa este módulo`.

La causa raíz es que `resolve_services(scan_repo, manager, target)` recibe el manager entero para
usar exactamente tres cosas suyas, dos de ellas privadas:

```python
manager.is_host_reachable(...)
manager._discover_ports(target, self.discover_ports)   # pylint: disable=protected-access
manager._discover_udp_ports(target)                    # pylint: disable=protected-access
```

Un `ServiceSource` que necesita el manager completo para llamar a tres métodos no está desacoplado
del manager; solo lo parece.

**Acción:** pasar un pequeño objeto de capacidades (un `NamedTuple` de tres callables) en vez del
manager. El import de `LybraEngineManager` en `lybra_sources.py` desaparece, el ciclo desaparece,
los dos imports diferidos vuelven a la cabecera del fichero y los dos `protected-access` sobran.
Como efecto secundario, `SelfDiscovery.resolve_services` pasa a ser testeable sin instanciar un
manager.

---

### D1 · `lybra_sources.py` está en el directorio equivocado
**Impacto: Medio · Velocidad: ⚡**

De acuerdo con el diagnóstico: `managers/lybra_sources.py` es una pieza de Lybra, no un manager, y
el `managers/` de Themis ya tiene once ficheros sin agrupar.

**Salvedad importante — el destino que propones no funciona tal cual.** `themis/lybra/` declara y
mantiene una invariante explícita en su `__init__.py`: *«Everything here is deliberately free of the
ORM and of network side effects»*. Se verifica: ningún fichero de `lybra/` importa `repositories`,
`model`, `managers`, `sqlalchemy` ni `infrastructure`. `lybra_sources.py` importa `ScanRepository`,
`UnitOfWork`, `AuthorizedTargetManager` y `ScanManager` — moverlo ahí rompería la única invariante
arquitectónica del paquete mejor construido del repositorio, y lo haría de forma invisible (nada
la comprueba automáticamente hoy).

**Acción propuesta en su lugar:** subpaquete dentro de `managers/`, que es donde el ORM sí está
permitido:

```
themis/managers/lybra/
    __init__.py      # reexporta LybraEngineManager
    engine.py        # ← lybra_engine.py
    sources.py       # ← lybra_sources.py
```

Se gana lo mismo que buscabas (los dos ficheros de Lybra juntos, `managers/` con once entradas
menos una) sin tocar la invariante. Y de paso, la colisión `managers/kb.py` vs `lybra/kb.py`
(→ **C4**) queda más visible.

**Extra recomendado:** un test de una línea que congele la invariante, para que la próxima vez no
dependa de que alguien la recuerde:

```python
def test_lybra_package_is_orm_free():
    for path in (Path("src/modules/features/themis/lybra")).rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "repositories" not in source and "sqlalchemy" not in source, path
```

---

### B4 · `_build_strategy` de scribe y herald son cadenas `if/elif`
**Impacto: Medio · Velocidad: ⚡**

`tools/scribe/factory.py:27-50` y `tools/herald/factory.py:27-48`. Ambos:

```python
if name == "ollama":  return OllamaStrategy(...)
if name == "openai":  return OpenAIStrategy(...)
if name == "google":  return GoogleStrategy(...)
raise AIStrategyConfigurationError(f"estrategia desconocida: '{name}'")
```

Es exactamente el caso que el `@register` de `ScanManager` resuelve: añadir un proveedor obliga a
editar un `if/elif` en un fichero distinto de donde vive la estrategia. Herald lo tiene aún más
claro: hoy hay **una sola** rama, así que la próxima estrategia (una API transaccional, que es lo
que su propio docstring anticipa) tendrá que abrir la factory.

**Acción:** decorador de registro en cada `strategies.py`, con la construcción declarada junto a la
clase que construye:

```python
@ModelStrategy.register("openai")
class OpenAIStrategy(ModelStrategy):
    @classmethod
    def from_config(cls, overrides): ...
```

`_build_strategy` se reduce a una búsqueda en el registro más el `raise`. El mensaje de error puede
además enumerar las estrategias disponibles, como ya hace `mailbox/registry.py`.

**Nota:** el registro de `scribe` y el de `herald` deben ser **dos registros separados** (una
estrategia de correo no es una de IA), pero pueden compartir el mismo mini-helper genérico. Ese
helper es también el que usarían **B3** y **B5**.

---

### B6 · `ThemisScheduler.execute` reimplementa `@scheduler_job` a mano
**Impacto: Medio · Velocidad: ⚡**

`infrastructure/scheduling.py:57` define `scheduler_job(logger, error_message)`, cuyo docstring
explica exactamente por qué existe: aislar excepciones y liberar la sesión con `close_all()` en el
`finally`. Hygeia lo usa (3 jobs) e Iris lo usa (1 job). Themis, que es de donde salió el patrón,
lo reimplementa a mano en `themis/services/scheduling.py:318-338`:

```python
except Exception:
    logger.exception("Scheduled scan %d failed", ps_id)
finally:
    close_all()
```

**Acción:** decorar `execute` con `@scheduler_job(logger, "Scheduled scan %d failed")` y borrar el
`try/except/finally` exterior (el `try` interior de fases se queda). Dos de tres consumidores ya
usan el helper; el tercero es el que lo inspiró.

**Relacionado:** `_build_trigger` (`:139-152`) construye triggers de APScheduler y solo lo usa
Themis; Hygeia e Iris construyen los suyos a mano. Si se toca esto, subir `_build_trigger` a
`infrastructure/scheduling.py` cuesta lo mismo y cierra la simetría.

---

### C2 · Booleanos sin `is`/`are`, y nombres booleanos para cosas que no lo son
**Impacto: Medio · Velocidad: ⚡**

Dos errores opuestos, ambos presentes:

**(a) Booleanos que no se leen como booleanos:**

| Ubicación | Actual | Propuesto |
|---|---|---|
| `lybra_engine.py:97,169,188`, `schemas.py:47`, `endpoints.py:379` | `deep` | `is_deep_analysis` |
| `scan.py:375`, `iris/managers.py:483`, `system/endpoints.py:240` | `cancelled` | `was_cancelled` |
| `aegis/managers.py:898` | `cancelled` | `was_cancelled` |
| `scan.py:485` | `success` | `did_succeed` |
| `scan.py:513`, `endpoints.py:704` | `finished` | `is_finished` |
| `scan.py:385` | `written` | `was_written` |
| `lybra/engine.py:196` | `verified` | `is_verified` |

`deep` es el peor de la lista: viaja por cinco firmas, un schema de la API y los argumentos
serializados de la TaskQueue, y en ningún punto de esa cadena su nombre dice que es un `bool`.

**(b) Nombres que suenan a booleano pero no lo son** — el error inverso, y más peligroso porque
induce un `if` incorrecto al leer en diagonal:

| Ubicación | Actual | Qué es realmente | Propuesto |
|---|---|---|---|
| `themis/services/scheduling.py:256` | `active` | `List[ProgramedScan]` | `active_scans` |
| `themis/services/analyzers.py:510,669` | `valid` | `list[str]` de severidades | `valid_severities` |
| `themis/services/history.py:200` | `empty` | `dict` de payload vacío | `empty_payload` |
| `iris/services/rules/body_content_rules.py:197` | `found` | `list[str]` de coincidencias | `matched_phrases` |
| `iris/services/rules/sender_identity_rules.py:485` | `found` | `list` de typosquats | `typosquat_matches` |
| `themis/services/processors.py:158` | `finished` | nodo XML | `finished_node` |

Es la misma regla que el `CLAUDE.md` ya fija para `critical` vs `critical_threshold`, aplicada
donde todavía no se aplicó.

**Acción:** renombrado mecánico. La parte (b) primero: es donde un lector se equivoca de verdad.

---

### A13 · `requirements.txt` duplica dev-deps y declara 5 paquetes sin usar
**Impacto: Medio · Velocidad: ⚡**

Existe `requirements-dev.txt`, con un comentario que explica su propósito. Y sin embargo
`requirements.txt` **también** declara `pytest`, `pytest-cov`, `pytest-mock` (los tres ya están en
el dev, con las mismas versiones) más `mypy`, `black`, `flake8`. Seis paquetes de desarrollo en la
imagen de producción, tres de ellos por duplicado con posibilidad de divergir.

Además, cinco paquetes declarados que **ningún fichero importa** (verificado con un barrido AST
sobre `src/`, `tests/` y `run.py`):

| Paquete | Importaría como | Apariciones |
|---|---|---|
| `python-nmap==0.7.1` | `nmap` | 0 |
| `lxml>=4.9.3` | `lxml` | 0 (se usa `xml` de la stdlib) |
| `xmltodict==0.13.0` | `xmltodict` | 0 |
| `dnspython` | `dns` | 0 |
| `python-dateutil==2.8.2` | `dateutil` | 0 |

`python-nmap` y `lxml` son residuos identificables de cuando el parseo de Nmap iba por otro camino.
`Pillow` sí puede quedarse (es requisito real de reportlab, y declararlo explícitamente es
defendible).

**Acción:** quitar los seis de desarrollo de `requirements.txt`; quitar los cinco no usados;
añadir un comentario a `Pillow` explicando por qué se declara si no se importa (mismo estilo que ya
tienen `PyYAML` y `Jinja2`, que sí lo explican).

---

### A12 · La semántica de horarios está implementada dos veces
**Impacto: Medio · Velocidad: ⚡**

`themis/services/scheduling.py` traduce `(schedule_type, schedule_config)` a una hora futura por
dos caminos independientes:

- `_build_trigger` (:139) → `IntervalTrigger(**{unit: every})` / `CronTrigger.from_crontab(...)` — **quién dispara de verdad**
- `calculate_next_run` (:340) → `timedelta(**{unit: every})` / `croniter(...)` — **lo que se muestra en la UI y se guarda en `next_run_at`**

Dos librerías distintas (APScheduler y croniter) interpretando la misma cadena cron. Coinciden
hoy; nada garantiza que coincidan en un caso raro (DST, `*/7` en día del mes, `L`), y cuando no
coincidan el síntoma será «la UI dice una hora y el escaneo salta en otra» — un bug caro de
diagnosticar precisamente porque las dos implementaciones parecen la misma.

Que existan las dos está justificado (`calculate_next_run` se usa también fuera del scheduler, y
`_job_next_run` ya prefiere el valor autoritativo de APScheduler cuando lo tiene). Lo que falta es
que estén atadas.

**Acción:** documentar en ambas cuál es la autoritativa y cuál la estimación, y añadir un test
parametrizado sobre ~10 expresiones (`0 2 * * *`, `*/15 * * * *`, `0 0 1 * *`, `0 3 * * 1-5`, …)
que compruebe que `calculate_next_run` y `_build_trigger().get_next_fire_time()` dan el mismo
instante. Barato, y convierte una divergencia futura en un fallo de CI en vez de en un ticket.

---

### A11 · Cada clave de configuración hay que tocarla en 3 sitios
**Impacto: Alto · Velocidad: ○**

El propio `CLAUDE.md` ya documenta el problema: *«Any key you move must be updated in three places
— the `@config_block` path in `config_reading.py`, the literal path in `ConfigView.vue`, and
`test_config_shape.py`»*. Verificado: `web/app/src/views/ConfigView.vue` contiene ~50 rutas
punteadas literales dentro de `v-model`, del tipo
`store.configFlat['features.themis.history.maxScans']`.

Y hay un agravante que el `CLAUDE.md` no menciona: **el front tiene que conocer la convención de
mayúsculas de cada clave.** Conviven, en el mismo fichero:

```
store.configFlat['general.security.argon2.time_cost']    ← snake_case
store.configFlat['features.iris.legitimateThreshold']    ← camelCase
```

Porque `config_reading.py` mapea `snake_case → camelCase` automáticamente **salvo** en los campos
que declaran `metadata={"key": "pool_size"}` por pasarse tal cual como kwargs a
argon2/SQLAlchemy/redis-py. Esa excepción, que es una decisión interna del backend, se ha filtrado
a un fichero `.vue`.

El coste real: `_cfg()` devuelve el *default* cuando una ruta no resuelve. Un typo en `ConfigView`
no da error — simplemente ese control deja de estar enlazado a nada, y el usuario edita un campo
que no se guarda.

**Acción (por eso es ○):** un endpoint `GET /system/config-schema` que devuelva, derivado de
`CONFIG_BLOCKS`, la lista de claves con su ruta real, tipo, default y rango. `ConfigView.vue`
renderiza los controles a partir de esa respuesta en vez de codificarlos. Las tres fuentes pasan a
una, y `test_config_shape.py` pasa de verificar una lista escrita a mano a verificar el endpoint.

**Alternativa barata si no se quiere abordar entero (⚡):** un test que cargue `ConfigView.vue`,
extraiga con regex todas las cadenas `configFlat['...']` y afirme que cada una resuelve contra
`SecOpsConfig.json`. No unifica las fuentes, pero convierte la divergencia silenciosa en un fallo
de CI. **Recomendado hacer esto ya, y el endpoint cuando toque.**

---

### D5 · `themis/services/reports.py`: 85 KB en un fichero
**Impacto: Alto · Velocidad: ○**

Es, con diferencia, el fichero más grande del repositorio (84.826 bytes; el segundo,
`iris/managers.py`, tiene 64 KB). Contiene al menos cinco responsabilidades distintas:
`ThemisTool` (→ **A2**), `ColorType`, `ReportTheme` (estilos, tablas, cabeceras), la clase base
`PrintingStrategy` con su registro, y cuatro estrategias concretas (Nmap, Nikto, Lybra, Nuclei)
más el `PDFCreator`.

La estructura interna es buena — el registro `@PrintingStrategy.register` ya está bien hecho. El
problema es puramente de tamaño: cualquier cambio en la paleta de un escáner obliga a abrir un
fichero de 2.000+ líneas, y dos personas (o dos agentes) tocando escáneres distintos colisionan
siempre en el mismo fichero.

**Acción:** paquete `themis/services/reports/`, con `theme.py` (ReportTheme + ColorType), `base.py`
(PrintingStrategy + registro), `nmap.py`/`nikto.py`/`lybra.py`/`nuclei.py`, `creator.py`
(PDFCreator) y un `__init__.py` que reexporte los nombres públicos. Es exactamente la Fase 3 que ya
se aplicó a `themis/managers.py` (~2.700 líneas → paquete), con el mismo resultado esperado y el
mismo riesgo: bajo, porque el `__init__.py` conserva la superficie de import.

**Prerrequisito:** hacer **A2** y **B7** antes; adelgazan el fichero y eliminan dos decisiones que
si no habría que reubicar.

---

### A7 · ≈15 excepciones `XNotFoundError` clonadas
**Impacto: Medio · Velocidad: ◐**

El mismo cuerpo, quince veces:

```python
class XNotFoundError(YError):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, entity_id: int):
        super().__init__(
            message=f"<Etiqueta> {entity_id} no encontrado",
            details={"<campo>_id": entity_id},
            user_message="<Etiqueta> no encontrado.",
        )
```

`ScanNotFoundError` (:27), `FindingNotFoundError` (:42), `ReportNotFoundError` (:205),
`ProgramedScanNotFoundError` (:320), `FolderNotFoundError`, `AuthorizedTargetNotFoundError` (:154),
`AssetNotFoundError` (hygeia:27), `AnomalyNotFoundError` (:101),
`IrisAnalysisNotFoundError` (:23), `IrisMailboxConnectionNotFoundError` (:67),
`DistributionListNotFoundError` (aegis:109), `CampaignNotFoundError` (:122),
`VaultNotFoundError` (acheron:43), `StorableNotFoundError` (:61),
`DocumentNotFoundError` (shared:323), `UserNotFoundError` (users:66).

La consecuencia visible es que los mensajes ya han divergido: unos dicen «no encontrado», otros
«no encontrada»; unos incluyen el ID en el `user_message` («El escaneo #12 no existe») y otros no
(«Campaña no encontrada»). Es decir, la API responde con dos estilos distintos al mismo tipo de
error según el módulo.

**Acción:** una base en `shared/_exceptions.py`:

```python
class EntityNotFoundError(EllysiaException):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW
    entity_label: str = "Entidad"
    id_field: str = "entity_id"

    def __init__(self, entity_id):
        super().__init__(
            message=f"{self.entity_label} {entity_id} no encontrado",
            details={self.id_field: entity_id},
            user_message=f"{self.entity_label} #{entity_id} no existe.",
        )
```

Cada subclase queda en tres líneas. Los códigos específicos (`SCAN_NOT_FOUND`,
`PROGRAMED_SCAN_NOT_FOUND`…) se conservan sobrescribiendo `default_code` — no se pierde
granularidad.

**Dos cuidados** (son los que hacen que esto sea ◐ y no ⚡):

1. Hay que respetar la herencia existente (`ScanNotFoundError` hereda de `ScanError`, y hay
   `except ScanError` en el código). La base nueva se mezcla, no sustituye:
   `class ScanNotFoundError(EntityNotFoundError, ScanError)`.
2. No las quince encajan igual de limpio. `FolderNotFoundError`
   (`themis/exceptions.py:376-388`) tiene una firma más permisiva
   (`folder_id=None, message=None, details=None, **kwargs`) que permite construirla sin ID; si
   algún llamante la usa así, o se conserva ese constructor sobrescribiendo `__init__`, o se
   migra el llamante. Verificarlo antes de tocarla, no después.

---

### A9 · Los tres repositorios de documentos repiten las mismas 3 consultas
**Impacto: Medio · Velocidad: ◐**

`ThemisReportRepository` (`themis/repositories.py:732-780`), `IrisReportRepository`
(`iris/repositories.py:201-225`) y `AegisDocumentRepository` (`aegis/repositories.py:72-120`)
implementan cada uno `get_latest_document`, `get_documents_by_user` y `get_documents_by_<padre>`,
con la misma forma de consulta y distinta columna de orden/filtro.

**Acción:** `infrastructure/document_repository.py::DocumentRepository(BaseRepository[T])`
parametrizado por `_PARENT_FK` (`scan_id` / `analysis_id` / `topic_id`). Encaja de forma natural
con **A3**: el `DocumentManager` común necesita exactamente estos tres métodos garantizados.

---

### C1 · Abreviaturas y siglas en nombres de variables
**Impacto: Medio · Velocidad: ◐**

Recuento sobre `API/src` (barrido de identificadores de 1–3 caracteres y abreviaturas conocidas):

| Abreviatura | Apariciones | Debería ser |
|---|---|---|
| `mgr` | 41 | `manager` |
| `ps` / `ps_id` | ~30 (`themis/services/scheduling.py`, `managers/programed.py`) | `programed_scan` / `programed_scan_id` |
| `doc` | 28 | `document` |
| `tq` / `_tq` | 8 | `task_queue` |
| `uid` | 9 | `user_id` |
| `fp` | 11 | `fingerprint` (o `previous_finding` en `_previous_findings_map`) |
| `ps` (variable de puertos, `lybra/`) | 10 | `port_specs` |
| `inc` / `inc_data` | ~8 | `incident` / `incident_data` |
| `st` | 6 | `storable` (acheron) |
| `sq_task` | 4 | `queued_task` |
| `camp_repo` | 3 | `campaign_repository` |
| `dist_list` | 8 | `distribution_list` |
| `resp` / `req` | 6 | `response` / `request` |
| `f`, `p`, `t`, `d`, `q`, `r`, `c`, `a` en comprensiones | ~180 | nombre del elemento |

Los dos peores casos, por frecuencia y por confusión, son:

- **`ps`** — significa `programed_scan` en `themis/services/scheduling.py` y `programed.py`, pero
  significa `port_specs` en `lybra/`. La misma sigla, dos cosas distintas, en el mismo módulo.
- **`f`** — 58 apariciones como variable de comprensión, casi siempre un `finding`, pero también un
  fichero (`aegis/managers.py:599`) y un campo (`acheron/schemas.py:60`).

**Acción:** por lotes y por fichero, con `pylint` verde después de cada lote. Excepciones que se
mantienen (ya autorizadas por el `CLAUDE.md`): `repo`, `config`, `uow`, `pk`, `CR`, y `e` en
`except ... as e` cuando el bloque tiene tres líneas.

**Recomendación de secuenciación:** hacerlo *después* de los cambios estructurales (A3, A4, B1,
D1, D3, D4), no antes — cada renombrado sobre código que va a moverse es trabajo tirado y conflictos
de merge gratis.

---

### E7 · Dos idiomas HTTP conviviendo
**Impacto: Medio · Velocidad: ◐**

`requests` está declarado como dependencia y se usa en el conector de buzones de Iris
(`mailbox/gmail.py`, `mailbox/microsoft.py`, `mailbox_managers.py`). Pero otras tres partes del
código hacen HTTP con `urllib.request` de la stdlib:

- `aegis/services/pills.py:411,531` — fetch de alertas externas, timeouts 15 s / 10 s a mano
- `themis/lybra/checks.py:848,902` — sondas activas, con `ssl._create_unverified_context()` y UA propio
- `themis/lybra/kb.py:42` — descarga de feeds NVD/KEV/EPSS

Lybra tiene motivo legítimo: una sonda de seguridad necesita control fino sobre TLS, redirecciones
y verificación de certificado, y `requests` esconde precisamente eso. Ese caso se queda como está
y merece un comentario que lo diga.

Los otros dos no tienen motivo: son fetches ordinarios de JSON contra endpoints de confianza, con
timeout/UA/manejo de error reimplementados. `aegis/services/pills.py` es el más expuesto (valida
URLs a mano en `:310` con una lista de patrones inválidos).

**Acción:** migrar `pills.py` y `lybra/kb.py` a `requests`. Dejar `lybra/checks.py` en `urllib` con
un comentario explicando por qué. Resultado: una sola implementación de política de red para el
tráfico ordinario, y una excepción documentada para la que necesita ser distinta.

---

### E8 · El SPA reimplementa el polling en 6 sitios
**Impacto: Medio · Velocidad: ◐**

Seis implementaciones del mismo patrón «pedir estado hasta que termine», con dos idiomas
incompatibles:

| Ubicación | Idioma | Intervalo |
|---|---|---|
| `stores/themisStore.js:134` | `setTimeout` reencadenado | `SCAN_POLL_INTERVAL_MS` |
| `stores/themisStore.js:502` | `setTimeout` reencadenado | traceroute |
| `stores/themisStore.js:618` | `await new Promise(setTimeout)` en bucle | generación de PDF |
| `stores/irisStore.js:308,325` | `setTimeout` reencadenado | 2000 ms |
| `stores/irisStore.js:481` | **`setInterval`** | — |
| `views/HygeiaView.vue:288` | **`setInterval`** | `POLL_MS` |

El propio código documenta por qué `setInterval` es el idioma malo (`irisStore.js:297`: *«setInterval
con callback async no esperaba a que la petición anterior terminara → varias peticiones
solapadas»*)… y sin embargo quedan dos `setInterval` vivos, uno de ellos en el mismo fichero que
lo explica.

**Acción:** `composables/usePolling.js` con la forma correcta (reencadenado, cancelación en
`onUnmounted`, pausa cuando la pestaña está oculta) y migrar los seis. Ya hay `composables/`
establecido (`useApi`, `useCache`, `useBatchSelection`…), así que la ubicación no está en discusión.

---

### D4 · `iris/managers.py` (64 KB) + `mailbox_managers.py` sueltos
**Impacto: Medio · Velocidad: ◐**

Iris es el único módulo con **dos** ficheros de managers en la raíz (`managers.py` de 64 KB, el
segundo fichero más grande del repo, y `mailbox_managers.py` de 20 KB). `managers.py` contiene
`IrisManager` (1.100 líneas) e `IrisReportManager`.

**Acción:** paquete `iris/managers/` con `analysis.py`, `reports.py`, `mailbox.py` y un
`__init__.py` reexportador — la misma Fase 3 que ya se hizo en Themis, con el mismo patrón de
`__init__.py`. Cierra además la asimetría de que `mailbox_managers.py` esté en la raíz mientras el
resto de mailbox vive en `services/mailbox/`.

**Sinergia:** hacerlo junto a **A3** (el `DocumentManager` común saca `IrisReportManager` de ahí
casi entero de todas formas).

---

### D3 · `aegis/managers.py`: tres managers en un fichero
**Impacto: Medio · Velocidad: ◐**

42 KB con `AegisManager` (píldoras), `AegisOrgProfileManager` (perfil) y `CampaignManager`
(campañas + quiz público). El docstring de cabecera lo justifica con «Todos viven en este único
fichero por convención» — pero la convención del proyecto, después de la Fase 3 de Themis, es la
contraria.

Las tres responsabilidades no se solapan: `CampaignManager` no toca la generación con IA, y
`AegisManager` no toca herald ni tokens de quiz.

**Acción:** `aegis/managers/` con `pills.py`, `org_profile.py`, `campaigns.py`. Prioridad menor que
D4 porque el fichero es la mitad de grande, pero el mismo movimiento.

---

## Bloque B — Registro de estrategias (los `if` que deberían ser `@register`)

> El patrón de referencia es `ScanManager.register` (`themis/managers/scan.py:600-643`) junto con
> `register_dissector` (`lybra/fingerprinting/registry.py`). Es el más completo del repositorio
> porque cubre las cuatro cosas que un registro tiene que cubrir: alta declarativa junto a la
> clase, resolución por clave, iteración sobre todo lo registrado (`all_managers`), y un error
> claro cuando la clave no existe. Los puntos siguientes son los sitios donde se resolvió el mismo
> problema peor.

### B2 · La clase base ramifica sobre `scan_type == "nmap"`
**Impacto: Medio · Velocidad: ⚡**

`themis/managers/scan.py:503`, dentro de `_execute_scan`, en la **clase base**:

```python
domain_data = processor.process(task.results, target) if scan_type == "nmap" else processor.process(task.results)
```

Una clase base que se registra y despacha polimórficamente, y que aun así conoce por su nombre a
uno de sus hijos. Si un escáner futuro necesita el target, hay que volver a editar la base — que es
exactamente lo que el registro existe para evitar.

**Acción:** que sea el manager quien decida cómo invoca su procesador. Un método sobrescribible:

```python
def _process_results(self, processor, results, target):
    return processor.process(results)
```

`NmapScanManager` lo sobrescribe en una línea. La base deja de nombrar a Nmap.

---

### B3 · `ScanLoggerFactory.register_defaults()` imperativo
**Impacto: Bajo · Velocidad: ⚡**

`themis/services/csv_logger.py:261-268`:

```python
@classmethod
def register_defaults(cls) -> None:
    cls.register("nmap", NmapScanLogger())
    cls.register("nikto", NiktoScanLogger())
    cls.register("nuclei", NucleiScanLogger())

ScanLoggerFactory.register_defaults()
```

Registro correcto, alta incorrecta: el alta está a 100 líneas de la clase que da de alta, en vez de
encima de ella. Es el mismo tipo de olvido que **B1** — el fichero se edita, la lista al final no.

Detalle revelador: **no hay logger de Lybra**, y no está claro si es intencional (Lybra no pasa por
el camino de `_log_to_csv`, `append_csv_data` es un no-op documentado en `lybra_engine.py:829`) o
si simplemente se olvidó al añadirlo. Con el alta declarativa, esa ausencia sería visible en la
definición de la clase en vez de deducible.

**Acción:** convertir `register` en decorador de clase, poner `@ScanLoggerFactory.register("nmap")`
sobre `NmapScanLogger`, borrar `register_defaults`. Documentar en `LybraPrintingStrategy` o en el
propio `csv_logger` que Lybra no tiene logger a propósito.

---

### B5 · `MAILBOX_CONNECTORS` es un dict literal, no un registro
**Impacto: Bajo · Velocidad: ⚡**

`iris/services/mailbox/registry.py:20-23`. El fichero se defiende bien (*«aquí la selección es por
dato… un diccionario simple basta»*) y el argumento es correcto en cuanto al **mecanismo de
resolución**. Pero el alta sigue siendo remota: `GmailConnector` vive en `gmail.py` y se da de alta
en `registry.py`, importando ambas clases arriba del fichero.

Es el caso más leve del bloque — dos entradas, cero probabilidad de que se olvide una. Se incluye
por consistencia: si se hace el mini-helper genérico de **B4**, aplicarlo aquí cuesta cinco
minutos y deja los cuatro registros del repo con la misma forma.

**Acción (opcional, solo si se hace B4):** `@register_connector("gmail")` sobre la clase.
`registry.py` conserva su `get_connector` y su mensaje de error enumerando los soportados, que es
lo mejor que ya tiene.

---

### B7 · Mapa nombre-de-clase → herramienta en `reports.py`
**Impacto: Bajo · Velocidad: ⚡**

`themis/services/reports.py:390-394`:

```python
scan_type = type(self.scan).__name__
tool_key = {'NmapScan': 'nmap', 'NiktoScan': 'nikto', 'LybraScan': 'lybra',
            'NucleiScan': 'nuclei'}.get(scan_type, 'nmap')
```

Un mapa de nombres de clase a strings, con **fallback silencioso a `'nmap'`** — así que un escáner
nuevo no da error: genera su informe con los prompts de IA de Nmap. Ese es el peor modo de fallo
posible para un despacho.

**Acción:** `self.scan.scan_type` ya contiene el valor (es la columna discriminadora del modelo,
`model.py:391`). Sustituir las cuatro líneas por una lectura de esa columna y que el `.get` sin
coincidencia lance en vez de caer a Nmap. Cae junto con **A1**.

---

## Bloque C — Nomenclatura (los que no están arriba)

### C3 · `thirdparty_scans_managers.py`: nombre malo
**Impacto: Bajo · Velocidad: ⚡**

Tres problemas en un nombre: plural mal puesto (`scans_managers`), un concepto que ya no es cierto
(«third party» distinguía de OpenVAS, retirado) y no dice qué contiene. Nadie que busque
`NmapScanManager` lo busca ahí.

**Acción:** el fichero desaparece si se hace **D2**. Si no se hace, `external_tool_managers.py`.

---

### C4 · Colisión de nombres: `managers/kb.py` vs `lybra/kb.py`
**Impacto: Bajo · Velocidad: ⚡**

`themis/managers/kb.py` (`KbSyncManager`, orquesta la sincronización) y `themis/lybra/kb.py` (31 KB,
la base de conocimiento: `version_compare`, `normalize_cpe_to_23`, los feeds). Dos ficheros con el
mismo nombre en el mismo módulo, uno importando al otro.

**Acción:** renombrar el manager a `managers/kb_sync.py`, que es lo que hace y lo que se llama la
clase. El de `lybra/` se queda: ahí `kb` es el nombre correcto de la capa.

---

### C5 · TODO obsoleto en `lybra_sources.py:101`
**Impacto: Bajo · Velocidad: ⚡**

```python
# TODO: Cambiar nombre de la función a algo más descriptivo,
# como `resolve_services` o `get_resolved_services`.
def resolve_services(self, ...):
```

El TODO pide renombrar la función a `resolve_services`. La función ya se llama `resolve_services`.
El trabajo se hizo y el comentario se quedó.

Es de impacto bajo pero de señal alta: un TODO que miente entrena a quien lee a ignorar los TODOs
del repositorio, y solo hay tres marcadores de este tipo en todo `API/src` (los otros dos —
`config_reading.py:995` y los `ponytail:` de `snmp.py` y `reports.py` — sí son reales).

**Acción:** borrar las dos líneas.

---

### C6 · Docstring de `shared/_endpoints.py` lista 3 helpers inexistentes
**Impacto: Bajo · Velocidad: ⚡**

La cabecera del módulo anuncia:

```
- Manager factory (DRY principle)
- Scan lookup helper by ID
- Centralized validation constants
- PDFCreator builder helper
```

Ninguno de los cuatro existe en el fichero. Lo que sí hay: `limiter`, `current_actor` y
`normalize_target`. El módulo tiene 3 símbolos y el docstring promete 7.

**Acción:** reescribir la cabecera con lo que el fichero contiene hoy.

---

## Bloque D — Ubicación (los que no están arriba)

### D2 · `thirdparty_scans_managers.py` debería ser tres ficheros
**Impacto: Bajo · Velocidad: ⚡**

611 líneas con tres managers independientes. La justificación del docstring («unificadas en un solo
fichero porque cada una es pequeña y comparten la misma forma») era cierta cuando eran Nmap y
Nikto; hoy `NucleiScanManager` solo tiene 280 líneas y su propio `_execute_scan`, `_persist_scan_results`
y `_previous_findings_map`.

**Acción:** `managers/nmap.py`, `managers/nikto.py`, `managers/nuclei.py`. El `managers/__init__.py`
ya reexporta los tres nombres, así que ningún import externo cambia. Hacerlo después de **A4**
(cuando `_create_scan_record` ya no está triplicado) para que los ficheros nazcan limpios.

---

### D6 · `iris/services/shared.py`: 43 KB de dos cosas distintas
**Impacto: Bajo · Velocidad: ⚡**

Un fichero llamado `shared` dentro de un módulo llamado `services` dentro de un módulo llamado
`iris` — tres niveles de contenedor genérico sin decir nada. Contiene dos familias sin relación:

- **Accesores de datos cacheados** (~30 funciones): `multi_level_tlds()`, `canonical_brands()`,
  `shortener_domains()`, `dangerous_extensions()`… todas envoltorios de `_cached_set(key)`.
- **Utilidades de texto/dominio** (~10 funciones): `extract_domain`, `registrable_domain`,
  `url_host`, `strip_html`, `levenshtein`, `is_obfuscated_ip_host`.

**Acción:** `iris/services/wordlists.py` (accesores) y `iris/services/text.py` (utilidades). Las
reglas importan de uno o de otro según lo que usen, y el nombre del import ya dice de qué tipo de
cosa se trata.

---

## Bloque E — Diseño y limpieza (los que no están arriba)

### E3 · 23 imports sin usar
**Impacto: Bajo · Velocidad: ⚡**

Barrido AST sobre `src/` (excluyendo `__init__.py`, que reexporta a propósito, y
`from __future__ import annotations`). Los 23 reales, agrupados:

| Fichero | Símbolos |
|---|---|
| `aegis/endpoints.py:13` | `CampaignAlreadyLaunchedError`, `CampaignEmptyListError`, `CampaignNoQuestionsError`, `CampaignNotFoundError`, `DistributionListNotFoundError`, `QuizAlreadyCompletedError`, `QuizTokenInvalidError` |
| `aegis/endpoints.py:3` | `request` |
| `aegis/exceptions.py:1,15` | `DatabaseError`, `EntityAlreadyExistsError`, `AIConnectionError`, `AIResponseError`, `AIFallbackExhaustedError`, `CircuitBreakerOpenError` |
| `aegis/services/pills.py:27,30,38` | `date`, `Path`, `AegisInsufficientContentError`, `AegisFetchError` |
| `aegis/services/exporters.py:31` | `ExporterError` |
| `acheron/exceptions.py:23` | `EllysiaException` |
| `hygeia/endpoints.py:26` | `AnomalyStillOpenError` |
| `iris/endpoints.py:35` | `IrisAnalysisNotReadyError`, `IrisInvalidStateError` |

El bloque de `aegis/endpoints.py:13` merece un vistazo antes de borrar: siete excepciones de
campaña importadas y ninguna usada sugiere que en algún momento esos endpoints las capturaban
explícitamente y ahora dependen de `@handle_exceptions`. Confirmar que el manejo genérico las
traduce al código HTTP correcto **antes** de quitar los imports (es un cambio de comportamiento
disfrazado de limpieza si no).

**Acción:** verificar el caso de aegis; borrar los 23.

---

### E2 · `_strategy_class` declarado 4 veces y leído nunca
**Impacto: Bajo · Velocidad: ⚡**

`thirdparty_scans_managers.py:50,187,345` y `lybra_engine.py:82` asignan
`_strategy_class = <X>PrintingStrategy`. Un `grep` sobre todo el repositorio (`src/`, `tests/`,
`run.py`) devuelve **solo esas cuatro asignaciones**: nadie lo lee. La resolución de estrategia de
impresión va por `PrintingStrategy._registry` (`reports.py:331`), que es un registro
independiente.

Es código muerto que además *parece* vivo: un lector razonable asume que la base lo usa, y una
estrategia nueva que se olvide de declararlo parecerá rota sin estarlo.

**Acción:** borrar las cuatro líneas. Alternativa (peor): hacer que `PrintingStrategy` lo use de
verdad y eliminar el registro paralelo — pero el registro es el mecanismo correcto y esto es
solo un residuo.

---

### A8 · `__init__` de repositorio repetido 24 veces
**Impacto: Bajo · Velocidad: ⚡**

26 clases heredan de `BaseRepository[T]` y 24 escriben exactamente:

```python
def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
    super().__init__(<Model>, uow, session)
```

El modelo ya está declarado en el parámetro genérico (`BaseRepository[Scan]`) y se repite en el
`super()`.

**Acción:** atributo de clase más `__init_subclass__`, misma forma que `ScanManager._MODEL`:

```python
class ScanRepository(BaseRepository[Scan]):
    _MODEL = Scan
```

`BaseRepository.__init__` lee `self._MODEL`. 24 bloques de tres líneas desaparecen. Alternativa sin
atributo nuevo: extraer el modelo de `__orig_bases__` — más mágico, menos legible, no compensa.

---

### A6 · `_previous_findings_map` duplicado
**Impacto: Bajo · Velocidad: ⚡**

`thirdparty_scans_managers.py:529-543` (staticmethod de `NucleiScanManager`) y
`lybra_engine.py:634-645` (método de `LybraEngineManager`). Cuerpos idénticos; la única diferencia
es el repositorio que consultan (`get_previous_findings(..., ScanType.NUCLEI.value, ...)` vs
`get_previous_lybra_findings(...)`). El propio docstring de Nuclei lo admite: *«Mirrors
`LybraEngineManager._previous_findings_map` — same shape, own scan type»*.

La parte del repositorio **ya está unificada**: `get_previous_lybra_findings`
(`repositories.py:653`) es hoy un envoltorio de tres líneas sobre `get_previous_findings`
(`:630`), y su propio docstring lo dice («*Thin wrapper kept for its existing call sites*»). Solo
falta que los managers hagan lo mismo.

**Acción:** una implementación única en `ScanManager` que use `self.SCAN_TYPE` y
`get_previous_findings`; borrar los dos overrides y, con ellos, el envoltorio
`get_previous_lybra_findings` (su único llamante desaparece).

---

### E6 · `AegisManager._lock` promete una garantía que no da
**Impacto: Bajo · Velocidad: ⚡**

`aegis/managers.py:86` declara `_lock = threading.Lock()` como atributo de clase, y `generate()`
(:115) envuelve con él la creación del documento y el `submit` a la TaskQueue. El docstring dice
«Thread-safe».

Es cierto dentro de un proceso e irrelevante fuera: en producción la API corre bajo gunicorn con
varios workers (y los jobs, en procesos worker de RQ aparte). Un `threading.Lock` de clase no
coordina nada entre procesos. Si la sección crítica de verdad importa, el mecanismo tendría que ser
otro (una restricción `UNIQUE` en la tabla, o un lock en Redis); si no importa — y probablemente no,
porque el `submit` es idempotente respecto al `document_id` recién creado — el lock sobra.

**Acción:** determinar cuál de los dos casos es y actuar en consecuencia. Lo que no puede quedarse
es un lock que hace creer que hay una garantía que no hay. Si sobra, borrarlo y quitar
«Thread-safe» del docstring.

---

## 2. Plan de ejecución sugerido

No es obligatorio seguirlo, pero las dependencias entre puntos sí lo son.

### Sprint 0 — «una tarde» (todo ⚡, sin dependencias, riesgo nulo)

`A14` · `C5` · `C6` · `E2` · `E3` · `A13` · `A2` · `B7` · `C4`

Nueve puntos, ninguno toca comportamiento salvo `A13` (dependencias) y `E3` (verificar aegis
primero). Deja el repositorio sin código muerto, sin documentación falsa y con el catálogo de
escáneres a la mitad de sitios.

### Sprint 1 — DRY estructural (⚡ con dependencias entre sí)

`A10` → `A3` (parte de `external_id`) · `A4` · `A5` · `A6` · `A8` · `E5` → `E4` · `B2` · `B6`

Orden importante: `A10` antes que `A3`; `E5` antes que `E4`.

### Sprint 2 — Registros

`A1` (los cinco literales) · `B1` · `B3` · `B4` · `B5`

Al terminar, añadir el test parametrizado sobre `ScanType` descrito en `A1`: es lo que impide que
esto vuelva a divergir.

### Sprint 3 — Ubicación

`D1` (+ test de invariante) · `E1` (hacerlo *con* D1, se tocan los mismos ficheros) · `D2` · `D6` ·
`D3` · `D4` · `D5`

`D5` al final: es el más grande y se beneficia de `A2` y `B7` ya hechos.

### Sprint 4 — Nomenclatura

`C2` (parte b primero) · `C2` (parte a) · `C1` · `C3`

Deliberadamente el último: renombrar antes de mover es trabajo tirado.

### Sprint 5 — Los grandes

`A7` · `A9` (+ cierre de `A3`) · `A11` (empezando por la alternativa ⚡) · `A12` · `E7` · `E8`

---

## 3. Lo que se ha comprobado y está bien

Para calibrar: no todo lo auditado tiene deuda. Estos puntos se revisaron expresamente y **no**
generan ninguna entrada:

- **Código muerto real: prácticamente cero.** Un barrido AST de funciones privadas nunca
  referenciadas devolvió dos candidatos, ambos falsos positivos (`_require_one_mode` es un
  `@validates_schema` de Marshmallow; `_install_signal_handlers` es un hook de RQ). Es un resultado
  inusualmente bueno para un repositorio de este tamaño.
- **`lybra/`** — la invariante ORM-free se cumple sin excepciones; el registro de dissectors es
  correcto; la separación por capas (L0 transport / L1 fingerprinting / L2 engine+checks /
  L3 kb+correlation) se sostiene en el código, no solo en el docstring.
- **`infrastructure/`** — `UnitOfWork`, `build_repository` y el reparto de responsabilidad de la
  sesión entre `teardown_request` y `job_context` están bien documentados y bien aplicados. El
  motivo del `close_all()` en cada borde está explicado donde hay que explicarlo.
- **`tools/herald/`** — es el módulo más limpio del repositorio. `rendering.py` con `ChoiceLoader` y
  autoescape selectivo por extensión resuelve el problema entero sin dejar nada a medias. Su única
  entrada aquí es `B4`, compartida con scribe.
- **`shared/_documents.py`** y **`shared/_ownership.py`** — extracciones correctas, con el porqué
  documentado. La deuda no es que existan; es que se aplicaron a la mitad de los llamantes (`A3`,
  `E5`).
- **`TaskTrackingMixin`** y **`job_context`** — bien diseñados y bien documentados. Igual: la deuda
  es que no todos los managers los usan (`A10`, `A3`).

---

*Documento generado tras auditoría directa del código en `feature/aegis/campaignes`, 2026-08-03.
Cada punto cita fichero y línea sobre ese estado del repositorio.*
