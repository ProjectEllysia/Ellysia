# Calidad de código — segunda pasada (SOLID / DRY / LEAN)

> Evaluación realizada el 2026-07-14 sobre la rama `refactor/fix-general-issues`. Alcance: backend `API/` y SPA `web/app/`.
>
> **Relación con el sondeo anterior:** [sondeo-codigo-api-web.md](sondeo-codigo-api-web.md) (2026-07-10) ya catalogó y ejecutó por fases gran parte de los hallazgos originales (Fases 1–2 completas, Fase 3 parcial). Este documento **no repite** lo ya corregido: recoge los **hallazgos nuevos** de esta pasada (prefijo `N`) y reordena junto a ellos los **pendientes vigentes** del sondeo (se citan por su ID original: `D1`, `A1`, `Q1`, …). Cada hallazgo nuevo se verificó leyendo el código citado en esta fecha.

## Leyenda

- **Impacto** (ganancia de calidad que aporta el cambio): 🔴 Alto · 🟠 Medio · 🟡 Bajo
- **Esfuerzo:** ⚡ Rápido (<2 h) · 🔧 Medio (½–1 día) · 🏗️ Largo (>2 días / refactor)
- **Principio:** Correctness · Security · SOLID · DRY · LEAN

Orden del plan: primero mayor impacto con menor esfuerzo; dentro del mismo cuadrante, primero lo que desbloquea o simplifica otros ítems.

---

## Hallazgos nuevos (N1–N12)

### N1 — Ownership faltante en dos endpoints de documentos Themis (IDOR) — 🔴 ⚡ · Security/Correctness

Dos endpoints de Themis devuelven metadatos de documentos **sin comprobar que el escaneo/documento pertenezca al usuario autenticado**:

- `GET /themis/scan/<scan_id>/documents` ([endpoints.py:907-918](API/src/modules/features/themis/endpoints.py:907)): resuelve el scan con `resolve_manager` + `get_scan_by_id` y lista sus documentos sin ninguna aserción de propiedad. Cualquier usuario con `THEMIS_READ` puede enumerar los documentos (ids, fechas, estado, `downloadUrl`) de escaneos ajenos.
- `GET /themis/document-status?scan_id=` ([endpoints.py:819-850](API/src/modules/features/themis/endpoints.py:819)): la propiedad solo se verifica en la rama `document_id` (`if document_id: assert_document_ownership(...)`); consultando por `scan_id` no hay ninguna comprobación.

La descarga (`/document/<id>/download`) sí verifica propiedad, así que la fuga es de metadatos + enumeración de IDs, no del PDF — pero rompe el patrón que el resto del módulo aplica de forma consistente. **Iris hace exactamente esto bien** ([iris/endpoints.py:383](API/src/modules/features/iris/endpoints.py:383) comprueba `doc.user_id != user.id` en ambas ramas, y `get_documents_by_analysis` asegura `assert_analysis_ownership`), lo que confirma que en Themis es un descuido, no un diseño.

**Fix:** usar `ScanManager.assert_scan_ownership(scan_id, user.id)` (o `resolve_owned_scan`) en ambos endpoints; en `document-status` por `scan_id`, verificar `doc.user_id == user.id` como hace Iris. Añadir test de regresión (usuario B consulta documentos del scan de usuario A → 404).

### N2 — `run_report_generation` (helper compartido) existe pero nadie lo usa: cerrar D1 ahora es barato — 🔴 ⚡ · DRY/LEAN

`shared/_documents.py` contiene `run_report_generation()` y `_set_document_status_safe()` ([\_documents.py:27-79](API/src/modules/shared/_documents.py:27)), escritos explícitamente para deduplicar el patrón de generación de PDFs («Patrón común a Themis e Iris (antes duplicado en ambos managers)»)… pero **ningún módulo los llama** (verificado con grep: cero usos fuera del propio fichero). Mientras tanto:

- `ThemisReportManager._generate_pdf_async` + `_update_document_status` ([reports.py:163-205](API/src/modules/features/themis/managers/reports.py:163))
- `IrisReportManager._generate_pdf_async` + `_update_document_status` ([managers.py:1093-1133](API/src/modules/features/iris/managers.py:1093))

siguen duplicando el mismo bloque casi literal (mismo comentario sobre RQ incluido). Es el ítem **D1** del sondeo (marcado allí como pendiente, esfuerzo 🔧) — pero como el helper ya existe con su docstring y semántica de errores resuelta, cablearlo baja el esfuerzo a ⚡: cada `_generate_pdf_async` queda reducido a construir su `render` callable y delegar.

**Fix:** ambos managers llaman a `run_report_generation(doc_id, RepoCls, render=lambda: ...)`; borrar los dos `_update_document_status` privados. La suite de integración existente (`test_iris_documents.py`, `test_themis.py`) cubre la regresión.

### N3 — Parámetro muerto `strategy_class` + acceso a atributo privado desde el endpoint — 🟠 ⚡ · LEAN/SOLID (encapsulación)

`ThemisReportManager.generate_report(scan_id, ai_report, strategy_class=None)` declara y documenta `strategy_class` pero **no lo usa en el cuerpo** ([reports.py:129-155](API/src/modules/features/themis/managers/reports.py:129) — la estrategia real se resuelve dentro de `PDFCreator` vía su propio registro, [services/reports.py:373](API/src/modules/features/themis/services/reports.py:373)). Para alimentar ese parámetro muerto, el endpoint accede a un atributo privado de otro objeto: `manager._strategy_class` ([endpoints.py:795](API/src/modules/features/themis/endpoints.py:795)).

**Fix:** eliminar el parámetro del manager y el acceso `_strategy_class` del endpoint. Cero cambio de comportamiento.

### N4 — Serialización de documentos duplicada 3× dentro de `themis/endpoints.py` — 🟠 ⚡ · DRY

El bloque `download_url = None; is_done = ...; docs_list.append({...})` está copiado casi idéntico en `get_document_status`, `get_all_documents` y `get_documents_by_scan` ([endpoints.py:837-850](API/src/modules/features/themis/endpoints.py:837), [873-889](API/src/modules/features/themis/endpoints.py:873), [920-936](API/src/modules/features/themis/endpoints.py:920)). Iris ya resolvió esto con un helper `_download_url_for(doc)` — Themis debería tener su `_serialize_document(doc)` equivalente (o mejor: un Marshmallow schema que lo haga, ya que los response schemas existen).

**Fix:** extraer `_serialize_document(doc) -> dict` en `themis/endpoints.py` (o método en `ThemisReportManager`) y usarlo en los 3 sitios. De paso corrige la asimetría de que la lógica «cuándo hay downloadUrl» viva en la capa HTTP.

### N5 — Excepciones de documentos genéricas viviendo en `aegis.exceptions` — 🟠 🔧 · SOLID (acoplamiento entre módulos)

`DocumentError`, `DocumentNotFoundError`, `DocumentNotReadyError` se definen en `aegis/exceptions.py` pero las importan **Themis** ([endpoints.py:22](API/src/modules/features/themis/endpoints.py:22), [managers/reports.py:7](API/src/modules/features/themis/managers/reports.py:7)) e **Iris** ([managers.py:22](API/src/modules/features/iris/managers.py:22)). Tres módulos feature acoplados a las excepciones de un cuarto viola la regla de capas del propio repo (lo transversal vive en `shared/`); además obliga a Themis a conocer Aegis para algo que no tiene nada que ver con campañas.

**Fix:** mover las tres excepciones a `shared/_exceptions.py` y dejar re-exports en `aegis/exceptions.py` para compatibilidad (mismo patrón que ya usa `unit_of_work.py` con los helpers de `engine.py`). Actualizar imports en themis/iris cuando toque tocar esos ficheros.

### N6 — N+1 en los listados de escaneos — 🟠 🔧 · LEAN (eficiencia)

- `ScanManager.get_scans_paginated` obtiene la página de scans y luego llama `self.format_scan(item.id)` **por cada ítem** ([scan.py:131](API/src/modules/features/themis/managers/scan.py:131)) — y `format_scan` re-consulta el scan por id, de modo que una página de 10 hace ~11+ queries.
- `GET /themis/results?type=all` ([endpoints.py:521-527](API/src/modules/features/themis/endpoints.py:521)) itera los 4 managers, carga **todos** los scans del usuario sin paginación y vuelve a llamar `format_scan(scan.id)` por cada uno (re-query por fila otra vez).

**Fix:** que `format_scan` acepte la instancia ya cargada (sobrecarga `format_scan(scan)` o parámetro opcional) y que la rama `all` pagine o al menos reutilice las instancias que ya tiene. Beneficio directo en el endpoint más consultado del módulo (la SPA lo sondea cada 4 s cuando hay escaneos activos).

### N7 — Config OAuth leída en import-time en `users/managers.py` — 🟠 🔧 · SOLID (mismo patrón que A8)

`ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, JWT_SECRET_KEY, JWT_ALGORITHM = CR.get_oauth_config()` se ejecuta **al importar el módulo** ([managers.py:69-74](API/src/modules/users/managers.py:69)). Consecuencias: cambios de tuning JWT exigen reinicio aunque `PUT /system` recargue config; los tests que quieren variar expiraciones tienen que parchear constantes de módulo en vez de config. Es el mismo defecto que el sondeo marcó como **A8** para OpenVAS, en un sitio más sensible.

**Fix:** leer vía funciones (`CR.get_oauth_config()` ya cachea con `@_lazy_load`) en el punto de uso, o encapsular en un `@property`/función módulo-local. Bajo riesgo, pero tocar la emisión/verificación de tokens merece pasar `test_oauth.py` + `test_mfa.py` completos.

### N8 — Sleep mágico de 600 ms restante en `generateLybraPdf` — 🟠 ⚡ · Correctness (residuo de B9)

El fix de **B9** (sondeo, Fase 3) sustituyó el `setTimeout(600)` de `handlePreviewPdf` por `waitForDocument()`, pero quedó otro idéntico en `themisStore.generateLybraPdf` ([themisStore.js:923](web/app/src/stores/themisStore.js:923)): espera 600 ms fijos y refresca la lista de documentos, con la misma condición de carrera (generación encolada que suele tardar más).

**Fix:** reutilizar `waitForDocument(scanId)` (ya existe en el mismo store) antes de `loadLybraDocs`.

### N9 — Código muerto y documentación interna obsoleta (lote LEAN) — 🟡 ⚡ · LEAN

Lote de limpieza sin riesgo, todo verificado con grep:

- `IrisManager._is_cancelled` ([managers.py:961-977](API/src/modules/features/iris/managers.py:961)): sin ningún caller.
- `MAX_PDF_SIZE_BYTES` ([themis/endpoints.py:108](API/src/modules/features/themis/endpoints.py:108)): declarado y nunca usado (= **Q12** del sondeo, sigue vigente).
- Docstrings «Generate PDF in a background **thread**» en ambos `_generate_pdf_async` (Themis e Iris): el modelo pasó a procesos worker de RQ hace tiempo. (Desaparece solo si se hace N2.)
- `delete_authorized_target` devuelve `"target": ""` fijo ([endpoints.py:450](API/src/modules/features/themis/endpoints.py:450)) — o se devuelve el target real (se tiene antes de borrar) o se quita la clave del schema.
- `IrisManager._validate_headers_pre` usa formato `%`-style con unicode escapado (`á`) en literales que podrían ser UTF-8 normal ([managers.py:558-561](API/src/modules/features/iris/managers.py:558)) — legibilidad.

### N10 — `web/app/CLAUDE.md` desactualizado (habla de "sentinel") — 🟡 ⚡ · LEAN (docs que mienten)

El CLAUDE.md del SPA referencia `sentinelStore`, vistas "Sentinel" y el proxy `/sentinel` — el módulo se renombró a **themis** ([vite.config.js:33](web/app/vite.config.js:33) ya proxya `/themis`; no existe ningún `sentinelStore.js`). Mismo tipo de deuda que el hallazgo del nginx (`/sentinel/` y sin ruta `/iris/`) que el sondeo dejó anotado sin tocar. Documentación de agentes incorrecta = instrucciones erróneas en cada sesión futura.

**Fix:** actualizar nombres y lista de proxies en `web/app/CLAUDE.md`; decidir a la vez qué hacer con `web/nginx.conf` (pendiente del sondeo).

### N11 — `assert_scan_ownership`: query extra de User por llamada — 🟡 ⚡ · LEAN (complementa A10)

Además de no usar el helper compartido `assert_owned` (ya anotado como **A10**), `assert_scan_ownership` ([scan.py:288-313](API/src/modules/features/themis/managers/scan.py:288)) hace un `UserManager().get_user_by_id(user_id)` **por cada llamada** solo para lanzar `UserNotFoundError` — un caso imposible en la práctica (el `user_id` viene del JWT ya verificado) que cuesta una query en el camino caliente de casi todos los endpoints de Themis. Migrar a `assert_owned` (fix de A10) elimina la query de gratis.

### N12 — Pila de ~8 decoradores repetida en los ~30 endpoints de Themis — 🟡 🏗️ · DRY (opcional, discutible)

Cada endpoint repite el mismo sándwich (`@blp.arguments/response/alt_response ×4 + @require_oauth_token + @require_attributes + @limiter.limit + @handle_exceptions`). Es verboso pero **explícito y grepeable**; una factory de decoradores lo comprimiría a costa de indirección. Solo abordarlo si se hace junto a **A7** (sacar la lógica de negocio de endpoints) — no como cambio aislado. Se lista para dejar constancia de la decisión, no como recomendación activa.

---

## Pendientes vigentes del sondeo anterior (reordenados aquí)

Estado verificado a 2026-07-14 — siguen abiertos:

| ID sondeo | Resumen | Impacto | Esfuerzo | Nota de esta pasada |
|---|---|---|---|---|
| **D1** | Duplicación `_generate_pdf_async`/`_update_document_status` Themis↔Iris | 🟠→🔴 | 🔧→⚡ | Reclasificado: ver **N2** — el helper ya existe, solo falta usarlo |
| **D2** | `delete_document` (get→exists→remove→delete) reimplementado 3× | 🟠 | ⚡ | Sigue igual ([reports.py:84](API/src/modules/features/themis/managers/reports.py:84), [iris/managers.py:1027](API/src/modules/features/iris/managers.py:1027)); encaja natural tras N2/N5 |
| **A10** | `assert_scan_ownership` no usa `assert_owned` | 🟠 | ⚡ | Ampliado por **N11** (query extra) |
| **A7** | Lógica de negocio en endpoints Themis (`severityBreakdown`, `openPorts`, `TYPE_MGR_MAP`) | 🟠 | 🔧 | Sigue igual ([endpoints.py:497-502](API/src/modules/features/themis/endpoints.py:497), [610-624](API/src/modules/features/themis/endpoints.py:610)) |
| **Q4** | `TaskStatus` duplicado (themis/services/tasks.py vs taskqueue) | 🟠 | 🔧 | Sigue igual; documentado como trampa en CLAUDE.md |
| **Q1** | Sin estado de error en la UI (fallo → empty-state feliz) | 🟠 | 🔧 | Sigue igual (`catch { /* noop */ }` en stores) |
| **Q11** | `find_task` (round-trip Redis) por cada regla de Iris | 🟡 | ⚡ | Sigue igual ([iris/managers.py:652-654](API/src/modules/features/iris/managers.py:652)) |
| **S7/S9/S11** | Decisiones de producto de seguridad | 🟠 | 🔧 | Requieren luz verde explícita — fuera del alcance «no romper funcionamiento» de este plan |
| **A1/A2/A3** | God-class `ScanManager` / god-store `themisStore` (970 líneas) / `IrisReportViewer` (1200 líneas) | 🔴 | 🏗️ | Siguen igual; hacer **después** de los quick wins y con la suite verde |
| **D4** | Pipeline `create→commit_for_handoff→submit→execute` sin base común | 🟠 | 🏗️ | Sigue igual; N2+D2 lo dejan más cerca |
| **T1** | Cobertura de integración Themis (parcial tras Fase 1) | 🟠 | 🔧 | N1 añade el caso concreto que falta: ownership de documentos |
| **nginx** | `web/nginx.conf` enruta `/sentinel/` y no `/iris/` | 🟠 | ⚡* | *Pequeño de código, pero necesita verificación de despliegue; agrupar con N10 |

---

## Matriz y orden de ejecución

| | ⚡ Rápido | 🔧 Medio | 🏗️ Largo |
|---|---|---|---|
| **🔴 Alto** | **N1** ownership docs Themis · **N2** cablear `run_report_generation` (cierra D1) | — | **A1/A2/A3** god-* |
| **🟠 Medio** | **N3** strategy_class muerto · **N4** serialización docs · **N8** sleep 600 ms · **D2** delete_document · **A10+N11** assert_owned | **N5** excepciones a shared · **N6** N+1 listados · **N7** OAuth import-time · **A7** lógica en endpoints · **Q1** error-state UI · **Q4** TaskStatus · **T1** tests | **D4** pipeline común |
| **🟡 Bajo** | **N9** código muerto · **N10** CLAUDE.md web + nginx · **Q11** find_task por regla | — | **N12** factory decoradores (no recomendado aislado) |

### Secuencia recomendada

1. **Fase A — Quick wins de seguridad y DRY (⚡, ~1 día):** N1 → N2 → N3 → N4 → N8 → D2 → A10+N11 → Q11. Todos con test de regresión donde aplique (N1 obligatorio). Tras esta fase, `themis/managers/reports.py` e `iris/managers.py` quedan sensiblemente más pequeños y el hueco de ownership cerrado.
2. **Fase B — Limpieza LEAN (⚡, ~½ día):** N9 + N10 (+ decisión sobre nginx). Sin riesgo funcional; ideal como PR separado y pequeño.
3. **Fase C — Estructural medio (🔧):** N5 (excepciones a shared) → N6 (N+1) → N7 (OAuth lazy) → A7 (lógica fuera de endpoints; reevaluar N12 aquí) → Q4 → Q1 → T1. Cada uno con la suite completa verde antes de encadenar el siguiente.
4. **Fase D — Refactors grandes (🏗️):** A1/A2/A3 y D4, en ese orden, solo con la cobertura de C/T1 en su sitio. Son los de mayor ganancia de mantenibilidad a largo plazo pero también los únicos con riesgo real de regresión.

### Verificación

- **Backend:** `cd API && pytest` (suite completa, SQLite + mocks; no requiere Postgres/Redis) y `pylint src`. N1 y N6 merecen tests nuevos en `tests/integration/test_themis.py` (ownership cruzado y conteo de queries respectivamente).
- **SPA:** `npm run build` no detecta errores de referencia (no hay type-check) — N8 verificarlo en navegador real con el dev server (`npm run dev`), igual que se hizo con B9.
- **Regla del repo:** los `xfail(strict=True)` que pasen a XPASS tras un fix deben perder el marcador; SQLite/mocks solo en `tests/`, nunca adaptar `src/`.
