# Iris — análisis de mercado, oportunidades y roadmap de evolución

> Documento de decisión para llevar Iris desde un analizador heurístico de correos a una
> plataforma de triage, inteligencia y respuesta anti-phishing. Verificado contra el código
> de `API/src/modules/features/iris/`, los tests relacionados y la documentación pública de
> Microsoft 365, Google Workspace y estándares abiertos. Fecha de revisión: 2026-08-24.

## 0. Decisión ejecutiva

Iris no necesita convertirse primero en otro gateway de correo. Ya tiene una base diferencial
para un producto de **investigación explicable de mensajes sospechosos**:

- 46 reglas en 10 familias, cubriendo autenticación, identidad, reply-path, threading,
  destinatarios, cadena `Received`, contenido, enlaces, QR y adjuntos.
- Análisis de cabeceras RFC 5322 y mensajes MIME completos, incluido el desenvoltorio de
  `message/rfc822`.
- Puntuación 0–100, gates de alta confianza, razones del veredicto y principales señales.
- Extracción de dominios, URLs, IPs, correos electrónicos y hashes de adjuntos.
- Resumen ejecutivo mediante IA y generación de informes PDF.
- Conectores OAuth para Gmail y Microsoft 365, ingesta programada y notificación por correo.

La oportunidad de mercado no está en añadir cien reglas aisladas. Está en cerrar el circuito:

```text
mensaje -> evidencia -> veredicto calibrado -> caso de analista -> inteligencia de campaña
        -> acción segura -> feedback -> mejora medible del detector
```

La recomendación es seguir este orden:

1. Corregir los fallos que pueden perder mensajes, falsear estados o relajar autenticación.
2. Hacer que cada veredicto sea auditable y accionable por un analista.
3. Convertir el análisis individual en triage por lotes y detección de campañas.
4. Añadir enriquecimiento, automatización e integraciones solo cuando exista una base de
   evidencia y feedback suficientemente fiable.
5. Tratar sandbox, ML avanzado y gateway inline como apuestas estratégicas, no como el siguiente
   sprint.

## 1. Alcance y método

Este documento analiza mejoras sobre lo que ya existe y funcionalidades que Iris todavía no
tiene. No es un estudio de tamaño de mercado, pricing o ventas: sin entrevistas, métricas de uso
ni datos comerciales no sería honesto inventar un TAM. Es un **benchmark de capacidades** y un
plan de producto técnico.

Se han considerado cuatro fuentes de evidencia:

- Código y tests del módulo Iris, especialmente `endpoints.py`, `model.py`, `schemas.py`,
  `repositories.py`, `managers/analysis.py`, `managers/mailbox.py`, `services/parsers.py` y
  `services/rules/`.
- Estado operativo descrito en `README.md`, `AGENTS.md` y el `ROADMAP.md` histórico de Iris.
- Capacidades que Microsoft y Google publicitan actualmente para protección de correo cloud.
- Estándares y formatos que condicionan interoperabilidad: RFC 5322, SPF/DKIM/DMARC, ARC,
  STIX 2.1 y MISP.

El inventario de esta hoja de ruta distingue explícitamente entre:

- **Bug / deuda de corrección:** comportamiento actual que puede perder datos, producir un
  resultado incorrecto, dejar estados incoherentes o incumplir el contrato documentado.
- **Hardening / arquitectura:** cambio preventivo que mejora seguridad, resiliencia, privacidad
  o capacidad de operar Iris a escala.
- **Mejora:** evolución de una capacidad existente sin cambiar su propósito principal.
- **Funcionalidad:** capacidad nueva visible para el usuario o para integraciones externas.
- **Estratégica / I+D:** apuesta de alto coste, alta incertidumbre o dependencia externa.

## 2. Estado actual auditado

| Área | Situación real | Lectura de producto |
|---|---|---|
| Detección | 46 reglas, 10 familias, score sustractivo y gates | Base sólida de triage offline y explicable |
| Autenticación | SPF, DKIM, DMARC, ARC y provenance interpretados desde cabeceras | Útil como evidencia, pero no equivale a verificación DNS/criptográfica independiente |
| Contenido | BEC, urgencia, URLs, cloaking, QR, Unicode, adjuntos sospechosos | Buena cobertura heurística; falta inspección profunda y OCR |
| Evidencia | Gates, top signals, reglas, recomendaciones, IOCs y cadena `Received` | Falta anclar cada finding a posiciones concretas del mensaje |
| IA | Resumen ejecutivo asíncrono y persistido | Debe quedar subordinada a evidencia y mostrar incertidumbre |
| Ingesta | Gmail y Microsoft Graph con OAuth, polling y cursor | Es la parte con más riesgo operativo actual |
| Respuesta | Email de notificación para phishing | No hay cuarentena, remediación, casos ni acciones sobre el buzón |
| Interoperabilidad | CSV de IOCs y API JSON | Falta contrato estable, STIX/MISP, webhooks y SIEM/SOAR |
| Aprendizaje | No existe feedback etiquetado de analista | Iris no tiene todavía un mecanismo seguro para calibrarse con uso real |
| Retención | Raw email en `IrisAnalysis.raw_headers`, sin política de retención visible | Riesgo de crecimiento, privacidad y coste de almacenamiento |

### 2.1 Deuda documental detectada

El `API/src/modules/features/iris/ROADMAP.md` histórico sigue describiendo como pendientes
algunas capacidades que ya existen, como provenance de `Authentication-Results`, conectores de
Gmail/Graph y desenvoltorio de `.eml`. También hay desfases entre permisos documentados y permisos
reales en `README.md`, y `iris.ai_summary` se usa al encolar pero no está registrado en
`API/src/modules/features/iris/__init__.py`.

Este documento debe ser la referencia de producto a partir de ahora. Tras aprobar fases, el
roadmap histórico debe archivarse o actualizarse; no conviene mantener dos listas normativas.

## 3. Qué está haciendo el mercado

El benchmark se ha hecho sobre documentación pública, no sobre pruebas internas de productos.
La señal común es clara: una solución madura no se limita a decir “phishing”.

| Expectativa de mercado | Evidencia pública | Implicación para Iris |
|---|---|---|
| Protección contra spoofing e impersonación de usuarios, dominios y marcas | [Microsoft Defender: anti-phishing policies](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about) | La lista global de marcas de Iris debe evolucionar a entidades protegidas por usuario/organización, con allowlist controlada |
| Ajuste de sensibilidad y equilibrio falso positivo/falso negativo | Microsoft documenta umbrales estándar, agresivos y más agresivos | Iris necesita score versionado, calibración y perfiles de política, no solo dos umbrales globales |
| Inteligencia basada en relación histórica remitente-destinatario | Microsoft documenta mailbox intelligence y contactos frecuentes | Iris puede empezar con un grafo local de comunicación antes de abordar ML complejo |
| Sandbox y análisis profundo de malware | Google Workspace publica Security Sandbox y reglas para adjuntos dañinos | El análisis de PDF/OOXML/HTML y, más adelante, sandbox, son brechas reales, no adornos |
| OCR y protección de contenido visual | Google documenta OCR para leer imágenes en filtros de contenido | El QR detectado por Iris debe ampliarse a texto, URLs y formularios embebidos en imágenes |
| Cuarentena, listas permitidas/bloqueadas y acciones post-entrega | Microsoft y Google documentan quarantine, allowlists, blocklists y acciones administrativas | El siguiente salto de valor es responder en Gmail/Graph, no solo notificar por email |
| Telemetría, informes y búsqueda histórica | Google documenta logs de Gmail, BigQuery y búsqueda de entrega | Iris necesita historial consultable, campañas, métricas y auditoría de acciones |
| Sincronización incremental y orientada a eventos | [Microsoft Graph: delta query para mensajes](https://learn.microsoft.com/en-us/graph/delta-query-messages) y [recurso message](https://learn.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0) | El polling actual debe tener checkpoints fiables y evolucionar a delta/webhooks cuando el uso lo justifique |
| Interoperabilidad de inteligencia | STIX 2.1 y MISP son formatos de intercambio ampliamente usados | La exportación CSV es un buen inicio, pero no es suficiente para SOC/SIEM/SOAR |

### 3.1 Posición recomendada

Iris no debe intentar ganar a Microsoft Defender o Gmail en filtrado masivo de cada mensaje del
proveedor. Es más realista y más distintivo posicionarlo como:

**“El laboratorio explicable de correo sospechoso que convierte un mensaje, una cabecera o un
buzón conectado en evidencia, contexto de campaña y una acción segura.”**

Esto permite convivir con el filtro nativo del proveedor: Iris investiga lo que el usuario reporta,
lo que cae en una carpeta de sospechosos y lo que un SOC necesita entender o correlacionar.

## 4. Sistema de priorización

Cada iniciativa recibe cuatro valores.

### 4.1 Impacto de usuario (`I`)

| Valor | Significado |
|---|---|
| 5 | Evita pérdida de mensajes, una decisión de seguridad incorrecta o desbloquea un flujo central de trabajo |
| 4 | Reduce mucho el tiempo de triage, mejora detección o permite una acción habitual |
| 3 | Mejora una parte relevante del análisis, pero existe una alternativa manual |
| 2 | Mejora comodidad, cobertura secundaria o administración |
| 1 | Beneficio principalmente interno o experimental |

### 4.2 Facilidad (`F`)

| Valor | Significado |
|---|---|
| 5 | Horas o 1 día; cambio localizado y tests directos |
| 4 | 2–5 días; varios ficheros dentro de un módulo |
| 3 | 1–3 semanas; backend, UI, migración o pruebas de integración |
| 2 | Varias semanas; proveedor externo, infraestructura o cambio transversal |
| 1 | Meses, varios repositorios, hardware, investigación o dependencia comercial |

### 4.3 Valor de ordenación

`Valor = I × F`. La tabla maestra está ordenada de mayor a menor valor dentro de cada horizonte de
ejecución. En empates se prioriza impacto y después se antepone un bug que pueda afectar a
integridad, seguridad o pérdida de datos. Las iniciativas estratégicas se mantienen en un bloque
final aunque alguna obtenga una multiplicación matemática alta: su realismo `R3/R4` y sus
dependencias externas son un gate de gobernanza. Un resultado alto no significa “hacerlo ya” si
depende de una fase previa: la columna de fase y las dependencias mandan.

### 4.4 Nivel de realismo (`R`)

| Nivel | Lectura | Horizonte orientativo |
|---|---|---|
| R1 | Muy realista: control técnico directo, alcance acotado | Horas a 2 semanas |
| R2 | Realista: requiere diseño, migración o UI, pero encaja con la arquitectura | 2–6 semanas |
| R3 | Estratégico viable: depende de proveedor, feed, seguridad operacional o volumen de datos | 1–3 meses |
| R4 | Experimental: I+D, nueva superficie de producto o dependencia difícil de controlar | Más de 3 meses o sin estimación fiable |

El realismo no sustituye a la facilidad: una funcionalidad puede ser fácil de prototipar, pero poco
realista de operar de forma segura.

## 5. Tabla maestra priorizada

| # | ID | Categoría | Iniciativa | I | F | Valor | R | Fase |
|---:|---|---|---|---:|---:|---:|---|---|
| 1 | B03 | Bug | Marcar `failed` cuando falla el parser después de crear el análisis | 5 | 4 | 20 | R1 | 0 |
| 2 | B04 | Bug | Reconciliación correcta de jobs `running` | 5 | 4 | 20 | R1 | 0 |
| 3 | B05 | Hardening | Fallo de regla visible y modo `degraded`, no fail-open silencioso | 5 | 4 | 20 | R1 | 0 |
| 4 | B11 | Bug | Nombre de PDF único por documento | 4 | 5 | 20 | R1 | 0 |
| 5 | B12 | Bug | Cursor Graph como `Text` y validación de tokens opacos | 4 | 5 | 20 | R1 | 0 |
| 6 | B13 | Bug | Alinear límite de tamaño frontend/backend | 4 | 5 | 20 | R1 | 0 |
| 7 | M06 | Mejora | Public Suffix List y confusables IDN completos | 4 | 4 | 16 | R1 | 3 |
| 8 | M07 | Mejora | Modo mensaje completo visible y coherente en la UI | 4 | 4 | 16 | R1 | 2 |
| 9 | M10 | Mejora | Salud, métricas y observabilidad de mailbox | 4 | 4 | 16 | R2 | 1 |
| 10 | F16 | Funcionalidad | Simulador de reglas y replay de corpus | 4 | 4 | 16 | R2 | 2 |
| 11 | B01 | Bug | Checkpoint de ingesta por mensaje, no solo por lote | 5 | 3 | 15 | R1 | 1 |
| 12 | B02 | Bug | Lock distribuido por conexión y deduplicación de sync | 5 | 3 | 15 | R1 | 1 |
| 13 | B06 | Hardening | Trust boundary real para `Authentication-Results` y ARC | 5 | 3 | 15 | R1 | 0 |
| 14 | B10 | Bug | Registrar `iris.ai_summary`, evitar duplicados y reembolsar cuota | 3 | 5 | 15 | R1 | 0 |
| 15 | B14 | Bug | Alinear permisos reales con el contrato publicado | 3 | 5 | 15 | R1 | 0 |
| 16 | M01 | Mejora | Evidencia anclada a cabeceras, MIME, body y adjuntos | 5 | 3 | 15 | R2 | 2 |
| 17 | M02 | Mejora | Confianza, incertidumbre y estado degradado en el veredicto | 5 | 3 | 15 | R2 | 2 |
| 18 | M03 | Mejora | Políticas de confianza por usuario, organización y proveedor | 5 | 3 | 15 | R2 | 2 |
| 19 | M04 | Mejora | Feedback de analista y corpus de falsos positivos | 5 | 3 | 15 | R2 | 2 |
| 20 | B07 | Bug | Transiciones de estado atómicas frente a cancelación concurrente | 4 | 3 | 12 | R1 | 1 |
| 21 | B09 | Bug | Consumo de cuota atómico e idempotencia antes de cobrar | 4 | 3 | 12 | R1 | 1 |
| 22 | B15 | Bug | Persistir el contexto ganador de forwards MIME | 4 | 3 | 12 | R1 | 2 |
| 23 | B16 | Hardening | Validación de `folder` específica por proveedor | 3 | 4 | 12 | R1 | 1 |
| 24 | B17 | Arquitectura | Índices, paginación y retención para crecimiento sostenido | 4 | 3 | 12 | R2 | 1 |
| 25 | M08 | Mejora | Preferencias de notificación, digest y severidad | 4 | 3 | 12 | R1 | 1 |
| 26 | M09 | Privacidad | Retención, redacción y almacenamiento por capas | 4 | 3 | 12 | R2 | 1 |
| 27 | M11 | Mejora | Metadatos MITRE ATT&CK y taxonomía estable de findings | 3 | 4 | 12 | R1 | 3 |
| 28 | M12 | Mejora | Historial de triage: filtros guardados, etiquetas y navegación rápida | 4 | 3 | 12 | R1 | 2 |
| 29 | F02 | Funcionalidad | Clustering y vista de campañas | 4 | 3 | 12 | R2 | 4 |
| 30 | F03 | Funcionalidad | Análisis por lotes y bandeja de triaje | 4 | 3 | 12 | R2 | 2 |
| 31 | F04 | Funcionalidad | Soporte `.msg` de Outlook | 4 | 3 | 12 | R2 | 3 |
| 32 | F05 | Funcionalidad | Inspección profunda de PDF, OOXML y HTML | 4 | 3 | 12 | R2 | 3 |
| 33 | F18 | Funcionalidad | Grafo de relación remitente-destinatario | 4 | 3 | 12 | R2 | 4 |
| 34 | B08 | Arquitectura | Outbox fiable entre PostgreSQL y TaskQueue | 5 | 2 | 10 | R2 | 1 |
| 35 | M05 | Mejora | Score versionado, calibración y perfiles de sensibilidad | 5 | 2 | 10 | R2 | 2 |
| 36 | F01 | Funcionalidad | Casos de analista con asignación, notas y ciclo de vida | 5 | 2 | 10 | R2 | 2 |
| 37 | F12 | Funcionalidad | Cuarentena y remediación segura en Gmail/Graph | 5 | 2 | 10 | R3 | 5 |
| 38 | F14 | Funcionalidad | Ingesta orientada a eventos y sincronización casi en tiempo real | 5 | 2 | 10 | R3 | 5 |
| 39 | B18 | Bug | Invalidar cachés de datasets al recargar configuración | 3 | 3 | 9 | R1 | 0 |
| 40 | F10 | Funcionalidad | Exportación estable STIX 2.1, MISP y JSON | 3 | 3 | 9 | R2 | 4 |
| 41 | F17 | Funcionalidad | Inteligencia de tenant y campañas entre usuarios autorizados | 4 | 2 | 8 | R3 | 4 |
| 42 | B19 | Privacidad | Reducir scopes y separar raw email de resultados | 4 | 2 | 8 | R2 | 1 |
| 43 | B20 | Calidad | Suite PostgreSQL y pruebas reales de concurrencia | 4 | 2 | 8 | R2 | 0 |
| 44 | F06 | Funcionalidad | OCR de imágenes y texto visual de phishing | 4 | 2 | 8 | R2 | 3 |
| 45 | F07 | Funcionalidad | Expansión segura de URLs, redirects y captura visual | 4 | 2 | 8 | R3 | 4 |
| 46 | F08 | Funcionalidad | RDAP, edad de dominio, ASN y contexto de infraestructura | 4 | 2 | 8 | R3 | 4 |
| 47 | F09 | Funcionalidad | Threat intelligence externa con caché y degradación | 4 | 2 | 8 | R3 | 4 |
| 48 | F11 | Funcionalidad | Webhooks, SIEM y SOAR | 4 | 2 | 8 | R3 | 5 |
| 49 | F13 | Funcionalidad | Botón de reportar phishing, add-in y extensión | 4 | 2 | 8 | R3 | 5 |
| 50 | F15 | Funcionalidad | Shared mailboxes, IMAP y cuentas de servicio | 3 | 2 | 6 | R3 | 5 |
| 51 | X02 | Estratégica | Clasificación semántica multilingüe con LLM controlado | 4 | 2 | 8 | R3 | 6 |
| 52 | X01 | Estratégica | Modelo híbrido de comportamiento y aprendizaje supervisado | 5 | 1 | 5 | R4 | 6 |
| 53 | X04 | Estratégica | Gateway inline MTA/API para prevención antes de entrega | 5 | 1 | 5 | R4 | 6 |
| 54 | X03 | Estratégica | Sandbox de detonación de adjuntos y enlaces | 4 | 1 | 4 | R4 | 6 |
| 55 | X07 | Estratégica | Copiloto SOC con acciones aprobables y auditadas | 4 | 1 | 4 | R4 | 6 |
| 56 | X05 | Estratégica | Despliegue offline, privacidad avanzada y federación | 3 | 1 | 3 | R4 | 6 |
| 57 | X06 | Estratégica | Bucle Iris → Aegis para simulación y aprendizaje | 3 | 1 | 3 | R4 | 6 |
| 58 | X08 | Estratégica | Extensión a mensajes de Teams, Slack y SMS | 3 | 1 | 3 | R4 | 6 |

Los ítems X02–X08 aparecen después de iniciativas con menor puntuación matemática porque
pertenecen a una fase de I+D y no deben adelantar el trabajo de fiabilidad del producto.

## 6. Mapa exacto de implementación

Esta sección convierte cada iniciativa en una primera lista de trabajo para el implementador.
Las rutas son relativas a la raíz del repositorio. Las funciones y clases son más importantes que
los números de línea, porque estos cambiarán al aplicar las fases. “Nuevos” identifica ficheros,
modelos, endpoints o migraciones que todavía no existen y que deben crearse en vez de forzar la
lógica dentro de un fichero que no corresponde.

Para mantener las tablas legibles, `analysis.py`, `mailbox.py`, `reports.py`, `model.py`,
`schemas.py`, `repositories.py` y `services/...` sin prefijo significan
`API/src/modules/features/iris/<ruta>`. `shared/_documents.py` significa
`API/src/modules/shared/_documents.py`; los tests sin prefijo significan
`API/tests/<tipo>/`. Cuando la ruta no existe todavía, se marca como “nuevo”.

### 6.1 Bugs y hardening

| ID | Punto exacto de cambio | Nuevos artefactos | Tests que deben cambiar o añadirse |
|---|---|---|---|
| B01 | `API/src/modules/features/iris/managers/mailbox.py`: `IrisMailboxManager._sync_connection()`, `_ingest_message()`, `_finish_sync()` | `model.py`: `IrisMailboxInbox`/dead-letter; repositorio; migración `add_iris_mailbox_inbox` | `API/tests/integration/test_iris_mailbox_manager.py` y `test_iris_mailbox_model.py`: cuota, fallo intermedio, reintento y dedupe |
| B02 | `mailbox.py`: `trigger_sync()`, `submit_sync()`, `execute_sync_connection()`, `_sync_connection()`; `services/mailbox/scheduling.py::_poll_connections()` | `services/mailbox/locks.py` con Redis `SET NX EX`; `sync_started_at` y `sync_job_id` en `IrisMailboxConnection`; migración | `test_iris_mailbox_manager.py` y `test_iris_mailbox_endpoints.py`: sync concurrente, lock huérfano y expiración |
| B03 | `API/src/modules/features/iris/managers/analysis.py::_run_analysis()` (`:665-755`): envolver parseo, validación y evaluación en el mismo manejador que llama a `_fail_analysis()` | Opcionales `failure_reason`/`failure_code` en `IrisAnalysis`; migración y campos en `AnalysisDetailResponseSchema` | Test unitario con `parse_raw_message` roto; integración que confirme `failed`, `finishedAt` y razón no sensible |
| B04 | `analysis.py::reconcile_orphaned_analyses()` (`:1177-1201`); `API/src/modules/system/taskqueue/queue.py` para exponer si el job sigue recuperable | Helper público `TaskQueue.is_recoverable()` si hace falta; sin migración | `API/tests/integration/test_iris_reconciliation.py`: estados `RUNNING`, worker muerto, job expirado y job desconocido |
| B05 | `analysis.py::_run_analysis()` bloque de captura de reglas (`:705-719`), `_persist_analysis_results()` y `get_analysis_results()` | Campos JSONB `failed_rules`, `analysis_quality`, `detector_version`; migración compartida con M02; UI/PDF/prompt IA | `test_iris_rules.py`, integración de análisis y `test_iris_reports.py`: fallo de auth, adjunto y contenido |
| B06 | `API/src/modules/features/iris/services/rules/auth_rules.py::check_auth_results_provenance()` (`:476-542`) y `check_arc_chain()` (`:390-456`); `analysis.py::_extract_verdict_signals()` (`:864-879`) | `services/auth_trust.py`; dataset `trusted_authserv_ids`; modelo de ocurrencias múltiples solo si se persiste | `test_iris_recalibration_rules.py`: `Received` inyectado, hop falso, ARC `cv=pass` falsificado y cabeceras duplicadas |
| B07 | `analysis.py::cancel_analysis()` (`:466-501`), `_persist_analysis_results()` (`:763-798`) y `_update_analysis()` (`:1158-1174`) | `IrisAnalysisRepository.transition_if_state()`; opcional `cancel_requested_at` y migración | Integración con barrera entre cancelación y persistencia |
| B08 | Todos los puntos create-then-enqueue: `analysis.py:163-179`, `reports.py:87-97`, `mailbox.py:301-311`, generación IA y notificaciones | En `API/src/modules/system/taskqueue/`: nuevo `outbox.py` (modelo/dispatcher), `outbox_repository.py` y dispatcher periódico; migración `add_task_dispatch_outbox` | Nuevo `API/tests/integration/test_taskqueue_outbox.py`: caída de Redis, retry y publicación idempotente |
| B09 | `analysis.py:150-166`; `IrisMailboxManager._ingest_message()`; `API/src/modules/accounts/services/quotas.py` | `QuotaManager.consume_many()`/release transaccional; `IrisAnalysisRepository.exists_by_source()` | `test_iris_mailbox_manager.py`, `test_iris_mailbox_model.py` y `API/tests/integration/test_quotas.py` |
| B10 | Registrar `iris.ai_summary` en `API/src/modules/features/iris/__init__.py`; modificar `analysis.py::generate_ai_summary()` | Campos `ai_summary_status`, `ai_summary_job_id`, `ai_summary_model`, `ai_summary_prompt_version`; migración `add_iris_ai_summary_state` | `test_iris_ai_writer.py` y nuevo test de doble POST, resultado existente, regeneración y cuota |
| B11 | `API/src/modules/features/iris/services/reports.py::IrisPDFCreator.print_pdf()` (`:681-711`); pasar `document_id` desde `managers/reports.py` | Ninguno; temporal + rename atómico | `test_iris_reports.py` y `API/tests/integration/test_iris_documents.py`: dos PDFs y borrado independiente |
| B12 | `API/src/modules/features/iris/model.py::IrisMailboxConnection.sync_cursor`; `services/mailbox/microsoft.py::GraphConnector.list_new()` | Migración `alter_iris_sync_cursor_to_text` | `API/tests/unit/test_iris_mailbox_connectors.py`: delta link >255, preservación exacta y `410 Gone` |
| B13 | Backend `API/src/modules/features/iris/schemas.py::AnalyzeRequestSchema.validate_max_size()` (`:34-50`); frontend `web/app/src/views/IrisView.vue` (`:111-180`) | `GET /iris/capabilities` y `IrisCapabilitiesResponseSchema`, compartidos con M07 | `API/tests/integration/test_iris.py` y test frontend de fichero 10–20 MiB |
| B14 | Decorators en `API/src/modules/features/iris/endpoints.py:235-267` y `:345-353`; contrato `README.md:233-249` | Ninguno | `API/tests/integration/test_iris.py`: solo `IRIS_CREATE`, `IRIS_UPDATE`, `IRIS_READ` para reanálisis, IA, PDF y mailbox |
| B15 | `analysis.py:684-747`, `get_analysis_results()`, `get_analysis_path()`, `get_analysis_iocs()`; `services/parsers.py:333-363` | `winning_context` en `IrisAnalysis`, `context_type` en `IrisRuleResult`; migración `add_iris_analysis_context_metadata` | `test_iris_message_parser.py`, `test_iris_rules.py`, `test_iris_reports.py`: wrapper peor y wrapper mejor |
| B16 | `schemas.py:336-372`; `mailbox.py::start_connect()/update_connection()`; `services/mailbox/base.py::MailboxConnector` | Campos `folder_provider_id`, `folder_display_name`, `folder_type`; `MailboxConnector.list_folders()`; endpoint `GET /iris/mailbox/connections/<id>/folders`; migración | Conectores Gmail/Graph, longitud, incompatibilidad y endpoint de carpetas |
| B17 | `model.py`, `repositories.py::get_by_user_paginated()`, `shared/_documents.py::DocumentManager`, `endpoints.py:404-459`; scheduler mailbox | Migración de índices; paginación de documentos; `services/retention.py` y job de limpieza | `test_iris_results_filtering.py`, `test_iris_documents.py`, dataset grande y purga idempotente |
| B18 | `API/src/modules/features/iris/services/wordlists.py:424-559`; `API/src/modules/system/config_reading.py:115-151` | Fingerprint/version de configuración o `invalidate_iris_dataset_caches()` | Test que modifica config, ejecuta `reload_if_changed()` y verifica marca, keyword, TLD y homoglyph |
| B19 | `services/mailbox/gmail.py`, `microsoft.py`; `model.py::IrisAnalysis.raw_headers`; `services/reports.py` | `IrisRawMessage`/almacenamiento cifrado; migración `split_iris_raw_message_storage`; política de borrado | Scopes OAuth, borrado raw/resultados, ownership y exportación |
| B20 | CI y fixtures, no un punto de negocio de Iris | `.github/workflows/tests-postgres.yml` o extensión de `tests.yml`; fixtures PostgreSQL/Redis | Migraciones JSONB, FKs, unique idempotency, cuotas, cancelación, locks, PDF y outbox |

### 6.2 Mejoras sobre capacidades existentes

| ID | Punto exacto de cambio | Nuevos artefactos | Tests que deben cambiar o añadirse |
|---|---|---|---|
| M01 | `API/src/modules/features/iris/services/registry.py::RuleResult`; decoradores de `services/rules/*.py`; `schemas.py::RuleResultSchema`; `web/app/src/components/iris/IrisRuleCard.vue`, `IrisReportViewer.vue`; `services/reports.py` | `services/evidence.py` para offsets, rangos y defanging | Unitarios por reglas; serialización; salto UI → raw y render PDF |
| M02 | `managers/analysis.py::_run_analysis()`, `_persist_analysis_results()`, `get_analysis_results()`; `schemas.py`; `IrisReportViewer.vue`; `IrisPDFCreator`; `IrisAIWriter` | `confidence`, `coverage`, `uncertainty_reasons`, `analysis_quality`; migración compartida con B05 | Headers-only/full-message, regla fallida, wrapper y resumen IA |
| M03 | Nuevo CRUD junto a `endpoints.py`, `managers/`, `repositories.py` e integración en `analysis.py` antes de gates | `IrisTrustedSender` en `model.py`; migración `add_iris_trusted_senders`; endpoints `/iris/trusted-senders` | Nuevo `test_iris_trusted_senders.py`: ownership, expiración, auditoría y gates duros |
| M04 | Nuevo `POST /iris/results/<id>/feedback`; manager/repository; `web/app/src/components/iris/IrisReportViewer.vue` | Preferible `IrisAnalystFeedback` y migración `add_iris_analyst_feedback`; corpus bajo `API/tests/fixtures/iris/` | Nuevo test de autores, permisos, notas y no mutación del veredicto |
| M05 | `analysis.py::_aggregate_score()`, `_determine_verdict()`, `_persist_analysis_results()`; `config_reading.py::get_iris_scoring_weight()`; `services/registry.py::RuleRegistry` | Snapshot de pesos/floors/umbrales/datasets; `services/replay.py`; migración de versión | `test_iris_fp_regression.py`, replay de dos versiones y rollback |
| M06 | `services/text.py::registrable_domain()`, `registrable_label()`, `normalize_homoglyphs()`; reglas de identidad, reply-path y URL | Dependencia PSL en `API/requirements.txt`; tabla Unicode controlada si procede | `test_iris_rules.py`, `test_iris_new_rules.py`, `test_iris_fp_regression.py` |
| M07 | `web/app/src/components/iris/IrisForm.vue`, `IrisView.vue`, `stores/irisStore.js`; backend `AnalyzeRequestSchema` | `GET /iris/capabilities` y schema, compartidos con B13 | Integración de tamaños/modos y test de cobertura/advertencia de sensibilidad |
| M08 | `managers/notifications.py::IrisPhishingNotifyManager`; scheduler nuevo; endpoints Iris | `IrisNotificationPreference`; `services/notifications/scheduling.py`; migración; `GET/PUT /iris/notification-preferences` | Extender `test_iris_notifications.py`: digest, mute, reauth y sync detenido |
| M09 | `model.py`, `services/reports.py`, `shared/_documents.py`, flujo de eliminación de cuenta | `services/storage.py`, `services/redaction.py`, job de retención; migración raw/adjuntos/PDF | Retención, redacción, borrado de cuenta y descarga post-purga |
| M10 | `managers/mailbox.py::_sync_connection()`, `_finish_sync()`, `_record_sync_error()`; `services/mailbox/scheduling.py`; `IrisMailboxConnection` | Contadores y timestamps; `GET /iris/mailbox/connections/<id>/health`; migración | Manager/endpoints/TaskQueue: sin correo frente a proveedor caído y reauth |
| M11 | `services/registry.py::RuleRegistry.register()`; 46 decoradores; `model.py::IrisRuleResult`; schemas, PDF y exportadores | `rule_id`, `severity`, `mitre_techniques`; migración `add_iris_rule_taxonomy` | Registro estable, serialización, PDF y nombres traducidos |
| M12 | `repositories.py::get_by_user_paginated()`, `ResultsQuerySchema`, `IrisArchiveModal.vue`, `irisStore.js` | `IrisSavedView`, `IrisAnalysisTag`; migración; endpoints `/iris/triage/views` y `/iris/tags` | `test_iris_results_filtering.py`: vistas, IOC, teclado y comparación |

### 6.3 Funcionalidades nuevas

| ID | Punto exacto de cambio | Nuevos artefactos | Tests que deben cambiar o añadirse |
|---|---|---|---|
| F01 | Nuevos managers/repositories/endpoints de casos; vínculo con `IrisAnalysis` desde `endpoints.py` | `IrisCase`, `IrisCaseAnalysis`, `IrisCaseNote`, timeline; migración `add_iris_cases` | Nuevo `API/tests/integration/test_iris_cases.py`: lifecycle, ownership, assignment y varios análisis |
| F02 | Poblar desde `analysis.py::_persist_analysis_results()` mediante `services/campaigns.py`; nuevos endpoints `/iris/campaigns` | `IrisIndicator`, `IrisCampaign` y asociaciones; migración `add_iris_indicators_campaigns` | Nuevo `test_iris_campaigns.py`: similitud, ventana temporal y aislamiento |
| F03 | Nuevo `POST /iris/analyze/batch`, schemas de lote y `services/batch.py`; cada elemento llama a `IrisManager.analyze()` | Opcional `IrisBatch`/`IrisBatchItem`; migración para progreso | Nuevo `test_iris_batch.py`: ZIP, límites, duplicados, backpressure y errores parciales; `IrisForm.vue`/`IrisView.vue` |
| F04 | Nuevo `services/msg_converter.py` antes de `parse_raw_message()`; nuevo upload multipart | Dependencia `extract-msg`; `POST /iris/analyze/upload` o extensión explícita del endpoint actual | `test_iris_msg_converter.py` e integración upload |
| F05 | `services/attachment_inspectors/` y `services/rules/attachment_media_rules.py::check_suspicious_attachments()` | `pdf.py`, `ooxml.py`, `html.py`, `zip.py`; límites en config | Nuevo `test_iris_attachment_inspectors.py`: JavaScript/OpenAction, VBA/DDE, smuggling y ZIP bombs |
| F06 | Nuevo `services/ocr.py`; ampliar `MessageContext`/`Attachment`; nueva regla en `body_content_rules.py` | Dependencia OCR, configuración de idioma/límites y evidencia OCR | OCR mockeado, píxeles máximos, texto de login, imagen sin texto y QR |
| F07 | Nuevo `services/enrichment/url_expander.py`; endpoint bajo demanda, nunca dentro de `check_body_links()` por defecto | Cache `IrisUrlExpansion`; migración; `GET/POST /iris/results/<id>/url-expansions` | Redirects, DNS rebinding, IP privada, protocolos y timeout |
| F08 | Nuevo `services/enrichment/rdap.py`; endpoint `GET /iris/domains/<domain>/context`; job opcional | `IrisDomainCache`; migración y categoría `iris.enrichment` si es asíncrono | TTL, rate limit, dominio nuevo legítimo y proveedor caído |
| F09 | Nuevo `services/enrichment/threat_intel/` con adaptadores; endpoint de enriquecimiento | `IrisThreatIntelResult`; cache y migración | Mocks VT/urlscan/PhishTank/URLhaus, cache, cuota y no exfiltración |
| F10 | `services/exporters/stix.py`, `misp.py`, `json.py`; endpoint `GET/POST /iris/results/<id>/export` | Esquema de exportación versionado; extender `IrisIocsResponseSchema` | Nuevo `test_iris_exports.py`: validación, defanging, fuente, confianza y timestamps |
| F11 | Emisión desde `_persist_analysis_results()`, casos, campañas y mailbox; integración con TaskQueue | `IrisWebhookSubscription`, auditoría y MIG; categoría `iris.webhook` | Firma, retry/backoff, dedupe, replay y auto-desactivación |
| F12 | Extender `services/mailbox/base.py::MailboxConnector` con `move`, `label`, `report_phishing`, `delete`; implementar en Gmail/Graph | `IrisActionAudit`; migración; `/iris/mailbox/messages/<id>/actions`; atributo de permiso específico si procede | Conectores, confirmación destructiva, rollback, auditoría y ownership |
| F13 | Reutilizar `POST /iris/analyze/upload` y `IrisManager.analyze()`; contrato de reenvío contextual | Tokens de integración separados y documentación para add-in/extensión | Upload MIME, wrapper, ownership y preservación del contexto |
| F14 | `services/mailbox/scheduling.py` como fallback; módulos Gmail Watch y Graph change notifications | Suscripciones/renovación persistentes; endpoints públicos firmados; migración; categoría `iris.ingest` reutilizada | Renovación, firma, replay, backpressure y fallback a polling |
| F15 | Nuevos `services/mailbox/imap.py` y adapter service-account; cambios en `MailboxConnector`, `IrisMailboxManager` y ABAC | Campos tenant/actor/ownership y migración | Shared mailbox, scopes, rotación, reauth, carpetas múltiples y aislamiento |
| F16 | Reutilizar `services/replay.py` y `iris_rules.get_rules()`; endpoint admin-only `/iris/admin/replay`; vista de administración | Schemas de replay y diff; permisos admin | Corpus sintético, gates modificados, fallo de regla y permisos |
| F17 | Resolver organización desde `User`; repositorios con scope tenant y servicios de F02/F18 | `IrisTenantProfile`, dominios/contactos/marcas protegidas, consentimiento y migración | Dos tenants aislados, anonimización y miembros autorizados |
| F18 | Construir aristas desde `From`, `To`, `Cc`, `Reply-To` en `_persist_analysis_results()`; nuevo `services/graph.py` | `IrisCommunicationEdge`, índices y retención corta; migración; endpoint de grafo | Contacto habitual, desviación de dominio, retención y aislamiento |

### 6.4 Iniciativas estratégicas

| ID | Punto exacto de cambio | Nuevos artefactos | Tests y condición de entrada |
|---|---|---|---|
| X01 | Nuevo `services/ml/feature_extraction.py` e `inference.py`; integrar después de `_aggregate_score()` sin eliminar reglas | Snapshot/model score y migración solo cuando el prototipo sea estable; artefactos de entrenamiento fuera de `API/src/data` | Replay temporal, drift, ablation, modo sin ML y rollback; requiere M04/M05/F17/F18 |
| X02 | Nuevo `services/ai_intent.py`, reutilizando scribe pero no sobrecargando `IrisAIWriter.generate()` | Prompt `features.iris.prompts.intent`, categoría `iris.ai_intent`, estado/modelo y migración si persiste | Salida estructurada, prompt injection, cache, coste, idioma y backend caído |
| X03 | Nuevo `services/sandbox/client.py`; nunca ejecutar en workers Iris actuales | `IrisSandboxExecution`, resultados, auditoría y migración; categoría `iris.sandbox` | Fake sandbox, timeout, egress, cleanup y respuesta maliciosa; requiere F05/F07/B19 |
| X04 | No tiene un punto válido dentro de `features/iris`; requiere adaptador MTA/API externo | Probable `API/src/modules/gateway/` o servicio separado, contratos de ingestión y F12 | Latencia, fail-open/fail-closed, idempotencia y compatibilidad; decisión de producto previa |
| X05 | Transversal: `services/storage.py`, `shared/_crypto.py`, configuración Docker, scribe local y pipelines de features | Perfiles de despliegue, claves por tenant, feed local y protocolo de federación | Instalación sin egress, rotación, restauración y no salida de raw; no hay punto Iris único |
| X06 | Nuevo `services/training_patterns.py` y contrato explícito con Aegis, nunca import circular Iris→Aegis | `IrisTrainingPattern`, aprobación y migración; job `iris.training` si procede | PII no sale, anonimización, aprobación humana y contenido sintético; requiere M04/M09/F17 |
| X07 | Nuevo `services/copilot.py`, basado solo en `IrisCase`/findings persistidos; primera versión read-only | Propuestas de acción, aprobación y auditoría reutilizando `IrisActionAudit` | Prompt injection, grounding, permisos, aprobación/rechazo; requiere F01/F10/F12 |
| X08 | Nuevo adaptador que produzca `MessageContext` canónico o módulo `features/messaging`; no tocar `parse_raw_message()` con reglas de cada canal | Conectores, identidad, políticas y endpoints propios | Contrato por canal, Unicode, URLs, adjuntos y privacidad; tratar como producto hermano |

### 6.5 Reglas para interpretar el mapa

- Una ruta existente indica el punto de integración, no permiso para añadir toda la funcionalidad a
  ese fichero. Si aparece un servicio nuevo, la lógica debe vivir allí y el manager solo debe
  orquestarla.
- Toda migración nueva debe ser lineal, reversible cuando sea razonable y acompañarse de un test
  contra PostgreSQL.
- Todo endpoint nuevo debe pasar por `endpoints.py` para auth/schema/limitación, por un manager
  para negocio y por un repository para acceso a datos.
- Las reglas deben seguir registrándose en `services/rules/` por familia; no crear imports entre
  reglas para reutilizar helpers.
- La UI debe tocar `irisStore.js` para estado remoto y los componentes Iris para presentación; no
  duplicar llamadas API dentro de cada vista.
- Los números de línea del documento son referencias de auditoría; los símbolos
  (`IrisManager._run_analysis`, `GraphConnector.list_new`, etc.) son el ancla estable.

## 7. Iniciativas detalladas por categoría

### 7.1 Bugs y corrección de comportamiento

#### B01 — Checkpoint de ingesta por mensaje

**Diagnóstico.** `IrisMailboxManager._sync_connection()` obtiene `new_cursor`, procesa un lote y
lo guarda siempre en `_finish_sync()` (`managers/mailbox.py:335-363`). Si se alcanza la cuota,
falla el encolado o falla un mensaje individual, el cursor puede avanzar más allá de mensajes que
nunca llegaron a analizarse.

**Intervención.** No confirmar el cursor del proveedor hasta que cada referencia anterior esté
aceptada por Iris. Alternativas válidas, a decidir por proveedor:

- Guardar `cursor_before`, `cursor_after` y una cola de referencias pendientes.
- Confirmar por página o por mensaje cuando el conector lo permita.
- Crear una tabla `IrisMailboxInbox`/dead-letter para referencias fallidas, con reintentos y
  motivo visible.

**Cierre.** Un test simula cuota agotada y fallo transitorio en el segundo mensaje; el siguiente
sync vuelve a ver el mensaje no procesado y nunca duplica el primero.

#### B02 — Lock distribuido por conexión

**Diagnóstico.** El scheduler puede volver a encolar una conexión mientras el sync manual o el
sync anterior sigue vivo (`services/mailbox/scheduling.py`, `managers/mailbox.py:296-317`). El
`external_id` ayuda a identificar el job, pero no constituye por sí solo un lock de ejecución.

**Intervención.** Adquirir en Redis un lock `iris:mailbox-sync:<connection_id>` con TTL renovable,
liberarlo en `finally` y devolver una respuesta idempotente cuando ya exista un sync en curso.
Persistir `sync_started_at` y `sync_job_id` para que la UI no dependa de adivinarlo.

**Cierre.** Dos llamadas simultáneas producen un único sync efectivo; un lock huérfano expira y
permite continuar; una conexión pausada no procesa trabajo ya adquirido.

#### B03 — Parser que deja análisis en `running`

**Diagnóstico.** El parseo y `_validate_headers_parsed()` están fuera del bloque que llama a
`_fail_analysis()` (`managers/analysis.py:675-683`). Una excepción en esa ventana puede dejar la
fila en `running` aunque RQ marque el job como fallido.

**Intervención.** Encapsular parseo, validación y evaluación en un único manejador de ciclo de
vida. Distinguir `invalid_input` de `internal_error`, persistir un mensaje técnico no sensible y
terminar siempre en estado terminal.

**Cierre.** Parser roto, entrada inválida y error inesperado dejan respectivamente estados
`failed`/`invalid` definidos, `finished_at` y una razón consultable sin filtrar el raw email.

#### B04 — Reconciliación de tareas `running`

**Diagnóstico.** La reconciliación conserva una tarea solo si su estado es exactamente `pending`
(`managers/analysis.py:1177-1201`). Un job RQ `running` puede estar trabajando en otro proceso y
ser marcado erróneamente como fallido.

**Intervención.** Modelar explícitamente `pending`, `started/running`, `finished/completed`,
`failed`, `cancelled` y `unknown`. Solo marcar huérfano tras comprobar heartbeat/TTL o un job
definitivamente perdido. El worker debe reclamar la fila con una transición condicional.

**Cierre.** Un test deja una tarea `running` durante la reconciliación y confirma que no se toca;
otro simula un job expirado y confirma que sí se recupera.

#### B05 — Fallos de reglas fail-open

**Diagnóstico.** Una excepción de regla se convierte en `RuleResult(score=0, verdict="error")`
(`managers/analysis.py:705-719`) y el análisis puede terminar como `Legitimate` sin advertencia
global.

**Intervención.** Mantener disponibilidad, pero añadir `analysis_quality=complete|degraded`,
`failed_rules`, `detector_version` y una advertencia en API/UI/PDF. Un análisis degradado no debe
poder presentarse como “limpio” sin contexto; definir si baja el techo, impide `Legitimate` o
requiere revisión según la familia de la regla.

**Cierre.** Una regla de autenticación, una de adjuntos y una de contenido fallidas tienen tests
con comportamiento conservador y el frontend muestra la degradación.

#### B06 — Trust boundary de `Authentication-Results` y ARC

**Diagnóstico.** La provenance actual acepta que `authserv-id` coincida con cualquiera de los
dominios `by` de cualquier `Received` (`services/rules/auth_rules.py:511-526`). Los saltos inferiores
pueden ser aportados por el remitente. Además, `ARC cv=pass` se declara válido sin verificar la
firma y relaja gates SPF/DMARC/alignment (`auth_rules.py:390-456`, `analysis.py:864-878`).

**Intervención.** Separar hops potencialmente falsificables del último MTA receptor conocido;
usar una lista configurable de verificadores confiables por tenant/proveedor; tratar ARC no
verificado como contexto, nunca como permiso para suprimir señales fuertes. En una fase posterior,
ofrecer validación DNS/criptográfica real mediante librería aislada.

**Cierre.** Corpus con cabeceras duplicadas, `Received` inyectado y ARC falsificado; ningún
`Authentication-Results` del atacante convierte por sí solo un mensaje en autenticado.

#### B07 — Cancelación y finalización concurrentes

**Diagnóstico.** `cancel_analysis()` señaliza el job y actualiza la fila (`analysis.py:466-501`),
mientras el worker puede persistir `finished` después de su última comprobación.

**Intervención.** Usar transiciones SQL condicionadas: `running -> finished` solo si sigue
`running`, `pending/running -> cancelled` solo si no es terminal. Registrar `cancel_requested_at`
separado del estado efectivo.

**Cierre.** Una prueba con barrera entre cancelación y persistencia demuestra que nunca se pierde
la decisión final del usuario ni se escriben reglas parciales.

#### B08 — Outbox entre base de datos y TaskQueue

**Diagnóstico.** Iris hace commit del análisis antes de `TaskQueue.submit()` (`analysis.py:163-179`).
Si Redis o el submit fallan, queda una fila `pending` sin trabajo.

**Intervención.** Crear una outbox transaccional común o un reintento reconciliable: insertar
`TaskDispatch` en la misma transacción y tener un dispatcher idempotente que publique en RQ.
Aplicarlo primero a análisis e ingesta; después al PDF, IA y notificaciones.

**Cierre.** El API puede reiniciarse entre commit y publish sin perder el trabajo ni duplicarlo.

#### B09 — Cuotas e idempotencia

**Diagnóstico.** Se consume cuota antes de la constraint `(connection_id, source_message_uid)`
(`analysis.py:150-166`, `model.py:90-93`). La IA consume dos claves en transacciones separadas
(`analysis.py:432-436`). Un duplicado o un fallo intermedio puede cobrar uso no realizado.

**Intervención.** Añadir `QuotaManager.consume_many()` atómico y comprobar idempotencia antes de
consumir. Si la constraint sigue siendo la defensa final, reembolsar de forma transaccional la
cuota cuando el insert sea un duplicado esperado.

**Cierre.** Reintentos de Gmail/Graph, doble clic en IA y fallo del segundo contador dejan el
consumo exactamente en el número de operaciones reales.

#### B10 — Categoría y duplicación de resúmenes IA

**Diagnóstico.** Se encola `iris.ai_summary`, pero `__init__.py` registra solo `iris.analyze`,
`iris.report`, `iris.ingest` e `iris.notify`. Además, dos peticiones pueden consumir cuota y
encolar dos resúmenes del mismo análisis.

**Intervención.** Registrar la cola, hacer el endpoint idempotente por `analysis_id`, guardar
`ai_summary_status`, `ai_summary_job_id` y versión del prompt/modelo. Decidir si repetir implica
regenerar explícitamente o devolver el resultado existente.

**Cierre.** El job aparece en su cola nominal, dos peticiones concurrentes producen un solo job y
el usuario puede solicitar regeneración de forma explícita.

#### B11 — Colisión de PDFs

**Diagnóstico.** Todos los informes de un análisis escriben `<analysis_id>_Iris.pdf`
(`services/reports.py:681-687`) aunque el modelo permite múltiples `IrisDocument`.

**Intervención.** Usar `document_id` o UUID en el path y en el nombre descargable. Generar en un
fichero temporal y hacer rename atómico. El endpoint de descarga debe usar el nombre del documento,
no solo el analysis id.

**Cierre.** Dos PDFs concurrentes del mismo análisis son descargables, independientes y no se
destruyen al eliminar uno.

#### B12 — Cursor de Microsoft Graph demasiado corto

**Diagnóstico.** `sync_cursor` es `String(255)` (`model.py:156-159`), pero Graph devuelve un
`@odata.deltaLink` opaco que puede superar esa longitud (`services/mailbox/microsoft.py:99-141`).

**Intervención.** Migrar a `Text`, validar que el cursor es opaco y no truncarlo ni interpretarlo.
Añadir prueba con un delta link largo y con expiración `410 Gone`.

**Cierre.** Se guarda y reutiliza un delta link largo exactamente, y un cursor expirado reinicia
el bootstrap sin perder el estado local.

#### B13 — Límite de tamaño contradictorio

**Diagnóstico.** El backend valida `maxMessageBytes` en `schemas.py:34-50`, actualmente 10 MiB,
mientras la UI permite hasta 20 MiB antes de cambiar de modo (`IrisView.vue`). El usuario puede
subir un fichero que la interfaz considera válido y recibir un rechazo posterior.

**Intervención.** Obtener el límite desde una respuesta de capacidades de Iris o compartir una
constante generada. Mostrar el mismo umbral, ofrecer “solo cabeceras” de forma explícita y evitar
cargar el fichero completo en memoria cuando no procede.

**Cierre.** La misma entrada obtiene la misma decisión en UI y API, con mensaje accionable.

#### B14 — Permisos publicados y reales

**Diagnóstico.** `README.md` documenta `IRIS_UPDATE` para reanálisis, resumen IA y PDF, pero
`endpoints.py:235-266` y `345-353` exigen `IRIS_CREATE`.

**Intervención.** Elegir la semántica correcta, aplicarla al código, schemas/documentación y
tests de ABAC. Repetir la revisión para todas las operaciones de mailbox y documentos.

**Cierre.** Un usuario con el permiso documentado recibe el resultado documentado y un usuario sin
él obtiene 403 sin revelar existencia ni contenido.

#### B15 — Contexto incoherente en forwards MIME

**Diagnóstico.** El motor evalúa wrapper e interno y se queda con el peor veredicto
(`analysis.py:739-747`), pero el informe reparsea y describe principalmente el mensaje interno
(`analysis.py:264-280`). Puede persistir score de un contexto y evidencia visual de otro.

**Intervención.** Persistir `winning_context=inner|wrapper`, resultados separados por contexto y
una explicación de por qué ganó. El informe debe mostrar siempre el contexto que produjo el
veredicto y mantener el otro como contexto secundario.

**Cierre.** Un test con wrapper malicioso e interno benigno, y el inverso, mantiene alineados
veredicto, score, reglas, IOCs, preview y PDF.

#### B16 — Contrato de carpeta por proveedor

**Diagnóstico.** `folder` es un `String` sin límites ni semántica (`schemas.py:336-371`), aunque
Gmail usa label y Graph usa id/nombre de folder.

**Intervención.** Modelar `folder_type`, `folder_provider_id`, `folder_display_name` y validarlo
con el conector. Exponer una lista de carpetas autorizadas tras OAuth en lugar de aceptar texto
arbitrario.

**Cierre.** Una conexión no puede guardar un folder inválido, excesivamente largo o incompatible
con el proveedor.

#### B17 — Crecimiento de consultas y almacenamiento

**Diagnóstico.** Faltan índices específicos para usuario, fecha, estado, veredicto, conexión y
resultados de regla. Los listados de documentos devuelven todo (`endpoints.py:404-459`) y no hay
retención configurable.

**Intervención.** Añadir índices y paginación cursor-based. Definir retención independiente para
raw email, análisis, reglas, IOCs y PDFs; añadir job de limpieza y métricas de espacio.

**Cierre.** Un dataset sintético grande mantiene tiempos de consulta aceptables y elimina datos
según la política sin dejar documentos huérfanos.

#### B18 — Cachés de datasets no invalidadas

**Diagnóstico.** La recarga de configuración sustituye `_configs`, pero caches permanentes de
`wordlists.py` pueden conservar marcas, proveedores, keywords o TLDs antiguos.

**Intervención.** Asociar cada cache al `config_version`/mtime, invalidarla desde un único hook o
eliminar la cache si no es necesaria. Registrar qué versión de datasets usó cada análisis.

**Cierre.** Un cambio de marca o keyword mediante configuración afecta al siguiente análisis sin
reiniciar y no cambia retroactivamente los informes existentes.

### 7.2 Hardening, calidad y privacidad

#### B19 — Scopes y minimización de datos

**Diagnóstico.** Graph necesita `Mail.Read` aunque Iris pueda trabajar en modo cabeceras
(`services/mailbox/microsoft.py:7-15`, `:68`). El raw completo vive en la misma fila que el
resultado.

**Intervención.** Usar el menor scope viable por proveedor, documentar la diferencia inevitable de
Graph y separar raw cifrado/objeto del resultado analítico. Añadir borrado seguro, exportación y
auditoría de acceso.

**Cierre.** El usuario entiende qué concede, el resultado puede conservarse sin el raw y una
política de retención elimina ambos en el orden correcto.

#### B20 — Pruebas PostgreSQL y concurrencia

**Diagnóstico.** La suite usa principalmente SQLite y mocks; no reproduce bien FKs, JSONB,
constraints y carreras reales.

**Intervención.** Añadir un job de CI con PostgreSQL y Redis efímeros para mailbox, cuotas,
reconciliación, documentos y cancelación. Mantener los tests unitarios rápidos y reservar la
matriz de servicios para integración.

**Cierre.** Las invariantes de producción tienen al menos un test contra los motores reales.

### 7.3 Mejoras sobre capacidades existentes

#### M01 — Evidencia anclada

Cada regla debe devolver referencias estructuradas como `evidence_headers`, rangos del body,
partes MIME, adjuntos y URLs. La UI debe saltar desde “Display Name Spoofing” a la cabecera exacta
y el PDF debe mostrar un extracto defanged. Esto evita que el analista tenga que reconstruir la
decisión leyendo 40 reglas.

**Touchpoints:** `RuleResult.details`, decorador de reglas, `schemas.py`, `IrisReportViewer.vue`,
`services/reports.py`.

**Cierre:** las diez señales con mayor peso tienen evidencia clicable y todos los demás findings
declaran cuando no pueden anclarse.

#### M02 — Confianza e incertidumbre

El score actual es una escala de riesgo, no una probabilidad. Añadir `confidence`,
`analysis_quality`, `coverage` y `uncertainty_reasons` evita que un 92/100 se interprete como 92 %
de certeza. Mostrar “Legitimate con cobertura parcial” cuando faltan cuerpo, adjuntos o reglas.

**Cierre:** la API, la UI, el PDF y el resumen IA usan la misma semántica y no presentan confianza
numérica sin calibración estadística.

#### M03 — Políticas de confianza configurables

Crear entidades para remitentes, dominios, usuarios y proveedores confiables por usuario/tenant,
con fecha de caducidad, motivo, creador y alcance. Una allowlist nunca debe desactivar gates de
adjuntos ejecutables, URLs cloaked o autenticación forjada; solo debe modular las señales que
realmente cubre.

**Cierre:** el analista puede reducir un falso positivo sin crear un bypass global y toda
excepción aparece en la auditoría.

#### M04 — Feedback del analista

Añadir `legitimate|malicious|unknown`, nota, autor y timestamp. El feedback debe afectar a
calibración y reporting, no cambiar retroactivamente el veredicto original. Crear un corpus
versionado con muestras anonimizadas o referencias hash.

**Cierre:** un analista puede corregir un resultado en dos clics y el sistema puede medir precisión,
recall, cobertura y tasa de desacuerdo por familia.

#### M05 — Score versionado y calibración

Guardar `ruleset_version`, pesos, floors, umbrales y datasets usados. Crear un replay offline para
comparar versiones sobre corpus legítimo/malicioso y perfiles `strict|balanced|lenient`. No
permitir editar pesos en producción sin regresión y rollback.

**Cierre:** se puede responder qué habría decidido Iris con otra versión y desplegar una
recalibración con métricas de falso positivo/falso negativo.

#### M06 — Public Suffix List y confusables IDN

Sustituir la lista reducida de TLDs por Public Suffix List actualizable; normalizar IDNA y aplicar
la tabla completa de confusables Unicode con especial cuidado para no penalizar idiomas legítimos.
Separar “dominio internacionalizado válido” de “homoglyph sospechoso”.

**Cierre:** tests con `co.uk`, nuevos TLDs, punycode, cirílico y dominios multilingües no producen
regresiones en remitentes legítimos.

#### M07 — Mensaje completo visible y coherente

La UI debe permitir elegir cabeceras o `.eml` completo, enseñar qué reglas quedan sin cobertura en
modo cabeceras y avisar de que el modo completo puede incluir datos sensibles. El backend debe
devolver capacidades y límites, no obligar al navegador a inferirlos.

**Cierre:** el usuario entiende por qué un resultado no tiene body/adjuntos y puede cambiar de modo
sin recibir un error contradictorio.

#### M08 — Notificaciones útiles, no solo alarmas

Crear preferencias por conexión, severidad y canal; digest diario, agrupación por campaña,
silenciado temporal y notificación de `reauth_required`/sync detenido. Mantener una opción de
notificación inmediata para Phishing de alta confianza.

**Cierre:** el usuario puede controlar ruido, nunca pierde una incidencia crítica y puede saber si
el buzón lleva tiempo sin sincronizar.

#### M09 — Retención, redacción y almacenamiento por capas

Separar el resultado pequeño y consultable del raw MIME, adjuntos y PDFs. Cifrar por tenant o
usuario cuando el modelo de despliegue lo permita, redaccionar PII en vistas compartibles y
permitir conservar únicamente hashes/IOCs después del plazo operativo.

**Cierre:** existe una política visible, un job de retención idempotente y un informe de qué datos
se conservan y durante cuánto tiempo.

#### M10 — Salud y observabilidad de mailbox

Exponer `last_success`, latencia, mensajes descubiertos, aceptados, pendientes, fallidos,
reintentos, cuota, cursor y causa de reautenticación. Añadir métricas de cola, edad del mensaje más
antiguo y SLO de análisis.

**Cierre:** un administrador puede distinguir “no hay correo nuevo” de “Iris está roto” sin leer
logs del servidor.

#### M11 — Taxonomía y MITRE ATT&CK

Añadir identificador estable de regla, tactic/technique como metadato y severidad separada del
score. Por ejemplo, phishing por adjunto puede mapear a `T1566.001` y URL a `T1566.002`, sin
pretender que cada heurística sea una técnica independiente.

**Cierre:** el mismo finding puede usarse en PDF, API, dashboard y export sin depender del nombre
humano traducible de la regla.

#### M12 — Historial de triage

Añadir filtros guardados, etiquetas, búsqueda por IOC, teclado, comparación de análisis y vista de
“pendiente de revisar”. Es el puente entre la lista paginada existente y el caso de analista de
F01.

**Cierre:** un analista puede volver a una cola de trabajo sin reconstruir cada filtro y abrir dos
mensajes lado a lado.

### 7.4 Nuevas funcionalidades

#### F01 — Casos de analista

Crear `IrisCase` con estado `new|triage|contained|resolved|false_positive`, asignación, prioridad,
notas, etiquetas, timeline y relación con uno o varios análisis. El análisis original debe seguir
siendo inmutable; el caso representa la decisión humana.

**Valor:** convierte un informe aislado en trabajo operativo medible.

**Dependencias:** M01, M02, M04, B17.

#### F02 — Clustering y campañas

Agrupar mensajes por asunto normalizado, remitente, dominios, URLs, hashes, marca suplantada,
plantilla visual y ventana temporal. Mostrar “otros 17 mensajes relacionados”, primer/último
avistamiento y señales comunes. Empezar con similitud determinista antes de embeddings.

**Valor:** un analista investiga una campaña una vez en lugar de 17 mensajes por separado.

**Dependencias:** F01, indicador normalizado, M05.

#### F03 — Análisis por lotes

Endpoint y UI para varios `.eml`, `.msg` o un ZIP controlado, con límites de tamaño, progreso,
deduplicación y tabla de triaje. No debe ser un bucle HTTP que cree cientos de tareas sin back
pressure.

**Cierre:** un lote devuelve resumen, errores por elemento y enlaces a cada análisis; una entrada
fallida no pierde el resto.

#### F04 — Soporte `.msg`

Usar un conversor aislado como `extract-msg` para producir un modelo canónico, conservando
Message-ID, remitente, cuerpo, adjuntos y fecha originales. Validar macros y adjuntos sin ejecutar
contenido.

**Cierre:** muestras de Outlook con RTF, HTML, adjuntos inline y Unicode conservan evidencia
equivalente a un `.eml`.

#### F05 — Inspección profunda de adjuntos

Crear inspectores separados por tipo:

- PDF: `/JavaScript`, `/Launch`, `/OpenAction`, URLs y formularios.
- OOXML: `vbaProject.bin`, `externalLinks`, plantillas remotas, DDE y relaciones externas.
- HTML: formularios externos, JavaScript ofuscado, blobs/base64 y smuggling.
- ZIP: traversal, tamaño expandido, recursión y combinación de extensiones.

Todo debe ser análisis estático y con límites de CPU, memoria, profundidad y tamaño.

#### F06 — OCR de phishing visual

Aplicar OCR solo a imágenes relevantes, con límites y procesamiento aislado. Reutilizar el texto
extraído en reglas de credenciales, urgencia, idioma, marca y URL; guardar el texto como evidencia
redactada, no necesariamente la imagen completa.

**Dependencias:** M09, F05 y revisión de licencias/idiomas del motor OCR.

#### F07 — Expansión segura de URLs

Seguir redirects mediante un servicio aislado con SSRF protection, DNS rebinding defense, allowlist
de protocolos, timeouts y sin enviar credenciales. Registrar cada salto, certificado, dominio final,
captura visual opcional y diferencia respecto a la URL original.

No debe ejecutarse por defecto en cada análisis hasta tener límites y consentimiento operativo.

#### F08 — RDAP y contexto de infraestructura

Consultar edad de dominio, registrar, ASN, país y fechas con caché, TTL, rate limit y modo neutral
si no hay red. La edad nunca debe ser un gate aislado: dominios nuevos legítimos existen y dominios
antiguos también pueden ser comprometidos.

#### F09 — Threat intelligence externa

Adaptadores opcionales para VirusTotal, urlscan, PhishTank, URLhaus u otro feed seleccionado.
Normalizar respuestas a `known_malicious|suspicious|unknown|unavailable`, guardar fuente y
timestamp, cachear por IOC y no exfiltrar raw email sin consentimiento.

#### F10 — STIX 2.1, MISP y JSON estable

Definir un esquema versionado para análisis, findings, IOCs, adjuntos, campaña y feedback.
Exportar indicadores defanged por defecto y STIX/MISP bajo una acción explícita. Incluir
`created_by`, `valid_until`, fuente, confianza y relación con el análisis.

#### F11 — Webhooks, SIEM y SOAR

Emitir eventos firmados para `analysis.finished`, `case.updated`, `campaign.detected` y
`mailbox.reauth_required`, con reintentos, backoff, dedupe y replay. Añadir adaptadores simples para
un webhook genérico antes de construir integraciones propietarias.

#### F12 — Cuarentena y remediación segura

Después de confirmar OAuth/scopes y permisos, permitir mover, etiquetar, marcar como phishing o
eliminar mensajes en Gmail/Graph. Separar “recomendación” de “acción”, exigir confirmación para
destructivas, registrar actor/razón y ofrecer rollback cuando el proveedor lo permita.

#### F13 — Report button y cliente cercano al usuario

Un botón de reportar desde Outlook/Gmail, extensión de navegador o endpoint de reenvío debe crear
el análisis con el contexto correcto, no pedir al usuario que copie cabeceras. Empezar por el canal
que entregue más contexto con menor mantenimiento.

#### F14 — Mailbox event-driven

Mantener el polling como fallback, pero añadir Gmail watch/renewal y Graph change notifications
cuando existan garantías de renovación, firma, backpressure y recuperación. El evento solo
despierta la sincronización; no debe confiar en payload externo como evidencia completa.

#### F15 — Shared mailboxes, IMAP y cuentas de servicio

Ampliar conectores solo después de cerrar el modelo de tenant/ownership. Deben existir scopes
mínimos, rotación, reautenticación, límites por conexión, carpetas múltiples y política clara de
quién puede ver los mensajes.

#### F16 — Simulador de reglas y replay de corpus

Panel interno para ejecutar una entrada contra el ruleset actual, comparar dos versiones, mostrar
qué gate cambió y listar falsos positivos conocidos. Es una funcionalidad de producto para
administradores y una herramienta de seguridad para no degradar el detector.

#### F17 — Inteligencia de tenant

Con consentimiento y separación estricta por organización, agregar dominios frecuentes, contactos
habituales, marcas protegidas y campañas observadas. Nunca mezclar raw email entre tenants; compartir
solo indicadores anonimizados o reglas de política explícitas.

#### F18 — Grafo remitente-destinatario

Construir un grafo de metadatos: quién escribe a quién, con qué frecuencia, desde qué dominios y
con qué desviación. Una primera versión determinista puede detectar “nuevo remitente con nombre de
contacto habitual” sin ML. El grafo debe tener retención corta y controles de privacidad.

### 7.5 Apuestas estratégicas e I+D

#### X01 — Modelo híbrido de comportamiento

Combinar heurísticas, features estructurales y modelo calibrado con feedback. El modelo nunca debe
ocultar reglas ni convertirse en una caja negra; debe devolver contribuciones y funcionar con un
modo sin ML. Requiere corpus etiquetado, evaluación temporal, drift monitoring y un proceso de
rollback.

#### X02 — Clasificación semántica multilingüe con LLM

Detectar intención como robo de credenciales, fraude de pago, entrega, soporte falso o extorsión.
Debe ser señal secundaria, con cache por hash, coste limitado, redacción, defensa contra prompt
injection en el correo y salida estructurada validada. Nunca debe ser gate por sí sola.

#### X03 — Sandbox de detonación

Ejecutar adjuntos y URLs en entorno desechable para observar redirects, scripts, macros y llamadas
de red. Es valioso, pero requiere aislamiento real, gestión de secretos, capacidad, egress
controlado, retención y una política de datos mucho más exigente que la del parser actual.

#### X04 — Gateway inline

Integrarse antes de la entrega mediante MTA, gateway o API de proveedor para bloquear/quarantinar en
tiempo real. Es una categoría distinta del actual analizador bajo demanda y compite directamente
con capacidades nativas de Microsoft/Google. Solo tiene sentido después de demostrar precisión,
latencia y remediación segura.

#### X05 — Offline, privacidad avanzada y federación

Permitir instalación sin egress, feeds locales, OCR/ML local, cifrado por tenant y aprendizaje
federado o agregado sin raw compartido. Es un posible diferenciador para entornos sensibles, pero
duplica la complejidad operacional.

#### X06 — Bucle Iris → Aegis

Convertir patrones reales anonimizados en píldoras de formación y simulaciones. No reutilizar
mensajes reales automáticamente: primero extraer patrón, eliminar PII y exigir aprobación humana.
El valor es cerrar detección y resiliencia humana sin convertir Iris en una plataforma de campañas.

#### X07 — Copiloto SOC aprobable

Un agente puede resumir un caso, proponer pivots, agrupar evidencias y preparar una acción, pero
cada cambio sobre el buzón debe requerir aprobación y dejar auditoría. La primera versión debe ser
read-only y basada únicamente en findings persistidos.

#### X08 — Mensajería más allá del correo

Extender detecciones a Teams, Slack, SMS o formularios puede capturar el mismo patrón de ingeniería
social, pero rompe el foco y exige nuevos conectores, modelos de identidad y políticas de privacidad.
Debe tratarse como un producto hermano o una nueva fuente de `MessageContext`, no como reglas
pegadas a Iris.

## 8. Fases de ejecución

Las fases agrupan iniciativas por fragmentos de código, invariantes y tema. Las duraciones son
orientativas para una dedicación parcial de 10–15 horas semanales; no son promesas de calendario.

### Fase 0 — Veredicto confiable y contrato correcto

**Objetivo:** que ningún análisis se presente como terminado, autenticado o limpio cuando el
pipeline no puede sostenerlo.

**Incluye:** B03, B04, B05, B06, B10, B11, B12, B13, B14, B18 y B20.

**Fragmentos principales:** `managers/analysis.py`, `services/rules/auth_rules.py`,
`services/reports.py`, `model.py`, `schemas.py`, `__init__.py`, migraciones y tests.

**Salida mínima:** estados terminales fiables, auth provenance endurecida, PDFs independientes,
cursor Graph sin truncado, contrato de permisos y tamaño consistente, cola IA registrada, cachés
versionadas y matriz de integración PostgreSQL/Redis.

**No cerrar la fase sin:** test de parser roto, test de job `running`, test de regla fallida, test
de ARC/Auth-Results falsificado, test de PDF concurrente y test de delta link largo.

### Fase 1 — Ingesta que no pierde correo

**Objetivo:** hacer operativa la conexión Gmail/Graph bajo reintentos, cuotas, reinicios y
concurrencia.

**Incluye:** B01, B02, B07, B08, B09, B16, B17, B19, M08, M09 y M10.

**Fragmentos principales:** `managers/mailbox.py`, `services/mailbox/*`, scheduler, Redis,
`QuotaManager`, repositorios y migraciones.

**Salida mínima:** checkpoint/dead-letter, lock por conexión, outbox, cuotas idempotentes,
retención, scopes documentados, carpetas validadas y health de sync observable.

**Decisión de diseño:** no añadir más proveedores ni eventos en tiempo real antes de demostrar que
el polling actual no pierde mensajes y que una conexión bloqueada se recupera sola.

### Fase 2 — Workbench del analista

**Objetivo:** reducir tiempo de decisión y hacer auditable el resultado.

**Incluye:** M01, M02, M03, M04, M05, M07, M12, F01, F03 y F16.

**Fragmentos principales:** `RuleResult.details`, schemas, repositorios, vista Iris, PDF,
TaskQueue y nuevas tablas de casos/feedback.

**Salida mínima:** evidencia anclada, calidad/confianza explícita, allowlists seguras, feedback,
score versionado, casos y análisis por lotes con replay.

**Métrica de salida:** un analista puede explicar por qué se clasificó un mensaje, corregir un
falso positivo, comparar dos versiones y procesar un lote sin leer logs.

### Fase 3 — Detección multimodal y formatos reales

**Objetivo:** cubrir el contenido que el atacante oculta fuera de las cabeceras o del texto plano.

**Incluye:** M06, M11, F04, F05 y F06.

**Fragmentos principales:** parser canónico, `services/rules/`, inspectores de adjuntos,
dependencias de OCR, frontend de carga y PDF.

**Salida mínima:** `.msg`, Public Suffix List, IDN/confusables completos, PDF/OOXML/HTML estáticos,
OCR con límites y evidencia por parte MIME.

**Guardrail:** ningún adjunto se ejecuta, ningún HTML se renderiza sin aislamiento y ningún OCR se
usa para enviar el contenido a un tercero por defecto.

### Fase 4 — Campañas e inteligencia

**Objetivo:** pasar de “este correo es sospechoso” a “esta campaña afecta a estos mensajes y usa
estos IOCs”.

**Incluye:** F02, F07, F08, F09, F10, F17 y F18.

**Fragmentos principales:** tabla de indicadores, enriquecimiento con caché, grafo de relaciones,
clustering, exportadores y políticas de egress.

**Salida mínima:** campañas agrupadas, pivots, RDAP/reputación opcionales, JSON estable y STIX/MISP
con confianza, fuente y timestamps.

**Guardrail:** timeout, cache, rate limit, SSRF defense, redacción y modo neutral cuando el servicio
externo no está disponible.

### Fase 5 — Respuesta e integración SOC

**Objetivo:** cerrar el bucle operativo sin convertir cada finding en una acción destructiva.

**Incluye:** F11, F12, F13, F14 y F15.

**Fragmentos principales:** conectores Gmail/Graph, OAuth, webhooks, auditoría, casos y UI de
confirmación.

**Salida mínima:** botón de reportar o canal equivalente, eventos firmados, acción de cuarentena
con confirmación, sincronización event-driven con fallback y soporte de buzones compartidos según
el modelo de tenant.

**Gate de entrada:** no se implementan borrado automático ni respuesta autónoma; primero deben
existir ownership, auditoría, permisos, idempotencia y rollback.

### Fase 6 — Apuestas estratégicas

**Objetivo:** explorar ventajas que no son necesarias para validar el producto principal.

**Incluye:** X01, X02, X03, X04, X05, X06, X07 y X08.

**Orden recomendado dentro de la fase:** X02 read-only y X06 con datos sintéticos antes que X01;
X01 antes que X07; X03 solo con aislamiento probado; X04 y X08 como decisiones de producto
separadas.

**Salida mínima:** prototipo medido contra corpus versionado, criterio de abandono, presupuesto de
operación y documentación explícita de qué riesgo nuevo introduce.

## 9. Métricas para decidir si Iris mejora

No basta con contar reglas o endpoints. Cada fase debe producir métricas de usuario y de seguridad.

| Dimensión | Métrica propuesta |
|---|---|
| Calidad del detector | Precision, recall, F1, falso positivo por 1.000 legítimos y cobertura por familia |
| Explicabilidad | Porcentaje de findings con evidencia anclada y tiempo medio para justificar un veredicto |
| Operación | Tiempo desde descubrimiento hasta análisis, edad del backlog y porcentaje de jobs huérfanos |
| Ingesta | Mensajes descubiertos, aceptados, pendientes, dead-letter, duplicados y pérdida confirmada: objetivo cero |
| Usuario | Tiempo de triage, porcentaje de análisis con feedback y porcentaje de casos resueltos sin export manual |
| Campañas | Mensajes agrupados correctamente, IOCs reutilizables y tiempo de pivot entre análisis |
| IA | Aceptación de resumen, correcciones humanas, alucinaciones detectadas y coste por análisis |
| Privacidad | Raw retenido fuera de política, accesos auditados y scopes concedidos por proveedor |
| Respuesta | Acciones confirmadas, revertidas, fallidas y tiempo hasta contención |

### 9.1 Criterios de éxito iniciales

- Cero pérdida de mensajes en pruebas de cuota, reintento, crash y concurrencia.
- Cero análisis `running` sin heartbeat ni explicación terminal después de la reconciliación.
- 100 % de veredictos `Legitimate` con estado de cobertura visible.
- 100 % de acciones sobre buzón con actor, motivo, permiso y timestamp.
- Toda modificación de scoring comparada contra un corpus de regresión.
- Toda integración externa con timeout, cache y modo degradado.

## 10. Decisiones que conviene no tomar todavía

- No añadir ML entrenado sin feedback etiquetado, versión de dataset y métricas de drift.
- No usar un LLM para convertir un mensaje en `Phishing` sin evidencia estructural independiente.
- No ejecutar URLs o adjuntos en el mismo proceso que Flask, RQ o el parser MIME.
- No crear una allowlist que desactive todas las reglas; la confianza debe tener alcance y
  caducidad.
- No compartir datos entre usuarios para clustering hasta cerrar tenant, consentimiento y
  anonimización.
- No construir un gateway inline antes de demostrar latencia, precisión y remediación segura.
- No abrir demasiados conectores: Gmail y Graph deben ser fiables antes de IMAP, add-ins y
  servicios de terceros.

## 11. Fuentes y referencias externas

Consultadas el 2026-08-24:

- [Microsoft Defender — Anti-phishing policies](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about)
- [Google Workspace — Advanced phishing and malware protection](https://support.google.com/a/answer/9157861?hl=en)
- [Microsoft Graph — Message resource](https://learn.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0)
- [Microsoft Graph — Delta query for messages](https://learn.microsoft.com/en-us/graph/delta-query-messages)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/rfc/rfc7489)
- [RFC 8617 — Authenticated Received Chain](https://www.rfc-editor.org/rfc/rfc8617)
- [OASIS — STIX 2.1 documentation](https://oasis-open.github.io/cti-documentation/stix/intro)
- [MISP — Objects and sharing format](https://www.misp-project.org/objects.html)

Estas fuentes sirven para identificar capacidades y estándares, no para afirmar que un proveedor
tenga mejor precisión que otro. Las decisiones de Iris deben validarse con su propio corpus,
telemetría y restricciones de privacidad.
