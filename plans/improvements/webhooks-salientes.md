# Webhooks salientes — análisis de viabilidad y diseño

> Documento de diseño, **no código existente**. Nace de la pregunta: *¿es fácil y útil añadir
> webhooks a Ellysia, como herramienta universal para cualquier módulo, sin caer en
> implementaciones ad-hoc por módulo?*
>
> **Veredicto corto**: sí a ambas, con matices. La dificultad es **media-baja** (~2-3 semanas
> repartidas en 3 fases) porque la arquitectura actual ya tiene *las tres piezas difíciles*
> resueltas: cola persistente con reintentos (`TaskQueue`/RQ), patrón de herramienta transversal
> pluggable (`herald`/`scribe`) y frontera transaccional explícita (`UnitOfWork`). El valor es
> **alto pero desigual entre módulos** — ver §2. Lo que de verdad cuesta no es enviar el POST:
> es el **catálogo de eventos** y el **SSRF saliente** (§6.2).

---

## 0. Qué es un webhook (contexto, porque no tiene por qué ser obvio)

Un webhook es la inversión del modelo cliente-servidor habitual. Hoy, quien quiere saber si un
escaneo de Themis terminó tiene que **preguntar** (`GET /themis/scans/{id}` en bucle: *polling*).
Con webhooks, el cliente registra una vez una URL suya, y es **Ellysia quien hace un `POST` a esa
URL** cuando ocurre algo relevante. "Webhook" = "un hook (gancho) que se dispara por HTTP".

En una frase: **es un `Mailer`, pero el destinatario es una máquina y el transporte es HTTP en vez
de SMTP.** Esa analogía no es retórica — es literalmente el encaje arquitectónico que se propone
en §3, y la razón de que el coste sea moderado: Ellysia ya tiene el hermano de esta pieza (`herald`).

El "contrato" de un webhook tiene solo cuatro partes, y todas las decisiones de diseño de este
documento cuelgan de ellas:

| Parte | Qué es | Dónde se decide aquí |
|---|---|---|
| **Suscripción** | Quién quiere recibir qué, y en qué URL | §4.2 (tabla `WebhookSubscription`) |
| **Evento** | El JSON que se envía y su tipo (`hygeia.anomaly.opened`) | §4.1 (sobre canónico) |
| **Entrega** | El `POST`, sus reintentos y su firma | §5 (entrega asíncrona) |
| **Verificación** | Cómo el receptor sabe que el POST viene de Ellysia y no de un impostor | §6.1 (HMAC) |

---

## 1. Por qué "universal" y no ad-hoc (el requisito clave)

Un webhook ad-hoc por módulo (Hygeia llama a una URL cuando abre una anomalía; Themis llama a otra
al terminar un escaneo) es el camino corto y es una **trampa conocida**: acaba en N implementaciones
divergentes con N formatos de payload, N políticas de reintento y N agujeros de SSRF distintos que
auditar. Además obliga a cada módulo a conocer HTTP saliente, cuando su responsabilidad es su dominio.

La forma universal invierte la dependencia, exactamente como ya hace `scribe` (IA) y `herald`
(email) en `tools/`:

> **Los módulos no envían webhooks. Los módulos *publican eventos de dominio*, y una herramienta
> transversal — que no conoce a ningún módulo — decide quién los recibe y los entrega.**

Hygeia no sabe que existen los webhooks; solo declara "he abierto una anomalía crítica". Si mañana
esa misma publicación alimenta también un canal de Slack, un SIEM o un WebSocket para la SPA, no se
toca ni una línea de Hygeia. Esta es la propiedad que justifica el trabajo extra frente al ad-hoc.

Precedente exacto en el repo: `herald/__init__.py` documenta *"Aegis depende de herald; herald no
conoce a Aegis"*. La pieza nueva se sostiene sobre esa misma frase.

---

## 2. ¿Es útil? Sí, pero no en todos los módulos por igual

Un webhook solo vale lo que valga el sistema al otro lado. En una plataforma de seguridad los
destinos reales son: **Slack/Teams** (avisos a un canal de guardia), **SIEM/SOAR** (Splunk, Wazuh,
TheHive), **n8n / Zapier** (automatizaciones sin código), **Jira / ticketing** (abrir incidencia
automáticamente) y **el propio backend del cliente**.

| Módulo | Eventos candidatos | Valor | Comentario |
|---|---|---|---|
| **Hygeia** | `anomaly.opened`, `anomaly.closed`, `asset.offline` | **Muy alto** | Es monitorización: su valor *es* la inmediatez. Hoy el aviso solo sale por email (`hygeia.notify`), que es el canal más lento y menos automatizable. Caso de uso #1. |
| **Themis** | `scan.completed`, `scan.failed`, `vulnerability.critical_found` | **Alto** | Escaneos largos (Nuclei con feed completo, análisis profundo de Lybra) — el patrón "lanzo y me avisas" es el natural; hoy obliga a polling. |
| **Aegis** | `campaign.finished`, `recipient.clicked`, `quiz.failed` | **Medio** | Útil para reporting, pero contiene datos personales de empleados → cuidado legal (§6.4). |
| **Iris** | `analysis.completed` | **Medio** | Mismo patrón que Themis pero análisis más cortos. |
| **Acheron** | — | **Ninguno / contraindicado** | Es una bóveda de cifrado con conocimiento cero. Emitir eventos con contenido sería una fuga; emitirlos sin contenido no aporta. **Decisión explícita: Acheron no publica eventos.** |
| **System / users** | `task.failed`, `user.created` | **Bajo-medio** | Interesante para auditoría, prescindible en la v1. |

**Conclusión de utilidad**: el motor se justifica con Hygeia y Themis solos. Si solo se implementara
para Hygeia, seguiría mereciendo la pena construirlo genérico (§1), porque el coste diferencial
entre "genérico" y "ad-hoc para Hygeia" es de días, no de semanas.

---

## 3. Encaje arquitectónico propuesto

Una herramienta transversal nueva en `API/src/modules/tools/`, hermana de `scribe` y `herald`.
Nombre propuesto: **`echo`** (Eco, la ninfa que repite hacia fuera lo que oye) — coherente con la
nomenclatura mitológica del repo y semánticamente exacto: repite eventos internos hacia el exterior.

```
API/src/modules/tools/echo/
├── __init__.py        # API pública: publish(), EventEnvelope, EventCatalog
├── catalog.py         # EventCatalog — registro de tipos de evento (espejo de QueueRegistry)
├── envelope.py        # EventEnvelope, DeliveryAttempt (dataclasses de tránsito, espejo de inputs.py)
├── bus.py             # publish() → resuelve suscripciones → encola entregas
├── transport.py       # WebhookStrategy (HTTP hoy; Slack/SNS mañana), firma HMAC, validación SSRF
├── factory.py         # build_transport(module) leyendo SecOpsConfig.json (espejo de factory.py)
└── exceptions.py
```

Y el **estado persistente** (suscripciones, entregas) vive donde vive el resto de lo administrativo:
como submódulo de `system/` (`system/webhooks/` con su `model.py`, `repositories.py`, `managers.py`,
`endpoints.py`, siguiendo el layering estándar). Es decir:

- `tools/echo` = **mecanismo** sin estado (cómo se firma, cómo se envía, qué es un evento). No conoce ni la BD ni los módulos.
- `system/webhooks` = **estado y superficie REST** (quién está suscrito, qué se entregó, CRUD).
- Los módulos = **solo publican**: `echo.publish(EventEnvelope(...))`.

### El catálogo de eventos: lo que hace que esto sea universal

Es la pieza conceptualmente más importante y la más barata de escribir. Copia literal del patrón
`QueueRegistry` que ya funciona en el repo: cada módulo declara sus tipos de evento en su
`__init__.py`, y nadie más los toca.

```python
# API/src/modules/features/hygeia/__init__.py
from src.modules.system.taskqueue import QueueRegistry
from src.modules.tools.echo import EventCatalog

QueueRegistry.register("hygeia.notify")

EventCatalog.register(
    "hygeia.anomaly.opened",
    description="Se ha abierto una anomalía en un activo monitorizado.",
    schema=AnomalyEventSchema,   # Marshmallow, reutiliza el de la API — claves camelCase
)
```

Beneficios que se obtienen gratis de tener catálogo:
- `GET /system/webhooks/events` devuelve la **documentación viva** de qué se puede escuchar (la SPA
  puede pintar el selector de eventos sin hardcodear nada).
- Validar en el alta de una suscripción que los `eventTypes` pedidos existen (un typo se detecta al
  suscribirse, no seis meses después cuando el webhook "no llega nunca").
- Un evento nuevo = una línea en el `__init__.py` del módulo + una llamada a `publish()`. **Cero
  cambios en `echo`.** Ese es el test de si el diseño es universal de verdad.

---

## 4. Contratos de datos

### 4.1 Sobre canónico del evento (`EventEnvelope`)

Todos los eventos de todos los módulos tienen la misma forma exterior; solo cambia `data`. Esto es
lo que permite al receptor escribir *un* handler y no N.

```json
{
  "id": "evt_01HQ8...",
  "type": "hygeia.anomaly.opened",
  "specVersion": "1.0",
  "occurredAt": "2026-07-21T10:32:11.482Z",
  "source": "hygeia",
  "actor": { "userId": 42, "kind": "agent" },
  "resource": { "kind": "anomaly", "id": 1187 },
  "data": {
    "assetId": 12, "hostname": "web-01", "metric": "cpu",
    "severity": "critical", "value": 98.4, "threshold": 90
  }
}
```

Notas de diseño, cada una con su porqué:
- **`type` con jerarquía `modulo.recurso.acción`** → permite suscripciones por comodín
  (`hygeia.*`, `themis.scan.*`) sin inventar sintaxis nueva más adelante.
- **`specVersion`** desde el día 1. Cambiar el payload de un webhook rompe integraciones de
  terceros silenciosamente; sin versión en el sobre no hay forma limpia de evolucionar.
- **`data` es un resumen, nunca el objeto completo.** El receptor que quiera el detalle llama a la
  API con su propio token. Esto acota la superficie de fuga (§6.4) y evita payloads de megabytes.
- **camelCase**, coherente con el resto de la API.
- **`occurredAt` ≠ momento de entrega.** Una entrega reintentada 3 h después conserva su
  `occurredAt` original.

### 4.2 Persistencia (`system/webhooks/model.py`)

```
WebhookSubscription
    id, user_id (FK User), name, url,
    event_types (JSONB: ["hygeia.anomaly.opened", "themis.scan.*"]),
    secret_encrypted,           # ver §6.1 — cifrado, NO hasheado
    custom_headers (JSONB),     # p.ej. auth extra del receptor
    active (bool), consecutive_failures (int),
    disabled_at, created_at, last_delivery_at

WebhookDelivery                  # historial / dead-letter / reentrega manual
    id, subscription_id (FK), event_id, event_type,
    payload (JSONB), status ("pending"|"success"|"failed"|"exhausted"),
    attempts (int), last_status_code, last_error, next_retry_at,
    created_at, completed_at
```

Nota: `WebhookDelivery` crece rápido → necesita política de retención, exactamente igual que
`AssetSnapshot` de Hygeia (`hygeia.retentionDays` y su tarea de purga ya son el precedente a copiar).

---

## 5. Flujo de entrega (y el punto sutil: *cuándo* publicar)

```
Manager de módulo
   └─ echo.publish(envelope)          [síncrono, barato: solo bufferiza]
        └─ tras COMMIT de la transacción
             └─ bus resuelve suscripciones activas que casan con el type
                  └─ 1 job por (evento × suscripción) → TaskQueue, categoría "echo.deliver"
                       └─ worker RQ: firma HMAC → valida URL → POST (timeout 10 s)
                            ├─ 2xx  → delivery = success
                            └─ else → backoff exponencial + jitter, hasta N intentos
```

### El detalle que muerde: publicar antes del commit

Este es el error clásico y en Ellysia tiene una forma muy concreta. En una petición HTTP el commit
**no** ocurre al salir del `with UnitOfWork()` — ocurre en `teardown_request` (el `__exit__` es un
no-op en contexto de request, por diseño). Es decir: si un manager publica un evento y el job se
encola inmediatamente, el worker — que corre en **otro proceso** — puede intentar leer una fila que
todavía no está confirmada, o peor, notificar un cambio que después se revierte por una excepción
posterior en la misma petición. Sería un webhook que anuncia algo que nunca pasó, y no hay forma de
retractarlo.

El repo ya se topó con esto y lo resolvió a mano: `HygeiaNotifyManager.enqueue_for()` documenta que
*"debe llamarse siempre después de que la transacción que las creó ya sea durable"*. Esa disciplina
manual funciona para un caso; para un mecanismo genérico que van a usar todos los módulos, hay que
hacerla estructural. Dos opciones:

- **(a) Buffer + flush en el borde** — `publish()` acumula en un buffer de contexto (`g` en request,
  el `job_context` en background) y el flush se engancha *después* del commit, en los mismos dos
  bordes que ya gestionan la sesión. Barato, encaja como un guante con la arquitectura existente.
  **Recomendada para la v1.**
- **(b) Outbox transaccional** — el evento se escribe como fila en la *misma* transacción, y un
  worker aparte la lee y entrega. Es la solución correcta al 100 % (sobrevive a una caída entre el
  commit y el encolado), pero añade una tabla, un poller y latencia. **Guardarla para cuando alguien
  pague por "entrega garantizada"**, no para la v1.

La diferencia práctica entre (a) y (b) es una ventana de milisegundos en la que un crash del proceso
API pierde el evento. Para avisos operativos es asumible; para facturación no lo sería. Ellysia está
en el primer caso.

### Política de reintentos (valores de partida, configurables)

- Éxito = **cualquier 2xx**. Cualquier otra cosa (4xx incluido) o timeout = fallo.
- Backoff: `10 s, 1 min, 10 min, 1 h, 6 h` (5 intentos) + jitter, para no sincronizar tormentas de
  reintentos contra un receptor que acaba de volver.
- Timeout por intento: **10 s**, sin excepción. Un receptor lento no puede bloquear un worker.
- Tras agotar intentos → `status = "exhausted"`, visible en la UI y reentregable a mano.
- Tras **N=20 fallos consecutivos** en la misma suscripción → auto-desactivación + email al dueño
  (vía `herald`, ya existe). Sin esto, una URL muerta genera trabajo inútil para siempre.
- **Cola propia (`echo.deliver`)**, nunca compartida con `themis.scan` o `hygeia.notify`: un
  receptor caído no debe poder retrasar los escaneos.
- **El orden no está garantizado** y hay que documentarlo. Con reintentos, `anomaly.closed` puede
  llegar antes que `anomaly.opened`. El receptor debe ordenar por `occurredAt`, no por llegada.

---

## 6. Seguridad (la parte que hay que hacer bien o no hacer)

### 6.1 Firma HMAC — cómo sabe el receptor que el POST es de Ellysia

Sin firma, cualquiera que conozca la URL del receptor puede inventarse alertas críticas. Esquema
estándar (el de Stripe/GitHub, elegido porque los receptores ya saben verificarlo):

```
X-Ellysia-Event:      hygeia.anomaly.opened
X-Ellysia-Delivery:   dlv_01HQ8...        # idempotencia: mismo id en todos los reintentos
X-Ellysia-Signature:  t=1753093931,v1=5f2b...   # HMAC-SHA256("{t}.{body_crudo}", secret)
```

El `t` dentro de la firma es lo que evita el replay: el receptor rechaza lo que tenga más de ~5 min.
Firmar solo el body permitiría reenviar un POST capturado indefinidamente.

> **Detalle de implementación que hay que acertar**: el secreto debe poder **recuperarse en claro**
> para firmar, así que **no puede hashearse** como se hace con las contraseñas o con la
> `agent_key_hash` de Hygeia. El patrón correcto ya existe en el repo: `MFATotpCredential.
> secret_encrypted` (cifrado reversible, no hash). Se muestra una sola vez en la respuesta del alta
> — eso sí, igual que la clave de agente de Hygeia.

### 6.2 SSRF saliente — el riesgo real de esta feature

**Este es el verdadero coste de seguridad de los webhooks, y conviene decirlo sin rodeos.** Un
webhook es, por definición, *"un usuario autenticado le dicta al servidor a qué URL hacer una
petición"*. Eso es la definición literal de SSRF. Un usuario podría registrar
`http://169.254.169.254/latest/meta-data/` (metadatos de cloud) o `http://localhost:5000/system` y
usar Ellysia como proxy hacia su propia red interna.

Mitigaciones **obligatorias**, no opcionales:
1. Solo `https://` (salvo un allowlist explícito para desarrollo).
2. Resolver el DNS y **validar la IP resuelta**, no el hostname: rechazar privadas, loopback,
   link-local (`169.254.0.0/16`), multicast, IPv6 equivalentes.
3. **Fijar la IP validada para la conexión** o revalidar tras resolver — si no, hay ventana de
   *DNS rebinding* (el dominio resuelve a una IP pública en la validación y a `127.0.0.1` en el POST).
4. **`allow_redirects=False`**. Un 302 hacia `127.0.0.1` salta todas las validaciones anteriores.
5. Cabecera `User-Agent: Ellysia-Webhooks/1.0` y sin cookies ni credenciales ambientales.

Themis ya tiene lógica anti-SSRF (`themis.areLocalIpsAllowed`, `validate_ip`). **Extraerla a
`shared/` y reutilizarla** es preferible a escribir una segunda — dos validadores anti-SSRF
divergentes es peor que uno. Ojo con el aviso de `CLAUDE.md`: hoy `areLocalIpsAllowed` está en
`true` para desarrollo local; el validador de webhooks debe tener **su propio flag independiente**,
porque "quiero escanear mi LAN" y "acepto hacer POST a mi LAN" son decisiones distintas.

### 6.3 Autorización de las suscripciones

- Nuevo atributo ABAC `WEBHOOK_MANAGE` (`webhook_manage`) en `AttributeType`, siguiendo la
  convención `{MODULE}_{OPERATION}` ya establecida.
- Una suscripción pertenece a un `user_id` y **solo recibe eventos de recursos que ese usuario podría
  leer vía API**. Esto es crítico y fácil de olvidar: sin ese filtro, un webhook se convierte en una
  escalada de privilegios silenciosa (me suscribo a `themis.*` y recibo los escaneos de todos).
- Al degradar o borrar un usuario → desactivar sus suscripciones. El filtro debe evaluarse **en el
  momento de la entrega**, no solo en el del alta.

### 6.4 Privacidad

Los eventos de Aegis contienen datos personales de empleados (quién picó en el phishing). Enviarlos
a un endpoint de terceros tiene implicaciones de RGPD que la plataforma no controla. Mitigación:
`data` como resumen mínimo (§4.1), y para Aegis considerar enviar solo IDs, obligando al receptor a
autenticarse contra la API para obtener el detalle.

---

## 7. Superficie REST y SPA

Bajo el blueprint `/system` que ya existe (es administración de plataforma, no un módulo de dominio):

```
GET    /system/webhooks/events            # catálogo vivo de tipos de evento (§3)
GET    /system/webhooks                   # listar suscripciones del usuario
POST   /system/webhooks                   # crear (devuelve el secreto UNA sola vez)
GET    /system/webhooks/{id}
PUT    /system/webhooks/{id}              # url, eventTypes, active
DELETE /system/webhooks/{id}
POST   /system/webhooks/{id}/test         # dispara un evento "ping" sintético
POST   /system/webhooks/{id}/rotate-secret
GET    /system/webhooks/{id}/deliveries   # historial paginado
POST   /system/webhooks/deliveries/{id}/redeliver
```

`/test` no es un extra: sin él, dar de alta un webhook es a ciegas y el 80 % de las incidencias de
soporte de cualquier sistema de webhooks son "no me llega nada" resueltas con un ping.

En la SPA: una pestaña dentro de `ConfigView.vue` (no una vista nueva de primer nivel — es
configuración, no un módulo). Lista de suscripciones + estado de salud + timeline de entregas con
código de respuesta y botón de reentrega. `QueueView.vue` ya es el precedente visual para la tabla
de entregas.

---

## 8. Fases y esfuerzo estimado

| Fase | Alcance | Esfuerzo | Deja algo usable |
|---|---|---|---|
| **1 — Motor** | `tools/echo` (catálogo, sobre, transporte HTTP, HMAC, SSRF), modelo + migración Alembic, cola `echo.deliver`, reintentos. Un solo productor: `hygeia.anomaly.opened`. Alta de suscripciones por API. | ~1 semana | Sí: Hygeia → Slack/n8n funcionando de punta a punta |
| **2 — Cobertura** | Eventos de Themis e Iris, comodines (`themis.*`), historial de entregas, `/test`, reentrega, auto-desactivación, purga por retención. | ~4-5 días | Sí: cubre los casos de uso reales |
| **3 — UI y pulido** | Pestaña en `ConfigView`, rotación de secreto, docs públicas de verificación de firma (snippet en Node/Python para el receptor). | ~3-4 días | Sí: autoservicio sin tocar la API a mano |

Fase 1 es la que tiene todo el riesgo técnico; 2 y 3 son incrementales y aplazables sin deuda.

**Tests**: la fase 1 necesita unitarios de firma HMAC (vector fijo), del validador SSRF (batería de
URLs maliciosas — es el test que más valor tiene de todo el paquete) y del cálculo de backoff; e
integración con un receptor falso que devuelva 500 y luego 200, para verificar el reintento. Todo
encaja en el esquema `pytest -m unit / -m integration` existente, sin infraestructura nueva.

---

## 9. Alternativas consideradas y descartadas

- **Webhooks ad-hoc por módulo** — descartado, es el requisito explícito. Y por §1.
- **Polling desde el cliente** — es el statu quo. Funciona, pero escala mal y añade latencia
  (Hygeia detecta en segundos algo que el cliente ve en minutos).
- **WebSocket / SSE hacia la SPA** — resuelve un problema *distinto* (refrescar una UI abierta), no
  sustituye a los webhooks (integrar sistemas que no tienen a nadie mirando la pantalla). Son
  complementarios y, de hecho, si el bus de eventos de §3 existe, alimentar un SSE después es casi
  gratis. Argumento adicional a favor del bus.
- **Integración directa con Slack/Teams como estrategia de `herald`** — más simple y cubre el caso
  de uso más frecuente, pero solo ese uno, y no es universal. **Es un buen complemento posterior**:
  con el bus ya montado, "Slack" se añade como una `WebhookStrategy` más en `transport.py` en lugar
  de un módulo aparte.
- **Broker de mensajería (Kafka, RabbitMQ)** — sobredimensionado. Redis + RQ ya da persistencia y
  reintentos, y añadir un broker nuevo por esto no se sostiene.

---

## 10. Resumen ejecutivo

**Facilidad: media-baja.** El grueso del riesgo técnico está en dos sitios y ambos están acotados:
publicar después del commit (§5) y SSRF saliente (§6.2). Todo lo demás son piezas que el repo ya
tiene y que solo hay que componer.

**Utilidad: alta**, concentrada en Hygeia y Themis. Es la diferencia entre una plataforma que hay
que mirar y una que se integra en el flujo de trabajo que el cliente ya tiene.

**Universalidad: se consigue con una sola decisión** — el catálogo de eventos registrado por cada
módulo (§3), calcado del `QueueRegistry` que ya funciona. Si añadir un evento nuevo obliga a tocar
`tools/echo`, el diseño ha fallado y hay que revisarlo.

**Recomendación**: hacer la Fase 1 con Hygeia como único productor y **un cliente/caso de uso real
que lo consuma** antes de generalizar. El catálogo garantiza que ampliar después sea aditivo.
