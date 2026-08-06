# Planes, cuotas y organizaciones

> Plan de diseño para la capa **comercial** de Ellysia: qué plan tiene cada usuario,
> cuánto de cada cosa puede hacer, cómo se da de alta él solo, y cómo un responsable
> de seguridad puede agrupar a su gente bajo una **organización** que hereda derechos
> de su plan.
>
> Es la fase aburrida: no añade ninguna capacidad de seguridad nueva. Añade el marco
> que hace que las cinco herramientas se puedan **enseñar y vender** sin regalar el
> coste de la IA ni el de los escaneos.
>
> Documento de diseño. Describe el camino, no código existente. Módulo nuevo: `accounts`.

---

## 1. Qué es y qué NO es

**Es** tres cosas que se apoyan una en otra:

1. Un **catálogo de planes** con sus límites, editable desde la propia plataforma
   (tablas, no JSON de configuración: los rellena el equipo sin desplegar).
2. Un **motor de cuotas** que cuenta lo que consume cada cuenta y corta cuando toca.
3. Un modelo de **organización**: un titular paga, sus miembros heredan derechos.

**NO es** (trampas de alcance):

- **No es una pasarela de pago.** No hay Stripe, ni checkout, ni facturas, ni webhooks.
  El plan lo asigna a mano root/admin. Pero **sí es el sitio donde la pasarela va a
  enchufarse**, así que el ciclo de vida completo de una suscripción — alta, renovación,
  impago, cancelación, subida y bajada de plan — se diseña **ahora** y se implementa
  ahora, movido a mano desde el panel de root. La pasarela, el día que llegue, será un
  segundo cliente del mismo puerto. Todo eso es §12.
- **No es multi-tenancy.** Una organización **no comparte datos**. Ni bóvedas, ni
  escaneos, ni análisis, ni activos. Acheron es zero-knowledge (el servidor solo ve
  cifrado: aunque quisiéramos, no podríamos compartirlo) e Iris analiza correo personal.
  La organización comparte **plan y factura**, nada más. Todos los `assert_owned` y los
  filtros `user_id == current_user` del código actual se quedan **exactamente como están**.
- **No sustituye al ABAC.** El ABAC sigue diciendo *qué puede hacer* un usuario; el plan
  dice *cuánto*. Ver §5.
- **No reimplementa el limitador.** `shared/_endpoints.py` (Flask-Limiter) protege contra
  abuso por ráfaga y seguirá haciéndolo. Las cuotas son otra cosa: se miden por mes y
  cuestan dinero. No se mezclan.
- **No es un motor de reglas.** Un límite es un número (o `NULL` = ilimitado). Si algún
  día hace falta "3 escaneos salvo los martes", será otro documento.

---

## 2. Decisión de arquitectura: módulo nuevo `accounts`

Las tres piezas son **transversales**: las tocan Themis, Aegis, Iris, Acheron, Hygeia y
`users`. No son una herramienta, así que no llevan nombre de deidad — van con el resto
de módulos de infraestructura (`system`, `users`, `shared`, `infrastructure`, `tools`).

```
API/src/modules/accounts/
  endpoints.py       # plans_blp (/plans) + organizations_blp (/organizations)
  managers.py        # PlanManager, SubscriptionManager, QuotaManager, OrganizationManager
  repositories.py    # PlanRepository, SubscriptionRepository, UsageRepository,
                     # OrganizationRepository, InvitationRepository
  model.py           # Plan, PlanLimit, Subscription, Organization,
                     # OrganizationMember, OrganizationInvitation, UsageCounter
  schemas.py         # Marshmallow, claves JSON camelCase
  exceptions.py      # QuotaExceededError (402), PlanFeatureDisabledError (402), ...
  services/
    limits.py        # catálogo LimitKey + LimitSpec + registro de contadores de stock
    entitlements.py  # resolución "plan efectivo" (personal ∪ organización)
    invitations.py   # emisión/verificación de tokens de invitación
```

Registro en `run.py`, junto al resto:

```python
flask_smorest_api.register_blueprint(plans_blp,         url_prefix="/plans")
flask_smorest_api.register_blueprint(organizations_blp, url_prefix="/organizations")
```

Dos blueprints en un módulo es el patrón que ya usa `users` (`oauth_blp` + `users_blp`).

**Por qué en BD y no en `SecOpsConfig.json`:** los planes cambian sin desplegar, los
edita quien no toca código, y los límites tienen que poder consultarse en la misma
transacción que la cuota. `SecOpsConfig.json` se queda con lo que sí es configuración
de instancia: si el alta pública está abierta y cuánto duran los tokens (§10).

---

## 3. Modelo de datos

Siete tablas nuevas y tres columnas en `User`. Las de límites nacen **vacías a propósito**:
son el formulario que rellena el equipo.

### 3.1 `Plan` — el catálogo

| Columna | Tipo | Notas |
|---|---|---|
| `id` | Integer PK | |
| `code` | String(32) unique | `freemium`, `bronze`, `silver`, `gold` |
| `name` | String(64) | Nombre comercial |
| `tagline` | String(160) nullable | La línea de la tabla de precios |
| `rank` | Integer | Orden ascendente. El de menor `rank` público es el "más bajo" |
| `monthly_price_cents` | Integer default 0 | En céntimos, nunca en float |
| `org_addon_price_cents` | Integer default 0 | Sobrecoste del toggle de organización |
| `currency` | String(3) default `EUR` | |
| `is_public` | Boolean default True | Si se muestra en la web (permite planes a medida) |
| `is_default` | Boolean default False | El que recibe un usuario recién creado. **Exactamente uno** |
| `created_at` / `updated_at` | DateTime | `utcnow_naive` |

### 3.2 `PlanLimit` — la tabla que rellena el equipo

PK compuesta `(plan_id, limit_key, scope)`.

| Columna | Tipo | Notas |
|---|---|---|
| `plan_id` | FK `Plan.id` PK | |
| `limit_key` | String(64) PK | Una de `LimitKey` (§6.1) |
| `scope` | String(8) PK | `holder` = lo que obtiene quien contrata; `member` = lo que obtiene cada miembro de su organización |
| `value` | Integer nullable | `NULL` = ilimitado · `0` = no incluido · `n` = tope |
| `period` | String(8) | `month` · `day` · `stock` (ver §6.2) |

**Por qué filas y no una columna por característica:** añadir una herramienta medible
nueva es un `INSERT`, no una migración. Un `PlanLimit` que no existe se lee como `0`
(no incluido), así que el fallo es cerrado: una clave nueva no se regala por olvido.

### 3.3 `Subscription` — quién tiene qué

| Columna | Tipo | Notas |
|---|---|---|
| `id` | Integer PK | |
| `user_id` | FK `User.id` unique | Una suscripción viva por usuario |
| `plan_id` | FK `Plan.id` | |
| `status` | String(16) | `trialing`, `active`, `past_due`, `canceled` (§12.2) |
| `organization_enabled` | Boolean default False | **El toggle**: ortogonal al plan |
| `started_at` | DateTime | |
| `current_period_start` / `current_period_end` | DateTime nullable | Fin de vigencia. `NULL` = sin caducidad (el plan por defecto) |
| `cancel_at_period_end` | Boolean default False | Cancelada pero vigente hasta `current_period_end` |
| `grace_until` | DateTime nullable | Cortesía tras un impago (§12.4) |
| `external_customer_ref` / `external_subscription_ref` | String(64) nullable | Identificadores de la pasarela. Indexado el segundo |
| `external_event_at` | DateTime nullable | Marca del último evento aplicado — **idempotencia** (§12.6) |
| `assigned_by_user_id` | FK `User.id` nullable | Quién lo movió a mano (`NULL` = lo movió la pasarela) |
| `created_at` / `updated_at` | DateTime | |

Las cuatro columnas de pasarela (`external_*`, `cancel_at_period_end`, `grace_until`)
**no son huecos muertos**: el panel de root las usa desde el primer día para mover la
misma máquina de estados a mano. Ver §12.

El toggle de organización va aquí y no en `Plan` porque así lo describiste: *"puedes
aplicarlo a cualquiera de los planes"*. Bronze y "Bronze con organización" son la misma
fila de `Plan` con un booleano distinto en la suscripción; el tope de miembros lo da la
clave `organization.members` del plan (20/50/100).

### 3.4 `Organization` y `OrganizationMember`

```
Organization
  id, name (String 128), slug (String 64 unique),
  owner_user_id (FK User.id, unique), created_at, updated_at

OrganizationMember
  organization_id (FK, PK), user_id (FK, PK, además unique global),
  member_role (String 16: 'owner' | 'member'),
  invited_by_user_id (FK nullable), joined_at
```

`user_id` **unique global** en `OrganizationMember`: un usuario pertenece a lo sumo a una
organización. Es una restricción de BD, no una comprobación en Python (rung 4: que lo
imponga Postgres). Multi-organización no está pedido y multiplicaría la resolución de §4.

El dueño es miembro de su propia organización, con `member_role = 'owner'`. Así la
resolución de derechos y el recuento de miembros no necesitan un caso especial.

### 3.5 `OrganizationInvitation`

| Columna | Tipo | Notas |
|---|---|---|
| `id` | Integer PK | |
| `organization_id` | FK | |
| `email` | String(128) | Puede no corresponder a ningún `User` todavía |
| `token_hash` | String(128) unique index | **Se guarda el hash, nunca el token** (mismo criterio que `MFARecoveryCode`) |
| `status` | String(16) | `pending`, `accepted`, `revoked`, `expired` |
| `invited_by_user_id` | FK | |
| `created_user_id` | FK nullable | Si la invitación creó la cuenta |
| `expires_at`, `created_at`, `accepted_at` | DateTime | |

### 3.6 `UsageCounter` — el contador

PK compuesta `(holder_kind, holder_id, limit_key, period_start)`.

| Columna | Tipo | Notas |
|---|---|---|
| `holder_kind` | String(8) PK | `user` · `org` |
| `holder_id` | Integer PK | id del usuario o de la organización |
| `limit_key` | String(64) PK | |
| `period_start` | Date PK | Primer día del periodo, UTC |
| `used` | Integer default 0 | |

No hay job de reseteo: al cambiar el mes cambia `period_start` y nace una fila nueva.
La poda de filas viejas es un `DELETE ... WHERE period_start < now - 13 months`, si
algún día molesta.

### 3.7 Columnas nuevas en `User`

```python
email_verified_at             = Column(DateTime,     nullable=True)
email_verification_hash       = Column(String(128),  nullable=True)
email_verification_expires_at = Column(DateTime,     nullable=True)
must_change_password          = Column(Boolean,      nullable=False, default=False)
```

Tres columnas en vez de una tabla `EmailVerificationToken`: solo hay un token vivo por
usuario y no queremos histórico. `must_change_password` es necesario aparte porque
`password_changed_at IS NULL` ya significa otra cosa (nunca cambiada, incluidas las
cuentas antiguas).

---

## 4. Resolución de derechos: la regla

Es la parte que hay que entender bien; el resto es fontanería.

Un usuario tiene **dos fuentes** de derechos, y **nunca se anulan entre sí**:

1. Su **plan personal** (`Subscription` propia). Por defecto `freemium`. Es suyo.
2. Los derechos **derivados de su organización**, si pertenece a una: las filas
   `scope='member'` del plan del **dueño**, y solo si la suscripción del dueño está
   **vigente** (§12.3) y tiene `organization_enabled = True`.

Ninguna de las dos fuentes es una foto guardada: ambas se **calculan en cada lectura** a
partir del estado y las fechas de la suscripción. Esa decisión es la que sostiene todo
§12 — no hay ningún proceso que "aplique" una degradación, y por tanto ningún proceso
que pueda olvidarse de aplicarla.

```
límite_efectivo(usuario, clave) = max(
    plan_personal(usuario).holder[clave],
    plan_organización(usuario).member[clave],   # 0 si no pertenece a ninguna
)
# NULL (ilimitado) gana a cualquier número.
```

**Esto resuelve el debate que planteaste.** Entrar en una organización **no cancela ni
sustituye** el plan personal: un empleado sigue siendo Freemium *y además* tiene buzón
de Iris y bóveda ilimitada porque su empresa tiene Gold. Si además se compra un Bronze
para sus cosas, sube por `max()` en lo que Bronze le dé más, sin tocar nada de la
organización, y al salir de la empresa conserva su Bronze intacto. Ninguna cancelación
automática, ningún caso especial, ninguna sorpresa en la factura de nadie.

**Quién paga cada consumo.** Si el usuario pertenece a una organización, todo lo que el
plan de la organización cubre (`member[clave] > 0`) se carga a la **bolsa común**
(`holder_kind='org'`); lo que solo cubre su plan personal se carga a su contador
(`holder_kind='user'`). Una sola regla, incluido el dueño — que es miembro de su propia
organización y por tanto también consume de la bolsa.

```python
# accounts/services/entitlements.py  (esqueleto)

@dataclass(frozen=True)
class Entitlement:
    limit: int | None          # None = ilimitado
    period: str                # 'month' | 'day' | 'stock'
    holder_kind: str           # 'user' | 'org'  → a quién se le carga
    holder_id: int
    source: str                # 'personal' | 'organization'  → para explicarlo en la UI
```

`source` no es adorno: la vista "Mi plan" tiene que poder decir *"ilimitado, cortesía de
tu organización"*, porque de eso depende que el usuario entienda qué pierde si se va.

---

## 5. Encaje con el ABAC

No hay conflicto si se enuncia bien:

> **El ABAC es la llave; el plan es el techo.** Hacen falta las dos.

- `require_attributes` **no se toca**. Sigue decidiendo *qué operaciones* puede invocar
  un usuario, y sigue siendo el administrador quien concede o quita atributos.
- El plan decide *cuántas veces* y *si la característica está incluida*.
- Efectivo = `ABAC.permite(op)` **∧** `plan.límite(clave) > uso`.

Casos que aclaran la frontera:

| Situación | Resultado |
|---|---|
| Admin da `themis_create` a un Freemium | Puede crear escaneos, hasta agotar los del plan Freemium |
| Plan Gold pero sin `iris_create` | 403 del ABAC. El plan no regala permisos |
| Plan sin buzón de Iris (`iris.mailbox.connections = 0`) | 402, aunque tenga `iris_create` |
| `role_root` | Salta el ABAC (ya lo hace) **y** salta la cuota. Es la cuenta de operación |

**Las puertas de característica y los topes son el mismo mecanismo**: un `PlanLimit` con
`value = 0` es "no incluido en tu plan" y con `value = 25` es "tope 25". No hay dos
sistemas.

### 5.1 El plan NUNCA escribe atributos

Un usuario Freemium recién enrolado tiene **exactamente los mismos atributos** que uno
Gold. Lo que cambia es el número, no la llave.

La tentación es la contraria: "compra Gold → le metemos `themis_create`". No hacerlo, por
tres razones, y la tercera es la que importa de cara a la pasarela:

1. **Dos escritores en la misma tabla.** El plan y el administrador escribirían ambos en
   `UserAttribute`, y nadie sabría quién puso cada fila.
2. **La degradación no tiene vuelta.** Al caducar una suscripción habría que *quitar*
   atributos — y no hay forma de distinguir los que puso el plan de los que concedió un
   administrador a mano. Se borraría trabajo humano, que es justo lo que dijiste que
   querías conservar.
3. **El webhook de la pasarela se convierte en una reconciliación.** Con esta regla, el
   webhook de Stripe hace **un solo `UPDATE` idempotente sobre `Subscription`** y se acabó.
   Sin ella, tiene que calcular un conjunto de permisos, aplicarlo, revertirlo en un
   impago y volver a aplicarlo en el reintento. Ahí es donde estos sistemas se pudren.

> **Regla:** la suscripción la escribe el pago (o root a mano). Los atributos los escribe
> una persona. Nunca tocan la misma tabla.

**Y el reparto de papeles queda más limpio que ahora**, no más confuso:

| | Quién lo escribe | Qué responde |
|---|---|---|
| `Subscription` + `PlanLimit` | El pago | *Qué ha comprado esta cuenta* |
| `UserAttribute` | El admin, o el dueño de la organización | *Qué le deja hacer su jefe, dentro de lo comprado* |

Caso real: organización Gold con 40 empleados. Los 40 tienen los mismos atributos por
defecto; el responsable de seguridad le quita `themis_create` a 38 porque no quiere que
nadie lance escaneos por su cuenta. Los otros 2 sí pueden, y consumen de la bolsa común.
El plan no ha entrado en la conversación en ningún momento.

### 5.2 Dos arreglos previos en el ABAC (fase 0, bloquean todo lo demás)

Esta pregunta destapa dos cosas que hoy no se notan y que harían inviable el modelo:

**(a) Un usuario recién enrolado hoy no puede hacer nada.**
`ROLE_PERMISSIONS[Role.USER]` da lecturas, carpetas de Themis y Hygeia — pero **no** da
`acheron_create`, `iris_create`, `aegis_create` ni `themis_create`. Alguien que entre por
*"Regístrate gratis y prueba Ellysia"* no puede guardar una credencial ni analizar un
correo. El plan gratuito es inservible **independientemente** de las cuotas.

**(b) Lo que concede el rol no se puede quitar.**
`require_attributes` calcula `baseline | filas_explícitas`, y `remove_user_attributes`
solo borra filas. No hay tabla de denegación. Es decir: hoy un administrador **no puede**
revocarle `hygeia_delete` a un `role_user`, porque viene del baseline. Ahora no duele
porque el baseline es tacaño; en cuanto lo ampliemos para arreglar (a), el ABAC dejaría
de poder restringir nada — matando justo lo que el dueño de una organización necesita.

**El arreglo, pequeño y en fase 1:**

- Vaciar `ROLE_PERMISSIONS[Role.USER]`.
- Definir un **conjunto de atributos por defecto** y escribirlo como **filas explícitas
  de `UserAttribute`** en el momento del alta, sea el alta pública, la de un admin o la
  de una invitación.
- Una migración escribe esas filas a los usuarios existentes.

> **Implementado así** (fase 0, commit `refactor(users): los atributos ABAC pasan a ser
> filas explícitas`): el conjunto por defecto es
> `DEFAULT_USER_ATTRIBUTES = frozenset(AttributeType)` — **todos**, no un subconjunto de
> autoservicio como se escribió arriba. La razón la impone §11: Freemium incluye 3
> escaneos de Lybra y 2 píldoras de Aegis, así que una cuenta nueva necesita
> `themis_create` y `aegis_create` desde el primer minuto; y §5.1 ya decía que Freemium y
> Gold tienen el mismo llavero. Es seguro por construcción — cada endpoint filtra por
> `user_id` y lo peligroso lo guarda `require_role`. La migración concede ese mismo
> conjunto completo a los `role_user` existentes, para no dejar dos clases de cuenta
> conviviendo para siempre.

A partir de ahí el administrador puede **añadir y quitar de verdad**, y `ROLE_PERMISSIONS`
se queda solo con lo que de verdad es estructural (`Role.ADMIN`).

**En el cliente son dos mensajes distintos y ambos hacen falta:** `403` → *"tu
administrador no te ha concedido esto"*; `402` → *"tu plan no incluye esto"*. Con la
regla de §5.1, cada uno tiene una sola causa posible y se puede escribir sin ambigüedad.

**La única cosa que el plan sí "concede"** es el toggle de organización, y no es un
atributo: es `Subscription.organization_enabled`, que comprueba el endpoint de creación
(§8.1). Se queda ahí, fuera del ABAC.

**Código HTTP nuevo: `402 Payment Required`** para todo lo que corta el plan, distinto
del `403` del ABAC, para que el cliente pueda ofrecer "mejorar plan" en vez de "pide
permiso a tu administrador":

```json
{
  "error": "plan_limit",
  "error_description": "Has alcanzado el límite de escaneos de tu plan",
  "code": "PLAN_LIMIT_REACHED",
  "limit": { "key": "themis.lybra.scans", "value": 3, "used": 3,
             "period": "month", "resetsAt": "2026-09-01T00:00:00Z",
             "source": "personal" }
}
```

---

## 6. Motor de cuotas

### 6.1 Catálogo de claves

En `accounts/services/limits.py`, un `Enum` con la misma disciplina que `AttributeType`.
Propuesta inicial — **los números son de §11, aquí solo se declara qué se mide**:

| Clave | Periodo | Qué mide |
|---|---|---|
| `themis.lybra.scans` | month | Escaneos del motor propio |
| `themis.thirdparty.scans` | month | Nmap / Nikto / Nuclei |
| `themis.scheduled` | stock | Escaneos programados activos |
| `themis.reports.ai` | month | Informes redactados por IA |
| `aegis.pills` | month | Píldoras generadas |
| `aegis.campaigns` | month | Campañas lanzadas |
| `aegis.recipients` | stock | Destinatarios totales en listas |
| `iris.analyses` | month | Análisis de cabeceras |
| `iris.ai_summaries` | month | Resúmenes IA de un análisis |
| `iris.mailbox.connections` | stock | Buzones conectados |
| `acheron.vaults` | stock | Bóvedas |
| `acheron.items` | stock | Secretos guardados |
| `hygeia.assets` | stock | Agentes dados de alta (activos) |
| `ai.requests` | month | Techo global de peticiones a Scribe (paraguas) |
| `organization.members` | stock | Miembros de la organización |

`ai.requests` es un techo agregado *además* de los específicos: protege el coste de
OpenAI aunque un plan sea generoso en cada módulo por separado. Se consume a la vez que
la clave concreta.

### 6.2 Dos naturalezas, dos formas de contar

- **`month` / `day` (consumo):** hay contador (`UsageCounter`). Se incrementa y no baja.
- **`stock` (existencias):** **no hay contador**. Se cuenta la tabla real
  (`SELECT count(*) FROM Vault WHERE user_id IN (...)`). Un contador de stock se
  desincroniza en cuanto alguien borra algo; la BD ya sabe la respuesta (rung 4).
  Cada clave de stock declara su función de recuento en el registro:

```python
@dataclass(frozen=True)
class LimitSpec:
    key: LimitKey
    period: str
    label: str                                  # texto para la UI
    count_stock: Callable[[UnitOfWork, list[int]], int] | None = None
```

### 6.3 Consumo atómico

```python
# consumo (month/day) — la condición viaja en el UPDATE, no en Python
UPDATE "UsageCounter"
   SET used = used + :amount
 WHERE holder_kind = :kind AND holder_id = :id
   AND limit_key = :key AND period_start = :period
   AND (:limit IS NULL OR used + :amount <= :limit)
```

Si `rowcount == 0` → cuota agotada (o carrera perdida) → `QuotaExceededError`. Precedido
de un `INSERT ... ON CONFLICT DO NOTHING` para crear la fila del periodo. Postgres
serializa el `UPDATE`; no hace falta bloqueo en aplicación (rung 4 otra vez).

Para `stock`: `count(*)` y comparación, dentro del mismo `UnitOfWork` que la escritura.

### 6.4 Dónde se llama — la trampa

`QuotaManager.consume()` va en la **costura del manager**, no en el endpoint. Es
exactamente la lección que dejó el arreglo SSRF de OpenVAS documentado en `CLAUDE.md`:
si la validación vive solo en el endpoint HTTP, el flujo programado (`scheduling.py`
llama a `run_scan()` directamente) y las reejecuciones del worker RQ se la saltan.

```python
class LybraScanManager:
    @staticmethod
    def execute_lybra_scan(...):          # entrada picklable para RQ
        ...
    def _run_lybra_scan(self, user_id, ...):
        QuotaManager().consume(user_id, LimitKey.THEMIS_LYBRA_SCANS)   # ← aquí
        ...
```

El decorador `@enforce_quota(LimitKey.X)` existe solo como azúcar para **puertas de
característica** en endpoints sin manager propio (p. ej. conectar un buzón de Iris).

**Sin devolución.** Si la tarea falla después de consumir, la cuota se gastó. Es fallo
cerrado y es lo aburrido; si en pruebas resulta molesto, el gancho es un
`QuotaManager.release()` simétrico, pero no se escribe hasta que duela.

**Un guard único dentro de `consume()`** cubre el correo sin verificar (§7): si
`email_verified_at IS NULL` y la clave tiene coste, `EmailNotVerifiedError`. Una
comprobación, todos los sitios.

---

## 7. Alta pública (auto-enrolamiento)

`POST /users/sign-up` (admin) **se queda como está**. Se añade una ruta pública aparte,
porque las reglas son distintas: rol forzado, plan por defecto, límite de tasa mucho más
duro y verificación obligatoria.

```
POST /users/register            público · 5/hora/IP · 20/día
POST /users/verify-email        público · {token}
POST /users/verify-email/resend autenticado · 3/hora
```

Flujo:

1. Se crea el `User` con `role_user`, `email_verified_at = NULL`, y una `Subscription`
   al plan con `is_default = True` (la categoría más baja).
2. Herald manda el correo con `{PUBLIC_WEB_URL}/verificar?token=…`. El token se guarda
   **hasheado** en `User.email_verification_hash`.
3. Sin verificar, la cuenta **entra y navega**, pero `consume()` la corta en todo lo que
   cuesta dinero. Se puede enseñar en una demo sin esperar al correo, y no es un grifo
   abierto a cuentas desechables.
4. Los atributos ABAC iniciales son los que ya da `ROLE_PERMISSIONS[Role.USER]`. No se
   toca la matriz.

`general.registration.enabled` en `SecOpsConfig.json` permite cerrar el alta pública en
un despliegue on-premise. Es de las pocas cosas de este documento que sí son
configuración de instancia y no de negocio.

---

## 8. Organizaciones

### 8.1 Crear

`POST /organizations {name}` — requiere `Subscription.status == 'active'` **y**
`organization_enabled == True`. Un usuario puede ser dueño de una sola organización.

### 8.2 Invitar

`POST /organizations/<id>/invitations {email}`. Antes de nada, comprobar
`organization.members` contando miembros **más invitaciones pendientes** (si no, se
invita a 300 personas con un plan de 20 y el tope no sirve de nada).

Dos caminos:

- **El correo ya tiene cuenta en Ellysia** → invitación `pending` + correo con enlace de
  aceptación. **No cambia absolutamente nada hasta que acepta**: ni organización, ni
  plan, ni derechos. Es lo que decidiste, y además evita que un tercero le cambie a
  alguien su contexto sin permiso.
- **El correo no tiene cuenta** → se crea el `User` con contraseña aleatoria
  (`secrets.token_urlsafe`), `must_change_password = True`, `email_verified_at` puesto
  (el dueño de la organización responde por esa dirección), suscripción al plan por
  defecto, y **se une directo**. Se le mandan las credenciales y el cliente le obliga a
  cambiarlas en el primer acceso.

`POST /organizations/invitations/accept {token}` es **público**: el token es la única
identidad, igual que el quiz de Aegis. Un solo uso, expira (`general.registration
.invitationTtlHours`, por defecto 168 = 7 días).

### 8.3 Salir, expulsar, degradar

`DELETE /organizations/<id>/members/<user_id>` (el dueño) y `DELETE /organizations/mine`
(el propio miembro). En ambos casos:

- **Nunca se borra ningún dato.** El usuario conserva cuenta, bóveda, escaneos y su
  plan personal.
- Si al perder los derechos de la organización queda **por encima** de su límite personal
  (500 secretos guardados, plan personal de 25), entra en **modo excedido** (§12.5): esa
  clave pasa a solo lectura hasta que baje del tope. Puede leer, exportar y borrar.
  Es la misma regla que la bajada de plan y que la caducidad — una sola, para las tres.

El dueño no puede borrar su cuenta sin disolver o transferir la organización antes.

### 8.4 Lo que el dueño **no** ve

El dueño de la organización ve **consumo agregado** (quién ha gastado cuánto de la
bolsa) y la lista de miembros. **No ve los datos de sus miembros**: ni sus bóvedas
(imposible, es zero-knowledge), ni sus correos analizados, ni sus escaneos. Esto hay que
decirlo en la venta, no esconderlo: es una garantía, no una carencia.

### 8.5 Correos

Tres plantillas nuevas en `tools/herald/templates`: `org_invitation`, `org_credentials`,
`email_verification`. Añadir `accounts` a `tools.herald.modules` en `SecOpsConfig.json`
para que elija su estrategia como hace Aegis.

### 8.6 El dueño de organización **no** es un rol

La tentación es añadir `role_org_owner` a `Role` y asignarlo al contratar el toggle. No
hacerlo, por las mismas tres razones de §5.1 y una cuarta específica:

1. **`Role` es una escalera lineal, no un conjunto de sombreros.** `Role.hierarchy()` es
   una lista ordenada y `require_role` compara con `rank()`. ¿Dónde entra un dueño de
   organización? ¿Por encima de `role_user`? No manda sobre ningún usuario ajeno a su
   organización, y sigue sin poder tocar `/system`. Sea cual sea el peldaño, la
   comparación numérica da la respuesta equivocada en la mitad de los casos.
2. **La propiedad tiene ámbito; el rol no.** No es "un dueño", es "el dueño de la
   organización 7". Una columna en `User` no puede expresar *de qué*. El día que haya
   co-administradores o alguien traspase la organización, la columna miente.
3. **Habría que revocarlo.** Al cancelar el plan, al degradar a uno sin toggle, al
   traspasar la organización. Es exactamente la podredumbre que rechazamos en §5.1: el
   pago escribiendo identidad.
4. **Ya está en los datos.** Ser dueño es tener una fila: `Organization.owner_user_id
   == user.id`. No hace falta duplicar ese hecho en una segunda tabla que puede
   contradecirlo.

**Lo que sí se crea** es un decorador con ámbito, hermano del `assert_owned` que ya existe
en `shared/_ownership.py` — mismo criterio de no enumerar (idéntico error si la
organización no existe o si no es tuya):

```python
# accounts/services/ownership.py
def require_organization_owner(f):
    """Exige que el usuario autenticado sea dueño de la organización de la ruta.

    Se usa DESPUÉS de @require_oauth_token. Resuelve la propiedad contra la BD
    en cada llamada: no viaja en el JWT ni en una columna de User.
    """
```

Para las rutas sin id (`GET /organizations/mine`) la resuelve el manager desde el usuario.

**Lo que hay detrás de tu instinto sí es real**, y es esto: el dueño necesita **conceder y
retirar atributos a sus miembros** sin ser administrador de Ellysia. Hoy eso vive en
`UserManager.can_manage_user` ([managers.py:376](../../../API/src/modules/users/managers.py)),
que tiene tres únicos llamadores — los tres endpoints de atributos. Ahí se añade **una
cláusula**, no un rol:

| Actor | Puede gestionar |
|---|---|
| `role_root` | Todo |
| `role_admin` | Cualquier `role_user` |
| **Dueño de organización** | **Los `role_user` miembros de *su* organización** |
| Resto | Nadie |

Y los tres endpoints pasan de `require_role(Role.ADMIN)` a `require_oauth_token` a secas,
dejando a `can_manage_user` como **única autoridad**. Hoy hay dos puertas diciendo cosas
que se solapan y el 403 sale de la que dispare antes.

> ⚠️ **Trampa de escalada de privilegios.** `can_manage_user` empieza con
> `if actor_id == target_id: return True`. Hoy es inofensivo porque
> `require_role(Role.ADMIN)` filtra antes. **Si se quita ese decorador sin más, cualquier
> usuario podría concederse a sí mismo cualquier atributo.** El arreglo: dejar
> `can_manage_user` como está para las **lecturas**, y añadir un
> `can_administer_user(actor, target)` para las **escrituras** que devuelva `False` en el
> caso reflexivo salvo para root. Dos funciones con nombres honestos en vez de una con un
> booleano de modo.

**Fronteras del dueño.** Puede: invitar, revocar invitaciones, expulsar, conceder y
retirar atributos a sus miembros, y ver el consumo agregado de la bolsa. **No** puede:
ver los datos de sus miembros (§8.4), cambiarles el rol, tocar `/system`, `/users` global
ni `/queue`, ni gestionar a un `role_admin` que resulte ser miembro de su organización.

**No hace falta comprobar el techo del plan al conceder un atributo.** Si el dueño le da
`themis_create` a alguien y el plan de la organización tiene `themis.lybra.scans = 0`, el
miembro recibirá un 402 al intentarlo. Los dos sistemas se cruzan solos, que es justo lo
que promete §5. Ni una comprobación extra.

---

## 9. API REST

```
# Catálogo y estado
GET    /plans                             público   catálogo con límites (tabla de precios)
GET    /plans/me                          auth      plan efectivo + uso + origen de cada derecho
GET    /plans/me/usage                    auth      solo los contadores (para refrescar barras)

# Gestor de planes (root)
POST   /plans                             root
PUT    /plans/<id>                        root
PUT    /plans/<id>/limits                 root      reemplaza el conjunto de límites del plan
DELETE /plans/<id>                        root      solo si no hay suscripciones vivas

# Asignación (admin/root)
GET    /users/<id>/subscription           admin
PUT    /users/<id>/subscription           admin     {planCode, organizationEnabled, status}

# Organizaciones
POST   /organizations                     auth      requiere toggle
GET    /organizations/mine                auth      la propia (como dueño o miembro)
PUT    /organizations/<id>                dueño
GET    /organizations/<id>/members        dueño
DELETE /organizations/<id>/members/<uid>  dueño
DELETE /organizations/mine                miembro   salirse
POST   /organizations/<id>/invitations    dueño
GET    /organizations/<id>/invitations    dueño
DELETE /organizations/invitations/<id>    dueño      revocar
POST   /organizations/invitations/accept  público   {token}

# Atributos de un miembro — mismas rutas de siempre, nueva autoridad (§8.6)
GET    /users/<id>/attributes             admin · root · dueño (solo sus miembros)
PUT    /users/<id>/attributes             ídem, y nunca sobre uno mismo
DELETE /users/<id>/attributes             ídem

# Alta pública
POST   /users/register                    público
POST   /users/verify-email                público   {token}
POST   /users/verify-email/resend         auth
```

---

## 10. Frontend

### 10.1 Registro desde el umbral

En `LoginView.vue`, bajo el formulario: *"¿No tienes cuenta? Regístrate gratis y prueba
Ellysia"*. Reutiliza el estilo `portal` que ya está ahí; es un paso más del mismo
formulario (como ya se hace con el paso de MFA, `v-if="!mfaStep"`), no una vista nueva.

### 10.2 `AccountMenu.vue` — el punto que pediste

Hoy el desplegable de perfil vive **solo** en `LandingView.vue` (líneas 72-90) y las
demás vistas tienen o `SiteHeader` (avatar que solo enlaza a `/profile`) o `Topbar`
(píldora de sesión + Salir). Por eso las opciones no están en todas partes.

Extraer ese desplegable a `components/shared/AccountMenu.vue` y usarlo en los tres
sitios: `LandingView`, `SiteHeader` y `Topbar`. Entradas:

```
Perfil
Mi plan                      siempre
Mi organización              si es dueño o miembro
Crear organización           si tiene el toggle y no tiene ninguna
──────────
Usuarios · Configuración · Cola de tareas     admin/root
──────────
Cerrar sesión
```

Es un componente que ya existe escrito; solo está atrapado en una vista. Rung 2 del
ladder: no se escribe nada nuevo, se mueve.

### 10.3 Vistas nuevas

| Ruta | Vista | Acceso |
|---|---|---|
| `/planes` | Comparativa de planes (tabla de precios) | pública |
| `/mi-plan` | Plan efectivo, barras de uso, origen de cada derecho | auth |
| `/organizacion` | Miembros, invitar, revocar, expulsar, consumo agregado | dueño/miembro |
| `/admin/planes` | Gestor: CRUD de planes y sus límites, asignar plan a usuario | root |
| `/verificar` | Aterrizaje del enlace de verificación | pública |
| `/invitacion` | Aterrizaje del enlace de invitación | pública |

### 10.4 `accountStore.js` y el 402

Un store de Pinia con el plan efectivo y el uso, cargado tras el login. Y **un solo
punto** para el corte: `composables/useApi.js` ya centraliza el 401 y el refresco de
token; ahí mismo se traduce el 402 a un toast *"Has alcanzado el límite de tu plan"* con
enlace a `/planes`. No hay que tocar ni una vista.

---

## 11. Planes de ejemplo

Provisionales — la gracia de `PlanLimit` es que esto se cambia sin desplegar. Sirven
para tener algo enseñable el primer día. `∞` = `NULL`, `—` = `0` (no incluido).

### Ámbito `holder` (lo que obtiene quien contrata)

| Clave | Freemium | Bronze | Silver | Gold |
|---|---:|---:|---:|---:|
| `themis.lybra.scans` /mes | 3 | 25 | 100 | 400 |
| `themis.thirdparty.scans` /mes | — | 10 | 50 | 200 |
| `themis.scheduled` | — | 3 | 15 | 50 |
| `themis.reports.ai` /mes | 1 | 10 | 40 | 150 |
| `aegis.pills` /mes | 2 | 15 | 60 | 200 |
| `aegis.campaigns` /mes | — | 2 | 10 | 40 |
| `aegis.recipients` | — | 100 | 500 | 2000 |
| `iris.analyses` /mes | 10 | 100 | 500 | ∞ |
| `iris.ai_summaries` /mes | 2 | 25 | 100 | 400 |
| `iris.mailbox.connections` | — | 1 | 3 | 10 |
| `acheron.vaults` | 1 | 3 | 10 | ∞ |
| `acheron.items` | 25 | 250 | 1000 | ∞ |
| `hygeia.assets` | 1 | 10 | 40 | 150 |
| `ai.requests` /mes | 5 | 60 | 250 | 900 |
| `organization.members` | — | 20 | 50 | 100 |

### Ámbito `member` (lo que obtiene cada empleado de la organización)

Tu ejemplo, hecho tabla: el empleado sigue siendo Freemium en lo suyo, pero tiene buzón
de Iris y bóveda de verdad porque su empresa paga.

| Clave | Bronze | Silver | Gold |
|---|---:|---:|---:|
| `acheron.vaults` | 3 | 5 | ∞ |
| `acheron.items` | 250 | 1000 | ∞ |
| `iris.analyses` /mes | 50 | 200 | ∞ |
| `iris.mailbox.connections` | 1 | 2 | 3 |
| `iris.ai_summaries` /mes | 10 | 40 | 100 |
| `hygeia.assets` | 2 | 5 | 10 |

Todo lo que no aparece en `member` vale `0`: un empleado no lanza pentestings ni campañas
de concienciación por su cuenta. Eso es del responsable de seguridad, y encaja con el
ABAC (tampoco tendría `themis_create`).

**Precios de partida:** Freemium 0 · Bronze 29 € · Silver 79 € · Gold 199 € al mes, con
el toggle de organización en +20 / +50 / +120 €. Números para tener algo en la tabla de
precios, no una decisión comercial.

**Semilla:** en una **migración Alembic de datos**, no en `_init_db()`. `_init_db()` solo
corre con `CREATE_DATABASE=True` (destructivo, primer despliegue); un entorno ya
desplegado se quedaría sin planes y todo el mundo sin suscripción.

> **Corregido en la fase 1.** Aquí decía que la migración debía crear una `Subscription`
> al plan por defecto para todos los usuarios existentes. No hace falta, y meterla era
> peor: **la ausencia de fila significa "plan por defecto"**, exactamente igual que una
> suscripción caducada. El camino de respaldo tiene que existir de todos modos (§12.3),
> así que el backfill sería un segundo mecanismo para el mismo resultado — y obligaría a
> acordarse de crear la fila en los tres caminos de alta (admin, público, invitación),
> con un cuarto esperando a que alguien lo añada. `Subscription` solo tiene fila cuando
> alguien ha comprado o se le ha asignado algo.

---

## 12. Ciclo de vida de una suscripción

Esta sección es la que hace que la pasarela sea, el día que llegue, un trabajo de días y
no de meses. Se implementa **entera ahora**, movida a mano desde el panel de root.

### 12.1 El puerto: `SubscriptionManager`

La pasarela no habla con la base de datos. Habla con **seis operaciones de intención**, y
un adaptador traduce sus eventos a ellas. Ningún concepto de Stripe (ni de Paddle, ni de
Redsys) entra en `managers.py`: aquí no existen las palabras *invoice*, *checkout session*
ni *price id*.

```python
class SubscriptionManager:
    def activate(self, user_id, plan_code, *, organization_enabled=False,
                 period_end=None, external_refs=None, actor_id=None) -> Subscription:
        """Alta, renovación o cambio de plan. Idempotente. El caso de uso del 'pago OK'."""

    def start_trial(self, user_id, plan_code, *, ends_at) -> Subscription: ...

    def mark_past_due(self, user_id, *, grace_until) -> Subscription:
        """Impago. No degrada nada todavía: abre la ventana de cortesía."""

    def cancel(self, user_id, *, immediate=False, actor_id=None) -> Subscription:
        """Baja. Por defecto al final del periodo pagado."""

    def resume(self, user_id) -> Subscription:
        """Deshace una cancelación pendiente, o un past_due tras cobrar."""

    def expire(self, user_id) -> Subscription:
        """Fin de vigencia: la cuenta vuelve al plan por defecto."""
```

Ese es **todo** el vocabulario. Si un evento de la pasarela no encaja en una de las seis,
la respuesta correcta es ignorarlo, no añadir una séptima.

**Y son dos clientes del mismo puerto, no dos caminos:**

```
Panel de root (fase 6)  ─┐
                         ├─→  SubscriptionManager  ─→  Subscription  ─→  entitlements
Adaptador de pasarela  ──┘         (el puerto)          (una tabla)      (todo lo demás)
   (fase futura)
```

Consecuencia práctica: **la máquina de estados se prueba hoy, sin pasarela**. Un test
llama a `mark_past_due()` y comprueba el plan efectivo. El día del webhook, lo único sin
probar es el adaptador.

### 12.2 Estados

```
        start_trial            activate
   ∅ ──────────────→ trialing ──────────→ active ←──────────┐
   │                    │                  │  │             │ resume
   │  (alta pública)    │ expire           │  │ mark_past_due
   ├──→ [plan default]  ↓                  │  └────────→ past_due
   │                  expirada             │                 │ expire
   │                                       │ cancel          ↓
   └───────────────────────────────────────┴──────→ canceled ──→ [plan default]
```

- **`trialing`** se comporta **exactamente** como `active` a efectos de derechos. La única
  diferencia es lo que dice la UI y que su final llama a `expire()`, no a `mark_past_due()`.
- **`canceled` no significa "cortado"**: significa "no se va a renovar". Mientras
  `current_period_end` esté en el futuro, el usuario sigue disfrutando lo que pagó.
- Nadie vuelve a `∅`. Se vuelve al plan por defecto, que es un estado con derechos, no la
  ausencia de suscripción.

### 12.3 Vigencia: la única función que importa

Todo lo anterior se reduce a una pregunta que `entitlements.py` hace en cada lectura:

```python
def is_effective(subscription, now) -> bool:
    """¿Esta suscripción concede derechos ahora mismo?"""
    if subscription.status in ("active", "trialing"):
        return subscription.current_period_end is None or now < subscription.current_period_end
    if subscription.status == "past_due":
        return subscription.grace_until is not None and now < subscription.grace_until
    if subscription.status == "canceled":
        return subscription.current_period_end is not None and now < subscription.current_period_end
    return False
```

Si devuelve `False`, el plan efectivo del usuario es **el plan por defecto**. No hay más.

> **No hay job de degradación, y es deliberado.** La alternativa —un cron nocturno que
> recorra suscripciones caducadas y las "baje"— es la que se usa en todas partes y la que
> falla en silencio: el día que el cron no corre, hay gente con Gold gratis y nadie se
> entera. Aquí la caducidad es aritmética de fechas en el momento de leer; que el
> servidor se caiga un fin de semana no regala nada a nadie.
>
> Sí hay trabajo programado, pero solo para **avisar** (correo de "tu plan caduca el 3",
> "no hemos podido cobrar"). Que ese job falle cuesta un correo, no dinero.

### 12.4 Los casos, uno a uno

| Suceso | Operación | Qué cambia en BD | Qué nota el usuario |
|---|---|---|---|
| **Pago correcto (alta)** | `activate(plan, period_end)` | `plan_id`, `status='active'`, `current_period_*`, `external_*` | Límites nuevos en la siguiente petición |
| **Renovación correcta** | `activate(…)` con nuevo `period_end` | Solo las fechas | Nada. Es el caso silencioso y debe serlo |
| **Subida de plan** | `activate(plan_superior)` | `plan_id` | Inmediato. Los contadores **no se resetean**: 40 gastados de 100 pasan a ser 40 de 400 |
| **Bajada de plan** | `activate(plan_inferior)` | `plan_id` | Inmediato, sin devolver nada. Si ya gastó por encima del nuevo tope → **modo excedido** (§12.5) |
| **Impago** | `mark_past_due(grace_until)` | `status`, `grace_until` | Sigue funcionando durante la cortesía, con aviso visible |
| **Cobro tras el impago** | `resume()` | `status='active'`, `grace_until=NULL` | Desaparece el aviso |
| **Fin de la cortesía** | `expire()` | `status='canceled'` | Cae al plan por defecto |
| **Baja voluntaria** | `cancel()` | `status='canceled'`, `cancel_at_period_end=True` | **Sigue igual hasta fin de periodo**. Es lo que ha pagado |
| **Se arrepiente** | `resume()` | `status='active'`, `cancel_at_period_end=False` | Como si nada |
| **Devolución / contracargo** | `cancel(immediate=True)` | `status='canceled'`, `current_period_end=now` | Cae al plan por defecto al instante |
| **Fin del trial** | `expire()` | `status='canceled'` | Cae al plan por defecto |

**La cortesía por impago no es blandura comercial, es defensa.** Una tarjeta caducada es
mucho más frecuente que un moroso, y cortarle Hygeia a alguien porque su banco rechazó un
cargo el martes es cortarle la monitorización de sus servidores. Valor por defecto
sugerido: **7 días**, en `general.billing.gracePeriodDays`.

### 12.5 Modo excedido: la regla única de degradación

Al bajar de plan, al salir de una organización (§8.3) o al caducar una suscripción, un
usuario puede quedar **por encima** de un límite: 500 secretos con un tope nuevo de 25.

> **Nunca se borra nada. Nunca se bloquea el acceso. La clave excedida pasa a solo
> lectura hasta que baje del tope.** Puede leer, exportar y borrar; no puede crear más.

Una sola regla para las tres situaciones, y la única defendible: los datos son del
usuario, y borrarlos por un impago sería indefendible tanto legal como comercialmente.
Para las claves de consumo (`month`) no hay nada que hacer — el contador se resetea solo
al cambiar de periodo.

`GET /plans/me` marca esas claves con `"exceeded": true` para que la UI pueda decir
*"tienes 500 de 25 — no puedes añadir más hasta liberar espacio"* en vez de un error seco.

### 12.6 Idempotencia y desorden

Toda pasarela reintenta y toda pasarela entrega eventos desordenados. Dos mecanismos,
ninguno caro:

1. **Idempotente por construcción.** Las seis operaciones escriben un estado absoluto
   (`SET plan_id=…, status=…, current_period_end=…`), nunca un delta. Aplicar dos veces
   el mismo evento da el mismo resultado.
2. **`external_event_at`.** Se descarta cualquier evento cuya marca de tiempo sea anterior
   a la última aplicada. Una columna mata el desorden y la duplicación.

```python
if event.occurred_at <= (subscription.external_event_at or MIN_DATETIME):
    return subscription      # evento viejo o repetido: ignorar, no es un error
```

> `ponytail:` una columna en vez de una tabla `WebhookEvent`. El techo es que no se puede
> auditar ni reproducir el historial de eventos. El día que haga falta (una disputa de
> cobro, normalmente), la salida es un ledger `WebhookEvent(external_id unique, payload,
> received_at, applied_at)` con `external_id` como clave de deduplicación — y las seis
> operaciones siguen igual.

### 12.7 Qué NO puede hacer un pago

El resumen de todo el documento, en cinco líneas. Un pago —hoy a mano, mañana por
webhook— escribe **`Subscription` y nada más**. En concreto **no** puede:

- escribir en `UserAttribute` (§5.1) — el impago borraría permisos concedidos a mano;
- cambiar `User.role` (§8.6) — la propiedad de una organización es una fila, no un rango;
- crear ni borrar una `Organization` (§12.8);
- tocar `UsageCounter` — lo consumido, consumido está; pagar más sube el techo, no borra
  el historial;
- borrar datos de nadie, nunca (§12.5).

### 12.8 El caso feo: una organización cuyo dueño deja de pagar

Gold con 40 miembros, la suscripción caduca. Qué pasa exactamente:

- La `Organization` y sus 40 `OrganizationMember` **siguen existiendo**. Borrarlas dejaría
  huérfanas las invitaciones y haría irreversible un problema que suele ser una tarjeta
  caducada.
- Los 40 conservan cuenta, datos y su **plan personal** intacto (§4: nunca se sustituyó).
- Pierden los derechos `scope='member'`. Lo que quede por encima de su plan personal entra
  en **modo excedido**, no se borra.
- El dueño **no puede invitar** a nadie más mientras la suscripción no esté vigente.
- El día que paga, `activate()` y **todo vuelve solo**. No hay nada que reconstruir,
  porque no se destruyó nada.
- **Solo se avisa al dueño.** Los 40 empleados no reciben un correo diciendo que su jefe
  no ha pagado; verán en la UI que ciertas funciones ya no están disponibles. No es
  nuestro mensaje que dar.

### 12.9 Lo que la UI necesita saber

`GET /plans/me` devuelve, además de los límites y el uso:

```json
{
  "plan": { "code": "gold", "name": "Gold" },
  "status": "past_due",
  "isEffective": true,
  "currentPeriodEnd": "2026-09-01T00:00:00Z",
  "cancelAtPeriodEnd": false,
  "graceUntil": "2026-08-13T00:00:00Z",
  "organizationEnabled": true
}
```

Con eso el cliente escribe los tres avisos que hacen falta y ni uno más: *"hay un problema
con tu pago, tienes hasta el 13"*, *"tu plan termina el 1 de septiembre"* y *"has superado
el límite de tu plan"*. Los tres salen de datos, no de adivinar.

---

## 13. Fases

| # | Fase | Contenido | Deja funcionando |
|---|---|---|---|
| 0 | **Saneado del ABAC** | §5.2: vaciar `ROLE_PERMISSIONS[Role.USER]`, conjunto de atributos por defecto en el alta, migración para los existentes | El admin puede quitar atributos de verdad; un usuario nuevo puede usar el producto |
| 1 | **Esqueleto** | Módulo `accounts`, siete tablas, migración + semilla de los cuatro planes, `GET /plans`, `GET /plans/me`. **Sin enforcement.** | Se ve el plan de cada uno; no corta nada |
| 2 | **Motor de cuotas** | `limits.py`, `entitlements.py`, `QuotaManager`, 402, tests. Cableado en **tres claves** primero: `themis.lybra.scans`, `ai.requests`, `hygeia.assets` | El corte funciona de verdad en lo que más cuesta |
| 3 | **Resto del cableado** | Las 12 claves restantes en sus managers | Cobertura completa |
| 4 | **Alta pública** | `/users/register`, verificación por correo, plantilla Herald, guard en `consume()` | Un desconocido se registra solo |
| 5 | **Organizaciones** | Tablas ya creadas en la 1; managers, invitaciones, correos, aceptación, expulsión, solo-lectura al degradar | La venta a PYME es contable |
| 6 | **Ciclo de vida** | Las seis operaciones de §12.1, `is_effective()`, modo excedido, `external_event_at`, avisos por correo. **Sin pasarela**: el driver es el panel | La máquina de estados de cobro, entera y probada, movida a mano |
| 7 | **Gestor de planes** | `PUT /plans/<id>/limits`, `PUT /users/<id>/subscription`, vista `/admin/planes` con las seis operaciones como botones | El equipo rellena los números y mueve suscripciones sin tocar código |
| 8 | **Frontend transversal** | `AccountMenu` compartido, `/planes`, `/mi-plan`, `/organizacion`, registro en el login, 402 y los tres avisos de §12.9 en `useApi` | Presentable |
| — | *(futuro)* | Checkout + portal de cliente + **adaptador** de webhooks a las seis operaciones | Cobro real |

Las fases 1-2 son la mitad del valor: en cuanto el plan se ve y el corte funciona en la
IA y en Lybra, se puede enseñar sin miedo a la factura de OpenAI.

**La fase 6 es la que compra el futuro.** Al terminarla, la pasarela no necesita diseño:
necesita un adaptador que traduzca sus eventos a seis llamadas ya escritas y ya probadas.
Y hasta entonces, root mueve esas mismas seis operaciones desde un panel — que es
exactamente lo que hace falta para una demo comercial y para el primer cliente real
cobrado por transferencia.

---

## 14. Cosas que muerden

- **Ningún job puede ser la razón por la que alguien pierde derechos** (§12.3). Si en
  algún momento alguien propone "un cron que degrade las suscripciones caducadas",
  significa que la vigencia dejó de calcularse al leer — y el día que ese cron no corra,
  habrá cuentas con Gold gratis y nadie se enterará.
- **`cancel()` no corta.** Corta `expire()`. Confundirlos es quitarle a un cliente lo que
  ya ha pagado el día que pulsa "darme de baja", y es el tipo de error del que uno se
  entera por Twitter.
- **Los eventos de pasarela llegan repetidos y desordenados**, siempre. Sin
  `external_event_at` (§12.6), una renovación que llega después de un impago deja la
  suscripción marcada como impagada.
- **`can_manage_user(a, a)` devuelve `True`.** Al quitar `require_role(Role.ADMIN)` de los
  endpoints de atributos (§8.6), esa línea se convierte en autoconcesión de permisos. Es
  el fallo más caro de todo el documento y cabe en un test: *"un `role_user` no puede
  darse `themis_create` a sí mismo"*.
- **El pago no escribe `UserAttribute`, jamás** (§5.1). El día que entre la pasarela, su
  webhook toca una tabla y una sola: `Subscription`. Si alguien "optimiza" esto
  concediendo atributos al comprar, el impago y el reintento se llevan por delante los
  permisos que un administrador concedió a mano.
- **No metas el plan en el JWT.** Es tentador (evita una query) y es el mismo error que
  ya corrigió S9 con el rol: un cambio de plan tardaría hasta `access_token_expiry_minutes`
  en surtir efecto, y el usuario que acaba de pagar seguiría cortado. Se revalida contra
  BD, y solo en endpoints de escritura.
- **El `consume()` en el endpoint no basta.** `scheduling.py` llama a `run_scan()`
  directamente y el worker RQ reejecuta desde `execute_*`. Va en el manager (§6.4).
- **Fila de `PlanLimit` ausente = 0, no ilimitado.** Fallo cerrado. Al añadir una clave
  nueva hay que acordarse de rellenarla en todos los planes o queda deshabilitada — que
  es exactamente lo que queremos que pase cuando se olvida.
- **Contadores de stock, jamás.** Se cuenta la tabla real. Un contador de existencias se
  desincroniza en el primer borrado.
- **Un usuario ≠ una organización.** El `unique` de `OrganizationMember.user_id` lo
  impone Postgres, no un `if` en Python.
- **Sin fila en `Subscription` = plan por defecto.** No hay backfill ni hook en el alta, a
  propósito (§11). Quien escriba un `JOIN` contra `Subscription` dando por hecho que todo
  usuario tiene fila contará de menos; el `activate()` de la fase 6 hace *upsert* por
  `user_id`, que es lo que ya tenía que hacer para ser idempotente.
- **`CREATE_DATABASE=True` sigue siendo destructivo.** La semilla va en Alembic.
- **Periodos en UTC naive**, primer día del mes, con `utcnow_naive()` como el resto del
  proyecto. Nada de zonas horarias por usuario en la v1.
- **Borrar un usuario dueño de organización**: prohibido sin disolver o transferir antes.
- Si acaba habiendo bloques nuevos en `SecOpsConfig.json` (`general.registration`),
  registrarlos en `CONFIG_BLOCKS` de `tests/unit/test_config_shape.py` y actualizar la
  ruta literal en `web/app/src/views/ConfigView.vue` — los tres sitios de siempre.

---

## 15. Decisiones tomadas y preguntas que quedan

**Tomadas** (de la conversación de arranque):

1. Bolsa de consumo **común por organización**, no por miembro.
2. Un usuario existente invitado **debe aceptar** por enlace; y **nunca cambia de plan**:
   los derechos de la organización se **suman** a los suyos por `max()` (§4).
3. Alta pública **con verificación de correo** por enlace, no bloqueante para entrar pero
   sí para consumir.
4. **Sin pasarela de pago** en este alcance — pero **con el ciclo de vida completo**
   (§12), movido a mano desde el panel de root. La pasarela será un segundo cliente del
   mismo puerto, no un rediseño.
5. **El plan nunca escribe atributos** (§5.1) y **el pago nunca escribe identidad**
   (§8.6, §12.7). `Subscription` la escribe el cobro; `UserAttribute` la escribe una
   persona; `Organization` la escribe el dueño. Tres tablas, tres autores, sin solape.
6. **Ser dueño de una organización no es un rol**, es una fila (§8.6). El ABAC se sanea
   antes (fase 0) para que `can_manage_user` pueda ser la única autoridad.
7. **Nada se borra nunca por dinero.** Bajada de plan, impago, salida de una organización
   y caducidad convergen en la misma regla: **modo excedido** (§12.5), solo lectura hasta
   volver bajo el tope.

**Abiertas, para el equipo:**

- **Los números de §11.** Están puestos para que haya algo enseñable; hay que revisarlos
  con el coste real de OpenAI y de los escaneos delante.
- **`acheron.vaults` promete algo que el esquema no permite.** La tabla de precios vende
  3 bóvedas en Bronze, 10 en Silver e ilimitadas en Gold, pero `Vault.user_id` es
  `UNIQUE`: hoy nadie puede tener más de una. Al cablear la clave (fase 3) el tope quedó
  funcionando como una **puerta** — `0` es "tu plan no incluye Acheron" y cualquier valor
  ≥ 1 es "sí" — que es coherente pero no es lo que dice la tabla. Hay que elegir: o
  Acheron pasa a admitir varias bóvedas por usuario (cambio de modelo y de cliente, que
  es quien cifra), o §11 deja de venderlas y la clave se documenta como puerta.
- **¿El dueño puede lanzar acciones "en nombre de" un miembro?** (p. ej. un escaneo que
  aparece en el histórico del empleado). Recomendación: **no** en la v1 — abre la puerta
  a que el dueño toque datos ajenos, que es justo lo que §8.4 promete que no pasa.
- **¿La bolsa común necesita un sub-límite por miembro?** Descartado para la v1 (un
  campo más en `PlanLimit` y lógica de doble tope). El riesgo real —un empleado se come
  la bolsa del mes— se mitiga primero enseñando el consumo por miembro en
  `/organizacion`; si duele, entonces se añade `member_cap`.
- **¿Trial?** `Subscription.status = 'trialing'` está en el modelo y `start_trial()` en el
  puerto, pero nadie los llama. Un "14 días de Silver al registrarte" es media hora de
  trabajo cuando se quiera.
- **¿Cuántos días de cortesía tras un impago?** Propuestos 7 (§12.4). Es un número
  comercial, no técnico: cuanto más largo, menos clientes perdidos por una tarjeta
  caducada y más margen para el que no piensa pagar.
- **¿Ellysia calcula dinero alguna vez?** Recomendación firme: **no**. Ni prorrateos al
  subir de plan, ni cálculo de importes, ni impuestos. `monthly_price_cents` existe para
  **pintar la tabla de precios**, no para cobrar. Cuando entre la pasarela, el dinero lo
  calcula ella y nosotros solo recibimos "esta cuenta tiene derecho a este plan hasta esta
  fecha". Es la diferencia entre integrar una pasarela y escribir un facturador.
- **Nombre del módulo.** `accounts` sigue el criterio de los transversales (`users`,
  `system`, `shared`). Si preferís mantener el hilo griego incluso aquí, `Plutos`
  (Πλοῦτος, la riqueza) sería el candidato — pero rompería la separación deidad =
  herramienta que hoy es muy legible.
