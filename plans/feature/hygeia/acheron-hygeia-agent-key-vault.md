# Guardar la clave de agente de Hygeia en la bóveda de Acheron

## Contexto

Idea propuesta por el usuario: permitir que la `agentKey` que Hygeia emite al dar de alta (o rotar) un `MonitoredAsset` se pueda guardar directamente en la bóveda cifrada de Acheron, en vez de que el usuario tenga que copiarla y guardarla por su cuenta. Se plantea como posible reclamo de venta ("ecosistema unificado"), no como una necesidad funcional reportada por ningún flujo roto.

Tras varias vueltas de diseño, la decisión de arquitectura clave es la **dirección de la dependencia**: es `MonitoredAsset` (Hygeia) quien apunta a una `ApiKey` (Acheron), nunca al revés. Este documento recoge el diseño final con esa dirección — sustituye cualquier planteamiento anterior en el que `ApiKey` conociera a Hygeia.

Este documento es un análisis de viabilidad con diseño técnico concreto, no una decisión de construir la funcionalidad ya — sirve para dejar registrada la idea si en algún momento se decide abordarla.

## Estado actual verificado

- **Acheron** (`API/src/modules/features/acheron`) es zero-knowledge de verdad: el cifrado ocurre en el cliente (Web Crypto), el servidor solo persiste blobs cifrados + parámetros KDF (`model.py: Vault`). Los tipos de secreto soportados están centralizados en `storable_specs.py` (`STORABLE_SPECS`): `account`, `creditcard`, `securenote`, `identity`, `bankaccount`, `wifi`, `license` — ninguno modela bien una API key tipo `keyId.secreto`. `managers.py`/`endpoints.py` iteran ese registro; añadir un tipo nuevo no requiere dispatch nuevo.
- **Hygeia** (`API/src/modules/features/hygeia`) emite la `agentKey` en claro **una sola vez**, en la respuesta de `HygeiaAssetManager.create_asset` (`managers.py:48-88`) y `rotate_key` (`managers.py:162-185`). El servidor solo persiste `agent_key_id` (prefijo público) + `agent_key_hash` (Argon2id) — el secreto en claro es irrecuperable tras esa respuesta, igual que la master password de Acheron.
- **Frontend** (`web/app/src/stores/hygeiaStore.js:9-11,45-57,70-79`): la clave en claro se guarda solo en memoria del store (`state.lastAgentKey`), se muestra una vez en un modal y se descarta con `clearAgentKey()`; nunca se vuelve a pedir al servidor. Este es exactamente el punto de la UI donde encaja el botón "Guardar en la bóveda".
- No existe ningún acoplamiento entre módulos a día de hoy: `hygeia/managers.py` no importa nada de `acheron`. La convención del proyecto (`CLAUDE.md`) es que cada módulo accede a datos solo vía su propio `UnitOfWork`/repositorio.

## Decisión de diseño: dirección de la dependencia

Se descartó explícitamente la opción de que `ApiKey` (Acheron) tuviera una FK a `MonitoredAsset` (Hygeia). Motivo: eso obligaría a Acheron — el módulo genérico, reutilizable por cualquier otra parte de la plataforma — a conocer la existencia de un módulo de negocio concreto. Rompe la dirección natural de dependencia (lo genérico no debe depender de lo específico) y contamina el modelo de Acheron con semántica ajena.

**Diseño elegido:** `MonitoredAsset.apikey_id` es una FK opcional (`nullable=True`) hacia `Storable.id`. Es Hygeia quien "opta-in" a usar el vault como almacén de credenciales; Acheron no sabe que Hygeia existe.

```python
# acheron/model.py — SIN CAMBIOS DE FORMA, solo un tipo nuevo
class ApiKey(Storable):
    __tablename__ = "ApiKey"
    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)
    label = Column(String(512), nullable=False)      # p.ej. hostname del asset
    value = Column(String(512), nullable=False)       # el secreto cifrado
    issued_by = Column(String(255), nullable=True)    # p.ej. "Hygeia", opcional y genérico
    __mapper_args__ = {"polymorphic_identity": "apikey"}
```

```python
# hygeia/model.py — una columna nueva en MonitoredAsset
apikey_id = Column(Integer, ForeignKey("Storable.id"), nullable=True)
```

Consecuencias de esta dirección:
- Acheron sigue siendo 100% independiente y reutilizable — el tipo `apikey` no tiene ni idea de quién lo usa.
- Hygeia controla el ciclo de vida del vínculo: es quien decide cuándo crear, sustituir o borrar la `ApiKey` asociada a un asset, nunca al revés.
- El acoplamiento es una única FK opcional, documentada, y reversible sin purgar datos de Acheron (quitar la columna no invalida nada en el vault).

## Flujo completo: alta de asset y guardado en la bóveda

1. Usuario crea un activo desde la SPA → `POST /hygeia/assets` (`hygeia_blp` en `endpoints.py:53-75`). El backend genera `agentKey` en claro (una vez) y la fila persiste solo el hash.
2. El store (`hygeiaStore.js:createAsset`) guarda `state.lastAgentKey` y el asset se añade a la lista.
3. El modal de "clave creada" muestra la clave junto al botón habitual "Copiar" y uno nuevo: **"Guardar en la bóveda"**.
4. Al pulsarlo, si el vault de Acheron está bloqueado, se pide la master password (flujo ya existente de Acheron) y se deriva la `vaultKey` en cliente.
5. El frontend cifra un `Storable` de tipo `apikey` (label = hostname, value = `agentKey`, issuedBy = "Hygeia") y llama al endpoint existente de creación de storables de Acheron (`POST /acheron/vault` o el endpoint de storable individual, según lo que exponga `endpoints.py` en el momento de implementar — hoy el alta de storables va vía upsert de vault completo; conviene revisar si se necesita un endpoint de creación incremental de un único storable antes de dar esto por hecho).
6. Acheron responde con el `id` del `Storable` creado.
7. El frontend llama `PATCH /hygeia/assets/{id}` con `{"apikeyId": storableId}` para completar el vínculo (endpoint nuevo, ver más abajo).
8. Hygeia persiste `asset.apikey_id = storableId`. Listo — el vínculo vive solo en Hygeia.

**Importante:** en ningún paso Hygeia desencripta nada de Acheron. El único dato que cruza de Acheron hacia Hygeia es el `id` (entero) del storable creado, nunca su contenido.

## Cambios necesarios

### Acheron (`API/src/modules/features/acheron`)
- `model.py`: clase `ApiKey(Storable)` nueva, tal como arriba.
- `storable_specs.py`: entrada `"apikey": StorableSpec(ApiKey, "apikeys", (("label","label"), ("value","value"), ("issued_by","issuedBy")))`.
- Migración Alembic (`alembic revision --autogenerate -m "add ApiKey storable type"`).
- Sin cambios en `managers.py`/`endpoints.py`: ya iteran `STORABLE_SPECS`.

### Hygeia (`API/src/modules/features/hygeia`)
- `model.py`: columna `apikey_id = Column(Integer, ForeignKey("Storable.id"), nullable=True)` en `MonitoredAsset`. Requiere que `hygeia/model.py` importe el modelo `Storable` de Acheron (única dirección de import: Hygeia → Acheron, nunca al revés).
- `managers.py`: **el acceso a los datos de Acheron va vía `VaultManager` (`acheron/managers.py`), nunca vía `StorableRepository` directamente.** Hay precedente exacto de este patrón en el propio módulo: `HygeiaNotifyManager._run_notify` ya importa y usa `UserManager` de `users/managers.py` en lugar de tocar su repositorio. Ventajas concretas de usar el manager aquí:
  - `VaultManager.get_storable(storable_id)` ya resuelve la comprobación de propiedad (filtra por los storables del vault del usuario activo internamente, en `find_storables`) — Hygeia no tiene que reimplementar esa validación.
  - `VaultManager.delete_storable(storable_id)` abre su propio `UnitOfWork`, pero en contexto HTTP `__exit__` es un no-op (el commit real lo hace `teardown_request`) — anidar `with UnitOfWork()` de Hygeia con una llamada a un método de `VaultManager` que abre el suyo propio sigue siendo una única transacción atómica de request. No aplica igual en contexto de background job; `rotate_key`/`delete_asset` solo se invocan desde endpoints, así que no es un problema aquí.
  - Pendiente de decidir al implementar: `VaultManager` lanza `ValueError`/`PermissionError` genéricos, no excepciones del dominio de Hygeia. Hay que traducirlas (no dejar que un error interno de Acheron se filtre tal cual en la respuesta de un endpoint de Hygeia).

  **Encapsulación de excepciones:** `VaultManager` es de otro módulo y lanza sus propias excepciones (`ValueError`, `PermissionError` — genéricas, no tipadas por dominio como en Hygeia). Estas **nunca deben propagarse tal cual** fuera de `HygeiaAssetManager`: filtrarían detalles internos de Acheron en la respuesta de un endpoint de Hygeia, y romperían el contrato de que `handle_exceptions(default_exception=HygeiaError, ...)` en `endpoints.py` solo espera excepciones de la jerarquía `HygeiaError`. Se añade una excepción nueva en `hygeia/exceptions.py`, siguiendo el mismo patrón que `AssetNotFoundError`/`AnomalyNotFoundError`:

    ```python
    class ApiKeyLinkError(HygeiaError):
        """Se lanza cuando falla la operación sobre la ApiKey vinculada de Acheron
        (no encontrada, no pertenece al usuario, o error al borrarla/enlazarla).

        Encapsula cualquier excepción que llegue de ``VaultManager`` (otro
        módulo): Hygeia nunca debe propagar tipos de excepción ajenos a su
        propia jerarquía — igual que ``AssetNotFoundError`` unifica "no existe"
        y "pertenece a otro usuario" en una sola respuesta.
        """
        default_code = ErrorCode.ENTITY_NOT_FOUND
        default_status_code = 404

        def __init__(self, storable_id: int) -> None:
            super().__init__(
                message=f"No se pudo operar sobre la ApiKey {storable_id} del vault",
                details={"storable_id": storable_id},
                user_message="La credencial guardada en la bóveda no está disponible.",
            )
    ```

  Métodos nuevos/modificados — toda llamada a `VaultManager` queda envuelta en `try/except` que traduce a `ApiKeyLinkError`:
  - Nuevo método `HygeiaAssetManager.link_apikey(asset_id, storable_id)`:
    ```python
    from src.modules.features.acheron.managers import VaultManager
    from .exceptions import ApiKeyLinkError

    def link_apikey(self, asset_id: int, storable_id: int) -> dict:
        acheron_mgr = VaultManager(self.user)
        try:
            storable = acheron_mgr.get_storable(storable_id)  # ya valida propiedad
        except (ValueError, PermissionError) as exc:
            raise ApiKeyLinkError(storable_id) from exc
        if storable is None:
            raise ApiKeyLinkError(storable_id)

        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = self._get_owned_asset(repo, asset_id, self.user.id)
            asset.apikey_id = storable_id
            repo.update(asset)
        return asset.to_dict()
    ```
  - `rotate_key`: si `asset.apikey_id is not None`, envuelve igual la llamada:
    ```python
    if asset.apikey_id is not None:
        try:
            VaultManager(self.user).delete_storable(asset.apikey_id)
        except (ValueError, PermissionError) as exc:
            raise ApiKeyLinkError(asset.apikey_id) from exc
        asset.apikey_id = None
    ```
    antes de generar la clave nueva — evita dejar una `ApiKey` huérfana con un secreto ya inválido.
  - `delete_asset`: mismo patrón de `try/except` alrededor de `VaultManager(self.user).delete_storable(...)`, antes de borrar el asset.

  El principio general: **`from src.modules.features.acheron.managers import VaultManager` es el único punto de contacto permitido** entre los dos módulos, y cualquier excepción que cruce esa frontera se traduce inmediatamente a `ApiKeyLinkError` — nunca se deja escapar un tipo de excepción de Acheron hacia el resto de Hygeia ni hacia la respuesta HTTP.
- `endpoints.py`: nuevo `PATCH /hygeia/assets/<int:asset_id>/apikey` (o incluirlo en un `PATCH /hygeia/assets/<int:asset_id>` genérico si se prefiere) protegido por `require_oauth_token` + `HYGEIA_UPDATE`, que llama a `link_apikey`. Se añade `hygeia_blp.alt_response(404, schema=ErrorSchema, description="ApiKey not found or not owned")` para documentar el nuevo caso de error.
- `schemas.py`: schema de request `{"storableId": int}` para el endpoint nuevo.

### Frontend (`web/app/src`)
- Modal de "clave creada"/"clave rotada" (donde hoy vive el botón "Copiar"): añadir botón "Guardar en la bóveda" que dispara el flujo de cifrado + creación de storable + `PATCH` de vínculo descrito arriba.
- Reutiliza el cifrado cliente-side de Acheron (`web/app/src/acheron/crypto.js`, `vault.js`) sin cambios.

## Casos de borde ya resueltos por el diseño

- **Rotación de clave:** `rotate_key` limpia el vínculo y borra la `ApiKey` vieja *antes* de emitir la nueva — no hay entrada huérfana ni clave inválida flotando en el vault. El usuario, si quiere, vuelve a pulsar "Guardar en la bóveda" con la clave nueva.
- **Borrado de asset:** `delete_asset` arrastra el borrado de la `ApiKey` asociada en la misma transacción — no quedan restos de una credencial de un asset que ya no existe.
- **Asset sin ApiKey guardada:** `apikey_id` es `nullable`, es el caso por defecto (usuario no usó la función). Ningún flujo existente se ve afectado.
- **Reutilización de `apikey` fuera de Hygeia:** al no llevar ninguna FK hacia atrás, el tipo `apikey` de Acheron queda disponible para cualquier otro módulo futuro con credenciales similares, sin arrastrar semántica de Hygeia.

## Valoración

- **Esfuerzo**: medio. Una columna nueva + migración en Hygeia, un tipo nuevo en Acheron, un endpoint de vínculo, y el trabajo de frontend (mayor parte del esfuerzo real, por ser UX de dos módulos coordinados).
- **Riesgo**: bajo. Al pasar por `VaultManager.get_storable`/`delete_storable` en vez de por el repositorio, la comprobación de propiedad viene incluida — no es responsabilidad de Hygeia reimplementarla. La frontera entre módulos queda encapsulada: toda excepción de `VaultManager` (`ValueError`/`PermissionError`) se traduce a `ApiKeyLinkError` (nueva, en `hygeia/exceptions.py`) en el único punto de contacto entre ambos managers — Hygeia nunca deja escapar un tipo de excepción ajeno a su propia jerarquía hacia `endpoints.py` ni hacia la respuesta HTTP.
- **Valor real**: el tipo `apikey` es genérico y reutilizable; el vínculo opcional en Hygeia resuelve de forma limpia los dos casos de borde que antes quedaban como "limitación aceptada" (rotación y borrado). Como reclamo de venta frente a gestores de contraseñas externos no es diferenciador — todos ya tienen "API credential" como tipo de item —, pero la integración interna (nunca salir de la SPA, limpieza automática al rotar/borrar) es un argumento de cohesión de producto sólido.
- **Recomendación**: viable con la dirección de dependencia Hygeia → Acheron. No urgente, no bloqueante para nada. Buen candidato de "quick win" de producto cuando haya hueco.
