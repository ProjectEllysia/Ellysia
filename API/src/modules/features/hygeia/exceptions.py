"""
Excepciones específicas del módulo Hygeia.

Hierarchy:
    HygeiaError (EllysiaException)
    ├── AssetNotFoundError        (404)
    ├── AssetQuotaExceededError   (409)
    ├── IngestPayloadTooLargeError (413)
    ├── IngestClockSkewError      (400)
    ├── IngestTooFrequentError    (429)
    ├── AnomalyNotFoundError      (404)
    ├── AnomalyStillOpenError     (409)
    ├── InventoryNotAvailableError (409)
    ├── TagNotFoundError          (404)
    ├── TagAlreadyExistsError     (409)
    ├── TagQuotaExceededError     (409)
    ├── SystemTagImmutableError   (403)
    └── OrganizationScopeNotAllowedError (403)
"""

from __future__ import annotations

from src.modules.shared._exceptions import EllysiaException, EntityNotFoundError, ErrorCode


class HygeiaError(EllysiaException):
    """Excepción base para todos los errores del módulo Hygeia."""
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500


class AssetNotFoundError(EntityNotFoundError, HygeiaError):
    """Se lanza cuando un activo no existe o no pertenece al usuario.

    Sirve también como capa de privacidad: la misma excepción se devuelve
    tanto si el activo no existe como si pertenece a otro usuario, para no
    permitir enumerar IDs ajenos por diferencia de respuesta.
    """
    entity_label = "Activo"
    id_field = "asset_id"


class AssetQuotaExceededError(HygeiaError):
    """Se lanza cuando un usuario supera su cuota de activos monitorizados."""
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, max_assets: int) -> None:
        super().__init__(
            message=f"Cuota de activos superada (máximo {max_assets})",
            details={"max_assets": max_assets},
            user_message=f"Has alcanzado el máximo de {max_assets} activos monitorizados.",
        )


class IngestPayloadTooLargeError(HygeiaError):
    """El cuerpo de un heartbeat supera los límites configurados (§16.1)."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 413

    def __init__(self, reason: str) -> None:
        super().__init__(
            message=f"Payload de ingesta rechazado: {reason}",
            details={"reason": reason},
            user_message="El payload enviado supera los límites permitidos.",
        )


class IngestClockSkewError(HygeiaError):
    """El reloj del agente (``collectedAt``) se sale de la ventana de cordura (§16.3)."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400

    def __init__(self, collected_at: str) -> None:
        super().__init__(
            message=f"collectedAt fuera de la ventana de reloj permitida: {collected_at}",
            details={"collected_at": collected_at},
            user_message="El reloj del agente está desincronizado.",
        )


class IngestTooFrequentError(HygeiaError):
    """Un heartbeat llega más rápido de lo permitido para esta clave (§16.2).

    Protege la DB de un agente en bucle cerrado (con un bug, o comprometido):
    el heartbeat se descarta sin persistir nada, no se intenta procesar.
    """
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 429

    def __init__(self, min_interval_sec: int) -> None:
        super().__init__(
            message=f"Heartbeat rechazado: por debajo del intervalo mínimo de {min_interval_sec}s",
            details={"min_interval_sec": min_interval_sec},
            user_message="Cadencia de heartbeat demasiado alta.",
        )


class AnomalyNotFoundError(EntityNotFoundError, HygeiaError):
    """Se lanza cuando una anomalía no existe o no pertenece al usuario."""
    entity_label = "Anomalía"
    entity_is_feminine = True
    id_field = "anomaly_id"


class AnomalyStillOpenError(HygeiaError):
    """Se lanza al intentar borrar una anomalía que sigue en estado ``open``.

    Solo se puede borrar una anomalía ya reconocida o resuelta: una abierta
    todavía representa una condición activa sin atender, y borrarla la
    haría desaparecer del panel sin que nadie la haya visto ni resuelto.
    """
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, anomaly_id: int) -> None:
        super().__init__(
            message=f"Anomalía {anomaly_id} sigue abierta, no se puede borrar",
            details={"anomaly_id": anomaly_id},
            user_message="Solo se pueden borrar anomalías reconocidas o resueltas.",
        )


class InventoryNotAvailableError(HygeiaError):
    """Se intenta analizar un activo que todavía no ha reportado inventario.

    No es un fallo del sistema sino un estado legítimo del activo (agente
    recién instalado, o el escaneo de software —que va cada ~6h, no en cada
    heartbeat— aún no le ha tocado), así que el frontend simplemente no
    ofrece el botón hasta que haya inventario. Esto es la red de seguridad
    para la llamada directa.
    """
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, asset_id: int) -> None:
        super().__init__(
            message=f"El activo {asset_id} no tiene inventario de software que analizar",
            details={"asset_id": asset_id},
            user_message="Este activo aún no ha reportado un inventario de software.",
        )


class TagNotFoundError(EntityNotFoundError, HygeiaError):
    """Se lanza cuando una etiqueta no existe o no es visible para el usuario.

    Igual que con los activos: una etiqueta personal de otro usuario da el
    mismo 404 que una inexistente, para no permitir enumerar el catálogo
    ajeno por diferencia de respuesta.
    """
    entity_label = "Etiqueta"
    entity_is_feminine = True
    id_field = "tag_id"


class TagAlreadyExistsError(HygeiaError):
    """El usuario ya tiene (o el catálogo común ya trae) una etiqueta con ese nombre."""
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, name: str) -> None:
        super().__init__(
            message=f"Ya existe una etiqueta llamada {name!r}",
            details={"name": name},
            user_message=f"Ya existe una etiqueta «{name}».",
        )


class TagQuotaExceededError(HygeiaError):
    """El usuario ha llegado al tope de etiquetas personales."""
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, max_tags: int) -> None:
        super().__init__(
            message=f"Tope de etiquetas personales superado (máximo {max_tags})",
            details={"max_tags": max_tags},
            user_message=f"Has alcanzado el máximo de {max_tags} etiquetas personales.",
        )


class SystemTagImmutableError(HygeiaError):
    """Se intenta borrar una etiqueta del catálogo común.

    No es un 404 a propósito: la etiqueta existe y el usuario la ve, así que
    fingir que no está sería confuso. Lo que no puede es tocarla — el
    catálogo es común, y borrarla se la quitaría a todo el mundo.
    """
    default_code = ErrorCode.AUTHORIZATION_ERROR
    default_status_code = 403

    def __init__(self, tag_id: int) -> None:
        super().__init__(
            message=f"La etiqueta {tag_id} es del catálogo común y no se puede borrar",
            details={"tag_id": tag_id},
            user_message="Las etiquetas del catálogo común no se pueden borrar.",
        )


class OrganizationScopeNotAllowedError(HygeiaError):
    """Se pide el inventario de toda la organización sin ser su dueño.

    Cubre dos situaciones con la misma respuesta, y es deliberado: no
    pertenecer a ninguna organización y pertenecer a una que no es tuya son,
    desde fuera, indistinguibles. Distinguirlas revelaría a un miembro
    cualquiera si su organización existe y quién manda en ella.

    Hoy solo hay dos roles (``owner`` y ``member``) y no hay uno intermedio,
    así que "cualquier miembro" significaría cualquiera a quien se haya
    invitado alguna vez — y este informe lista hostnames, kernels y software
    de todos sus compañeros.
    """
    default_code = ErrorCode.AUTHORIZATION_ERROR
    default_status_code = 403

    def __init__(self) -> None:
        super().__init__(
            message="El ámbito de organización exige ser dueño de una organización",
            user_message=(
                "Solo el dueño de una organización puede generar el inventario "
                "de todos sus activos."
            ),
        )
