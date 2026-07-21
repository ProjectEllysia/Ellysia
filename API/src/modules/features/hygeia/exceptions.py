"""
Excepciones específicas del módulo Hygeia.

Hierarchy:
    HygeiaError (EllysiaException)
    ├── AssetNotFoundError        (404)
    ├── AssetQuotaExceededError   (409)
    ├── IngestPayloadTooLargeError (413)
    ├── IngestClockSkewError      (400)
    ├── IngestTooFrequentError    (429)
    └── AnomalyNotFoundError      (404)
"""

from __future__ import annotations

from src.modules.shared._exceptions import EllysiaException, ErrorCode


class HygeiaError(EllysiaException):
    """Excepción base para todos los errores del módulo Hygeia."""
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500


class AssetNotFoundError(HygeiaError):
    """Se lanza cuando un activo no existe o no pertenece al usuario.

    Sirve también como capa de privacidad: la misma excepción se devuelve
    tanto si el activo no existe como si pertenece a otro usuario, para no
    permitir enumerar IDs ajenos por diferencia de respuesta.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404

    def __init__(self, asset_id: int) -> None:
        super().__init__(
            message=f"Activo {asset_id} no encontrado",
            details={"asset_id": asset_id},
            user_message="Activo no encontrado.",
        )


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


class AnomalyNotFoundError(HygeiaError):
    """Se lanza cuando una anomalía no existe o no pertenece al usuario."""
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404

    def __init__(self, anomaly_id: int) -> None:
        super().__init__(
            message=f"Anomalía {anomaly_id} no encontrada",
            details={"anomaly_id": anomaly_id},
            user_message="Anomalía no encontrada.",
        )
