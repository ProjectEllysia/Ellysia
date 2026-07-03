from src.modules.shared._exceptions import (
    SecOpsException,
    ErrorCode,
    ErrorSeverity,
    ValidationError,
    DatabaseError,
    EntityAlreadyExistsError,
)

# Las excepciones de la capa de IA son ahora propiedad del módulo `scribe`.
# Se reexportan aquí por retrocompatibilidad con los imports existentes.
from src.modules.scribe.exceptions import (  # noqa: F401
    AIConnectionError,
    AIResponseError,
    AIFallbackExhaustedError,
    CircuitBreakerOpenError,
)


class AegisValidationError(ValidationError):
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400

    def __init__(self, message: str, field: str | None = None, value: str | None = None):
        details = {}
        if field:
            details["field"] = field
        if value:
            details["value"] = value
        super().__init__(
            message=message,
            details=details,
            user_message=f"Error de validación: {message}"
        )


class AegisInsufficientContentError(AegisValidationError):
    default_code = ErrorCode.VALIDATION_ERROR

    def __init__(self, expected: int, found: int):
        super().__init__(
            message=f"Contenido insuficiente: esperados {expected}, encontrados {found}",
            field="tips",
            value=str(found)
        )


class AegisFetchError(SecOpsException):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR

    def __init__(self, source: str, message: str):
        super().__init__(
            message=f"Error fetching {source}: {message}",
            details={"source": source},
            user_message=f"Error al obtener alertas de {source}."
        )


class DocumentError(SecOpsException):
    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class DocumentNotFoundError(DocumentError):
    default_code = ErrorCode.DOCUMENT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, doc_id: int):
        super().__init__(
            message=f"Documento {doc_id} no encontrado",
            details={"document_id": doc_id},
            user_message=f"Documento {doc_id} no encontrado."
        )


class DocumentNotReadyError(DocumentError):
    default_code = ErrorCode.DOCUMENT_NOT_FOUND
    default_status_code = 409

    def __init__(self, doc_id: int, status: str):
        super().__init__(
            message=f"Documento {doc_id} no disponible (estado: {status})",
            details={"document_id": doc_id, "status": status},
            user_message="El documento aún no está listo."
        )


class DocumentGenerationError(DocumentError):
    default_code = ErrorCode.REPORT_GENERATION_ERROR


class ExporterError(DocumentError):
    default_code = ErrorCode.REPORT_ERROR


class ExporterFormatError(ExporterError):
    default_code = ErrorCode.INVALID_PARAMETER
    default_status_code = 400

    def __init__(self, format: str):
        super().__init__(
            message=f"Formato de exportación no soportado: {format}",
            details={"format": format},
            user_message=f"El formato '{format}' no es soportado."
        )


class ExporterConfigurationError(ExporterError):
    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500

    def __init__(self, missing_fields: list[str]):
        super().__init__(
            message=f"Exportador mal configurado. Faltan: {missing_fields}",
            details={"missing_fields": missing_fields},
            user_message="Error de configuración del exportador."
        )


# =============================================================================
# CAMPAÑAS DE CONCIENCIACIÓN
# =============================================================================

class CampaignError(SecOpsException):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class DistributionListNotFoundError(CampaignError):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, list_id: int):
        super().__init__(
            message=f"Lista de distribución {list_id} no encontrada",
            details={"list_id": list_id},
            user_message="Lista de distribución no encontrada."
        )


class CampaignNotFoundError(CampaignError):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, campaign_id: int):
        super().__init__(
            message=f"Campaña {campaign_id} no encontrada",
            details={"campaign_id": campaign_id},
            user_message="Campaña no encontrada."
        )


class CampaignAlreadyLaunchedError(CampaignError):
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self, campaign_id: int, status: str):
        super().__init__(
            message=f"Campaña {campaign_id} ya no está en borrador (estado: {status})",
            details={"campaign_id": campaign_id, "status": status},
            user_message="La campaña ya ha sido lanzada."
        )


class CampaignEmptyListError(AegisValidationError):
    def __init__(self, list_id: int):
        super().__init__(
            message=f"La lista {list_id} no tiene destinatarios",
            field="list_id",
            value=str(list_id),
        )


class CampaignNoQuestionsError(AegisValidationError):
    def __init__(self, document_id: int):
        super().__init__(
            message=f"La píldora {document_id} no tiene preguntas de quiz",
            field="document_id",
            value=str(document_id),
        )


class QuizTokenInvalidError(CampaignError):
    """Token desconocido en la página pública del quiz.

    Deliberadamente no distingue entre 'token nunca existió' y 'ya fue
    usado y su fila fue purgada': el mensaje es genérico para no dar pistas
    a quien intente enumerar tokens.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self):
        super().__init__(
            message="Token de quiz inválido o inexistente",
            user_message="Este enlace no es válido."
        )


class QuizAlreadyCompletedError(CampaignError):
    """Regla no-repetir: el test para este token ya fue completado."""
    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self):
        super().__init__(
            message="Este test ya fue completado y no se puede repetir",
            user_message="Ya has completado este test anteriormente."
        )