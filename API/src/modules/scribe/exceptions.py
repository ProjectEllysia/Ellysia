"""
scribe.exceptions
─────────────────
Excepciones del módulo de generación con IA.

Estas excepciones representan fallos en la capa de *model calling* (transporte
hacia el modelo) y en el parseo de su respuesta. Son independientes del dominio
que consume el generador (Aegis, Themis, …).

Históricamente vivían en ``aegis.exceptions``; ahora son propiedad de ``scribe``
y aquél las reexporta por retrocompatibilidad.
"""

from src.modules.shared._exceptions import SecOpsException, ErrorCode, ErrorSeverity


class AIConnectionError(SecOpsException):
    """No se pudo establecer comunicación con el backend del modelo."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str, model: str | None = None):
        details = {"model": model} if model else {}
        super().__init__(
            message=f"Error de conexión con IA: {message}",
            details=details,
            user_message="Error al conectar con el servicio de IA.",
        )


class AIResponseError(SecOpsException):
    """El modelo devolvió una respuesta vacía o no parseable."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str, attempt: int = 0):
        super().__init__(
            message=f"Error en respuesta de IA (intento {attempt}): {message}",
            details={"attempt": attempt},
            user_message="La IA generó una respuesta inválida.",
        )


class AIFallbackExhaustedError(SecOpsException):
    """Se agotaron todos los reintentos sin obtener una respuesta válida."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH

    def __init__(self, attempts: int, last_error: str):
        super().__init__(
            message=f"Fallo tras {attempts} intentos: {last_error}",
            details={"attempts": attempts, "last_error": last_error},
            user_message="No se pudo generar el contenido tras varios intentos.",
        )


class CircuitBreakerOpenError(SecOpsException):
    """El circuit breaker del backend está abierto tras fallos repetidos."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, service: str):
        super().__init__(
            message=f"Circuit breaker abierto para {service}",
            details={"service": service},
            user_message="El servicio está temporalmente no disponible.",
        )


class AIStrategyConfigurationError(SecOpsException):
    """La estrategia solicitada no existe o le faltan credenciales."""

    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str):
        super().__init__(
            message=f"Configuración de estrategia IA inválida: {message}",
            user_message="El servicio de IA no está configurado correctamente.",
        )
