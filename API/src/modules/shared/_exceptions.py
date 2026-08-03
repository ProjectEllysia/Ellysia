from typing import Any, Dict, Optional, Type
from enum import Enum
from functools import wraps
import traceback
import sys

from ._time import utcnow_naive, isoformat_utc


class ErrorCode(Enum):
    UNKNOWN_ERROR = 1000
    INTERNAL_SERVER_ERROR = 1001
    NOT_IMPLEMENTED = 1002
    ILLEGAL_STATE_ERROR = 1003

    VALIDATION_ERROR = 1100
    INVALID_PORT_SPEC = 1101
    INVALID_IP_SPEC = 1102
    INVALID_URL = 1103
    INVALID_PARAMETER = 1104
    MISSING_PARAMETER = 1105

    DATABASE_ERROR = 1200
    ENTITY_NOT_FOUND = 1201
    ENTITY_ALREADY_EXISTS = 1202
    DATABASE_CONNECTION_ERROR = 1203
    TRANSACTION_ERROR = 1204
    CONSTRAINT_VIOLATION = 1205

    SCAN_ERROR = 1300
    SCAN_NOT_FOUND = 1301
    SCAN_ALREADY_RUNNING = 1302
    SCAN_NOT_FINISHED = 1303
    SCAN_EXECUTION_ERROR = 1304
    SCAN_TIMEOUT = 1305
    MAX_CONCURRENT_SCANS = 1306
    MAX_HOSTS_EXCEEDED = 1307
    PRIVATE_IP_REQUESTED = 1308
    PROGRAMED_SCAN_NOT_FOUND = 1309
    PROGRAMED_SCAN_ALREADY_ACTIVE = 1310
    PROGRAMED_SCAN_INVALID_ARGUMENT = 1311
    TARGET_NOT_AUTHORIZED = 1312
    AUTHORIZED_TARGET_NOT_FOUND = 1313
    AUTHORIZED_TARGET_ALREADY_EXISTS = 1314

    REPORT_ERROR = 1400
    REPORT_GENERATION_ERROR = 1401
    REPORT_NOT_FOUND = 1402

    CONFIGURATION_ERROR = 1500
    MISSING_CONFIG = 1501
    INVALID_CONFIG = 1502

    AUTHENTICATION_ERROR = 1600
    AUTHORIZATION_ERROR = 1601
    INVALID_CREDENTIALS = 1602
    USER_NOT_FOUND = 1603
    TOKEN_EXPIRED = 1604
    USER_ALREADY_EXISTS = 1605
    UNBINDABLE_USER = 1606
    DUPLICATED_CREDENTIALS = 1607
    PROFILE_UPDATE_ERROR = 1608
    PASSWORD_CHANGED = 1609
    MFA_ALREADY_ENABLED = 1610
    MFA_NOT_ENABLED = 1611
    INVALID_MFA_CODE = 1612
    MFA_CHALLENGE_INVALID = 1613
    PARSING_ERROR = 1700
    XML_PARSING_ERROR = 1701
    JSON_PARSING_ERROR = 1702
    VAULT_ERROR = 1703
    VAULT_REVISION_MISMATCH = 1704

    DOCUMENT_NOT_FOUND = 1801


class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EllysiaException(Exception):
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM

    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        details: Optional[Dict[str, Any]] = None,
        original_exception: Optional[Exception] = None,
        severity: Optional[ErrorSeverity] = None,
        status_code: Optional[int] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.details = details or {}
        self.original_exception = original_exception
        self.severity = severity or self.default_severity
        self.status_code = status_code or self.default_status_code
        self.user_message = user_message or self._generate_user_message()

        self.timestamp = utcnow_naive()
        self.traceback = self._capture_traceback()

    def _generate_user_message(self) -> str:
        user_messages = {
            ErrorCode.VALIDATION_ERROR: "Los datos proporcionados no son válidos.",
            ErrorCode.MISSING_PARAMETER: "Falta un parámetro requerido.",
            ErrorCode.DATABASE_ERROR: "Error al acceder a la base de datos.",
            ErrorCode.SCAN_ERROR: "Error durante el escaneo.",
            ErrorCode.AUTHENTICATION_ERROR: "Error de autenticación.",
            ErrorCode.INVALID_CREDENTIALS: "Usuario o contraseña incorrectos.",
            ErrorCode.INTERNAL_SERVER_ERROR: "Ha ocurrido un error interno.",
        }
        return user_messages.get(self.code, "Ha ocurrido un error inesperado.")

    def _capture_traceback(self) -> str:
        if sys.exc_info()[0] is not None:
            return ''.join(traceback.format_exception(*sys.exc_info()))
        return traceback.format_stack()[-1] if traceback.format_stack() else ""

    def to_dict(self, include_traceback: bool = False) -> Dict[str, Any]:
        result = {
            "error": self.__class__.__name__,
            "code": self.code.value,
            "message": self.user_message,
            "timestamp": isoformat_utc(self.timestamp),
        }

        if self.details:
            result["details"] = self.details

        if include_traceback:
            result["technical_message"] = self.message
            result["traceback"] = self.traceback
            if self.original_exception:
                result["original_error"] = str(self.original_exception)

        return result

    def __str__(self) -> str:
        return f"[{self.code.name}] {self.message}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"code={self.code.name}, "
            f"message='{self.message}', "
            f"severity={self.severity.value})"
        )


class IllegalStateError(EllysiaException):
    default_code = ErrorCode.ILLEGAL_STATE_ERROR
    default_status_code = 409
    default_severity = ErrorSeverity.MEDIUM

    def __init__(
        self,
        message: str,
        expected_state: Optional[str] = None,
        current_state: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if expected_state:
            details["expected_state"] = expected_state
        if current_state:
            details["current_state"] = current_state

        if "details" in kwargs:
            details.update(kwargs.pop("details"))

        if "user_message" not in kwargs:
            if current_state and expected_state:
                kwargs["user_message"] = (
                    f"Estado inválido: se esperaba '{expected_state}' "
                    f"pero se encontró '{current_state}'."
                )
            else:
                kwargs["user_message"] = "Estado inválido en el sistema."

        super().__init__(
            message=message,
            details=details,
            **kwargs
        )


class ValidationError(EllysiaException):
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400
    default_severity = ErrorSeverity.LOW

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
        expected: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        if expected:
            details["expected"] = expected

        if "details" in kwargs:
            details.update(kwargs.pop("details"))

        if "user_message" not in kwargs:
            _msg = str(message).strip()
            if len(_msg) > 100:
                _msg = _msg[:97] + "…"
            if field:
                kwargs["user_message"] = f"'{field}' no es válido: {_msg}"
            else:
                kwargs["user_message"] = _msg or "Validación fallida."

        super().__init__(
            message=f"Validación fallida: {message}",
            details=details,
            **kwargs
        )


class MissingParameterError(ValidationError):
    default_code = ErrorCode.MISSING_PARAMETER

    def __init__(self, parameter: str):
        super().__init__(
            message=f"Parámetro requerido '{parameter}' no proporcionado",
            field=parameter,
            user_message=f"El parámetro '{parameter}' es obligatorio."
        )


class MissingJsonBodyError(EllysiaException):
    default_code = ErrorCode.JSON_PARSING_ERROR
    default_status_code = 400
    default_severity = ErrorSeverity.LOW

    def __init__(self, message: str = "Request body must be JSON"):
        super().__init__(
            message=message,
            user_message="El cuerpo de la petición debe ser JSON válido."
        )


class DatabaseError(EllysiaException):
    default_code = ErrorCode.DATABASE_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH


class EntityNotFoundError(DatabaseError):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, entity_type: str, identifier: Any):
        super().__init__(
            message=f"{entity_type} con identificador {identifier} no encontrado",
            details={"entity_type": entity_type, "identifier": str(identifier)},
            user_message=f"{entity_type} no encontrado."
        )


class EntityAlreadyExistsError(DatabaseError):
    default_code = ErrorCode.ENTITY_ALREADY_EXISTS
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, entity_type: str, identifier: str):
        super().__init__(
            message=f"{entity_type} con identificador '{identifier}' ya existe",
            details={"entity_type": entity_type, "identifier": identifier},
            user_message=f"El {entity_type} ya existe."
        )


class DatabaseConnectionError(DatabaseError):
    default_code = ErrorCode.DATABASE_CONNECTION_ERROR
    default_severity = ErrorSeverity.CRITICAL

    def __init__(self, message: str, host: Optional[str] = None):
        details = {"host": host} if host else {}
        super().__init__(
            message=f"Error de conexión a base de datos: {message}",
            details=details,
            user_message="No se pudo conectar a la base de datos."
        )


class TransactionError(DatabaseError):
    default_code = ErrorCode.TRANSACTION_ERROR
    default_severity = ErrorSeverity.HIGH


# =========================================================================
# Excepciones de documentos (transversales: Themis, Iris, Aegis)
# Antes vivían en aegis/exceptions.py, lo que acoplaba tres módulos feature
# a las excepciones de un cuarto. Se re-exportan desde aegis/exceptions.py
# para compatibilidad.
# =========================================================================


class DocumentError(EllysiaException):
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


class ParsingError(EllysiaException):
    default_code = ErrorCode.PARSING_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class XMLParsingError(ParsingError):
    default_code = ErrorCode.XML_PARSING_ERROR

    def __init__(self, file_path: str, reason: str):
        super().__init__(
            message=f"Error parseando XML '{file_path}': {reason}",
            details={"file_path": file_path, "reason": reason},
            user_message="Error procesando resultados del escaneo."
        )


class JSONParsingError(ParsingError):
    default_code = ErrorCode.JSON_PARSING_ERROR

    def __init__(self, data: str, reason: str):
        super().__init__(
            message=f"Error parseando JSON: {reason}",
            details={"data": data[:100], "reason": reason},
            user_message="Error procesando datos JSON."
        )


class ExceptionHandler:
    @staticmethod
    def wrap_exception(
        exc: Exception,
        default_exception_class: Type[EllysiaException] = EllysiaException,
        logger=None
    ) -> EllysiaException:
        if isinstance(exc, EllysiaException):
            return exc

        if logger:
            logger.error(f"Excepción no manejada: {exc}", exc_info=True)

        exc_type = type(exc).__name__
        exc_message = str(exc)

        if any(keyword in exc_type for keyword in ["SQL", "Database", "Integrity"]):
            return DatabaseError(
                message=f"Error de base de datos: {exc_message}",
                original_exception=exc
            )

        if "Timeout" in exc_type or "timeout" in exc_message.lower():
            return OperationTimeoutError(
                message=f"Timeout: {exc_message}",
                original_exception=exc
            )

        if "Connection" in exc_type or "connection" in exc_message.lower():
            return DatabaseConnectionError(
                message=f"Error de conexión: {exc_message}"
            )

        if any(keyword in exc_type for keyword in ["JSON", "XML", "Parse"]):
            return ParsingError(
                message=f"Error de parsing: {exc_message}",
                original_exception=exc
            )

        return default_exception_class(
            message=f"Error inesperado: {exc_message}",
            details={"exception_type": exc_type},
            original_exception=exc
        )

    @staticmethod
    def handle_and_log(exc: Exception, logger) -> EllysiaException:
        secops_exc = ExceptionHandler.wrap_exception(exc, logger=logger)

        if secops_exc.severity == ErrorSeverity.CRITICAL:
            logger.critical(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.HIGH:
            logger.error(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.MEDIUM:
            logger.warning(secops_exc.message)
        else:
            logger.info(secops_exc.message)

        return secops_exc


class OperationTimeoutError(EllysiaException):
    default_code = ErrorCode.SCAN_TIMEOUT
    default_status_code = 408
    default_severity = ErrorSeverity.MEDIUM


def handle_exceptions(
    default_exception: Type[EllysiaException] = EllysiaException,
    logger=None,
    re_raise: bool = True
):
    """
    Decorador para manejo automático de excepciones en funciones/métodos.

    Envuelve una función para capturar excepciones que no sean EllysiaException
    y convertirlas automáticamente al formato de la aplicación.

    Args:
        default_exception: Clase de excepción EllysiaException a usar como base
                          cuando se envuelve una excepción unknown. Por defecto
                          EllysiaException.
        logger: Logger opcional para registrar las excepciones envueltas.
        re_raise: Si True, relanza la excepción envuelta. Si False, la retorna
                  sin relanzar. Por defecto True.

    Returns:
        Función decorada con manejo automático de excepciones.

    Example:
    >>> from src.modules.shared import handle_exceptions
    >>> from src.modules.features.themis.exceptions import ScanError
    >>> import logging
    >>> _logger = logging.getLogger(__name__)
    >>>
    >>> @handle_exceptions(default_exception=ScanError, logger=_logger)
    ... def scan_operation(target):
    ...     # código que puede lanzar excepciones
    ...     pass

    Note:
        Las excepciones que ya heredan de EllysiaException se propagan directamente
        sin conversión.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except EllysiaException:
                raise
            except Exception as e:
                secops_exc = ExceptionHandler.wrap_exception(
                    e,
                    default_exception_class=default_exception,
                    logger=logger
                )
                if re_raise:
                    raise secops_exc from e
                return secops_exc
        return wrapper
    return decorator


def create_error_response(
    exception: EllysiaException,
    include_debug_info: bool = False
) -> tuple[Dict[str, Any], int]:
    response = {
        "error": exception.__class__.__name__,
        "error_description": exception.user_message,
        "code": exception.code.value,
    }

    if include_debug_info:
        response["technical_message"] = exception.message
        response["traceback"] = exception.traceback
        if exception.original_exception:
            response["original_error"] = str(exception.original_exception)
        if exception.details:
            response["details"] = exception.details

    return response, exception.status_code