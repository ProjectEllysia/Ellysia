"""
herald.exceptions
──────────────────
Excepciones del módulo de envío de correo.

Estas excepciones representan fallos en la capa de transporte (conexión con
el proveedor SMTP) y de envío (mensaje rechazado). Son independientes del
dominio que consume el mailer (Aegis, …). Espejo de ``scribe.exceptions``.
"""

from src.modules.shared._exceptions import EllysiaException, ErrorCode, ErrorSeverity


class EmailConnectionError(EllysiaException):
    """No se pudo establecer comunicación con el servidor de correo."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str, host: str | None = None):
        details = {"host": host} if host else {}
        super().__init__(
            message=f"Error de conexión con el servidor de correo: {message}",
            details=details,
            user_message="Error al conectar con el servicio de correo.",
        )


class EmailSendError(EllysiaException):
    """El proveedor rechazó el mensaje (destinatario o contenido inválido)."""

    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_status_code = 502
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str, recipient: str | None = None):
        details = {"recipient": recipient} if recipient else {}
        super().__init__(
            message=f"Envío de correo rechazado: {message}",
            details=details,
            user_message="No se pudo enviar el correo.",
        )


class EmailConfigurationError(EllysiaException):
    """La estrategia de correo solicitada no existe o le faltan credenciales."""

    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str):
        super().__init__(
            message=f"Configuración de correo inválida: {message}",
            user_message="El servicio de correo no está configurado correctamente.",
        )
