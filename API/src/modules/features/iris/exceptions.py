"""
Custom exceptions for the Iris email header analysis module.

Hierarchy:
    IrisError (EllysiaException)
    ├── IrisAnalysisNotFoundError   (404)
    ├── IrisAnalysisNotReadyError   (409)
    ├── IrisExecutionError          (500)
    └── IrisInvalidStateError       (400)
"""

from __future__ import annotations

from src.modules.shared._exceptions import EllysiaException, EntityNotFoundError, ErrorCode


class IrisError(EllysiaException):
    """Base exception for all Iris module errors."""
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500


class IrisAnalysisNotFoundError(EntityNotFoundError, IrisError):
    """Raised when an analysis ID does not exist or is not owned by the user.

    This also serves as a privacy layer — the same error is returned
    whether the analysis does not exist or belongs to another user.
    """
    entity_label = "Análisis"
    id_field = "analysis_id"


class IrisAnalysisNotReadyError(IrisError):
    """Raised when trying to read results of an unfinished analysis."""
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 409

    def __init__(self, analysis_id: int, status: str) -> None:
        super().__init__(f"Analysis {analysis_id} is not ready (status: {status})")


class IrisRawMessagePurgedError(IrisError):
    """El raw de este análisis ya no existe -- lo purgó la política de
    retención, que conserva el resultado analítico
    (score/veredicto/reglas) pero no el contenido del correo indefinidamente.

    410 Gone y no 404: el análisis existe de verdad y su resultado sigue
    siendo consultable por otras vías (``GET /iris/results/<id>``); es
    específicamente el raw, y solo el raw, lo que ha dejado de estar --
    para siempre, no temporalmente, que es justo la diferencia entre 410 y
    404/503.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 410

    def __init__(self, analysis_id: int) -> None:
        super().__init__(
            f"El raw del análisis {analysis_id} ya no está disponible: "
            "la política de retención lo ha purgado."
        )


class IrisExecutionError(IrisError):
    """Raised when an analysis fails to start or complete."""
    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 500


class IrisInvalidStateError(IrisError):
    """Raised when an operation is attempted in the wrong lifecycle state.

    For example, cancelling an analysis that is already finished.
    """
    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 400


class IrisInvalidInputError(IrisError):
    """Raised when the submitted headers do not contain enough valid entries
    to perform a meaningful analysis."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400


class IrisMailboxConnectionNotFoundError(EntityNotFoundError, IrisError):
    """Raised when a mailbox connection id does not exist or is not owned
    by the user (same error for both, prevents ID enumeration)."""
    entity_label = "Conexión de buzón"
    entity_is_feminine = True
    id_field = "connection_id"


class IrisTrustedSenderNotFoundError(EntityNotFoundError, IrisError):
    """La excepción de confianza no existe o no es del usuario.

    El mismo error para los dos casos, como el resto de entidades de Iris,
    para que no se puedan enumerar ids ajenos.
    """
    entity_label = "Excepción de confianza"
    entity_is_feminine = True
    id_field = "trusted_sender_id"


class IrisSavedViewNotFoundError(EntityNotFoundError, IrisError):
    """La vista guardada no existe o no es del usuario (mismo error para los dos)."""
    entity_label = "Vista guardada"
    entity_is_feminine = True
    id_field = "view_id"


class IrisCaseNotFoundError(EntityNotFoundError, IrisError):
    """El caso no existe o no es del usuario (mismo error para los dos)."""
    entity_label = "Caso"
    id_field = "case_id"


class IrisMailboxInvalidProviderError(IrisError):
    """Raised when connecting to an unsupported mailbox provider."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400

    def __init__(self, provider: str) -> None:
        super().__init__(f"Unsupported mailbox provider: {provider}")


class IrisMailboxQuotaExceededError(IrisError):
    """Raised when a user tries to connect more mailboxes than iris.maxConnectionsPerUser."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400


class IrisMailboxOAuthStateError(IrisError):
    """Raised when the OAuth callback's `state` fails to verify — expired,
    tampered, or never issued by start_connect (CSRF protection)."""
    default_code = ErrorCode.AUTHENTICATION_ERROR
    default_status_code = 400


class IrisMailboxInvalidFolderError(IrisError):
    """Raised when ``folder`` doesn't match any real folder/label the
    provider returns for this account — wrong id, typo, or a value
    that belongs to another provider."""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400

    def __init__(self, folder: str) -> None:
        super().__init__(
            f"'{folder}' no es una carpeta válida para esta cuenta.",
            user_message=f"'{folder}' no es una carpeta válida para esta cuenta.",
        )
