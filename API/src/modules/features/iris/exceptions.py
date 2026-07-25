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

from src.modules.shared._exceptions import EllysiaException, ErrorCode


class IrisError(EllysiaException):
    """Base exception for all Iris module errors."""
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500


class IrisAnalysisNotFoundError(IrisError):
    """Raised when an analysis ID does not exist or is not owned by the user.

    This also serves as a privacy layer — the same error is returned
    whether the analysis does not exist or belongs to another user.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404

    def __init__(self, analysis_id: int) -> None:
        super().__init__(f"Analysis {analysis_id} not found")


class IrisAnalysisNotReadyError(IrisError):
    """Raised when trying to read results of an unfinished analysis."""
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 409

    def __init__(self, analysis_id: int, status: str) -> None:
        super().__init__(f"Analysis {analysis_id} is not ready (status: {status})")


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


class IrisMailboxConnectionNotFoundError(IrisError):
    """Raised when a mailbox connection id does not exist or is not owned
    by the user (same error for both, prevents ID enumeration)."""
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404

    def __init__(self, connection_id: int) -> None:
        super().__init__(f"Mailbox connection {connection_id} not found")


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
