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
