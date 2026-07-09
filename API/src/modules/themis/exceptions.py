"""
Excepciones específicas del módulo Themis (escaneos de seguridad).

Grupos: Escaneo, Reportes, Escaneo Programado, Validación, Carpetas.

>>> raise ScanNotFoundError(scan_id=42)
>>> raise ScanExecutionError(scan_type="nmap", target="192.168.1.1", reason="Timeout")
>>> raise PortValidationError(message="Puerto inválido", port_spec="invalid")
"""

from src.modules.shared._exceptions import (
    SecOpsException,
    ErrorCode,
    ErrorSeverity,
    ValidationError,
)


class ScanError(SecOpsException):
    """Excepción base para errores de escaneo."""

    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ScanNotFoundError(ScanError):
    """Escaneo no encontrado en la base de datos."""

    default_code = ErrorCode.SCAN_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, scan_id: int):
        super().__init__(
            message=f"Escaneo con ID {scan_id} no encontrado",
            details={"scan_id": scan_id},
            user_message=f"El escaneo #{scan_id} no existe."
        )


class FindingNotFoundError(ScanError):
    """Hallazgo (Finding) no encontrado o no perteneciente al usuario."""

    default_code = ErrorCode.SCAN_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, finding_id: int):
        super().__init__(
            message=f"Hallazgo con ID {finding_id} no encontrado",
            details={"finding_id": finding_id},
            user_message=f"El hallazgo #{finding_id} no existe."
        )


class ScanAlreadyRunningError(ScanError):
    """Ya existe un escaneo en ejecución para el objetivo dado."""

    default_code = ErrorCode.SCAN_ALREADY_RUNNING
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, target: str, scan_type: str = "escaneo"):
        super().__init__(
            message=f"Ya existe un {scan_type} en ejecución para '{target}'",
            details={"target": target, "scan_type": scan_type},
            user_message=f"Ya hay un {scan_type} activo para este objetivo."
        )


class ScanExecutionError(ScanError):
    """Error durante la ejecución de un escaneo (conexión, proceso hijo, permisos)."""

    default_code = ErrorCode.SCAN_EXECUTION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, scan_type: str, target: str, reason: str):
        super().__init__(
            message=f"Error ejecutando {scan_type} en '{target}': {reason}",
            details={"scan_type": scan_type, "target": target, "reason": reason},
            user_message=f"Error durante el escaneo: {reason}"
        )


class ScanTimeoutError(ScanError):
    """Un escaneo excedió el tiempo límite establecido."""

    default_code = ErrorCode.SCAN_TIMEOUT
    default_status_code = 408
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, scan_id: int, timeout: int):
        super().__init__(
            message=f"Escaneo {scan_id} excedió timeout de {timeout}s",
            details={"scan_id": scan_id, "timeout": timeout},
            user_message=f"El escaneo excedió el tiempo límite de {timeout} segundos."
        )


class MaxConcurrentScansError(ScanError):
    """Se alcanzó el límite de escaneos concurrentes del usuario."""

    default_code = ErrorCode.MAX_CONCURRENT_SCANS
    default_status_code = 429
    default_severity = ErrorSeverity.LOW

    def __init__(self, max_scans: int, current: int):
        super().__init__(
            message=f"Límite de escaneos concurrentes alcanzado ({current}/{max_scans})",
            details={"max_concurrent": max_scans, "current": current},
            user_message=f"Se alcanzó el límite de {max_scans} escaneos simultáneos."
        )


class MaxHostsExceededError(ScanError):
    """La especificación de IPs/rangos produce más hosts de los permitidos."""

    default_code = ErrorCode.MAX_HOSTS_EXCEEDED
    default_status_code = 400
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, max_hosts: int, found: int):
        super().__init__(
            message=f"Límite de hosts excedido ({found} > {max_hosts})",
            details={"max_hosts": max_hosts, "found": found},
            user_message=f"El objetivo incluye más de {max_hosts} hosts."
        )


class ReportError(SecOpsException):
    """Excepción base para errores de reportes y documentos."""

    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ReportGenerationError(ReportError):
    """Error al procesar resultados del escaneo o generar los datos del reporte."""

    default_code = ErrorCode.REPORT_GENERATION_ERROR

    def __init__(self, scan_id: int, reason: str):
        super().__init__(
            message=f"Error generando reporte para escaneo {scan_id}: {reason}",
            details={"scan_id": scan_id, "reason": reason},
            user_message="No se pudo generar el reporte."
        )


class ReportNotFoundError(ReportError):
    """Reporte o documento no encontrado."""

    default_code = ErrorCode.REPORT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, report_id: str):
        super().__init__(
            message=f"Reporte '{report_id}' no encontrado",
            details={"report_id": report_id},
            user_message="El reporte solicitado no existe."
        )


class PortValidationError(ValidationError):
    """Especificación de puertos inválida (formatos válidos: '80', '80,443', '1-1000')."""

    default_code = ErrorCode.INVALID_PORT_SPEC

    def __init__(self, message: str, port_spec: str):
        super().__init__(
            message=message,
            field="ports",
            value=port_spec,
            expected="Formato: '80', '80,443', '1-1000', '80,443-8080'"
        )


class IPValidationError(ValidationError):
    """Especificación de IP inválida (formatos válidos: IP única, CIDR, o rango)."""

    default_code = ErrorCode.INVALID_IP_SPEC

    def __init__(self, message: str, ip_spec: str):
        super().__init__(
            message=message,
            field="ip_address",
            value=ip_spec,
            expected="Formato: '192.168.1.1', '192.168.1.0/24', '192.168.1.1-10'"
        )


class URLValidationError(ValidationError):
    """URL inválida (debe ser http o https)."""

    default_code = ErrorCode.INVALID_URL

    def __init__(self, message: str, url: str):
        super().__init__(
            message=message,
            field="url",
            value=url,
            expected="URL válida: http://example.com o https://example.com"
        )


class PrivateIPRequested(ScanError):
    """Se solicitó escanear IPs privadas con 'areLocalIpsAllowed' en falso."""

    default_code = ErrorCode.PRIVATE_IP_REQUESTED
    default_status_code = 403
    default_severity = ErrorSeverity.LOW

    def __init__(self, private_ips: list[str]):
        ips_list = ", ".join(private_ips)
        super().__init__(
            message=f"No se permite escanear IPs privadas: {ips_list}",
            details={"private_ips": private_ips},
            user_message="El escaneo de IPs locales/privadas está deshabilitado."
        )


class HostUnreachableError(ScanError):
    """El host objetivo no respondió a conexiones TCP antes de escanear.

    Usada internamente en ``_execute_scan_in_thread`` para marcar el escaneo
    como ``FAILED`` sin esperar al timeout de la herramienta de escaneo.
    """

    default_code = ErrorCode.SCAN_EXECUTION_ERROR
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, host: str, port: int, details: str = ""):
        super().__init__(
            message=f"Host '{host}' no alcanzable en puerto {port}: {details}",
            details={"host": host, "port": port, "reason": details},
            user_message=f"No se pudo conectar con {host} antes de iniciar el escaneo."
        )


class PDFGenerationError(ReportError):
    """Error al generar un PDF de reporte de escaneo."""

    default_code = ErrorCode.REPORT_GENERATION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str, scan_id: int | None = None):
        details = {"scan_id": scan_id} if scan_id else {}
        super().__init__(
            message=f"Error generando PDF: {message}",
            details=details,
            user_message="Error al generar el informe PDF."
        )


# =========================================================================
# EXCEPCIONES DE ESCANEO PROGRAMADO
# =========================================================================


class ProgramedScanError(ScanError):
    """Excepción base para errores de escaneos programados (recurrentes o cron)."""


class ProgramedScanNotFoundError(ProgramedScanError):
    """Escaneo programado no encontrado."""

    default_code = ErrorCode.PROGRAMED_SCAN_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, ps_id: int):
        super().__init__(
            message=f"Escaneo programado con ID {ps_id} no encontrado",
            details={"programed_scan_id": ps_id},
            user_message=f"El escaneo programado #{ps_id} no existe."
        )


class ProgramedScanAlreadyActiveError(ProgramedScanError):
    """Ya existe un escaneo programado activo con la misma configuración."""

    default_code = ErrorCode.PROGRAMED_SCAN_ALREADY_ACTIVE
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, user_id: int, scan_type: str):
        super().__init__(
            message=f"Ya existe un escaneo programado activo de tipo "
                    f"'{scan_type}' para el usuario {user_id}",
            details={"user_id": user_id, "scan_type": scan_type},
            user_message=f"Ya tienes un escaneo {scan_type} programado activo."
        )


class InvalidProgramedTaskArgumentError(ProgramedScanError):
    """Argumento requerido faltante o inválido en un escaneo programado."""

    default_code = ErrorCode.PROGRAMED_SCAN_INVALID_ARGUMENT
    default_status_code = 400
    default_severity = ErrorSeverity.LOW

    def __init__(self, scan_type: str, field: str):
        super().__init__(
            message=f"Argumento '{field}' requerido para escaneo "
                    f"{scan_type} no encontrado o inválido",
            details={"scan_type": scan_type, "field": field},
            user_message=f"Falta el argumento '{field}' para el escaneo de "
                         f"tipo '{scan_type}'."
        )


# =========================================================================
# EXCEPCIONES DE CARPETAS DE ESCANEOS
# =========================================================================

class FolderError(ScanError):
    """Excepción base para errores relacionados con carpetas de escaneos."""


class FolderNotFoundError(FolderError):
    """La carpeta no existe o no pertenece al usuario."""

    default_code = ErrorCode.SCAN_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, folder_id: int = None, message: str = None, details: dict = None, **kwargs):
        if message is None:
            message = f"Carpeta con ID {folder_id} no encontrada"
        if details is None:
            details = {"folder_id": folder_id}
        kwargs.setdefault("user_message", f"La carpeta #{folder_id} no existe." if folder_id else "Carpeta no encontrada.")
        super().__init__(message=message, details=details, **kwargs)


class FolderNameInvalidError(FolderError):
    """El nombre de carpeta contiene caracteres inválidos."""

    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400
    default_severity = ErrorSeverity.LOW

    def __init__(self, name: str):
        super().__init__(
            message=f"Nombre de carpeta inválido: '{name}'",
            details={"name": name},
            user_message="El nombre de carpeta solo puede contener letras, números, espacios, guiones y guiones bajos."
        )


class ScanAlreadyInFolderError(FolderError):
    """El escaneo ya pertenece a la carpeta destino."""

    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, scan_id: int, folder_id: int):
        super().__init__(
            message=f"El escaneo {scan_id} ya está en la carpeta {folder_id}",
            details={"scan_id": scan_id, "folder_id": folder_id},
            user_message="El escaneo ya pertenece a esta carpeta."
        )
