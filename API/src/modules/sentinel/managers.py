"""
Managers for security scan orchestration and result persistence.

This module provides manager classes for coordinating security scans:
- NmapScanManager: Network exploration and security scanning.
- NiktoScanManager: Web server vulnerability scanning.
- OpenVASScanManager: Comprehensive vulnerability management.

Each manager handles the complete lifecycle of a scan:
- Creating scan records via ScanRepository.
- Executing scans in background threads.
- Processing and saving results.
- Generating PDF reports asynchronously.

Database access is performed exclusively through UnitOfWork + ScanRepository.
ScanManager no longer inherits from BaseManager.

Usage:
    manager = NmapScanManager(user)
    scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    scan = manager.get_scan_by_id(scan_id)
"""

import hashlib
import logging
import os
import re
import uuid

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse


import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, TaskTrackingMixin, job_context
from src.modules.aegis.exceptions import DocumentError
from src.modules.shared import Document
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import get_db_session
from .services.csv_logger import ScanLoggerFactory

from .repositories import (
    ScanRepository,
    ScanFolderRepository,
    SentinelReportRepository,
    ProgramedScanRepository,
    TracerouteRepository,
    KbRepository)
from .model import (
    EllysiaScan,
    NiktoScan,
    NmapScan,
    OpenVASScan,
    ProgramedScan,
    Scan,
    ScanFolder,
    ScanStatus,
    ScanType,
    SentinelDocument,
)
from .ellysia import (
    EllysiaEngine,
    services_from_open_ports,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    score_finding,
)
from .services import (
    NiktoResultProcessor,
    NmapResultProcessor,
    OpenVASResultProcessor,
    NiktoPrintingStrategy,
    NmapPrintingStrategy,
    OpenVASPrintingStrategy,
    PDFCreator,
    OpenVASTask,
    TaskStatus,
    _Task,
    Scheduler,
    HistoryStatsService,
    TracerouteService,
)
from .services import parsing
from .exceptions import (
    ScanNotFoundError,
    FindingNotFoundError,
    InvalidProgramedTaskArgumentError,
    ProgramedScanNotFoundError,
    FolderNotFoundError,
    FolderNameInvalidError,
    ScanAlreadyInFolderError,
)


logger = logging.getLogger(__name__)


class ScanManager(TaskTrackingMixin, ABC):
    """
    Base class for scan managers.

    Coordinates task execution and result persistence without inheriting from
    BaseManager. All database access is performed through UnitOfWork and
    ScanRepository, keeping transaction boundaries explicit.

     Task lifecycle is managed by TaskQueue (the Redis-backed task queue).

    Class Attributes:
        _scan_timeout_margin: Seconds added to task timeout for wait().

    Attributes:
        user: User executing the scan operations.
        logger:      Logger instance for this manager.
    """

    _scan_timeout_margin: int = 30
    _registry: Dict[ScanType, type["ScanManager"]] = {}

    SCAN_TYPE: Optional[ScanType] = None
    _MODEL: Optional[type] = None  # Concrete Scan subclass; set by each subclass.

    EXTERNAL_ID_PREFIX = "scan:"
    TASK_CATEGORY = "sentinel.scan"

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        """
        Initialize the scan manager.

        Args:
            task_queue: Cola de tareas a usar (inyectable para tests). Por
                defecto, el singleton ``TaskQueue``.
        """
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()


    # =========================================================================
    # SCAN QUERIES
    # =========================================================================

    def get_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """
        Retrieve a scan by its primary key, typed to ``self._MODEL``.

        With request-scoped sessions, lazy loading of the subclass-specific
        relationships (open_ports_relation, incidents, results…) works
        transparently.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Scan instance (typed to ``self._MODEL``), or None if not found.
        """
        session = get_db_session()
        scan = ScanRepository(session=session).get_by_id_and_type(self._MODEL, scan_id)

        if not scan:
            logger.warning(f"Escaneo {self.SCAN_TYPE.value if self.SCAN_TYPE else ''} {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self, user_id: int) -> List[Scan]:
        """
        Retrieve all scans of ``self._MODEL`` belonging to the active user.

        Returns:
            List of Scan instances ordered by start time descending.
        """
        session = get_db_session()
        scans = ScanRepository(session=session).get_by_type_and_user(self._MODEL, user_id)

        logger.info(
            f"Se obtuvieron {len(scans)} escaneos {self.SCAN_TYPE.value if self.SCAN_TYPE else ''} para el usuario {user_id}"
        )
        return scans

    def get_scans_paginated(self, user_id: int, page: int = 1, per_page: int = 10):
        """
        Retrieve a paginated, formatted list of scans for a user.

        Uses the subclass's SCAN_TYPE to filter by scan type and delegates
        formatting to format_scan().

        Args:
            user_id:   Owner user primary key.
            page:      1‑based page number.
            per_page:  Items per page.

        Returns:
            Tuple of (formatted_results: list[dict], total_count: int).
        """
        if self.SCAN_TYPE is None:
            raise NotImplementedError("SCAN_TYPE must be defined in subclass")
        session = get_db_session()
        repo = ScanRepository(session=session)
        items, total_count = repo.get_scans_by_type_paginated(
            user_id, self.SCAN_TYPE, page, per_page
        )
        formatted = [self.format_scan(item.id) for item in items]
        return formatted, total_count

    def get_scan_progress(self, scan_id: int) -> Optional[int]:
        """
        Return the progress percentage (0-100) of a running scan.

        Delegates to the TaskQueue registry via ``TaskTrackingMixin``.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Integer percentage, or None if the scan is not in the task registry.
        """
        return self.task_progress_of(scan_id)

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        """
        Return the current status string of a scan.

        Checks the TaskQueue registry first (via ``TaskTrackingMixin``); falls
        back to the database.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Status string, or None if not found.
        """
        status = self.task_status_of(scan_id)
        if status is not None:
            return status
        if self.is_scan_finished(scan_id):
            return str(TaskStatus.COMPLETED)
        return None

    def is_scan_finished(self, scan_id: int) -> bool:
        """
        Check whether a scan has reached FINISHED status.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            True if status == FINISHED, False otherwise (including not found).
        """
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            logger.warning(f"Escaneo {scan_id} no encontrado para verificar finalización")
            return False

        return scan.status == ScanStatus.FINISHED.value # pyright: ignore[reportReturnType]

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its associated documents (including PDF files on disk).

        Args:
            scan_id: Primary key of the scan to delete.

        Returns:
            True if deleted successfully, False if the scan was not found.
        """
        try:
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                doc_repo = SentinelReportRepository(uow)

                scan = scan_repo.get_by_id(scan_id)
                if not scan:
                    return False

                docs = doc_repo.get_documents_by_scan(scan_id)

                for doc in docs:
                    if doc.filename and os.path.exists(doc.filename): # type: ignore
                        try:
                            os.remove(doc.filename) # type: ignore
                            logger.info(f"Archivo eliminado: {doc.filename}")
                        except (OSError, IOError) as e:
                            logger.warning(f"No se pudo eliminar archivo {doc.filename}: {e}", exc_info=True)
                    doc_repo.delete(doc)

                scan_repo.delete(scan)
                # UnitOfWork commits on __exit__

            logger.info(f"Escaneo {scan_id} eliminado")
            return True

        except (OSError, RuntimeError) as e:
            logger.error(f"Error eliminando escaneo {scan_id}: {e}", exc_info=True)
            raise


    @classmethod
    def bulk_delete_scans(cls, scan_ids: list[int], user_id: int) -> dict:
        """
        Delete multiple scans and their documents in a single operation.

        Cancels running scans before deleting. Returns per-scan status.

        Args:
            scan_ids: List of scan primary keys.
            user_id:  Owner user primary key.

        Returns:
            Dict with ``deletedCount``, ``failedCount``, and ``results`` list.
        """
        results = []
        for scan_id in scan_ids:
            try:
                mgr = cls.resolve_manager(scan_id)
                cls.assert_scan_ownership(scan_id, user_id)
                scan = mgr.get_scan_by_id(scan_id)
                if not scan:
                    results.append({"scanId": scan_id, "status": "error", "error": "not_found"})
                    continue

                if scan.status in ("pending", "running"):
                    mgr.cancel_scan(scan_id, user_id)

                mgr.delete_scan(scan_id)
                results.append({"scanId": scan_id, "status": "ok", "error": None})
            except Exception as e:
                results.append({"scanId": scan_id, "status": "error", "error": str(e)})

        deleted = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - deleted
        return {
            "deletedCount": deleted,
            "failedCount": failed,
            "results": results,
        }


    # =========================================================================
    # OWNERSHIP ASSERTIONS
    # =========================================================================

    @classmethod
    def assert_scan_ownership(cls, scan_id: int, user_id: int) -> Scan:
        """
        Verifica que el escaneo pertenece al usuario. Lanza ScanNotFoundError
        si no pertenece para evitar enumerar IDs ajenos.

        Args:
            scan_id: ID del escaneo a verificar.
            user_id: ID del usuario que debería ser propietario.

        Raises:
            ScanNotFoundError: Si el escaneo no pertenece al usuario.
        """
        session = get_db_session()
        scan = ScanRepository(session=session).get_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        from src.modules.users.exceptions import UserNotFoundError
        from src.modules.users import UserManager
        user = UserManager().get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)

        if scan.user_id != user_id: # type: ignore
            raise ScanNotFoundError(scan_id)

        return scan

    @classmethod
    def resolve_owned_scan(cls, scan_id: int, user_id: int) -> tuple["ScanManager", Scan]:
        """
        Resolve the manager for ``scan_id`` and assert the user owns it.

        Combines ``resolve_manager`` with ``assert_scan_ownership`` in one call,
        avoiding a second lookup of the same scan in callers that need both.

        Raises:
            ScanNotFoundError: If the scan does not exist or is not owned by ``user_id``.
        """
        scan = cls.assert_scan_ownership(scan_id, user_id)
        return cls.resolve_manager(scan_id), scan

    # =========================================================================
    # LIFECYCLE OPERATIONS
    # =========================================================================

    def cancel_scan(self, scan_id: int, user_id: int) -> bool:
        """
        Cancel a running scan.

        Signals the TaskQueue task to stop and marks the scan as CANCELLED
        in the database.

        Args:
            scan_id: Primary key of the scan to cancel.
            user_id: ID of the user requesting cancellation.

        Returns:
            True if cancelled successfully, False otherwise.
        """
        try:
            # Valida existencia del escaneo, del usuario y la propiedad en un
            # único punto (lanza ScanNotFoundError/UserNotFoundError si falla).
            scan = self.assert_scan_ownership(scan_id, user_id)

            if scan.status not in ("pending", "running"):
                logger.warning(
                    f"El escaneo {scan_id} no se puede cancelar "
                    f"(estado actual: {scan.status})"
                )
                return False

            sq_task = self.find_task(scan_id)

            if sq_task is None:
                logger.warning(
                    f"No se encontro tarea activa para el escaneo {scan_id}"
                )
                return False

            cancelled = self._tq.cancel(sq_task.id)
            if not cancelled:
                logger.warning(f"No se pudo cancelar la tarea del escaneo {scan_id}")
                return False

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                fresh_scan = scan_repo.get_by_id(scan_id)
                if fresh_scan:
                    scan_repo.update_status(fresh_scan, ScanStatus.CANCELLED)

            logger.info(f"Escaneo {scan_id} cancelado exitosamente")
            return True

        except (OSError, RuntimeError) as e:
            logger.error(f"Error cancelando escaneo {scan_id}: {e}", exc_info=True)
            return False

    @classmethod
    def reconcile_orphaned_scans(cls) -> int:
        """
        Marca como FAILED los escaneos huérfanos tras un apagado abrupto.

        Si el proceso se mata mientras un escaneo está en PENDING/RUNNING, no
        queda ninguna tarea viva en TaskQueue que lo actualice tras reiniciar:
        el registro se queda en "running" para siempre y bloquea, p. ej., que
        ``Scheduler`` vuelva a lanzar ese escaneo programado (ver
        ``scheduling.py``). Se llama una vez al arrancar la API.

        Returns:
            Número de escaneos marcados como FAILED.
        """
        tq = TaskQueue.get_instance()
        fixed = 0
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            for scan in repo.get_active_scans():
                external_id = f"{cls.EXTERNAL_ID_PREFIX}{scan.id}"
                task = tq.get_task_by_external_id(external_id, cls.TASK_CATEGORY)
                # PENDING: el job sigue encolado en Redis y un nuevo worker lo
                # recogerá normalmente. Cualquier otro caso (None, RUNNING
                # "started" sin worker vivo, o un estado terminal que no llegó
                # a sincronizarse) es un huérfano del proceso anterior.
                if task is not None and task.status == TaskStatus.PENDING:
                    continue
                repo.update_status(scan, ScanStatus.FAILED)
                fixed += 1
        return fixed

    # =========================================================================
    # INTERNAL SCAN EXECUTION
    # =========================================================================

    def _execute_scan(
        self,
        scan_id: int,
        task: _Task,
        skip_normalize: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Execute a scan and persist its results, with cancellation support.

        Args:
            scan_id:       Primary key of the scan being executed.
            task:          Task instance that drives the actual scanning.
            skip_normalize: Skip IP normalization if True.
            cancel_check:  Optional callable returning True to cancel the scan.
        """
        thread_manager = self.__class__()
        fresh_scan = None

        try:
            with UnitOfWork() as uow:
                scan = ScanRepository(uow).get_by_id(scan_id)
            if not scan:
                logger.error(f"Escaneo {scan_id} no encontrado en el hilo")
                return

            thread_manager.update_scan_status(scan_id, ScanStatus.RUNNING)
            logger.info(f"Iniciando escaneo {scan_id}")

            if CR.is_host_reachability_check_enabled():
                raw_target = scan.target if "://" in scan.target else f"tcp://{scan.target}"
                parsed_target = urlparse(url=raw_target) # type: ignore
                host = parsed_target.hostname or scan.target
                reachable_port = parsed_target.port or CR.get_host_reachability_check_port()
                reachable_timeout = CR.get_host_reachability_check_timeout()
                if not self.is_host_reachable(host=host, port=reachable_port, timeout=reachable_timeout): # type: ignore
                    logger.warning(
                        f"Host '{host}' inalcanzable en puerto {reachable_port}. "
                        f"Marcando escaneo {scan_id} como FAILED"
                    )
                    thread_manager.update_scan_status(scan_id, ScanStatus.FAILED)
                    return

            task.scan()
            success = task.wait(
                timeout=task.timeout + self._scan_timeout_margin,
                cancel_check=cancel_check,
            )

            no_results = task.results is None
            if not success or no_results:
                if task.status == TaskStatus.CANCELLED:
                    logger.info(f"Escaneo {scan_id} cancelado por el usuario")
                    thread_manager.update_scan_status(scan_id, ScanStatus.CANCELLED)
                else:
                    logger.error(f"Escaneo {scan_id} falló. Estado: {task.status}")
                    thread_manager.update_scan_status(scan_id, ScanStatus.FAILED)
                return

            logger.info(f"Procesando resultados de escaneo {scan_id}")

            processor  = thread_manager.result_processor # type: ignore
            scan_type = scan.scan_type
            domain_data = processor.process(task.results, scan.target) if scan_type == "nmap" else processor.process(task.results) # type: ignore

            with UnitOfWork() as uow:
                fresh_scan              = ScanRepository(uow).get_by_id(scan_id)
                thread_manager._persist_scan_results(uow, fresh_scan, domain_data)
                fresh_scan.status       = ScanStatus.FINISHED.value # type: ignore
                fresh_scan.finished_at  = datetime.now() # type: ignore

            logger.info(f"Escaneo {scan_id} completado exitosamente")
            thread_manager._log_to_csv(scan_id, fresh_scan, task)

        except Exception as e:
            if task.status == TaskStatus.CANCELLED:
                logger.info(f"Escaneo {scan_id} cancelado por el usuario")
                thread_manager.update_scan_status(scan_id, ScanStatus.CANCELLED)
            else:
                logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
                thread_manager.update_scan_status(scan_id, ScanStatus.FAILED)
            thread_manager._log_to_csv(scan_id, fresh_scan, task)

    def update_scan_status(self, scan_id: int, status: ScanStatus) -> None:
        """
        Persist a status change for a scan, ignoring errors (best-effort).

        Args:
            scan_id: Primary key of the scan.
            status:  New ScanStatus value.
        """
        try:
            with UnitOfWork() as uow:
                repo = ScanRepository(uow)
                scan = repo.get_by_id(scan_id)
                if scan:
                    repo.update_status(scan, status)
        except (OSError, RuntimeError) as update_err:
            logger.error(f"Error actualizando estado de escaneo {scan_id}: {update_err}", exc_info=True)

    def _log_to_csv(self, scan_id: int, scan: Scan, task: "_Task") -> None:
        """
        Registra el escaneo en el CSV correspondiente.
        Fallos en logging no interrumpen el flujo del scan.

        Args:
            scan_id: Primary key del escaneo.
            scan: Instancia del scan (puede estar detached de la sesión).
            task: Task que ejecutó el scan.
        """
        try:
            with UnitOfWork() as uow:
                fresh_scan = ScanRepository(uow).get_by_id(scan_id)
                scan_type = fresh_scan.scan_type # type: ignore
                start = fresh_scan.started_at # type: ignore
                end = fresh_scan.finished_at # type: ignore
                status = fresh_scan.status # type: ignore
                duration = (end - start).total_seconds() if end and start else 0 # type: ignore

                data = {
                    "duration_sec": round(duration, 2),
                    "status": status,
                    "concurrent_tasks": self._tq.get_status()["runningCount"],
                }

                self.append_csv_data(data, fresh_scan, task)

            logger_obj = ScanLoggerFactory.get(scan_type) # type: ignore
            logger_obj.log(data)
            logger.debug(f"Escaneo {scan_id} registrado en CSV ({scan_type})")
        except Exception as csv_err:
            logger.warning(f"Error registrando escaneo {scan_id} en CSV: {csv_err}", exc_info=True)


    # =========================================================================
    # STATIC UTILITIES
    # =========================================================================

    @classmethod
    def register(cls, scan_type: ScanType):
        def decorator(subclass: type["ScanManager"]):
            cls._registry[scan_type] = subclass
            return subclass
        return decorator

    @classmethod
    def resolve_manager(cls, scan_id: int) -> "ScanManager":
        raw_type = cls.get_scan_type(scan_id)
        try:
            scan_type = ScanType(raw_type)
        except ValueError:
            raise ScanNotFoundError(scan_id)
        manager_class = cls._registry.get(scan_type)
        if manager_class is None:
            raise ScanNotFoundError(scan_id)
        return manager_class()

    @classmethod
    def get_scan_rich(cls, scan_id: int) -> Scan:
        """Get scan with relationships eagerly loaded for background threads.

        Uses UnitOfWork with eager-loading repository methods so that the
        returned scan is fully populated before the session closes. Only
        needed when lazy loading is unavailable (e.g. PDF generation thread).

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Scan instance with all relationships loaded.

        Raises:
            ScanNotFoundError: If scan_id not found or type not registered.
        """
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            if scan is None:
                raise ScanNotFoundError(scan_id)
            scan_type_raw = scan.scan_type

            try:
                scan_type = ScanType(scan_type_raw)
            except ValueError:
                raise ScanNotFoundError(scan_id)

            if scan_type == ScanType.NMAP:
                scan =  repo.get_nmap_rich(scan_id)
            elif scan_type == ScanType.NIKTO:
                scan = repo.get_nikto_rich(scan_id)
            else:
                scan = repo.get_openvas_rich(scan_id)

        return scan

    @classmethod
    def get_scan_type(cls, scan_id: int) -> Optional[str]:
        """
        Devuelve el tipo del escaneo en función de su id.

        Uses UnitOfWork because it is called from both request context
        (resolve_manager) and background threads (resolve_printing_strategy).

        Args:
            scan_id: Id del escaneo a revisar

        Returns:
            Tipo del escaneo ("nmap", "nikto", "openvas")
        """

        with UnitOfWork() as uow:
            scan = ScanRepository(uow).get_by_id(scan_id)
            if scan is None:
                raise ScanNotFoundError(scan_id)

            scan_type = scan.scan_type

            if scan_type is None:
                return None

            return scan_type # pyright: ignore[reportReturnType]

    @classmethod
    def _append_document_info(cls, scan, result: dict) -> None:
        """Append the latest document ID and status to a scan result dict."""
        inst = SentinelReportManager()
        doc = inst.get_latest_document_by_scan_id(scan.id)
        if doc:
            result["documentId"] = doc.id
            result["documentStatus"] = doc.status

    @staticmethod
    def validate_ip(ips_str: str, max_hosts: int = 10) -> List[str]:
        """Valida y expande una especificación de IPs/rangos.

        Ver ``sentinel.services.parsing.validate_ip`` para los formatos
        soportados y las excepciones que puede lanzar.
        """
        return parsing.validate_ip(ips_str, max_hosts)

    @staticmethod
    def validate_port(ports_str: str) -> List[int]:
        """Valida y expande una especificación de puertos.

        Ver ``sentinel.services.parsing.validate_port`` para las reglas de
        validación y las excepciones que puede lanzar.
        """
        return parsing.validate_port(ports_str)

    @staticmethod
    def is_host_reachable(host: str, port: int = 80, timeout: float = 3.0) -> bool:
        """
        Verifica conectividad básica con un host sin dependencias externas.

        Primero intenta TCP con ``socket.create_connection`` (maneja resolución
        DNS automáticamente). Si el host responde con ``ConnectionRefusedError``
        se considera alcanzable (el puerto está cerrado pero el host está vivo
        y responde).

        Si el puerto TCP no responde (timeout/sin ruta), se hace un fallback a
        ``ping`` (ICMP echo): un host con firewall que descarta silenciosamente
        los paquetes a puertos cerrados (p. ej. Windows Firewall por defecto)
        daría un falso "inalcanzable" con solo el chequeo TCP, aunque nmap
        encontraría puertos abiertos en otros rangos.

        Args:
            host:    Dirección IP o hostname a comprobar.
            port:    Puerto TCP de destino (default: 80).
            timeout: Tiempo máximo de espera en segundos (default: 3.0).

        Returns:
            ``True`` si el host responde (TCP aceptado/rechazado o ping ICMP).
            ``False`` si no hay respuesta por ninguna vía.
        """
        import socket
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except ConnectionRefusedError:
            return True
        except (socket.timeout, OSError):
            pass

        return ScanManager._ping_host(host, timeout)

    @staticmethod
    def _ping_host(host: str, timeout: float) -> bool:
        """Fallback ICMP echo (``ping -c 1``) cuando el puerto TCP no responde."""
        import subprocess
        deadline = max(1, int(round(timeout)))
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(deadline), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=deadline + 1,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    # =========================================================================
    # ABSTRACT INTERFACE
    # =========================================================================

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """Start a new scan. Returns the scan's primary key."""

    @abstractmethod
    def _create_scan_record(self, **kwargs) -> Scan:
        """Create and persist the initial scan record."""

    @abstractmethod
    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist domain data into the database within the given UnitOfWork."""

    @abstractmethod
    def format_scan(self, scan_id: int) -> dict:
        """
        Formatea un escaneo como diccionario JSON.

        Args:
            scan_id: ID del escaneo.

        Returns:
            Diccionario con los datos del escaneo en formato JSON.
        """

    @abstractmethod
    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """Añade datos específicos del tipo de scan al diccionario data para el CSV."""
        pass


class ProgramedScanManager():

    _REQUIRED_ARGS: dict[ScanType, List[str]] = {
        ScanType.NMAP:      ["target_host", "target_ports"],
        ScanType.NIKTO:     ["target_domain"],
        ScanType.OPENVAS:   ["target"]
    }

    @classmethod
    def register(
        cls,
        user_id: int,
        scan_type: ScanType,
        arguments: dict[str, str],
        schedule_type: str,
        schedule_config: dict
    ):
        cls._assert_valid_arguments(
            scan_type=scan_type,
            arguments=arguments
        )
        cls._assert_valid_scheduling_config(
            schedule_type=schedule_type,
            schedule_config=schedule_config
        )
        next_run = Scheduler.calculate_next_run(
            schedule_type=schedule_type,
            schedule_config=schedule_config,
        )
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.create(
                user_id=user_id,
                scan_type=scan_type,
                arguments=arguments,
                schedule_type=schedule_type,
                schedule_config=schedule_config,
                next_run_at=next_run,
            )

        Scheduler.schedule(
            ps_id=ps.id,
            scan_type=ps.scan_type,
            user_id=ps.user_id,
            schedule_type=schedule_type,
            schedule_config=schedule_config,
        )
        return ps

    @classmethod
    def _assert_valid_arguments(cls, scan_type: ScanType, arguments: dict[str, str]):
        required_list = cls._REQUIRED_ARGS[scan_type]

        for field in required_list:
            if arguments.get(field) is None:
                raise InvalidProgramedTaskArgumentError(scan_type, field)

    @classmethod
    def _assert_valid_scheduling_config(
        cls,
        schedule_type: str,
        schedule_config: dict
    ):
        if schedule_type == "interval":
            every = schedule_config.get("every")
            if not isinstance(every, (int, float)) or every <= 0:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"interval every must be > 0, got: {every}"
                )
            unit = schedule_config.get("unit")
            if unit not in ("minutes", "hours", "days"):
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"invalid interval unit: {unit}"
                )

        elif schedule_type == "cron":
            cron_expr = schedule_config.get("cron")
            if not cron_expr:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, "missing cron expression"
                )
            try:
                from croniter import croniter as _ci
                _ci(cron_expr, datetime.now())
            except Exception:
                raise InvalidProgramedTaskArgumentError(
                    schedule_type, f"invalid cron expression: {cron_expr}"
                )

        else:
            raise InvalidProgramedTaskArgumentError(
                schedule_type, f"unknown schedule_type: {schedule_type}"
            )

    @classmethod
    def assert_ownership(cls, ps_id: int, user_id: int) -> ProgramedScan:
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if not ps:
                raise ProgramedScanNotFoundError(ps_id)
            if ps.user_id != user_id: # type: ignore
                raise ProgramedScanNotFoundError(ps_id)
            return ps

    @classmethod
    def get_scans_for_user(cls, user_id: int) -> List[ProgramedScan]:
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            programed_scans = repo.get_by_user(user_id)

        return programed_scans

    @classmethod
    def revoke(cls, ps_id: int, user_id: int) -> None:
        Scheduler.unschedule(ps_id)
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)
            if ps.user_id != user_id: # type: ignore
                raise ProgramedScanNotFoundError(ps_id)
            ps.is_active = False # type: ignore
            repo.update(ps)

    @classmethod
    def delete(cls, ps_id: int, user_id: int) -> None:
        Scheduler.unschedule(ps_id)
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if ps is None:
                raise ProgramedScanNotFoundError(ps_id)
            if ps.user_id != user_id: # type: ignore
                raise ProgramedScanNotFoundError(ps_id)
            repo.delete(ps)


# =============================================================================
# SCAN FOLDERS
# =============================================================================

class ScanFolderManager:
    """
    Manager for scan folder lifecycle.

    Handles creation, renaming, deletion and scan assignment. A scan can belong
    to at most one folder; deleting a folder leaves its scans unassigned.
    """

    _FOLDER_NAME_RE = re.compile(r"^[a-zA-Z0-9\s_-]+$")

    @staticmethod
    def _validate_name(name: str) -> str:
        """Strip and validate a folder name, raising FolderNameInvalidError if invalid."""
        stripped = (name or "").strip()
        if not stripped or not ScanFolderManager._FOLDER_NAME_RE.match(stripped):
            raise FolderNameInvalidError(name)
        return stripped

    @staticmethod
    def _assert_scan_ownership(scan: Scan, user_id: int) -> None:
        """Raise ScanNotFoundError if the scan does not belong to the user."""
        if scan is None or scan.user_id != user_id:
            raise ScanNotFoundError(scan.id if scan else 0)

    @staticmethod
    def _assert_folder_ownership(folder: ScanFolder, user_id: int) -> None:
        """Raise FolderNotFoundError if the folder does not belong to the user."""
        if folder is None or folder.user_id != user_id:
            raise FolderNotFoundError(folder.id if folder else 0)

    def create_folder(self, user_id: int, name: str) -> ScanFolder:
        """Create and persist a new folder for the user."""
        validated_name = self._validate_name(name)
        with UnitOfWork() as uow:
            folder = ScanFolder(user_id=user_id, name=validated_name)
            ScanFolderRepository(uow).save(folder)
        logger.info(f"Carpeta '{validated_name}' creada para usuario {user_id}")
        return folder

    def rename_folder(self, folder_id: int, user_id: int, name: str) -> ScanFolder:
        """Rename an existing folder owned by the user."""
        validated_name = self._validate_name(name)
        with UnitOfWork() as uow:
            repo = ScanFolderRepository(uow)
            folder = repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)
            folder.name = validated_name  # type: ignore
            repo.update(folder)
        logger.info(f"Carpeta {folder_id} renombrada a '{validated_name}'")
        return folder

    def delete_folder(self, folder_id: int, user_id: int) -> None:
        """Delete a folder and unassign its scans (folder_id -> NULL)."""
        with UnitOfWork() as uow:
            folder_repo = ScanFolderRepository(uow)
            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            scan_repo = ScanRepository(uow)
            for scan in scan_repo.get_by_folder(folder_id, user_id):
                scan_repo.unset_folder(scan)

            folder_repo.delete(folder)
        logger.info(f"Carpeta {folder_id} eliminada por usuario {user_id}")

    def move_scan_to_folder(self, scan_id: int, folder_id: int, user_id: int) -> Scan:
        """Move a scan into a folder, replacing any previous folder assignment."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            scan = scan_repo.get_by_id(scan_id)
            self._assert_scan_ownership(scan, user_id)

            folder_repo = ScanFolderRepository(uow)
            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            if scan.folder_id == folder_id:
                raise ScanAlreadyInFolderError(scan_id, folder_id)

            scan_repo.set_folder(scan, folder)
        logger.info(f"Escaneo {scan_id} movido a carpeta {folder_id}")
        return scan

    def add_scans_to_folder(self, scan_ids: list[int], folder_id: int, user_id: int) -> list[Scan]:
        """Add multiple scans to a folder at once."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            folder_repo = ScanFolderRepository(uow)

            folder = folder_repo.get_by_id_and_user(folder_id, user_id)
            self._assert_folder_ownership(folder, user_id)

            added = []
            for scan_id in scan_ids:
                scan = scan_repo.get_by_id(scan_id)
                self._assert_scan_ownership(scan, user_id)
                if scan.folder_id == folder_id:
                    continue
                scan_repo.set_folder(scan, folder)
                added.append(scan)

        logger.info(f"{len(added)} escaneos añadidos a carpeta {folder_id}")
        return added

    def remove_scan_from_folder(self, scan_id: int, user_id: int) -> Scan:
        """Remove a scan from its current folder."""
        with UnitOfWork() as uow:
            scan_repo = ScanRepository(uow)
            scan = scan_repo.get_by_id(scan_id)
            self._assert_scan_ownership(scan, user_id)

            if scan.folder_id is None:
                return scan

            scan_repo.unset_folder(scan)
        logger.info(f"Escaneo {scan_id} sacado de su carpeta")
        return scan

    def get_folders_with_scans(self, user_id: int) -> dict:
        """
        Return all user folders with their scans plus an unfoldered group.

        Returns:
            Dict with keys ``folders`` (list) and ``unfoldered`` (dict).
        """
        default_name = CR.get_sentinel_default_folder_name()

        with UnitOfWork() as uow:
            folder_repo = ScanFolderRepository(uow)
            scan_repo = ScanRepository(uow)

            folders = folder_repo.get_by_user(user_id)
            result_folders = []
            for folder in folders:
                scans = scan_repo.get_by_folder(folder.id, user_id)
                result_folders.append({
                    "id": folder.id,
                    "name": folder.name,
                    "createdAt": folder.created_at,
                    "updatedAt": folder.updated_at,
                    "scanCount": len(scans),
                    "scans": [self._format_scan(scan) for scan in scans],
                })

            unfoldered_scans = scan_repo.get_unfoldered_by_user(user_id)
            unfoldered = {
                "id": None,
                "name": default_name,
                "scanCount": len(unfoldered_scans),
                "scans": [self._format_scan(scan) for scan in unfoldered_scans],
            }

        return {
            "folders": result_folders,
            "unfoldered": unfoldered,
        }

    @staticmethod
    def _format_scan(scan: Scan) -> dict:
        """Format a scan using the appropriate type manager."""
        manager = ScanManager.resolve_manager(scan.id)
        return manager.format_scan(scan.id)


# =============================================================================
# NMAP
# =============================================================================

class ScanHistoryManager:
    """
    Manager for per-host historical scan statistics.

    Orchestrates UnitOfWork + ScanRepository + HistoryStatsService to produce
    the chart-ready payload consumed by both the REST endpoint and the PDF
    report. Every query is scoped to the owning user, so a user can only ever
    see statistics built from their own scans.
    """

    def list_scanned_hosts(self, user_id: int) -> List[dict]:
        """Return the distinct hosts the user has finished scanning."""
        with UnitOfWork() as uow:
            return ScanRepository(uow).get_scanned_targets(user_id)

    def get_host_history(self, user_id: int, target: str, scan_type: ScanType) -> dict:
        """Build the historical statistics payload for a host + tool.

        Args:
            user_id:   Owner user primary key (enforces the security scope).
            target:    The scanned host.
            scan_type: The tool discriminator (nmap/nikto/openvas).

        Returns:
            JSON-serializable statistics payload (see HistoryStatsService.build).
        """
        scan_type = ScanType(scan_type)
        limit = CR.get_sentinel_history_size()
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_recent_finished(
                user_id, target, scan_type, limit
            )
            scans = list(reversed(scans))  # ascending (oldest -> newest) for charting
            return HistoryStatsService().build(scans, scan_type, target)


class TracerouteManager(TaskTrackingMixin):
    """
    Manager for cached traceroutes from the Ellysia server to scan targets.

    The traceroute is **computed asynchronously** by a background worker (the
    probe can take up to a minute on an unreachable host, which must not block
    the request thread). The REST endpoint never runs the command itself: it
    serves the cached path when fresh, otherwise enqueues a job and replies
    immediately with ``status="pending"`` so the client can poll until the
    result is ready.

    State machine (no dedicated DB column — derived from the cached row plus the
    live RQ task, which keeps this project migration-free):
        - ``done``    → a row with hops exists and is within ``cacheHours``.
        - ``failed``  → a row with **empty** hops exists and is within
          ``retryFailedMinutes`` (a terminal "no route" result; kept briefly so
          we do not re-probe an unreachable host on every modal open, but short
          enough to retry soon and overridable via refresh).
        - ``pending`` → a job is enqueued/running, or one was just submitted.

    Results are cached per (user, target) and reused across all scan types
    (Nmap, Nikto, OpenVAS). Every operation is scoped to the owning user via
    ``ScanManager.assert_scan_ownership`` so a user can only ever trace targets
    from their own scans.
    """

    EXTERNAL_ID_PREFIX = "sentinel-traceroute:"
    TASK_CATEGORY = "sentinel.traceroute"

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        """Initialize the manager.

        Args:
            task_queue: Task queue to use (injectable for tests). Defaults to
                the singleton ``TaskQueue``.
        """
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    # =========================================================================
    # REQUEST-SIDE (non-blocking)
    # =========================================================================

    def get_for_scan(self, scan_id: int, user_id: int, force_refresh: bool = False) -> dict:
        """Return the traceroute for a scan's target without blocking.

        Serves a fresh cached result when available; otherwise enqueues a
        background job and returns a ``pending`` payload for the client to poll.

        Args:
            scan_id:       Scan whose target to trace.
            user_id:       Owner user primary key (enforces the security scope).
            force_refresh: If True, ignore the cache and recompute.

        Returns:
            JSON-serializable payload: ``target``, ``hops``, ``hopCount``,
            ``computedAt`` (ISO), ``cached`` (bool) and ``status`` (one of
            ``pending`` / ``done`` / ``failed``).
        """
        scan = ScanManager.assert_scan_ownership(scan_id, user_id)
        target = scan.target

        if not force_refresh:
            cached = self._get_fresh_cached(user_id, target)
            if cached is not None:
                return cached

            # A job already in flight for this (user, target): just report it.
            task = self.find_task(self._trace_key(user_id, target))
            if task is not None and task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                return self._pending(target)

        self._enqueue(user_id, target)
        return self._pending(target)

    def _enqueue(self, user_id: int, target: str) -> None:
        """Submit the traceroute job to the background worker.

        Uses a stable job id per (user, target) so a refresh replaces any job
        still in flight instead of piling up duplicate probes. The job name must
        be RQ-safe (letters, numbers, _, -); external_id can have other chars.
        """
        key = self._trace_key(user_id, target)
        timeout = int(CR.get_sentinel_traceroute_timeout()) + 30
        self._tq.submit(
            func=TracerouteManager.execute_traceroute,
            args=(user_id, target),
            name=f"traceroute_{key}",  # RQ-safe job name
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(key),  # can have any chars
            timeout=timeout,
        )
        logger.info(f"Traceroute encolado para usuario {user_id}, target '{target}'")

    def _get_fresh_cached(self, user_id: int, target: str):
        """Return the cached payload if the stored row is still fresh, else None.

        A row with hops is fresh for ``cacheHours``; an empty (failed) row is
        fresh for the much shorter ``retryFailedMinutes`` so transient failures
        clear quickly without re-probing on every open.
        """
        with UnitOfWork() as uow:
            trace = TracerouteRepository(uow).get_by_user_and_target(user_id, target)
            if trace is None:
                return None
            if trace.hops:
                max_age = timedelta(hours=CR.get_sentinel_traceroute_cache_hours())
            else:
                max_age = timedelta(minutes=CR.get_sentinel_traceroute_retry_failed_minutes())
            if datetime.utcnow() - trace.created_at > max_age:
                return None
            return self._format(trace, cached_hit=True)

    # =========================================================================
    # WORKER-SIDE (background)
    # =========================================================================

    @staticmethod
    def execute_traceroute(user_id: int, target: str) -> None:
        """Entry point submitted to the TaskQueue: run the probe and persist it.

        Runs in the background worker. ``TracerouteService.trace`` swallows its
        own errors and returns an empty list on failure, so the row is always
        written — an empty ``hops`` list is the terminal "no route" marker that
        stops the client from polling forever.
        """
        with job_context():
            hops = TracerouteService().trace(TracerouteManager._probe_host(target))
            with UnitOfWork() as uow:
                TracerouteRepository(uow).upsert(user_id, target, hops)
            if not hops:
                logger.warning(
                    f"Traceroute vacío para target '{target}' (usuario {user_id}); "
                    f"se cachea como fallo temporal. Revisa los logs de "
                    f"TracerouteService para la causa."
                )
            else:
                logger.info(
                    f"Traceroute calculado para target '{target}' "
                    f"(usuario {user_id}): {len(hops)} saltos"
                )

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _trace_key(user_id: int, target: str) -> str:
        """Stable per (user, target) key for the job id / external id.

        Uses a hash because the target may contain URL characters (/, :, ?) that
        RQ rejects in job IDs. The hash is deterministic and collision-resistant.
        """
        hash_obj = hashlib.sha256(f"{user_id}:{target}".encode())
        return f"{user_id}_{hash_obj.hexdigest()[:12]}"

    @staticmethod
    def _probe_host(target: str) -> str:
        """Resolve the host to probe from a stored target (strips URL/scheme).

        The cache key stays the user-facing ``target`` string, but the actual
        probe goes to the resolved IP for reliability (Nikto stores URLs).
        """
        from src.modules.shared._endpoints import normalize_target
        try:
            ip, _ = normalize_target(target)
            return ip or target
        except ValueError:
            return target

    @staticmethod
    def _pending(target: str) -> dict:
        """Payload returned while the traceroute is still being computed."""
        return {
            "target": target,
            "hops": [],
            "hopCount": 0,
            "computedAt": None,
            "cached": False,
            "status": "pending",
        }

    @staticmethod
    def _format(trace, cached_hit: bool) -> dict:
        """Format a Traceroute row as a JSON-serializable payload.

        ``status`` is derived from the stored hops: a row with hops is a
        successful ``done`` result, an empty row is a terminal ``failed`` one.
        """
        return {
            "target": trace.target,
            "hops": trace.hops,
            "hopCount": trace.hop_count,
            "computedAt": trace.created_at.isoformat() if trace.created_at else None,
            "cached": cached_hit,
            "status": "done" if trace.hops else "failed",
        }


@ScanManager.register(ScanType.NMAP)
class NmapScanManager(ScanManager):
    SCAN_TYPE = ScanType.NMAP
    _MODEL = NmapScan
    _strategy_class = NmapPrintingStrategy

    """
    Manager for Nmap network security scans.

    Handles Nmap scan execution, result processing, and async PDF generation.

    Example:
    >>> manager = NmapScanManager(user)
    >>> scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    """

    def __init__(self):
        super().__init__()
        self.result_processor = NmapResultProcessor()

    def run_scan(
            self,
            target_host: str,
            target_ports: str,
            user_id: int,
            timeout: int = 300,
            programed_scan_id: Optional[int] = None
    ) -> int:  # pylint: disable=arguments-differ
        """
        Start an Nmap scan in a background thread.

        Args:
            target_host:  Target IP address or hostname.
            target_ports: Port range to scan (e.g., "1-1000").
            timeout:      Maximum scan duration in seconds.

        Returns:
            Primary key of the created NmapScan record.
        """
        try:
            scan    = self._create_scan_record(
                target=target_host,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id = scan.id

            self._tq.submit(
                func=NmapScanManager.execute_nmap_scan,
                args=(scan_id, target_host, target_ports, timeout),
                name=f"NmapScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=timeout + self._scan_timeout_margin,
            )

            logger.info(f"Escaneo Nmap {scan_id} iniciado")

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)

        return scan_id # type: ignore

    @staticmethod
    def execute_nmap_scan(scan_id: int, target_host: str, target_ports: str, timeout: int) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nmap scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.sentinel.services.tasks import NmapScanTask

            task = NmapScanTask(
                target_host=target_host,
                target_ports=target_ports,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NmapScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> NmapScan: # pylint: disable=arguments-differ
        """Create and persist an NmapScan row."""
        scan = NmapScan(target=target, user_id=user_id, started_at=datetime.now(), programed_scan_id=programed_scan_id)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nmap host and port data into the database."""
        host_data, ports_data = domain_data
        scan_repo = ScanRepository(uow)
        host = scan_repo.get_or_create_host(
            hostname    = host_data["hostname"],
            ip_address  = host_data["ip_address"],
            mac_address = host_data["mac_address"],
            vendor      = host_data["vendor"],
        )
        scan_repo.persist_nmap_results(scan, host, ports_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nmap",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None, # type: ignore
            "openPorts": [
                {"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason}
                for p in scan.open_ports_relation
            ],
            "totalOpenPorts": len(scan.open_ports_relation),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target_host"] = scan.target
        data["target_ports"] = getattr(task, "target_ports", "")
        data["timeout_sec"] = task.timeout


# =============================================================================
# NIKTO
# =============================================================================

@ScanManager.register(ScanType.NIKTO)
class NiktoScanManager(ScanManager):
    SCAN_TYPE = ScanType.NIKTO
    _MODEL = NiktoScan
    _strategy_class = NiktoPrintingStrategy

    """
    Manager for Nikto web vulnerability scans.

    Example:
    >>> manager = NiktoScanManager(user)
    >>> scan_id = manager.run_scan(target_domain="example.com")
    """

    def __init__(self):
        super().__init__()
        self.result_processor = NiktoResultProcessor()

    def run_scan(self, target_domain: str, user_id: int, timeout: int = 6000, programed_scan_id: Optional[int] = None) -> int:  # pylint: disable=arguments-differ
        """
        Start a Nikto scan in a background thread.

        Args:
            target_domain: Target domain or hostname.
            timeout:       Maximum scan duration in seconds.

        Returns:
            Primary key of the created NiktoScan record.
        """
        try:
            scan = self._create_scan_record(
                target=target_domain,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id = scan.id

            self._tq.submit(
                func=NiktoScanManager.execute_nikto_scan,
                args=(scan_id, target_domain, timeout),
                name=f"NiktoScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=timeout + self._scan_timeout_margin,
            )

            logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_nikto_scan(scan_id: int, target_domain: str, timeout: int) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nikto scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.sentinel.services.tasks import NiktoScanTask

            task = NiktoScanTask(
                target_domain=target_domain,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NiktoScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> NiktoScan: # pylint: disable=arguments-differ
        """Create and persist a NiktoScan row."""
        scan = NiktoScan(target=target, user_id=user_id, started_at=datetime.now(), programed_scan_id=programed_scan_id)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nikto incidents and associate a host."""
        incidents_data = domain_data
        scan_repo = ScanRepository(uow)

        from src.modules.shared._endpoints import normalize_target
        ip, host = normalize_target(scan.target, resolve_hostname=True)
        host = scan_repo.get_or_create_host(
            hostname   = host or ip or scan.target,
            ip_address = ip or scan.target,
        )

        scan_repo.persist_nikto_results(scan, host, incidents_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nikto",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None, # type: ignore
            "incidents": [
                {
                    "osvdbId": i.osvdb_id,
                    "method": i.method,
                    "url": i.url,
                    "description": i.description,
                    "severity": getattr(i, "severity", "UNKNOWN"),
                    "discoveredAt": i.discovered_at.isoformat() if i.discovered_at else None,
                }
                for i in scan.incidents
            ],
            "totalIncidents": len(scan.incidents),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target_domain"] = scan.target
        data["timeout_sec"] = getattr(scan, "timeout", task.timeout) if hasattr(scan, "timeout") else task.timeout


# =============================================================================
# OPENVAS
# =============================================================================

@ScanManager.register(ScanType.OPENVAS)
class OpenVASScanManager(ScanManager):
    """
    Manager for OpenVAS vulnerability scans.

    Reads OpenVAS connection parameters from the configuration module on init.

    Class Attributes:
        SCAN_CONFIGS: Known scan configuration UUIDs.
        PORT_LISTS:   Known port list UUIDs.

    Example:
    >>> manager = OpenVASScanManager(user)
    ... scan_id = manager.run_scan(target="192.168.1.1")
    """

    SCAN_CONFIGS = CR.get_openvas_scan_configs()
    PORT_LISTS = CR.get_openvas_port_list()

    SCAN_TYPE = ScanType.OPENVAS
    _MODEL = OpenVASScan
    _strategy_class = OpenVASPrintingStrategy

    def __init__(self) -> None:
        super().__init__()

        config = CR.get_openvas_environment()
        self.hostname  = config["hostname"]
        self.port      = config["port"]
        self.username  = config["username"]
        self.password  = config["password"]

        self.result_processor = OpenVASResultProcessor()

    def run_scan(               # pylint: disable=arguments-differ
        self,
        target: str,
        user_id: int,
        scan_config: str = "full_fast",
        skip_normalize: bool = False,
        programed_scan_id: Optional[int] = None,
    ) -> int:
        """
        Start an OpenVAS scan in a background thread.

        Args:
            target:         Target IP address or hostname.
            scan_config:    Scan configuration key (default: 'full_fast').
            skip_normalize: Skip target normalization if True.

        Returns:
            Primary key of the created OpenVASScan record.
        """
        try:
            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS["full_fast"])
            scan      = self._create_scan_record(
                target=target,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id   = scan.id

            self._tq.submit(
                func=OpenVASScanManager.execute_openvas_scan,
                args=(scan_id, target, config_id, skip_normalize),
                name=f"OpenVASScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=14400,
            )

            logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_openvas_scan(scan_id: int, target: str, scan_config_id: str, skip_normalize: bool) -> None:
        """Entry point submitted to the TaskQueue. Executes the OpenVAS scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.sentinel.services.tasks import OpenVASTask

            manager = OpenVASScanManager()
            task = OpenVASTask(
                target=target,
                hostname=manager.hostname,
                port=manager.port,
                username=manager.username,
                password=manager.password,
                scan_config=scan_config_id,
                progress_callback=job.progress,
            )
            manager._execute_scan(scan_id, task, skip_normalize, cancel_check=job.cancelled)

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> OpenVASScan: # pylint: disable=arguments-differ
        """Create and persist an OpenVASScan row with placeholder task/report IDs."""
        placeholder = f"PENDING_{uuid.uuid4()}"
        scan = OpenVASScan(
            target    = target,
            user_id   = user_id,
            task_id   = placeholder,
            report_id = placeholder,
            programed_scan_id = programed_scan_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _execute_scan(
        self,
        scan_id: int,
        task: OpenVASTask,
        skip_normalize: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Override: after the base execution, persist the OpenVAS task/report IDs.

        Args:
            scan_id:        Primary key of the scan.
            task:           OpenVASTask instance.
            skip_normalize: Skip IP normalization if True.
            cancel_check:   Optional callable returning True to cancel the scan.
        """
        from src.modules.shared._endpoints import normalize_target
        if not skip_normalize:
            target_ip, _ = normalize_target(task.target)
            task.target  = target_ip # type: ignore

        super()._execute_scan(scan_id, task, skip_normalize, cancel_check)

        if task.task_id:
            try:
                with UnitOfWork() as uow:
                    scan = ScanRepository(uow).get_by_id(scan_id)
                    if scan:
                        scan.task_id   = task.task_id
                        scan.report_id = task.report_id
            except (OSError, RuntimeError) as e:
                logger.error(
                    f"Error actualizando task_id/report_id para escaneo {scan_id}: {e}",
                    exc_info=True
                )

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist OpenVAS vulnerabilities, hosts, and scan results."""
        vulnerabilities_data, scan_results_data, _ = domain_data
        scan_repo = ScanRepository(uow)

        vulnerability_map = {}
        for vuln_data in vulnerabilities_data:
            vuln = scan_repo.get_or_create_vulnerability(vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln

        scan_repo.persist_openvas_results(scan, scan_results_data, vulnerability_map)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "openvas",
            "target": scan.target,
            "taskId": scan.task_id,
            "reportId": scan.report_id,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None, # type: ignore
            "vulnerabilities": [
                {
                    "nvtOid": r.vulnerability.nvt_oid,
                    "name": r.vulnerability.name,
                    "severityScore": r.vulnerability.severity_score,
                    "severityClass": r.vulnerability.severity_class,
                    "cvssBaseScore": r.vulnerability.cvss_base_score,
                    "cvssVector": r.vulnerability.cvss_vector,
                    "cveIds": r.vulnerability.cve_ids,
                    "description": r.vulnerability.description,
                    "solution": r.vulnerability.solution,
                    "solutionType": r.vulnerability.solution_type,
                    "affectedSoftware": r.vulnerability.affected_software,
                    "hostIp": r.host.ip_address if r.host else None,
                    "hostName": r.host.hostname if r.host else None,
                }
                for r in scan.results
            ],
            "totalVulnerabilities": len(scan.results),
            "criticalCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "highCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["scan_config"] = getattr(scan, "scan_config_name", "")
        data["skip_normalize"] = getattr(scan, "skip_normalize", False)


# =============================================================================
# ELLYSIA ENGINE
# =============================================================================

@ScanManager.register(ScanType.ELLYSIA)
class EllysiaEngineManager(ScanManager):
    """
    Manager for Ellysia's own vulnerability engine.

    Unlike the other scanners it launches no external subprocess: in the current
    phase (Fase 0) it takes the services discovered by a previous Nmap scan
    (``source_scan_id``) and produces normalized :class:`Finding` rows through the
    :class:`EllysiaEngine`. Because that work is a fast, in-memory pass (no
    network), it does not go through the base ``_execute_scan`` (built for
    long-running subprocess tasks); the body lives in ``_run_ellysia`` and the
    worker entry point ``execute_ellysia_scan`` just wraps it in ``job_context``.

    Example:
    >>> manager = EllysiaEngineManager()
    >>> scan_id = manager.run_scan(source_scan_id=42, user_id=1)
    """

    SCAN_TYPE = ScanType.ELLYSIA
    _MODEL = EllysiaScan
    _strategy_class = None  # ponytail: no PDF for Ellysia yet; wire a strategy when reports land

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        super().__init__(task_queue)

    def run_scan(self, source_scan_id: int, user_id: int, timeout: int = 120) -> int:  # pylint: disable=arguments-differ
        """
        Start an Ellysia engine scan over a previous Nmap scan's services.

        Ownership and the source scan's type are validated by the caller
        (the endpoint) before this runs.

        Args:
            source_scan_id: The Nmap scan whose discovered services to analyse.
            user_id:        Owner user primary key.
            timeout:        Job timeout margin in seconds.

        Returns:
            Primary key of the created EllysiaScan record.
        """
        with UnitOfWork() as uow:
            source = ScanRepository(uow).get_by_id(source_scan_id)
            if not source:
                raise ScanNotFoundError(source_scan_id)
            target = source.target

        scan = self._create_scan_record(
            target=target,
            user_id=user_id,
            source_scan_id=source_scan_id,
        )
        scan_id = scan.id

        self._tq.submit(
            func=EllysiaEngineManager.execute_ellysia_scan,
            args=(scan_id, source_scan_id),
            name=f"EllysiaScan-{scan_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(scan_id),
            timeout=timeout + self._scan_timeout_margin,
        )

        logger.info(f"Escaneo Ellysia {scan_id} iniciado (fuente: Nmap {source_scan_id})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_ellysia_scan(scan_id: int, source_scan_id: int) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker."""
        with job_context():
            EllysiaEngineManager()._run_ellysia(scan_id, source_scan_id)

    def _run_ellysia(self, scan_id: int, source_scan_id: int) -> None:
        """Read the source scan's services, produce findings, and persist them.

        This is the testable body of the scan (the ``execute_* seam → _run_*``
        pattern). Runs synchronously; safe to call directly in tests without a
        worker.
        """
        try:
            self.update_scan_status(scan_id, ScanStatus.RUNNING)

            # Phase 1 — read services, run version/informational detection with
            # the KB in-session, and load the previous scan for lifecycle.
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                kb_repo = KbRepository(uow)

                open_ports = scan_repo.get_open_ports_for_scan(source_scan_id)
                source = scan_repo.get_by_id(source_scan_id)
                source_host_id = source.host_id if source else None
                source_target = source.target if source else None
                services = services_from_open_ports(open_ports)

                ellysia_scan = scan_repo.get_by_id(scan_id)
                user_id = ellysia_scan.user_id if ellysia_scan else None
                previous_map = self._previous_findings_map(scan_repo, user_id, source_target, scan_id)

                engine = EllysiaEngine(
                    cve_lookup=kb_repo.cves_for_cpe,
                    kev_lookup=lambda cve_id: kb_repo.get_kev(cve_id) is not None,
                    epss_lookup=lambda cve_id: getattr(kb_repo.get_epss(cve_id), "score", None),
                )
                findings_data = engine.analyze(services)

            # Phase 2 — active checks over the network, outside any transaction.
            # Opt-in (they touch the target; see roadmap §6 authorized targets).
            if source_target and CR.is_ellysia_active_checks_enabled():
                findings_data.extend(self._run_active_checks(source_target, services))

            # Phase 2.3 — own fingerprinting (Fase F), calibrated against Nmap.
            if source_target and CR.is_ellysia_fingerprinting_enabled():
                findings_data.extend(self._run_fingerprinting(source_target, services))

            # Phase 2.5 — correlation: key, merge duplicates/sources, set lifecycle.
            for finding in findings_data:
                finding["host_id"] = source_host_id
                finding["dedup_key"] = compute_dedup_key(finding)
            findings_data = merge_findings(findings_data)
            findings_data = apply_lifecycle(findings_data, previous_map)

            # Phase 3 — persist everything.
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                scan = scan_repo.get_by_id(scan_id)
                scan.host_id = source_host_id
                self._persist_scan_results(uow, scan, findings_data)
                scan.status = ScanStatus.FINISHED.value  # type: ignore
                scan.finished_at = datetime.now()  # type: ignore

            logger.info(f"Escaneo Ellysia {scan_id} completado: {len(findings_data)} hallazgos")

        except Exception as e:
            logger.error(f"Error en escaneo Ellysia {scan_id}: {e}", exc_info=True)
            self.update_scan_status(scan_id, ScanStatus.FAILED)

    def _run_active_checks(self, target: str, services) -> list:
        """Run the declarative check runtime against the target's HTTP services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan. Safe mode only.
        """
        from .ellysia import load_checks, CheckRuntime, HttpProbe, HostRateLimiter
        try:
            runtime = CheckRuntime(
                load_checks(),
                HttpProbe().fetch,
                mode="safe",
                rate_limiter=HostRateLimiter(),
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Ellysia active checks failed for %s", target)
            return []

    def _run_fingerprinting(self, target: str, services) -> list:
        """Run Ellysia's own HTTP/SSH dissectors and record agreement with Nmap.

        Informational only (Fase F): a fingerprint finding never feeds
        vulnerability confidence — it exists to accumulate the concordance
        evidence the roadmap's Definition of Done requires before Nmap `-sV`
        can be demoted to a fallback for a service family. Best-effort per
        service; a probe failure just skips that service.
        """
        from .ellysia import (
            HttpProbe, SshProbe, HostRateLimiter, is_http_service,
            fingerprint_http, fingerprint_ssh,
        )
        http_probe = HttpProbe()
        ssh_probe = SshProbe()
        rate_limiter = HostRateLimiter()
        findings = []

        for service in services:
            try:
                if is_http_service(service):
                    rate_limiter.acquire(target)
                    resp = http_probe.fetch(target, service.port, "GET", "/")
                    if resp is None:
                        continue
                    rate_limiter.acquire(target)
                    favicon = http_probe.fetch_bytes(target, service.port, "/favicon.ico")
                    fp = fingerprint_http(resp, favicon)
                    findings.append(self._fingerprint_finding(service, fp.product, fp.version, "HTTP"))
                elif (service.name or "").lower() == "ssh" or service.port == 22:
                    rate_limiter.acquire(target)
                    probed = ssh_probe.fetch(target, service.port or 22)
                    if probed is None:
                        continue
                    banner, kexinit_payload = probed
                    fp = fingerprint_ssh(banner, kexinit_payload)
                    findings.append(self._fingerprint_finding(service, fp.product, fp.version, "SSH"))
            except Exception:
                logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)
        return findings

    @staticmethod
    def _fingerprint_finding(service, product: Optional[str], version: Optional[str], label: str) -> dict:
        """Build an informational Finding comparing our fingerprint to Nmap's."""
        from .ellysia import agrees_with_nmap, QOD_FINGERPRINT
        agrees = agrees_with_nmap(product, version, service.product, service.version)
        own = f"{product or '?'} {version or ''}".strip()
        nmap = f"{service.product or '?'} {service.version or ''}".strip()
        verdict = "concuerda con Nmap" if agrees else "no concuerda con Nmap"
        return {
            "title":        f"Fingerprint propio ({label}): {own} — {verdict} (Nmap: {nmap})",
            "category":     "fingerprint",
            "port":         service.port,
            "service":      service.name or None,
            "source":       "ellysia",
            "check_id":     "ellysia:fingerprint@1",
            "feed_version": "ellysia-fingerprint-1",
            "qod":          QOD_FINGERPRINT,
            "confirmed":    False,
            "state":        "open",
        }

    def _previous_findings_map(self, scan_repo, user_id, target, exclude_scan_id) -> dict:
        """Build ``dedup_key -> {state, snapshot}`` from the previous Ellysia scan
        of this target, for lifecycle comparison."""
        if not user_id or not target:
            return {}
        result: dict = {}
        for pf in scan_repo.get_previous_ellysia_findings(user_id, target, exclude_scan_id):
            snapshot = self._finding_snapshot(pf)
            key = pf.dedup_key or compute_dedup_key(snapshot)
            snapshot["dedup_key"] = key
            result[key] = {"state": pf.state or "open", "snapshot": snapshot}
        return result

    @staticmethod
    def _finding_snapshot(f) -> dict:
        """Plain-dict copy of a Finding's columns (to recreate a 'fixed' ghost)."""
        return {
            "host_id": f.host_id, "title": f.title, "category": f.category,
            "port": f.port, "service": f.service, "cpe": f.cpe, "cve_ids": f.cve_ids,
            "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
            "epss_score": f.epss_score, "in_kev": f.in_kev,
            "exploit_maturity": f.exploit_maturity, "source": f.source,
            "check_id": f.check_id, "feed_version": f.feed_version,
            "dedup_key": f.dedup_key, "qod": f.qod, "confirmed": f.confirmed,
        }

    def set_finding_state(self, finding_id: int, user_id: int, state: str):
        """Set a finding's lifecycle state (e.g. mark a risk as ``accepted``).

        Scoped to the owner: a finding of another user's scan is reported as not
        found. Returns the updated finding.
        """
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            finding = repo.get_finding(finding_id)
            if finding is None:
                raise FindingNotFoundError(finding_id)
            scan = repo.get_by_id(finding.scan_id)
            if scan is None or scan.user_id != user_id:
                raise FindingNotFoundError(finding_id)
            finding.state = state  # type: ignore
            repo.update(finding)
            return finding

    def _create_scan_record(self, target: str, user_id: int, source_scan_id: int) -> EllysiaScan:  # pylint: disable=arguments-differ
        """Create and persist an EllysiaScan row linked to its source Nmap scan."""
        scan = EllysiaScan(
            target=target,
            user_id=user_id,
            started_at=datetime.now(),
            source_scan_id=source_scan_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist the engine's findings (``domain_data`` is a list of dicts)."""
        ScanRepository(uow).persist_findings(scan, domain_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        session = get_db_session()
        findings = ScanRepository(session=session).get_findings_by_scan(scan_id)
        exposure = classify_exposure(scan.target)

        def _priority(f):
            return score_finding(
                {"cvss_score": f.cvss_score, "in_kev": f.in_kev,
                 "epss_score": f.epss_score, "confirmed": f.confirmed},
                exposure,
            )

        result = {
            "id": scan.id,
            "scanType": "ellysia",
            "target": scan.target,
            "sourceScanId": scan.source_scan_id,
            "exposure": exposure,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None,  # type: ignore
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "port": f.port,
                    "service": f.service,
                    "cpe": f.cpe,
                    "cveIds": f.cve_ids,
                    "cvssScore": f.cvss_score,
                    "epssScore": f.epss_score,
                    "inKev": f.in_kev,
                    "qod": f.qod,
                    "confirmed": f.confirmed,
                    "source": f.source,
                    "state": f.state,
                    "dedupKey": f.dedup_key,
                    "priority": _priority(f),
                }
                for f in findings
            ],
            "totalFindings": len(findings),
            "vulnerableFindings": sum(1 for f in findings if f.category == "outdated_software"),
            "openFindings": sum(1 for f in findings if f.state == "open"),
            "fixedFindings": sum(1 for f in findings if f.state == "fixed"),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """No-op: Ellysia does not use the base CSV-logging execution path."""
        pass


# =============================================================================
# ELLYSIA KNOWLEDGE BASE SYNC
# =============================================================================

class KbSyncManager:
    """Populates and refreshes the local vulnerability KB (the Ellysia Feed).

    Pulls NVD (incremental, by ``lastModified`` window), CISA-KEV and FIRST-EPSS
    and upserts them via :class:`KbRepository`. The fetch/ingest split lives in
    ``ellysia.kb``; this manager only orchestrates and owns the DB transactions.
    NVD is written in batches so a large delta never becomes one giant
    transaction; the initial full backfill is an operational one-off (run
    ``sync_nvd`` with a wide window) rather than something the nightly job does.
    """

    NVD_BATCH_SIZE = 200

    def sync_kev(self, url: str) -> int:
        """Mirror the CISA KEV catalogue. Returns the number of entries upserted."""
        from .ellysia import fetch_kev, ingest_kev
        count = 0
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for vuln in fetch_kev(url):
                row = ingest_kev(vuln)
                if row:
                    repo.upsert_kev(row)
                    count += 1
        logger.info("KB: KEV sync upserted %d entries", count)
        return count

    def sync_epss(self, url: str) -> int:
        """Mirror the current EPSS scores. Returns the number of rows upserted."""
        from .ellysia import fetch_epss, parse_epss_rows
        csv_text = fetch_epss(url)
        count = 0
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for row in parse_epss_rows(csv_text):
                repo.upsert_epss(row)
                count += 1
        logger.info("KB: EPSS sync upserted %d rows", count)
        return count

    def sync_nvd(self, base_url: str, window_days: int = 8, api_key: Optional[str] = None) -> int:
        """Mirror NVD CVEs modified in the last ``window_days``. Returns the count."""
        from .ellysia import iter_nvd_pages, ingest_nvd_cve
        last_start, last_end = self._nvd_window(window_days)

        count = 0
        batch: List[tuple] = []
        for item in iter_nvd_pages(base_url, last_start, last_end, api_key):
            parsed = ingest_nvd_cve(item)
            if parsed:
                batch.append(parsed)
            if len(batch) >= self.NVD_BATCH_SIZE:
                self._flush_cves(batch)
                count += len(batch)
                batch = []
        if batch:
            self._flush_cves(batch)
            count += len(batch)
        logger.info("KB: NVD sync upserted %d CVEs (window %dd)", count, window_days)
        return count

    def _flush_cves(self, batch: List[tuple]) -> None:
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for cve_row, cpe_matches in batch:
                repo.upsert_cve(cve_row, cpe_matches)

    @staticmethod
    def _nvd_window(days: int) -> tuple[str, str]:
        """NVD-formatted (lastModStartDate, lastModEndDate) for the last ``days``."""
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        return start.strftime(fmt), end.strftime(fmt)

    def sync_all(self) -> dict:
        """Run every configured source once; return a per-source count summary."""
        sources = CR.get_kb_sources()
        summary: dict = {}
        if sources.get("kev"):
            summary["kev"] = self.sync_kev(sources["kev"])
        if sources.get("epss"):
            summary["epss"] = self.sync_epss(sources["epss"])
        if sources.get("nvd"):
            summary["nvd"] = self.sync_nvd(
                sources["nvd"],
                window_days=CR.get_kb_nvd_window_days(),
                api_key=CR.get_kb_nvd_api_key(),
            )
        logger.info("KB sync complete: %s", summary)
        return summary

    @staticmethod
    def execute_kb_sync() -> None:
        """Scheduled entry point (APScheduler). Runs the full sync, best-effort."""
        from src.modules.infrastructure.unit_of_work import close_all
        try:
            KbSyncManager().sync_all()
        except Exception:
            logger.exception("KB sync failed")
        finally:
            close_all()


# =============================================================================
# SENTINEL REPORT MANAGER
# =============================================================================

class SentinelReportManager:
    """
    Manager for Sentinel document lifecycle and PDF report generation.

    Handles document CRUD operations, ownership verification, and async
    PDF generation for security scan reports.

    Attributes:
        user: User performing the operations.
    """

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    @staticmethod
    def _create_document(scan, ai_report: bool) -> int:
        """Create a SentinelDocument for a scan and return its ID."""
        with UnitOfWork() as uow:
            document = SentinelDocument(
                scan_id         = scan.id,
                scan_type       = scan.scan_type,
                document_type   = "sentinel",
                filename        = "",
                format          = "pdf",
                status          = "running",
                user_id         = scan.user_id,
                is_ai_generated = 1 if ai_report else 0,
            )
            SentinelReportRepository(uow).save(document)

        return document.id  # type: ignore

    def get_document_by_id(self, document_id: int) -> Optional[SentinelDocument]:
        """Retrieve a SentinelDocument by its primary key."""
        session = get_db_session()
        doc = SentinelReportRepository(session=session).get_by_id(document_id)

        if not doc:
            logger.warning(f"Documento {document_id} no encontrado")

        return doc

    def get_latest_document_by_scan_id(self, scan_id: int) -> Optional[SentinelDocument]:
        """Retrieve the most recently created document for a scan."""
        session = get_db_session()
        doc = SentinelReportRepository(session=session).get_latest_document(scan_id)

        return doc

    def get_documents_for_user(self, user_id: int) -> List[SentinelDocument]:
        """Retrieve all documents belonging to the active user."""
        session = get_db_session()
        docs = SentinelReportRepository(session=session).get_documents_by_user(user_id)  # type: ignore

        logger.info(f"Se obtuvieron {len(docs)} documentos")
        return docs

    def get_documents_by_scan_id(self, scan_id: int) -> List[SentinelDocument]:
        """Retrieve all documents associated with a specific scan."""
        session = get_db_session()
        docs = SentinelReportRepository(session=session).get_documents_by_scan(scan_id)

        logger.info(f"Se obtuvieron {len(docs)} documentos para scan {scan_id}")
        return docs

    def delete_document(self, document_id: int) -> bool:
        """
        Delete a document and its associated file on disk.

        Returns:
            True if deleted successfully.

        Raises:
            DocumentError: If the document was not found.
        """
        with UnitOfWork() as uow:
            doc_repo = SentinelReportRepository(uow)
            doc = doc_repo.get_by_id(document_id)

            if not doc:
                raise DocumentError(f"Documento {document_id} no encontrado")

            if doc.filename and os.path.exists(doc.filename):  # pyright: ignore[reportArgumentType, reportGeneralTypeIssues]
                try:
                    os.remove(doc.filename)  # type: ignore
                except (OSError, IOError) as e:
                    logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}", exc_info=True)

            doc_repo.delete(doc)

        return True

    def assert_document_ownership(self, document_id: int, user_id: int) -> Document:
        """
        Verify document ownership and return the document.

        Args:
            document_id: ID of the document.

        Returns:
            Document instance.

        Raises:
            DocumentError: If document not found or not owned by user.
        """
        session = get_db_session()
        doc_repo = SentinelReportRepository(session=session)
        doc = doc_repo.get_by_id(document_id)
        if not doc:
            raise DocumentError(f"Documento {document_id} no encontrado")

        if doc.user_id != user_id: # type: ignore
            raise DocumentError(f"Documento {document_id} no encontrado")

        return doc

    def generate_report(self, scan_id: int, ai_report: bool = False, strategy_class=None) -> int:
        """
        Create a SentinelDocument and start async PDF generation.

        Args:
            scan_id:        Primary key of the scan.
            ai_report:      Include AI-generated analysis.
            strategy_class: Printing strategy class for the scan type.

        Returns:
            Primary key of the created SentinelDocument.
        """
        scan_manager = ScanManager.resolve_manager(scan_id)
        scan = scan_manager.get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Escaneo {scan_id} no encontrado")

        doc_id = self._create_document(scan, ai_report)

        self._tq.submit(
            func=SentinelReportManager.execute_report_generation,
            args=(doc_id, scan.id, ai_report),
            name=f"PDFGeneration-Scan-{scan.id}",
            category="sentinel.report",
            external_id=f"sentinel-doc:{doc_id}",
        )
        return doc_id  # type: ignore

    @staticmethod
    def execute_report_generation(doc_id: int, scan_id: int, ai_report: bool) -> None:
        """Entry point submitted to the TaskQueue for background PDF generation."""
        SentinelReportManager()._generate_pdf_async(doc_id, scan_id, ai_report)

    def _generate_pdf_async(
        self,
        document_id: int,
        scan_id: int,
        ai_report: bool,
    ) -> None:
        """Generate PDF in a background thread and update document status."""

        try:
            pdf_creator = PDFCreator(scan_id)
            pdf_path = pdf_creator.print_pdf(ai_report=ai_report)

            with UnitOfWork() as uow:
                doc = SentinelReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.filename     = pdf_path  # type: ignore
                    doc.status       = "done"  # type: ignore
                    doc.generated_at = datetime.utcnow()  # type: ignore

            logger.info(f"PDF generado exitosamente para documento {document_id}")

        except (OSError, RuntimeError) as e:
            logger.error(
                f"Error generando PDF para documento {document_id}: {e}",
                exc_info=True
            )
            self._update_document_status(document_id, "error")

    def _update_document_status(self, document_id: int, status: str) -> None:
        """Update document status in database."""
        try:
            with UnitOfWork() as uow:
                doc = SentinelReportRepository(uow).get_by_id(document_id)
                if doc:
                    doc.status = status  # type: ignore
        except (OSError, RuntimeError) as e:
            logger.exception(f"Error updating document status for document {document_id}")
