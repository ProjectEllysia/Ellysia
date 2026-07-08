"""ScanManager — extraido de sentinel/managers.py (Fase 3 del refactor de estructura)."""

import logging
import os
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, TaskTrackingMixin
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from src.modules.shared import utcnow_naive
from ..services.csv_logger import ScanLoggerFactory
from ..repositories import (
    ScanRepository,
    SentinelReportRepository,
)
from ..model import (
    Scan,
    ScanStatus,
    ScanType,
)
from ..services import (
    TaskStatus,
    _Task,
)
from ..services import parsing
from ..exceptions import ScanNotFoundError


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
        scan = read_repo(ScanRepository).get_by_id_and_type(self._MODEL, scan_id)

        if not scan:
            logger.warning(f"Escaneo {self.SCAN_TYPE.value if self.SCAN_TYPE else ''} {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self, user_id: int) -> List[Scan]:
        """
        Retrieve all scans of ``self._MODEL`` belonging to the active user.

        Returns:
            List of Scan instances ordered by start time descending.
        """
        scans = read_repo(ScanRepository).get_by_type_and_user(self._MODEL, user_id)

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
        repo = read_repo(ScanRepository)
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
        scan = read_repo(ScanRepository).get_by_id(scan_id)
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
                fresh_scan.finished_at  = utcnow_naive() # type: ignore

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
        from .reports import SentinelReportManager
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

