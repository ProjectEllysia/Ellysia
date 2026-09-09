"""ScanManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import src.modules.system.config_reading as CR

from src.modules.shared._exceptions import EllysiaException, ValidationError
from src.modules.system.taskqueue import JobDeadlineExceeded, TaskQueue, TaskTrackingMixin
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox import build_dispatch
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive
from ..services.csv_logger import ScanLoggerFactory
from ..repositories import (
    ScanRepository,
    ThemisReportRepository,
)
from ..model import (
    Scan,
    ScanFailureReason,
    ScanStatus,
    ScanType,
)
from ..services import (
    TaskStatus,
    _Task,
)
from ..services import parsing, reachability
from ..exceptions import IPValidationError, MaxHostsExceededError, PrivateIPRequested, ScanError, ScanNotFoundError
from ..lybra import compute_dedup_key


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

    Nota sobre los ``# type: ignore`` restantes en este fichero (Q3): los
    modelos del proyecto usan `Column(...)` clásico de SQLAlchemy en vez de
    `Mapped[...]` (no hay plugin de mypy para SQLAlchemy configurado), así
    que el checker a veces infiere el tipo de un atributo de instancia como
    `Column[T]` en vez de `T` — sobre todo cuando el valor pasa por una
    variable intermedia o una reasignación cercana. Es ruido de tipado
    estático, no una inseguridad real de `None`: en tiempo de ejecución el
    ORM ya hidrató el valor real. Cada uno de los que quedan se auditó al
    hacer Q3; los que sí escondían un bug real (reasignación de variable
    que perdía el narrowing, un `_MODEL` sin comprobar, un argumento con el
    tipo equivocado) se corrigieron en la fuente, no con un ignore.
    """

    _scan_timeout_margin: int = 30
    _registry: Dict[ScanType, type["ScanManager"]] = {}

    SCAN_TYPE: Optional[ScanType] = None
    _MODEL: Optional[type] = None  # Concrete Scan subclass; set by each subclass.

    EXTERNAL_ID_PREFIX = "scan:"
    TASK_CATEGORY = "themis.scan"

    # __init__ (task_queue inyectable) lo aporta TaskTrackingMixin (A10).

    # Contrato para el lanzamiento programado (B1): qué claves de
    # ProgramedScan.arguments son obligatorias para este tipo, y cómo
    # traducirlas a los kwargs de run_scan(). Con esto ThemisScheduler
    # despacha por el mismo _registry que resolve_manager en vez de llevar
    # su propio mapeo scan_type -> función de lanzamiento en paralelo.
    SCHEDULED_REQUIRED_ARGS: tuple = ()

    @classmethod
    def scheduled_run_kwargs(cls, arguments: dict) -> dict:
        """Map a ``ProgramedScan.arguments`` dict to this scan type's
        ``run_scan()`` kwargs (B1).

        Default: every required arg passed through unchanged (arg name ==
        ``run_scan`` parameter name). Override when a kwarg needs
        translation — an optional arg, a different name, a type coercion —
        see ``LybraEngineManager.scheduled_run_kwargs`` for an example.
        """
        return {name: arguments[name] for name in cls.SCHEDULED_REQUIRED_ARGS}


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
        # Q3: _MODEL es Optional a nivel de la clase base porque solo las
        # subclases concretas lo fijan (Nmap/Nikto/Lybra/Nuclei) — nunca es
        # None en una instancia real. El assert lo deja explícito para el
        # checker de tipos y sirve de red si alguna subclase nueva lo olvidara.
        assert self._MODEL is not None, f"{type(self).__name__} no define _MODEL"
        scan = build_repository(ScanRepository).get_by_id_and_type(self._MODEL, scan_id)

        if not scan:
            logger.warning(f"Escaneo {self.SCAN_TYPE.value if self.SCAN_TYPE else ''} {scan_id} no encontrado")

        return scan

    def get_scans_for_user(self, user_id: int) -> List[Scan]:
        """
        Retrieve all scans of ``self._MODEL`` belonging to the active user.

        Returns:
            List of Scan instances ordered by start time descending.
        """
        assert self._MODEL is not None, f"{type(self).__name__} no define _MODEL"
        scans = build_repository(ScanRepository).get_by_type_and_user(self._MODEL, user_id)

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
        repo = build_repository(ScanRepository)
        items, total_count = repo.get_scans_by_type_paginated(
            user_id, self.SCAN_TYPE, page, per_page
        )
        formatted = [self.format_scan(item.id, _scan=item) for item in items]
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
        # B8: cuando el job de TaskQueue ya no está (expiró de Redis, o el
        # proceso se reinició), caemos al estado persistido en BD — que usa
        # el vocabulario de ScanStatus ("finished"), no el de TaskStatus
        # ("completed"). Antes esta rama devolvía "completed", así que el
        # mismo escaneo podía verse como "finished" o "completed" según de
        # dónde se leyera el estado.
        status = self.task_status_of(scan_id)
        if status is not None:
            return status
        if self.is_scan_finished(scan_id):
            return ScanStatus.FINISHED.value
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
            from src.modules.shared._documents import delete_document_with_file

            scan = build_repository(ScanRepository).get_by_id(scan_id)
            if not scan:
                return False

            docs = build_repository(ThemisReportRepository).get_documents_by_parent(scan_id)
            for document in docs:
                delete_document_with_file(
                    document.id, ThemisReportRepository,
                    lambda eid: ValueError(f"Documento {eid} no existe"),
                )

            with UnitOfWork() as uow:
                repo = ScanRepository(uow)
                scan = repo.get_by_id(scan_id)
                if scan:
                    repo.delete(scan)

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
                manager = cls.resolve_manager(scan_id)
                cls.assert_scan_ownership(scan_id, user_id)
                scan = manager.get_scan_by_id(scan_id)
                if not scan:
                    results.append({"scanId": scan_id, "status": "error", "error": "not_found"})
                    continue

                if scan.status in ("pending", "running"):
                    # Cooperativa: si la cancelación falla, el subproceso puede
                    # seguir vivo. Borrar la fila igualmente lo dejaría huérfano
                    # (ver el mismo guard en endpoints.delete_scan), así que este
                    # escaneo se salta y se reporta como fallido en vez de forzar
                    # la eliminación.
                    if not manager.cancel_scan(scan_id, user_id):
                        results.append({
                            "scanId": scan_id, "status": "error",
                            "error": "no_se_pudo_cancelar",
                        })
                        continue

                manager.delete_scan(scan_id)
                results.append({"scanId": scan_id, "status": "ok", "error": None})
            except Exception as e:
                results.append({"scanId": scan_id, "status": "error", "error": str(e)})

        deleted = sum(1 for result in results if result["status"] == "ok")
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
            ScanNotFoundError: Si el escaneo no existe o no pertenece al usuario.
        """
        return assert_owned(
            ScanRepository, scan_id, user_id,
            lambda eid: ScanNotFoundError(eid),
        )

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

            queued_task = self.find_task(scan_id)

            if queued_task is None:
                logger.warning(
                    f"No se encontro tarea activa para el escaneo {scan_id}"
                )
                return False

            was_cancelled = self._task_queue.cancel(queued_task.id)
            if not was_cancelled:
                logger.warning(f"No se pudo cancelar la tarea del escaneo {scan_id}")
                return False

            with UnitOfWork() as uow:
                # CAS: si el worker ya terminó el escaneo (FINISHED/FAILED) en
                # la ventana entre la señal cooperativa y esta escritura, no lo
                # sobrescribimos a CANCELLED — evita mostrar resultados reales
                # como si el escaneo se hubiera cancelado.
                was_written = ScanRepository(uow).update_status_if(
                    scan_id, {ScanStatus.PENDING, ScanStatus.RUNNING}, ScanStatus.CANCELLED
                )

            if not was_written:
                logger.warning(
                    f"Escaneo {scan_id} ya no estaba pending/running al cancelar "
                    "(probablemente terminó justo antes)"
                )
                return False

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

        Antes se conservaba el escaneo **solo** si su tarea estaba exactamente
        en ``PENDING``, y ese criterio se comía trabajo vivo. Los workers son
        procesos aparte y reiniciar la API no los para: un job ``RUNNING``
        puede estar escaneando ahora mismo en otro proceso. El usuario veía el
        escaneo como fallido y, minutos después, el worker terminaba y escribía
        ``finished`` encima de esa misma fila — una contradicción que además
        deja el informe de un escaneo "fallido".

        La pregunta correcta no es "¿en qué estado está el job?" sino "¿queda
        alguien que vaya a terminarlo?". La responde
        ``TaskQueue.is_recoverable()``, que para un job en ejecución comprueba
        además si el worker que lo tomó sigue vivo de verdad — necesario porque
        la clave ``rq:worker:<name>`` sobrevive con su TTL completo a una
        muerte abrupta, así que su mera existencia no prueba nada.

        Mismo arreglo que Iris hizo en su reconciliación (#208); el defecto era
        literalmente el mismo porque este método fue el espejo del que se copió.

        Returns:
            Número de escaneos marcados como FAILED.
        """
        task_queue = TaskQueue.get_instance()
        fixed = 0
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            for scan in repo.get_active_scans():
                # El prefijo sale de la clase, no escrito a mano. No se compone
                # con ``external_id_for`` —que es lo que hace Iris— porque
                # ``ScanManager`` es abstracta: este método se invoca sobre ella
                # para barrer los escaneos de los cuatro escáneres a la vez, que
                # comparten prefijo y categoría.
                external_id = f"{cls.EXTERNAL_ID_PREFIX}{scan.id}"
                if task_queue.is_recoverable(external_id, cls.TASK_CATEGORY):
                    continue
                repo.update_status(scan, ScanStatus.FAILED, ScanFailureReason.ORPHANED)
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
                # B7: leer este atributo aquí, dentro de la sesión que lo
                # cargó, en vez de en instancia detached más abajo — antes
                # solo funcionaba porque expire_on_commit=False lo permite
                # implícitamente, no por contrato.
                target = scan.target

            thread_manager.update_scan_status(scan_id, ScanStatus.RUNNING)
            logger.info(f"Iniciando escaneo {scan_id}")

            if CR.host_reachability_check().enabled:
                raw_target = target if "://" in target else f"tcp://{target}"
                parsed_target = urlparse(url=raw_target) # type: ignore
                host = parsed_target.hostname or target
                reachable_port = parsed_target.port or CR.host_reachability_check().port
                reachable_timeout = CR.host_reachability_check().timeout
                if not self.is_host_reachable(host=host, port=reachable_port, timeout=reachable_timeout): # type: ignore
                    logger.warning(
                        f"Host '{host}' inalcanzable en puerto {reachable_port}. "
                        f"Marcando escaneo {scan_id} como FAILED"
                    )
                    thread_manager.update_scan_status(
                        scan_id, ScanStatus.FAILED, ScanFailureReason.HOST_UNREACHABLE)
                    return

            task.scan()
            did_succeed = task.wait(
                timeout=task.timeout + self._scan_timeout_margin,
                cancel_check=cancel_check,
            )

            no_results = task.results is None
            if not did_succeed or no_results:
                if task.status == TaskStatus.CANCELLED:
                    logger.info(f"Escaneo {scan_id} cancelado por el usuario")
                    thread_manager.update_scan_status(scan_id, ScanStatus.CANCELLED)
                else:
                    logger.error(f"Escaneo {scan_id} falló. Estado: {task.status}")
                    thread_manager.update_scan_status(
                        scan_id, ScanStatus.FAILED, ScanFailureReason.NO_RESULTS)
                return

            logger.info(f"Procesando resultados de escaneo {scan_id}")

            processor   = thread_manager.result_processor # type: ignore
            domain_data = thread_manager._process_results(processor, task.results, target)

            with UnitOfWork() as uow:
                scan_repo  = ScanRepository(uow)
                fresh_scan = scan_repo.get_by_id(scan_id)
                thread_manager._persist_scan_results(uow, fresh_scan, domain_data)
                # CAS: si cancel_scan ya escribió CANCELLED en la ventana entre
                # que este worker terminó de escanear y esta transacción, no lo
                # sobrescribimos a FINISHED — los resultados quedan igual
                # persistidos, pero el estado respeta la cancelación pedida.
                is_finished = scan_repo.update_status_if(
                    scan_id, {ScanStatus.PENDING, ScanStatus.RUNNING}, ScanStatus.FINISHED
                )

            if is_finished:
                logger.info(f"Escaneo {scan_id} completado exitosamente")
            else:
                logger.info(
                    f"Escaneo {scan_id} completó su procesamiento pero ya había "
                    "sido cancelado; se conservan los resultados obtenidos"
                )
            thread_manager._log_to_csv(scan_id, fresh_scan, task)

        # El mismo plazo agotado que recoge ``LybraEngineManager._run_lybra``,
        # aquí para los tres escáneres que sí lanzan un subproceso. Hereda de
        # ``BaseException`` (#395) para que no lo capture ningún ``except
        # Exception``, y el precio era que la fila se quedaba en `running`
        # eternamente cuando la cola mataba el trabajo. Se cierra la fila y se
        # vuelve a lanzar, para que RQ siga viendo un trabajo fallido.
        except JobDeadlineExceeded:
            logger.error(
                "Escaneo %s agotó su plazo y la cola lo terminó. El trabajo pedido "
                "no cabía en el tiempo pedido: acota el objetivo o sube el plazo.",
                scan_id)
            thread_manager.update_scan_status(
                scan_id, ScanStatus.FAILED, ScanFailureReason.TIMEOUT)
            raise
        except Exception as e:
            if task.status == TaskStatus.CANCELLED:
                logger.info(f"Escaneo {scan_id} cancelado por el usuario")
                thread_manager.update_scan_status(scan_id, ScanStatus.CANCELLED)
            else:
                logger.error(f"Error en escaneo {scan_id}: {e}", exc_info=True)
                thread_manager.update_scan_status(
                    scan_id, ScanStatus.FAILED, ScanFailureReason.INTERNAL_ERROR)
            thread_manager._log_to_csv(scan_id, fresh_scan, task)

    def _process_results(self, processor, results, target: str):
        """Hand raw task results to this scan type's result processor (B2).

        Default: every processor except Nmap's only needs ``results``. Nmap
        overrides this because its processor also needs ``target`` (to
        resolve the scanned host) — see ``NmapScanManager._process_results``.
        Keeping the dispatch here as an overridable method, rather than the
        base class branching on ``scan_type == "nmap"``, means a future scan
        type whose processor also needs ``target`` doesn't require editing
        this base class again.
        """
        return processor.process(results)

    def update_scan_status(
        self,
        scan_id: int,
        status: ScanStatus,
        failure_reason: Optional[ScanFailureReason] = None,
    ) -> None:
        """
        Persist a status change for a scan, ignoring errors (best-effort).

        Args:
            scan_id: Primary key of the scan.
            status:  New ScanStatus value.
            failure_reason: Por qué falló, cuando ``status`` es FAILED. Sin él,
                la interfaz sólo puede decir «falló» — que es la misma frase
                para un host apagado y para un error del motor, y el usuario no
                sabe si el problema es suyo o del producto.
        """
        try:
            with UnitOfWork() as uow:
                repo = ScanRepository(uow)
                scan = repo.get_by_id(scan_id)
                if scan:
                    repo.update_status(scan, status, failure_reason)
        except (OSError, RuntimeError) as update_err:
            logger.error(f"Error actualizando estado de escaneo {scan_id}: {update_err}", exc_info=True)

    def _log_to_csv(self, scan_id: int, scan: Optional[Scan], task: "_Task") -> None:
        """
        Registra el escaneo en el CSV correspondiente.
        Fallos en logging no interrumpen el flujo del scan.

        Args:
            scan_id: Primary key del escaneo.
            scan: Instancia del scan pasada por el caller — no se usa aquí
                (el método relee su propio `fresh_scan` por `scan_id`); el
                parámetro es Optional porque el caller (`_execute_scan`)
                puede tener `None` si el escaneo se borró a mitad de
                ejecución (Q3). Cualquier fallo al releer/loguear queda
                absorbido por el try/except de abajo — es logging
                best-effort, nunca interrumpe el escaneo.
            task: Task que ejecutó el scan.
        """
        try:
            with UnitOfWork() as uow:
                fresh_scan = ScanRepository(uow).get_by_id(scan_id)
                scan_type = fresh_scan.scan_type # type: ignore
                start = fresh_scan.started_at # type: ignore
                end = fresh_scan.finished_at # type: ignore
                status = fresh_scan.status # type: ignore
                duration = (end - start).total_seconds() if end and start else 0

                data = {
                    "duration_sec": round(duration, 2),
                    "status": status,
                    # Q3: get_status() es admin/monitoring, fuera a propósito
                    # del contrato ITaskQueue (per-tarea) — self._task_queue aquí es
                    # siempre el TaskQueue real (nunca un doble de test, que
                    # no llega a este código de logging en segundo plano).
                    "concurrent_tasks": self._task_queue.get_status()["runningCount"],  # type: ignore[attr-defined]
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
    def get_manager_for_type(cls, scan_type: str) -> "ScanManager":
        """Resolver un manager por nombre de tipo (p. ej. 'nmap').

        Usa el mismo ``_registry`` que ``resolve_manager``, así que añadir un
        tipo nuevo no requiere tocar este método.
        """
        manager_class = cls._registry.get(ScanType(scan_type))
        if manager_class is None:
            # Q3: ScanNotFoundError espera un scan_id (int) — scan_type es un
            # str, así que reutilizarla aquí producía un mensaje incorrecto
            # ("Escaneo con ID nmap2 no encontrado"). En la práctica el
            # esquema del endpoint ya restringe scan_type a valores válidos
            # (validate.OneOf), así que esta rama es defensiva.
            raise ScanError(
                f"Tipo de escaneo desconocido: '{scan_type}'",
                status_code=404,
                user_message=f"Tipo de escaneo desconocido: '{scan_type}'.",
            )
        return manager_class()

    @classmethod
    def all_managers(cls) -> List["ScanManager"]:
        """Una instancia por cada tipo de escaneo registrado."""
        return [scan_manager() for scan_manager in cls._registry.values()]

    # Name of the ScanRepository method that eager-loads this manager's scan
    # type for background-thread use (e.g. "get_nmap_rich"). None means the
    # plain `get_by_id` row already fetched by `get_scan_rich` is enough —
    # true for any scan type with no ORM relationships to eager-load, like
    # LybraScan (see repositories.py). Set by subclasses that need it.
    _RICH_LOADER: Optional[str] = None

    @classmethod
    def get_scan_rich(cls, scan_id: int) -> Scan:
        """Get scan with relationships eagerly loaded for background threads.

        Dispatches to whichever ``ScanRepository`` method the scan type's own
        manager declares via ``_RICH_LOADER`` (looked up through the same
        ``_registry`` that ``resolve_manager`` uses) — adding a new scan type
        never requires touching this method, only setting `_RICH_LOADER` (or
        leaving it unset) on the new manager class.

        Args:
            scan_id: Primary key of the scan.

        Returns:
            Scan instance, eager-loaded if its manager declares a loader.

        Raises:
            ScanNotFoundError: If scan_id not found or type not registered.
        """
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            if scan is None:
                raise ScanNotFoundError(scan_id)

            try:
                scan_type = ScanType(scan.scan_type)
            except ValueError:
                raise ScanNotFoundError(scan_id)

            manager_class = cls._registry.get(scan_type)
            loader_name = getattr(manager_class, "_RICH_LOADER", None)
            if loader_name:
                # Q3: el loader puede devolver None si el escaneo se borró
                # entre el get_by_id de arriba y esta segunda consulta (race
                # real, no solo teórica) — si eso pasa, nos quedamos con el
                # `scan` ya cargado en vez de perderlo, en vez de devolver
                # None desde un método tipado a `Scan` no-opcional.
                rich_scan = getattr(repo, loader_name)(scan_id)
                if rich_scan is not None:
                    scan = rich_scan

        # mypy no conserva el narrowing de `scan is not None` (línea 671) a
        # través del bloque `with` + la reasignación condicional de arriba.
        assert scan is not None
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
            Tipo del escaneo ("nmap", "nikto", "lybra", "nuclei")
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
        from .reports import ThemisReportManager
        inst = ThemisReportManager()
        document = inst.get_latest_document_by_parent(scan.id)
        if document:
            result["documentId"] = document.id
            result["documentStatus"] = document.status
    
    @classmethod
    def validate_targets(cls, raw: str, max_hosts: int = 10) -> list[str]:
        """
        Validate ``raw`` as a target spec via ``ScanManager.validate_ip``,
        translating its domain exceptions into the HTTP-facing ones.
        """
        try:
            return cls.validate_ip(raw, max_hosts=max_hosts)
        except IPValidationError as exc:
            raise ValidationError(field="target", message=str(exc), value=raw) from exc
        except MaxHostsExceededError as exc:
            raise ValidationError(str(exc.user_message or exc))
        except PrivateIPRequested as exc:
            raise EllysiaException(str(exc.user_message or exc), status_code=403)

    @staticmethod
    def validate_ip(ips_str: str, max_hosts: int = 10) -> List[str]:
        """Valida y expande una especificación de IPs/rangos.

        Ver ``themis.services.parsing.validate_ip`` para los formatos
        soportados y las excepciones que puede lanzar.
        """
        return parsing.validate_ip(ips_str, max_hosts)

    @staticmethod
    def validate_port(ports_str: str) -> List[int]:
        """Valida y expande una especificación de puertos.

        Ver ``themis.services.parsing.validate_port`` para las reglas de
        validación y las excepciones que puede lanzar.
        """
        return parsing.validate_port(ports_str)

    @staticmethod
    def reject_private_ip(ip: str) -> None:
        """Lanza ``PrivateIPRequested`` si ``ip`` es privada y
        'areLocalIpsAllowed' está en falso. Para llamantes que resuelven un
        hostname/URL ellos mismos (Nikto) en vez de expandir un
        rango vía ``validate_ip``.
        """
        parsing.reject_private_ip(ip)

    @staticmethod
    def is_host_reachable(host: str, port: int = 80, timeout: float = 3.0) -> bool:
        """Verifica conectividad básica con un host.

        Ver ``themis.services.reachability.is_host_reachable`` para el
        algoritmo (TCP con fallback a ping ICMP). Delegado fino a propósito
        (A1): varios tests monkeypatchean ``ScanManager.is_host_reachable``
        directamente, así que se mantiene como atributo de la clase en vez
        de sustituir las llamadas por la función del módulo.
        """
        return reachability.is_host_reachable(host, port, timeout)

    # =========================================================================
    # ABSTRACT INTERFACE
    # =========================================================================

    @abstractmethod
    def run_scan(self, **kwargs) -> int:
        """Start a new scan. Returns the scan's primary key."""

    def _build_scan(
        self, target: str, user_id: int, programed_scan_id: Optional[int] = None, **extra
    ) -> Scan:
        """Construye —sin persistir— la fila de escaneo de ``self._MODEL``.

        Extraído de ``_create_scan_record`` para que también lo use
        ``_create_scan_and_dispatch``: los dos necesitan el mismo objeto, pero
        cada uno lo guarda en una transacción distinta (una sola fila el
        primero, fila + outbox el segundo). Duplicar la construcción habría
        significado que añadir una columna al modelo obligase a acordarse de
        los dos sitios.

        Args:
            target: Objetivo del escaneo, ya resuelto y validado por el
                llamante (host, IP o URL, según el escáner).
            user_id: Primary key del usuario dueño del escaneo.
            programed_scan_id: Primary key del ``ProgramedScan`` que lo lanzó,
                cuando viene del scheduler; ``None`` (por defecto) para un
                escaneo lanzado a mano.
            **extra: Columnas adicionales del modelo concreto — p. ej.
                ``asset_id``/``source_scan_id`` de ``LybraScan``. Vacío para
                los modelos que no tienen ninguna.

        Returns:
            Scan: Instancia de ``self._MODEL`` sin persistir, con
                ``started_at`` ya fijado a la hora actual.
        """
        assert self._MODEL is not None, f"{type(self).__name__} no define _MODEL"
        return self._MODEL(
            target=target, user_id=user_id, started_at=utcnow_naive(),
            programed_scan_id=programed_scan_id, **extra,
        )

    def _create_scan_record(
        self, target: str, user_id: int, programed_scan_id: Optional[int] = None, **extra
    ) -> Scan:
        """Create and persist the initial scan record for ``self._MODEL`` (A4).

        Default implementation shared by every scan type whose model needs
        no columns beyond target/user_id/started_at/programed_scan_id.
        Subclasses whose model has extra columns (e.g. ``LybraScan``'s
        ``source_scan_id``/``asset_id``) pass them via ``**extra`` instead of
        overriding this method wholesale — see
        ``LybraEngineManager._create_scan_record``.

        Crea la fila **y nada más**. Los ``run_scan()`` ya no lo usan: encolan
        con ``_create_scan_and_dispatch``, que añade la fila de outbox en la
        misma transacción. Sigue aquí porque es la forma corta de fabricar un
        escaneo ya persistido sin encolar nada, que es justo lo que quieren las
        pruebas que ejercitan el motor sin worker.
        """
        scan = self._build_scan(target, user_id, programed_scan_id, **extra)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return scan

    def _create_scan_and_dispatch(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, *, target: str, user_id: int, func: Callable, job_name: str,
        timeout: int, trailing_args: tuple = (),
        programed_scan_id: Optional[int] = None, **extra,
    ) -> Scan:
        """Crea el escaneo y su intención de encolado en la MISMA transacción, y publica.

        Los cinco escáneres hacían lo mismo en dos pasos: ``_create_scan_record()``
        confirmaba la fila y, ya fuera de esa transacción, un
        ``TaskQueue.submit()`` publicaba el trabajo. Entre ambos hay una ventana
        real — si la API muere o Redis falla justo ahí, el escaneo queda creado y
        sin nadie que lo procese, con la cuota ya cobrada. La reconciliación de
        arranque lo marca FAILED, pero solo al reiniciar la API y sin devolver la
        cuota: el usuario paga por un escaneo que nunca corrió.

        Aquí la fila ``TaskDispatch`` viaja en el mismo commit que el escaneo, así
        que o existen las dos o no existe ninguna. Publicar viene después y ya no
        es crítico: en el caso normal (Redis arriba) sale al instante y el escaneo
        arranca sin latencia añadida; si falla, la fila se queda ``pending`` y la
        recogen el barrido periódico o la reconciliación de arranque — ver
        ``system/taskqueue/outbox.py``.

        Vive en la base y no en cada escáner porque el cableado era idéntico en
        los cinco: misma categoría, mismo ``external_id``, mismo margen de
        timeout, y el ``scan_id`` siempre como primer argumento del job.

        Args:
            target: Objetivo del escaneo, ya resuelto y validado por el llamante.
            user_id: Primary key del usuario dueño del escaneo.
            func: ``@staticmethod`` ``execute_*`` que ejecutará el worker. Debe
                ser importable por referencia (ver ``outbox.encode_func``): nunca
                una lambda ni un closure.
            job_name: Prefijo del id determinista del job; el nombre final es
                ``f"{job_name}-{scan_id}"`` (p. ej. ``"NmapScan"`` →
                ``"NmapScan-42"``). Debe ser RQ-safe: letras, números, ``_`` y ``-``.
            timeout: Timeout del escaneo en segundos, **sin** margen. El margen
                (``_scan_timeout_margin``) se suma aquí, que es lo que hacía cada
                escáner por su cuenta.
            trailing_args: Argumentos que siguen al ``scan_id`` en la llamada a
                ``func``. Deben ser JSON-serializables — la outbox los guarda en
                JSONB, no los picklea como hace RQ —, así que un dataclass hay que
                convertirlo a dict antes de pasarlo por aquí (lo hace
                ``LybraEngineManager.run_scan`` con sus ``Service``). Por defecto,
                ninguno.
            programed_scan_id: Primary key del ``ProgramedScan`` que lo lanzó,
                cuando viene del scheduler; ``None`` (por defecto) si es manual.
            **extra: Columnas adicionales del modelo concreto, como en
                ``_build_scan``.

        Returns:
            Scan: El escaneo ya persistido. Que su job esté publicado o
                todavía ``pending`` en la outbox no cambia lo que devuelve:
                para el llamante el escaneo existe y acabará ejecutándose en
                los dos casos, que es justo lo que aporta este mecanismo.
        """
        scan = self._build_scan(target, user_id, programed_scan_id, **extra)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            scan_id = scan.id
            dispatch = TaskDispatchRepository(uow).save(build_dispatch(
                func=func,
                name=f"{job_name}-{scan_id}",
                category=self.TASK_CATEGORY,
                args=(scan_id, *trailing_args),
                external_id=self.external_id_for(scan_id),
                timeout=timeout + self._scan_timeout_margin,
            ))
            dispatch_id = dispatch.id
            # Durable antes de intentar publicar: el worker corre en otro proceso.
            uow.commit_for_handoff()

        OutboxDispatcher.dispatch(dispatch_id, task_queue=self._task_queue)
        return scan

    def _previous_findings_map(
        self, scan_repo: ScanRepository, user_id: int, target: str, exclude_scan_id: int
    ) -> dict:
        """Build ``dedup_key -> {state, snapshot}`` from the previous scan of
        this type against ``target``, for lifecycle comparison (A6).

        Shared by every manager that does lifecycle correlation over
        ``Finding`` (Lybra, Nuclei) — uses ``self.SCAN_TYPE`` to pick the
        right previous scan, so the two hand-rolled copies (identical save
        for which scan type they filtered on) collapse into one.
        """
        if not user_id or not target:
            return {}
        result: dict = {}
        for previous_finding in scan_repo.get_previous_findings(user_id, target, self.SCAN_TYPE.value, exclude_scan_id):
            snapshot = previous_finding.snapshot
            key = previous_finding.dedup_key or compute_dedup_key(snapshot)
            snapshot["dedup_key"] = key
            result[key] = {
                "state": previous_finding.state or "open",
                "snapshot": snapshot,
                # La decisión del usuario viaja aparte del snapshot porque no
                # describe el hallazgo sino lo que alguien dijo sobre él (L35).
                # Sin esto sobreviviría el estado pero no su justificación, y
                # un `accepted` sin motivo ni autor vuelve a ser deuda al día
                # siguiente de haberlo razonado.
                "state_reason": previous_finding.state_reason,
                "state_set_by": previous_finding.state_set_by,
                "state_set_at": previous_finding.state_set_at,
                "state_expires_at": previous_finding.state_expires_at,
            }
        return result

    @abstractmethod
    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist domain data into the database within the given UnitOfWork."""

    @abstractmethod
    def format_scan(self, scan_id: int, _scan: Optional[Scan] = None) -> dict:
        """
        Formatea un escaneo como diccionario JSON.

        Args:
            scan_id: ID del escaneo.
            _scan:   Instancia ya cargada del escaneo (opcional). Si se
                     pasa, evita el re-query por ID — útil en listados
                     paginados donde la instancia ya está disponible.

        Returns:
            Diccionario con los datos del escaneo en formato JSON.
        """

    @abstractmethod
    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """Añade datos específicos del tipo de scan al diccionario data para el CSV."""
        pass

