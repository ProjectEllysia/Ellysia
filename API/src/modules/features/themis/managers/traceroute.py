"""TracerouteManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
import hashlib
from datetime import timedelta
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import TaskTrackingMixin, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive, isoformat_utc
from ..repositories import TracerouteRepository
from ..services import (
    TaskStatus,
    TracerouteService,
)

from .scan import ScanManager


logger = logging.getLogger(__name__)


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

    Results are cached per (user, target) and reused across all scan types.
    Every operation is scoped to the owning user via
    ``ScanManager.assert_scan_ownership`` so a user can only ever trace targets
    from their own scans.
    """

    EXTERNAL_ID_PREFIX = "themis-traceroute:"
    TASK_CATEGORY = "themis.traceroute"

    # __init__ (task_queue inyectable) lo aporta TaskTrackingMixin (A10).

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
        timeout = int(CR.traceroute_config().timeout) + 30
        self._task_queue.submit(
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
                max_age = timedelta(hours=CR.traceroute_config().cache_hours)
            else:
                max_age = timedelta(minutes=CR.traceroute_config().retry_failed_minutes)
            if utcnow_naive() - trace.created_at > max_age:
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
            "computedAt": isoformat_utc(trace.created_at),
            "cached": cached_hit,
            "status": "done" if trace.hops else "failed",
        }

