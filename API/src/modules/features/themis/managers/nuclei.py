"""NucleiScanManager — extraído del antiguo thirdparty_scans_managers.py (ver el
docstring de nmap.py para el porqué)."""

import logging
from typing import Callable, Optional

import src.modules.system.config_reading as CR
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.system.taskqueue import job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import isoformat_utc
from ..repositories import ScanRepository
from ..model import NucleiScan, Scan, ScanType
from ..lybra import (
    compute_dedup_key,
    nuclei_result_to_finding,
    finding_to_json,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
)
from ..services import NucleiResultProcessor, _Task
from ..exceptions import ScanNotFoundError, TargetNotAuthorizedError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NUCLEI)
class NucleiScanManager(ScanManager):
    """
    Manager for Nuclei template-based vulnerability scans (roadmap Fase U1).

    Unlike Nikto, Nuclei writes no result table of its own — every
    hallazgo vive directamente en ``Finding`` vía ``nuclei_result_to_finding``,
    la misma forma que ``LybraEngineManager`` ya adoptó. Eso es lo que le deja
    entrar gratis en la deduplicación multifuente, el ciclo de vida
    ``open``/``fixed``/``regressed`` y el scoring contextual de la Fase 5.

    Example:
    >>> manager = NucleiScanManager()
    >>> scan_id = manager.run_scan(target="https://example.com", user_id=1)
    """
    SCAN_TYPE = ScanType.NUCLEI
    _MODEL = NucleiScan
    # _RICH_LOADER no se define: sin relaciones ORM propias que precargar,
    # igual que LybraScan (ver ScanManager._RICH_LOADER).
    SCHEDULED_REQUIRED_ARGS = ("target",)

    def __init__(self) -> None:
        super().__init__()
        self.result_processor = NucleiResultProcessor()

    @classmethod
    def scheduled_run_kwargs(cls, arguments: dict) -> dict:
        """target obligatorio + severities/tags/rate_limit/request_timeout
        opcionales, pasados solo si están presentes (B1) — run_scan() ya
        tiene default None para todos ellos."""
        kwargs = super().scheduled_run_kwargs(arguments)
        for name in ("severities", "tags", "rate_limit", "request_timeout"):
            if arguments.get(name) is not None:
                kwargs[name] = arguments[name]
        return kwargs

    def run_scan(  # pylint: disable=arguments-differ
        self,
        target: str,
        user_id: int,
        severities: Optional[list] = None,
        tags: Optional[list] = None,
        rate_limit: Optional[int] = None,
        request_timeout: Optional[int] = None,
        timeout: Optional[int] = None,
        programed_scan_id: Optional[int] = None,
    ) -> int:
        """
        Start a Nuclei scan in a background thread.

        Args:
            target:          Target URL/host — se resuelve y se autoriza antes
                de llegar aquí (ver ``endpoints.start_nuclei_scan``).
            severities:      Perfil acotado de severidades (p. ej.
                ``["critical", "high", "medium"]``). Sin esto, Nuclei con el
                feed completo son miles de peticiones — no es un detalle de
                afinado, es la diferencia entre una herramienta usable y una
                que satura al objetivo en su primer uso.
            tags:            Tags de plantillas opcionales (p. ej. ``["cve"]``).
            rate_limit:      Peticiones/segundo máximas.
            request_timeout: Timeout por petición HTTP individual (segundos).
            timeout:         Timeout total del escaneo (segundos).

        Returns:
            Primary key of the created NucleiScan record.
        """
        try:
            # Rechazo de IP privada + gate de objetivos autorizados aquí (no
            # solo en el endpoint HTTP, ver validate_web_target y
            # start_nuclei_scan): el flujo programado
            # (scheduling._run_nuclei_scan) llama a run_scan() directo — mismo
            # hueco que C3 (OpenVAS), mismo patrón de cierre. Nuclei toca el
            # objetivo desde el día uno, así que además del rechazo de IP
            # privada exige estar en el registro de objetivos autorizados,
            # igual que hace el endpoint.
            from src.modules.shared import normalize_target
            from .authorized_target import AuthorizedTargetManager
            resolved_ip, _ = normalize_target(target)
            ScanManager.reject_private_ip(resolved_ip)
            if not AuthorizedTargetManager.is_authorized(user_id, resolved_ip):
                raise TargetNotAuthorizedError(target)

            resolved_timeout = int(timeout) if timeout is not None else int(CR.nuclei_config().timeout)

            # Después de validar y justo antes de crear el registro: un objetivo
            # rechazado o no autorizado no gasta cuota. Aquí y no en el endpoint,
            # porque el flujo programado entra por este mismo método.
            QuotaManager().consume(user_id, LimitKey.THEMIS_THIRDPARTY_SCANS)

            scan = self._create_scan_and_dispatch(
                target=target,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
                func=NucleiScanManager.execute_nuclei_scan,
                job_name="NucleiScan",
                trailing_args=(
                    target, severities, tags, rate_limit, request_timeout, resolved_timeout,
                ),
                timeout=resolved_timeout,
            )
            scan_id = scan.id

            logger.info(f"Escaneo Nuclei {scan_id} iniciado")
            return scan_id

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nuclei: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_nuclei_scan(
        scan_id: int, target: str,
        severities: Optional[list], tags: Optional[list],
        rate_limit: Optional[int], request_timeout: Optional[int],
        timeout: int,
    ) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nuclei scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.features.themis.services.tasks import NucleiScanTask

            task = NucleiScanTask(
                target=target,
                severities=severities,
                tags=tags,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NucleiScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    # _create_scan_record: NucleiScan no necesita columnas extra — usa el
    # default de ScanManager (A4).

    def _execute_scan(
        self,
        scan_id: int,
        task,
        skip_normalize: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Override: after the base execution, patch every Finding's
        ``feed_version`` with the live templates version the binary reported.

        ``_persist_scan_results`` (called inside the base ``_execute_scan``,
        on a *different* manager instance — ``thread_manager =
        self.__class__()``) has no access to this ``task``, so findings are
        persisted first with the config-level fallback
        (``CR.nuclei_config().templates_version``) and corrected here once the
        real value is available — the same persist-now/patch-post-hoc shape
        any scanner uses when a value is only known after the subprocess has
        already produced its output.
        """
        super()._execute_scan(scan_id, task, skip_normalize, cancel_check)

        templates_version = getattr(task, "templates_version", None)
        if templates_version:
            try:
                with UnitOfWork() as uow:
                    ScanRepository(uow).set_feed_version_for_scan(
                        scan_id, f"nuclei-templates-{templates_version}"
                    )
            except (OSError, RuntimeError) as e:
                logger.error(
                    f"Error actualizando feed_version para escaneo Nuclei {scan_id}: {e}",
                    exc_info=True,
                )

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nuclei findings as normalized Finding rows.

        Three things happen beyond the raw adapter mapping: results sharing a
        template collapse via ``merge_findings`` (Nuclei repeats the same
        template once per ``matched-at``, so one exposed path found on three
        URLs of the same host would otherwise become three rows), and
        ``apply_lifecycle`` compares against this target's previous Nuclei
        scan so ``state`` is genuinely ``fixed``/``regressed``/``open`` instead
        of always ``open`` — the two things that make Nuclei "enter for free"
        into Fase 5's correlation, per the roadmap.
        """
        results_data = domain_data
        scan_repo = ScanRepository(uow)

        from src.modules.shared._endpoints import normalize_target
        ip, host = normalize_target(scan.target, resolve_hostname=True)
        host_row = scan_repo.get_or_create_host(
            hostname   = host or ip or scan.target,
            ip_address = ip or scan.target,
        )

        previous_map = self._previous_findings_map(scan_repo, scan.user_id, scan.target, scan.id)

        # Fallback usado hasta que _execute_scan lo corrija con la versión
        # real leída del binario (ver el override de arriba).
        default_feed_version = CR.nuclei_config().templates_version

        findings = []
        for result_data in results_data:
            finding = nuclei_result_to_finding(result_data, feed_version=default_feed_version)
            finding["host_id"] = host_row.id
            finding["dedup_key"] = compute_dedup_key(finding)
            findings.append(finding)

        findings = merge_findings(findings)
        findings = apply_lifecycle(findings, previous_map)

        scan_repo.persist_findings(scan, findings)

    # _previous_findings_map: usa el default de ScanManager (A6).

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = build_repository(ScanRepository)
        exposure = classify_exposure(scan.target)

        findings = []
        for finding_row in repo.get_findings_by_scan(scan_id):
            snapshot = finding_row.snapshot
            snapshot["id"] = finding_row.id
            snapshot["state"] = finding_row.state
            findings.append(snapshot)

        json_findings = [finding_to_json(finding, exposure) for finding in findings]

        result = {
            "id": scan.id,
            "scanType": "nuclei",
            "target": scan.target,
            "exposure": exposure,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at),  # type: ignore
            "findings": json_findings,
            "totalFindings": len(json_findings),
            "criticalCount": sum(1 for json_finding in json_findings if json_finding.get("priority") == "CRITICAL"),
            "highCount": sum(1 for json_finding in json_findings if json_finding.get("priority") == "HIGH"),
            "confirmedFindings": sum(1 for json_finding in json_findings if json_finding.get("confirmed")),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target"] = scan.target
        data["severities"] = ",".join(getattr(task, "severities", None) or [])
        data["tags"] = ",".join(getattr(task, "tags", None) or [])
        data["rate_limit"] = getattr(task, "rate_limit", "")
        data["timeout_sec"] = task.timeout
