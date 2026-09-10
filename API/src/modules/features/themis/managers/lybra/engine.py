"""LybraEngineManager — orquesta el motor de escaneo propio de Lybra: descubrimiento
de servicios, fingerprinting, checks activos y persistencia de los hallazgos resultantes."""

import logging
import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from typing import Any, Callable, List, Optional
import src.modules.system.config_reading as CR
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.system.taskqueue import ITaskQueue, JobDeadlineExceeded, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive, isoformat_utc
from ...repositories import (
    ScanRepository,
    KbRepository,
)
from ...model import (
    Finding,
    LybraScan,
    Scan,
    ScanFailureReason,
    ScanStatus,
    ScanType,
)
from ...lybra import (
    LybraEngine,
    Service,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    finding_to_json,
    QOD_OPEN_PORT,
    default_dissectors,
    DissectorResult,
    identify_unknown_service,
    HostRateLimiter,
    kb_feed_version,
    load_checks,
    CheckRuntime,
    HttpProbe,
    TlsProbe,
    NetworkProbe,
    default_script_plugins,
    load_credentials,
    CredentialRuntime,
    sweep_with_retries,
    PortSweep,
    scan_udp_ports_sync,
    score_finding,
    build_service_rollup,
    apply_backport_verdicts,
)
from ...lybra.ingest import select_for_services, translate_all
from ...services import _Task
from ...services.cve_context import enrich_with_cve_context
from ...services.nuclei_templates import NucleiTemplateStore
from src.modules.shared._exceptions import ValidationError
from ...exceptions import (
    ScanFailedError,
    ScanNotFoundError,
    FindingNotFoundError,
)

from ..scan import ScanManager
from ..authorized_target import AuthorizedTargetManager
from .sources import ServiceSource, DiscoveryProbes


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.LYBRA)
class LybraEngineManager(ScanManager):
    """
    Manager for Lybra's own vulnerability engine.

    Unlike the other scanners it launches no external subprocess: it discovers
    the target's services itself — or takes a services list the caller
    already resolved — and produces normalized :class:`Finding` rows through the
    :class:`LybraEngine`. Because that work is a fast, in-memory pass (no
    network), it does not go through the base ``_execute_scan`` (built for
    long-running subprocess tasks); the body lives in ``_run_lybra`` and the
    worker entry point ``execute_lybra_scan`` just wraps it in ``job_context``.

    Example:
    >>> manager = LybraEngineManager()
    >>> scan_id = manager.run_scan(target="scanme.nmap.org", user_id=1)
    """

    SCAN_TYPE = ScanType.LYBRA
    _MODEL = LybraScan
    SCHEDULED_REQUIRED_ARGS = ("target",)

    # Categories that are point-in-time events, not persistent vulnerability
    # state - excluded from lifecycle tracking (see the lifecycle pass in
    # _run_lybra).
    _EVENT_CATEGORIES = {"fingerprint", "surface_change"}

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        super().__init__(task_queue)

    @classmethod
    def scheduled_run_kwargs(cls, arguments: dict) -> dict:
        """Construye los argumentos de ejecución para un escaneo Lybra programado.

        target obligatorio + discover_ports opcional. Un escaneo
        programado siempre es autodescubrimiento — nunca tiene un
        payload de services que programar.

        Warning:
            Un ``ProgramedScan`` puede llevar todavía una clave ``deep`` en su
            columna JSON ``arguments`` (formato antiguo, ya no usado al
            programar). Este método la ignora sin más, que es lo que hace con
            cualquier argumento que no reconozca.
        """
        kwargs = super().scheduled_run_kwargs(arguments)
        kwargs["discover_ports"] = arguments.get("discover_ports")
        return kwargs

    def run_scan(self,  # pylint: disable=too-many-arguments,too-many-positional-arguments
        user_id: int,
        target: Optional[str] = None,  # pylint: disable=arguments-differ
        services: Optional[List[Service]] = None,
        discover_ports: Optional[list] = None,
        timeout: int = 120,
        programed_scan_id: Optional[int] = None,
        asset_id: Optional[int] = None,
        aggressive: bool = False,
    ) -> int:
        """
        Start an Lybra engine scan in one of two modes.

        - **External payload** (``services`` + ``target``): analyse a
          services list the caller already resolved — a Hygeia inventory
          adapter is the motivating case, but any in-process producer of a
          ``List[Service]`` qualifies. No network discovery, fingerprinting or
          active checks run in this mode by default (see ``_run_lybra``); it
          exists precisely for services data that came from *not* touching the
          target's network. ``target`` is still required — it is the host
          identity findings get attached to.
        - **Self-discovery** (``target``, optional ``discover_ports``): Lybra
          discovers the open ports itself with its own connect scan.
          The caller validates the target (reject private, etc.).

        Args:
            programed_scan_id: Set when launched by the scheduler (Themis
                scheduled scans), same convention as the other scan managers.
            asset_id: The Hygeia asset whose inventory produced
                ``services``. Recorded on the scan row for provenance and
                grouping; it is never an input to the analysis itself, which
                is why it does not travel in the TaskQueue args.
            aggressive: Explicit request for the aggressive mode.
                Deliberately **not** enough on its own — ``_run_lybra`` only
                honours it when the target is *also* in the authorized-target
                register. A registered target does not pre-authorize
                everything that could ever be done to it; this is the second
                half of that double gate, and it is what unblocks the
                default-credentials engine, the only family that
                writes to the target. Never set from a scheduled scan — see
                ``scheduled_run_kwargs``, which does not forward it.

        Returns:
            Primary key of the created LybraScan record.
        """
        source = ServiceSource.build_for_args(services, discover_ports)
        scan_target = source.valid_scan_target(user_id, target)

        # La cuota se consume aquí y no en el endpoint: por este método pasan
        # también el flujo programado (scheduling.py llama a run_scan
        # directamente) y la puerta de Hygeia. Es la misma lección que dejó el
        # arreglo SSRF de los escáneres — lo que vive solo en el endpoint HTTP
        # se lo saltan los otros caminos.
        #
        # Y va después de resolver el objetivo, no antes: un objetivo inválido
        # no debe gastar cuota. Se cobra justo antes de crear el registro.
        QuotaManager().consume(user_id, LimitKey.THEMIS_LYBRA_SCANS)

        # Los `Service` viajan como dicts, no como dataclasses: la outbox
        # guarda los argumentos del job en JSONB, mientras que RQ los picklea.
        # `execute_lybra_scan` los rehidrata al otro lado.
        services_payload = (
            None if services is None else [asdict(service) for service in services]
        )

        scan = self._create_scan_and_dispatch(
            target=scan_target,
            user_id=user_id,
            programed_scan_id=programed_scan_id,
            asset_id=asset_id,
            func=LybraEngineManager.execute_lybra_scan,
            job_name="LybraScan",
            trailing_args=(discover_ports, services_payload, timeout, aggressive),
            timeout=timeout,
        )
        scan_id = scan.id

        logger.info(f"Escaneo Lybra {scan_id} iniciado ({source.label})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_lybra_scan(
        scan_id: int,
        discover_ports: Optional[list] = None,
        services: Optional[List[Service]] = None,
        timeout: Optional[int] = None,
        aggressive: bool = False,
    ) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker.

        ``timeout`` es opcional para que un job encolado antes de ese cambio
        —que viaja con una tupla de tres argumentos— siga ejecutándose tras el
        despliegue en vez de fallar al deserializarse. ``aggressive`` es
        opcional por el mismo motivo, con el mismo default seguro: un job
        encolado antes de este cambio se ejecuta en modo ``safe``, nunca en
        agresivo por sorpresa.

        ``services`` acepta tanto ``Service`` como el dict equivalente, y por el
        mismo motivo de compatibilidad: desde que ``run_scan`` encola por la
        outbox transaccional los argumentos se guardan en JSONB, así que llegan como
        dicts. Un job pickleado por RQ antes de ese cambio sigue trayendo
        dataclasses, y esos se dejan pasar tal cual.
        """
        with job_context() as job:
            manager = LybraEngineManager()
            manager._run_lybra( # type: ignore
                scan_id,
                discover_ports,
                LybraEngineManager._rehydrate_services(services),
                timeout,
                cancel_check=job.cancelled,
                progress=job.progress,
                aggressive=aggressive,
            )

    @staticmethod
    def _rehydrate_services(
        services: Optional[List[Any]],
    ) -> Optional[List[Service]]:
        """Reconstruye los ``Service`` que llegan al worker como diccionarios.

        La outbox guarda los argumentos del job en JSONB, así que un
        ``Service`` (dataclass congelada de escalares) sale por el otro lado
        como dict. Convertirlo aquí y no dentro de ``_run_lybra`` mantiene la
        conversión en la costura ``execute_*``, que es la que conoce el
        transporte; el cuerpo sigue viendo sólo ``Service``.

        Args:
            services: Lista de servicios tal como viajó en el job, o ``None``
                si el escaneo es de autodescubrimiento (Lybra descubre los
                puertos él mismo y no recibe payload). Cada elemento puede ser
                un dict —lo normal desde que se encola por la outbox— o ya un
                ``Service``, que es como viaja un job pickleado por RQ antes de
                ese cambio o una llamada
                directa desde un test.

        Returns:
            Optional[List[Service]]: La misma lista con cada dict convertido a
                ``Service`` y los ``Service`` intactos, o ``None`` si entró
                ``None`` — el valor que ``ServiceSource.build_for_args``
                interpreta como "modo autodescubrimiento".
        """
        if services is None:
            return None
        return [
            Service(**service) if isinstance(service, dict) else service
            for service in services
        ]

    @staticmethod
    def _remaining_budget(deadline: Optional[float]) -> Optional[float]:
        """Segundos que quedan hasta ``deadline``, o ``None`` si no hay plazo."""
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    def _run_lybra(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements,too-many-positional-arguments
        self,
        scan_id: int,
        discover_ports: Optional[list] = None,
        services_payload: Optional[List[Service]] = None,
        timeout: Optional[int] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress: Optional[Callable[[int], None]] = None,
        aggressive: bool = False,
    ) -> None:
        """Resolve services (own discovery or a payload), detect, persist.

        This is the testable body of the scan (the ``execute_* seam → _run_*``
        pattern). Runs synchronously; safe to call directly in tests without a
        worker.

        ``timeout`` es el que el usuario escribió en el panel de lanzamiento.
        Abre un plazo de reloj propio que acota **el escaneo entero**: el
        descubrimiento come de él como presupuesto, y las fases de después lo
        consultan por ``should_stop`` y se cortan solas. Un plazo por
        operación —2 s por puerto, 8 s por petición HTTP— no basta por sí
        solo: limita cuánto tarda cada sonda, no cuántas se hacen, y cuántas
        se hacen lo decide el objetivo (cuántos puertos abiertos tenga), no el
        motor.

        ``aggressive`` es la petición explícita del usuario; por sí sola
        no basta. El modo efectivo con el que corren los checks activos y el
        motor de credenciales sólo sube a ``"aggressive"``
        cuando además ``is_target_authorized`` es verdadero — la doble puerta
        que protege cualquier cosa que escriba en el objetivo.
        Un objetivo autorizado sin petición explícita se queda en ``safe``;
        una petición explícita sobre un objetivo no autorizado, también.
        """
        deadline = time.monotonic() + timeout if timeout else None
        is_cancelled = cancel_check or (lambda: False)

        def should_stop() -> bool:
            """El escaneo tiene que dejar de mirar el objetivo: o se lo han
            cancelado, o se le acabó el reloj que pidió el usuario.

            Las dos cosas significan lo mismo para todo lo que viene detrás —
            vio parte del objetivo, no todo— y por eso comparten predicado: cada
            fase lo consulta y se corta sola, el escaneo se marca ``is_partial``
            y termina bien.
            """
            return is_cancelled() or (deadline is not None and time.monotonic() >= deadline)

        def report(pct: int) -> None:
            if progress is not None:
                progress(pct)

        source = ServiceSource.build_for_args(services_payload, discover_ports)
        probes = DiscoveryProbes(
            is_host_reachable=self.is_host_reachable,
            # El presupuesto se calcula al llamar, no aquí: para cuando el
            # descubrimiento arranca ya se han gastado la comprobación de
            # alcanzabilidad y las consultas de apertura del escaneo. El
            # cancel_check baja hasta el barrido de puertos —la fase más larga—
            # para que un escaneo grande se pueda parar a mitad.
            # Los nombres de los argumentos son parte del contrato con
            # ``_discover_ports``, y esta llamada es la única que lo ejercita en
            # producción: un desajuste aquí no lo ve ningún test que sustituya
            # el método por un doble, que es lo que hacen todos los de
            # integración. `test_the_probe_wiring_reaches_the_real_method` lo
            # recorre de verdad.
            discover_ports=lambda target, ports: self._discover_ports(
                target=target,
                ports=ports,
                budget_seconds=self._remaining_budget(deadline),
                cancel_check=should_stop
            ),
            discover_udp_ports=self._discover_udp_ports,
        )
        try:
            self.update_scan_status(scan_id, ScanStatus.RUNNING)

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                kb_repo = KbRepository(uow)

                lybra_scan = scan_repo.get_by_id(scan_id)
                source_target = lybra_scan.target if lybra_scan else None
                user_id = lybra_scan.user_id if lybra_scan else None

                is_target_authorized = bool(
                    user_id 
                    and source_target
                    and AuthorizedTargetManager.is_authorized(user_id, source_target)
                )
                # La doble puerta del modo agresivo: la petición
                # explícita del usuario por sí sola no basta, y el registro de
                # autorización por sí solo tampoco — autorizar un objetivo no
                # es autorizar cualquier cosa contra él. Sólo con las dos a la
                # vez sube el modo; en cualquier otro caso, ``safe``.
                mode = "aggressive" if (aggressive and is_target_authorized) else "safe"

                resolved = source.resolve_services(scan_repo, probes, source_target)
                services, source_host_id, source_target = resolved.services, resolved.host_id, resolved.target
                # Un escaneo cancelado a mitad es, a efectos del ciclo de vida,
                # lo mismo que uno truncado por reloj: vio parte del objetivo,
                # no todo. Comparte la bandera ``is_partial`` para no cerrar por
                # omisión lo que no llegó a comprobar.
                is_partial = resolved.is_partial or should_stop()
                # Descubrimiento hecho: 40 % del trabajo (reparto de pesos entre
                # las fases: descubrimiento 40, fingerprint 30, checks 20,
                # correlación y persistencia 10).
                report(40)

                fingerprint_findings: list = []
                if (
                    source.probes_target_network
                    and source_target
                    and is_target_authorized
                    and CR.lybra_config().fingerprinting_enabled
                    and not should_stop()
                ):
                    services, fingerprint_findings = self._fingerprint_services(
                        target=source_target,
                        services=services,
                        cancel_check=should_stop,
                    )
                    is_partial = is_partial or should_stop()
                report(70)

                previous_map = self._previous_findings_map(
                    scan_repo,
                    user_id,
                    source_target,
                    scan_id
                )

                surface_findings: list = []
                if source_host_id:
                    surface_findings = self._detect_surface_changes(scan_repo, source_host_id, services)

                engine = LybraEngine(
                    cve_lookup=kb_repo.cves_for_cpe,
                    kev_lookup=lambda cve_id: kb_repo.get_kev(cve_id) is not None,
                    epss_lookup=lambda cve_id: getattr(kb_repo.get_epss(cve_id), "score", None),
                    product_alias_lookup=kb_repo.resolve_product_alias,
                    feed_version=kb_feed_version(kb_repo.knowledge_state()),
                    # Qué nombres de producto no logramos identificar. El
                    # motor los cuenta, no los escribe — el paquete `lybra/` es
                    # libre de ORM y lo sigue siendo porque esto entra
                    # inyectado, como los demás lookups.
                    record_resolution=kb_repo.record_resolution,
                    # La madurez de explotación. Sale de lo que ya está en
                    # casa —la referencia que la propia NVD etiqueta como
                    # exploit— y se combina con KEV dentro del motor.
                    exploit_evidence_lookup=kb_repo.exploit_evidence,
                )
                findings_data = engine.analyze(services)
                findings_data.extend(fingerprint_findings)
                findings_data.extend(surface_findings)

            # Las CVEs que la detección por versión acaba de proponer. Son las
            # hipótesis (confirmed=false, qod=70) que un confirmador puede
            # ascender a hecho: el runtime sólo corre un confirmador cuya CVE
            # esté aquí — nunca "por si acaso".
            proposed_cves = frozenset(
                cve for finding in findings_data
                for cve in (finding.get("cve_ids") or ()))

            if (source.probes_target_network and source_target and is_target_authorized
                    and CR.lybra_config().active_checks and not should_stop()):
                findings_data.extend(
                    self._run_active_checks(source_target, services,
                                            cancel_check=should_stop,
                                            proposed_cves=proposed_cves,
                                            mode=mode))
                is_partial = is_partial or should_stop()

            # Motor de credenciales por defecto — la única
            # familia que escribe en el objetivo. ``_run_credential_checks``
            # repite por su cuenta la comprobación de ``mode`` antes de probar
            # nada; esta condición sólo evita el trabajo de construir el
            # runtime cuando ya se sabe que no va a correr.
            if source.probes_target_network and source_target and mode == "aggressive" and not should_stop():
                findings_data.extend(self._run_credential_checks(source_target, services, mode))
            report(90)

            for finding in findings_data:
                finding["host_id"] = source_host_id
                finding["dedup_key"] = compute_dedup_key(finding)
            findings_data = merge_findings(findings_data)

            trackable = [finding for finding in findings_data if finding.get("category") not in self._EVENT_CATEGORIES]
            events = [finding for finding in findings_data if finding.get("category") in self._EVENT_CATEGORIES]
            for event in events:
                event["state"] = "open"
            trackable_previous = {
                key: prev for key, prev in previous_map.items()
                if prev["snapshot"].get("category") not in self._EVENT_CATEGORIES
            }
            # Un escaneo que no vio todo el objetivo no cierra nada: la
            # ausencia de un hallazgo que esta vez no se llegó a comprobar no
            # es evidencia de que se haya corregido. Sin esto, un
            # descubrimiento truncado le diría al usuario que sus
            # vulnerabilidades fueron remediadas.
            findings_data = apply_lifecycle(
                trackable, trackable_previous, close_missing=not is_partial) + events

            # Se aplica el backport **después** del ciclo de vida a propósito.
            # Un backport de la distribución corrige el fallo sin subir el
            # número de versión visible, que es la causa más común de falsos
            # positivos del motor, así que la palabra del proveedor es la
            # última sobre si el hallazgo es real. Si se aplicara antes,
            # `apply_lifecycle` reasignaría el estado de todo hallazgo
            # presente y borraría ese veredicto: un `fixed` recién puesto
            # volvería a `open` en la misma pasada.
            with UnitOfWork() as uow:
                apply_backport_verdicts(findings_data, KbRepository(uow).distro_package_status)

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                scan = scan_repo.get_by_id(scan_id)
                scan.host_id = source_host_id
                scan.is_partial = is_partial  # type: ignore
                self._persist_scan_results(uow, scan, findings_data)
                scan.status = ScanStatus.FINISHED.value  # type: ignore
                scan.finished_at = utcnow_naive()  # type: ignore

            report(100)
            if is_partial:
                logger.warning(
                    "Escaneo Lybra %s completado PARCIALMENTE: %s hallazgos sobre una "
                    "superficie que no se llegó a recorrer entera",
                    scan_id, len(findings_data))
            else:
                logger.info(f"Escaneo Lybra {scan_id} completado: {len(findings_data)} hallazgos")

        # Va antes del handler general a propósito: éste es el fallo que sí
        # sabe de qué murió, y quien lo lanzó ya lo registró en el log con su
        # detalle. Caer en el ``except Exception`` de abajo lo convertiría en
        # "error interno", que es justo la etiqueta que no le corresponde.
        except ScanFailedError as scan_failure:
            self.update_scan_status(scan_id, ScanStatus.FAILED, scan_failure.reason)
        # La sentencia de muerte de la cola. Hereda de ``BaseException`` para
        # que ningún ``except Exception`` la confunda con un fallo de red
        # y se la trague, y el efecto colateral era que tampoco la veía el único sitio
        # que sabe qué fila hay que cerrar: la fila se quedaba en `running`
        # para siempre y el panel decía «escaneando» un día después. Se captura
        # explícitamente, se cierra la fila y **se vuelve a lanzar**, para que
        # RQ siga marcando el trabajo como fallido — cerrar el escaneo es
        # legítimo, tragarse el plazo no.
        except JobDeadlineExceeded:
            logger.error(
                "Escaneo Lybra %s agotó su plazo y la cola lo terminó. El trabajo "
                "pedido no cabía en el tiempo pedido: acota los puertos o sube el "
                "plazo del panel.", scan_id)
            self.update_scan_status(scan_id, ScanStatus.FAILED, ScanFailureReason.TIMEOUT)
            raise
        except Exception as e:
            logger.error(f"Error en escaneo Lybra {scan_id}: {e}", exc_info=True)
            self.update_scan_status(scan_id, ScanStatus.FAILED, ScanFailureReason.INTERNAL_ERROR)

    def _discover_ports(
        self,
        target: str,
        ports=None,
        budget_seconds: Optional[float] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Optional[PortSweep]:
        """Discover open ports with Lybra's own connect scan.

        Devuelve el barrido entero y no una lista porque los desenlaces son
        tres, no dos, y el llamante tiene que distinguirlos:

        - **limpio** — el objetivo contestó; ``open_ports`` es su superficie.
        - **bloqueado** (``None``) — nada contestó de ninguna forma, así que no
          se sabe nada. Tratarlo como "todo cerrado" hacía que el ciclo de vida
          marcara como corregidos hallazgos que seguían abiertos, y le dijera
          al usuario que sus vulnerabilidades se arreglaron solas.
        - **truncado** (``was_truncated``) — se acabó el reloj a mitad. Lo
          encontrado es cierto; lo que quedó sin mirar es desconocido. El
          escaneo sigue adelante con lo que hay y se marca como parcial, en
          lugar de tirar información verificada.
        """
        engine = CR.lybra_engine_config()
        try:
            sweep = sweep_with_retries(
                target, ports,
                concurrency=engine.tcp_concurrency,
                timeout=engine.tcp_timeout,
                retries=engine.udp_retries,
                budget_seconds=budget_seconds,
                cancel_check=cancel_check,
            )
        except Exception:
            logger.exception("Lybra port discovery failed for %s", target)
            return None
        if sweep.is_blocked:
            logger.error(
                "Descubrimiento bloqueado para %s: el host respondió al chequeo de "
                "alcanzabilidad y después ningún puerto contestó. El escaneo falla "
                "en vez de reportar un objetivo limpio.",
                target,
            )
            return None
        if sweep.was_truncated:
            logger.warning(
                "Descubrimiento parcial de %s: %s puertos abiertos encontrados (%s) "
                "antes de agotar el presupuesto. El escaneo continúa marcado como "
                "incompleto y no cerrará ningún hallazgo anterior.",
                target, len(sweep.open_ports), list(sweep.open_ports),
            )
        return sweep

    def _discover_udp_ports(self, target: str) -> list:
        """Discover open UDP ports via the curated probe table.

        Unlike :meth:`_discover_ports`, this never returns ``None``: UDP
        silence is *by definition* indistinguishable from "nothing there", so
        a probe failure carries no information that would justify discarding
        an otherwise good TCP discovery result — best-effort, ``[]`` on any
        error. Always uses :data:`UDP_PROBES` (never the caller's TCP port
        list): a user-supplied ``discover_ports`` is a TCP list.
        """
        try:
            engine = CR.lybra_engine_config()
            return scan_udp_ports_sync(
                target,
                timeout=engine.udp_timeout,
                retries=engine.udp_retries,
                budget_seconds=engine.udp_budget_seconds,
            )
        except Exception:
            logger.exception("Lybra UDP port discovery failed for %s", target)
            return []

    def _run_active_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, target: str, services, cancel_check=None,
        proposed_cves=None, mode: str = "safe") -> list:
        """Run the check runtime against the target's HTTP, TLS, network
        and script services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan.

        ``mode`` llega ya resuelto por :meth:`_run_lybra` — esta capa no decide
        si el agresivo procede, sólo lo aplica: un ``check`` marcado
        ``mode: aggressive`` en el feed sigue sin correr en modo ``safe``, y
        eso lo sigue decidiendo ``CheckRuntime._applies_mode`` como siempre.
        """
        try:
            engine = CR.lybra_engine_config()
            runtime = CheckRuntime(
                load_checks() + self._ingested_checks(services),
                HttpProbe(
                    timeout=engine.http_timeout,
                    max_bytes=engine.http_max_body_bytes,
                    user_agent=engine.http_user_agent,
                ).fetch,
                mode=mode,
                rate_limiter=HostRateLimiter(min_interval=engine.rate_limit_interval),
                tls_fetch=TlsProbe().fetch,
                network_open=NetworkProbe(timeout=engine.network_timeout).open,
                script_plugins=default_script_plugins(),
                capture_evidence=CR.lybra_evidence_config().enabled,
                max_payload_expansions=engine.max_payload_expansions,
                # El mismo pool acotado por host que usa el fingerprinting: los
                # checks activos tienen exactamente la misma forma —espera de
                # red servicio a servicio— y el mismo motivo para no hacerla en
                # fila india.
                mapper=self._in_host_pool,
            )
            return runtime.run(target, services, cancel_check=cancel_check,
                               proposed_cves=proposed_cves)
        except Exception:
            logger.exception("Lybra active checks failed for %s", target)
            return []

    def _run_credential_checks(self, target: str, services, mode: str) -> list:
        """Probar credenciales por defecto contra los servicios del objetivo.

        Es la única familia de detección que escribe en el objetivo, así que
        no basta con la doble puerta de quien llama (autorizado + agresivo
        pedido explícitamente): esta función además **repite** la comprobación
        de modo antes de construir nada. Dos guardas para la única capacidad
        que de verdad puede bloquear una cuenta real es defensa en profundidad
        barata, no paranoia.

        Best-effort igual que ``_run_active_checks``: un fallo de red no debe
        hundir un escaneo que ya tenía hallazgos de las demás familias.
        """
        if mode != "aggressive":
            return []
        try:
            engine = CR.lybra_engine_config()
            credentials = CR.lybra_credentials_config()
            runtime = CredentialRuntime(
                load_credentials(),
                HttpProbe(
                    timeout=engine.http_timeout,
                    max_bytes=engine.http_max_body_bytes,
                    user_agent=engine.http_user_agent,
                ).fetch,
                # Intervalo mayor que el de los checks de lectura: cada
                # intento aquí es un login real, y hace falta un ritmo
                # distinto al de un GET de ``.git/config`` para no parecer un
                # ataque de fuerza bruta.
                rate_limiter=HostRateLimiter(min_interval=engine.rate_limit_interval * 5),
                max_attempts_per_account=credentials.max_attempts,
                capture_evidence=CR.lybra_evidence_config().enabled,
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Lybra credential checks failed for %s", target)
            return []

    def _ingested_checks(self, services) -> list:
        """Checks traducidos del árbol de plantillas de Nuclei.

        Desactivado por defecto: hasta que el censo de cobertura del feed diga
        que la ingesta merece la pena, esto devuelve una lista vacía y el
        motor corre exactamente con su feed propio.

        La selección (:func:`select_for_services`) se aplica **aquí**, antes de
        construir el runtime, y no dentro de él: el feed propio no debe pagar
        nada por que esta capa exista. Sin ese filtro previo, miles de
        plantillas por servicio a 0,2 s de limitador serían horas de tráfico
        contra el objetivo.

        Best-effort igual que el resto del método: si el árbol no está o algo
        falla, se sigue con el feed propio en vez de hundir el escaneo.
        """
        if not CR.lybra_ingest_config().enabled:
            return []
        try:
            store = NucleiTemplateStore()
            if not store.is_available:
                logger.warning(
                    "Ingesta de plantillas activada pero no hay árbol de plantillas; "
                    "se sigue solo con el feed propio"
                )
                return []
            translated = translate_all(
                (document for _path, document in store.iter_templates()),
                store.version,
            )
            return select_for_services(
                translated,
                services,
                min_severity=CR.lybra_ingest_config().min_severity,
                max_checks=CR.lybra_ingest_config().max_checks,
            )
        except Exception:
            logger.exception("Fallo ingiriendo plantillas de Nuclei; se sigue con el feed propio")
            return []

    def _fingerprint_services(self, target: str, services: list, cancel_check=None) -> tuple:
        """Run Lybra's own HTTP/SSH/FTP dissectors and identify each service.

        La identificación que sale de aquí **es** la identificación del
        servicio: alimenta el matcher de versiones (``LybraEngine._resolve_cpe``)
        y deja además un hallazgo informativo con lo que se leyó. El motor es
        independiente: su propio análisis prevalece sobre el de otra
        herramienta. La comparación con Nmap sigue siendo posible, pero como
        **medición**, desde el arnés de pruebas (``tests/oracle/_concordance.py``),
        no dentro del producto.

        Best-effort per service; a probe failure just skips that service. The
        dissector selection itself is a registry lookup
        (:func:`~..lybra.default_dissectors`), not an if/elif chain — adding a
        new protocol never touches this method again, only that registry.

        Returns:
            A ``(services, findings)`` tuple: the service list with any newly
            identified product/version filled in, and the informational
            fingerprint findings.
        """
        dissectors = default_dissectors()
        cascade_config = CR.lybra_engine_config()
        rate_limiter = HostRateLimiter(min_interval=cascade_config.rate_limit_interval)

        def identify(service):
            """Sonda un servicio y devuelve ``(servicio, resultado)``.

            Se define dentro para que cada llamada comparta los ``dissectors`` y
            el ``rate_limiter`` de **esta** ejecución: el limitador es lo que
            mantiene el ritmo por host cuando varias sondas van a la vez, así que
            compartirlo es justo el punto.

            Comprueba la cancelación al entrar: con el pool concurrente, las
            unidades ya lanzadas terminan, pero las que aún no han arrancado
            devuelven de inmediato — que es lo que hace que un fingerprint de
            veinte servicios se corte pronto y no al final."""
            if cancel_check is not None and cancel_check():
                return service, None
            dissector = next((dissector for dissector in dissectors if dissector.applies(service)), None)
            result = None
            if dissector is not None:
                try:
                    result = dissector.probe(target, service, rate_limiter)
                except Exception:
                    logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)
            elif (service.protocol or "tcp").lower() != "udp":
                # Ningún dissector reclama este servicio: la aplicabilidad se
                # decide por nombre o por número de puerto, y en el camino de
                # autodescubrimiento el nombre sale a su vez de una tabla de
                # puertos. Sin la cascada de abajo, un MySQL en el 33060 o un
                # SSH en el 2222 quedarían completamente ciegos.
                #
                # La cascada pregunta en vez de suponer (ver
                # ``fingerprinting/cascade.py``). Sólo TCP: leer un saludo
                # ofrecido no significa nada sobre un datagrama.
                try:
                    result = identify_unknown_service(
                        target, service, dissectors, rate_limiter,
                        banner_timeout=cascade_config.banner_timeout,
                        max_blind_probes=cascade_config.max_blind_probes,
                    )
                except Exception:
                    logger.debug("Cascade failed for %s:%s", target, service.port, exc_info=True)
            return service, result

        findings: list = []
        updated: list = []
        # El orden de ``services`` se conserva —``map`` devuelve en el orden de
        # entrada, no en el de terminación—, así que el resultado de un escaneo no
        # depende de cuál de los servicios contestó antes. Un escáner cuyos
        # hallazgos cambian de orden entre ejecuciones hace ruido en cualquier
        # comparación posterior, empezando por el ciclo de vida.
        for service, result in self._in_host_pool(identify, services):
            if result is None:
                updated.append(service)
                continue

            findings.append(self._fingerprint_finding(service, result))
            findings.extend(self._layer_findings(service, result))
            if result.product and result.version:
                service = replace(service, product=result.product, version=result.version)
            updated.append(service)

        return updated, findings

    @staticmethod
    def _in_host_pool(work, items):
        """Ejecuta ``work`` sobre cada elemento con un pool acotado por host.

        El fingerprinting y los checks activos son entrada/salida pura: casi todo
        su tiempo es esperar a que un servicio conteste o a que se agote su plazo.
        En fila india, **un servicio mudo retrasa a todos los que vienen detrás**,
        y la fase más lenta de un escaneo acababa siendo la que menos trabajo hace.

        Tres cosas que este pool **no** cambia, y que son las condiciones que lo
        hacen aceptable:

        - Los dissectors siguen siendo síncronos y sin estado compartido. El
          paralelismo vive aquí, en el manager, y no dentro de cada protocolo:
          migrar ocho módulos a asyncio costaría mucho más y daría lo mismo,
          porque el trabajo es espera de red.
        - El ritmo por host lo sigue marcando ``HostRateLimiter``, que es seguro
          entre hilos y reserva el turno antes de dormir. El pool decide cuántas
          sondas pueden estar **esperando** a la vez, no a qué ritmo salen.
        - El aislamiento de fallos se mantiene: cada unidad de trabajo captura lo
          suyo, así que un protocolo que revienta sigue costando su servicio y
          nada más.

        Args:
            work: La función a aplicar a cada elemento.
            items: Los elementos.

        Returns:
            Los resultados, **en el orden de entrada**.
        """
        items = list(items)
        if not items:
            return []
        workers = max(1, min(CR.lybra_engine_config().host_pool_size, len(items)))
        if workers == 1:
            return [work(item) for item in items]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(work, items))

    @classmethod
    def _layer_findings(cls, service, result) -> list:
        """Un hallazgo informativo por cada capa de servidor adicional.

        Un puerto HTTP no siempre lo atiende **un** programa: la topología más
        corriente que existe —un nginx de proxy inverso por delante de un
        Apache— son dos, y el motor tiene que poder reportar ambas capas: casos
        reales muestran a Lybra diciendo ``nginx`` y a Nmap diciendo
        ``Apache httpd`` para el mismo servicio, sin que ninguno de los dos
        estuviera equivocado.

        Reportar las dos capas es la respuesta honesta. Las dos están expuestas
        y las dos tienen CVEs; elegir una en silencio produce falsos negativos
        por un lado y falsos positivos por el otro.
        """
        return [
            cls._fingerprint_finding(
                service,
                DissectorResult(product, version, f"{result.label} {role}", qod=result.qod),
            )
            for product, version, role in getattr(result, "extra_layers", ())
        ]

    @staticmethod
    def _fingerprint_finding(service, result) -> dict:
        """Build an informational Finding stating what Lybra identified.

        Es una constatación, no un veredicto: dice qué vio el motor y con qué
        dissector, sin compararlo con lo que haya dicho otra herramienta.

        El ``qod`` lo pone el dissector. Era una constante para todos, de
        modo que una versión leída de una cabecera ``Server`` explícita y otra
        deducida de una página de error valían lo mismo; ahora cada lectura
        dice cuánto se fía de sí misma. Sigue sin alimentar la confianza de
        ninguna vulnerabilidad — ver ``dispatch.QOD_FINGERPRINT``.
        """
        own = f"{result.product or '?'} {result.version or ''}".strip()
        title = f"Fingerprint propio ({result.label}): {own}"
        return {
            "title":        title,
            "category":     "fingerprint",
            "port":         service.port,
            "service":      service.name or None,
            "protocol":     service.protocol,
            "source":       "lybra",
            "check_id":     "lybra:fingerprint@1",
            "feed_version": "lybra-fingerprint-1",
            "qod":          result.qod,
            "confirmed":    False,
            "state":        "open",
        }

    def _detect_surface_changes(self, scan_repo, host_id: int, services: list[Service]) -> list:
        """Diff this scan's services against the host's tracked surface.

        Emits an informational finding for a port opening for the first time,
        for a package appearing for the first time (an ``origin="inventory"``
        service with no port), or for either kind's product/version
        changing since it was last seen — attack-surface events in their own
        right, not vulnerability guesses. Always upserts every current service
        afterwards, so the surface stays current regardless of whether
        anything changed.
        """
        existing = {
            self._surface_key(service): service for service in scan_repo.get_host_services(host_id)
        }
        # A host's very first Lybra scan establishes the baseline surface, not
        # a change to it — every port would otherwise be "new" by definition,
        # duplicating the open_port finding the matcher already emits for it.
        had_baseline = bool(existing)
        findings: list = []
        for service in services:
            protocol = service.protocol or "tcp"
            prior = existing.get(self._surface_key(service))
            if prior is None:
                if had_baseline:
                    findings.append(self._surface_finding(service, self._new_surface_title(service, protocol)))
            elif service.product and prior.product and (
                service.product != prior.product or service.version != prior.version
            ):
                findings.append(self._surface_finding(
                    service, self._changed_surface_title(service, prior)
                ))
            scan_repo.upsert_host_service(
                host_id=host_id, port=service.port, protocol=protocol,
                name=service.name or None, product=service.product or None,
                version=service.version or None, cpe=service.cpe or None,
            )
        return findings

    @staticmethod
    def _new_surface_title(service, protocol: str) -> str:
        """Title for a first-seen port or package."""
        if service.port is not None:
            return f"Nuevo puerto abierto: {service.port}/{protocol} ({service.name or 'desconocido'})"
        return f"Nuevo paquete instalado: {service.label}"

    @staticmethod
    def _changed_surface_title(service, prior) -> str:
        """Title for a product/version change on a tracked port or package."""
        change = f"{prior.product} {prior.version or ''} -> {service.product} {service.version or ''}".strip()
        if service.port is not None:
            return f"Cambio de versión detectado en el puerto {service.port}: {change}"
        return f"Cambio de versión detectado en el paquete {service.product}: {change}"

    @staticmethod
    def _surface_finding(service, title: str) -> dict:
        """Build an informational Finding for an attack-surface change.

        ``service`` falls back to ``product`` when there is no service name —
        for a portless (inventory-origin) service this is also what
        ``compute_dedup_key`` uses to disambiguate two different packages that
        would otherwise both hash to the same "port=None" identity.
        Mirrors the same fallback in ``engine.py``'s finding builders.
        """
        return {
            "title":        title,
            "category":     "surface_change",
            "port":         service.port,
            "service":      service.name or service.product or None,
            "protocol":     service.protocol,
            "source":       "lybra",
            "check_id":     "lybra:surface-change@1",
            "feed_version": "lybra-surface-1",
            "qod":          QOD_OPEN_PORT,
            "confirmed":    True,
            "state":        "open",
        }

    @staticmethod
    def _surface_key(service_or_row) -> tuple:
        """Identity key for surface tracking: ``(port, protocol)`` for a
        networked service, or ``(None, protocol, product)`` for a portless
        inventory service.

        A port already uniquely identifies a listening socket, so the product
        is deliberately excluded there — that is what lets a version bump on
        the *same* port read as "changed", not "closed + reopened". A
        portless service has no such anchor: without folding the product into
        the key, two different installed packages on the same host would
        collide on ``(None, protocol)`` and silently overwrite each other's
        tracked row. Works identically for a ``Service`` and a stored
        ``HostService`` row — both expose the same three attributes.
        """
        protocol = service_or_row.protocol or "tcp"
        if service_or_row.port is not None:
            return (service_or_row.port, protocol, None)
        return (None, protocol, service_or_row.product or None)

    # _previous_findings_map: usa el default de ScanManager.

    @classmethod
    def _finding_view_dict(cls, finding: Finding) -> dict:
        view = finding.snapshot
        view["id"] = finding.id
        view["state"] = finding.state
        # La decisión del usuario no está en el snapshot porque el snapshot
        # describe el hallazgo, no lo que alguien dijo sobre él. La interfaz
        # necesita el motivo: un estado sin su porqué obliga a preguntar a
        # quien lo puso.
        view["state_reason"] = finding.state_reason
        view["state_expires_at"] = finding.state_expires_at
        return view

    def grouped_findings(self, scan_id: int, user_id: int) -> dict:
        """Los hallazgos de un escaneo, agrupados por unidad remediable.

        Es lo que la interfaz pide al desplegar la tarjeta de un escaneo, y lo
        que sustituye a la lista plana de 150 filas que devolvía el listado. Un
        host con dos productos desactualizados no da 150 trabajos: da dos
        —subir dos productos— más las cosas de configuración que no pertenecen
        a ningún producto y se arreglan de otra manera. Esa separación es
        ``is_product``.

        El enriquecimiento con la KB se hace **aquí y no en el listado** por lo
        que cuesta: una consulta en bloque por escaneo es barata cuando se
        pide un escaneo, y son diez consultas por página cuando se pintan diez
        tarjetas colapsadas de las que el usuario abrirá una.

        Args:
            scan_id: El escaneo.
            user_id: Dueño; un escaneo ajeno se reporta como inexistente.

        Returns:
            Los grupos ya en la forma de la API (camelCase), de más grave a
            menos, con sus hallazgos dentro.
        """
        with UnitOfWork() as uow:
            assert_owned(ScanRepository, scan_id, user_id, ScanNotFoundError, uow=uow)
            repo = ScanRepository(uow)
            scan = repo.get_by_id(scan_id)
            exposure = self.exposure_for(scan)
            findings = [self._finding_view_dict(finding)
                        for finding in repo.get_findings_by_scan(scan_id)]

        for finding in findings:
            finding["priority"] = score_finding(finding, exposure)
        enrich_with_cve_context(findings)

        groups = build_service_rollup(findings)
        return {
            "scanId": scan_id,
            "exposure": exposure,
            "totalFindings": len(findings),
            "groups": [self._group_to_json(group, exposure) for group in groups],
        }

    @staticmethod
    def _group_to_json(group, exposure: str) -> dict:
        """Un :class:`ServiceGroup` en la forma de la API.

        La traducción vive aquí y no en la capa pura porque el prompt del
        informe necesita otras claves —las suyas, en castellano, que su texto
        de sistema documenta una por una—. Que cada consumidor traduzca evita
        que uno le imponga su vocabulario al otro.
        """
        return {
            "label": group.label,
            "isProduct": group.is_product,
            "port": group.port,
            "service": group.service,
            "totalFindings": group.total_findings,
            "totalCves": group.total_cves,
            "cveIds": group.cve_ids,
            "kevCveIds": group.kev_cve_ids,
            "maxCvss": group.max_cvss,
            "maxEpss": group.max_epss,
            "fixedVersion": group.fixed_version,
            "confirmedCount": group.confirmed_count,
            "byPriority": group.by_priority,
            "priority": group.worst_priority,
            "findings": [finding_to_json(finding, exposure) for finding in group.findings],
        }

    #: Los estados que un usuario puede fijar a mano. El resto —``fixed``,
    #: ``regressed``— los pone el ciclo de vida al comparar escaneos, y
    #: dejarlos escribir desde fuera permitiría falsear el historial.
    USER_SETTABLE_STATES = ("open", "accepted", "false_positive")

    def set_finding_state(self, finding_id: int, user_id: int, state: str,
                          reason: Optional[str] = None):
        """Fijar el estado de un hallazgo: asumir el riesgo, o desmentirlo.

        ``accepted`` y ``false_positive`` dicen cosas opuestas, y por eso no
        comparten casilla. Aceptar un riesgo es "esto es real, lo asumo": se
        anota con su motivo y su autor, y **caduca**, porque un riesgo asumido
        hace un año merece volver a mirarse. Marcar un falso positivo es "esto
        no es real, el motor se equivocó": no caduca por tiempo —el motor no se
        equivoca más por ser más tarde— sino cuando el motor cambia, y de eso
        se encarga ``apply_lifecycle``.

        Volver a ``open`` deshace la decisión y limpia sus anotaciones: no es
        una decisión nueva, es retirar la anterior.

        La validación se repite aquí aunque el schema del endpoint ya la haga,
        porque el manager es la frontera de verdad: hasta ahora aceptaba
        cualquier cadena, así que un segundo llamante —otro módulo, un script—
        podía escribir un estado que el ciclo de vida no sabe interpretar.

        Scoped to the owner: a finding of another user's scan is reported as not
        found. Returns the updated finding.
        """
        if state not in self.USER_SETTABLE_STATES:
            raise ValidationError(
                field="state", value=state,
                message=f"Estado no asignable a mano: {state}. "
                        f"Válidos: {', '.join(self.USER_SETTABLE_STATES)}",
            )

        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            finding = repo.get_finding(finding_id)
            if finding is None:
                raise FindingNotFoundError(finding_id)
            # El finding se busca por su propio id, pero la propiedad se
            # verifica sobre el scan al que pertenece: FindingNotFoundError
            # se lanza con finding_id para no revelar el scan_id ajeno.
            assert_owned(ScanRepository, finding.scan_id, user_id,
                         lambda _scan_id: FindingNotFoundError(finding_id), uow=uow)

            finding.state = state  # type: ignore
            if state == "open":
                finding.state_reason = None      # type: ignore
                finding.state_set_by = None      # type: ignore
                finding.state_set_at = None      # type: ignore
                finding.state_expires_at = None  # type: ignore
            else:
                now = utcnow_naive()
                finding.state_reason = reason        # type: ignore
                finding.state_set_by = user_id       # type: ignore
                finding.state_set_at = now           # type: ignore
                finding.state_expires_at = (         # type: ignore
                    now + timedelta(days=CR.themis_config().accepted_risk_days)
                    if state == "accepted" else None
                )
            repo.update(finding)
            return finding

    @staticmethod
    def unresolved_products(limit: int = 50, origin: Optional[str] = None) -> list:
        """Los nombres de producto que el matcher no consigue identificar.

        Es el documento de trabajo del feed curado de alias: cada línea es un
        alias que merece la pena escribir, ordenado por cuánto duele no
        tenerlo. El volumen de datos depende de tener el agente de Hygeia
        desplegado en más de un equipo, pero eso vale para el volumen y no
        para la herramienta: hay que construirla **antes** de que lleguen los
        datos, o cuando lleguen no habrá dónde mirarlos. Y la vía de red
        aporta muestras desde el primer escaneo, sin agente ninguno.

        No se acota por usuario: el feed de alias es del producto, no de quien
        escanea, y un nombre que falla lo hace para todos.
        """
        repo = build_repository(KbRepository)
        return [{
            "name": row.normalized_name,
            "origin": row.origin,
            "occurrences": row.occurrences,
            "firstSeenAt": isoformat_utc(row.first_seen_at),
            "lastSeenAt": isoformat_utc(row.last_seen_at),
        } for row in repo.top_unresolved_products(limit, origin)]

    def false_positives(self, user_id: int) -> list:
        """Los hallazgos que este usuario ha desmentido.

        Cada uno es **una muestra etiquetada gratis**, que es lo que convierte
        esta necesidad de una casilla de interfaz en un bucle de mejora: dicen
        contra qué check y contra qué producto se equivoca el motor, que es
        exactamente la entrada que el banco de falsos positivos tiene
        que aprender a consumir y lo que permite rankear qué familia falla más.
        """
        repo = build_repository(ScanRepository)
        return [{
            "findingId": finding.id,
            "title": finding.title,
            "category": finding.category,
            "checkId": finding.check_id,
            "cpe": finding.cpe,
            "cveIds": finding.cve_ids or [],
            "feedVersion": finding.feed_version,
            "confirmed": bool(finding.confirmed),
            "qod": finding.qod,
            "reason": finding.state_reason,
            "markedAt": isoformat_utc(finding.state_set_at),
        } for finding in repo.get_findings_by_state(user_id, "false_positive")]

    def get_finding_evidence(self, finding_id: int, user_id: int) -> list:
        """Devuelve la evidencia cruda de un hallazgo propio.

        Mismo criterio de propiedad que :meth:`set_finding_state`: la evidencia
        de un hallazgo de otro usuario se reporta como no encontrada, sin
        revelar el ``scan_id`` ajeno.

        Returns:
            Una lista de dicts con ``kind``, ``payload``, ``contentHash`` y
            ``capturedAt`` de cada evidencia, la más reciente primero.
        """
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            finding = repo.get_finding(finding_id)
            if finding is None:
                raise FindingNotFoundError(finding_id)
            assert_owned(ScanRepository, finding.scan_id, user_id,
                         lambda _scan_id: FindingNotFoundError(finding_id), uow=uow)
            return [
                {
                    "kind": evidence.kind,
                    "payload": evidence.payload,
                    "contentHash": evidence.content_hash,
                    "capturedAt": evidence.captured_at.isoformat() if evidence.captured_at else None,
                }
                for evidence in repo.get_evidence_for_finding(finding_id)
            ]

    def _create_scan_record(
        self, target: str, user_id: int,
        programed_scan_id: Optional[int] = None, asset_id: Optional[int] = None,
    ) -> LybraScan:  # pylint: disable=arguments-differ
        """Create and persist an LybraScan row.

        Delegates to ``ScanManager._create_scan_record``, passing
        LybraScan's extra columns via ``**extra``. Antes esta clase no
        llamaba ``uow.commit_for_handoff()`` como las demás — inconsistencia
        real, no deliberada: ``run_scan()`` encola en TaskQueue justo después
        (mismo patrón que Nmap/Nikto/Nuclei), así que el worker en otro
        proceso también necesita ver esta fila ya confirmada.
        """
        return super()._create_scan_record(
            target=target, user_id=user_id, programed_scan_id=programed_scan_id,
            asset_id=asset_id,
        )

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist the engine's findings (``domain_data`` is a list of dicts).

        Aprovecha la escritura para purgar la evidencia caducada: cada
        escaneo que graba evidencia se lleva de paso la que ha pasado su
        retención, así la tabla no crece sin fin sin necesidad de un barredor
        aparte.
        """
        evidence_config = CR.lybra_evidence_config()
        repo = ScanRepository(uow)
        repo.persist_findings(scan, domain_data,
                              evidence_max_body=evidence_config.max_body_bytes)
        repo.delete_expired_evidence(evidence_config.retention_days)

    def get_scans_paginated(  # pylint: disable=arguments-differ
        self, user_id: int, page: int = 1, per_page: int = 10,
        asset_id=ScanRepository.PANEL_SCANS,
    ):
        """Paginated Lybra scans, split by origin.

        Overrides the base implementation, which filters by ``scan_type``
        alone, so that the ordinary Lybra feed shows only what the user
        launched from the Themis panel. Scans produced from a Hygeia asset's
        software inventory are browsed per-agent instead — mixing them into
        the same list would bury the handful of scans a user actually asked
        for under one per agent per re-analysis.

        Args:
            asset_id: ``ScanRepository.PANEL_SCANS`` (default) for panel-launched
                scans, an ``int`` for one asset's scans, or ``None`` for all.
        """
        repo = build_repository(ScanRepository)
        items, total_count = repo.get_lybra_scans_paginated(user_id, page, per_page, asset_id)
        return ([self.format_scan(item.id, _scan=item, include_findings=False)
                 for item in items], total_count)

    def latest_findings_by_asset(self, user_id: int, asset_ids: List[int]) -> dict:
        """Hallazgos del último análisis por activo Hygeia, en un par de queries.

        Es lo que la rejilla de agentes de Themis necesita para pintar el
        "N hallazgos" de cada tarjeta sin un request por activo: el
        ``totalFindings`` del último escaneo de inventario del activo, o
        ``None`` (ausente del dict) si nunca se analizó.

        Args:
            user_id:   Dueño de los escaneos.
            asset_ids: Activos cuyo último recuento se quiere.

        Returns:
            Dict ``{asset_id: count}`` solo con los activos que ya tienen
            algún análisis.
        """
        if not asset_ids:
            return {}
        repo = build_repository(ScanRepository)
        latest = repo.get_latest_scan_by_asset(user_id, asset_ids)
        counts = repo.count_findings_by_scan([scan.id for scan in latest])
        return {
            scan.asset_id: counts.get(scan.id, 0)
            for scan in latest
            if scan.asset_id is not None
        }

    def delete_scans_for_asset(self, asset_id: int) -> int:
        """Delete every Lybra scan produced from a Hygeia asset's inventory.

        The explicit cleanup that ``LybraScan.asset_id`` needs for lack of a
        ``ForeignKey`` cascade (see the model). Goes through ``delete_scan``
        per scan so each one's generated PDFs are removed from disk too.

        This is the Themis-side entry point Hygeia calls when an asset is
        deleted; Themis itself never invokes it.

        Returns:
            How many scans were deleted.
        """
        scan_ids = build_repository(ScanRepository).get_lybra_scan_ids_for_asset(asset_id)
        deleted = sum(1 for scan_id in scan_ids if self.delete_scan(scan_id))
        if deleted:
            logger.info(f"Eliminados {deleted} escaneos Lybra del activo Hygeia {asset_id}")
        return deleted

    @staticmethod
    def exposure_for(scan) -> str:
        """Contextual exposure of a Lybra scan, used by the priority scoring.

        Normally that is just ``classify_exposure(target)``. An inventory scan
        is the exception: it never observed the target's network at
        all, so its "target" is a Hygeia asset's bare hostname, not a reachable
        surface. ``classify_exposure`` recognises internal *suffixes*
        (``.local``, ``.lan``...) but not a bare ``DESKTOP-ABC``, so it would
        call such a host "public" and push every finding up one severity band
        on the strength of a naming artefact. Reporting these as private is
        both safer and more honest: an installed package says nothing about
        what the host exposes — that remains Themis's territory, not Hygeia's.

        Lives here rather than in ``correlation.py`` because it needs the scan
        row, and that module is deliberately ORM-free (pure functions over
        plain values).
        """
        if getattr(scan, "asset_id", None):
            return "private"
        return classify_exposure(scan.target)

    def format_scan(self, scan_id: int, _scan=None, include_findings: bool = True) -> dict:  # pylint: disable=arguments-differ
        """Un escaneo en la forma de la API.

        Args:
            include_findings: Si la respuesta lleva dentro los hallazgos uno a
                uno. El listado pasa ``False``: una página de diez escaneos con
                150 hallazgos cada uno son 1.500 objetos por respuesta, y la
                interfaz no usa ninguno hasta que el usuario despliega una
                tarjeta — momento en el que pide
                ``GET /themis/lybra/scans/<id>/findings``, que además se los da
                ya agrupados. Los contadores viajan siempre, porque la cabecera
                de la tarjeta colapsada los necesita.
        """
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = build_repository(ScanRepository)
        # Todos los hallazgos de un escaneo Lybra son de Lybra: no incluyen los
        # de los escaneos corroboradores (Nmap/Nikto/Nuclei) que el "análisis
        # profundo" pueda lanzar aparte.
        display_findings = [self._finding_view_dict(finding) for finding in repo.get_findings_by_scan(scan_id)]

        exposure = self.exposure_for(scan)
        target_authorized = bool(
            scan.target and AuthorizedTargetManager.is_authorized(scan.user_id, scan.target)
        )

        json_findings = [finding_to_json(display_finding, exposure) for display_finding in display_findings]

        result = {
            "id": scan.id,
            "scanType": "lybra",
            "target": scan.target,
            "assetId": scan.asset_id,
            "isPartial": bool(scan.is_partial),
            "exposure": exposure,
            "targetAuthorized": target_authorized,
            "status": getattr(scan, "status", "unknown"),
            # Un código, no una frase: la prosa de cara al usuario vive en el
            # SPA. Viaja siempre (``None`` cuando el escaneo no falló, y también
            # en los que fallaron antes de que existiera la columna).
            "failureReason": scan.failure_reason,
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at),  # type: ignore
            "totalFindings": len(json_findings),
            # Un falso positivo no es un riesgo: el usuario ha dicho que el
            # motor se equivocó, así que no cuenta como vulnerabilidad ni
            # engorda el resumen de prioridades. Contarlo sería exactamente el
            # informe que miente sobre la postura de seguridad.
            "vulnerableFindings": sum(
                1 for display_finding in display_findings
                if display_finding.get("category") == "outdated_software"
                and display_finding.get("state") != "false_positive"),
            "openFindings": sum(1 for display_finding in display_findings if display_finding.get("state") == "open"),
            "fixedFindings": sum(1 for display_finding in display_findings if display_finding.get("state") == "fixed"),
            "falsePositiveFindings": sum(
                1 for display_finding in display_findings
                if display_finding.get("state") == "false_positive"),
            **self._finding_counters(display_findings, json_findings),
        }
        if include_findings:
            result["findings"] = json_findings
        self._append_document_info(scan, result)
        return result

    @staticmethod
    def _finding_counters(display_findings: list, json_findings: list) -> dict:
        """Los recuentos que la tarjeta colapsada necesita sin abrir el escaneo.

        Los derivaba la interfaz recorriendo la lista completa de hallazgos, que
        era la razón de que el listado tuviera que mandarla entera. Calcularlos
        aquí cuesta un recorrido más sobre filas que ya están leídas.

        ``unresolvedPackages`` cuenta los paquetes de inventario que el matcher
        no pudo resolver ni a un CPE: es lo que distingue "comprobado y limpio"
        de "ni siquiera supe qué es esto", que en los datos se leen igual.
        """
        by_priority: dict = {}
        for finding in json_findings:
            if finding.get("state") == "false_positive":
                continue          # desmentido por el usuario: no es riesgo
            priority = finding.get("priority", "INFO")
            by_priority[priority] = by_priority.get(priority, 0) + 1

        packages = [finding for finding in display_findings
                    if finding.get("category") == "installed_package"]
        return {
            "byPriority": by_priority,
            "confirmedFindings": sum(1 for finding in display_findings
                                     if finding.get("confirmed")),
            "installedPackages": len(packages),
            "unresolvedPackages": sum(1 for package in packages
                                      if package.get("cpe_resolved") is False),
        }

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """No-op: Lybra does not use the base CSV-logging execution path."""
        pass

