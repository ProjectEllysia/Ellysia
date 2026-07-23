"""
Lógica de negocio del módulo Hygeia.

Sigue la convención del proyecto para el acceso a datos: las **lecturas**
usan ``build_repository(RepoCls)`` (sesión ambiental de la request, sin
demarcar transacción) y las **escrituras** van dentro de un ``UnitOfWork``.
El manager nunca crea ni cierra sesiones — de eso se encargan los bordes
(``teardown_request`` en HTTP, ``job_context``/``Scheduler.execute`` en
background).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.system.taskqueue import TaskQueue, job_context
from src.modules.tools.herald import EmailMessage, build_mailer
from src.modules.users.model import User

from .exceptions import (
    AnomalyNotFoundError,
    AnomalyStillOpenError,
    AssetNotFoundError,
    AssetQuotaExceededError,
    IngestTooFrequentError,
)
from .model import Anomaly, MonitoredAsset, AssetSnapshot
from .repositories import AnomalyRepository, AssetSnapshotRepository, MonitoredAssetRepository
from .services import check_clock_skew, denormalize, evaluate, generate_agent_key

logger = logging.getLogger(__name__)


class HygeiaAssetManager:
    """
    Gestiona el alta, consulta, baja y credenciales de los activos
    monitorizados de un usuario.
    """

    def __init__(self, user: User) -> None:
        self.user = user

    def create_asset(self, hostname: str, os_name: Optional[str], labels: dict) -> dict:
        """
        Da de alta un nuevo activo y emite su clave de agente.

        La clave completa (``keyId.secreto``) se genera aquí y se devuelve
        en claro en la respuesta; a partir de este momento es irrecuperable
        — solo persiste su hash Argon2id.

        Args:
            hostname: Nombre del host que reportará el agente.
            os_name: Sistema operativo del host, si se conoce de antemano.
            labels: Etiquetas libres del activo (entorno, rol, ubicación...).

        Returns:
            Diccionario con ``asset`` (vista serializada del activo) y
            ``agentKey`` (la clave completa en claro, una única vez).

        Raises:
            AssetQuotaExceededError: Si el usuario ya alcanzó el máximo de
                activos permitido (``hygeia.limits.maxAssetsPerUser``).
        """
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)

            max_assets = CR.get_hygeia_max_assets_per_user()
            if repo.count_by_user(self.user.id) >= max_assets:
                raise AssetQuotaExceededError(max_assets)

            key_id, secret_hash, full_key = generate_agent_key()
            asset = MonitoredAsset(
                hostname=hostname,
                os=os_name,
                labels=labels,
                agent_key_id=key_id,
                agent_key_hash=secret_hash,
                heartbeat_interval_sec=CR.get_hygeia_heartbeat_interval_sec(),
                user_id=self.user.id,
            )
            saved = repo.save(asset)

        return {"asset": saved.to_dict(), "agentKey": full_key}

    def list_assets(self) -> list[dict]:
        """Devuelve todos los activos monitorizados del usuario, más recientes primero."""
        repo = build_repository(MonitoredAssetRepository)
        return [asset.to_dict() for asset in repo.get_by_user(self.user.id)]

    def get_metrics(
        self, asset_id: int, since: Optional[object] = None, until: Optional[object] = None,
    ) -> dict:
        """
        Devuelve la serie temporal de métricas de un activo del usuario, para
        el gráfico de la SPA (§5, Fase 5).

        Solo se devuelven los escalares ya desnormalizados por punto — nunca
        el JSONB completo de cada snapshot, que multiplicaría el peso de la
        respuesta por cada punto de la serie sin aportar nada a un gráfico.
        Lo que tiene cardinalidad por entidad (disco por montaje, red por
        interfaz) o solo tiene sentido "ahora" (procesos, núcleos) se sirve
        por ``get_latest_metrics``.

        Args:
            asset_id: Activo cuya serie se consulta.
            since: Límite inferior opcional de ``receivedAt``.
            until: Límite superior opcional de ``receivedAt``.

        Returns:
            Diccionario con ``snapshots`` y ``truncated``. Este último avisa
            de que el histórico da para más puntos de los devueltos, para que
            la SPA pueda rotular la ventana con honestidad en vez de
            presentar un recorte silencioso como si fuera la serie entera.

        Raises:
            AssetNotFoundError: Si el activo no existe o pertenece a otro usuario.
        """
        asset_repo = build_repository(MonitoredAssetRepository)
        self._get_owned_asset(asset_repo, asset_id, self.user.id)

        limit = CR.get_hygeia_max_series_points()
        snapshot_repo = build_repository(AssetSnapshotRepository)
        snapshots = snapshot_repo.get_series(
            asset_id, since=since, until=until, limit=limit,
        )
        return {
            "snapshots": [snapshot.to_dict() for snapshot in snapshots],
            "truncated": len(snapshots) == limit,
        }

    def get_latest_metrics(self, asset_id: int) -> dict:
        """
        Devuelve el último heartbeat completo de un activo del usuario.

        A diferencia de la serie temporal, aquí sí viaja el JSONB íntegro:
        es un único punto, así que el desglose por punto de montaje, por
        interfaz de red, por núcleo y la lista de procesos caben sin
        penalizar la respuesta.

        Un activo dado de alta que aún no ha reportado devuelve los tres
        campos a ``None``. No es un 404: el activo existe y "todavía no ha
        latido" es un estado suyo legítimo (``status == "pending"``); un 404
        sería indistinguible del de un activo ajeno y haría que el sondeo de
        la SPA pintase un error cada pocos segundos sobre algo normal.

        Args:
            asset_id: Activo cuyas últimas métricas se consultan.

        Raises:
            AssetNotFoundError: Si el activo no existe o pertenece a otro usuario.
        """
        asset_repo = build_repository(MonitoredAssetRepository)
        self._get_owned_asset(asset_repo, asset_id, self.user.id)

        snapshot_repo = build_repository(AssetSnapshotRepository)
        snapshot = snapshot_repo.get_latest(asset_id)
        if snapshot is None:
            return {"collectedAt": None, "receivedAt": None, "metrics": None}

        return {
            "collectedAt": snapshot.collected_at,
            "receivedAt":  snapshot.received_at,
            "metrics":     snapshot.metrics,
        }

    def get_asset(self, asset_id: int) -> dict:
        """
        Devuelve el detalle de un activo del usuario.

        Returns:
            Diccionario con la vista serializada del activo en forma
            de diccionario.

        Raises:
            AssetNotFoundError: Si el activo no existe o pertenece a otro
                usuario (misma excepción en ambos casos, para no permitir
                enumerar activos ajenos por diferencia de respuesta).
        """
        repo = build_repository(MonitoredAssetRepository)
        asset = self._get_owned_asset(repo, asset_id, self.user.id)
        return asset.to_dict()

    def delete_asset(self, asset_id: int) -> None:
        """
        Da de baja un activo, revocando su clave de agente.

        Al eliminar la fila se revoca implícitamente la clave: cualquier
        heartbeat posterior con esa clave falla la búsqueda por ``keyId``
        en ``require_agent_key`` con el mismo 401 genérico que una clave
        nunca emitida.

        Raises:
            AssetNotFoundError: Si el activo no existe o pertenece a otro usuario.
        """
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = self._get_owned_asset(repo, asset_id, self.user.id)
            repo.delete(asset)

    def rotate_key(self, asset_id: int) -> dict:
        """
        Regenera la clave de agente de un activo, invalidando la anterior.

        Args:
            asset_id: Activo cuya clave se rota.

        Returns:
            Diccionario con ``agentKey`` (la nueva clave completa en claro,
            una única vez).

        Raises:
            AssetNotFoundError: Si el activo no existe o pertenece a otro usuario.
        """
        with UnitOfWork() as uow:
            repo = MonitoredAssetRepository(uow)
            asset = self._get_owned_asset(repo, asset_id, self.user.id)

            key_id, secret_hash, full_key = generate_agent_key()
            asset.agent_key_id = key_id
            asset.agent_key_hash = secret_hash
            repo.update(asset)

        return {"agentKey": full_key}

    @staticmethod
    def _get_owned_asset(
        repo: MonitoredAssetRepository, asset_id: int, user_id: int,
    ) -> MonitoredAsset:
        """Obtiene un activo por id y verifica que pertenece a ``user_id``.

        Ayudante interno de la clase: a diferencia de ``assert_owned`` de
        ``shared``, aquí se necesita reutilizar el mismo ``repo`` (y por
        tanto la misma sesión) que el llamador, para poder mutar y guardar
        la entidad devuelta dentro del mismo ``UnitOfWork``.

        Lanza la misma excepción tanto si el activo no existe como si
        pertenece a otro usuario, para no permitir enumerar activos ajenos
        por diferencia de respuesta.
        """
        asset = repo.get_by_id(asset_id)
        if asset is None or asset.user_id != user_id:
            raise AssetNotFoundError(asset_id)
        return asset


class HygeiaIngestManager:
    """
    Procesa los heartbeats que empujan los agentes Hygeia.

    Toda la lógica de un heartbeat vive en una única transacción: actualizar
    la presencia del activo, resolver una posible caída ya detectada,
    persistir el snapshot y evaluar los umbrales de CPU/memoria/disco
    (histéresis, apertura/resolución de anomalías). Comparar unos umbrales
    estáticos contra un único snapshot son microsegundos — no justifica una
    tarea RQ aparte (§6); vive en la misma transacción del request.
    """

    def __init__(self, asset_id: int) -> None:
        self.asset_id = asset_id

    def ingest_heartbeat(self, payload: dict) -> dict:
        """
        Procesa un heartbeat ya autenticado y validado por schema.

        El orden importa (§7.2): actualizar la presencia y resolver una
        anomalía ``host_down`` abierta ocurre **antes** de tocar las
        métricas del propio payload, para que el primer heartbeat tras una
        caída cierre la incidencia sin depender de si sus valores cruzan o
        no un umbral.

        Args:
            payload: Heartbeat ya validado por ``IngestRequestSchema``
                (``collectedAt`` ya normalizado a naive-UTC por el schema).

        Returns:
            Diccionario con ``ok``, ``nextIntervalSec`` (el intervalo que
            este activo debe usar en su próximo envío) y ``serverTime``.

        Raises:
            AssetNotFoundError: Si el activo resuelto por la clave ya no
                existe (no debería ocurrir: ``require_agent_key`` ya lo
                resolvió en esta misma request).
            IngestTooFrequentError: Si el heartbeat llega por debajo del
                suelo de cadencia configurado para esta clave (§16.2).
        """
        check_clock_skew(payload["collectedAt"])

        critical_anomaly_ids: list[int] = []

        with UnitOfWork() as uow:
            asset_repo = MonitoredAssetRepository(uow)
            asset = asset_repo.get_by_id(self.asset_id)
            if asset is None:
                raise AssetNotFoundError(self.asset_id)

            now = utcnow_naive()
            self._enforce_min_interval(asset, now)

            asset.last_seen_at = now
            asset.status = "online"
            asset.agent_version = payload["agentVersion"]
            asset.os = payload["host"]["os"] or asset.os
            # El kernel es identidad del host: si un heartbeat no lo trae, se
            # conserva el último conocido. El uptime es estado instantáneo, así
            # que se sobreescribe siempre — un None ahí también es información.
            asset.kernel = payload["host"]["kernel"] or asset.kernel
            asset.uptime_sec = payload["host"]["uptimeSec"]
            asset_repo.update(asset)

            self._resolve_host_down_if_open(uow, asset.id)

            metrics = payload["metrics"]
            # La forma del payload la conocen el schema de ingesta y
            # ``denormalize``, y nadie más: el camino de lectura sirve la serie
            # temporal desde columnas y no abre el JSONB jamás.
            snapshot = AssetSnapshot(
                asset_id=asset.id,
                collected_at=payload["collectedAt"],
                received_at=now,
                metrics=metrics,
                **denormalize(metrics),
            )
            AssetSnapshotRepository(uow).save(snapshot)

            critical_anomaly_ids = self._evaluate_thresholds(uow, asset, metrics)

            next_interval = asset.heartbeat_interval_sec or CR.get_hygeia_heartbeat_interval_sec()

            if critical_anomaly_ids:
                # Durable antes de encolar (§8): el worker de notificación
                # corre en otro proceso y debe poder leer ya la anomalía.
                uow.commit_for_handoff()

        # Encolado siempre fuera del UnitOfWork: nunca bloquear la respuesta
        # al agente por la latencia de SMTP (§8) — el correo lo manda el
        # worker, no esta request.
        HygeiaNotifyManager.enqueue_for(critical_anomaly_ids)

        return {
            "ok": True,
            "nextIntervalSec": next_interval,
            "serverTime": utcnow_naive(),
        }

    @staticmethod
    def _enforce_min_interval(asset: MonitoredAsset, now) -> None:
        """Rechaza un heartbeat que llega antes del suelo de cadencia (§16.2);
        es decir, que el tiempo entre el hearthbeat actual y el último registrado es menor que
        el tiempo dado: ``hygeia.minIntervalSec``.

        No persiste nada: se comprueba antes de tocar el activo o el
        snapshot, así que un heartbeat rechazado no deja rastro alguno.
        """
        if asset.last_seen_at is None:
            return
        min_interval = CR.get_hygeia_min_interval_sec()
        elapsed = (now - asset.last_seen_at).total_seconds()
        if elapsed < min_interval:
            raise IngestTooFrequentError(min_interval)

    @staticmethod
    def _resolve_host_down_if_open(uow: UnitOfWork, asset_id: int) -> None:
        """Cierra una anomalía ``host_down`` abierta de este activo, si la había.

        Recibir el heartbeat **es** la condición de resolución para este
        tipo concreto de anomalía (§7.2) — no hace falta ninguna otra
        comprobación sobre las métricas del payload.
        """
        anomaly_repo = AnomalyRepository(uow)
        open_host_down = anomaly_repo.get_active(asset_id, "host_down")
        if open_host_down is not None:
            open_host_down.state = "resolved"
            open_host_down.resolved_at = utcnow_naive()
            anomaly_repo.update(open_host_down)

    @staticmethod
    def _evaluate_thresholds(uow: UnitOfWork, asset: MonitoredAsset, metrics: dict) -> list[int]:
        """
        Evalúa las métricas del heartbeat contra los umbrales efectivos del
        activo y aplica el resultado: abre anomalías nuevas, resuelve las
        que ya no aplican, y persiste los contadores de histéresis
        actualizados en el propio activo.

        Los umbrales por activo (``MonitoredAsset.thresholds``) sustituyen
        por completo — métrica a métrica — a los globales de
        ``hygeia.thresholds``; no se fusionan campo a campo dentro de una
        misma métrica.

        Returns:
            IDs de las anomalías recién abiertas con severidad ``critical``.
            El llamador las usa para encolar la notificación por correo
            **después** de confirmar esta transacción (§8) — nunca desde
            aquí, que todavía vive dentro del ``UnitOfWork``.
        """
        thresholds = {**CR.get_hygeia_thresholds(), **(asset.thresholds or {})}

        anomaly_repo = AnomalyRepository(uow)
        active_anomalies = {
            (a.kind, a.metric): a for a in anomaly_repo.get_all_active(asset.id)
        }
        outcome = evaluate(
            metrics=metrics,
            breach_counters=asset.breach_counters or {},
            open_kinds=set(active_anomalies.keys()),
            thresholds=thresholds,
        )

        critical_anomaly_ids: list[int] = []
        for change in outcome.to_open:
            saved = anomaly_repo.save(Anomaly(
                asset_id=asset.id,
                kind=change.kind,
                severity=change.severity,
                metric=change.metric,
                value=change.value,
                threshold=change.threshold,
            ))
            if change.severity == "critical":
                critical_anomaly_ids.append(saved.id)

        for key in outcome.to_resolve:
            anomaly = active_anomalies[key]
            anomaly.state = "resolved"
            anomaly.resolved_at = utcnow_naive()
            anomaly_repo.update(anomaly)

        asset.breach_counters = outcome.breach_counters
        MonitoredAssetRepository(uow).update(asset)

        return critical_anomaly_ids


class HygeiaAlertManager:
    """
    Gestiona el ciclo de vida de las anomalías (alertas) de los activos de
    un usuario: listado con filtros, reconocimiento y resolución manual.
    """

    def __init__(self, user: User) -> None:
        self.user = user

    def list_alerts(
        self,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        asset_id: Optional[int] = None,
    ) -> list[dict]:
        """Lista las anomalías de los activos del usuario, con filtros opcionales."""
        repo = build_repository(AnomalyRepository)
        anomalies = repo.get_for_user(
            self.user.id, state=state, severity=severity, asset_id=asset_id,
        )
        return [anomaly.to_dict() for anomaly in anomalies]

    def ack_alert(self, anomaly_id: int) -> dict:
        """
        Reconoce una anomalía: registra que el dueño la ha visto, sin darla
        por resuelta.

        Raises:
            AnomalyNotFoundError: Si la anomalía no existe o pertenece a
                otro usuario (misma excepción en ambos casos).
        """
        with UnitOfWork() as uow:
            repo = AnomalyRepository(uow)
            anomaly = self._get_owned_anomaly(repo, anomaly_id, self.user.id)
            anomaly.state = "acknowledged"
            repo.update(anomaly)

        return anomaly.to_dict()

    def resolve_alert(self, anomaly_id: int) -> dict:
        """
        Resuelve manualmente una anomalía, sea cual sea su estado actual.

        Si la métrica que la disparó sigue por encima del umbral en el
        próximo heartbeat, ``evaluate()`` la reabre de inmediato — resolver
        a mano no reinicia el contador de histéresis, así que una anomalía
        genuina no queda enmascarada por error.

        Raises:
            AnomalyNotFoundError: Si la anomalía no existe o pertenece a
                otro usuario (misma excepción en ambos casos).
        """
        with UnitOfWork() as uow:
            repo = AnomalyRepository(uow)
            anomaly = self._get_owned_anomaly(repo, anomaly_id, self.user.id)
            anomaly.state = "resolved"
            anomaly.resolved_at = utcnow_naive()
            repo.update(anomaly)
            return anomaly.to_dict()

    def delete_alert(self, anomaly_id: int) -> None:
        """
        Borra una anomalía ya reconocida o resuelta.

        Una anomalía ``open`` no se puede borrar (§ver ``AnomalyStillOpenError``):
        primero hay que reconocerla o resolverla, para que el borrado sea
        siempre sobre algo que el dueño ya atendió, nunca un descarte
        silencioso de una condición activa sin ver.

        Raises:
            AnomalyNotFoundError: Si la anomalía no existe o pertenece a
                otro usuario (misma excepción en ambos casos).
            AnomalyStillOpenError: Si la anomalía sigue en estado ``open``.
        """
        with UnitOfWork() as uow:
            repo = AnomalyRepository(uow)
            anomaly = self._get_owned_anomaly(repo, anomaly_id, self.user.id)
            if anomaly.state == "open":
                raise AnomalyStillOpenError(anomaly_id)
            repo.delete(anomaly)

    @staticmethod
    def _get_owned_anomaly(repo: AnomalyRepository, anomaly_id: int, user_id: int) -> Anomaly:
        """Obtiene una anomalía por id y verifica que pertenece a un activo de ``user_id``."""
        anomaly = repo.get_by_id_for_user(anomaly_id, user_id)
        if anomaly is None:
            raise AnomalyNotFoundError(anomaly_id)
        return anomaly


class HygeiaMaintenanceManager:
    """
    Tareas periódicas de mantenimiento de Hygeia: detector de presencia
    (host caído) y poda de snapshots antiguos.

    Se invocan directamente desde ``HygeiaScheduler`` (APScheduler), sin
    pasar por ``TaskQueue`` — igual que ``KbSyncManager.execute_kb_sync`` en
    Themis: son tareas de mantenimiento periódicas, no trabajos de usuario
    que necesiten seguimiento ni cancelación cooperativa.
    """

    @staticmethod
    def execute_presence_check() -> None:
        """
        Detecta activos que llevan demasiado callados y transiciona su
        presencia en dos escalones (§7.1):

        1. ``online`` → ``stale`` en el primer corte (un heartbeat perdido):
           señal visual en el listado de activos, no abre ninguna incidencia.
        2. ``stale`` → ``offline`` en un segundo corte más permisivo
           (``offlineAfterMissed`` heartbeats perdidos): solo esta segunda
           transición abre ``Anomaly(kind="host_down")``, y solo si no había
           ya una abierta (apertura idempotente).

        Cada activo se compara contra su propio ``heartbeat_interval_sec``
        (el que tiene configurado, tras un posible auto-ajuste), no contra
        el valor global — un activo que reporta más despacio de lo habitual
        no debe declararse caído por comparar contra el intervalo por defecto.

        Los dos escalones se deciden sobre el ``status`` tal como se leyó al
        principio de esta ejecución: un activo que hoy pasa a ``stale`` no
        se reevalúa también contra el corte de ``offline`` en la misma
        pasada — necesita aparecer como ``stale`` durante al menos un ciclo
        del job antes de poder caer a ``offline``.

        Cada ``host_down`` recién abierto encola su notificación por correo
        (§8) — este job corre en background (nunca en una request), así que
        ``UnitOfWork`` ya confirma la transacción al salir del bloque; no
        hace falta un ``commit_for_handoff()`` explícito para que el worker
        de notificación vea la anomalía.
        """
        newly_offline_anomaly_ids: list[int] = []

        with UnitOfWork() as uow:
            asset_repo = MonitoredAssetRepository(uow)
            anomaly_repo = AnomalyRepository(uow)
            now = utcnow_naive()
            offline_after_missed = CR.get_hygeia_offline_after_missed()

            for asset in asset_repo.get_active_for_presence_check():
                interval = asset.heartbeat_interval_sec or CR.get_hygeia_heartbeat_interval_sec()

                if asset.status == "online":
                    stale_cutoff = now - timedelta(seconds=interval)
                    asset_repo.transition_status_if_still_silent(
                        asset.id, stale_cutoff, "online", "stale",
                    )
                elif asset.status == "stale":
                    offline_cutoff = now - timedelta(seconds=interval * offline_after_missed)
                    transitioned = asset_repo.transition_status_if_still_silent(
                        asset.id, offline_cutoff, "stale", "offline",
                    )
                    if transitioned and anomaly_repo.get_active(asset.id, "host_down") is None:
                        saved = anomaly_repo.save(Anomaly(
                            asset_id=asset.id, kind="host_down", severity="critical",
                        ))
                        newly_offline_anomaly_ids.append(saved.id)

        HygeiaNotifyManager.enqueue_for(newly_offline_anomaly_ids)

    @staticmethod
    def execute_retention() -> int:
        """
        Elimina los ``AssetSnapshot`` anteriores a ``hygeia.retentionDays`` (§7.3).

        Returns:
            Número de filas eliminadas.
        """
        cutoff = utcnow_naive() - timedelta(days=CR.get_hygeia_retention_days())
        with UnitOfWork() as uow:
            repo = AssetSnapshotRepository(uow)
            rows_affected = repo.delete_older_than(cutoff)

        return rows_affected


class HygeiaNotifyManager:
    """
    Envía la notificación por correo de una anomalía crítica recién abierta.

    Se dispara de forma asíncrona (``TaskQueue``, categoría
    ``hygeia.notify``) tras confirmar la transacción que abrió la anomalía
    — nunca de forma síncrona en la ingesta ni en el job de presencia, para
    no bloquear la respuesta al agente ni al propio scheduler por la
    latencia de SMTP (§8).
    """

    TASK_CATEGORY = "hygeia.notify"

    @staticmethod
    def enqueue_for(anomaly_ids: list[int]) -> None:
        """
        Encola la notificación de cada anomalía crítica recién abierta.

        Debe llamarse siempre **después** de que la transacción que las
        creó ya sea durable (commit de request/background, o
        ``commit_for_handoff()`` explícito) — el worker corre en otro
        proceso y no vería una fila todavía sin confirmar.

        Args:
            anomaly_ids: IDs de anomalías con severidad ``critical`` recién
                abiertas. Una lista vacía es un no-op.
        """
        tq = TaskQueue.get_instance()
        for anomaly_id in anomaly_ids:
            tq.submit(
                func=HygeiaNotifyManager.execute_notify_critical_anomaly,
                args=(anomaly_id,),
                name=f"HygeiaNotify-{anomaly_id}",
                category=HygeiaNotifyManager.TASK_CATEGORY,
                external_id=f"hygeia-notify:{anomaly_id}",
            )

    @staticmethod
    def execute_notify_critical_anomaly(anomaly_id: int) -> None:
        """Entry point submitted to the TaskQueue for background email sending."""
        with job_context():
            HygeiaNotifyManager._run_notify(anomaly_id)

    @staticmethod
    def _run_notify(anomaly_id: int) -> None:
        """
        Envía el correo de aviso al dueño del activo afectado.

        Un fallo de envío se registra y se descarta — no hay nada que
        reintentar de forma síncrona aquí, y la anomalía ya quedó
        registrada y visible en ``GET /hygeia/alerts`` con independencia de
        si el correo llegó o no.
        """
        from src.modules.users.managers import UserManager

        anomaly_repo = build_repository(AnomalyRepository)
        anomaly = anomaly_repo.get_by_id(anomaly_id)
        if anomaly is None:
            logger.error(f"Anomalía {anomaly_id} no encontrada para notificar")
            return

        asset_repo = build_repository(MonitoredAssetRepository)
        asset = asset_repo.get_by_id(anomaly.asset_id)
        if asset is None:
            logger.error(f"Activo {anomaly.asset_id} no encontrado para notificar anomalía {anomaly_id}")
            return

        user = UserManager().get_user_by_id(asset.user_id)
        if user is None:
            logger.error(f"Usuario {asset.user_id} no encontrado para notificar anomalía {anomaly_id}")
            return

        message = EmailMessage(
            to=user.email,
            to_name=user.first_name,
            subject=f"[Hygeia] Anomalía crítica en {asset.hostname}",
            html_body=HygeiaNotifyManager._render_notify_email_html(asset, anomaly),
        )
        try:
            build_mailer("hygeia").send(message)
            logger.info(f"Notificación enviada para anomalía {anomaly_id} ({asset.hostname})")
        except Exception as exc:
            logger.error(f"Fallo enviando notificación de anomalía {anomaly_id}: {exc}")

    @staticmethod
    def _render_notify_email_html(asset: MonitoredAsset, anomaly: Anomaly) -> str:
        """HTML mínimo del correo de aviso: qué activo, qué anomalía, qué valor la disparó."""
        metric_line = (
            f"<p>Métrica: <strong>{anomaly.metric}</strong> — "
            f"valor {anomaly.value} (umbral {anomaly.threshold})</p>"
            if anomaly.metric else ""
        )
        return (
            f"<p>Hola,</p>"
            f"<p>Se ha detectado una anomalía <strong>crítica</strong> en el activo "
            f"<strong>{asset.hostname}</strong>.</p>"
            f"<p>Tipo: <strong>{anomaly.kind}</strong></p>"
            f"{metric_line}"
            f"<p>Puedes revisar el detalle desde tu panel de Hygeia.</p>"
        )
