"""
Modelos de base de datos del módulo Hygeia (monitorización de activos).

Hygeia recibe telemetría de agentes instalados en los activos (host caído,
picos de CPU/memoria/disco...), la persiste y evalúa reglas de umbral para
abrir/cerrar anomalías. Es un flujo *push*: el backend nunca sondea al
agente, son los agentes los que empujan.

Classes:
    MonitoredAsset: Activo (host/máquina) vigilado por un agente Hygeia.
    AssetSnapshot: Instantánea de métricas de un activo en un heartbeat.
    Anomaly: Incidencia abierta por la detección de umbrales.

Example:
    >>> from src.modules.features.hygeia.model import MonitoredAsset
    >>> asset = MonitoredAsset(hostname="web-01", agent_key_id="abc123",
    ...                        agent_key_hash="$argon2...", user_id=1)
    >>> print(asset)
    <MonitoredAsset(id=None, hostname='web-01', status='pending')>
"""

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, utcnow_naive


class MonitoredAsset(Base):
    """
    Activo (host o máquina) monitorizado por un agente Hygeia.

    La identidad del agente que empuja telemetría para este activo es un
    bearer opaco de dos partes: ``agent_key_id`` (prefijo público, indexado,
    permite localizar la fila en O(1)) y ``agent_key_hash`` (Argon2id del
    secreto de alta entropía; el secreto en claro nunca se persiste y solo
    se muestra una vez, en la respuesta del alta).

    Attributes:
        id: Clave primaria, autoincremental.
        hostname: Nombre del host tal como lo reporta el agente.
        os: Sistema operativo ("linux" | "windows" | "darwin"), opcional.
        labels: Etiquetas libres del activo (entorno, rol, ubicación...).
        agent_key_id: Prefijo público de la clave de agente, único e indexado.
        agent_key_hash: Hash Argon2id del secreto de la clave de agente.
        agent_version: Versión del agente instalado, opcional.
        status: Estado de presencia ("pending" | "online" | "stale" | "offline").
        last_seen_at: Instante del último heartbeat recibido.
        heartbeat_interval_sec: Intervalo de heartbeat que el agente tiene
            configurado actualmente para este activo. Nace con el valor
            global de config y se actualiza si el agente se auto-ajusta
            (ver el campo ``nextIntervalSec`` de la respuesta de ingesta).
            El detector de presencia compara el silencio contra este valor,
            no contra el global, para no declarar caído a un activo que
            simplemente reporta más despacio de lo habitual.
        breach_counters: Contadores de cruces de umbral consecutivos por
            métrica (p. ej. ``{"cpu": 2, "mem": 0}``), tal como quedaron
            tras el último heartbeat evaluado. Es la memoria que necesita
            la histéresis de ``services/detection.py`` para decidir cuándo
            abrir una anomalía sin tener que releer snapshots históricos.
        thresholds: Umbrales específicos de este activo, en el mismo formato
            que el bloque ``hygeia.thresholds`` de la configuración global.
            Si una métrica no aparece aquí, se usa el umbral global.
        user_id: Clave foránea al usuario dueño del activo.
        created_at: Instante de alta del activo.
        snapshots: Heartbeats recibidos de este activo.
        anomalies: Anomalías (abiertas o resueltas) de este activo.
    """

    __tablename__ = "MonitoredAsset"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), nullable=False)
    os       = Column(String(64), nullable=True)
    labels   = Column(JSONB, nullable=True)

    agent_key_id   = Column(String(32), unique=True, index=True, nullable=False)
    agent_key_hash = Column(String(255), nullable=False)
    agent_version  = Column(String(32), nullable=True)

    status                 = Column(String(16), nullable=False, default="pending")
    last_seen_at           = Column(DateTime, nullable=True)
    heartbeat_interval_sec = Column(Integer, nullable=True)
    breach_counters        = Column(JSONB, nullable=True)
    thresholds             = Column(JSONB, nullable=True)

    user_id    = Column(Integer, ForeignKey("User.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    snapshots = relationship(
        "AssetSnapshot", back_populates="asset", cascade="all, delete-orphan",
    )
    anomalies = relationship(
        "Anomaly", back_populates="asset", cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        """
        Serializa el activo para respuestas de API (vista del dueño).

        Nunca incluye ``agent_key_hash`` ni el secreto de la clave: la clave
        completa solo se devuelve una vez, en el momento del alta o de la
        rotación, nunca en una lectura posterior.

        Las fechas se devuelven como ``datetime`` crudo, sin formatear: es el
        schema de respuesta (``UTCDateTime``) quien las serializa a ISO 8601
        con sufijo de zona horaria, igual que en el resto de módulos.

        Returns:
            Diccionario con id, hostname, os, labels, status, lastSeenAt,
            agentVersion y createdAt.
        """
        return {
            "id":           self.id,
            "hostname":     self.hostname,
            "os":           self.os,
            "labels":       self.labels or {},
            "status":       self.status,
            "lastSeenAt":   self.last_seen_at,
            "agentVersion": self.agent_version,
            "createdAt":    self.created_at,
        }

    def __repr__(self) -> str:
        """Representación de depuración con id, hostname y estado."""
        return f"<MonitoredAsset(id={self.id}, hostname='{self.hostname}', status='{self.status}')>"


class AssetSnapshot(Base):
    """
    Instantánea de métricas de un activo en un instante (un heartbeat).

    Decisión de diseño: una fila por heartbeat, con todas las métricas en
    ``metrics`` (JSONB), en lugar de una fila por (métrica, timestamp). El
    agente empuja un payload completo por intervalo, así que una fila por
    payload es el mapeo natural y minimiza volumen de filas y complejidad
    de escritura. Solo las dos métricas más consultadas se desnormalizan a
    columnas propias para poder filtrar/ordenar sin abrir el JSONB.

    Attributes:
        id: Clave primaria, autoincremental.
        asset_id: Clave foránea al activo que envió este heartbeat.
        collected_at: Instante del heartbeat según el reloj del agente (no
            confiable por sí solo; ver ``received_at``).
        received_at: Instante en que el servidor recibió el heartbeat. El
            detector de presencia y el orden de la serie temporal se basan
            en este campo, nunca en ``collected_at``.
        metrics: Payload completo de métricas del heartbeat, tal como llegó
            (ya validado por el schema de ingesta).
        cpu_pct: Porcentaje de uso de CPU, desnormalizado desde ``metrics``.
        mem_pct: Porcentaje de uso de memoria, desnormalizado desde ``metrics``.
        asset: Activo al que pertenece este snapshot.
    """

    __tablename__ = "AssetSnapshot"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    asset_id     = Column(
        Integer, ForeignKey("MonitoredAsset.id", ondelete="CASCADE"),
        index=True, nullable=False,
    )
    collected_at = Column(DateTime, index=True, nullable=False)
    received_at  = Column(DateTime, nullable=False, default=utcnow_naive)

    metrics = Column(JSONB, nullable=False)
    cpu_pct = Column(Float, nullable=True)
    mem_pct = Column(Float, nullable=True)

    asset = relationship("MonitoredAsset", back_populates="snapshots")

    __table_args__ = (
        Index("ix_snapshot_asset_time", "asset_id", "collected_at"),
        # La serie temporal se ordena y se poda por ``received_at``; sin este
        # índice, el ORDER BY ... DESC LIMIT de get_series tendría que ordenar
        # la partición entera del activo (30 días de heartbeats) en cada carga.
        Index("ix_snapshot_asset_received", "asset_id", "received_at"),
    )

    def to_dict(self) -> dict:
        """
        Serializa el snapshot para respuestas de API (serie temporal).

        Returns:
            Diccionario con collectedAt, receivedAt, cpuPct, memPct y metrics.
        """
        return {
            "collectedAt": self.collected_at,
            "receivedAt":  self.received_at,
            "cpuPct":      self.cpu_pct,
            "memPct":      self.mem_pct,
            "metrics":     self.metrics,
        }

    def __repr__(self) -> str:
        """Representación de depuración con id, asset_id y collected_at."""
        return f"<AssetSnapshot(id={self.id}, asset={self.asset_id}, at={self.collected_at})>"


class Anomaly(Base):
    """
    Anomalía detectada sobre las métricas de un activo, con ciclo de vida propio.

    No se crea una fila por cada heartbeat que cruza el umbral: se abre al
    primer cruce sostenido (N heartbeats consecutivos) y se resuelve cuando
    la métrica vuelve por debajo (con histéresis). La única excepción es
    ``host_down``: su apertura la decide el job de presencia por *ausencia*
    de heartbeat, y su cierre lo decide la ingesta por *presencia* de uno.

    Attributes:
        id: Clave primaria, autoincremental.
        asset_id: Clave foránea al activo afectado.
        kind: Tipo de anomalía ("cpu_spike" | "mem_high" | "swap_thrash" |
            "disk_full" | "host_down").
        severity: Severidad ("info" | "warning" | "critical").
        metric: Métrica que disparó la anomalía (p. ej. "cpu.usagePct"),
            opcional para tipos que no dependen de una métrica puntual.
        value: Valor de la métrica en el momento de la apertura.
        threshold: Umbral que se cruzó.
        details: Contexto adicional (p. ej. el proceso responsable del pico).
        state: Estado del ciclo de vida ("open" | "acknowledged" | "resolved").
        opened_at: Instante de apertura.
        resolved_at: Instante de resolución, nulo mientras siga abierta.
        asset: Activo al que pertenece esta anomalía.
    """

    __tablename__ = "Anomaly"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(
        Integer, ForeignKey("MonitoredAsset.id", ondelete="CASCADE"),
        index=True, nullable=False,
    )

    kind      = Column(String(48), nullable=False)
    severity  = Column(String(16), nullable=False)
    metric    = Column(String(64), nullable=True)
    value     = Column(Float, nullable=True)
    threshold = Column(Float, nullable=True)
    details   = Column(JSONB, nullable=True)

    state       = Column(String(16), nullable=False, default="open")
    opened_at   = Column(DateTime, nullable=False, default=utcnow_naive, index=True)
    resolved_at = Column(DateTime, nullable=True)

    asset = relationship("MonitoredAsset", back_populates="anomalies")

    def to_dict(self) -> dict:
        """
        Serializa la anomalía para respuestas de API.

        Returns:
            Diccionario con id, assetId, kind, severity, metric, value,
            threshold, details, state, openedAt y resolvedAt.
        """
        return {
            "id":         self.id,
            "assetId":    self.asset_id,
            "kind":       self.kind,
            "severity":   self.severity,
            "metric":     self.metric,
            "value":      self.value,
            "threshold":  self.threshold,
            "details":    self.details or {},
            "state":      self.state,
            "openedAt":   self.opened_at,
            "resolvedAt": self.resolved_at,
        }

    def __repr__(self) -> str:
        """Representación de depuración con id, asset_id, kind y state."""
        return (
            f"<Anomaly(id={self.id}, asset={self.asset_id}, "
            f"kind='{self.kind}', state='{self.state}')>"
        )
