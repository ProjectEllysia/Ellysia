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
    HygeiaTag: Etiqueta con la que agrupar activos (base polimórfica).
    SystemTag: Etiqueta del catálogo común, sembrada por migración.
    UserTag: Etiqueta personal, siempre asociada a su dueño.

Example:
    >>> from src.modules.features.hygeia.model import MonitoredAsset
    >>> asset = MonitoredAsset(hostname="web-01", agent_key_id="abc123",
    ...                        agent_key_hash="$argon2...", user_id=1)
    >>> print(asset)
    <MonitoredAsset(id=None, hostname='web-01', status='pending')>
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    UniqueConstraint,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, utcnow_naive


# =========================================================================
# ASSOCIATION TABLES
# =========================================================================

AssetTag = Table(
    "AssetTag",
    Base.metadata,
    Column(
        "asset_id", Integer,
        ForeignKey("MonitoredAsset.id", ondelete="CASCADE"), primary_key=True,
    ),
    Column(
        "tag_id", Integer,
        ForeignKey("HygeiaTag.id", ondelete="CASCADE"), primary_key=True,
    ),
)
"""Qué etiquetas lleva cada activo.

Los dos ``ondelete="CASCADE"`` son la mitad de la garantía que pide el
producto: borrar una etiqueta borra sus asociaciones, **nunca los activos**
que la llevaban. La otra mitad la pone el ORM, que limpia la tabla de
asociación al borrar cualquiera de los dos extremos de la relación.
"""


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
        kernel: Versión de kernel reportada por el agente, opcional. Es
            identidad del host, no una métrica: se conserva el último valor
            conocido si un heartbeat concreto no lo trae.
        labels: Etiquetas libres del activo (entorno, rol, ubicación...).
        agent_key_id: Prefijo público de la clave de agente, único e indexado.
        agent_key_hash: Hash Argon2id del secreto de la clave de agente.
        agent_version: Versión del agente instalado, opcional.
        status: Estado de presencia ("pending" | "online" | "stale" | "offline").
        last_seen_at: Instante del último heartbeat recibido.
        uptime_sec: Segundos que el host llevaba encendido en el último
            heartbeat. Es estado instantáneo, no identidad: se sobreescribe
            en cada heartbeat, ``None`` incluido. Para presentarlo conviene
            derivar el instante de arranque (``last_seen_at - uptime_sec``),
            que no envejece entre lecturas.
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
        is_persistent: Si el host debería estar encendido siempre. ``True``
            (por defecto) es el comportamiento de un servidor 24/7: quedarse
            callado es una incidencia y el detector de presencia abre
            ``host_down``. ``False`` marca un host que se apaga a propósito
            (un portátil, un sobremesa que se suspende de noche): sigue
            transicionando a ``offline`` porque el estado es un hecho, pero
            no abre anomalía ni dispara correo — una caída esperada avisando
            cada noche solo entrena al dueño a ignorar los avisos de verdad.
        thresholds: Umbrales específicos de este activo, en el mismo formato
            que el bloque ``features.hygeia.thresholds`` de la configuración global.
            Si una métrica no aparece aquí, se usa el umbral global.
        inventory: Lista de software instalado (``Software[]`` del contrato
            de ingesta), tal como llegó en el último escaneo del agente. No
            hay histórico: cada escaneo es el estado completo, así que un
            escaneo nuevo reemplaza por completo al anterior, nunca se
            fusiona. ``None`` significa "el agente nunca ha escaneado
            software" (agente antiguo, o primer heartbeat aún no procesado);
            una lista vacía significa "escaneó y no encontró nada" (stub de
            Linux/macOS, o un host realmente sin software registrado).
        inventory_collected_at: Instante (reloj del servidor) del heartbeat
            que trajo el último ``inventory``. Vive aparte de ``last_seen_at``
            porque el inventario solo viaja cada
            ``InventoryIntervalSec`` (típicamente 6h), muchísimo más
            espaciado que el heartbeat.
        user_id: Clave foránea al usuario dueño del activo.
        created_at: Instante de alta del activo.
        snapshots: Heartbeats recibidos de este activo.
        anomalies: Anomalías (abiertas o resueltas) de este activo.
        tags: Etiquetas con las que el dueño agrupa este activo.
    """

    __tablename__ = "MonitoredAsset"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), nullable=False)
    os       = Column(String(64), nullable=True)
    kernel   = Column(String(128), nullable=True)
    labels   = Column(JSONB, nullable=True)

    agent_key_id   = Column(String(32), unique=True, index=True, nullable=False)
    agent_key_hash = Column(String(255), nullable=False)
    agent_version  = Column(String(32), nullable=True)

    status                 = Column(String(16), nullable=False, default="pending")
    last_seen_at           = Column(DateTime, nullable=True)
    uptime_sec             = Column(Integer, nullable=True)
    heartbeat_interval_sec = Column(Integer, nullable=True)
    breach_counters        = Column(JSONB, nullable=True)
    thresholds             = Column(JSONB, nullable=True)
    is_persistent          = Column(Boolean, nullable=False, default=True, server_default=true())

    inventory               = Column(JSONB, nullable=True)
    inventory_collected_at  = Column(DateTime, nullable=True)

    user_id    = Column(Integer, ForeignKey("User.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    snapshots = relationship(
        "AssetSnapshot", back_populates="asset", cascade="all, delete-orphan",
    )
    anomalies = relationship(
        "Anomaly", back_populates="asset", cascade="all, delete-orphan",
    )
    # `selectin` y no lazy por defecto: `list_assets()` serializa todos los
    # activos del usuario y la SPA sondea ese endpoint cada minuto. Con carga
    # perezosa serían N+1 consultas por listado; así son dos.
    tags = relationship(
        "HygeiaTag", secondary=AssetTag, back_populates="assets", lazy="selectin",
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
            Diccionario con id, hostname, os, kernel, labels, tags, status,
            isPersistent, lastSeenAt, uptimeSec, agentVersion y createdAt.
        """
        return {
            "id":           self.id,
            "hostname":     self.hostname,
            "os":           self.os,
            "kernel":       self.kernel,
            "labels":       self.labels or {},
            "tags":         [tag.to_dict() for tag in self.tags],
            "status":       self.status,
            "isPersistent": self.is_persistent,
            "lastSeenAt":   self.last_seen_at,
            "uptimeSec":    self.uptime_sec,
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
    de escritura.

    Sobre esa base se desnormalizan a columnas propias las métricas
    **escalares por snapshot** — un número por heartbeat, que es lo que
    tiene sentido graficar en el tiempo — para poder servir la serie
    temporal sin abrir el JSONB ni una sola vez. Las calcula
    ``services/aggregation.denormalize`` en el momento de la ingesta, de
    modo que el camino de lectura no necesita conocer la forma del payload
    del agente. Lo que tiene cardinalidad por entidad (uso por punto de
    montaje, tráfico por interfaz) o solo tiene sentido "ahora" (uso por
    núcleo, procesos top) se queda únicamente en ``metrics``.

    Todas las columnas desnormalizadas son nullable y ``NULL`` significa
    "no reportado", que es distinto de ``0``: un agente de Windows no manda
    ``loadAvg``, y uno sin interfaces visibles no manda red. Las filas
    anteriores a la instrumentación de cada columna se quedan a ``NULL`` y
    el gráfico simplemente empieza la traza donde hay datos.

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
        swap_pct: Porcentaje de swap en uso.
        load1: Carga media a 1 minuto (``loadAvg[0]``); nulo en Windows.
        disk_max_pct: Uso del punto de montaje más lleno del host.
        disk_max_mount: Punto de montaje al que corresponde ``disk_max_pct``.
        net_rx_bps: Bytes/s recibidos, sumados sobre las interfaces no-loopback.
        net_tx_bps: Bytes/s enviados, sumados sobre las interfaces no-loopback.
        power_watts: Potencia eléctrica del host en el momento del heartbeat,
            o ``None`` si el agente no expone ninguna fuente compatible.
        power_estimated: Si ``power_watts`` es una estimación por modelo
            (``True``) o una medición de sensor (``False``); ``None`` junto a
            un ``power_watts`` nulo.
        power_source: Procedencia concreta de la lectura (p. ej. ``"rapl"``,
            ``"hwmon"``, ``"windows-model"``), en texto libre del agente — el
            servidor no interpreta su valor, así que una fuente nueva no
            exige coordinación. Longitud 64 para coincidir con la validación
            del schema de ingesta.
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

    cpu_pct        = Column(Float, nullable=True)
    mem_pct        = Column(Float, nullable=True)
    swap_pct       = Column(Float, nullable=True)
    load1          = Column(Float, nullable=True)
    disk_max_pct   = Column(Float, nullable=True)
    disk_max_mount = Column(String(256), nullable=True)
    net_rx_bps     = Column(BigInteger, nullable=True)
    net_tx_bps     = Column(BigInteger, nullable=True)
    power_watts     = Column(Float, nullable=True)
    power_estimated = Column(Boolean, nullable=True)
    power_source    = Column(String(64), nullable=True)

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
        Serializa el snapshot como punto de la serie temporal.

        Devuelve **solo los escalares desnormalizados**, nunca el JSONB
        ``metrics``: multiplicado por los cientos de puntos de una serie, el
        payload completo pesaría órdenes de magnitud más sin aportar nada a
        un gráfico. Quien necesite el desglose por montaje, interfaz, núcleo
        o proceso lo pide para un único instante, por el endpoint de últimas
        métricas.

        Returns:
            Diccionario con collectedAt, receivedAt y los escalares del
            heartbeat, con las claves en camelCase.
        """
        return {
            "collectedAt":  self.collected_at,
            "receivedAt":   self.received_at,
            "cpuPct":       self.cpu_pct,
            "memPct":       self.mem_pct,
            "swapPct":      self.swap_pct,
            "load1":        self.load1,
            "diskMaxPct":   self.disk_max_pct,
            "diskMaxMount": self.disk_max_mount,
            "netRxBps":     self.net_rx_bps,
            "netTxBps":     self.net_tx_bps,
            "powerWatts":     self.power_watts,
            "powerEstimated": self.power_estimated,
            "powerSource":    self.power_source,
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


class HygeiaTag(Base):
    """
    Etiqueta con la que agrupar activos monitorizados.

    Hay dos clases de etiqueta y comparten tabla (herencia *single-table*,
    discriminada por ``tag_type``), porque son la misma cosa desde el punto
    de vista de un activo: un nombre y un color que se le cuelgan. Lo único
    que las distingue es de quién son.

    - ``SystemTag``: catálogo común, sembrado por migración. ``user_id`` es
      ``NULL``, todo el mundo las ve y nadie las crea ni las borra.
    - ``UserTag``: repositorio personal. ``user_id`` es obligatorio y solo
      su dueño la ve, la asigna y la borra.

    Esa regla no vive solo en el manager: el ``CheckConstraint`` de más
    abajo la impone en la base de datos, así que ni una migración torcida
    ni un ``INSERT`` a mano pueden dejar una etiqueta personal huérfana ni
    una de sistema con dueño.

    Attributes:
        id: Clave primaria, autoincremental.
        name: Texto de la etiqueta, tal como se pinta en el badge.
        color: Nombre del color de la paleta cerrada (ver ``TAG_COLORS`` en
            ``schemas.py``). No es un valor CSS: el frontend lo traduce, para
            que un cambio de tema no obligue a reescribir filas.
        tag_type: Discriminador ("system" | "user").
        user_id: Dueño de la etiqueta; ``NULL`` en las de sistema.
        created_at: Instante de alta de la etiqueta.
        assets: Activos que llevan esta etiqueta.
    """

    __tablename__ = "HygeiaTag"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    name       = Column(String(48), nullable=False)
    color      = Column(String(16), nullable=False, default="slate")
    tag_type   = Column(String(16), nullable=False)
    user_id    = Column(Integer, ForeignKey("User.id", ondelete="CASCADE"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    assets = relationship("MonitoredAsset", secondary=AssetTag, back_populates="tags")

    # Sin `polymorphic_identity` en la base a propósito: toda fila es de un
    # tipo concreto, `HygeiaTag` nunca se instancia directamente.
    __mapper_args__ = {"polymorphic_on": tag_type}

    __table_args__ = (
        # Un usuario no repite nombre. Las de sistema quedan fuera (en
        # Postgres los NULL son distintos entre sí) y no hace falta más: su
        # único escritor es la migración de siembra.
        UniqueConstraint("user_id", "name", name="uq_hygeiatag_user_name"),
        CheckConstraint(
            "(tag_type = 'system' AND user_id IS NULL) OR "
            "(tag_type = 'user' AND user_id IS NOT NULL)",
            name="ck_hygeiatag_owner",
        ),
        Index("ix_hygeiatag_user", "user_id"),
    )

    def to_dict(self) -> dict:
        """
        Serializa la etiqueta para respuestas de API.

        No incluye ``userId``: quien la recibe es siempre su dueño (o el de
        una etiqueta de sistema, que no tiene), así que el dato no añade
        nada y sí revela la forma interna del modelo.

        Returns:
            Diccionario con id, name, color y tagType.
        """
        return {
            "id":      self.id,
            "name":    self.name,
            "color":   self.color,
            "tagType": self.tag_type,
        }

    def __repr__(self) -> str:
        """Representación de depuración con id, nombre y tipo."""
        return f"<HygeiaTag(id={self.id}, name='{self.name}', type='{self.tag_type}')>"


class SystemTag(HygeiaTag):
    """Etiqueta del catálogo común: sin dueño, visible para todos, inmutable."""

    __mapper_args__ = {"polymorphic_identity": "system"}


class UserTag(HygeiaTag):
    """Etiqueta personal: siempre con dueño, y solo su dueño la usa."""

    __mapper_args__ = {"polymorphic_identity": "user"}
