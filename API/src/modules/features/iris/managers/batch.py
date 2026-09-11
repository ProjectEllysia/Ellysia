"""
IrisBatchManager — análisis por lotes: varios ``.eml`` o un ZIP en una petición.

El lote orquesta; no reimplementa el análisis. Cada mensaje pasa por el
``IrisManager.analyze()`` de siempre —mismas validaciones, misma cuota, misma
outbox— y el lote solo decide qué entra y deja constancia de qué pasó con
cada elemento (``IrisBatch``/``IrisBatchItem``).

Lo que el lote añade es el freno:

- **Límites de lote** (``iris.batchMaxItems``, ``iris.batchMaxTotalBytes``):
  un lote que no cabe se rechaza entero, antes de crear nada.
- **Back pressure** (``iris.maxActiveAnalysesPerUser``): si los análisis en
  curso del usuario más los que crearía el lote superan el tope, el lote se
  rechaza entero con un 429. No se aceptan la mitad de los mensajes y se
  pierden los demás: o entra todo lo analizable o nada, y el usuario sabe que
  tiene que esperar.
- **Duplicados**: un mensaje que ya está en el lote o que el usuario ya
  analizó (misma huella, ``IrisAnalysis.content_sha256``) no se vuelve a
  analizar ni cobra cuota; el elemento apunta al análisis existente.

Una entrada que falla (no es un correo analizable, se agotó la cuota) queda
marcada con su motivo y no afecta al resto.
"""

from __future__ import annotations

import logging
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple

import src.modules.system.config_reading as CR
from src.modules.accounts import QuotaExceededError
from src.modules.infrastructure import UnitOfWork, build_repository
from src.modules.shared import assert_owned, isoformat_utc

from ..exceptions import (
    IrisBatchBackpressureError,
    IrisBatchNotFoundError,
    IrisInvalidInputError,
)
from ..model import BatchItemStatus, IrisBatch, IrisBatchItem
from ..repositories import IrisAnalysisRepository, IrisBatchItemRepository, IrisBatchRepository
from ..services.batch import BatchLimitError, decode_message, expand_uploads, message_fingerprint
from .analysis import IrisManager

logger = logging.getLogger(__name__)

#: Lotes que devuelve el listado: los más recientes; los viejos siguen
#: consultables por su id.
RECENT_BATCHES_LIMIT = 20

#: Longitud máxima del nombre de fichero que se guarda; coincide con la columna.
_MAX_FILENAME_LENGTH = 255


def _invalid_input(text: str) -> IrisInvalidInputError:
    """Error de validación cuyo mensaje se enseña tal cual al usuario.

    Args:
        text: Qué falló, en castellano.

    Returns:
        IrisInvalidInputError: Con ``user_message`` igual a ``text``.
    """
    return IrisInvalidInputError(text, user_message=text)


def _read_uploads(uploads: Sequence[Tuple[str, BinaryIO]], max_total_bytes: int) -> List[Tuple[str, bytes]]:
    """Lee los ficheros subidos sin cargar nunca más de lo que admite un lote.

    Args:
        uploads: Pares ``(nombre, flujo)`` tal como llegan en la petición.
        max_total_bytes: Tope del lote; de cada fichero se lee como mucho un
            byte más, lo justo para saber que se pasa.

    Returns:
        List[Tuple[str, bytes]]: Pares ``(nombre, bytes)``.

    Raises:
        IrisInvalidInputError: Si algún fichero supera él solo el tope del lote.
    """
    read: List[Tuple[str, bytes]] = []
    for filename, stream in uploads:
        data = stream.read(max_total_bytes + 1)
        if len(data) > max_total_bytes:
            raise _invalid_input(f"«{filename}» supera él solo el tamaño máximo de un lote ({max_total_bytes} bytes).")
        read.append((filename or "sin-nombre", data))
    return read


def _item_to_dict(item: IrisBatchItem) -> Dict[str, Any]:
    """Serializa un elemento del lote con el estado actual de su análisis.

    Args:
        item: Fila ``IrisBatchItem``.

    Returns:
        dict: ``position``, ``filename``, ``status`` (``created``,
            ``duplicate``, ``rejected`` o ``failed``), ``analysisId``,
            ``error`` y, si hay análisis, su ``analysisStatus``, ``verdict`` y
            ``totalScore`` en este momento (es lo que la interfaz sondea para
            enseñar el progreso).
    """
    analysis = item.analysis
    return {
        "position": item.position,
        "filename": item.filename,
        "status": item.status,
        "analysisId": item.analysis_id,
        "error": item.error,
        "analysisStatus": analysis.status if analysis else None,
        "verdict": analysis.verdict if analysis else None,
        "totalScore": analysis.total_score if analysis else None,
    }


def _counts(items: Sequence[IrisBatchItem]) -> Dict[str, int]:
    """Cuántos elementos del lote hay en cada estado.

    Args:
        items: Elementos del lote.

    Returns:
        dict: Una clave por ``BatchItemStatus``, a cero si no hay ninguno.
    """
    counts = {status.value: 0 for status in BatchItemStatus}
    for item in items:
        counts[item.status] += 1
    return counts


class IrisBatchManager:
    """Recibe lotes de mensajes, los reparte en análisis y los deja consultables."""

    def submit_batch(self, user_id: int, uploads: Sequence[Tuple[str, BinaryIO]]) -> Dict[str, Any]:
        """Analiza un lote de ``.eml`` sueltos y/o ZIP.

        Args:
            user_id: Usuario que envía el lote; dueño de los análisis.
            uploads: Pares ``(nombre, flujo)`` de los ficheros subidos.

        Returns:
            dict: El lote (ver ``get_batch``): resumen por estado y un
                elemento por mensaje con su análisis.

        Raises:
            IrisInvalidInputError: Si el lote está vacío o no cabe en los
                límites (``iris.batchMaxItems``, ``iris.batchMaxTotalBytes``).
                No se crea nada.
            IrisBatchBackpressureError: Si crearía más análisis en curso de los
                que admite ``iris.maxActiveAnalysesPerUser``. No se crea nada.
        """
        config = CR.iris_config()
        try:
            entries = expand_uploads(
                _read_uploads(uploads, config.batch_max_total_bytes),
                max_items=config.batch_max_items,
                max_message_bytes=config.max_message_bytes,
                max_total_bytes=config.batch_max_total_bytes,
            )
        except BatchLimitError as e:
            raise _invalid_input(str(e)) from e

        # Primero se planifica todo el lote —qué se crea, qué se repite, qué se
        # rechaza— y solo después se crea nada, para poder aplicar el freno al
        # lote entero.
        analysis_repo = build_repository(IrisAnalysisRepository)
        plan: List[Dict[str, Any]] = []
        first_position_by_fingerprint: Dict[str, int] = {}
        for position, entry in enumerate(entries):
            step: Dict[str, Any] = {"entry": entry, "status": None, "raw": None,
                                    "analysis_id": None, "error": None, "same_as": None}
            if entry.rejection:
                step.update(status=BatchItemStatus.REJECTED.value, error=entry.rejection)
            else:
                raw = decode_message(entry.content)
                fingerprint = message_fingerprint(raw)
                existing = analysis_repo.get_by_user_and_fingerprint(user_id, fingerprint)
                if fingerprint in first_position_by_fingerprint:
                    step.update(status=BatchItemStatus.DUPLICATE.value,
                                same_as=first_position_by_fingerprint[fingerprint])
                elif existing is not None:
                    step.update(status=BatchItemStatus.DUPLICATE.value, analysis_id=existing.id)
                else:
                    first_position_by_fingerprint[fingerprint] = position
                    step.update(status=BatchItemStatus.CREATED.value, raw=raw)
            plan.append(step)

        to_create = sum(1 for step in plan if step["status"] == BatchItemStatus.CREATED.value)
        active = analysis_repo.count_active_by_user(user_id)
        if active + to_create > config.max_active_analyses_per_user:
            raise IrisBatchBackpressureError(active, to_create, config.max_active_analyses_per_user)

        with UnitOfWork() as uow:
            batch = IrisBatchRepository(uow).save(IrisBatch(user_id=user_id, total=len(entries)))
            batch_id = batch.id

        manager = IrisManager()
        for step in plan:
            if step["status"] != BatchItemStatus.CREATED.value:
                continue
            title = step["entry"].filename.rsplit("/", 1)[-1][:120]
            try:
                step["analysis_id"] = manager.analyze(None, user_id, title=title, raw_message=step["raw"])
            except IrisInvalidInputError as e:
                step.update(status=BatchItemStatus.FAILED.value, error=str(e.user_message or e))
            except QuotaExceededError as e:
                step.update(status=BatchItemStatus.FAILED.value, error=str(getattr(e, "user_message", None) or e))
            except Exception:  # pylint: disable=broad-except
                # Un fallo inesperado en un mensaje no puede tirar el resto del
                # lote: queda en el log con su traza y el elemento, marcado.
                logger.exception("Lote %s: fallo al crear el análisis de %s", batch_id, step["entry"].filename)
                step.update(status=BatchItemStatus.FAILED.value, error="Error interno al crear el análisis.")

        for step in plan:
            if step["same_as"] is not None:
                original = plan[step["same_as"]]
                step["analysis_id"] = original["analysis_id"]
                if original["analysis_id"] is None:
                    step.update(status=BatchItemStatus.FAILED.value, error=original["error"])

        with UnitOfWork() as uow:
            item_repo = IrisBatchItemRepository(uow)
            for position, step in enumerate(plan):
                item_repo.save(IrisBatchItem(
                    batch_id=batch_id, position=position,
                    filename=step["entry"].filename[:_MAX_FILENAME_LENGTH],
                    status=step["status"], analysis_id=step["analysis_id"], error=step["error"],
                ))
        logger.info("Lote %s de %s mensajes enviado por el usuario %s", batch_id, len(entries), user_id)
        return self.get_batch(batch_id, user_id)

    def get_batch(self, batch_id: int, user_id: int) -> Dict[str, Any]:
        """Un lote con el estado actual de cada uno de sus análisis.

        Args:
            batch_id: Lote pedido.
            user_id: Usuario que lo pide; debe ser el dueño.

        Returns:
            dict: ``batchId``, ``createdAt``, ``total``, ``counts`` (ver
                ``_counts``) e ``items`` (ver ``_item_to_dict``), en el orden
                en que llegaron los mensajes.

        Raises:
            IrisBatchNotFoundError: Si no existe o no es suyo.
        """
        batch = assert_owned(IrisBatchRepository, batch_id, user_id, IrisBatchNotFoundError)
        return {
            "batchId": batch.id,
            "createdAt": isoformat_utc(batch.created_at),
            "total": batch.total,
            "counts": _counts(batch.items),
            "items": [_item_to_dict(item) for item in batch.items],
        }

    def list_batches(self, user_id: int, limit: Optional[int] = None) -> Dict[str, Any]:
        """Lotes recientes de un usuario, del más nuevo al más antiguo.

        Args:
            user_id: Dueño de los lotes.
            limit: Cuántos como máximo. Por defecto ``None``: ``RECENT_BATCHES_LIMIT``.

        Returns:
            dict: ``batches``, cada uno con ``batchId``, ``createdAt``,
                ``total`` y ``counts``.
        """
        batches = build_repository(IrisBatchRepository).get_recent_by_user(user_id, limit or RECENT_BATCHES_LIMIT)
        return {"batches": [{
            "batchId": batch.id,
            "createdAt": isoformat_utc(batch.created_at),
            "total": batch.total,
            "counts": _counts(batch.items),
        } for batch in batches]}
