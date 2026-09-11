"""
IrisCaseManager — casos de analista: la decisión humana encima de los análisis.

Un análisis es el resultado inmutable de lo que decidió Iris. Un caso agrupa
uno o varios análisis y registra lo que decidió una persona: estado,
prioridad, asignación, etiquetas, notas y una timeline (``IrisCaseEvent``)
con cada cambio, para que el trabajo operativo se pueda medir y auditar. Qué
transiciones de estado son válidas lo decide ``services/cases.py``.

Un caso es de un usuario, igual que sus análisis: una organización comparte
plan y factura, no datos (ver ``Organization``), así que un caso solo se puede
asignar a quien puede ver sus análisis, que es su dueño.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from src.modules.infrastructure import UnitOfWork, build_repository
from src.modules.shared import assert_owned, isoformat_utc, utcnow_naive

from ..exceptions import IrisCaseNotFoundError, IrisInvalidInputError
from ..model import CasePriority, IrisCase, IrisCaseAnalysis, IrisCaseEvent
from ..repositories import IrisCaseAnalysisRepository, IrisCaseEventRepository, IrisCaseRepository
from ..services.cases import MAX_CASE_TEXT_LENGTH, validate_transition
from ..services.tags import normalize_tags
from .analysis import IrisManager

#: Análisis que se pueden vincular a un caso al crearlo, en una sola petición.
MAX_ANALYSES_ON_CREATE = 50

#: Marca "no venía en la petición" en ``update_case``, distinta de ``None``
#: (que en ``assignee_id`` significa "quitar la asignación").
_UNSET = object()


def _invalid_input(text: str) -> IrisInvalidInputError:
    """Error de validación cuyo mensaje se enseña tal cual al usuario.

    Args:
        text: Qué falló, en castellano.

    Returns:
        IrisInvalidInputError: Con ``user_message`` igual a ``text``.
    """
    return IrisInvalidInputError(text, user_message=text)


def _clean_tags(tags: Iterable[str]) -> List[str]:
    """Normaliza las etiquetas de un caso con la misma regla que las de un análisis.

    Args:
        tags: Etiquetas tal como las escribió el usuario.

    Returns:
        List[str]: Etiquetas normalizadas (ver ``services/tags.normalize_tags``).

    Raises:
        IrisInvalidInputError: Si alguna es demasiado larga o son demasiadas.
    """
    try:
        return normalize_tags(tags)
    except ValueError as e:
        raise _invalid_input(str(e)) from e


def _record_event(uow: UnitOfWork, case: IrisCase, actor_id: int, kind: str,
                  detail: Optional[Dict[str, Any]] = None, note: Optional[str] = None) -> None:
    """Añade una entrada a la timeline del caso y marca su última modificación.

    Args:
        uow: Transacción en curso; el evento se confirma con el cambio que describe.
        case: Caso al que pertenece el evento.
        actor_id: Usuario que hizo el cambio.
        kind: Qué pasó: ``created``, ``status_changed``, ``priority_changed``,
            ``assigned``, ``title_changed``, ``tags_changed``, ``note``,
            ``analysis_linked`` o ``analysis_unlinked``.
        detail: Datos del cambio (``from``/``to``, ``analysisId``…). Por defecto ``None``.
        note: Texto de una nota. Por defecto ``None``.
    """
    case.updated_at = utcnow_naive()
    IrisCaseEventRepository(uow).save(IrisCaseEvent(
        case_id=case.id, actor_id=actor_id, kind=kind, detail=detail, note=note,
    ))


def _assert_case(uow: UnitOfWork, case_id: int, user_id: int) -> IrisCase:
    """Carga un caso dentro de la transacción y comprueba que es del usuario.

    Args:
        uow: Transacción en curso.
        case_id: Caso pedido.
        user_id: Usuario que lo pide.

    Returns:
        IrisCase: El caso.

    Raises:
        IrisCaseNotFoundError: Si no existe o no es suyo.
    """
    return assert_owned(IrisCaseRepository, case_id, user_id, IrisCaseNotFoundError, uow=uow)


def _summary(case: IrisCase) -> Dict[str, Any]:
    """Serializa lo que enseña el listado de casos.

    Args:
        case: Caso con sus vínculos cargados.

    Returns:
        dict: ``caseId``, ``title``, ``status``, ``priority``, ``assignee``,
            ``tags``, ``analysisCount``, ``createdAt``, ``updatedAt`` y ``closedAt``.
    """
    return {
        "caseId": case.id,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "assignee": case.assignee.username if case.assignee else None,
        "tags": list(case.tags or []),
        "analysisCount": len(case.links),
        "createdAt": isoformat_utc(case.created_at),
        "updatedAt": isoformat_utc(case.updated_at),
        "closedAt": isoformat_utc(case.closed_at),
    }


def _detail(case: IrisCase) -> Dict[str, Any]:
    """Serializa un caso entero: resumen, análisis vinculados y timeline.

    Args:
        case: Caso con sus vínculos y eventos cargados.

    Returns:
        dict: Lo de ``_summary`` más ``ownerId`` (el único usuario al que se
            puede asignar), ``assigneeId``, ``resolutionReason``, ``analyses``
            (id, título, estado, veredicto, score, confianza y cuándo se
            vinculó) y ``timeline`` (del evento más antiguo al más reciente,
            con su autor).
    """
    return {
        **_summary(case),
        "ownerId": case.user_id,
        "assigneeId": case.assignee_id,
        "resolutionReason": case.resolution_reason,
        "analyses": [{
            "analysisId": link.analysis.id,
            "title": link.analysis.title,
            "status": link.analysis.status,
            "verdict": link.analysis.verdict,
            "totalScore": link.analysis.total_score,
            "confidence": link.analysis.confidence,
            "addedAt": isoformat_utc(link.added_at),
        } for link in case.links],
        "timeline": [{
            "eventId": event.id,
            "kind": event.kind,
            "detail": event.detail,
            "note": event.note,
            "actor": event.actor.username if event.actor else None,
            "createdAt": isoformat_utc(event.created_at),
        } for event in case.events],
    }


class IrisCaseManager:
    """Alta, consulta y ciclo de vida de los casos de un usuario."""

    def create_case(self, user_id: int, title: str, priority: str = CasePriority.MEDIUM.value,
                    analysis_ids: Iterable[int] = (), tags: Iterable[str] = ()) -> Dict[str, Any]:
        """Abre un caso, opcionalmente con análisis ya vinculados.

        Args:
            user_id: Dueño del caso, que es también quien lo abre.
            title: Título visible; se recortan los espacios (hasta 120 caracteres).
            priority: ``low``, ``medium``, ``high`` o ``critical``. Por defecto ``medium``.
            analysis_ids: Análisis del usuario que se vinculan al abrirlo; se
                ignoran los repetidos. Por defecto ninguno.
            tags: Etiquetas del caso. Por defecto ninguna.

        Returns:
            dict: El caso abierto (ver ``_detail``), en estado ``new``.

        Raises:
            IrisInvalidInputError: Si el título está vacío, la prioridad no
                existe, hay demasiados análisis o las etiquetas no son válidas.
            IrisAnalysisNotFoundError: Si algún análisis no existe o no es suyo.
        """
        cleaned_title = (title or "").strip()[:120]
        if not cleaned_title:
            raise _invalid_input("El caso necesita un título.")
        if priority not in {member.value for member in CasePriority}:
            raise _invalid_input(f"Prioridad desconocida: {priority!r}.")
        unique_ids = list(dict.fromkeys(analysis_ids))
        if len(unique_ids) > MAX_ANALYSES_ON_CREATE:
            raise _invalid_input(f"Como mucho {MAX_ANALYSES_ON_CREATE} análisis al abrir un caso.")
        for analysis_id in unique_ids:
            IrisManager.assert_analysis_ownership(analysis_id, user_id)
        cleaned_tags = _clean_tags(tags)

        with UnitOfWork() as uow:
            case = IrisCaseRepository(uow).save(IrisCase(
                user_id=user_id, title=cleaned_title, priority=priority, tags=cleaned_tags,
            ))
            link_repo = IrisCaseAnalysisRepository(uow)
            for analysis_id in unique_ids:
                link_repo.save(IrisCaseAnalysis(case_id=case.id, analysis_id=analysis_id))
            _record_event(uow, case, user_id, "created", {"analysisIds": unique_ids, "priority": priority})
            case_id = case.id
        return self.get_case(case_id, user_id)

    def list_cases(self, user_id: int, status: Optional[str] = None, priority: Optional[str] = None,
                   assigned_to_me: bool = False) -> Dict[str, Any]:
        """Casos de un usuario, del modificado más recientemente al más antiguo.

        Args:
            user_id: Dueño de los casos.
            status: Solo los de este estado. Por defecto ``None``: todos.
            priority: Solo los de esta prioridad. Por defecto ``None``: todas.
            assigned_to_me: Solo los asignados al propio usuario. Por defecto ``False``.

        Returns:
            dict: ``cases`` (ver ``_summary``), ``total`` y ``countsByStatus``,
                cuántos casos tiene en cada estado sin aplicar los filtros: es
                la cola de trabajo de un vistazo.
        """
        repo = build_repository(IrisCaseRepository)
        cases = repo.get_by_user_filtered(user_id, status=status, priority=priority,
                                          assignee_id=user_id if assigned_to_me else None)
        return {
            "cases": [_summary(case) for case in cases],
            "total": len(cases),
            "countsByStatus": repo.count_by_status_for_user(user_id),
        }

    def get_case(self, case_id: int, user_id: int) -> Dict[str, Any]:
        """Un caso entero, con sus análisis y su timeline.

        Args:
            case_id: Caso pedido.
            user_id: Usuario que lo pide; debe ser el dueño.

        Returns:
            dict: Ver ``_detail``.

        Raises:
            IrisCaseNotFoundError: Si no existe o no es suyo.
        """
        case = assert_owned(IrisCaseRepository, case_id, user_id, IrisCaseNotFoundError)
        return _detail(case)

    def update_case(self, case_id: int, user_id: int, *, title: Any = _UNSET, priority: Any = _UNSET,
                    tags: Any = _UNSET, assignee_id: Any = _UNSET) -> Dict[str, Any]:
        """Cambia título, prioridad, etiquetas o asignación, dejando rastro de cada cambio.

        Solo se toca lo que se pasa; un valor igual al actual no genera evento.

        Args:
            case_id: Caso a cambiar; debe ser del usuario.
            user_id: Usuario que lo cambia.
            title: Título nuevo. Por defecto sin cambios.
            priority: ``low``, ``medium``, ``high`` o ``critical``. Por defecto sin cambios.
            tags: Conjunto completo de etiquetas. Por defecto sin cambios.
            assignee_id: A quién se asigna, o ``None`` para quitar la asignación.
                Solo puede ser el dueño del caso: es el único que ve sus
                análisis. Por defecto sin cambios.

        Returns:
            dict: El caso actualizado (ver ``_detail``).

        Raises:
            IrisCaseNotFoundError: Si no existe o no es suyo.
            IrisInvalidInputError: Si algún valor no es válido.
        """
        with UnitOfWork() as uow:
            case = _assert_case(uow, case_id, user_id)
            if title is not _UNSET:
                cleaned = (title or "").strip()[:120]
                if not cleaned:
                    raise _invalid_input("El caso necesita un título.")
                if cleaned != case.title:
                    _record_event(uow, case, user_id, "title_changed", {"from": case.title, "to": cleaned})
                    case.title = cleaned
            if priority is not _UNSET and priority != case.priority:
                if priority not in {member.value for member in CasePriority}:
                    raise _invalid_input(f"Prioridad desconocida: {priority!r}.")
                _record_event(uow, case, user_id, "priority_changed", {"from": case.priority, "to": priority})
                case.priority = priority
            if tags is not _UNSET:
                cleaned_tags = _clean_tags(tags)
                if cleaned_tags != list(case.tags or []):
                    _record_event(uow, case, user_id, "tags_changed", {"from": list(case.tags or []), "to": cleaned_tags})
                    case.tags = cleaned_tags
            if assignee_id is not _UNSET and assignee_id != case.assignee_id:
                if assignee_id is not None and assignee_id != case.user_id:
                    raise _invalid_input(
                        "Un caso solo se puede asignar a quien puede ver sus análisis: su dueño."
                    )
                _record_event(uow, case, user_id, "assigned", {"from": case.assignee_id, "to": assignee_id})
                case.assignee_id = assignee_id
            IrisCaseRepository(uow).update(case)
        return self.get_case(case_id, user_id)

    def change_status(self, case_id: int, user_id: int, status: str,
                      reason: Optional[str] = None) -> Dict[str, Any]:
        """Mueve un caso por su ciclo de vida.

        Cerrar (``resolved`` o ``false_positive``) exige una razón y fija la
        fecha de cierre; reabrir (volver a ``triage``) las quita del caso, y
        la timeline conserva las dos cosas.

        Args:
            case_id: Caso a mover; debe ser del usuario.
            user_id: Usuario que lo mueve.
            status: Estado de destino (ver ``services/cases.ALLOWED_TRANSITIONS``).
            reason: Razón; obligatoria al cerrar. Por defecto ``None``.

        Returns:
            dict: El caso actualizado (ver ``_detail``).

        Raises:
            IrisCaseNotFoundError: Si no existe o no es suyo.
            IrisInvalidInputError: Si la transición no está permitida o falta la razón.
        """
        with UnitOfWork() as uow:
            case = _assert_case(uow, case_id, user_id)
            try:
                cleaned_reason = validate_transition(case.status, status, reason)
            except ValueError as e:
                raise _invalid_input(str(e)) from e
            _record_event(uow, case, user_id, "status_changed",
                          {"from": case.status, "to": status, "reason": cleaned_reason})
            case.status = status
            case.resolution_reason = cleaned_reason
            case.closed_at = utcnow_naive() if cleaned_reason else None
            IrisCaseRepository(uow).update(case)
        return self.get_case(case_id, user_id)

    def add_note(self, case_id: int, user_id: int, note: str) -> Dict[str, Any]:
        """Añade una nota a la timeline del caso.

        Args:
            case_id: Caso anotado; debe ser del usuario.
            user_id: Autor de la nota.
            note: Texto; se recortan los espacios y se limita a
                ``MAX_CASE_TEXT_LENGTH`` caracteres.

        Returns:
            dict: El caso actualizado (ver ``_detail``).

        Raises:
            IrisCaseNotFoundError: Si no existe o no es suyo.
            IrisInvalidInputError: Si la nota está vacía.
        """
        cleaned = (note or "").strip()[:MAX_CASE_TEXT_LENGTH]
        if not cleaned:
            raise _invalid_input("La nota está vacía.")
        with UnitOfWork() as uow:
            case = _assert_case(uow, case_id, user_id)
            _record_event(uow, case, user_id, "note", note=cleaned)
            IrisCaseRepository(uow).update(case)
        return self.get_case(case_id, user_id)

    def link_analysis(self, case_id: int, user_id: int, analysis_id: int) -> Dict[str, Any]:
        """Vincula un análisis del usuario a un caso. El análisis no cambia.

        Args:
            case_id: Caso; debe ser del usuario.
            user_id: Usuario que vincula.
            analysis_id: Análisis; debe ser del usuario.

        Returns:
            dict: El caso actualizado (ver ``_detail``).

        Raises:
            IrisCaseNotFoundError: Si el caso no existe o no es suyo.
            IrisAnalysisNotFoundError: Si el análisis no existe o no es suyo.
            IrisInvalidInputError: Si ya estaba vinculado.
        """
        IrisManager.assert_analysis_ownership(analysis_id, user_id)
        with UnitOfWork() as uow:
            case = _assert_case(uow, case_id, user_id)
            link_repo = IrisCaseAnalysisRepository(uow)
            if link_repo.get_link(case_id, analysis_id) is not None:
                raise _invalid_input(f"El análisis {analysis_id} ya está en este caso.")
            link_repo.save(IrisCaseAnalysis(case_id=case_id, analysis_id=analysis_id))
            _record_event(uow, case, user_id, "analysis_linked", {"analysisId": analysis_id})
            IrisCaseRepository(uow).update(case)
        return self.get_case(case_id, user_id)

    def unlink_analysis(self, case_id: int, user_id: int, analysis_id: int) -> Dict[str, Any]:
        """Desvincula un análisis de un caso. El análisis no se borra.

        Args:
            case_id: Caso; debe ser del usuario.
            user_id: Usuario que desvincula.
            analysis_id: Análisis a quitar del caso.

        Returns:
            dict: El caso actualizado (ver ``_detail``).

        Raises:
            IrisCaseNotFoundError: Si el caso no existe o no es suyo.
            IrisInvalidInputError: Si el análisis no estaba en el caso.
        """
        with UnitOfWork() as uow:
            case = _assert_case(uow, case_id, user_id)
            link_repo = IrisCaseAnalysisRepository(uow)
            link = link_repo.get_link(case_id, analysis_id)
            if link is None:
                raise _invalid_input(f"El análisis {analysis_id} no está en este caso.")
            link_repo.delete(link)
            _record_event(uow, case, user_id, "analysis_unlinked", {"analysisId": analysis_id})
            IrisCaseRepository(uow).update(case)
        return self.get_case(case_id, user_id)
