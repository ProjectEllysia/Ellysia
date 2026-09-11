"""
IrisTriageManager — vistas guardadas y etiquetas del historial de triaje.

Es el puente entre la lista paginada de análisis y el trabajo de un analista:
guardar una combinación de filtros con nombre («phishing sin revisar de esta
semana») para volver a esa cola sin reconstruirla, y etiquetar análisis para
agruparlos. Los filtros en sí (título, veredicto, estado, origen, etiqueta,
IOC y pendiente de revisar) los aplica ``IrisAnalysisRepository``.

Las etiquetas son filas aparte (``IrisAnalysisTag``): etiquetar no modifica el
análisis, que sigue siendo el resultado inmutable de lo que decidió Iris.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from src.modules.infrastructure import UnitOfWork, build_repository
from src.modules.shared import assert_owned, isoformat_utc

from ..exceptions import IrisInvalidInputError, IrisSavedViewNotFoundError
from ..model import IrisAnalysisTag, IrisSavedView
from ..repositories import IrisAnalysisTagRepository, IrisSavedViewRepository
from ..services.tags import normalize_tags
from .analysis import IrisManager

#: Vistas guardadas por usuario. Una lista más larga deja de ser un atajo.
MAX_SAVED_VIEWS = 50

#: Longitud máxima del nombre de una vista; coincide con la columna.
MAX_VIEW_NAME_LENGTH = 60


def _invalid_input(text: str) -> IrisInvalidInputError:
    """Error de validación cuyo mensaje se puede enseñar tal cual al usuario.

    Args:
        text: Qué falló, en castellano.

    Returns:
        IrisInvalidInputError: Con ``user_message`` igual a ``text``.
    """
    return IrisInvalidInputError(text, user_message=text)


class IrisTriageManager:
    """Vistas guardadas y etiquetas de los análisis de un usuario."""

    @staticmethod
    def view_to_dict(view: IrisSavedView) -> Dict[str, Any]:
        """Serializa una vista guardada con las claves de la API.

        Args:
            view: Fila ``IrisSavedView``.

        Returns:
            dict: ``viewId``, ``name``, ``filters`` (con las mismas claves que
                los parámetros de ``GET /iris/results``) y ``createdAt``.
        """
        return {
            "viewId": view.id,
            "name": view.name,
            "filters": view.filters or {},
            "createdAt": isoformat_utc(view.created_at),
        }

    def list_views(self, user_id: int) -> List[Dict[str, Any]]:
        """Vistas guardadas de un usuario, por nombre.

        Args:
            user_id: Dueño de las vistas.

        Returns:
            List[dict]: Las vistas (ver ``view_to_dict``); lista vacía si no tiene.
        """
        return [self.view_to_dict(view) for view in build_repository(IrisSavedViewRepository).get_by_user(user_id)]

    def create_view(self, user_id: int, name: str, filters: Mapping[str, Any]) -> Dict[str, Any]:
        """Guarda una combinación de filtros con nombre.

        Args:
            user_id: Dueño de la vista.
            name: Nombre visible; se recortan los espacios. Único por usuario.
            filters: Filtros ya validados por ``IrisTriageFiltersSchema``; se
                descartan los vacíos para que la vista guarde solo lo que filtra.

        Returns:
            dict: La vista creada (ver ``view_to_dict``).

        Raises:
            IrisInvalidInputError: Si el nombre está vacío o ya existe, o si el
                usuario ya tiene ``MAX_SAVED_VIEWS`` vistas.
        """
        cleaned_name = (name or "").strip()[:MAX_VIEW_NAME_LENGTH]
        if not cleaned_name:
            raise _invalid_input("La vista necesita un nombre.")
        cleaned_filters = {key: value for key, value in filters.items() if value not in (None, "")}
        with UnitOfWork() as uow:
            repo = IrisSavedViewRepository(uow)
            if repo.count_by_user(user_id) >= MAX_SAVED_VIEWS:
                raise _invalid_input(f"Como mucho {MAX_SAVED_VIEWS} vistas guardadas.")
            if repo.get_by_user_and_name(user_id, cleaned_name) is not None:
                raise _invalid_input(f"Ya tienes una vista llamada «{cleaned_name}».")
            view = repo.save(IrisSavedView(user_id=user_id, name=cleaned_name, filters=cleaned_filters))
            return self.view_to_dict(view)

    def delete_view(self, view_id: int, user_id: int) -> None:
        """Borra una vista guardada.

        Args:
            view_id: Vista a borrar; debe ser del usuario.
            user_id: Usuario que la borra.

        Raises:
            IrisSavedViewNotFoundError: Si no existe o no es suya.
        """
        with UnitOfWork() as uow:
            view = assert_owned(IrisSavedViewRepository, view_id, user_id, IrisSavedViewNotFoundError, uow=uow)
            IrisSavedViewRepository(uow).delete(view)

    def set_tags(self, analysis_id: int, user_id: int, tags: Sequence[str]) -> List[str]:
        """Sustituye las etiquetas de un análisis.

        Args:
            analysis_id: Análisis a etiquetar; debe ser del usuario.
            user_id: Usuario que etiqueta.
            tags: Conjunto completo de etiquetas; una lista vacía las quita todas.

        Returns:
            List[str]: Las etiquetas que quedan, ya normalizadas (ver
                ``services/tags.normalize_tags``).

        Raises:
            IrisAnalysisNotFoundError: Si el análisis no existe o no es suyo.
            IrisInvalidInputError: Si alguna etiqueta es demasiado larga o son
                demasiadas.
        """
        IrisManager.assert_analysis_ownership(analysis_id, user_id)
        try:
            normalized = normalize_tags(tags)
        except ValueError as e:
            raise _invalid_input(str(e)) from e
        with UnitOfWork() as uow:
            repo = IrisAnalysisTagRepository(uow)
            repo.delete_by_analysis(analysis_id)
            for tag in normalized:
                repo.save(IrisAnalysisTag(analysis_id=analysis_id, name=tag))
        return normalized

    def list_tags(self, user_id: int) -> List[Dict[str, Any]]:
        """Etiquetas que usa un usuario, con cuántos análisis lleva cada una.

        Args:
            user_id: Dueño de los análisis.

        Returns:
            List[dict]: ``{name, count}``, de la más usada a la menos; a igual
                uso, por nombre.
        """
        rows = build_repository(IrisAnalysisTagRepository).count_by_name_for_user(user_id)
        return [{"name": name, "count": count} for name, count in rows]
