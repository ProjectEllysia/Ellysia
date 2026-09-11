"""
IrisFeedbackManager — correcciones del analista y métricas del detector.

El analista puede decir si un veredicto era correcto; esa etiqueta alimenta
las métricas (precisión, recall, cobertura y desacuerdo por familia) y, más
adelante, la calibración. **Nunca** modifica el veredicto ya emitido: el
análisis sigue diciendo lo que Iris decidió y el feedback lo que opinó una
persona después.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import isoformat_utc

from ..exceptions import IrisAnalysisNotReadyError, IrisInvalidInputError
from ..model import IrisAnalystFeedback
from ..repositories import (
    IrisAnalysisRepository,
    IrisAnalystFeedbackRepository,
    IrisRuleResultRepository,
)
from ..services.feedback_metrics import FEEDBACK_LABELS, compute_feedback_metrics, outcome_from_rules
from ..services.rules import iris_rules
from .analysis import IrisManager

#: Longitud máxima de la nota del analista.
MAX_NOTE_LENGTH = 2000


class IrisFeedbackManager:
    """Registra correcciones del analista y calcula las métricas del detector."""

    @staticmethod
    def feedback_to_dict(feedback: IrisAnalystFeedback) -> Dict[str, Any]:
        """Serializa una corrección con las claves camelCase de la API.

        Args:
            feedback: Fila ``IrisAnalystFeedback`` persistida.

        Returns:
            dict: ``feedbackId``, ``analysisId``, ``label``, ``note``,
                ``author`` (nombre de usuario) y ``createdAt``.
        """
        return {
            "feedbackId": feedback.id,
            "analysisId": feedback.analysis_id,
            "label": feedback.label,
            "note": feedback.note,
            "author": feedback.author.username if feedback.author else "unknown",
            "createdAt": isoformat_utc(feedback.created_at),
        }

    def submit_feedback(self, analysis_id: int, user_id: int, label: str,
                        note: Optional[str] = None) -> Dict[str, Any]:
        """Registra la corrección de un analista sobre un análisis terminado.

        Añade una fila nueva y deja intacto el historial y el veredicto.

        Args:
            analysis_id: Análisis a corregir; debe ser del usuario.
            user_id: Analista que corrige; queda como autor.
            label: ``malicious``, ``legitimate`` o ``unknown``.
            note: Nota libre opcional; se recorta a ``MAX_NOTE_LENGTH`` y una
                nota en blanco se guarda como ``None``. Por defecto ``None``.

        Returns:
            dict: La corrección registrada (ver ``feedback_to_dict``).

        Raises:
            IrisAnalysisNotFoundError: Si el análisis no existe o no es suyo.
            IrisAnalysisNotReadyError: Si el análisis no ha terminado: sin
                veredicto no hay nada que corregir.
            IrisInvalidInputError: Si la etiqueta no es una de las tres.
        """
        analysis = IrisManager.assert_analysis_ownership(analysis_id, user_id)
        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)
        if label not in FEEDBACK_LABELS:
            raise IrisInvalidInputError(f"Etiqueta de feedback desconocida: {label!r}.")

        cleaned_note = note.strip()[:MAX_NOTE_LENGTH] if note and note.strip() else None
        with UnitOfWork() as uow:
            feedback = IrisAnalystFeedbackRepository(uow).save(IrisAnalystFeedback(
                analysis_id=analysis_id, author_id=user_id, label=label, note=cleaned_note,
            ))
            return self.feedback_to_dict(feedback)

    def list_feedback(self, analysis_id: int, user_id: int) -> List[Dict[str, Any]]:
        """Historial de correcciones de un análisis, de la más reciente a la más antigua.

        Args:
            analysis_id: Análisis consultado; debe ser del usuario.
            user_id: Usuario que consulta.

        Returns:
            List[dict]: Las correcciones (ver ``feedback_to_dict``).

        Raises:
            IrisAnalysisNotFoundError: Si el análisis no existe o no es suyo.
        """
        IrisManager.assert_analysis_ownership(analysis_id, user_id)
        repo = build_repository(IrisAnalystFeedbackRepository)
        return [self.feedback_to_dict(feedback) for feedback in repo.get_by_analysis(analysis_id)]

    @classmethod
    def latest_for_analysis(cls, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Corrección vigente de un análisis, ya serializada.

        Args:
            analysis_id: Primary key del análisis.

        Returns:
            Optional[dict]: La más reciente, o ``None`` si nadie lo revisó.
        """
        feedback = build_repository(IrisAnalystFeedbackRepository).latest_for_analysis(analysis_id)
        return cls.feedback_to_dict(feedback) if feedback else None

    def get_metrics(self, user_id: int) -> Dict[str, Any]:
        """Métricas del detector sobre los análisis revisados de un usuario.

        Por cada análisis con etiqueta vigente se toman las reglas del
        contexto ganador (las que describen el veredicto) y las reglas que no
        se evaluaron de verdad —las que fallaron y las que no tuvieron
        contenido que inspeccionar—, que restan cobertura a su familia.

        Args:
            user_id: Dueño de los análisis.

        Returns:
            dict: Salida de ``services/feedback_metrics.compute_feedback_metrics``.
        """
        family_of = {rule_def["name"]: rule_def.get("family") or "" for rule_def in iris_rules.get_rules()}
        families = {family for family in family_of.values() if family}

        rule_repo = build_repository(IrisRuleResultRepository)
        outcomes = []
        for feedback in build_repository(IrisAnalystFeedbackRepository).latest_per_analysis_for_user(user_id):
            analysis = feedback.analysis
            rules = rule_repo.get_by_analysis(analysis.id, context_type=analysis.winning_context)
            unevaluated = [rule["name"] for rule in (analysis.failed_rules or [])]
            unevaluated += list((analysis.coverage or {}).get("uncoveredRules") or [])
            outcomes.append(outcome_from_rules(
                feedback.label, analysis.verdict,
                [(rule.rule_name, rule.score) for rule in rules],
                family_of, unevaluated,
            ))

        analyses_total = build_repository(IrisAnalysisRepository).count_finished_by_user(user_id)
        return compute_feedback_metrics(outcomes, families, analyses_total)
