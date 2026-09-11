"""
Iris Rule Registry — decorator-based rule registration system.

Each rule is a callable that receives a parsed headers dict and returns a
RuleResult.  Rules are registered via the @iris_rules.register() decorator
and discovered automatically when their module is imported.

Los helpers compartidos entre reglas (extract_domain, registrable_domain,
datasets configurables, etc.) viven en ``shared.py`` — este módulo solo
contiene el mecanismo de registro.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Dict, List, Optional, Sequence

from .evidence import anchor_result

#: Forma de un ``rule_id``: ``iris.<grupo>.<nombre>``, en minúsculas. Es un
#: identificador estable: no cambia aunque cambie el nombre visible de la regla.
_RULE_ID_RE = re.compile(r"^iris\.[a-z_]+\.[a-z0-9_]+$")

#: Técnica o subtécnica de MITRE ATT&CK (``T1566`` o ``T1566.002``).
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleSeverity(StrEnum):
    """Gravedad de un hallazgo de la regla, separada de su score.

    El score mide cuánto pesa la señal en el veredicto; la severidad dice
    cuánto importa el hecho si es cierto (una suplantación de dominio es
    crítica aunque la regla pese poco en un mensaje concreto).

    Attributes:
        LOW: Indicio débil o frecuente en correo legítimo.
        MEDIUM: Anomalía que merece revisión.
        HIGH: Indicador fuerte de phishing.
        CRITICAL: Suplantación deliberada de una identidad.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RuleResult:
    """Result produced by a single analysis rule.

    Attributes:
        score: Numerical contribution to the overall credibility score.
               Positive = evidence of legitimacy, negative = suspicious.
        verdict: Short status string: "pass", "fail", "neutral", "error",
                 or a domain-specific variant like "softfail".
        details: Arbitrary structured data with rule-specific findings.
        recommendation: Human-readable advice shown when the rule
                        indicates a problem.  None when the rule passes.
        evidence: Dónde está, dentro del mensaje, lo que la regla encontró:
                  lista de elementos con el contrato de
                  ``services/evidence.py`` (``kind``, ``locator``, ``excerpt``).
                  Vacía por defecto; el registro la rellena con las cabeceras
                  declaradas cuando la regla penaliza sin aportarla.
        evidence_unavailable_reason: Por qué un hallazgo no se puede anclar a
                  un fragmento del mensaje; ``None`` si tiene evidencia o si
                  la regla no penalizó.
    """
    score: float
    verdict: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_unavailable_reason: Optional[str] = None


class RuleRegistry:
    """Global registry that collects rules via the @register decorator.

    Rules are callables that receive a parsed header dictionary and
    return a RuleResult.  The registry is populated automatically when
    rule modules are imported — just add a new ``.py`` file under
    ``services/rules/`` and import it in ``services/rules/__init__.py``.
    """

    def __init__(self) -> None:
        # Instance attribute, not class attribute: the latter is shared
        # across every RuleRegistry (in practice just the ``iris_rules``
        # singleton, but ``clear()`` — used in tests — mutated it as
        # global state regardless, making test order matter.
        self._rules: List[Dict] = []

    def register(self, name: str, category: str = "general",
                 description: str = "", needs_context: bool = False,
                 family: str = "", is_body_dependent: bool = False,
                 evidence_headers: Sequence[str] = (), is_self_anchoring: bool = False,
                 unanchorable_reason: str = "", rule_id: str = "", severity: str = "",
                 mitre_techniques: Sequence[str] = ()):
        """Decorator that registers a function as an analysis rule.

        La regla se guarda envuelta: tras ejecutarla, el envoltorio garantiza
        que un resultado que penaliza lleva evidencia anclada o dice por qué
        no (``services/evidence.anchor_result``). El decorador devuelve la
        función original, así que llamarla directamente no pasa por el
        envoltorio.

        Args:
            name: Human-readable rule name (e.g. "SPF", "DKIM").
            category: Grouping category (e.g. "authentication", "header_analysis").
            description: Detailed explanation of what the rule checks.
            needs_context: If True, the rule receives a
                ``services.parsers.MessageContext`` (headers + body
                + links + attachments) instead of the plain ``headers``
                dict. Used by rules that inspect the full message body.
            family: Recalibración de pesos -- techo de familia: agrupa
                reglas que corroboran el mismo hecho subyacente (p.ej. "auth",
                "identity") para que ``_aggregate_score`` limite la suma de
                penalizaciones de la familia y no cuente el mismo hecho varias
                veces. Cadena vacía = sin techo.
            is_body_dependent: ``True`` si la regla lee el cuerpo, los enlaces
                o los adjuntos del mensaje, es decir, si en un análisis de solo
                cabeceras no tiene nada que inspeccionar. Es lo que alimenta la
                cobertura del análisis (``services/quality.assess_coverage``).
                No equivale a ``needs_context``: varias reglas de contexto solo
                leen la cadena Received, que sí existe sin cuerpo. Por defecto
                ``False``.
            evidence_headers: Cabeceras (en minúsculas) donde vive la señal de
                la regla, en el orden en que se muestran. Si la regla penaliza
                sin aportar evidencia propia, se anclan las que existan. Por
                defecto vacío.
            is_self_anchoring: ``True`` si la regla construye su propia
                evidencia (qué enlace, qué adjunto, qué salto Received) en
                ``RuleResult.evidence``. Por defecto ``False``.
            unanchorable_reason: Motivo, en castellano y para el analista, por
                el que los hallazgos de la regla no se pueden anclar a un
                fragmento concreto. Por defecto vacío.

            rule_id: Identificador estable (``iris.<grupo>.<nombre>``). Es lo
                que usan el PDF, la API y las exportaciones para referirse al
                hallazgo; el nombre visible puede cambiar sin tocarlo.
                Obligatorio y único en el catálogo.
            severity: ``RuleSeverity`` del hallazgo, separada del score.
                Obligatoria.
            mitre_techniques: Técnicas MITRE ATT&CK (``T1566.002``) que
                corresponden al hallazgo, solo si encajan de verdad: la mayoría
                de heurísticas no son una técnica. Por defecto ninguna.

            Toda regla declara al menos una de ``evidence_headers``,
            ``is_self_anchoring`` o ``unanchorable_reason``: el catálogo no
            admite reglas cuyos hallazgos no digan dónde están ni por qué no.

        Returns:
            A decorator that appends the function to the internal rule list.

        Raises:
            ValueError: Si la regla no declara ni ``evidence_headers``, ni
                ``is_self_anchoring``, ni ``unanchorable_reason``; si su
                ``rule_id`` falta, no tiene la forma ``iris.<grupo>.<nombre>`` o
                ya existe; si la severidad no es una de ``RuleSeverity``; o si
                alguna técnica no tiene forma de técnica ATT&CK.
        """
        if not (evidence_headers or is_self_anchoring or unanchorable_reason):
            raise ValueError(
                f"La regla '{name}' debe declarar cómo ancla su evidencia: "
                "evidence_headers, is_self_anchoring o unanchorable_reason."
            )
        if not _RULE_ID_RE.match(rule_id or ""):
            raise ValueError(f"La regla '{name}' necesita un rule_id con forma iris.<grupo>.<nombre>.")
        if any(rule["rule_id"] == rule_id for rule in self._rules):
            raise ValueError(f"El rule_id '{rule_id}' ya está registrado.")
        if severity not in {member.value for member in RuleSeverity}:
            raise ValueError(f"La regla '{name}' tiene una severidad desconocida: {severity!r}.")
        techniques = tuple(mitre_techniques)
        invalid = [technique for technique in techniques if not _MITRE_TECHNIQUE_RE.match(technique)]
        if invalid:
            raise ValueError(f"La regla '{name}' declara técnicas ATT&CK no válidas: {invalid}.")
        header_names = tuple(evidence_headers)

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def anchored(rule_input: Any) -> RuleResult:
                return anchor_result(func(rule_input), rule_input, header_names,
                                     unanchorable_reason, name)

            self._rules.append({
                "func": anchored,
                "name": name,
                "category": category,
                "description": description,
                "needs_context": needs_context,
                "family": family,
                "is_body_dependent": is_body_dependent,
                "evidence_headers": header_names,
                "is_self_anchoring": is_self_anchoring,
                "unanchorable_reason": unanchorable_reason,
                "rule_id": rule_id,
                "severity": severity,
                "mitre_techniques": techniques,
            })
            return func
        return decorator

    def get_rules(self) -> List[Dict]:
        """Return a copy of all registered rule definitions."""
        return list(self._rules)

    def clear(self) -> None:
        """Remove all registered rules (used mainly in tests)."""
        self._rules.clear()


iris_rules = RuleRegistry()
