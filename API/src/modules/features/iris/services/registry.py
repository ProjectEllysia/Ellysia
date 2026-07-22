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

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


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
    """
    score: float
    verdict: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None


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
        # global state regardless, making test order matter (C6).
        self._rules: List[Dict] = []

    def register(self, name: str, category: str = "general",
                 description: str = "", needs_context: bool = False):
        """Decorator that registers a function as an analysis rule.

        Args:
            name: Human-readable rule name (e.g. "SPF", "DKIM").
            category: Grouping category (e.g. "authentication", "header_analysis").
            description: Detailed explanation of what the rule checks.
            needs_context: If True, the rule receives a
                ``services.parsers.MessageContext`` (headers + body
                + links + attachments) instead of the plain ``headers``
                dict. Used by rules that inspect the full message body.

        Returns:
            A decorator that appends the function to the internal rule list.
        """
        def decorator(func: Callable) -> Callable:
            self._rules.append({
                "func": func,
                "name": name,
                "category": category,
                "description": description,
                "needs_context": needs_context,
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
