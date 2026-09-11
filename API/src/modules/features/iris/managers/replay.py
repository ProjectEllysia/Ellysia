"""
IrisReplayManager — simulador de reglas para administradores.

Antes de desplegar un cambio de umbrales, perfil o pesos hay que saber si
mejora o degrada el detector. El simulador ejecuta el corpus versionado (y,
si el administrador los pega, mensajes sueltos) con la política vigente y con
una candidata, y devuelve qué veredictos y gates cambian y las métricas de
falsos positivos y negativos de cada una.

Nada de lo que se evalúa aquí se guarda: los mensajes pegados no crean
análisis, no cobran cuota y no quedan en la base de datos. Tampoco se lee el
correo de ningún usuario: el simulador solo ve el corpus y lo que el propio
administrador aporta en la petición.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional

import src.modules.system.config_reading as CR

from ..exceptions import IrisInvalidInputError
from ..services.parsers import parse_raw_message
from ..services.quality import detector_version
from ..services.replay import CORPUS_DIRECTORY, ReplaySample, load_corpus, replay
from ..services.rules import iris_rules
from ..services.scoring import ScoringPolicy, current_policy
from .analysis import IrisManager

#: Mensajes sueltos que se admiten por petición, además del corpus.
MAX_AD_HOC_MESSAGES = 20


def _invalid_input(text: str) -> IrisInvalidInputError:
    """Error de entrada cuyo texto llega tal cual al administrador.

    Sin ``user_message`` explícito, ``EllysiaException`` pone uno genérico por
    código de error, y el administrador no sabría qué mensaje o qué umbral
    rechazó el simulador.

    Args:
        text: Explicación en castellano, lista para ``error_description``.

    Returns:
        IrisInvalidInputError: La excepción, sin lanzar.
    """
    return IrisInvalidInputError(text, user_message=text)


def _ad_hoc_samples(messages: List[Mapping[str, Any]]) -> List[ReplaySample]:
    """Valida los mensajes pegados por el administrador y los prepara.

    Args:
        messages: Lista de ``{raw, label}``; ``label`` es opcional.

    Returns:
        List[ReplaySample]: Una muestra por mensaje, ``mensaje-1``,
            ``mensaje-2``…

    Raises:
        IrisInvalidInputError: Si hay demasiados mensajes, alguno supera el
            tamaño máximo o no es un correo analizable; el mensaje dice cuál.
    """
    if len(messages) > MAX_AD_HOC_MESSAGES:
        raise _invalid_input(f"Como mucho {MAX_AD_HOC_MESSAGES} mensajes por simulación.")
    max_bytes = CR.iris_config().max_message_bytes
    samples = []
    for index, message in enumerate(messages, start=1):
        raw = message["raw"]
        if len(raw.encode("utf-8")) > max_bytes:
            raise _invalid_input(f"El mensaje {index} supera el tamaño máximo ({max_bytes} bytes).")
        try:
            IrisManager._validate_headers_pre(raw)  # pylint: disable=protected-access
            IrisManager._validate_headers_parsed(parse_raw_message(raw).headers)  # pylint: disable=protected-access
        except IrisInvalidInputError as e:
            raise _invalid_input(f"El mensaje {index} no es un correo analizable: {e}") from e
        samples.append(ReplaySample(f"mensaje-{index}", raw, message.get("label")))
    return samples


class IrisReplayManager:
    """Compara la política vigente (o una dada) con una candidata."""

    @staticmethod
    def build_policy(spec: Optional[Mapping[str, Any]]) -> ScoringPolicy:
        """Construye una política a partir de su descripción en la petición.

        Args:
            spec: ``None`` o vacío para la vigente. Si trae ``snapshot``, se
                reconstruye esa política guardada (p. ej. el snapshot de un
                análisis antiguo, para comparar contra la versión con que se
                decidió). Si no, se parte de la vigente y se aplican, en este
                orden, ``profile``, ``legitimateThreshold``,
                ``suspiciousThreshold`` y ``weightOverrides`` (que se **suman**
                a los pesos vigentes, no los sustituyen).

        Returns:
            ScoringPolicy: La política descrita.

        Raises:
            IrisInvalidInputError: Si el snapshot está incompleto o si el
                umbral de ``Suspicious`` queda por encima del de ``Legitimate``.
        """
        if not spec:
            return current_policy()

        if spec.get("snapshot"):
            try:
                policy = ScoringPolicy.from_snapshot(spec["snapshot"])
            except (KeyError, TypeError, ValueError) as e:
                raise _invalid_input(f"El snapshot de puntuación está incompleto: {e}") from e
        else:
            policy = current_policy()
            if spec.get("profile"):
                policy = policy.with_profile(spec["profile"])
            if spec.get("legitimateThreshold") is not None:
                policy = replace(policy, legitimate_threshold=float(spec["legitimateThreshold"]))
            if spec.get("suspiciousThreshold") is not None:
                policy = replace(policy, suspicious_threshold=float(spec["suspiciousThreshold"]))
            if spec.get("weightOverrides"):
                policy = policy.with_weight_overrides({**policy.weight_overrides, **spec["weightOverrides"]})

        if policy.suspicious_threshold > policy.legitimate_threshold:
            raise _invalid_input(
                "El umbral de Sospechoso no puede quedar por encima del de Legítimo."
            )
        return policy

    def run(self, candidate_spec: Mapping[str, Any], baseline_spec: Optional[Mapping[str, Any]] = None,
            messages: Optional[List[Mapping[str, Any]]] = None, include_corpus: bool = True) -> Dict[str, Any]:
        """Ejecuta la simulación y devuelve el informe de replay.

        Args:
            candidate_spec: Descripción de la política candidata (ver
                ``build_policy``).
            baseline_spec: Descripción de la referencia. Por defecto
                ``None``: la política vigente.
            messages: Mensajes sueltos a comparar además del corpus. Por
                defecto ``None``: ninguno.
            include_corpus: Si se evalúa el corpus versionado. Por defecto
                ``True``.

        Returns:
            dict: El informe de ``services/replay.replay`` con las políticas
                ``baseline`` y ``candidate``, más ``corpusVersion`` (``None``
                si no se incluyó el corpus) y ``detectorVersion``.

        Raises:
            IrisInvalidInputError: Si no hay nada que comparar, o si alguna
                política o mensaje no es válido.
        """
        corpus_version = None
        samples: List[ReplaySample] = []
        if include_corpus:
            corpus_version, samples = load_corpus(CORPUS_DIRECTORY)
        samples += _ad_hoc_samples(list(messages or []))
        if not samples:
            raise _invalid_input("No hay nada que comparar: incluye el corpus o añade algún mensaje.")

        rules_defs = iris_rules.get_rules()
        family_of = {rule_def["name"]: rule_def.get("family") or "" for rule_def in rules_defs}
        detector = detector_version(rules_defs)
        policies = {
            "baseline": self.build_policy(baseline_spec),
            "candidate": self.build_policy(candidate_spec),
        }

        report = replay(samples, policies, IrisManager.evaluate_raw, family_of, detector)
        report["corpusVersion"] = corpus_version
        report["detectorVersion"] = detector
        return report
