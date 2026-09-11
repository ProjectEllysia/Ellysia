"""
Política de puntuación de Iris, versionada.

El score de un análisis depende de más cosas que las reglas: del techo del que
parte, de los suelos que acotan cada familia, de los umbrales que lo convierten
en veredicto, del perfil de sensibilidad y de los pesos que la configuración
sobreescribe. Todo eso cambiaba con la configuración **sin dejar rastro**, y
un análisis de hace tres meses no decía con qué reglas del juego se decidió.

``ScoringPolicy`` reúne esas piezas en un único objeto que:

- puntúa y decide (``aggregate`` y ``verdict_for``);
- se guarda con cada análisis como *snapshot* (``snapshot``) y se identifica
  con una marca estable (``version``);
- se puede reconstruir desde un snapshot guardado (``from_snapshot``), que es
  lo que permite preguntar "¿qué habría decidido Iris con la versión
  anterior?" y volver a ella.

Los pesos por defecto de cada regla viven en su propio código; lo que la
política recoge son los que ``features.iris.scoring`` sobreescribe. Por eso el
snapshot incluye también ``appVersion``: dos snapshots iguales de despliegues
distintos pueden seguir difiriendo en esos defaults.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Mapping

import src.modules.system.config_reading as CR

from .wordlists import datasets_fingerprint

logger = logging.getLogger(__name__)

#: Modelo sustractivo: un análisis parte de este techo y las reglas solo
#: restan. Una regla superada no aporta nada; una fallida resta su score.
CEILING = 100.0

#: Suelo de cada familia: el mínimo (más negativo) que puede sumar el conjunto
#: de penalizaciones de sus reglas. Varias reglas de una familia suelen
#: corroborar el mismo hecho (SPF, DKIM, DMARC y alineación describen **un**
#: fallo de autenticación), y sin suelo ese hecho pesaría varias veces. Las
#: reglas sin familia no tienen suelo porque ya son pequeñas individualmente.
FAMILY_SCORE_FLOORS = {
    "auth": -25.0,
    "identity": -28.0,
    "reply_path": -15.0,
    "content": -25.0,
    "links": -30.0,
    "received": -12.0,
    "attachment": -28.0,
}

PROFILE_STRICT = "strict"
PROFILE_BALANCED = "balanced"
PROFILE_LENIENT = "lenient"

#: Cuántos puntos desplaza cada perfil los dos umbrales configurados.
#: ``strict`` los sube (hace falta un score más alto para salir limpio, así que
#: avisa antes); ``lenient`` los baja. ``balanced`` usa los configurados tal cual.
PROFILE_THRESHOLD_OFFSETS = {
    PROFILE_STRICT: 5.0,
    PROFILE_BALANCED: 0.0,
    PROFILE_LENIENT: -5.0,
}

#: Versión del formato del snapshot; cambia si cambian sus claves.
SNAPSHOT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ScoringPolicy:
    """Reglas del juego con las que se puntúa y se decide un análisis.

    Attributes:
        profile: Perfil de sensibilidad (``strict``, ``balanced`` o
            ``lenient``).
        legitimate_threshold: Score (0–100) a partir del cual el veredicto es
            ``Legitimate``, ya con el desplazamiento del perfil aplicado.
        suspicious_threshold: Score a partir del cual es ``Suspicious``; por
            debajo, ``Phishing``. También con el perfil aplicado.
        ceiling: Techo del modelo sustractivo. Por defecto ``CEILING``.
        family_floors: Suelo de penalización por familia. Por defecto
            ``FAMILY_SCORE_FLOORS``.
        weight_overrides: Pesos de regla que sustituyen a los del código
            (``features.iris.scoring``); clave ``<regla>.<señal>``. Por
            defecto vacío: todas las reglas usan sus pesos de código.
        datasets_fingerprint: Huella de los datasets de detección (marcas,
            dominios, keywords…) con que se evaluó. Por defecto vacía.
        app_version: Versión de la aplicación que evaluó, que fija los pesos
            por defecto del código. Por defecto vacía.
    """

    profile: str
    legitimate_threshold: float
    suspicious_threshold: float
    ceiling: float = CEILING
    family_floors: Mapping[str, float] = field(default_factory=lambda: dict(FAMILY_SCORE_FLOORS))
    weight_overrides: Mapping[str, float] = field(default_factory=dict)
    datasets_fingerprint: str = ""
    app_version: str = ""

    def aggregate(self, rules_defs: List[dict], results: List[Any]) -> float:
        """Combina los resultados de regla en un score de 0 a ``ceiling``.

        Solo cuenta la parte negativa de cada regla; la suma de cada familia
        se acota a su suelo antes de restarla del techo.

        Args:
            rules_defs: Catálogo evaluado (se usa ``family`` de cada regla).
            results: Un ``RuleResult`` por regla, emparejado por posición.

        Returns:
            float: El score, acotado a ``[0, ceiling]``.
        """
        family_penalties: Dict[str, float] = {}
        unfamilied_penalties = 0.0
        for rule_def, result in zip(rules_defs, results):
            penalty = min(0.0, float(result.score))
            family = rule_def.get("family") or ""
            if family:
                family_penalties[family] = family_penalties.get(family, 0.0) + penalty
            else:
                unfamilied_penalties += penalty

        capped_total = unfamilied_penalties
        for family, penalty in family_penalties.items():
            floor = self.family_floors.get(family)
            capped_total += max(floor, penalty) if floor is not None else penalty

        return max(0.0, self.ceiling + capped_total)

    def verdict_for(self, total_score: float) -> str:
        """Traduce un score a veredicto con los umbrales de la política.

        Es solo la base numérica: los gates de alta confianza pueden empeorar
        el veredicto después, nunca mejorarlo.

        Args:
            total_score: Score de 0 a ``ceiling``.

        Returns:
            str: ``Legitimate``, ``Suspicious`` o ``Phishing``.
        """
        if total_score >= self.legitimate_threshold:
            return "Legitimate"
        if total_score >= self.suspicious_threshold:
            return "Suspicious"
        return "Phishing"

    def snapshot(self, detector: str) -> Dict[str, Any]:
        """Todo lo que decide un veredicto, en un dict serializable a JSONB.

        Args:
            detector: Marca del catálogo de reglas (``detector_version``).

        Returns:
            dict: Perfil, umbrales, techo, suelos por familia, pesos
                sobreescritos, huella de datasets, versión de la aplicación,
                catálogo y versión del formato.
        """
        return {
            "schemaVersion": SNAPSHOT_SCHEMA_VERSION,
            "profile": self.profile,
            "legitimateThreshold": self.legitimate_threshold,
            "suspiciousThreshold": self.suspicious_threshold,
            "ceiling": self.ceiling,
            "familyFloors": dict(sorted(self.family_floors.items())),
            "weightOverrides": dict(sorted(self.weight_overrides.items())),
            "datasetsFingerprint": self.datasets_fingerprint,
            "appVersion": self.app_version,
            "detectorVersion": detector,
        }

    def version(self, detector: str) -> str:
        """Marca estable de la política junto con el catálogo que la aplicó.

        Dos análisis con la misma marca se decidieron con las mismas reglas
        del juego; cualquier cambio en umbrales, perfil, suelos, pesos,
        datasets, catálogo o versión de la aplicación la cambia.

        Args:
            detector: Marca del catálogo de reglas (``detector_version``).

        Returns:
            str: ``iris-scoring:<12 hexadecimales>`` (cabe en 64 caracteres).
        """
        material = json.dumps(self.snapshot(detector), sort_keys=True)
        return "iris-scoring:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> "ScoringPolicy":
        """Reconstruye la política con la que se decidió un análisis guardado.

        Args:
            snapshot: ``IrisAnalysis.scoring_snapshot`` (ver ``snapshot``).

        Returns:
            ScoringPolicy: La misma política. Los pesos por defecto del código
                son los del despliegue actual, no los de ``appVersion``.
        """
        return cls(
            profile=snapshot["profile"],
            legitimate_threshold=float(snapshot["legitimateThreshold"]),
            suspicious_threshold=float(snapshot["suspiciousThreshold"]),
            ceiling=float(snapshot.get("ceiling", CEILING)),
            family_floors={family: float(floor) for family, floor in (snapshot.get("familyFloors") or {}).items()},
            weight_overrides={key: float(value) for key, value in (snapshot.get("weightOverrides") or {}).items()},
            datasets_fingerprint=snapshot.get("datasetsFingerprint", ""),
            app_version=snapshot.get("appVersion", ""),
        )

    def with_profile(self, profile: str) -> "ScoringPolicy":
        """Misma política con otro perfil de sensibilidad.

        Los umbrales se recalculan desde los de ``balanced`` para que cambiar
        de perfil dos veces no acumule desplazamientos.

        Args:
            profile: ``strict``, ``balanced`` o ``lenient``.

        Returns:
            ScoringPolicy: Copia con el perfil y los umbrales nuevos.

        Raises:
            ValueError: Si el perfil no existe.
        """
        if profile not in PROFILE_THRESHOLD_OFFSETS:
            raise ValueError(f"Perfil de sensibilidad desconocido: {profile!r}.")
        base_offset = PROFILE_THRESHOLD_OFFSETS[self.profile]
        offset = PROFILE_THRESHOLD_OFFSETS[profile]
        return replace(
            self, profile=profile,
            legitimate_threshold=self.legitimate_threshold - base_offset + offset,
            suspicious_threshold=self.suspicious_threshold - base_offset + offset,
        )

    def with_weight_overrides(self, weight_overrides: Mapping[str, float]) -> "ScoringPolicy":
        """Misma política con otros pesos de regla (un candidato de recalibración).

        Args:
            weight_overrides: Mapa ``<regla>.<señal>`` → peso que **sustituye**
                al de la política actual.

        Returns:
            ScoringPolicy: Copia con esos pesos.
        """
        return replace(self, weight_overrides=dict(weight_overrides))


def policy_for_profile(profile: str, base_legitimate_threshold: float,
                       base_suspicious_threshold: float, **extra: Any) -> ScoringPolicy:
    """Construye una política aplicando el desplazamiento de un perfil.

    Args:
        profile: ``strict``, ``balanced`` o ``lenient``; uno desconocido se
            trata como ``balanced`` y se avisa en el log, para que un error
            tipográfico en la configuración no tumbe los análisis.
        base_legitimate_threshold: Umbral de ``Legitimate`` configurado.
        base_suspicious_threshold: Umbral de ``Suspicious`` configurado.
        **extra: Resto de campos de ``ScoringPolicy`` (pesos, huella…).

    Returns:
        ScoringPolicy: La política con los umbrales desplazados.
    """
    if profile not in PROFILE_THRESHOLD_OFFSETS:
        logger.warning("Perfil de sensibilidad de Iris desconocido %r; se usa 'balanced'", profile)
        profile = PROFILE_BALANCED
    offset = PROFILE_THRESHOLD_OFFSETS[profile]
    return ScoringPolicy(
        profile=profile,
        legitimate_threshold=float(base_legitimate_threshold) + offset,
        suspicious_threshold=float(base_suspicious_threshold) + offset,
        **extra,
    )


def current_policy() -> ScoringPolicy:
    """La política que rige ahora mismo, leída de la configuración.

    Se lee en cada llamada (no se hornea al importar) para que un cambio vía
    ``PUT /system`` o una edición del fichero que el worker recarga surta
    efecto en el siguiente análisis.

    Returns:
        ScoringPolicy: Perfil ``features.iris.sensitivityProfile`` aplicado a
            los umbrales configurados, con los pesos de
            ``features.iris.scoring``, la huella de datasets y la versión.
    """
    config = CR.iris_config()
    return policy_for_profile(
        config.sensitivity_profile, config.legitimate_threshold, config.suspicious_threshold,
        weight_overrides=CR.get_iris_scoring_overrides(),
        datasets_fingerprint=datasets_fingerprint(),
        app_version=str(CR.get_app_version()),
    )
