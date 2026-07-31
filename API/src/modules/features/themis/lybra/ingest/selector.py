"""Selección de checks ingeridos antes de que el runtime los ejecute (Fase R).

**El problema que resuelve, en números.** ``CheckRuntime.run`` es
O(servicios × checks) y ejecuta *todo* check HTTP contra *todo* servicio HTTP.
Con los 16 checks del feed propio eso da igual. Con miles de plantillas
ingeridas no: el limitador de tasa impone un mínimo de 0,2 s por petición y
host, así que 3.000 checks contra un solo servicio son más de diez minutos de
tráfico contra el objetivo — y contra un host con cuatro puertos web, casi una
hora. Sin esta capa, activar la ingesta no sería una mejora, sería un disparo
en el pie.

**El criterio, en tres filtros de coste creciente.** Ninguno es sofisticado, y
eso es deliberado: un índice por CPE de verdad es trabajo mayor y el número de
la Fase U4 aún no dice si merece la pena. Lo que hay aquí es lo suficiente para
que activar la ingesta sea seguro.

1. **Severidad mínima.** Las plantillas ``info`` de Nuclei son miles de
   detecciones de tecnología; no aportan hallazgos accionables y sí todo el
   coste. Mismo criterio que ``get_nuclei_default_severities`` ya aplica al
   binario.
2. **Relevancia por etiqueta.** Un check etiquetado ``wordpress`` no se lanza
   contra un nginx. Un check *sin* etiquetas de producto reconocibles sí se
   lanza: es genérico (una ruta expuesta, una cabecera), y descartarlo por no
   declarar producto perdería justo los más aplicables.
3. **Tope duro.** La red de seguridad final, para que un fallo de los dos
   filtros anteriores no se traduzca en un escaneo de horas.

El filtro se aplica **antes** de construir el runtime, no dentro: así el feed
propio no paga nada por que exista esta capa.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Sequence

from ..checks import Check
from ..engine import Service

logger = logging.getLogger(__name__)

# Orden de severidad, de mayor a menor. El suelo por defecto excluye INFO por
# la misma razón que el perfil del binario lo hace.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
DEFAULT_MIN_SEVERITY = "MEDIUM"
DEFAULT_MAX_CHECKS = 300

# Etiquetas que no dicen nada sobre a qué producto aplica un check: describen la
# clase de vulnerabilidad o su procedencia, no el objetivo. Un check cuyas
# únicas etiquetas sean éstas cuenta como genérico, no como no-aplicable.
_NON_PRODUCT_TAGS = frozenset({
    "cve", "cves", "kev", "oast", "misconfig", "misconfiguration", "exposure",
    "exposures", "config", "files", "file", "disclosure", "panel", "tech",
    "detect", "detection", "default-login", "login", "auth", "unauth", "rce",
    "lfi", "rfi", "sqli", "xss", "ssrf", "xxe", "traversal", "redirect",
    "injection", "takeover", "generic", "http", "network", "tcp", "top-200",
    "top-100", "intrusive", "packetstorm", "edb", "seclists", "hackerone",
    "vulhub", "wordpress-core",
})


def _severity_rank(severity: str) -> int:
    """Posición de una severidad en la escala; las desconocidas van al fondo."""
    try:
        return _SEVERITY_ORDER.index((severity or "").upper())
    except ValueError:
        return len(_SEVERITY_ORDER)


def _service_vocabulary(services: Iterable[Service]) -> set:
    """Palabras que describen lo que hay corriendo en el objetivo.

    Sale del nombre y el producto de cada servicio identificado, troceado en
    palabras y en minúsculas: un ``Service(product="Apache httpd")`` aporta
    ``{"apache", "httpd"}``. Es contra este vocabulario contra el que se mide la
    relevancia de una etiqueta.
    """
    vocabulary = set()
    for service in services:
        for field in (service.name, service.product):
            for word in str(field or "").replace("-", " ").replace("_", " ").split():
                cleaned = word.strip().lower()
                if len(cleaned) > 2:
                    vocabulary.add(cleaned)
    return vocabulary


def _product_tags(check: Check) -> set:
    """Las etiquetas del check que sí nombran un producto o tecnología."""
    return {tag for tag in check.tags if tag not in _NON_PRODUCT_TAGS}


def is_relevant(check: Check, vocabulary: set) -> bool:
    """Decide si un check ingerido merece lanzarse contra los servicios vistos.

    Args:
        check: El check traducido.
        vocabulary: Las palabras que describen el objetivo
            (:func:`_service_vocabulary`).

    Returns:
        ``True`` si el check es genérico (no nombra producto alguno) o si algún
        producto que nombra aparece en el objetivo. Un check que nombra
        productos y ninguno coincide se descarta — es el grueso del ahorro.
    """
    product_tags = _product_tags(check)
    if not product_tags:
        return True
    return any(
        tag in vocabulary or any(tag in word or word in tag for word in vocabulary)
        for tag in product_tags
    )


def select_for_services(
    checks: Sequence[Check],
    services: Iterable[Service],
    min_severity: str = DEFAULT_MIN_SEVERITY,
    max_checks: int = DEFAULT_MAX_CHECKS,
) -> List[Check]:
    """Reduce un feed ingerido a los checks que vale la pena ejecutar.

    Args:
        checks: Los checks ingeridos (los del feed propio no pasan por aquí).
        services: Los servicios descubiertos en el objetivo.
        min_severity: Severidad mínima a conservar.
        max_checks: Tope duro de checks devueltos.

    Returns:
        El subconjunto seleccionado, ordenado por severidad descendente para
        que, si el tope recorta, lo que se pierda sea lo menos grave.
    """
    service_list = list(services)
    vocabulary = _service_vocabulary(service_list)
    severity_floor = _severity_rank(min_severity)

    relevant = [
        check for check in checks
        if _severity_rank(check.severity) <= severity_floor and is_relevant(check, vocabulary)
    ]
    relevant.sort(key=lambda check: (_severity_rank(check.severity), check.id))

    if len(relevant) > max_checks:
        logger.info(
            "Selección de checks ingeridos recortada por el tope: %d de %d "
            "(sube themis.lybra.ingest.maxChecks si de verdad hace falta)",
            max_checks, len(relevant),
        )
        relevant = relevant[:max_checks]

    logger.info(
        "Checks ingeridos seleccionados: %d de %d para %d servicio(s)",
        len(relevant), len(checks), len(service_list),
    )
    return relevant
