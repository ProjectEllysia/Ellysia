"""Qué checks de ``security_header`` debe disparar un servidor sin endurecer.

Los bancos necesitan saber qué es un acierto y qué es un falso positivo, y para
la familia de cabeceras esa lista estaba escrita a mano **dos veces**: una en
``test_lybra_precision_bench.py`` y otra en ``test_lybra_oracle_bench.py``, las
dos con los mismos tres identificadores. Cuando el feed creció de 28 a 55 checks
y aparecieron CSP, ``Referrer-Policy`` y ``Permissions-Policy``, ninguna
de las dos se enteró. Los tres checks nuevos son detecciones **correctas** —un
nginx recién sacado de la caja no manda ninguna de esas cabeceras— pero como el
catálogo no los listaba como esperados, se contaron como falsos positivos en los
diecisiete objetivos HTTP del banco y hundieron la precisión del banco a
0,557 frente a un umbral de 0,90. El banco nocturno llevaba tres noches en rojo
por eso.

La lección es la del repositorio de siempre: una lista que hay que acordarse de
actualizar a mano se desincroniza, y lo hace en silencio. Así que aquí no se
escribe la lista, **se deriva del feed** — la misma fuente de la que el motor
saca los checks que ejecuta, de modo que las dos no pueden divergir.

Lo único que se declara a mano es la excepción, y con su razón al lado: los
checks de la familia que **no** dispara todo servidor sin endurecer, porque
dependen de que la respuesta traiga algo que un ``return 200 "ok"`` no trae.

Not a test module itself (no ``test_`` prefix) — pytest does not collect it.
"""

from __future__ import annotations

from typing import Dict, Set

from src.modules.features.themis.lybra.checks import load_checks

HEADER_CATEGORY = "security_header"

# Los checks de la familia que dependen de algo que la respuesta puede traer o
# no, con el motivo por el que no valen como cabecera "que falta siempre".
#
# Clasificar mal uno de éstos falla en la dirección segura: pasaría a esperarse
# en todos los objetivos, no dispararía en ninguno, y saldría como falso
# negativo ruidoso en vez de inflar la precisión en silencio.
CONDITIONAL_HEADER_CHECKS: Dict[str, str] = {
    "lybra:session-cookie-without-secure@1":
        "necesita un Set-Cookie en la respuesta; los objetivos del catálogo "
        "sirven un 200 sin cookies, así que no hay cookie que juzgar",
}


def _check_id(check) -> str:
    """El identificador con el que un hallazgo nombra a su check."""
    return f"{check.namespace}:{check.id}@{check.version}"


def header_family_from_feed() -> Set[str]:
    """Todos los checks de ``security_header`` que declara el feed."""
    return {
        _check_id(check)
        for check in load_checks()
        if check.category == HEADER_CATEGORY
    }


def always_missing_header_checks() -> Set[str]:
    """Los que debe disparar cualquier servidor que no mande ninguna cabecera.

    Es la familia entera menos las excepciones declaradas arriba. Se deriva en
    cada llamada en vez de congelarse en una constante de módulo para que un
    test que parchee el feed vea lo que ha parcheado.
    """
    return header_family_from_feed() - set(CONDITIONAL_HEADER_CHECKS)
