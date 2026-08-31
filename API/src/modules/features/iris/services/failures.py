"""
Clasificación de fallos terminales de un análisis de Iris.

Un análisis puede morir por dos motivos muy distintos, y confundirlos hace
inútil el estado terminal: o el usuario mandó algo que no es un correo
analizable (culpa suya, accionable), o el pipeline se rompió por dentro
(culpa nuestra, no accionable por el usuario). ``classify_failure`` traduce
la excepción que aborta ``IrisManager._run_analysis`` en ese par
``(código, razón)``.

La razón es **texto técnico no sensible**: nunca el ``raw_input`` ni ningún
fragmento del correo. El motivo es que se persiste en ``IrisAnalysis`` y se
devuelve por API a quien consulte el estado, mientras que el cuerpo del
mensaje analizado puede contener datos personales o credenciales — el propio
informe ya lo trata como material sensible (ver la nota de consentimiento del
PDF en ``services/reports.py``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..exceptions import IrisInvalidInputError


#: El usuario mandó algo que no es un correo analizable.
FAILURE_INVALID_INPUT = "invalid_input"

#: El pipeline se rompió por dentro (parser, regla, persistencia).
FAILURE_INTERNAL_ERROR = "internal_error"

# Tope del mensaje persistido: `failure_reason` es una columna Text, pero un
# traceback repr-eado de una librería de terceros puede ser enorme y no aporta
# nada más allá de la primera línea.
_MAX_REASON_LENGTH = 500

_INTERNAL_REASON = (
    "El análisis falló por un error interno del motor. El equipo puede "
    "consultar el detalle en los registros del servidor."
)


@dataclass(frozen=True)
class AnalysisFailure:
    """Motivo terminal de un análisis fallido, listo para persistir.

    Attributes:
        code: ``invalid_input`` o ``internal_error``.
        reason: Mensaje legible y no sensible, apto para devolver por API.
    """

    code: str
    reason: str


def classify_failure(error: BaseException) -> AnalysisFailure:
    """Traduce la excepción que abortó un análisis en un motivo persistible.

    ``IrisInvalidInputError`` es la única excepción cuyo mensaje se propaga
    tal cual: lo construye este módulo a partir de un recuento de cabeceras,
    nunca del contenido del correo. Cualquier otra excepción —incluido un
    parser roto, que es el caso que motiva `B03`— se colapsa en un mensaje
    genérico: el ``str(error)`` de una librería de terceros puede arrastrar
    el fragmento de entrada que la hizo reventar.
    """
    if isinstance(error, IrisInvalidInputError):
        return AnalysisFailure(
            code=FAILURE_INVALID_INPUT,
            reason=str(error)[:_MAX_REASON_LENGTH],
        )
    return AnalysisFailure(code=FAILURE_INTERNAL_ERROR, reason=_INTERNAL_REASON)
