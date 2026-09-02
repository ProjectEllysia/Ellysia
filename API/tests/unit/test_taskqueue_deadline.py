"""El plazo de un job no se puede tragar con un ``except Exception``.

RQ interrumpe un job que se pasa de tiempo lanzándole una excepción desde
fuera. La suya hereda de ``Exception``, así que cualquiera de los muchos
``except Exception`` del código de negocio —que existen por buenas razones: un
escaneo no debe hundirse porque un objetivo cierre la conexión— la capturaba y
la registraba como si fuera un error corriente. El job seguía corriendo sin
límite (el temporizador dispara una sola vez) y al terminar RQ escribía
``Successfully completed`` sobre un trabajo que había sobrepasado su plazo.

Es lo que se vio en producción el 2026-09-02: un plazo de 60 segundos, un
``Lybra port discovery failed`` en el log, y el mismo job declarado exitoso
tras 2 min 39 s.

Estos tests fijan el arreglo: la excepción de plazo deriva de
``BaseException``, y la penalización del worker la usa en lugar de la de RQ.
"""

from __future__ import annotations

import time

import pytest
from rq.timeouts import JobTimeoutException

from src.modules.system.taskqueue.worker import (
    JobDeadlineExceeded,
    _UnswallowableTimerDeathPenalty,
)

pytestmark = pytest.mark.unit


def test_the_deadline_exception_is_not_an_ordinary_exception():
    """La invariante entera del arreglo, en una línea.

    Si algún día alguien la hace heredar de ``Exception`` "para que sea como
    las demás", el fallo de producción vuelve entero y en silencio.
    """
    assert issubclass(JobDeadlineExceeded, BaseException)
    assert not issubclass(JobDeadlineExceeded, Exception)


def test_the_penalty_substitutes_rqs_own_exception():
    """RQ codifica ``JobTimeoutException`` en la llamada que construye la
    penalización, así que la sustitución tiene que ignorar lo que nos pasan."""
    penalty = _UnswallowableTimerDeathPenalty(30, JobTimeoutException, job_id="x")
    assert penalty._exception is JobDeadlineExceeded  # pylint: disable=protected-access


def test_a_broad_except_does_not_swallow_the_deadline():
    """El caso real: trabajo con ``except Exception`` dentro del plazo.

    El bucle es Python puro a propósito. ``TimerDeathPenalty`` inyecta la
    excepción con ``PyThreadState_SetAsyncExc``, que sólo se materializa
    cuando el hilo vuelve a ejecutar bytecode; en producción el hilo estaba
    parado dentro de una llamada al sistema y por eso un plazo de 60 s
    apareció a los 159. Aquí interesa comprobar quién la captura, no cuándo
    llega, así que se le da bytecode que ejecutar.
    """
    swallowed = []
    deadline_escaped = False

    try:
        with _UnswallowableTimerDeathPenalty(0.1, JobTimeoutException, job_id="x"):
            limit = time.monotonic() + 5
            while time.monotonic() < limit:
                try:
                    for _ in range(1000):
                        pass
                except Exception as e:  # pylint: disable=broad-except
                    # El manejador que se comía la sentencia de muerte.
                    swallowed.append(e)
    except JobDeadlineExceeded:
        deadline_escaped = True

    assert deadline_escaped, "el plazo no llegó a escapar del trabajo"
    assert not swallowed, f"un except Exception capturó el plazo: {swallowed}"
