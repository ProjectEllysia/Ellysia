"""
taskqueue/deadline.py
─────────────────────
El plazo de un job: la excepción que lo anuncia y la penalización que la lanza.

Vive en su propio módulo y no dentro de ``worker.py`` porque quien necesita
**capturar** el plazo no es el worker sino el código de negocio: un manager que
escribe el estado de su trabajo en la base de datos es el único que sabe qué
fila hay que cerrar cuando la cola lo mata. Importar ``worker.py`` para eso
arrastraría sus efectos de módulo (registra la clase de penalización global de
RQ) en procesos que no son el worker.
"""

from __future__ import annotations

from rq.timeouts import TimerDeathPenalty


class JobDeadlineExceeded(BaseException):
    """El plazo de un job se agotó y RQ está terminándolo.

    Hereda de ``BaseException``, **no** de ``Exception``, y esa es toda su
    razón de ser.

    RQ interrumpe un job que se pasa de tiempo lanzándole una excepción desde
    fuera. La suya, ``rq.timeouts.JobTimeoutException``, hereda de
    ``Exception``, así que es indistinguible de un error corriente para
    cualquier ``except Exception``. Y el código de negocio está lleno de ellos
    por buenas razones: un escaneo no debe hundirse porque un objetivo cierre
    la conexión. El resultado era que la sentencia de muerte se registraba
    como «fallo de red», el job seguía corriendo —el temporizador dispara una
    sola vez, así que a partir de ahí ya no tiene ningún límite— y al terminar
    RQ escribía ``Successfully completed`` sobre un trabajo que había
    sobrepasado su plazo.

    Cambiar la clase de excepción lo arregla en los diez módulos a la vez y
    sin tocar ninguno, que es la razón de hacerlo aquí y no persiguiendo
    ``except`` uno a uno. Es seguro porque el manejador de RQ en
    ``Worker.perform_job`` es un ``except:`` pelado, sin tipo: sigue
    capturándola y marcando el job como fallido exactamente igual que antes.

    Quien quiera reaccionar a su propio plazo la captura **explícitamente** y
    la vuelve a lanzar: cerrar la fila del trabajo en la base de datos es
    legítimo, tragarse la sentencia de muerte no.
    """


class _UnswallowableTimerDeathPenalty(TimerDeathPenalty):
    """``TimerDeathPenalty`` que lanza :class:`JobDeadlineExceeded`.

    RQ codifica ``JobTimeoutException`` en la llamada de ``perform_job`` que
    construye la penalización, así que la sustitución tiene que hacerse aquí,
    ignorando la excepción que nos pasan.

    **Una subclase por penalización, y no la clase compartida.**
    ``TimerDeathPenalty.__init__`` parchea el ``__init__`` de la excepción que
    recibe para incrustarle el mensaje del plazo, porque la llamada del
    intérprete que inyecta una excepción en otro hilo
    (``PyThreadState_SetAsyncExc``) sólo admite una *clase*, no una instancia.
    Ese parche es global a la clase: con una sola compartida, el último job que
    construía su penalización le pisaba el mensaje a todos los demás del
    proceso. Es lo que se vio el 2026-09-05, cuando tres escaneos con plazo de
    10 030 s murieron diciendo «Task exceeded maximum timeout value (60
    seconds)» — un número que venía de otro job cualquiera del mismo worker, y
    que mandó el diagnóstico en la dirección equivocada.

    Acuñar una subclase por instancia le da a cada plazo su propio mensaje sin
    tocar nada más: ``except JobDeadlineExceeded`` sigue capturándolas todas, y
    el traceback sigue leyéndose igual porque la subclase conserva el nombre.
    """

    def __init__(self, timeout, exception=None, **kwargs):  # pylint: disable=unused-argument
        super().__init__(timeout, type("JobDeadlineExceeded", (JobDeadlineExceeded,), {}), **kwargs)
