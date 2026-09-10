"""
Outbox transaccional para TaskQueue (B08) -- modelo y (de)serialización.

**El problema**: varios managers seguían el patrón "crear entidad → confirmar
en BD → encolar en Redis" con el ``submit()`` fuera de la transacción de la
entidad. Entre esos dos pasos hay una ventana real: si la API se reinicia o
Redis falla justo ahí, la fila queda en BD en estado ``pending`` sin ningún
trabajo que la vaya a procesar nunca -- y nada lo nota hasta que alguien mira
esa fila y se pregunta por qué no avanza. La caída de B04 (Fase 0) atendía la
mitad de esto -- reconciliar un job que sí se encoló pero cuyo estado quedó
inconsistente --, no la mitad en la que el ``submit()`` nunca llegó a pasar.

**La solución**: ``TaskDispatch`` es la intención de publicar, persistida en
la MISMA transacción que la entidad que la origina (mismo commit, o ninguno
de los dos). ``OutboxDispatcher`` (``dispatcher.py``) la publica después:

    with UnitOfWork() as uow:
        EntityRepository(uow).save(entity)
        dispatch = TaskDispatchRepository(uow).save(build_dispatch(
            func=MyManager.execute_something,
            name=f"MyThing-{entity.id}",
            category="mymodule.something",
            args=(entity.id,),
        ))
        uow.commit_for_handoff()

    OutboxDispatcher.dispatch(dispatch.id, task_queue=self._task_queue)

La llamada a ``dispatch()`` de después del ``with`` es el camino feliz: en el
caso normal (Redis arriba) publica al instante, así que el trabajo arranca
sin esperar a nada. Si falla -- Redis caído en ese momento concreto -- la
fila se queda ``pending`` y la recoge más tarde el barrido periódico
(``TaskDispatchScheduler``, en ``scheduling.py``) o la reconciliación de
arranque, sin que el llamante tenga que hacer nada más.

**Por qué esto es "al menos una vez", no "exactamente una vez".** Publicar es
idempotente por construcción -- ``TaskQueue.submit()`` usa ``name`` como
job_id determinista de RQ, así que reencolar una fila que en realidad ya se
publicó no crea un segundo job mientras el primero siga en cola o corriendo
(RQ lo detecta y lo rechaza o lo sustituye, según el caso). Queda una rendija
angosta de verdad: si el proceso muere en el instante exacto entre que
``submit()`` devuelve con éxito y que esta fila se marca ``dispatched``, un
barrido posterior encontraría el job ya **terminado** y lo repetiría. Los
consumidores de esta primera aplicación (``IrisManager.execute_iris_analysis``)
recalculan y sobrescriben por ``analysis_id`` en vez de crear filas nuevas,
así que una repetición ahí es trabajo de más, no un dato duplicado -- pero
quien añada un nuevo consumidor de outbox debe poder decir lo mismo del suyo.

**Dónde se aplica.** Donde una fila confirmada antes de encolar puede quedarse
huérfana o, peor, ser el guardia que impide volver a intentarlo: los escaneos
de Themis, las campañas y píldoras de Aegis, el análisis de Iris y los avisos
con guardia anti-duplicado de Iris y Hygeia. Los sitios que siguen llamando a
``submit()`` directamente explican por qué junto a esa llamada.

**Por qué el dispatcher vive en un fichero aparte** (``dispatcher.py``): este
módulo es la base (modelo + (de)serialización) que ``outbox_repository.py``
importa; el dispatcher necesita el repositorio para leer/actualizar filas, así
que si viviera aquí este módulo tendría que importar de vuelta
``outbox_repository.py`` -- un ciclo real entre los dos ficheros, no solo un
rodeo de import diferido.
"""

from __future__ import annotations

import importlib
from typing import Any, Callable, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from src.modules.shared import Base, utcnow_naive


class TaskDispatch(Base):
    """Intención de publicar un job en TaskQueue, persistida antes de que exista.

    Attributes:
        id: Primary key, auto-incrementing integer.
        func_path: Referencia importable al callable a ejecutar
                 (``"modulo.paquete:Clase.metodo"``, ver ``encode_func``/
                 ``decode_func``) -- JSON no sabe serializar funciones, así
                 que se guarda como texto y se reconstruye al publicar.
        name: Id determinista del job en RQ (mismo valor que ``name=`` en
                 ``TaskQueue.submit()``) -- es lo que hace idempotente un
                 reintento de publicación.
        category: Categoría de cola registrada en ``QueueRegistry``.
        args / kwargs: Argumentos posicionales/nombrados para ``func``, tal
                 cual se le pasarían a ``TaskQueue.submit()``. Deben ser
                 JSON-serializables (ids, texto, listas/dicts simples) --
                 nunca objetos ORM ni closures.
        external_id: Id lógico de dominio, igual que en ``submit()``.
        timeout: Timeout del job en segundos.
        status: "pending" (sin publicar todavía) | "dispatched" (ya se
                 publicó, con éxito o porque un intento anterior lo hizo).
                 No hay estado terminal de fallo: un ``TaskDispatch`` sin
                 publicar es casi siempre un síntoma de infraestructura
                 (Redis caído), no de datos rotos, así que se reintenta
                 indefinidamente en vez de darlo por muerto.
        attempts: Cuántas veces falló un intento de publicación.
        last_error: Motivo del último fallo, si alguno.
        created_at: Cuándo se creó la intención (misma transacción que la
                 entidad que la origina).
        dispatched_at: Cuándo se publicó con éxito; NULL mientras siga
                 ``pending``.
    """
    __tablename__ = "TaskDispatch"

    id = Column(Integer, primary_key=True, autoincrement=True)
    func_path = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    args = Column(JSONB, nullable=False, default=list)
    kwargs = Column(JSONB, nullable=False, default=dict)
    external_id = Column(String(255), nullable=True)
    timeout = Column(Integer, nullable=False, default=600)
    status = Column(String(20), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    dispatched_at = Column(DateTime, nullable=True)


def encode_func(func: Callable) -> str:
    """Convierte un callable en la referencia importable que se guarda en
    ``TaskDispatch.func_path``, para poder reconstruirlo en otro proceso o
    después de un reinicio (JSON no sabe serializar funciones).

    ``__qualname__`` incluye el nombre de la clase para un ``@staticmethod``
    (p.ej. ``"IrisManager.execute_iris_analysis"``), que es exactamente lo
    que ``decode_func`` necesita para volver a resolverlo con ``getattr``.

    Args:
        func: Callable a codificar. Debe ser importable por referencia
            (un ``@staticmethod`` de un manager, o una función a nivel de
            módulo) -- nunca una lambda ni un closure, que no tienen un
            ``__qualname__`` resoluble desde otro proceso.

    Returns:
        str: Cadena con formato ``"modulo.paquete:Clase.metodo"`` (o
            ``"modulo.paquete:nombre_funcion"`` para una función suelta).
    """
    return f"{func.__module__}:{func.__qualname__}"


def decode_func(path: str) -> Callable:
    """Inversa de ``encode_func``: reconstruye el callable a partir de su
    referencia importable.

    Args:
        path: Cadena con el formato que produce ``encode_func`` --
            ``"modulo.paquete:Clase.metodo"`` o ``"modulo.paquete:funcion"``.

    Returns:
        Callable: El mismo objeto función/staticmethod que se codificó,
            siempre que el módulo y el atributo sigan existiendo.

    Raises:
        ImportError: El módulo de ``path`` ya no existe o no se puede importar.
        AttributeError: El módulo existe pero ya no tiene ese atributo (p.ej.
            el método se renombró o se borró después de encolar la fila).
    """
    module_path, qualname = path.split(":", 1)
    target: Any = importlib.import_module(module_path)
    for part in qualname.split("."):
        target = getattr(target, part)
    return target


def build_dispatch(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    func: Callable, *, name: str, category: str, args: tuple = (),
    kwargs: Optional[dict] = None, external_id: Optional[str] = None,
    timeout: int = 600,
) -> TaskDispatch:
    """Construye (sin guardar) la fila de outbox para una futura llamada a
    ``TaskQueue.submit()`` con los mismos argumentos.

    Args:
        func: Callable que ejecutará el worker -- ver ``encode_func`` para
            las restricciones (debe ser importable por referencia).
        name: Id determinista del job en RQ, igual que ``name=`` en
            ``TaskQueue.submit()``.
        category: Categoría de cola registrada en ``QueueRegistry`` (p.ej.
            ``"iris.analyze"``); si no está registrada, ``TaskQueue`` la
            enruta a ``"default"`` al publicarla.
        args: Argumentos posicionales para ``func``, JSON-serializables.
            Por defecto, ninguno.
        kwargs: Argumentos nombrados para ``func``, JSON-serializables. Por
            defecto ninguno (se guarda como diccionario vacío, nunca ``None``).
        external_id: Id lógico de dominio para localizar el job más tarde
            (p.ej. ``"iris-analysis:42"``); ``None`` si no aplica.
        timeout: Timeout del job en segundos una vez publicado. Por defecto
            ``600``.

    Returns:
        TaskDispatch: Instancia sin persistir -- el llamante la guarda con
            un repositorio, típicamente en la misma transacción que la
            entidad que la origina.
    """
    return TaskDispatch(
        func_path=encode_func(func), name=name, category=category,
        args=list(args), kwargs=dict(kwargs or {}), external_id=external_id,
        timeout=timeout,
    )
