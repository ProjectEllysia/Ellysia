"""
taskqueue/worker.py
───────────────────
RQ worker entry point with Flask application context pre-loaded.

Usage:
    python -m src.modules.system.taskqueue.worker

The worker creates a Flask app instance, pushes an application context
so that database sessions, config, and all Flask extensions are available
to every executed job. It then listens on the configured Redis queues.

Modelo de ejecución: **hilos + RQ SimpleWorker** (sin ``fork``). Los jobs son
I/O-bound (orquestan subprocesos nmap/nikto o peticiones de red del motor
propio), por lo que el aislamiento por-proceso de ``fork`` no aporta frente al aislamiento
de OS que ya dan esos subprocesos. Cada hilo crea su propia app Flask y empuja
un contexto de aplicación, evitando los problemas de fork-safety del ``Worker``
clásico de RQ (el ``engine`` de SQLAlchemy y las conexiones a Redis se crean
antes del fork y se compartirían entre el padre y cada hijo forkeado salvo que
se reconfiguren con ``NullPool``/``os.register_at_fork``). No cambiar a un
modelo basado en ``fork`` sin resolver esos problemas de fork-safety.

Separate process from the API server: if the API crashes, running
tasks survive; if a task crashes, the API stays healthy.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import uuid

import psutil

from rq import Queue, SimpleWorker
from rq.registry import BaseRegistry
from rq.timeouts import TimerDeathPenalty

BaseRegistry.death_penalty_class = TimerDeathPenalty

import src.modules.system.config_reading as CR
from src.modules.system.logging import configure_logging

from .connection import RedisConnectionFactory
from .queue import QueueRegistry

_workers = []
_workers_lock = threading.Lock()

# TTL del registro de cada worker en Redis (clave ``rq:worker:<name>``).
# RQ lo refresca con cada heartbeat; si el worker muere de forma abrupta
# (kill -9, contenedor reiniciado con otro hostname) la clave caduca como mucho
# este tiempo después del último heartbeat y deja de contarse como "vivo". El
# valor por defecto de RQ (420 s) hacía que los "workers fantasma" inflaran el
# contador durante ~8 min; con 120 s la ventana baja a ~3 min y el panel
# "X / max workers" se auto-sanea mucho antes. Es especialmente importante en
# despliegue por contenedores, donde el PID no es verificable cross-host.
_WORKER_TTL_SECONDS = 120


class _ThreadSafeWorker(SimpleWorker):
    """SimpleWorker que evita usar señales fuera del hilo principal.

    RQ elige ``death_penalty_class`` según la plataforma
    (``get_default_death_penalty_class``): en Linux usa
    ``UnixSignalDeathPenalty`` (``signal.signal(SIGALRM, ...)``), que solo
    funciona en el hilo principal del intérprete. Cada worker corre en su
    propio ``threading.Thread``, así que forzamos ``TimerDeathPenalty``
    (basado en ``threading.Timer``), que es thread-safe en cualquier
    plataforma.
    """

    death_penalty_class = TimerDeathPenalty

    def _install_signal_handlers(self):
        pass

    def perform_job(self, job, queue):
        """Ejecuta el job y limpia la sesión scoped del hilo al terminar.

        Los hilos de worker viven indefinidamente y ``scoped_session`` está
        keyed por hilo, así que la misma ``Session`` se reutilizaría entre
        jobs. Sin esta limpieza, un job que deje la transacción en estado
        abortado (``PendingRollbackError``) u objetos colgando en la
        identity-map envenenaría el siguiente job del mismo hilo. Este es el
        único choke-point por el que pasan todos los tipos de job, por lo que
        ``close_all()`` aquí cubre nmap/nikto/lybra/nuclei/aegis/iris.
        """
        try:
            return super().perform_job(job, queue)
        finally:
            from src.modules.infrastructure.unit_of_work import close_all
            close_all()

def _worker_thread(worker_num: int):
    """Hilo de trabajo independiente que escucha y ejecuta jobs de una o más colas.

    **Inicialización** (paso a paso):
        1. create_app(start_scheduler=False) → crea instancia Flask
           - Importa todos los módulos (blueprints, managers)
           - Cada módulo hace QueueRegistry.register("categoría")
        2. app.app_context() → empuja contexto Flask para que DB sessions funcionen
        3. QueueRegistry.names() → obtiene todas las colas registradas
           Ej: ["default", "themis.scan", "themis.report", "aegis.generate", "iris.analyze"]
        4. Crea RQ Queue para cada nombre (conexión a Redis)
        5. Crea RQ Worker y lo registra en _workers (para poder pararlo después)
        6. worker.work() → loop infinito que:
           - Escucha TODAS las colas en paralelo (FIFO)
           - Cuando hay un job, lo saca
           - Ejecuta func(args, kwargs) en el contexto Flask
           - Registra resultado/error en Redis (callbacks de RQ)
           - Vuelve a esperar

    **Aislamiento**: Cada worker corre en su propio thread con su propia
    app Flask y contexto. Si uno se cuelga, los otros siguen funcionando.

    **Proceso vs Thread**: RQ clásico usa fork() (procesos) por job. Aquí
    usamos threads porque los jobs son I/O-bound (subprocesos nmap/nikto,
    peticiones de red del motor propio) y el aislamiento de ``fork`` no aporta frente
    al que ya dan esos subprocesos. Cada thread tiene su propia app Flask, por
    lo que DB sessions no se interfieren, sin los problemas de fork-safety que
    tendría reutilizar conexiones de BD/Redis creadas antes de un fork.

    **Error handling**: Si el job crashea, RQ lo atrapa, registra el error,
    y el worker sigue escuchando. La tarea no se reintenta automáticamente
    (comportamiento configurable de RQ).
    """
    from run import create_app
    # create_app importa todos los módulos (blueprints), lo que dispara el
    # registro de categorías en QueueRegistry antes de construir las colas.
    app = create_app(start_scheduler=False, run_migrations=False)
    with app.app_context():
        # blocking=True: el bucle del worker saca jobs con BLPOP; un
        # socket_timeout abortaría el dequeue bloqueante.
        conn = RedisConnectionFactory.raw(blocking=True)
        queues = [Queue(name, connection=conn) for name in QueueRegistry.names()]
        worker_name = f"worker-{worker_num}-{uuid.uuid4().hex[:8]}"
        worker = _ThreadSafeWorker(queues, name=worker_name, worker_ttl=_WORKER_TTL_SECONDS)
        with _workers_lock:
            _workers.append(worker)
        try:
            worker.work(with_scheduler=False)
        finally:
            with _workers_lock:
                if worker in _workers:
                    _workers.remove(worker)

def _stop_workers():
    """Desregistra los workers de Redis antes de salir.

    ``register_death`` elimina la entrada del worker tanto del set global
    ``rq:workers`` como de los sets por-cola. Es clave para que, al reiniciar
    la app, no se acumulen "workers fantasma" en el contador. Tras esto el
    proceso hace ``os._exit(0)``, por lo que los hilos no llegan a re-registrarse.
    """
    logging.info("Stopping all workers...")
    with _workers_lock:
        for worker in list(_workers):
            try:
                worker.register_death()
            except Exception as exc:
                logging.warning("Failed to deregister worker %s: %s", worker.name, exc)

def _purge_dead_workers() -> None:
    """Reconcilia el registro ``rq:workers`` eliminando workers ya muertos.

    Si un worker murió de forma abrupta (``kill -9``, crash) sin desregistrarse,
    su nombre queda en el set global ``rq:workers`` indefinidamente e infla el
    contador. Antes de arrancar los nuevos workers se elimina toda entrada cuya
    clave de heartbeat (``rq:worker:<name>``) ya no exista o cuyo PID (en este
    mismo host) ya no esté vivo. Misma lógica de liveness que
    ``TaskQueue._worker_alive``.
    """
    try:
        conn = RedisConnectionFactory.decoded()
        worker_keys = conn.smembers("rq:workers")
    except Exception as exc:
        logging.warning("No se pudo purgar workers obsoletos: %s", exc)
        return

    hostname = socket.gethostname()
    for key in worker_keys:
        try:
            data = conn.hgetall(key)
        except Exception:
            continue
        if not data:
            conn.srem("rq:workers", key)
            continue
        pid = data.get("pid")
        whost = data.get("hostname")
        if pid and whost == hostname:
            try:
                if not psutil.pid_exists(int(pid)):
                    conn.srem("rq:workers", key)
            except (ValueError, TypeError):
                pass

def start_worker() -> None:
    """Entry point para iniciar los workers.

    **Responsabilidad**: Arrancar N workers (configurables) como threads,
    cada uno escuchando las colas registradas en QueueRegistry. Manejar
    señales (SIGINT, SIGTERM, SIGBREAK en Windows) para shutdown limpio.

    **Configuración**:
        - max_workers: int (config) → número de threads
        - Si max_workers == 1: single-threaded (simpler debugging)
        - Si max_workers > 1: multi-threaded, cada uno con su contexto Flask

    **Uso**: python -m src.modules.system.taskqueue.worker

    **Flujo**:
        1. Lee config max_workers
        2. Si max_workers == 1: corre _worker_thread(1) bloqueante
        3. Si max_workers > 1: inicia N threads, cada uno en _worker_thread(i)
        4. Instala signal handlers para SIGINT, SIGTERM, SIGBREAK (Windows)
        5. Espera a que los threads terminen (Ctrl+C los mata limpiamente)

    **Shutdown limpio**: _stop_workers() llama request_stop() en cada worker,
    que envía SIGTERM al worker RQ. Los jobs en progreso reciben SIGTERM y
    pueden hacer cleanup si quieren (context managers como job_context limpian
    señales de cancelación automáticamente).

    **Separación API/Workers**: Este proceso es independiente de run.py (API).
    - Si un worker crashea, la API sigue respondiendo
    - Si la API crashea, los workers siguen procesando tareas
    - El estado está en Redis (persiste entre reinicios)
    """

    configure_logging()

    def _signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
        logging.info("%s received, forcing shutdown...", sig_name)
        _stop_workers()
        os._exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _signal_handler)

    # Reconciliar el registro: limpiar workers de arranques anteriores que no
    # se desregistraron (p. ej. tras un kill -9) antes de crear los nuevos.
    _purge_dead_workers()

    max_workers = CR.taskqueue_config().max_workers
    # Nota: max_workers se lee solo aquí, al arrancar el proceso worker. Si se
    # cambia vía PUT /system/tasks/config, el cambio entra en vigor solo cuando
    # se reinicia este proceso (contenedor docker-compose up, o Ctrl+C + python -m).
    # El API process hablará de nuevos max_workers, pero este worker no lo sabe.

    if max_workers == 1:
        try:
            _worker_thread(1)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received")
            _stop_workers()
        return

    threads = []
    for i in range(max_workers):
        t = threading.Thread(
            target=_worker_thread,
            args=(i + 1,),
            daemon=True,
        )
        t.start()
        threads.append(t)
        logging.info("Worker %d started", i + 1)

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received, stopping workers...")
        _stop_workers()
        os._exit(0)


if __name__ == "__main__":
    start_worker()
