

import subprocess
import threading
import re
import time

from urllib.parse import urlparse
from pathlib import Path
from typing import Callable, Optional, Any, List
from abc import ABC, abstractmethod

import psutil

import logging

import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import TaskStatus


logger = logging.getLogger(__name__)


def _kill_process_tree(proc: Optional[subprocess.Popen], timeout: float = 3.0) -> None:
    """Mata el proceso y TODOS sus descendientes (terminate → kill con timeout).

    Necesario porque los escaneos se lanzan vía ``sudo``: matar solo el proceso
    padre deja hijos huérfanos (p. ej. ``nmap``) que siguen vivos. Con ``psutil``
    recorremos el árbol completo y nunca bloqueamos sin límite (``wait_procs``
    lleva timeout).
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        parent = psutil.Process(proc.pid)
    except psutil.NoSuchProcess:
        return
    targets = parent.children(recursive=True) + [parent]
    for p in targets:
        try:
            p.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(targets, timeout=timeout)
    for p in alive:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass



class _Task(ABC):
    """
    Clase base abstracta para representar una tarea de escaneo.
    """

    def __init__(
        self,
        target: str,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ):
        # Q2: el default vive en SecOpsConfig.json, no como literal aquí —
        # None solo cuando el caller no pasa timeout explícito (todas las
        # subclases sí lo hacen hoy, pero se mantiene el fallback).
        self.timeout = timeout if timeout is not None else CR.themis_task_defaults().timeout
        self.status: TaskStatus = TaskStatus.PENDING
        self.progress: int = 0
        self.results: Optional[Any] = None
        self.target: str = target
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._started = threading.Event()
        self._cancel_event = threading.Event()
        self._output_file: Optional[Path] = None
        self._progress_callback = progress_callback

    @abstractmethod
    def _build_command(self) -> List[str]:
        """Construye el comando a ejecutar."""

    def _terminate_proc(self) -> None:
        """Detiene el proceso de escaneo: árbol completo de descendientes.

        En Linux, con ``start_new_session=True`` los hijos (p. ej. ``nmap``) son
        descendientes reales del proceso lanzado, así que ``_kill_process_tree``
        basta para no dejar huérfanos.
        """
        _kill_process_tree(self._proc)

    def _process_results(self) -> None:
        """Procesa los resultados del escaneo. Override en subclases si es necesario."""

    def _check_output_line(self, line: str) -> None:
        """Hook para detectar en una línea de salida un fallo que el proceso
        no ha reportado aún vía código de salida. No-op por defecto — override
        en la subclase que lo necesite (A11: antes este check estaba
        hardcodeado aquí con strings de Nikto, acoplando la clase base a un
        único scanner concreto)."""

    def _parse_progress(self, line: str) -> int:
        """Extrae el porcentaje de progreso de una línea de salida."""
        match = re.search(r'(\d+(?:\.\d+)?)%', line)
        if match:
            prog_float = float(match.group(1))
            if 0 <= prog_float <= 100:
                return int(round(prog_float))
        return -1

    def _read_output(self):
        """Lee la salida del proceso en un thread separado."""
        try:
            self._started.set()
            while True:
                if self._proc is None or self._proc.stdout is None:
                    break
                line = self._proc.stdout.readline()
                if not line:
                    break
                logger.debug(f"Output: {line.strip()}")

                self._check_output_line(line)

                prog = self._parse_progress(line)
                if prog != -1:
                    with self._lock:
                        self.progress = prog
                    if self._progress_callback:
                        self._progress_callback(prog)

        except (OSError, IOError) as e:
            logger.error(f"Error leyendo salida: {e}", exc_info=True)

        finally:
            if self._proc:
                try:
                    self._proc.wait(timeout=10)
                    logger.debug(f"Proceso terminó con código: {self._proc.returncode}")
                except subprocess.TimeoutExpired:
                    logger.error("Timeout esperando fin del proceso", exc_info=True)
                    self._proc.kill()
                    self._proc.wait()

            time.sleep(0.5)
            self._finished.set()

    def scan(self) -> None:
        """Inicia el escaneo de forma ASÍNCRONA."""
        
        if self._cancel_event.is_set():
            self.status = TaskStatus.CANCELLED
            self._finished.set()
            logger.warning("Escaneo cancelado antes de iniciar")
            return

        if self._proc and self._proc.poll() is None:
            logger.warning("El escaneo ya está en ejecución")
            return

        try:
            self.status = TaskStatus.RUNNING
            cmd = self._build_command()
            logger.info(f"Iniciando escaneo con comando: {' '.join(cmd)}")

            # Sesión/grupo de proceso propios: el escaneo arranca en su propia
            # sesión, así matarlo (al cancelar) no propaga señales al proceso
            # principal y permite limpiar todo el árbol de descendientes.
            popen_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "text": True,
                "bufsize": 1,
                "start_new_session": True,
            }

            self._proc = subprocess.Popen(cmd, **popen_kwargs)

            time.sleep(0.1)
            returncode = self._proc.poll()

            if returncode is not None and returncode != 0:
                output, _ = self._proc.communicate(timeout=1)
                if output and output.strip():
                    logger.error("Salida del proceso fallido:\n%s", output.strip())
                if self.status != TaskStatus.CANCELLED:
                    self.status = TaskStatus.FAILED
                raise RuntimeError(f"Proceso falló al iniciar (código {returncode})")

            if returncode == 0:
                logger.warning("Proceso terminó inmediatamente con código 0.")

            self._thread = threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()

            if not self._started.wait(timeout=5):
                raise RuntimeError("Thread de lectura no inició")

        except (OSError, IOError, RuntimeError) as e:
            if self.status != TaskStatus.CANCELLED:
                self.status = TaskStatus.FAILED
            logger.error(f"Error iniciando escaneo: {e}", exc_info=True)
            raise

    def wait(self, timeout: Optional[float] = None, cancel_check: Optional[Callable[[], bool]] = None) -> bool:
        """Espera a que termine el escaneo. Llamada BLOQUEANTE para el thread worker."""
        try:
            if not self._started.is_set():
                logger.error("wait() llamado pero scan() nunca se ejecutó")
                return False

            granularity = 1.0
            deadline = time.monotonic() + timeout if timeout else None

            while not self._finished.is_set():
                if cancel_check and cancel_check():
                    self.cancel()
                    return False

                if deadline:
                    remaining = max(0.0, deadline - time.monotonic())
                    if remaining <= 0:
                        self.status = TaskStatus.TIMEOUT
                        logger.error("Timeout agotado")
                        self._terminate_proc()
                        return False
                    self._finished.wait(min(granularity, remaining))
                else:
                    self._finished.wait(granularity)

            if self._cancel_event.is_set():
                self.status = TaskStatus.CANCELLED
                logger.info("wait() detecta cancelación vía _cancel_event")
                return False

            if self.status in (TaskStatus.CANCELLED, TaskStatus.TIMEOUT, TaskStatus.FAILED):
                logger.info(f"wait() termina con estado {self.status.value}")
                return False

            if self._proc and self._proc.returncode != 0:
                if self.status != TaskStatus.CANCELLED:
                    self.status = TaskStatus.FAILED
                logger.error(f"Proceso terminó con error: código {self._proc.returncode}")
                return False

            self._process_results()

            if self.results is None:
                if self.status != TaskStatus.CANCELLED:
                    self.status = TaskStatus.FAILED
                logger.error("No se pudieron procesar los resultados")
                return False

            self.status = TaskStatus.COMPLETED
            self.progress = 100
            logger.info("Escaneo completado correctamente")
            return True

        except (OSError, IOError, ValueError) as e:
            self.status = TaskStatus.FAILED
            logger.error(f"Error en wait: {e}", exc_info=True)
            return False

    def cancel(self) -> None:
        """Cancela el escaneo."""
        self._cancel_event.set()
        self.status = TaskStatus.CANCELLED
        self._finished.set()

        self._terminate_proc()

        logger.info("Escaneo cancelado")


class NmapScanTask(_Task):
    """Implementación concreta para escaneos Nmap."""

    def __init__(self, target_host="127.0.0.1", target_ports="1-6000", timeout: int = 300, progress_callback: Optional[Callable[[int], None]] = None):
        super().__init__(target_host, timeout, progress_callback=progress_callback)
        temp_dir = CR.get_directory_of(CR.DirectoryType.TEMP)

        timestamp = int(time.time() * 1000)
        safe_target = target_host.replace("/", "_").replace(":", "_")
        file_name = f"nmap_scan_{safe_target}_{timestamp}.xml"

        self.target_ports = target_ports
        self._output_file = Path(f"{temp_dir}/{file_name}")

        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def _build_command(self) -> List[str]:
        return [
            "sudo", "-n", "nmap",
            "-sV", "-sS", "-T4",
            "-p", self.target_ports,
            "-oX", str(self._output_file),
            self.target,
            "--stats-every", "1s"
        ]

    def _process_results(self) -> None:
        try:
            output_file = self._output_file

            if not output_file.exists():
                logger.error(f"Archivo XML no existe: {output_file}")
                self.results = None
                return

            with output_file.open("r", encoding="utf-8") as f:
                xml_data = f.read()

            if not xml_data.strip():
                logger.error("Contenido del XML está vacío")
                self.results = None
                return

            self.results = xml_data
            logger.info(f"Resultados procesados: {output_file}")

        except (OSError, IOError) as e:
            logger.error(f"Error procesando resultados: {e}", exc_info=True)
            self.results = None
            raise


class NiktoScanTask(_Task):
    """Implementación concreta para escaneos Nikto."""

    def __init__(self, target_domain, timeout: int = 120, progress_callback: Optional[Callable[[int], None]] = None):
        super().__init__(target_domain, timeout, progress_callback=progress_callback)

        timestamp = int(time.time() * 1000)
        self.temp_path = (
            CR.verify_directory(directory=CR.DirectoryType.TEMP)
            /
            f"nikto_scan_{timestamp}.xml"
        )
        self._output_file = self.temp_path

    def _build_command(self) -> List[str]:
        target = self.target

        raw = target if "://" in target else f"http://{target}"
        parsed = urlparse(raw)

        host = parsed.hostname or target
        use_ssl = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if use_ssl else 80)

        nikto_cmd = [
            "nikto",
            "-h", host,
            "-port", str(port),
            "-output", str(self.temp_path),
            "-Format", "xml",
            "-timeout", "30",
            "-nointeractive",
        ]

        if use_ssl:
            nikto_cmd.append("-ssl")

        return nikto_cmd

    def _check_output_line(self, line: str) -> None:
        if "Unknown option:" in line or "requires a value" in line:
            logger.error(f"Nikto rechazó el comando (opción inválida): {line.strip()}")
            self.status = TaskStatus.FAILED

    def _process_results(self) -> None:
        try:
            if not self.temp_path.exists():
                logger.warning(f"Archivo XML no existe: {self.temp_path}")
                self.results = [] if self._cancel_event.is_set() else None
                return
            if self.temp_path.stat().st_size == 0:
                logger.warning(f"Archivo XML está vacío: {self.temp_path}")
                self.results = [] if self._cancel_event.is_set() else None
                return

            self.results = str(self.temp_path)
            logger.info("Resultados Nikto procesados")

        except (OSError, IOError) as e:
            logger.error(f"Error procesando resultados Nikto: {e}", exc_info=True)
            self.results = None
            raise


class NucleiScanTask(_Task):
    """Implementación concreta para escaneos Nuclei (roadmap Fase U1).

    Modelada sobre ``NiktoScanTask``: mismo patrón de fichero de salida
    temporal + progreso vía stdout. Dos diferencias que sí importan:

    - El feed de plantillas se hornea en la imagen (``-duc``, sin
      autoactualización en tiempo de ejecución — una llamada de red a mitad
      de un escaneo dentro de un worker sería latencia y un fallo posible
      nuevo). ``_check_output_line`` captura la versión real de plantillas
      del propio banner de arranque del binario, que es el dato más fiable
      posible: es lo que el binario está usando de verdad en este escaneo,
      no un valor de configuración que podría haber quedado desincronizado.
    - Nuclei no crea el fichero de export cuando el escaneo termina limpio
      sin ningún hallazgo — a diferencia de Nikto, cuyo XML siempre existe.
      ``_process_results`` distingue ese caso (resultado ``[]``, escaneo
      limpio) de uno realmente fallido (fichero ausente pero el proceso
      falló), para no marcar como FAILED todo escaneo sin hallazgos.
    """

    _TEMPLATES_VERSION_RE = re.compile(r"Nuclei Templates Version:\s*(v?[\d.]+)", re.IGNORECASE)

    def __init__(
        self,
        target: str,
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        rate_limit: Optional[int] = None,
        request_timeout: Optional[int] = None,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ):
        resolved_timeout = timeout if timeout is not None else CR.nuclei_config().timeout
        super().__init__(target, resolved_timeout, progress_callback=progress_callback)

        timestamp = int(time.time() * 1000)
        self.temp_path = (
            CR.verify_directory(directory=CR.DirectoryType.TEMP)
            /
            f"nuclei_scan_{timestamp}.jsonl"
        )
        self._output_file = self.temp_path

        self.severities = severities or CR.nuclei_config().default_severities
        self.tags = tags or []
        self.rate_limit = rate_limit or CR.nuclei_config().rate_limit
        self.request_timeout = request_timeout or CR.nuclei_config().request_timeout
        self._binary = CR.nuclei_config().binary_path
        # Única fuente de verdad sobre dónde vive el árbol de plantillas, la
        # misma que usan la ingesta (Fase R) y el censo (Fase U4) para leerlo.
        # ``None`` significa "no se pudo resolver ninguno", y entonces se omite
        # ``-templates`` y decide el binario — el mismo comportamiento que había
        # cuando el valor de configuración venía vacío.
        templates_dir = CR.nuclei_config().templates_dir
        self._templates_dir = str(templates_dir) if templates_dir else ""

        # Rellenado por _check_output_line al ver el banner de arranque; si el
        # escaneo termina sin que aparezca (binario silencioso, formato de
        # banner distinto entre versiones), el manager cae al valor de
        # configuración y, en último término, a un marcador explícito de
        # "desconocido" — nunca se inventa un número.
        self.templates_version: Optional[str] = None

    def _build_command(self) -> List[str]:
        cmd = [
            self._binary,
            "-target", self.target,
            "-jsonl-export", str(self.temp_path),
            "-duc", "-nc",
            "-stats", "-stats-interval", "1",
            "-rate-limit", str(self.rate_limit),
            "-timeout", str(self.request_timeout),
        ]
        if self.severities:
            cmd += ["-severity", ",".join(self.severities)]
        if self.tags:
            cmd += ["-tags", ",".join(self.tags)]
        if self._templates_dir:
            cmd += ["-templates", self._templates_dir]
        return cmd

    def _check_output_line(self, line: str) -> None:
        if self.templates_version is None:
            match = self._TEMPLATES_VERSION_RE.search(line)
            if match:
                self.templates_version = match.group(1)

    def _process_results(self) -> None:
        try:
            # _Task.wait() only reaches _process_results() once the process
            # has already exited with code 0 and neither cancellation nor a
            # timeout was hit (see the checks above this call) — so getting
            # here at all already means the scan itself succeeded. Nuclei
            # simply does not write the export file when it found nothing,
            # unlike Nikto's XML (which always exists); absence of the file
            # at this point is therefore a clean scan, not a failure.
            if not self.temp_path.exists() or self.temp_path.stat().st_size == 0:
                self.results = []
                logger.info("Escaneo Nuclei sin hallazgos")
                return

            self.results = str(self.temp_path)
            logger.info("Resultados Nuclei procesados")

        except (OSError, IOError) as e:
            logger.error(f"Error procesando resultados Nuclei: {e}", exc_info=True)
            self.results = None
            raise

