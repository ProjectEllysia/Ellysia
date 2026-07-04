

import subprocess
import threading
import re
import time

from urllib.parse import urlparse
from pathlib import Path
from typing import Callable, Optional, Any, List
from abc import ABC, abstractmethod

import psutil
import lxml.etree as lxml_etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.protocols.gmp.requests.v226 import AliveTest

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
        timeout: int = 200000,
        progress_callback: Optional[Callable[[int], None]] = None,
    ):
        self.timeout = timeout
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

                if "Unknown option:" in line or "requires a value" in line:
                    logger.error(f"Nikto rechazó el comando (opción inválida): {line.strip()}")
                    self.status = TaskStatus.FAILED

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
            "-sV", "-sT",
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


class OpenVASTask(_Task):
    """
    Tarea de escaneo OpenVAS mediante la API GMP (no CLI).
    Gestiona su propio ciclo de vida: setup → polling → reporte.
    """

    _KNOWN_SCAN_CONFIGS = {
        'Full and fast':           'daba56c8-73ec-11df-a475-002264764cea',
        'Full and fast ultimate':  '698f691e-7489-11df-9d8c-002264764cea',
        'Full and very deep':      '708f25c4-7489-11df-8094-002264764cea',
        'System Discovery':        'bbca7412-a950-11e3-9109-406186ea4fc5',
    }

    def __init__(
        self,
        target: str,
        hostname: str,
        port: str,
        username: str,
        password: str,
        scan_config: Optional[str] = None,
        port_list_id: Optional[str] = None,
        timeout: int = 14400,
        progress_callback: Optional[Callable[[int], None]] = None,
    ):
        super().__init__(target, timeout, progress_callback=progress_callback)
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self._preferred_scan_config = scan_config
        self._preferred_port_list = port_list_id

        self.task_id: Optional[str] = None
        self.report_id: Optional[str] = None

    def _build_command(self) -> List[str]:
        """OpenVAS no usa CLI."""
        return []

    def scan(self) -> None:
        """Inicia el escaneo OpenVAS de forma asíncrona."""
        try:
            self.status = TaskStatus.RUNNING
            self._started.set()
            self._thread = threading.Thread(target=self._execute_openvas_scan, daemon=True)
            self._thread.start()
            logger.info(f"Escaneo OpenVAS iniciado para {self.target}")
        except (OSError, RuntimeError) as e:
            self.status = TaskStatus.FAILED
            logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    def wait(self, timeout: Optional[float] = None, cancel_check: Optional[Callable[[], bool]] = None) -> bool:
        """Override: OpenVAS gestiona su propio ciclo interno."""
        try:
            safe_timeout = min(timeout, 28800) if timeout is not None else None
            granularity = 1.0
            deadline = time.monotonic() + safe_timeout if safe_timeout else None

            while not self._finished.is_set():
                if cancel_check and cancel_check():
                    self.cancel()
                    return False

                if deadline:
                    remaining = max(0.0, deadline - time.monotonic())
                    if remaining <= 0:
                        self.status = TaskStatus.TIMEOUT
                        logger.error("Timeout esperando finalización de OpenVAS")
                        return False
                    self._finished.wait(min(granularity, remaining))
                else:
                    self._finished.wait(granularity)

            if self.status in (TaskStatus.CANCELLED, TaskStatus.FAILED):
                return False

            if self.results is None:
                self.status = TaskStatus.FAILED
                logger.error("OpenVAS finalizó pero no hay resultados")
                return False

            self.status = TaskStatus.COMPLETED
            self.progress = 100
            return True

        except (OSError, IOError, ValueError) as e:
            self.status = TaskStatus.FAILED
            logger.error(f"Error en wait de OpenVAS: {e}", exc_info=True)
            return False

    def cancel(self) -> None:
        """Cancela el escaneo deteniendo la tarea en OpenVAS."""
        self._cancel_event.set()
        self.status = TaskStatus.CANCELLED
        logger.info("Cancelación solicitada; se detendrá en el próximo ciclo de polling")

    def _execute_openvas_scan(self) -> None:
        try:
            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                target_id = self._get_or_create_target(gmp)
                scanner_id = self._get_default_scanner(gmp)
                self._create_and_start_task(gmp, target_id, scanner_id)

            self._wait_for_completion()

            if self.status == TaskStatus.CANCELLED:
                self._finished.set()
                return

            with self._create_gmp_connection() as gmp:
                gmp.authenticate(self.username, self.password)
                self._fetch_report(gmp)

            self._finished.set()

        except (OSError, RuntimeError) as e:
            self.status = TaskStatus.FAILED
            logger.error(f"Error en escaneo OpenVAS: {e}", exc_info=True)
            self._finished.set()

    def _create_gmp_connection(self) -> Gmp:
        """Crea una conexión GMP nueva. Usar siempre con 'with'."""
        connection = TLSConnection(
            hostname=self.hostname,
            port=self.port,
            timeout=60
        )
        return Gmp(connection=connection, transform=EtreeTransform())

    def _extract_id_from_response(self, response, entity_name: str) -> Optional[str]:
        """
        Extrae el ID de una respuesta GMP probando múltiples estrategias.
        Evita duplicar esta lógica en cada método.
        """
        entity_id = response.attrib.get('id')
        if entity_id:
            return entity_id

        ids = response.xpath('@id')
        if ids:
            return ids[0]

        id_el = response.find('id')
        if id_el is not None and id_el.text:
            return id_el.text.strip()

        sub_el = response.find(entity_name)
        if sub_el is not None:
            entity_id = sub_el.get('id')
            if entity_id:
                return entity_id

        logger.error(
            f"No se pudo extraer ID de respuesta '{entity_name}': "
            f"{lxml_etree.tostring(response, encoding='unicode')}"
        )
        return None

    def _get_or_create_target(self, gmp: Gmp) -> str:
        target_name = f"Target_{self.target}"

        targets = gmp.get_targets(filter_string=f'name="{target_name}"')
        target_list = targets.xpath('target')
        if target_list:
            target_id = target_list[0].attrib.get('id')
            logger.info(f"Reutilizando target existente: {target_id}")
            return target_id

        port_list_id = self._preferred_port_list or self._get_or_create_port_list(gmp)

        logger.info(f"Creando target para {self.target}")
        target_response = gmp.create_target(
            name=target_name,
            hosts=[self.target],
            port_list_id=port_list_id,
            comment=f"Target para {self.target}",
            alive_test=AliveTest.CONSIDER_ALIVE
        )

        target_id = self._extract_id_from_response(target_response, 'target')
        if not target_id:
            raise RuntimeError("No se pudo obtener el target_id de la respuesta")

        logger.info(f"Target creado: {target_id}")
        return target_id

    def _get_default_scanner(self, gmp: Gmp) -> str:
        """Obtiene el scanner OpenVAS por defecto."""
        scanners = gmp.get_scanners()
        for scanner in scanners.xpath('scanner'):
            name_el = scanner.find('name')
            if name_el is not None and name_el.text == 'OpenVAS Default':
                scanner_id = scanner.get('id')
                logger.info(f"Scanner encontrado: {scanner_id}")
                return scanner_id

        raise RuntimeError("No se encontró el scanner 'OpenVAS Default'")

    def _get_or_create_port_list(self, gmp: Gmp) -> str:
        """Obtiene o crea una port list."""
        port_lists = gmp.get_port_lists()
        preferred_names = {'All IANA assigned TCP', 'Default', 'OpenVAS Default'}

        for port_list in port_lists.xpath('port_list'):
            name_el = port_list.find('name')
            if name_el is not None and name_el.text in preferred_names:
                port_list_id = port_list.get('id')
                logger.info(f"Port list encontrado: {name_el.text} ({port_list_id})")
                return port_list_id

        # Usar el primero disponible si no hay uno preferido
        first = port_lists.xpath('port_list')
        if first:
            port_list_id = first[0].get('id')
            name = first[0].findtext('name', 'desconocido')
            logger.info(f"Usando primer port_list disponible: {name} ({port_list_id})")
            return port_list_id

        # Crear uno básico si no existe ninguno
        logger.info("Creando port_list predeterminado")
        response = gmp.create_port_list(
            name="Ellysia Default",
            port_range="T:1-1024,U:1-1024",
            comment="Port list creado automáticamente por Ellysia"
        )
        port_list_id = self._extract_id_from_response(response, 'port_list')
        if not port_list_id:
            raise RuntimeError("No se pudo crear ni obtener un port_list")

        logger.info(f"Port list creado: {port_list_id}")
        return port_list_id

    def _get_default_scan_config(self, gmp: Gmp) -> str:
        """
        Obtiene el scan_config a usar.
        Prioridad: 1) preferencia explícita, 2) buscar en servidor,
        3) fallback a UUID conocido de 'Full and fast'.
        """
        if self._preferred_scan_config:
            logger.info(f"Usando scan_config explícito: {self._preferred_scan_config}")
            return self._preferred_scan_config

        scan_configs = gmp.get_scan_configs()
        configs = scan_configs.xpath('config')

        if not configs:
            # Los feeds aún no están cargados. Usar UUID conocido como fallback.
            fallback_id = self._KNOWN_SCAN_CONFIGS['Full and fast']
            logger.warning(
                f"No hay scan_configs en el servidor. "
                f"Usando UUID de fallback 'Full and fast': {fallback_id}. "
                f"Asegúrate de que los feeds de Greenbone estén sincronizados."
            )
            return fallback_id

        # Buscar preferencias en orden
        preferred = ['Full and fast', 'Full and fast ultimate', 'System Discovery']
        config_map = {}
        for config in configs:
            name_el = config.find('name')
            if name_el is not None and name_el.text:
                config_map[name_el.text] = config.get('id')
                logger.info(f"Scan config disponible: {name_el.text} ({config.get('id')})")

        for pref in preferred:
            if pref in config_map:
                logger.info(f"Usando scan_config: {pref}")
                return config_map[pref]

        # Usar el primero disponible
        first_id = configs[0].get('id')
        logger.info(f"Usando primer scan_config disponible: {first_id}")
        return first_id

    def _create_and_start_task(self, gmp: Gmp, target_id: str, scanner_id: str) -> None:
        scan_config_id = self._get_default_scan_config(gmp)
        task_name = f"Ellysia_Scan_{self.target}_{int(time.time())}"

        task_response = gmp.create_task(
            name=task_name,
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Escaneo de {self.target} iniciado por Ellysia"
        )

        self.task_id = self._extract_id_from_response(task_response, 'task')
        if not self.task_id:
            raise RuntimeError("No se pudo obtener el task_id de la respuesta de create_task")

        logger.info(f"Tarea creada: {self.task_id}")

        start_response = gmp.start_task(self.task_id)
        report_ids = start_response.xpath('report_id')
        if not report_ids or not report_ids[0].text:
            raise RuntimeError("No se pudo obtener el report_id al iniciar la tarea")

        self.report_id = report_ids[0].text
        logger.info(f"Escaneo iniciado. Report ID: {self.report_id}")

    def _wait_for_completion(self, check_interval: int = 60) -> None:
        """Espera a que el escaneo complete reconectando en cada iteración."""
        while True:
            if self._cancel_event.is_set():
                try:
                    with self._create_gmp_connection() as gmp:
                        gmp.authenticate(self.username, self.password)
                        gmp.stop_task(self.task_id)
                        logger.info(f"Tarea {self.task_id} detenida en OpenVAS")
                except (OSError, RuntimeError) as e:
                    logger.error(f"Error deteniendo tarea: {e}", exc_info=True)
                self.status = TaskStatus.CANCELLED
                break

            try:
                with self._create_gmp_connection() as gmp:
                    gmp.authenticate(self.username, self.password)
                    task = gmp.get_task(self.task_id)
            except (OSError, RuntimeError) as e:
                logger.warning(
                    f"Error consultando tarea, reintentando en {check_interval}s: {e}",
                    exc_info=True
                )
                time.sleep(check_interval)
                continue

            status_els = task.xpath('task/status')
            progress_els = task.xpath('task/progress')

            if not status_els:
                logger.warning("Respuesta de tarea sin campo 'status', reintentando...")
                time.sleep(check_interval)
                continue

            status = status_els[0].text
            progress_text = progress_els[0].text if progress_els else "0"

            try:
                with self._lock:
                    self.progress = max(0, int(float(progress_text)))
                if self._progress_callback:
                    self._progress_callback(self.progress)
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing progress '{progress_text}': {e}", exc_info=True)

            logger.info(f"Estado: {status} | Progreso: {progress_text}%")

            if status == 'Done':
                break
            elif status in ('Stopped', 'Interrupted'):
                logger.warning(f"Escaneo terminó con estado: {status}")
                self.status = TaskStatus.CANCELLED
                break

            time.sleep(check_interval)

    # ── Reporte y parseo ──────────────────────────────────────────────────────

    def _fetch_report(self, gmp: Gmp) -> None:
        """Obtiene el reporte XML del escaneo."""
        report_response = gmp.get_report(
            report_id=self.report_id,
            report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',
            ignore_pagination=True,
            details=True
        )
        self.results = lxml_etree.tostring(report_response, encoding='unicode', pretty_print=True)
        logger.info("Reporte XML obtenido")
