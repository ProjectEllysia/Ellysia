"""
csv_logger.py
Módulo para registrar escaneos de seguridad en archivos CSV.
Implementa patrón Strategy + Factory con SOLID.
"""

import threading
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable
from pathlib import Path
from datetime import datetime


@runtime_checkable
class ScanLogger(Protocol):
    """Protocolo que define la interfaz para todos los loggers CSV de escaneos."""

    def log(self, data: dict) -> None:
        ...

    @property
    def columns(self) -> list[str]:
        ...

    @property
    def scan_type(self) -> str:
        ...


class BaseScanLogger(ABC):
    """
    Clase base abstracta para loggers de escaneos.
    Implementa la lógica común de escritura CSV con rotación diaria.
    """

    _base_dir: Path | None = None
    _date_format: str = "%Y-%m-%d"
    _csv_name: str = ""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    @property
    @abstractmethod
    def columns(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def scan_type(self) -> str:
        pass

    @property
    def base_dir(self) -> Path:
        if self._base_dir is None:
            from src.modules.system.config_reading import get_themis_csv_dir
            self._base_dir = Path(get_themis_csv_dir())
            self._base_dir.mkdir(parents=True, exist_ok=True)
        return self._base_dir

    @property
    def subdir(self) -> Path:
        return self.base_dir / self.scan_type

    def _get_file_path(self) -> Path:
        date_str = datetime.now().strftime(self._date_format)
        self.subdir.mkdir(parents=True, exist_ok=True)
        return self.subdir / f"{self.scan_type}_scans_{date_str}.csv"

    def _ensure_header(self, file_path: Path) -> None:
        if not file_path.exists() or file_path.stat().st_size == 0:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                f.write(",".join(self.columns) + "\n")

    def log(self, data: dict) -> None:
        file_path = self._get_file_path()
        self._ensure_header(file_path)
        with self._lock:
            try:
                with open(file_path, "a", newline="", encoding="utf-8") as f:
                    values = [str(data.get(col, "")) for col in self.columns]
                    f.write(",".join(values) + "\n")
            except Exception:
                pass

    def _infer_ssl(self, target: str) -> tuple[str, int, bool]:
        """
        Infiere si el target usa SSL y devuelve (cleaned_target, port, is_ssl).
        """
        target = target.strip()
        is_ssl = False
        port = 80

        if target.startswith("https://"):
            is_ssl = True
            port = 443
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]

        if ":" in target:
            parts = target.rsplit(":", 1)
            target = parts[0]
            try:
                port = int(parts[1])
                if port == 443:
                    is_ssl = True
            except ValueError:
                pass

        if target.endswith("/"):
            target = target[:-1]

        return target, port, is_ssl

    def _parse_ports_count(self, ports_str: str) -> int:
        """Calcula el número de puertos en un rango."""
        total = 0
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    total += int(end) - int(start) + 1
                except ValueError:
                    total += 1
            else:
                try:
                    int(part)
                    total += 1
                except ValueError:
                    pass
        return total


class ScanLoggerFactory:
    """
    Factory central para loggers CSV de escaneos.

    ``register`` es un decorador de clase (B3): el alta vive junto a la
    clase que se da de alta, en vez de una lista aparte al final del
    fichero que hay que recordar tocar cuando se añade un logger nuevo.
    Lybra no tiene logger (no pasa por ``_log_to_csv`` — ``append_csv_data``
    es un no-op en ``LybraEngineManager``, ver su docstring).
    """

    _loggers: dict[str, BaseScanLogger] = {}

    @classmethod
    def register(cls, scan_type: str):
        def decorator(logger_cls: type[BaseScanLogger]) -> type[BaseScanLogger]:
            cls._loggers[scan_type] = logger_cls()
            return logger_cls
        return decorator

    @classmethod
    def get(cls, scan_type: str) -> BaseScanLogger:
        if scan_type not in cls._loggers:
            raise ValueError(f"Logger no registrado para tipo: {scan_type}")
        return cls._loggers[scan_type]


@ScanLoggerFactory.register("nmap")
class NmapScanLogger(BaseScanLogger):
    _csv_name = "nmap"

    @property
    def columns(self) -> list[str]:
        return [
            "timestamp",
            "target_host",
            "target_ports",
            "ports_count",
            "timeout_sec",
            "duration_sec",
            "concurrent_tasks",
            "status",
        ]

    @property
    def scan_type(self) -> str:
        return "nmap"

    def log(self, data: dict) -> None:
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_host": data.get("target_host", ""),
            "target_ports": data.get("target_ports", ""),
            "ports_count": data.get("ports_count", self._parse_ports_count(data.get("target_ports", "0"))),
            "timeout_sec": data.get("timeout_sec", ""),
            "duration_sec": data.get("duration_sec", ""),
            "concurrent_tasks": data.get("concurrent_tasks", ""),
            "status": data.get("status", ""),
        }
        super().log(log_data)


@ScanLoggerFactory.register("nikto")
class NiktoScanLogger(BaseScanLogger):
    _csv_name = "nikto"

    @property
    def columns(self) -> list[str]:
        return [
            "timestamp",
            "target_domain",
            "port",
            "is_ssl",
            "timeout_sec",
            "duration_sec",
            "concurrent_tasks",
            "status",
        ]

    @property
    def scan_type(self) -> str:
        return "nikto"

    def log(self, data: dict) -> None:
        target = data.get("target_domain", "")
        cleaned_target, port, is_ssl = self._infer_ssl(target)

        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_domain": cleaned_target,
            "port": data.get("port", port),
            "is_ssl": str(is_ssl).lower(),
            "timeout_sec": data.get("timeout_sec", ""),
            "duration_sec": data.get("duration_sec", ""),
            "concurrent_tasks": data.get("concurrent_tasks", ""),
            "status": data.get("status", ""),
        }
        super().log(log_data)


@ScanLoggerFactory.register("nuclei")
class NucleiScanLogger(BaseScanLogger):
    _csv_name = "nuclei"

    @property
    def columns(self) -> list[str]:
        return [
            "timestamp",
            "target",
            "severities",
            "tags",
            "rate_limit",
            "timeout_sec",
            "duration_sec",
            "concurrent_tasks",
            "status",
        ]

    @property
    def scan_type(self) -> str:
        return "nuclei"

    def log(self, data: dict) -> None:
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": data.get("target", ""),
            "severities": data.get("severities", ""),
            "tags": data.get("tags", ""),
            "rate_limit": data.get("rate_limit", ""),
            "timeout_sec": data.get("timeout_sec", ""),
            "duration_sec": data.get("duration_sec", ""),
            "concurrent_tasks": data.get("concurrent_tasks", ""),
            "status": data.get("status", ""),
        }
        super().log(log_data)


__all__ = [
    "ScanLoggerFactory",
    "BaseScanLogger",
    "ScanLogger",
    "NmapScanLogger",
    "NiktoScanLogger",
    "NucleiScanLogger",
]